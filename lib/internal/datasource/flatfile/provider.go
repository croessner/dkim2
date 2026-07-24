package flatfile

import (
	"context"
	"fmt"
	"io"
	"math"
	"sync/atomic"

	"github.com/croessner/dkim2/internal/datasource"
	"github.com/croessner/dkim2/internal/niliface"
)

var _ datasource.Provider = (*Provider)(nil)

// providerSnapshot is one immutable atomically published lifecycle state.
type providerSnapshot struct {
	state      datasource.ProviderState
	generation uint64
	snapshot   *Snapshot
}

// valid reports whether one publication is complete and generation-consistent.
func (s *providerSnapshot) valid() bool {
	return s != nil && s.state.Known() && s.generation != 0 &&
		s.snapshot != nil && s.snapshot.operational() &&
		s.snapshot.generation == s.generation
}

// Provider owns one confined root capability and atomically reloadable snapshot.
type Provider struct {
	publication atomic.Pointer[providerSnapshot]
	rootFD      int
	filename    string
	expectedUID uint32
	limits      datasource.Limits
	ops         filesystemOps
	slot        chan struct{}
	complete    bool
}

// New constructs one production confined provider from a borrowed root descriptor.
func New(
	rootFD int,
	filename string,
	limits datasource.Limits,
) (*Provider, error) {
	if rootFD < 0 || limits.Validate() != nil {
		return nil, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	if err := validateFilename(filename); err != nil {
		return nil, err
	}
	ops, err := newFilesystemOps()
	if availabilityErr := filesystemOpsAvailable(ops, err); availabilityErr != nil {
		return nil, availabilityErr
	}
	return newProvider(rootFD, filename, limits, ops)
}

// newProvider validates, duplicates, loads, and transfers one owned root capability.
func newProvider(
	rootFD int,
	filename string,
	limits datasource.Limits,
	ops filesystemOps,
) (provider *Provider, resultErr error) {
	if rootFD < 0 || limits.Validate() != nil {
		return nil, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	if err := validateFilename(filename); err != nil {
		return nil, err
	}
	if niliface.IsNil(ops) {
		return nil, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}

	ownedRoot := -1
	defer func() {
		if recovered := recover(); recovered != nil {
			provider = nil
			resultErr = datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
		if provider == nil && ownedRoot >= 0 {
			failure := callClose(ops, ownedRoot)
			ownedRoot = -1
			if failure == operationPanicked {
				resultErr = datasource.NewError(datasource.ErrorCodeInternalInvariant)
			} else if resultErr == nil && failure != operationSucceeded {
				resultErr = failureError(failure)
			}
		}
	}()

	descriptor, failure := callDuplicateRoot(ops, rootFD)
	if descriptor >= 0 && descriptor != rootFD {
		ownedRoot = descriptor
	}
	if failure != operationSucceeded {
		if ownedRoot >= 0 || descriptor >= 0 {
			return nil, datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
		return nil, failureError(failure)
	}
	if descriptor < 0 || descriptor == rootFD {
		return nil, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}

	metadata, failure := callMetadata(ops, ownedRoot)
	if failure != operationSucceeded {
		return nil, failureError(failure)
	}
	expectedUID, failure := callEffectiveUID(ops)
	if failure != operationSucceeded {
		return nil, failureError(failure)
	}
	if err := validateRootMetadata(metadata, expectedUID); err != nil {
		return nil, err
	}

	candidate := &Provider{
		rootFD: ownedRoot, filename: filename, expectedUID: expectedUID,
		limits: limits, ops: ops, slot: make(chan struct{}, 1), complete: true,
	}
	candidate.slot <- struct{}{}
	snapshot, err := candidate.loadSnapshot(context.Background(), 1)
	if err != nil {
		return nil, err
	}
	candidate.publication.Store(&providerSnapshot{
		state: datasource.ProviderStateReady, generation: 1, snapshot: snapshot,
	})
	provider = candidate
	ownedRoot = -1
	return provider, nil
}

// State returns the bounded lifecycle state without exposing generation or records.
func (p *Provider) State() (datasource.ProviderState, error) {
	if !p.operational() {
		return 0, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	published := p.publication.Load()
	if !published.valid() {
		return 0, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	return published.state, nil
}

// Usage returns bounded accounting retained for ready or degraded diagnosis.
func (p *Provider) Usage() (datasource.Usage, error) {
	if !p.operational() {
		return datasource.Usage{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	published := p.publication.Load()
	if !published.valid() {
		return datasource.Usage{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	if published.state == datasource.ProviderStateClosed {
		return datasource.Usage{}, datasource.NewError(datasource.ErrorCodeUnavailable)
	}
	return published.snapshot.Usage()
}

// String returns a constant protected provider summary.
func (p *Provider) String() string { return "flatfile.Provider{redacted}" }

// GoString returns a constant protected provider representation.
func (p *Provider) GoString() string { return p.String() }

// Format prevents formatting verbs from exposing capability or file facts.
func (p *Provider) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, p.String())
}

// MarshalJSON emits an empty object so provider internals cannot be serialized.
func (p *Provider) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// ResolveProfile resolves against the one lifecycle snapshot captured at linearization.
func (p *Provider) ResolveProfile(
	ctx context.Context,
	request datasource.ProfileRequest,
) (datasource.ResolvedProfile, error) {
	published, err := p.captureReady(ctx)
	if err != nil {
		return datasource.ResolvedProfile{}, err
	}
	return published.snapshot.ResolveProfile(ctx, request)
}

// ResolvePolicy resolves against the one lifecycle snapshot captured at linearization.
func (p *Provider) ResolvePolicy(
	ctx context.Context,
	request datasource.PolicyRequest,
) (datasource.ResolvedPolicy, error) {
	published, err := p.captureReady(ctx)
	if err != nil {
		return datasource.ResolvedPolicy{}, err
	}
	return published.snapshot.ResolvePolicy(ctx, request)
}

// Reload serializes one explicit load and atomically publishes success or degradation.
func (p *Provider) Reload(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
	}()
	if err := p.preflightContext(ctx); err != nil {
		return err
	}
	preflightPublication := p.publication.Load()
	if !preflightPublication.valid() {
		return datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	if preflightPublication.state == datasource.ProviderStateClosed {
		return datasource.NewError(datasource.ErrorCodeUnavailable)
	}
	if preflightPublication.generation == math.MaxUint64 {
		return datasource.NewError(datasource.ErrorCodeLimitExceeded)
	}
	if err := p.acquire(ctx); err != nil {
		return err
	}
	defer p.release()

	published := p.publication.Load()
	if !published.valid() {
		return datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	if published.state == datasource.ProviderStateClosed {
		return datasource.NewError(datasource.ErrorCodeUnavailable)
	}
	if err := datasource.ErrorFromContext(ctx); err != nil {
		p.publishDegraded(published)
		return err
	}
	if published.generation == math.MaxUint64 {
		return datasource.NewError(datasource.ErrorCodeLimitExceeded)
	}

	snapshot, err := p.loadSnapshot(ctx, published.generation+1)
	if err != nil {
		p.publishDegraded(published)
		return err
	}
	if err := datasource.ErrorFromContext(ctx); err != nil {
		p.publishDegraded(published)
		return err
	}
	p.publication.Store(&providerSnapshot{
		state:      datasource.ProviderStateReady,
		generation: published.generation + 1,
		snapshot:   snapshot,
	})
	return nil
}

// Close publishes closed state before one non-retried owned-root close.
func (p *Provider) Close(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
	}()
	if p != nil && p.operational() {
		published := p.publication.Load()
		if published.valid() && published.state == datasource.ProviderStateClosed {
			return nil
		}
	}
	if err := p.preflightContext(ctx); err != nil {
		return err
	}
	if err := p.acquire(ctx); err != nil {
		return err
	}
	defer p.release()

	published := p.publication.Load()
	if !published.valid() {
		return datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	if published.state == datasource.ProviderStateClosed {
		return nil
	}
	if p.rootFD < 0 {
		return datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	descriptor := p.rootFD
	p.rootFD = -1
	p.publication.Store(&providerSnapshot{
		state:      datasource.ProviderStateClosed,
		generation: published.generation,
		snapshot:   published.snapshot,
	})
	failure := callClose(p.ops, descriptor)
	if failure != operationSucceeded {
		return failureError(failure)
	}
	return nil
}

// captureReady performs context-first checks and one atomic state linearization.
func (p *Provider) captureReady(ctx context.Context) (*providerSnapshot, error) {
	if err := p.preflightContext(ctx); err != nil {
		return nil, err
	}
	published := p.publication.Load()
	if !published.valid() {
		return nil, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	if published.state != datasource.ProviderStateReady {
		return nil, datasource.NewError(datasource.ErrorCodeUnavailable)
	}
	return published, nil
}

// preflightContext validates context before touching lifecycle synchronization.
func (p *Provider) preflightContext(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
	}()
	if niliface.IsNil(ctx) {
		return datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	if err := datasource.ErrorFromContext(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		err := datasource.ErrorFromContext(ctx)
		if err == nil {
			return datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
		return err
	default:
	}
	if !p.operational() {
		return datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	return nil
}

// acquire waits for the one reload-close serialization token.
func (p *Provider) acquire(ctx context.Context) (resultErr error) {
	tokenOwned := false
	defer func() {
		if recover() != nil {
			if tokenOwned {
				p.release()
			}
			resultErr = datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
	}()
	done := ctx.Done()
	select {
	case <-done:
		err := datasource.ErrorFromContext(ctx)
		if err == nil {
			return datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
		return err
	case <-p.slot:
		tokenOwned = true
		select {
		case <-done:
			p.release()
			tokenOwned = false
			err := datasource.ErrorFromContext(ctx)
			if err == nil {
				return datasource.NewError(datasource.ErrorCodeInternalInvariant)
			}
			return err
		default:
		}
		if err := datasource.ErrorFromContext(ctx); err != nil {
			p.release()
			tokenOwned = false
			return err
		}
		tokenOwned = false
		return nil
	}
}

// release returns the one reload-close serialization token.
func (p *Provider) release() {
	select {
	case p.slot <- struct{}{}:
	default:
		panic("flatfile lifecycle token invariant")
	}
}

// publishDegraded retains one snapshot only for recovery and bounded diagnosis.
func (p *Provider) publishDegraded(previous *providerSnapshot) {
	p.publication.Store(&providerSnapshot{
		state:      datasource.ProviderStateDegraded,
		generation: previous.generation,
		snapshot:   previous.snapshot,
	})
}

// operational performs constant-time immutable provider checks.
func (p *Provider) operational() bool {
	return p != nil && p.complete && p.filename != "" &&
		p.limits.Validate() == nil && !niliface.IsNil(p.ops) &&
		p.slot != nil && cap(p.slot) == 1
}

// loadSnapshot opens, validates, reads, closes, and decodes one generation.
func (p *Provider) loadSnapshot(
	ctx context.Context,
	generation uint64,
) (snapshot *Snapshot, resultErr error) {
	if err := datasource.ErrorFromContext(ctx); err != nil {
		return nil, err
	}
	fileFD, failure := callOpenFile(p.ops, p.rootFD, p.filename)
	ownedFile := -1
	if fileFD >= 0 && fileFD != p.rootFD {
		ownedFile = fileFD
	}
	defer func() {
		closeFailure := operationSucceeded
		if ownedFile >= 0 {
			closeFailure = callClose(p.ops, ownedFile)
		}
		if recovered := recover(); recovered != nil {
			snapshot = nil
			resultErr = datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
		if closeFailure == operationPanicked {
			snapshot = nil
			resultErr = datasource.NewError(datasource.ErrorCodeInternalInvariant)
		} else if resultErr == nil && closeFailure != operationSucceeded {
			snapshot = nil
			resultErr = failureError(closeFailure)
		}
		if resultErr == nil &&
			(snapshot == nil || !snapshot.operational() || snapshot.generation != generation) {
			snapshot = nil
			resultErr = datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
		if resultErr != nil && snapshot != nil {
			snapshot = nil
			resultErr = datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
		resultErr = datasource.ReconcileContextFailure(
			resultErr,
			datasource.ErrorFromContext(ctx),
		)
		if resultErr != nil {
			snapshot = nil
		}
	}()
	if failure != operationSucceeded {
		if ownedFile >= 0 || fileFD >= 0 {
			return nil, datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
		return nil, failureError(failure)
	}
	if fileFD < 0 || fileFD == p.rootFD {
		return nil, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}

	if err := datasource.ErrorFromContext(ctx); err != nil {
		return nil, err
	}
	metadata, failure := callMetadata(p.ops, ownedFile)
	if failure != operationSucceeded {
		return nil, failureError(failure)
	}
	if err := validateFileMetadata(metadata, p.expectedUID); err != nil {
		return nil, err
	}
	if err := datasource.ErrorFromContext(ctx); err != nil {
		return nil, err
	}
	reader := &descriptorReader{ops: p.ops, fd: ownedFile}
	snapshot, resultErr = DecodeReader(generation, reader, p.limits)
	if resultErr != nil {
		return nil, resultErr
	}
	if err := datasource.ErrorFromContext(ctx); err != nil {
		return nil, err
	}
	return snapshot, nil
}
