// Package runtime owns joined datasource and protected-registry generations.
package runtime

import (
	"context"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/provider"
)

const redacted = "datasource_runtime{redacted}"

// State is one closed datasource lifecycle state.
type State string

const (
	// StateInitializing precedes the first complete generation.
	StateInitializing State = "initializing"
	// StateReady permits new immutable generation leases.
	StateReady State = "ready"
	// StateDegraded forbids stale serving after a linearized refresh failure.
	StateDegraded State = "degraded"
	// StateClosed forbids all new work.
	StateClosed State = "closed"
)

// Candidate joins one complete datasource snapshot to one protected registry generation.
type Candidate struct {
	Dataset            *provider.Dataset
	RegistryGeneration uint64
	Bindings           []provider.Binding
	Registry           Registry
}

// Registry signs and destroys one immutable protected generation.
type Registry interface {
	dkim2.PrivateKeySigner
	Generation(context.Context) (uint64, error)
	Bindings() []provider.Binding
	Close(context.Context) error
}

// RegistrySource opens one exact protected registry generation.
type RegistrySource interface {
	Load(context.Context, uint64) (Registry, error)
}

// Valid reports whether both candidate sides identify one exact generation.
func (c Candidate) Valid() bool {
	return c.Dataset != nil && c.Dataset.Valid() &&
		c.RegistryGeneration != 0 &&
		c.Dataset.Generation() == c.RegistryGeneration &&
		c.Registry != nil
}

// Loader constructs one complete candidate using the supplied bounded context.
type Loader interface {
	Load(context.Context) (Candidate, error)
}

type generation struct {
	candidate Candidate
	resolver  *provider.SigningResolver
	leases    int
	retired   bool
}

// Runtime serializes refresh and atomically leases joined immutable generations.
type Runtime struct {
	mu          sync.Mutex
	slot        chan struct{}
	loader      Loader
	maxDeadline time.Duration
	state       State
	current     *generation
	retired     map[*generation]struct{}
}

// Lease pins one joined immutable generation until release.
type Lease struct {
	mu       sync.Mutex
	owner    *Runtime
	ref      *generation
	released bool
}

// New loads and publishes the first complete generation.
func New(ctx context.Context, loader Loader, maxDeadline time.Duration) (*Runtime, error) {
	if loader == nil || maxDeadline <= 0 || maxDeadline > 30*time.Second {
		return nil, provider.NewError(provider.ErrorCodeInvalidRequest)
	}
	runtime := &Runtime{
		slot: makeSlot(), loader: loader, maxDeadline: maxDeadline,
		state: StateInitializing, retired: make(map[*generation]struct{}),
	}
	if err := runtime.refresh(ctx, true); err != nil {
		return nil, err
	}
	return runtime, nil
}

// State returns the current closed lifecycle state without generation detail.
func (r *Runtime) State() State {
	if r == nil {
		return StateClosed
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

// Ready reports whether new work may lease the current complete generation.
func (r *Runtime) Ready() bool { return r.State() == StateReady }

// Acquire pins the exact current joined generation.
func (r *Runtime) Acquire(ctx context.Context) (*Lease, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, provider.NewError(provider.ErrorCodeUnavailable)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != StateReady || r.current == nil || !r.current.candidate.Valid() {
		return nil, provider.NewError(provider.ErrorCodeUnavailable)
	}
	r.current.leases++
	return &Lease{owner: r, ref: r.current}, nil
}

// Refresh loads and publishes one strictly higher complete generation.
func (r *Runtime) Refresh(ctx context.Context) error {
	if r == nil {
		return provider.NewError(provider.ErrorCodeUnavailable)
	}
	return r.refresh(ctx, false)
}

// refresh owns preflight, serialization, degradation, and atomic publication.
func (r *Runtime) refresh(ctx context.Context, initial bool) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = provider.NewError(provider.ErrorCodeInternalInvariant)
			if r != nil && !initial {
				r.markDegraded()
			}
		}
	}()
	if err := validateDeadline(ctx, r.maxDeadline); err != nil {
		return err
	}
	if !initial {
		r.mu.Lock()
		if r.state == StateClosed {
			r.mu.Unlock()
			return provider.NewError(provider.ErrorCodeUnavailable)
		}
		if r.current != nil && r.current.candidate.Dataset.Generation() == math.MaxUint64 {
			r.mu.Unlock()
			return provider.NewError(provider.ErrorCodeLimitExceeded)
		}
		r.mu.Unlock()
	}
	if err := acquire(ctx, r.slot); err != nil {
		return err
	}
	defer release(r.slot)
	candidate, err := callLoader(ctx, r.loader)
	if err != nil {
		if !initial {
			r.markDegraded()
		}
		return err
	}
	if err := contextError(ctx); err != nil {
		if !initial {
			r.markDegraded()
		}
		return err
	}
	if !candidate.Valid() {
		discardCandidate(&candidate, nil)
		if !initial {
			r.markDegraded()
		}
		return provider.NewError(provider.ErrorCodeMalformedData)
	}
	resolver, err := candidate.Dataset.NewSigningResolver(candidate.Bindings, time.Now().UTC())
	if err != nil || resolver == nil {
		discardCandidate(&candidate, resolver)
		if !initial {
			r.markDegraded()
		}
		return provider.NewError(provider.ErrorCodeMalformedData)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == StateClosed {
		discardCandidate(&candidate, resolver)
		return provider.NewError(provider.ErrorCodeUnavailable)
	}
	if r.current != nil {
		currentGeneration := r.current.candidate.Dataset.Generation()
		switch {
		case candidate.Dataset.Generation() == currentGeneration &&
			r.state == StateReady &&
			candidatesEquivalent(candidate, r.current.candidate):
			discardCandidate(&candidate, resolver)
			return nil
		case candidate.Dataset.Generation() <= currentGeneration:
			discardCandidate(&candidate, resolver)
			if !initial {
				r.state = StateDegraded
			}
			return provider.NewError(provider.ErrorCodeMalformedData)
		}
	}
	previous := r.current
	r.current = &generation{candidate: candidate, resolver: resolver}
	r.state = StateReady
	if previous != nil {
		previous.retired = true
		if previous.leases != 0 {
			r.retired[previous] = struct{}{}
		} else {
			closeGeneration(previous)
		}
	}
	return nil
}

// candidatesEquivalent compares all immutable public and protected projection
// facts before accepting one same-generation refresh as a successful no-op.
func candidatesEquivalent(left, right Candidate) bool {
	if !left.Valid() || !right.Valid() ||
		left.RegistryGeneration != right.RegistryGeneration ||
		!left.Dataset.Equivalent(right.Dataset) ||
		len(left.Bindings) != len(right.Bindings) {
		return false
	}
	for index := range left.Bindings {
		if !left.Bindings[index].Equivalent(right.Bindings[index]) {
			return false
		}
	}
	return true
}

// Close prevents new leases and retires all generations.
func (r *Runtime) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := acquire(ctx, r.slot); err != nil {
		return err
	}
	defer release(r.slot)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == StateClosed {
		return nil
	}
	r.state = StateClosed
	if r.current != nil {
		r.current.retired = true
		if r.current.leases != 0 {
			r.retired[r.current] = struct{}{}
		} else {
			closeGeneration(r.current)
		}
		r.current = nil
	}
	return nil
}

// String returns a constant protected runtime summary.
func (*Runtime) String() string { return redacted }

// GoString returns a constant protected runtime representation.
func (*Runtime) GoString() string { return redacted }

// Format prevents formatting verbs from traversing runtime state.
func (*Runtime) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON emits an empty object without provider state.
func (*Runtime) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// Dataset returns the pinned immutable dataset and exact generation.
func (l *Lease) Dataset() (*provider.Dataset, uint64, error) {
	if l == nil {
		return nil, 0, provider.NewError(provider.ErrorCodeUnavailable)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released || l.owner == nil || l.ref == nil || !l.ref.candidate.Valid() {
		return nil, 0, provider.NewError(provider.ErrorCodeUnavailable)
	}
	return l.ref.candidate.Dataset, l.ref.candidate.Dataset.Generation(), nil
}

// ResolvePolicy resolves one exact policy through the pinned immutable projection.
func (l *Lease) ResolvePolicy(
	ctx context.Context,
	tenant string,
	domain string,
	use provider.ProfileUse,
	at time.Time,
) (dkim2.SigningProfile, error) {
	if l == nil || ctx == nil {
		return dkim2.SigningProfile{}, provider.NewError(provider.ErrorCodeInvalidRequest)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released || l.ref == nil || l.ref.resolver == nil {
		return dkim2.SigningProfile{}, provider.NewError(provider.ErrorCodeUnavailable)
	}
	return l.ref.resolver.ResolvePolicy(ctx, tenant, domain, use, at)
}

// SignDigest delegates to the private registry pinned by this generation.
func (l *Lease) SignDigest(
	ctx context.Context,
	handle dkim2.PrivateKeyHandle,
	request dkim2.PrivateKeySignRequest,
) (dkim2.PrivateKeySignResult, error) {
	if l == nil || ctx == nil {
		return dkim2.PrivateKeySignResult{}, dkim2.NewTemporaryProviderError()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released || l.ref == nil || l.ref.candidate.Registry == nil {
		return dkim2.PrivateKeySignResult{}, dkim2.NewTemporaryProviderError()
	}
	return l.ref.candidate.Registry.SignDigest(ctx, handle, request)
}

// Close releases the pinned joined generation exactly once.
func (l *Lease) Close() error {
	l.Release()
	return nil
}

// Release drops the generation pin exactly once.
func (l *Lease) Release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.released || l.owner == nil || l.ref == nil {
		l.mu.Unlock()
		return
	}
	owner, ref := l.owner, l.ref
	l.released = true
	l.owner = nil
	l.ref = nil
	l.mu.Unlock()
	owner.mu.Lock()
	if ref.leases > 0 {
		ref.leases--
	}
	if ref.retired && ref.leases == 0 {
		delete(owner.retired, ref)
		closeGeneration(ref)
	}
	owner.mu.Unlock()
}

// discardCandidate releases an unpublished resolver and protected registry.
func discardCandidate(candidate *Candidate, resolver *provider.SigningResolver) {
	if resolver != nil {
		_ = resolver.Close(context.Background())
	}
	if candidate != nil && candidate.Registry != nil {
		_ = candidate.Registry.Close(context.Background())
		candidate.Registry = nil
	}
}

// closeGeneration destroys both sides after the last lease retires.
func closeGeneration(generation *generation) {
	if generation == nil {
		return
	}
	if generation.resolver != nil {
		_ = generation.resolver.Close(context.Background())
		generation.resolver = nil
	}
	if generation.candidate.Registry != nil {
		_ = generation.candidate.Registry.Close(context.Background())
		generation.candidate.Registry = nil
	}
}

// String returns a constant protected lease summary.
func (*Lease) String() string { return redacted }

// GoString returns a constant protected lease representation.
func (*Lease) GoString() string { return redacted }

// Format prevents formatting verbs from traversing lease state.
func (*Lease) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON emits an empty object without lease facts.
func (*Lease) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// markDegraded prevents stale serving after backend work has started.
func (r *Runtime) markDegraded() {
	r.mu.Lock()
	if r.state != StateClosed {
		r.state = StateDegraded
	}
	r.mu.Unlock()
}

// callLoader contains panics and validates the provider error boundary.
func callLoader(ctx context.Context, loader Loader) (candidate Candidate, resultErr error) {
	defer func() {
		if recover() != nil {
			candidate = Candidate{}
			resultErr = provider.NewError(provider.ErrorCodeInternalInvariant)
		}
	}()
	candidate, resultErr = loader.Load(ctx)
	if resultErr != nil {
		if provider.ErrorCodeOf(resultErr) == provider.ErrorCodeInternalInvariant {
			return Candidate{}, provider.NewError(provider.ErrorCodeUnavailable)
		}
		return Candidate{}, resultErr
	}
	return candidate, nil
}

// validateDeadline requires one active caller deadline no wider than the limit.
func validateDeadline(ctx context.Context, maximum time.Duration) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return provider.NewError(provider.ErrorCodeInvalidRequest)
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return provider.NewError(provider.ErrorCodeDeadlineExceeded)
	}
	if remaining > maximum {
		return provider.NewError(provider.ErrorCodeInvalidRequest)
	}
	return nil
}

// contextError maps terminal caller state into the closed provider taxonomy.
func contextError(ctx context.Context) error {
	if ctx == nil {
		return provider.NewError(provider.ErrorCodeInvalidRequest)
	}
	switch ctx.Err() {
	case nil:
		return nil
	case context.Canceled:
		return provider.NewError(provider.ErrorCodeCancelled)
	case context.DeadlineExceeded:
		return provider.NewError(provider.ErrorCodeDeadlineExceeded)
	default:
		return provider.NewError(provider.ErrorCodeInternalInvariant)
	}
}

// makeSlot constructs one free serialization token.
func makeSlot() chan struct{} {
	slot := make(chan struct{}, 1)
	slot <- struct{}{}
	return slot
}

// acquire waits for serialized ownership or caller termination.
func acquire(ctx context.Context, slot <-chan struct{}) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return contextError(ctx)
	case <-slot:
		return nil
	}
}

// release returns serialized ownership.
func release(slot chan<- struct{}) { slot <- struct{}{} }
