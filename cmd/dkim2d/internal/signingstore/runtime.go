package signingstore

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/croessner/dkim2"
)

type generationReference struct {
	generation *Generation
	leases     int
	retired    bool
}

// Runtime atomically publishes complete datasource/private-key generations.
type Runtime struct {
	mu             sync.Mutex
	slot           chan struct{}
	rootFD         int
	datasourceFile string
	manifestFile   string
	current        *generationReference
	retired        map[*generationReference]struct{}
	reloadCancel   context.CancelFunc
	reloadDone     chan struct{}
	degraded       bool
	closed         bool
}

// Lease pins one immutable generation for the complete signing operation.
type Lease struct {
	mu     sync.Mutex
	owner  *Runtime
	ref    *generationReference
	closed bool
}

// NewRuntime validates the initial generation and retains only a duplicated root.
func NewRuntime(rootFD int, datasourceFile string, manifestFile string) (*Runtime, error) {
	retained, err := duplicateRootDescriptor(rootFD)
	if err != nil {
		return nil, &Error{}
	}
	generation, err := Open(retained, datasourceFile, manifestFile)
	if err != nil {
		_ = closeRootDescriptor(retained)
		return nil, &Error{}
	}
	reference := &generationReference{generation: generation}
	return &Runtime{
		rootFD: retained, datasourceFile: datasourceFile, manifestFile: manifestFile,
		current: reference, retired: make(map[*generationReference]struct{}),
		slot: makeRuntimeSlot(),
	}, nil
}

// Acquire pins the currently published immutable generation.
func (r *Runtime) Acquire() (*Lease, error) {
	if r == nil {
		return nil, &Error{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.degraded || r.current == nil || r.current.generation == nil {
		return nil, &Error{}
	}
	r.current.leases++
	return &Lease{owner: r, ref: r.current}, nil
}

// Reload validates a complete candidate before one atomic publication.
func (r *Runtime) Reload(ctx context.Context) error {
	if r == nil {
		return &Error{}
	}
	if err := acquireRuntimeSlot(ctx, r.slot); err != nil {
		return err
	}
	defer releaseRuntimeSlot(r.slot)
	r.mu.Lock()
	if r.closed || r.rootFD < 0 {
		r.mu.Unlock()
		return &Error{}
	}
	rootFD := r.rootFD
	datasourceFile := r.datasourceFile
	manifestFile := r.manifestFile
	r.mu.Unlock()
	candidate, err := Open(rootFD, datasourceFile, manifestFile)
	if err != nil {
		r.mu.Lock()
		if !r.closed {
			r.degraded = true
		}
		r.mu.Unlock()
		if contextError := runtimeContextError(ctx); contextError != nil {
			return contextError
		}
		return &Error{}
	}
	if contextError := runtimeContextError(ctx); contextError != nil {
		r.mu.Lock()
		if !r.closed {
			r.degraded = true
		}
		r.mu.Unlock()
		_ = candidate.Close(context.Background())
		return contextError
	}
	var closeNow *Generation
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = candidate.Close(context.Background())
		return &Error{}
	}
	previous := r.current
	r.current = &generationReference{generation: candidate}
	r.degraded = false
	if previous != nil {
		previous.retired = true
		if previous.leases == 0 {
			closeNow = previous.generation
			previous.generation = nil
		} else {
			r.retired[previous] = struct{}{}
		}
	}
	r.mu.Unlock()
	if closeNow != nil {
		_ = closeNow.Close(context.Background())
	}
	return nil
}

// StartReload begins the sole bounded periodic candidate loop.
func (r *Runtime) StartReload(interval time.Duration) error {
	if r == nil || interval < time.Second || interval > time.Hour {
		return &Error{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.reloadCancel != nil {
		return &Error{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	r.reloadCancel = cancel
	r.reloadDone = done
	go r.runReload(ctx, done, interval)
	return nil
}

// runReload serially validates candidates without changing the active generation on failure.
func (r *Runtime) runReload(ctx context.Context, done chan<- struct{}, interval time.Duration) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = r.Reload(ctx)
		}
	}
}

// Close joins reload and releases every unleased generation and root descriptor.
func (r *Runtime) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	alreadyClosed := r.closed
	r.mu.Unlock()
	if alreadyClosed {
		return nil
	}
	if err := acquireRuntimeSlot(ctx, r.slot); err != nil {
		return err
	}
	defer releaseRuntimeSlot(r.slot)
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	cancel := r.reloadCancel
	done := r.reloadDone
	r.reloadCancel = nil
	r.reloadDone = nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	var generations []*Generation
	r.mu.Lock()
	if r.current != nil {
		r.current.retired = true
		if r.current.leases == 0 {
			generations = append(generations, r.current.generation)
			r.current.generation = nil
		} else {
			r.retired[r.current] = struct{}{}
		}
		r.current = nil
	}
	for reference := range r.retired {
		if reference.leases == 0 {
			generations = append(generations, reference.generation)
			reference.generation = nil
			delete(r.retired, reference)
		}
	}
	rootFD := r.rootFD
	r.rootFD = -1
	r.mu.Unlock()
	failed := false
	for _, generation := range generations {
		if generation != nil && generation.Close(context.Background()) != nil {
			failed = true
		}
	}
	if rootFD >= 0 && closeRootDescriptor(rootFD) != nil {
		failed = true
	}
	if failed {
		return &Error{}
	}
	return nil
}

// makeRuntimeSlot constructs one occupied-free context-aware serialization slot.
func makeRuntimeSlot() chan struct{} {
	slot := make(chan struct{}, 1)
	slot <- struct{}{}
	return slot
}

// acquireRuntimeSlot waits for exact reload/close ownership or caller cancellation.
func acquireRuntimeSlot(ctx context.Context, slot chan struct{}) error {
	if slot == nil {
		return &Error{}
	}
	if err := runtimeContextError(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return runtimeContextError(ctx)
	case <-slot:
		if err := runtimeContextError(ctx); err != nil {
			releaseRuntimeSlot(slot)
			return err
		}
		return nil
	}
}

// runtimeContextError preserves context-first cancellation precedence.
func runtimeContextError(ctx context.Context) error {
	if ctx == nil {
		return &Error{}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		if err := ctx.Err(); err != nil {
			return err
		}
		return &Error{}
	default:
		return nil
	}
}

// releaseRuntimeSlot returns exact reload/close ownership.
func releaseRuntimeSlot(slot chan<- struct{}) {
	slot <- struct{}{}
}

// ResolvePolicy delegates to the lease's one pinned generation.
func (l *Lease) ResolvePolicy(
	ctx context.Context,
	tenant string,
	domain string,
	use PolicyUse,
	at time.Time,
) (dkim2.SigningProfile, error) {
	generation, err := l.generation()
	if err != nil {
		return dkim2.SigningProfile{}, err
	}
	return generation.ResolvePolicy(ctx, tenant, domain, use, at)
}

// ResolveAnyProfile reports local authority over one canonical domain by
// probing the flat-file store's profile-use inventory. It stops at the first
// use that resolves, returns the last permanent failure when no use resolves,
// and returns the first temporary failure unchanged, so that a store outage
// never degrades into an authoritative absence. The probe order is by
// expected hit likelihood for the received-DSN lookups that dominate this
// call, so a local domain usually costs one read; a foreign domain always
// costs one read per use, currently three, before it is answered not_local,
// which is why the caller serves repeated foreign domains from a bounded
// negative cache.
func (l *Lease) ResolveAnyProfile(
	ctx context.Context,
	tenant string,
	domain string,
	at time.Time,
) error {
	generation, err := l.generation()
	if err != nil {
		return err
	}
	var permanent error
	for _, use := range []PolicyUse{
		PolicyOrdinaryTransit, PolicyDeliveryStatus, PolicyOriginator,
	} {
		_, resolveErr := generation.ResolvePolicy(ctx, tenant, domain, use, at)
		if resolveErr == nil {
			return nil
		}
		if !PermanentProfileAbsence(resolveErr) {
			return resolveErr
		}
		permanent = resolveErr
	}
	if permanent == nil {
		return &Error{}
	}
	return permanent
}

// SignDigest delegates to the same pinned generation as policy resolution.
func (l *Lease) SignDigest(
	ctx context.Context,
	handle dkim2.PrivateKeyHandle,
	request dkim2.PrivateKeySignRequest,
) (dkim2.PrivateKeySignResult, error) {
	generation, err := l.generation()
	if err != nil {
		return dkim2.PrivateKeySignResult{}, dkim2.NewTemporaryProviderError()
	}
	return generation.SignDigest(ctx, handle, request)
}

// Close releases exactly one immutable-generation lease.
func (l *Lease) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.owner == nil || l.ref == nil {
		return &Error{}
	}
	l.owner.release(l.ref)
	l.owner = nil
	l.ref = nil
	return nil
}

// generation returns the still-pinned immutable generation.
func (l *Lease) generation() (*Generation, error) {
	if l == nil {
		return nil, &Error{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.ref == nil || l.ref.generation == nil {
		return nil, &Error{}
	}
	return l.ref.generation, nil
}

// release retires and closes an old generation after its final request.
func (r *Runtime) release(reference *generationReference) {
	var generation *Generation
	r.mu.Lock()
	if reference.leases > 0 {
		reference.leases--
	}
	if reference.retired && reference.leases == 0 {
		generation = reference.generation
		reference.generation = nil
		delete(r.retired, reference)
	}
	r.mu.Unlock()
	if generation != nil {
		_ = generation.Close(context.Background())
	}
}

// String returns a constant protected runtime summary.
func (*Runtime) String() string { return storeRedacted }

// GoString returns a constant protected runtime representation.
func (*Runtime) GoString() string { return storeRedacted }

// Format prevents formatting verbs from traversing generation state.
func (*Runtime) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, storeRedacted)
}

// MarshalJSON emits an empty object without provider or private-key facts.
func (*Runtime) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
