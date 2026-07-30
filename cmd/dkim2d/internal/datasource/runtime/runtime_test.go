package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/provider"
)

type loaderFunc func(context.Context) (Candidate, error)

// Load invokes the injected test loader.
func (f loaderFunc) Load(ctx context.Context) (Candidate, error) { return f(ctx) }

type testSigner struct {
	generation uint64
	bindings   []provider.Binding
}

// Generation returns the synthetic registry generation.
func (s testSigner) Generation(context.Context) (uint64, error) {
	return s.generation, nil
}

// Bindings returns detached synthetic registry bindings.
func (s testSigner) Bindings() []provider.Binding {
	return append([]provider.Binding(nil), s.bindings...)
}

// Close completes the synthetic registry lifecycle.
func (testSigner) Close(context.Context) error { return nil }

// SignDigest is unused by lifecycle-only tests.
func (testSigner) SignDigest(
	context.Context,
	dkim2.PrivateKeyHandle,
	dkim2.PrivateKeySignRequest,
) (dkim2.PrivateKeySignResult, error) {
	return dkim2.PrivateKeySignResult{}, dkim2.NewTemporaryProviderError()
}

// testCandidate builds one complete joined generation for lifecycle tests.
func testCandidate(generation, registryGeneration uint64) (Candidate, error) {
	return testCandidateForDomain(generation, registryGeneration, "example.test")
}

// testCandidateForDomain builds one complete joined generation with exact
// domain facts for same-generation identity tests.
func testCandidateForDomain(
	generation uint64,
	registryGeneration uint64,
	domain string,
) (Candidate, error) {
	public := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	public[0] = 1
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return Candidate{}, err
	}
	credential, err := provider.NewCredential(
		"selector", provider.AlgorithmEd25519SHA256, spki, "handle",
		provider.DefaultLimits(),
	)
	if err != nil {
		return Candidate{}, err
	}
	profile, err := provider.NewProfile(
		"profile", domain, provider.RecordStatusActive,
		[]provider.Credential{credential}, time.Time{}, time.Time{},
		provider.DefaultLimits(),
	)
	if err != nil {
		return Candidate{}, err
	}
	policy, err := provider.NewPolicy(
		"tenant", domain, provider.ProfileUseOriginator, "profile",
		provider.RecordStatusActive, provider.RolloutEnforce,
		provider.CompatibilityStrict, "", provider.DefaultLimits(),
	)
	if err != nil {
		return Candidate{}, err
	}
	dataset, err := provider.NewDataset(
		generation, []string{"handle"}, []provider.Profile{profile},
		[]provider.Policy{policy}, provider.DefaultLimits(),
	)
	if err != nil {
		return Candidate{}, err
	}
	handle, err := dkim2.NewPrivateKeyHandle([]byte("handle"))
	if err != nil {
		return Candidate{}, err
	}
	binding, err := provider.NewBinding(
		"tenant", domain, provider.ProfileUseOriginator, "handle",
		handle, provider.AlgorithmEd25519SHA256, sha256.Sum256(spki),
	)
	if err != nil {
		return Candidate{}, err
	}
	return Candidate{
		Dataset: dataset, RegistryGeneration: registryGeneration,
		Bindings: []provider.Binding{binding},
		Registry: testSigner{generation: registryGeneration, bindings: []provider.Binding{binding}},
	}, nil
}

// TestLifecycleDegradesWithoutStaleServing proves a linearized load failure
// closes new leases while an already pinned generation remains valid.
func TestLifecycleDegradesWithoutStaleServing(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	generation := uint64(1)
	fail := false
	loader := loaderFunc(func(context.Context) (Candidate, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return Candidate{}, provider.NewError(provider.ErrorCodeUnavailable)
		}
		return testCandidate(generation, generation)
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	runtime, err := New(ctx, loader, 2*time.Second)
	if err != nil {
		t.Fatal("construct runtime")
	}
	lease, err := runtime.Acquire(context.Background())
	if err != nil {
		t.Fatal("acquire initial lease")
	}
	mu.Lock()
	fail = true
	mu.Unlock()
	refreshCtx, refreshCancel := context.WithTimeout(context.Background(), time.Second)
	defer refreshCancel()
	if err := runtime.Refresh(refreshCtx); provider.ErrorCodeOf(err) != provider.ErrorCodeUnavailable {
		t.Fatal("expected unavailable refresh")
	}
	if runtime.State() != StateDegraded {
		t.Fatal("expected degraded state")
	}
	if _, err := runtime.Acquire(context.Background()); provider.ErrorCodeOf(err) != provider.ErrorCodeUnavailable {
		t.Fatal("stale generation must not be served")
	}
	if _, got, err := lease.Dataset(); err != nil || got != 1 {
		t.Fatal("existing lease must stay pinned")
	}
	lease.Release()
}

// TestLifecycleRecoversOnlyWithHigherMatchingGeneration proves complete
// generation agreement and strict monotonic publication.
func TestLifecycleRecoversOnlyWithHigherMatchingGeneration(t *testing.T) {
	t.Parallel()
	generation := uint64(3)
	registryGeneration := uint64(3)
	loader := loaderFunc(func(context.Context) (Candidate, error) {
		return testCandidate(generation, registryGeneration)
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	runtime, err := New(ctx, loader, 2*time.Second)
	if err != nil {
		t.Fatal("construct runtime")
	}
	generation = 4
	registryGeneration = 5
	refreshCtx, refreshCancel := context.WithTimeout(context.Background(), time.Second)
	if err := runtime.Refresh(refreshCtx); provider.ErrorCodeOf(err) != provider.ErrorCodeMalformedData {
		t.Fatal("mismatched candidate must fail closed")
	}
	refreshCancel()
	if runtime.State() != StateDegraded {
		t.Fatal("mismatched candidate must degrade")
	}
	registryGeneration = 4
	recoveryCtx, recoveryCancel := context.WithTimeout(context.Background(), time.Second)
	defer recoveryCancel()
	if err := runtime.Refresh(recoveryCtx); err != nil || !runtime.Ready() {
		t.Fatal("higher complete candidate must recover")
	}
}

// TestLifecycleRevalidatesUnchangedGenerationWithoutDegrading proves periodic
// health reloads are successful no-ops until a higher generation exists.
func TestLifecycleRevalidatesUnchangedGenerationWithoutDegrading(t *testing.T) {
	t.Parallel()
	loader := loaderFunc(func(context.Context) (Candidate, error) {
		return testCandidate(7, 7)
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	runtime, err := New(ctx, loader, 2*time.Second)
	if err != nil {
		t.Fatal("construct runtime")
	}
	refreshCtx, refreshCancel := context.WithTimeout(context.Background(), time.Second)
	defer refreshCancel()
	if err := runtime.Refresh(refreshCtx); err != nil || !runtime.Ready() {
		t.Fatal("unchanged fully validated generation degraded runtime")
	}
}

// TestLifecycleRejectsChangedFactsWithinCurrentGeneration proves a backend
// cannot mutate a generation in place while retaining runtime readiness.
func TestLifecycleRejectsChangedFactsWithinCurrentGeneration(t *testing.T) {
	t.Parallel()
	domain := "example.test"
	loader := loaderFunc(func(context.Context) (Candidate, error) {
		return testCandidateForDomain(9, 9, domain)
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	runtime, err := New(ctx, loader, 2*time.Second)
	if err != nil {
		t.Fatal("construct runtime")
	}
	domain = "changed.example"
	refreshCtx, refreshCancel := context.WithTimeout(context.Background(), time.Second)
	defer refreshCancel()
	if err := runtime.Refresh(refreshCtx); provider.ErrorCodeOf(err) != provider.ErrorCodeMalformedData {
		t.Fatal("changed same-generation facts must fail closed")
	}
	if runtime.State() != StateDegraded {
		t.Fatal("changed same-generation facts must degrade runtime")
	}
}
