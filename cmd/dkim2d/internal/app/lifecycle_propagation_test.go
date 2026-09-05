package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/propagationtest"
)

const lifecyclePropagationGeneration = "0123456789abcdef0123456789abcdef"

// lifecyclePropagationSnapshot loads one validated flat-file signing snapshot
// with or without the propagation capability.
func lifecyclePropagationSnapshot(t *testing.T, propagate bool) config.Snapshot {
	t.Helper()
	document := `config:
  version: dkim2d-config-v1
protected:
  generation: ` + lifecyclePropagationGeneration + `
server:
  capability_file: /secure/` + lifecyclePropagationGeneration + `/capability
  dsn_sign_capability_file: /secure/` + lifecyclePropagationGeneration + `/dsn-sign-capability
  dsn_propagate_capability_file: /secure/` + lifecyclePropagationGeneration + `/dsn-propagate-capability
replay:
  backend: disabled
signing:
  backend: flat_file
  datasource_file: /secure/` + lifecyclePropagationGeneration + `/datasource
  private_manifest_file: /secure/` + lifecyclePropagationGeneration + `/private-manifest
`
	if !propagate {
		document = strings.Replace(document, "  dsn_propagate_capability_file: /secure/"+lifecyclePropagationGeneration+"/dsn-propagate-capability\n", "", 1)
	}
	snapshot, err := config.Load([]byte(document), config.FlagValues{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return snapshot
}

// lifecyclePropagationVerifier is a verification service without the
// received-DSN evaluation seam. The verifier is held in a named field so
// that no evaluation method is promoted.
type lifecyclePropagationVerifier struct{ verifier *dkim2.Verifier }

// Assess delegates to the wrapped verifier.
func (v lifecyclePropagationVerifier) Assess(ctx context.Context, request dkim2.VerifyRequest) (dkim2.VerificationAssessment, error) {
	return v.verifier.Assess(ctx, request)
}

// TestComposePropagationFollowsCapabilityAndPrerequisites proves the
// propagation service is composed only under its own capability, refuses
// startup when the verifier lacks the evaluation seam or the replay runtime
// cannot hold the two-phase contract, and composes over the disabled replay
// policy when replay storage is explicitly off.
func TestComposePropagationFollowsCapabilityAndPrerequisites(t *testing.T) {
	corpus := propagationtest.Load(t)
	provider := corpus.Provider(t)
	verifier := corpus.Verifier(t, provider)
	authority := propagationtest.NewAuthority()
	operation := &SigningService{publicKeys: provider, store: lifecycleAuthority{authority}, clock: time.Now}
	disabledReplay := &ReplayRuntime{state: &replayRuntimeState{
		backend: config.ReplayDisabled, store: dkim2.NewReplayDisabledStore(),
	}}
	authorities, err := NewLocalAuthorityRegistry(lifecycleAuthority{authority}, time.Now)
	if err != nil {
		t.Fatalf("authority registry: %v", err)
	}
	service, err := composePropagation(verifier, operation, authorities, disabledReplay, lifecyclePropagationSnapshot(t, false))
	if err != nil || service != nil {
		t.Fatalf("without capability service=%v error=%v", service != nil, err)
	}
	enabled := lifecyclePropagationSnapshot(t, true)
	if _, err := composePropagation(lifecyclePropagationVerifier{verifier: verifier}, operation, authorities, disabledReplay, enabled); err == nil {
		t.Fatal("verifier without the evaluation seam composed a propagation service")
	}
	if _, err := composePropagation(verifier, nil, authorities, disabledReplay, enabled); err == nil {
		t.Fatal("missing signing generation composed a propagation service")
	}
	if _, err := composePropagation(verifier, operation, authorities, lifecycleReplayStub{}, enabled); err == nil {
		t.Fatal("replay without the propagation contract composed a propagation service")
	}
	service, err = composePropagation(verifier, operation, authorities, disabledReplay, enabled)
	if err != nil || service == nil {
		t.Fatalf("enabled composition service=%v error=%v", service != nil, err)
	}
	if _, ok := service.gate.(*PropagationReplayCoordinator); !ok || service.tokens == nil {
		t.Fatal("composed service is not bound to the runtime's propagation replay policy")
	}
}

// lifecycleAuthority binds the test-kit authority to the signing seam.
type lifecycleAuthority struct{ *propagationtest.Authority }

// Acquire returns the kit as the lease.
func (a lifecycleAuthority) Acquire(ctx context.Context) (SigningLease, error) {
	if err := a.Open(ctx); err != nil {
		return nil, err
	}
	return a.Authority, nil
}

// lifecycleReplayStub is a replay dependency that is not the runtime and
// therefore cannot hold the two-phase propagation contract.
type lifecycleReplayStub struct{}

// Coordinate is never reached by the composition check.
func (lifecycleReplayStub) Coordinate(context.Context, DomainResult) (ReplayOutcome, error) {
	return ReplayOutcome{}, &ReplayCoordinatorError{}
}

// AuthorityReady reports the stub as ready.
func (lifecycleReplayStub) AuthorityReady() bool { return true }

// Close satisfies the lifecycle replay seam.
func (lifecycleReplayStub) Close(context.Context) error { return nil }
