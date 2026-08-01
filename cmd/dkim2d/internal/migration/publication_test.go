package migration

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type memoryPublisher struct {
	mu        sync.Mutex
	current   uint64
	failAfter bool
}

// TestLDAPAssertionControlIsCriticalRFC4528 freezes the publication fence.
func TestLDAPAssertionControlIsCriticalRFC4528(t *testing.T) {
	control := ldapAssertionControl{filter: "(dkim2Generation=7)"}
	packet := control.Encode()
	if control.GetControlType() != assertionControlOID || packet == nil ||
		len(packet.Children) != 3 ||
		packet.Children[0].Value != assertionControlOID ||
		packet.Children[1].Value != true {
		t.Fatal("RFC 4528 assertion control shape drifted")
	}
	value, ok := packet.Children[2].Value.(string)
	if !ok || value == "" {
		t.Fatal("RFC 4528 assertion filter was absent")
	}
	decoded, err := ber.DecodePacketErr([]byte(value))
	if err != nil || decoded == nil {
		t.Fatal("RFC 4528 assertion filter was not BER")
	}
}

// TestPublicationFenceAcceptsOnlyV1MigrationOrV2 proves the offline publisher
// can replace an existing v1 current generation without widening runtime reads.
func TestPublicationFenceAcceptsOnlyV1MigrationOrV2(t *testing.T) {
	if !supportedPublicationFenceVersion("dkim2-datasource-v1") ||
		!supportedPublicationFenceVersion("dkim2-datasource-v2") ||
		supportedPublicationFenceVersion("dkim2-datasource-v3") ||
		supportedPublicationFenceVersion("") {
		t.Fatal("publication fence version policy drifted")
	}
}

// Current returns the exact synchronized synthetic fence.
func (p *memoryPublisher) Current(ctx context.Context) (uint64, error) {
	if p == nil || ctx == nil {
		return 0, errors.New("publication unavailable")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.current, nil
}

// Publish atomically compares and replaces one synthetic generation.
func (p *memoryPublisher) Publish(
	ctx context.Context,
	expected uint64,
	candidate PublicationCandidate,
) error {
	if p == nil || ctx == nil || candidate.generation <= expected {
		return errors.New("publication unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current != expected || p.failAfter {
		return errors.New("publication unavailable")
	}
	p.current = candidate.generation
	return nil
}

// TestConcurrentPublicationAllowsAtMostOneExpectedFenceWinner proves fencing.
func TestConcurrentPublicationAllowsAtMostOneExpectedFenceWinner(t *testing.T) {
	records, plan, imported := publicationFixture(t)
	publisher := &memoryPublisher{current: 1}
	var successes atomic.Int32
	var failures atomic.Int32
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			report, err := Apply(
				context.Background(), records, plan, imported, publisher, "development",
			)
			if err == nil && report.Result == migrationResultSuccess {
				successes.Add(1)
			} else {
				failures.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || publisher.current != 2 {
		t.Fatalf("concurrent expected-current publication did not fence: success=%d failure=%d current=%d", successes.Load(), failures.Load(), publisher.current)
	}
}

// TestConcurrentBootstrapPublicationAllowsExactlyOneWinner proves the explicit
// empty-backend sentinel cannot let two first publishers activate.
func TestConcurrentBootstrapPublicationAllowsExactlyOneWinner(t *testing.T) {
	records, plan, imported := publicationFixture(t)
	plan.ExpectedCurrent = "0"
	publisher := &memoryPublisher{}
	var successes atomic.Int32
	var failures atomic.Int32
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			report, err := Apply(
				context.Background(), records, plan, imported, publisher, "development",
			)
			if err == nil && report.Result == migrationResultSuccess {
				successes.Add(1)
			} else {
				failures.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || failures.Load() != 1 || publisher.current != 2 {
		t.Fatalf(
			"concurrent bootstrap publication did not fence: success=%d failure=%d current=%d",
			successes.Load(), failures.Load(), publisher.current,
		)
	}
}

// TestBootstrapExpectedCurrentIsOnlyCanonicalZero freezes the explicit sentinel.
func TestBootstrapExpectedCurrentIsOnlyCanonicalZero(t *testing.T) {
	plan := testConfig().Plan
	plan.ExpectedCurrent = "0"
	if err := validatePlan(plan); err != nil {
		t.Fatal("canonical empty-backend sentinel was rejected")
	}
	for _, invalid := range []string{"", "00", "+0", "-0", " 0", "0 "} {
		plan.ExpectedCurrent = invalid
		if err := validatePlan(plan); err == nil {
			t.Fatalf("noncanonical empty-backend sentinel accepted: %q", invalid)
		}
	}
}

// TestPublicationFailureAndHigherGenerationRollbackPreserveAtomicFence proves
// failed publication has no side effect and rollback never moves backward.
func TestPublicationFailureAndHigherGenerationRollbackPreserveAtomicFence(t *testing.T) {
	records, plan, imported := publicationFixture(t)
	failing := &memoryPublisher{current: 1, failAfter: true}
	report, err := Apply(
		context.Background(), records, plan, imported, failing, "development",
	)
	if err == nil || report.Publication.Completed || failing.current != 1 {
		t.Fatal("failed publication changed current fence")
	}
	plan.Generation = "3"
	plan.ExpectedCurrent = "2"
	publisher := &memoryPublisher{current: 2}
	report, err = Rollback(
		context.Background(), records, plan, imported, publisher, "development",
	)
	if err != nil || report.Mode != "rollback" ||
		!report.Publication.Completed || publisher.current != 3 {
		t.Fatalf("higher-generation rollback failed: report=%s failure=%s err=%v current=%d", report.Result, report.FailureClass, err, publisher.current)
	}
	plan.Generation = "1"
	plan.ExpectedCurrent = "3"
	if _, err := Rollback(
		context.Background(), records, plan, imported, publisher, "development",
	); err == nil || publisher.current != 3 {
		t.Fatal("backward rollback changed current fence")
	}
}

// TestLDAPReadbackMustEqualPublicationCandidate proves a different but valid
// staged dataset cannot be activated under the planned generation.
func TestLDAPReadbackMustEqualPublicationCandidate(t *testing.T) {
	_, plan, imported := publicationFixture(t)
	candidate, err := BuildPublicationCandidate(plan, imported)
	if err != nil {
		t.Fatal("build publication candidate")
	}
	defer clearCandidateRows(&candidate.rows)
	readback := candidateLDAPRecords(candidate)
	if !candidateLDAPReadbackMatches(candidate, readback) {
		t.Fatal("exact LDAP publication readback rejected")
	}
	readback.Handles[0].Attributes[ldapHandleAttribute][0] = []byte("different-handle")
	if candidateLDAPReadbackMatches(candidate, readback) {
		t.Fatal("different valid LDAP publication readback accepted")
	}
}

// publicationFixture returns one proven key and protected staging owner.
func publicationFixture(
	t *testing.T,
) ([]LegacyRecord, Plan, []*ImportedCredential) {
	t.Helper()
	plan := testConfig().Plan
	records := []LegacyRecord{{
		selector: migrationTestSelector, sourceSelector: migrationTestSelector,
		domain: migrationTestDomain, associated: migrationTestDomain,
		algorithm: AlgorithmRSA, active: true,
	}}
	imported, err := ImportKeys(
		context.Background(), records, plan,
		&keyImportClientFake{values: map[string][]byte{
			migrationTestSourceKey: rsaPrivatePEM(t),
		}},
		&dnsProverFake{},
	)
	if err != nil {
		t.Fatal("build publication fixture")
	}
	t.Cleanup(func() { closeImported(imported) })
	return records, plan, imported
}
