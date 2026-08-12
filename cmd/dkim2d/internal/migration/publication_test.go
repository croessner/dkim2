package migration

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	datasourceldap "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/ldap"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
)

// TestPublicationCandidateUsesNeutralContentOwner freezes operation-free v2 migration custody.
func TestPublicationCandidateUsesNeutralContentOwner(t *testing.T) {
	_, plan, imported := publicationFixture(t)
	candidate, err := BuildPublicationCandidate(plan, imported)
	if err != nil {
		t.Fatal("migration publication candidate rejected")
	}
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery action.
	assertNeutralContent := func(content *datasourceadmin.CandidateContent) {
		if content == nil || content.Generation() != candidate.Generation() {
			t.Fatal("migration did not retain the shared neutral content owner")
		}
	}
	assertNeutralContent(candidate.content)
}

type memoryPublisher struct {
	mu        sync.Mutex
	current   uint64
	failAfter bool
}

// TestLDAPAssertionControlIsCriticalRFC4528 freezes the publication fence.
func TestLDAPAssertionControlIsCriticalRFC4528(t *testing.T) {
	control, err := datasourceldap.NewCriticalAssertionControl("(dkim2Generation=7)")
	if err != nil {
		t.Fatal("construct shared LDAP assertion control")
	}
	packet := control.Encode()
	if control.GetControlType() != "1.3.6.1.1.12" || packet == nil ||
		len(packet.Children) != 3 ||
		packet.Children[0].Value != "1.3.6.1.1.12" ||
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

// TestEstablishedLDAPFenceUpgradesSchemaWithGeneration proves an existing v1
// current pointer cannot retain its legacy schema while activating v2 data.
func TestEstablishedLDAPFenceUpgradesSchemaWithGeneration(t *testing.T) {
	request, err := newEstablishedCurrentFenceRequest(
		"cn=current,dc=example,dc=test", 7, "8",
	)
	if err != nil || request == nil || len(request.Controls) != 1 || len(request.Changes) != 2 {
		t.Fatal("established LDAP fence did not replace generation and schema atomically")
	}
	wantFilter := "(&(dkim2Generation=7)(dkim2DatasetState=committed)" +
		"(|(dkim2SchemaVersion=dkim2-datasource-v1)" +
		"(dkim2SchemaVersion=dkim2-datasource-v2)))"
	compiled, compileErr := goldap.CompileFilter(wantFilter)
	packet := request.Controls[0].Encode()
	value, ok := packet.Children[2].Value.(string)
	if compileErr != nil || !ok || !bytes.Equal([]byte(value), compiled.Bytes()) {
		t.Fatal("established LDAP fence did not assert the complete upgrade boundary")
	}
	changes := make(map[string][]string, len(request.Changes))
	for _, change := range request.Changes {
		changes[change.Modification.Type] = change.Modification.Vals
	}
	if len(changes[ldapGenerationAttribute]) != 1 ||
		changes[ldapGenerationAttribute][0] != "8" ||
		len(changes[ldapSchemaVersionAttribute]) != 1 ||
		changes[ldapSchemaVersionAttribute][0] != migrationSchemaVersion {
		t.Fatal("established LDAP fence retained a mixed schema generation")
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
	if p == nil || ctx == nil || candidate.Generation() <= expected {
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
	p.current = candidate.Generation()
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
		wait.Go(func() {
			report, err := Apply(
				context.Background(), records, plan, imported, publisher, "development",
			)
			if err == nil && report.Result == migrationResultSuccess {
				successes.Add(1)
			} else {
				failures.Add(1)
			}
		})
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
		wait.Go(func() {
			report, err := Apply(
				context.Background(), records, plan, imported, publisher, "development",
			)
			if err == nil && report.Result == migrationResultSuccess {
				successes.Add(1)
			} else {
				failures.Add(1)
			}
		})
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
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	rows, rowsErr := candidate.detachedRows(context.Background())
	if rowsErr != nil {
		t.Fatal("detach publication candidate")
	}
	defer clearCandidateRows(&rows)
	readback := candidateLDAPRecords(rows)
	if !candidateLDAPReadbackMatches(rows, readback) {
		t.Fatal("exact LDAP publication readback rejected")
	}
	readback.Handles[0].Attributes[ldapHandleAttribute][0] = []byte("different-handle")
	if candidateLDAPReadbackMatches(rows, readback) {
		t.Fatal("different valid LDAP publication readback accepted")
	}
}

// TestLDAPClosedCandidateFailsBeforeConnectionUse freezes pre-mutation detachment.
func TestLDAPClosedCandidateFailsBeforeConnectionUse(t *testing.T) {
	_, plan, imported := publicationFixture(t)
	candidate, err := BuildPublicationCandidate(plan, imported)
	if err != nil {
		t.Fatal("build publication candidate")
	}
	if err := candidate.Close(); err != nil {
		t.Fatal("close publication candidate")
	}
	var calls atomic.Uint64
	publisher := &LDAPPublisher{client: &ldapInventoryClient{callCount: &calls}}
	if err := publisher.Publish(context.Background(), 1, candidate); err == nil {
		t.Fatal("closed candidate reached LDAP publication")
	}
	if calls.Load() != 0 {
		t.Fatal("closed candidate invoked the LDAP client")
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
