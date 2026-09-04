package signing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/routeplan"
	"github.com/croessner/dkim2/internal/verify"
)

// TestHashPlanDeliveryStatusPropagationPurpose proves the propagation plan
// is an initial single-instance plan, rejects other purposes, and binds an
// explicitly supplied operation instant.
func TestHashPlanDeliveryStatusPropagationPurpose(t *testing.T) {
	fixture := newRevisionTestFixture(t, nil, false)
	coordinator, verifier := newTestHashPlanCoordinator(t, fixture)
	report := mustParseRevisionMessage(t, []byte("From: Mail Delivery System <MAILER-DAEMON@example.test>\r\nSubject: report\r\n\r\nbody\r\n"))
	ticket := testPropagationTicket(t, report.RawBytes())
	instant, err := verifier.CaptureOperationInstant()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := coordinator.PlanDeliveryStatusPropagation(context.Background(), OriginatorPlanRequest{Message: report, Ticket: ticket, Instant: instant})
	assertOriginPlan(t, plan, err)
	if plan.operationTimestamp() != instant.UnixSeconds() {
		t.Fatalf("plan instant=%d supplied=%d", plan.operationTimestamp(), instant.UnixSeconds())
	}
	if _, err := coordinator.PlanDeliveryStatus(context.Background(), OriginatorPlanRequest{Message: report, Ticket: ticket}); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("propagation ticket accepted by the DSN plan: %v", err)
	}
	if _, err := coordinator.PlanOriginator(context.Background(), OriginatorPlanRequest{Message: report, Ticket: ticket}); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("propagation ticket accepted by the originator plan: %v", err)
	}
	dsnTicket := testPlanTicket(t, report.RawBytes(), routeplan.PurposeOrigin, VerifiedRevisionInput{})
	if _, err := coordinator.PlanDeliveryStatusPropagation(context.Background(), OriginatorPlanRequest{Message: report, Ticket: dsnTicket}); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("origin ticket accepted by the propagation plan: %v", err)
	}
	if core := verifier.Core(); !core.Valid() {
		t.Fatal("Core() of a valid revision verifier is invalid")
	}
	if core := (RevisionVerifier{}).Core(); core.Valid() {
		t.Fatal("Core() of a zero revision verifier is valid")
	}
}

// testPropagationTicket plans one propagation route ticket for the raw report.
func testPropagationTicket(t *testing.T, raw []byte) routeplan.CopyTicket {
	t.Helper()
	source, err := routeplan.NewImmutableSource(raw)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := routeplan.NewEntry(source, routeplan.PurposeDeliveryStatusPropagation, []byte("<>"),
		[][]byte{[]byte("<previous@example.test>")}, routeplan.DisclosureSingle, []byte("propagation-route"), nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := routeplan.NewPlanRequest([]routeplan.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := routeplan.NewCoordinator(routeplan.NewMemoryAuthority(), routeplan.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	_, tickets, err := authority.Finalize(context.Background(), request)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("Finalize() tickets=%d error=%v", len(tickets), err)
	}
	return tickets[0]
}

// TestHashPlanDeliveryStatusPropagationBoundsSuppliedInstant proves a
// caller-supplied instant is accepted only within the verifier's skew around
// a fresh capture and only from the coordinator's own verifier.
func TestHashPlanDeliveryStatusPropagationBoundsSuppliedInstant(t *testing.T) {
	fixture := newRevisionTestFixture(t, nil, false)
	report := mustParseRevisionMessage(t, []byte("From: Mail Delivery System <MAILER-DAEMON@example.test>\r\nSubject: report\r\n\r\nbody\r\n"))
	base := time.Unix(int64(revisionTestTimestamp), 0).Add(time.Hour)
	now := base
	proof, err := verify.NewVerifier(mustRevisionStaticProvider(t, fixture), verify.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	revision, err := newRevisionVerifier(proof, Limits{}, bytes.NewReader(bytes.Repeat([]byte{0x6e}, sha256.Size)))
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewHashPlanCoordinator(revision, recipe.GenerationLimits{}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	tolerance := verify.DefaultTimestampPolicy().FutureTolerance
	for name, offset := range map[string]time.Duration{"same instant": 0, "within skew": tolerance} {
		now = base
		instant, err := revision.CaptureOperationInstant()
		if err != nil {
			t.Fatal(err)
		}
		now = base.Add(offset)
		plan, err := coordinator.PlanDeliveryStatusPropagation(context.Background(), OriginatorPlanRequest{Message: report, Ticket: testPropagationTicket(t, report.RawBytes()), Instant: instant})
		if err != nil || plan.operationTimestamp() != instant.UnixSeconds() {
			t.Fatalf("%s: plan error=%v", name, err)
		}
	}
	now = base
	stale, err := revision.CaptureOperationInstant()
	if err != nil {
		t.Fatal(err)
	}
	now = base.Add(tolerance + time.Second)
	if _, err := coordinator.PlanDeliveryStatusPropagation(context.Background(), OriginatorPlanRequest{Message: report, Ticket: testPropagationTicket(t, report.RawBytes()), Instant: stale}); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("stale instant accepted: %v", err)
	}
	now = base
	_, foreignVerifier := newTestHashPlanCoordinator(t, fixture)
	foreign, err := foreignVerifier.CaptureOperationInstant()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.PlanDeliveryStatusPropagation(context.Background(), OriginatorPlanRequest{Message: report, Ticket: testPropagationTicket(t, report.RawBytes()), Instant: foreign}); !IsErrorCode(err, ErrorCodeInvalidRequest) {
		t.Fatalf("foreign verifier instant accepted: %v", err)
	}
}
