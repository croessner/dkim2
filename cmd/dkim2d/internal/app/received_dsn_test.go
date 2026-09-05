package app

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/propagationtest"
)

// receivedDSNFixture composes the domain processor over the frozen corpus
// with a tenant-keyed authority and a configurable default tenant.
type receivedDSNFixture struct {
	corpus    *propagationtest.Corpus
	provider  *propagationtest.Provider
	verifier  *dkim2.Verifier
	authority *propagationtest.Authority
}

// newReceivedDSNFixture builds the fixture; tenant-a holds local.example.
func newReceivedDSNFixture(t *testing.T) *receivedDSNFixture {
	t.Helper()
	corpus := propagationtest.Load(t)
	provider := corpus.Provider(t)
	authority := propagationtest.NewAuthority().AddLocal(propagationTestTenant, propagationtest.LocalDomain)
	return &receivedDSNFixture{corpus: corpus, provider: provider, verifier: corpus.Verifier(t, provider), authority: authority}
}

// processor constructs one domain processor in the mode with the binding.
func (f *receivedDSNFixture) processor(t *testing.T, mode config.PolicyMode, defaultTenant string, withAuthority bool) *DomainProcessor {
	t.Helper()
	processor, err := NewDomainProcessor(f.verifier, mode)
	if err != nil {
		t.Fatalf("domain processor: %v", err)
	}
	var authority SigningAuthority
	if withAuthority {
		authority = kitAuthority{f.authority}
	}
	authorities, err := NewLocalAuthorityRegistry(authority, time.Now)
	if err != nil {
		t.Fatalf("authority registry: %v", err)
	}
	binding, err := NewReceivedDSNBinding(f.verifier, authorities, defaultTenant)
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	if err := processor.BindReceivedDSN(binding); err != nil {
		t.Fatalf("bind: %v", err)
	}
	return processor
}

// inbound builds the process request of one corpus case for the tenant.
func (f *receivedDSNFixture) inbound(t *testing.T, name, tenant string) InboundRequest {
	t.Helper()
	testCase := f.corpus.Case(t, name)
	request, err := NewInboundRequest(dkim2.NewVerifyRequest(
		testCase.RawMessage(t), []byte("<>"), [][]byte{testCase.ForwardPath(t)},
	), tenant)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

// process runs one inbound request and requires an applicable result.
func process(t *testing.T, processor *DomainProcessor, request InboundRequest) DomainResult {
	t.Helper()
	result, err := processor.ProcessInbound(context.Background(), request)
	if err != nil || !result.Applicable() {
		t.Fatalf("ProcessInbound() applicable=%t error=%v", result.Applicable(), err)
	}
	return result
}

// requireDeliveryStatus asserts the presence and two closed members of the projection.
func requireDeliveryStatus(t *testing.T, result DomainResult, localHop dkim2.ReceivedDSNLocalHop, propagation dkim2.ReceivedDSNPropagation) DeliveryStatusProjection {
	t.Helper()
	projection, present := result.DeliveryStatus()
	if !present || projection.LocalHop() != localHop || projection.Propagation() != propagation {
		t.Fatalf("delivery_status present=%t local_hop=%q propagation=%q, want %q/%q", present, projection.LocalHop(), projection.Propagation(), localHop, propagation)
	}
	return projection
}

// requirePolicy asserts the verdict and the last recorded finding reason.
func requirePolicy(t *testing.T, result DomainResult, verdict dkim2.PolicyVerdict, reason dkim2.PolicyReason) {
	t.Helper()
	policy, err := result.Policy()
	if err != nil {
		t.Fatal(err)
	}
	findings := policy.Findings()
	if policy.Verdict() != verdict || len(findings) == 0 || findings[len(findings)-1].Reason() != reason {
		last := dkim2.PolicyReason("")
		if len(findings) > 0 {
			last = findings[len(findings)-1].Reason()
		}
		t.Fatalf("verdict=%q last finding=%q, want %q/%q", policy.Verdict(), last, verdict, reason)
	}
}

// TestProcessDeliveryStatusClassificationAndTenantPrecedence proves the
// member is emitted only for a null-sender signed delivery-status report,
// and that the tenant precedence is request member, then daemon default,
// then none, where none leaves local_hop and propagation not evaluated.
func TestProcessDeliveryStatusClassificationAndTenantPrecedence(t *testing.T) {
	fixture := newReceivedDSNFixture(t)
	t.Run("request tenant", func(t *testing.T) {
		processor := fixture.processor(t, config.PolicyStrict, propagationTestOtherTenant, true)
		result := process(t, processor, fixture.inbound(t, propagationtest.CaseRunOfOne, propagationTestTenant))
		requireDeliveryStatus(t, result, dkim2.ReceivedDSNLocalHopLocal, dkim2.ReceivedDSNPropagationEligible)
		requirePolicy(t, result, dkim2.PolicyVerdictAccept, dkim2.PolicyReasonReceivedDSNLinked)
	})
	t.Run("default tenant", func(t *testing.T) {
		processor := fixture.processor(t, config.PolicyStrict, propagationTestTenant, true)
		result := process(t, processor, fixture.inbound(t, propagationtest.CaseRunOfOne, ""))
		requireDeliveryStatus(t, result, dkim2.ReceivedDSNLocalHopLocal, dkim2.ReceivedDSNPropagationEligible)
	})
	t.Run("no tenant", func(t *testing.T) {
		processor := fixture.processor(t, config.PolicyStrict, "", true)
		result := process(t, processor, fixture.inbound(t, propagationtest.CaseRunOfOne, ""))
		requireDeliveryStatus(t, result, dkim2.ReceivedDSNLocalHopNotEvaluated, dkim2.ReceivedDSNPropagationNotEvaluated)
		requirePolicy(t, result, dkim2.PolicyVerdictAccept, dkim2.PolicyReasonReceivedDSNTenantUnavailable)
	})
	t.Run("no authority ignores tenants", func(t *testing.T) {
		processor := fixture.processor(t, config.PolicyStrict, propagationTestTenant, false)
		result := process(t, processor, fixture.inbound(t, propagationtest.CaseRunOfOne, propagationTestTenant))
		requireDeliveryStatus(t, result, dkim2.ReceivedDSNLocalHopNotEvaluated, dkim2.ReceivedDSNPropagationNotEvaluated)
	})
	t.Run("two tenants on one daemon", func(t *testing.T) {
		processor := fixture.processor(t, config.PolicyStrict, "", true)
		local := process(t, processor, fixture.inbound(t, propagationtest.CaseRunOfOne, propagationTestTenant))
		requireDeliveryStatus(t, local, dkim2.ReceivedDSNLocalHopLocal, dkim2.ReceivedDSNPropagationEligible)
		foreign := process(t, processor, fixture.inbound(t, propagationtest.CaseRunOfOne, propagationTestOtherTenant))
		requireDeliveryStatus(t, foreign, dkim2.ReceivedDSNLocalHopNotLocal, dkim2.ReceivedDSNPropagationNotEvaluated)
		requirePolicy(t, foreign, dkim2.PolicyVerdictAccept, dkim2.PolicyReasonReceivedDSNNotLocal)
	})
	t.Run("without binding nothing changes", func(t *testing.T) {
		processor, err := NewDomainProcessor(fixture.verifier, config.PolicyStrict)
		if err != nil {
			t.Fatal(err)
		}
		result := process(t, processor, fixture.inbound(t, propagationtest.CaseRunOfOne, propagationTestTenant))
		if _, present := result.DeliveryStatus(); present {
			t.Fatal("unbound processor emitted a delivery-status projection")
		}
	})
	t.Run("non-null sender is not a received DSN", func(t *testing.T) {
		processor := fixture.processor(t, config.PolicyStrict, propagationTestTenant, true)
		testCase := fixture.corpus.Case(t, propagationtest.CaseRunOfOne)
		request, _ := NewInboundRequest(dkim2.NewVerifyRequest(
			testCase.RawMessage(t), []byte("<bounce@destination.example>"), [][]byte{testCase.ForwardPath(t)},
		), propagationTestTenant)
		result, err := processor.ProcessInbound(context.Background(), request)
		if err != nil || !result.Applicable() {
			t.Fatalf("applicable=%t error=%v", result.Applicable(), err)
		}
		if _, present := result.DeliveryStatus(); present {
			t.Fatal("non-null sender produced a delivery-status projection")
		}
	})
	t.Run("non-report null sender is not a received DSN", func(t *testing.T) {
		processor := fixture.processor(t, config.PolicyStrict, propagationTestTenant, true)
		testCase := fixture.corpus.Case(t, propagationtest.CaseRunOfOne)
		raw := bytes.Replace(testCase.RawMessage(t), []byte("report-type=delivery-status"), []byte("report-type=disposition-notification"), 1)
		request, _ := NewInboundRequest(dkim2.NewVerifyRequest(raw, []byte("<>"), [][]byte{testCase.ForwardPath(t)}), propagationTestTenant)
		result, err := processor.ProcessInbound(context.Background(), request)
		if err != nil || !result.Applicable() {
			t.Fatalf("applicable=%t error=%v", result.Applicable(), err)
		}
		if _, present := result.DeliveryStatus(); present {
			t.Fatal("non-report message produced a delivery-status projection")
		}
	})
	t.Run("binding validation", func(t *testing.T) {
		if _, err := NewReceivedDSNBinding(nil, nil, ""); err == nil {
			t.Fatal("nil evaluator accepted")
		}
		if _, err := NewReceivedDSNBinding(fixture.verifier, nil, "bad tenant!"); err == nil {
			t.Fatal("invalid default tenant accepted")
		}
		if _, err := NewInboundRequest(dkim2.VerifyRequest{}, "bad tenant!"); err == nil {
			t.Fatal("invalid request tenant accepted")
		}
		var nilProcessor *DomainProcessor
		if err := nilProcessor.BindReceivedDSN(nil); err == nil {
			t.Fatal("nil binding accepted")
		}
	})
}

// TestProcessDeliveryStatusPolicyTable proves the policy rows the corpus
// reaches in every mode: linked accept keeps the outer verdict, not_local is
// accepted, and a datasource outage is a tempfail in strict and permissive
// mode and a delivery-neutral continue in testing mode.
func TestProcessDeliveryStatusPolicyTable(t *testing.T) {
	fixture := newReceivedDSNFixture(t)
	modes := []struct {
		mode     config.PolicyMode
		linked   dkim2.PolicyVerdict
		notLocal dkim2.PolicyVerdict
		outage   dkim2.PolicyVerdict
	}{
		{mode: config.PolicyStrict, linked: dkim2.PolicyVerdictAccept, notLocal: dkim2.PolicyVerdictAccept, outage: dkim2.PolicyVerdictTempfail},
		{mode: config.PolicyPermissive, linked: dkim2.PolicyVerdictAccept, notLocal: dkim2.PolicyVerdictAccept, outage: dkim2.PolicyVerdictTempfail},
		{mode: config.PolicyTesting, linked: dkim2.PolicyVerdictContinue, notLocal: dkim2.PolicyVerdictContinue, outage: dkim2.PolicyVerdictContinue},
	}
	for _, row := range modes {
		t.Run(string(row.mode), func(t *testing.T) {
			processor := fixture.processor(t, row.mode, "", true)
			linked := process(t, processor, fixture.inbound(t, propagationtest.CaseRunOfOne, propagationTestTenant))
			requirePolicy(t, linked, row.linked, dkim2.PolicyReasonReceivedDSNLinked)
			notLocal := process(t, processor, fixture.inbound(t, propagationtest.CaseRunOfOne, propagationTestOtherTenant))
			requirePolicy(t, notLocal, row.notLocal, dkim2.PolicyReasonReceivedDSNNotLocal)
			fixture.authority.SetOutage(true)
			outage := process(t, processor, fixture.inbound(t, propagationtest.CaseRunOfOne, propagationTestTenant))
			fixture.authority.SetOutage(false)
			projection := requireDeliveryStatus(t, outage, dkim2.ReceivedDSNLocalHopTemperror, dkim2.ReceivedDSNPropagationNotEvaluated)
			if projection.Structure() != dkim2.ReceivedDSNStructureValid {
				t.Fatalf("structure = %q", projection.Structure())
			}
			requirePolicy(t, outage, row.outage, dkim2.PolicyReasonReceivedDSNTemporaryFailure)
		})
	}
}

// TestProcessDeliveryStatusNegativeCacheAndObservation proves repeated
// foreign domains are served from the tenant's retained negative cache and
// that the closed observation stage follows the projection.
func TestProcessDeliveryStatusNegativeCacheAndObservation(t *testing.T) {
	fixture := newReceivedDSNFixture(t)
	processor := fixture.processor(t, config.PolicyStrict, "", true)
	for range 3 {
		process(t, processor, fixture.inbound(t, propagationtest.CaseRunOfOne, propagationTestOtherTenant))
	}
	if probes := fixture.authority.AuthorityProbes.Load(); probes != 1 {
		t.Fatalf("authority probes = %d, want 1 (negative cache)", probes)
	}
	for name, testCase := range map[string]struct {
		projection DeliveryStatusProjection
		stage      string
		result     string
	}{
		"invalid":         {stage: receivedDSNStageStructure, result: receivedDSNResultTemporary},
		"malformed":       {projection: DeliveryStatusProjection{structure: dkim2.ReceivedDSNStructureMalformed, embedded: dkim2.ReceivedDSNEmbeddedTemperror, localHop: dkim2.ReceivedDSNLocalHopNotEvaluated, outerAlignment: dkim2.ReceivedDSNOuterAlignmentNotEvaluated, recipientLinkage: dkim2.ReceivedDSNRecipientLinkageNotEvaluated, propagation: dkim2.ReceivedDSNPropagationNotEvaluated, valid: true}, stage: receivedDSNStageStructure, result: receivedDSNResultPermanent},
		"absent":          {projection: DeliveryStatusProjection{structure: dkim2.ReceivedDSNStructureValid, embedded: dkim2.ReceivedDSNEmbeddedAbsent, localHop: dkim2.ReceivedDSNLocalHopNotEvaluated, outerAlignment: dkim2.ReceivedDSNOuterAlignmentNotEvaluated, recipientLinkage: dkim2.ReceivedDSNRecipientLinkageNotEvaluated, propagation: dkim2.ReceivedDSNPropagationNotApplicable, valid: true}, stage: receivedDSNStageEmbedded, result: receivedDSNResultOK},
		"eligible":        {projection: DeliveryStatusProjection{structure: dkim2.ReceivedDSNStructureValid, embedded: dkim2.ReceivedDSNEmbeddedVerified, localHop: dkim2.ReceivedDSNLocalHopLocal, outerAlignment: dkim2.ReceivedDSNOuterAlignmentAligned, recipientLinkage: dkim2.ReceivedDSNRecipientLinkageLinked, propagation: dkim2.ReceivedDSNPropagationEligible, valid: true}, stage: receivedDSNStageCompleted, result: receivedDSNResultOK},
		"unlinked":        {projection: DeliveryStatusProjection{structure: dkim2.ReceivedDSNStructureValid, embedded: dkim2.ReceivedDSNEmbeddedVerified, localHop: dkim2.ReceivedDSNLocalHopLocal, outerAlignment: dkim2.ReceivedDSNOuterAlignmentAligned, recipientLinkage: dkim2.ReceivedDSNRecipientLinkageUnlinked, propagation: dkim2.ReceivedDSNPropagationNotEvaluated, valid: true}, stage: receivedDSNStageRecipientLinkage, result: receivedDSNResultPermanent},
		"not failure":     {projection: DeliveryStatusProjection{structure: dkim2.ReceivedDSNStructureValid, embedded: dkim2.ReceivedDSNEmbeddedVerified, localHop: dkim2.ReceivedDSNLocalHopLocal, outerAlignment: dkim2.ReceivedDSNOuterAlignmentAligned, recipientLinkage: dkim2.ReceivedDSNRecipientLinkageLinked, propagation: dkim2.ReceivedDSNPropagationNotFailure, valid: true}, stage: receivedDSNStageFailureClass, result: receivedDSNResultOK},
		"terminal origin": {projection: DeliveryStatusProjection{structure: dkim2.ReceivedDSNStructureValid, embedded: dkim2.ReceivedDSNEmbeddedVerified, localHop: dkim2.ReceivedDSNLocalHopLocal, outerAlignment: dkim2.ReceivedDSNOuterAlignmentAligned, recipientLinkage: dkim2.ReceivedDSNRecipientLinkageLinked, propagation: dkim2.ReceivedDSNPropagationTerminalOrigin, valid: true}, stage: receivedDSNStagePreviousHop, result: receivedDSNResultOK},
	} {
		stage, result := receivedDSNObservation(testCase.projection)
		if stage != testCase.stage || result != testCase.result {
			t.Fatalf("%s observation = %s/%s, want %s/%s", name, stage, result, testCase.stage, testCase.result)
		}
	}
}

// TestReceivedDSNCandidateGate proves the classification gate over exact
// header shapes: folded Content-Type fields, LF-only headers, parameter case,
// and the envelope conditions. A duplicated Content-Type stays a candidate in
// either order, because the library parser is the single authority that
// refuses it as a malformed structure; selecting one field here would hide
// the notification from the evaluation and from the policy that rejects it.
func TestReceivedDSNCandidateGate(t *testing.T) {
	report := "Content-Type: multipart/report;\r\n\treport-type=Delivery-Status; boundary=b\r\n\r\nbody"
	cases := []struct {
		name    string
		raw     string
		reverse string
		paths   int
		want    bool
	}{
		{name: "folded report", raw: report, reverse: "<>", paths: 1, want: true},
		{name: "lf only", raw: strings.ReplaceAll(report, "\r\n", "\n"), reverse: "<>", paths: 1, want: true},
		{name: "headers only", raw: "Content-Type: multipart/report; report-type=delivery-status\r\n", reverse: "<>", paths: 1, want: true},
		{name: "duplicate field is still a candidate", raw: "Content-Type: multipart/report; report-type=delivery-status\r\nContent-Type: text/plain\r\n\r\n", reverse: "<>", paths: 1, want: true},
		{name: "duplicate field in either order", raw: "Content-Type: text/plain\r\nContent-Type: multipart/report; report-type=delivery-status\r\n\r\n", reverse: "<>", paths: 1, want: true},
		{name: "non-null sender", raw: report, reverse: "<x@y.example>", paths: 1, want: false},
		{name: "two recipients", raw: report, reverse: "<>", paths: 2, want: false},
		{name: "other report type", raw: "Content-Type: multipart/report; report-type=disposition-notification\r\n\r\n", reverse: "<>", paths: 1, want: false},
		{name: "no content type", raw: "Subject: x\r\n\r\n", reverse: "<>", paths: 1, want: false},
		{name: "malformed media type", raw: "Content-Type: multipart/report; report-type\r\n\r\n", reverse: "<>", paths: 1, want: false},
		{name: "oversized header", raw: "X-Pad: " + strings.Repeat("a", receivedDSNMaxHeaderBytes) + "\r\n" + report, reverse: "<>", paths: 1, want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			paths := make([][]byte, testCase.paths)
			for index := range paths {
				paths[index] = []byte("<r@local.example>")
			}
			request := dkim2.NewVerifyRequest([]byte(testCase.raw), []byte(testCase.reverse), paths)
			if got := receivedDSNCandidate(request); got != testCase.want {
				t.Fatalf("candidate = %t, want %t", got, testCase.want)
			}
		})
	}
}

// TestProcessUndecodableOuterSignatureKeepsTheOuterVerdict is the reproducer
// for the process route: a received DSN whose outer DKIM2-Signature base64
// cannot be decoded is a permerror of the outer verification, and the
// received-DSN evaluation, which requires a verified outer message, must not
// run on it. The route used to run the evaluation anyway and turned its
// invalid-request error into a daemon failure instead of the verdict.
func TestProcessUndecodableOuterSignatureKeepsTheOuterVerdict(t *testing.T) {
	fixture := newReceivedDSNFixture(t)
	processor := fixture.processor(t, config.PolicyStrict, propagationTestTenant, true)
	testCase := fixture.corpus.Case(t, propagationtest.CaseRunOfOne)
	raw := breakOuterSignatureBase64(t, testCase.RawMessage(t))
	request, err := NewInboundRequest(dkim2.NewVerifyRequest(raw, []byte("<>"), [][]byte{testCase.ForwardPath(t)}), propagationTestTenant)
	if err != nil {
		t.Fatal(err)
	}
	result := process(t, processor, request)
	verification, err := result.Verification()
	if err != nil || verification.State() != dkim2.ResultStatePERMERROR {
		t.Fatalf("verification state=%q error=%v, want permerror", verification.State(), err)
	}
	if _, present := result.DeliveryStatus(); present {
		t.Fatal("an outer message that did not verify carried a delivery-status projection")
	}
}
