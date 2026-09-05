package dsn

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/croessner/dkim2/internal/dsn/dsntest"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/signature"
	"github.com/croessner/dkim2/internal/verify"
)

const (
	rebuildOriginHeaders   = "From: sender@remote.example\r\nSubject: origin\r\nMessage-ID: <origin@remote.example>\r\n"
	rebuildOriginBody      = "origin body\r\n"
	rebuildCurrentHeaders  = "From: sender@remote.example\r\nSubject: forwarded\r\nMessage-ID: <origin@remote.example>\r\n"
	rebuildCurrentBody     = "forwarded body\r\n"
	rebuildFullRecipe      = `{"h":{"subject":[{"d":[" origin"]}]},"b":[{"d":["origin body"]}]}`
	rebuildHeaderRecipe    = `{"h":{"subject":[{"d":[" origin"]}]}}`
	rebuildBodyRecipe      = `{"b":[{"d":["origin body"]}]}`
	rebuildNullRecipe      = `{"h":{"subject":[{"d":[" origin"]}]},"b":null}`
	rebuildReportingMTA    = "mta.local.example"
	rebuildTimestamp       = uint64(1700003600)
	rebuildToken           = "0123456789abcdef0123456789abcdef"
	rebuildPreviousSender  = "<sender@remote.example>"
	rebuildUpstreamMarker  = "UPSTREAM-DIAGNOSTIC-MARKER"
	rebuildRemoteMTAMarker = "remote-mta.destination.example"
	// propagationFixedPartsBound bounds the fixed outer, human, and machine parts of a rebuilt report.
	propagationFixedPartsBound = 2048
	rebuildTransientStatus     = "4.4.7"
	rebuildMatchingORCPT       = "rfc822;user@local.example"
	rebuildFromName            = "from"
	rebuildSubjectName         = "subject"
	rebuildMessageIDName       = "message-id"
	rebuildOriginSubject       = " origin"
)

// propagationSpec describes one received DSN whose embedded original carries
// a reconstructable local hop run.
type propagationSpec struct {
	original       dsntest.Original
	headersOnly    bool
	deliveryStatus string
	outerRecipient string
	outerSigner    string
	// mutate optionally rewrites the built original bytes before they are embedded.
	mutate func([]byte) []byte
}

// defaultPropagationOriginal returns the forwarded two-instance chain: the
// origin signs m=1, the local forwarder rewrites Subject and body and signs
// m=2 with the recipe that restores m=1.
func defaultPropagationOriginal(recipeJSON string) dsntest.Original {
	local := receivedHop(receivedLocalDomain, receivedLocalMailFrom, receivedDestination)
	local.Instance = 2
	local.Timestamp = dsntest.DefaultTimestamp + 60
	return dsntest.Original{
		Headers: rebuildCurrentHeaders, Body: rebuildCurrentBody,
		Revisions: []dsntest.Revision{{Headers: rebuildOriginHeaders, Body: rebuildOriginBody, Recipe: recipeJSON}},
		Hops: []dsntest.Hop{
			receivedHop(receivedRemoteDomain, rebuildPreviousSender, receivedLocalRecipient),
			local,
		},
	}
}

// headerRecipeOriginal returns the chain whose forwarder changed only the
// Subject, so the origin body equals the current body.
func headerRecipeOriginal() dsntest.Original {
	original := defaultPropagationOriginal(rebuildHeaderRecipe)
	original.Revisions[0].Body = rebuildCurrentBody
	return original
}

// bodyRecipeOriginal returns the chain whose forwarder changed only the
// body, so the origin headers equal the current headers.
func bodyRecipeOriginal() dsntest.Original {
	original := defaultPropagationOriginal(rebuildBodyRecipe)
	original.Revisions[0].Headers = rebuildCurrentHeaders
	return original
}

// build renders the outer DSN bytes and returns the observed outer recipient.
func (s propagationSpec) build(t *testing.T) ([]byte, string) {
	t.Helper()
	original, err := s.original.Build()
	if err != nil {
		t.Fatalf("Original.Build() error=%v", err)
	}
	if s.mutate != nil {
		original = s.mutate(original)
	}
	contentType := string(ContentTypeRFC822)
	if s.headersOnly {
		contentType = string(ContentTypeRFC822Headers)
		original = dsntest.HeaderBlock(original)
	}
	deliveryStatus := s.deliveryStatus
	if deliveryStatus == "" {
		deliveryStatus = dsntest.FailedDeliveryStatus(receivedDestinationDomain, receivedDestinationRaw, receivedFailedStatus)
	}
	recipient := s.outerRecipient
	if recipient == "" {
		recipient = receivedLocalMailFrom
	}
	signerDomain := s.outerSigner
	if signerDomain == "" {
		signerDomain = receivedDestinationDomain
	}
	signer := receivedHop(signerDomain, "<>", recipient)
	signer.Timestamp = dsntest.DefaultTimestamp + 120
	raw, err := (dsntest.Report{
		OuterHeaders:        "Received: from destination by outer (" + rebuildUpstreamMarker + ")\r\nFrom: MAILER-DAEMON@" + signerDomain + "\r\nSubject: Undelivered Mail " + rebuildUpstreamMarker + "\r\n",
		Human:               "human readable " + rebuildUpstreamMarker,
		DeliveryStatus:      deliveryStatus,
		OriginalContentType: contentType,
		Original:            original,
		Signer:              &signer,
	}).Build()
	if err != nil {
		t.Fatalf("Report.Build() error=%v", err)
	}
	return raw, recipient
}

// mustRebuildEvaluator builds an evaluator over every fixture key.
func mustRebuildEvaluator(t *testing.T, temporaryDomain string) ReceivedEvaluator {
	t.Helper()
	verifier, _ := mustReceivedVerifier(t, temporaryDomain)
	evaluator, err := NewReceivedEvaluator(verifier, ReceivedEvaluatorConfig{})
	if err != nil {
		t.Fatalf("NewReceivedEvaluator() error=%v", err)
	}
	return evaluator
}

// mustEvaluate evaluates the spec with the local domains as authority.
func mustEvaluate(t *testing.T, evaluator ReceivedEvaluator, spec propagationSpec) ReceivedEvaluation {
	t.Helper()
	raw, recipient := spec.build(t)
	evaluation, err := evaluator.Evaluate(context.Background(), ReceivedRequest{
		Raw: raw, OuterRecipient: []byte(recipient), Authority: newReceivedAuthority(receivedLocalDomain, receivedForwardDomain),
	})
	if err != nil {
		t.Fatalf("Evaluate() error=%v", err)
	}
	return evaluation
}

// rebuildRequest binds one evaluation to the deterministic rebuild inputs.
func rebuildRequest(evaluation ReceivedEvaluation) RebuildRequest {
	return RebuildRequest{Evaluation: evaluation, ReportingMTA: rebuildReportingMTA, Timestamp: rebuildTimestamp, MessageIDToken: []byte(rebuildToken)}
}

// mustRebuild evaluates and rebuilds one spec and requires the rebuilt outcome.
func mustRebuild(t *testing.T, spec propagationSpec) (RebuiltReport, ReceivedEvaluation) {
	t.Helper()
	evaluator := mustRebuildEvaluator(t, "")
	evaluation := mustEvaluate(t, evaluator, spec)
	if evaluation.Propagation() != PropagationEligible {
		t.Fatalf("evaluation propagation=%q local_hop=%q embedded=%q", evaluation.Propagation(), evaluation.LocalHop(), evaluation.Embedded())
	}
	report, err := evaluator.Rebuild(context.Background(), rebuildRequest(evaluation))
	if err != nil || report.Outcome() != RebuildRebuilt || !report.Valid() {
		t.Fatalf("Rebuild() outcome=%q failure=%q valid=%t error=%v", report.Outcome(), report.Failure(), report.Valid(), err)
	}
	return report, evaluation
}

// mustParseRebuilt parses the rebuilt DSN through the structural parser and the strict RFC 3464 parser.
func mustParseRebuilt(t *testing.T, raw []byte) (Report, deliveryStatusReport, rawmsg.Message) {
	t.Helper()
	report, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse(rebuilt) error=%v", err)
	}
	status, ok := parseDeliveryStatusBody(report.DeliveryStatus().BodyBytes(), deliveryStatusProfileStrictSequence)
	if !ok {
		t.Fatalf("rebuilt delivery-status body rejected by the strict parser: %q", report.DeliveryStatus().BodyBytes())
	}
	embedded, err := rawmsg.Parse(report.OriginalMessage().BodyBytes())
	if err != nil {
		t.Fatalf("rawmsg.Parse(rebuilt original) error=%v", err)
	}
	return report, status, embedded
}

// TestRebuildRunOfOneSignatureRestoresPreviousState proves the single-member
// run is removed, the previous state is restored, and every outer, machine,
// and DKIM2 fact of the rebuilt report matches the specification.
func TestRebuildRunOfOneSignatureRestoresPreviousState(t *testing.T) {
	report, evaluation := mustRebuild(t, propagationSpec{original: defaultPropagationOriginal(rebuildFullRecipe)})
	if report.Form() != EvidenceFormComplete || report.SMTPUTF8Required() || !bytes.Equal(report.NextHopRecipient(), []byte(rebuildPreviousSender)) {
		t.Fatalf("form=%q smtputf8=%t next=%q", report.Form(), report.SMTPUTF8Required(), report.NextHopRecipient())
	}
	if report.SigningDomain() != evaluation.CompletionDomain() || report.SigningDomain() != receivedLocalDomain {
		t.Fatalf("signing domain=%q", report.SigningDomain())
	}
	parsed, status, embedded := mustParseRebuilt(t, report.Bytes())
	headers := parsed.RawMessage().Headers()
	for name, want := range map[string]string{
		rebuildFromName:      " Mail Delivery System <MAILER-DAEMON@" + rebuildReportingMTA + ">",
		"to":                 " " + rebuildPreviousSender,
		rebuildSubjectName:   " " + propagationSubject,
		"date":               " Tue, 14 Nov 2023 23:13:20 +0000",
		rebuildMessageIDName: " <" + rebuildToken + "@" + rebuildReportingMTA + ">",
		"auto-submitted":     " auto-replied",
		"mime-version":       " 1.0",
	} {
		field, ok := headers.LastFieldByName(name)
		if !ok || string(field.UnfoldedValue()) != want || len(headers.FieldsByName(name)) != 1 {
			t.Fatalf("outer %s=%q ok=%t", name, field.UnfoldedValue(), ok)
		}
	}
	if len(headers.FieldsByName("received")) != 0 || len(headers.FieldsByName("dkim2-signature")) != 0 || len(headers.FieldsByName("message-instance")) != 0 {
		t.Fatal("rebuilt report carries Received or protocol fields before signing")
	}
	if parsed.OriginalMessage().ContentType() != ContentTypeRFC822 {
		t.Fatalf("third part content type=%q", parsed.OriginalMessage().ContentType())
	}
	if len(status.recipients) != 1 || !bytes.Equal(status.recipients[0].finalPath, []byte(receivedLocalRecipient)) ||
		!status.recipients[0].failed() || string(status.recipients[0].status) != receivedFailedStatus || status.hasEnvelopeID || status.recipients[0].hasOriginal {
		t.Fatalf("machine part recipients=%+v envelope=%t", len(status.recipients), status.hasEnvelopeID)
	}
	deliveryStatus := string(parsed.DeliveryStatus().BodyBytes())
	if deliveryStatus != "Reporting-MTA: dns; "+rebuildReportingMTA+"\r\n\r\nFinal-Recipient: rfc822; user@local.example\r\nAction: failed\r\nStatus: "+receivedFailedStatus+"\r\n" {
		t.Fatalf("machine part=%q", deliveryStatus)
	}
	signatures, err := signature.Extract(embedded)
	if err != nil || len(signatures) != 1 || signatures[0].Sequence() != 1 || signatures[0].InstanceNumber() != 1 {
		t.Fatalf("embedded signatures=%d error=%v", len(signatures), err)
	}
	if len(embedded.Headers().FieldsByName("message-instance")) != 1 {
		t.Fatalf("embedded instances=%d", len(embedded.Headers().FieldsByName("message-instance")))
	}
	subject, _ := embedded.Headers().LastFieldByName(rebuildSubjectName)
	if string(subject.UnfoldedValue()) != rebuildOriginSubject || !bytes.Equal(embedded.Body().Bytes(), []byte(rebuildOriginBody)) {
		t.Fatalf("embedded subject=%q body=%q", subject.UnfoldedValue(), embedded.Body().Bytes())
	}
	if len(report.Bytes()) > len(mustRawSpec(t, propagationSpec{original: defaultPropagationOriginal(rebuildFullRecipe)}))+propagationFixedPartsBound {
		t.Fatal("rebuilt report exceeds the received report plus the fixed parts")
	}
}

// mustRawSpec renders the raw outer DSN of a spec.
func mustRawSpec(t *testing.T, spec propagationSpec) []byte {
	t.Helper()
	raw, _ := spec.build(t)
	return raw
}

// TestRebuildRemovesEveryRunMember proves nd= and imaginary-hop runs of
// several signatures are removed completely and the previous hop is kept byte-exact.
func TestRebuildRemovesEveryRunMember(t *testing.T) {
	previous := receivedHop(receivedRemoteDomain, rebuildPreviousSender, receivedLocalRecipient)
	nextDomainMember := receivedNextDomainHop(receivedLocalDomain, receivedForwardDomain)
	nextDomainMember.Instance = 2
	nextDomainCompletion := receivedHop(receivedForwardDomain, receivedForwardMailFrom, receivedDestination)
	nextDomainCompletion.Instance = 2
	imaginaryMember := receivedHop(receivedLocalDomain, receivedLocalMailFrom, "<relay@forward.local.example>")
	imaginaryMember.Instance = 2
	cases := []struct {
		name      string
		hops      []dsntest.Hop
		recipient string
	}{
		{"next-domain run", []dsntest.Hop{previous, nextDomainMember, nextDomainCompletion}, receivedForwardMailFrom},
		{"imaginary hop run", []dsntest.Hop{previous, imaginaryMember, nextDomainCompletion}, receivedForwardMailFrom},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			original := defaultPropagationOriginal(rebuildFullRecipe)
			original.Hops = testCase.hops
			raw, err := original.Build()
			if err != nil {
				t.Fatal(err)
			}
			previousField := extractSignatureField(t, raw, 1)
			report, evaluation := mustRebuild(t, propagationSpec{original: original, outerRecipient: testCase.recipient})
			if evaluation.LocalHopRunLength() != 2 || report.SigningDomain() != receivedForwardDomain {
				t.Fatalf("run length=%d signing domain=%q", evaluation.LocalHopRunLength(), report.SigningDomain())
			}
			_, _, embedded := mustParseRebuilt(t, report.Bytes())
			signatureFields := embedded.Headers().FieldsByName("dkim2-signature")
			if len(signatureFields) != 1 || !bytes.Equal(signatureFields[0].OriginalBytes(), previousField) {
				t.Fatalf("embedded signature fields=%d byte-exact=%t", len(signatureFields), len(signatureFields) == 1 && bytes.Equal(signatureFields[0].OriginalBytes(), previousField))
			}
			if instances := embedded.Headers().FieldsByName("message-instance"); len(instances) != 1 || !strings.HasPrefix(string(instances[0].UnfoldedValue()), " m=1;") {
				t.Fatalf("embedded instances=%d", len(instances))
			}
		})
	}
}

// LocalHopRunLength returns the number of run members for test assertions.
func (e ReceivedEvaluation) LocalHopRunLength() int {
	run, ok := e.Run()
	if !ok {
		return 0
	}
	return len(run.Members())
}

// extractSignatureField returns the raw DKIM2-Signature field with the given sequence.
func extractSignatureField(t *testing.T, raw []byte, sequence uint64) []byte {
	t.Helper()
	message, err := rawmsg.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range message.Headers().FieldsByName("dkim2-signature") {
		parsed, err := signature.Parse(field)
		if err == nil && parsed.Sequence() == sequence {
			return field.OriginalBytes()
		}
	}
	t.Fatalf("signature i=%d not found", sequence)
	return nil
}

// TestRebuildDegradesToHeadersOnly proves null recipes, body-unavailable
// transitions, and headers-only originals produce text/rfc822-headers.
func TestRebuildDegradesToHeadersOnly(t *testing.T) {
	cases := []struct {
		name string
		spec propagationSpec
	}{
		{"null recipe", propagationSpec{original: defaultPropagationOriginal(rebuildNullRecipe)}},
		{"headers-only original with header recipe", propagationSpec{original: headerRecipeOriginal(), headersOnly: true}},
		{"headers-only original with data body recipe", propagationSpec{original: defaultPropagationOriginal(rebuildFullRecipe), headersOnly: true}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			report, _ := mustRebuild(t, testCase.spec)
			if report.Form() != EvidenceFormHeadersOnly {
				t.Fatalf("form=%q", report.Form())
			}
			parsed, _, embedded := mustParseRebuilt(t, report.Bytes())
			if parsed.OriginalMessage().ContentType() != ContentTypeRFC822Headers || embedded.Framing() != rawmsg.MessageFramingHeaderOnly || embedded.Body().Len() != 0 {
				t.Fatalf("third part type=%q framing=%q body=%d", parsed.OriginalMessage().ContentType(), embedded.Framing(), embedded.Body().Len())
			}
			subject, _ := embedded.Headers().LastFieldByName(rebuildSubjectName)
			if string(subject.UnfoldedValue()) != rebuildOriginSubject {
				t.Fatalf("headers-only subject=%q", subject.UnfoldedValue())
			}
		})
	}
	complete, _ := mustRebuild(t, propagationSpec{original: headerRecipeOriginal()})
	if complete.Form() != EvidenceFormComplete {
		t.Fatalf("complete original with header recipe form=%q", complete.Form())
	}
	_, _, embedded := mustParseRebuilt(t, complete.Bytes())
	if !bytes.Equal(embedded.Body().Bytes(), []byte(rebuildCurrentBody)) {
		t.Fatal("header-only recipe changed the body")
	}
	bodyOnly, _ := mustRebuild(t, propagationSpec{original: bodyRecipeOriginal()})
	if bodyOnly.Form() != EvidenceFormComplete {
		t.Fatalf("complete original with body recipe form=%q", bodyOnly.Form())
	}
	_, _, embedded = mustParseRebuilt(t, bodyOnly.Bytes())
	subject, _ := embedded.Headers().LastFieldByName(rebuildSubjectName)
	if !bytes.Equal(embedded.Body().Bytes(), []byte(rebuildOriginBody)) || string(subject.UnfoldedValue()) != " forwarded" {
		t.Fatal("body-only recipe changed the headers or kept the body")
	}
}

// TestRebuildUnsignedFieldPolicy proves every Section 4 hash-excluded field
// above the previous hop signature is removed while excluded fields below it
// and every signed field are preserved byte-exact.
func TestRebuildUnsignedFieldPolicy(t *testing.T) {
	original := defaultPropagationOriginal(rebuildFullRecipe)
	original.Headers = "Received: from origin by remote (below-previous)\r\nX-Origin-Trace: below-previous\r\n" + rebuildCurrentHeaders
	original.Revisions[0].Headers = "Received: from origin by remote (below-previous)\r\nX-Origin-Trace: below-previous\r\n" + rebuildOriginHeaders
	original.Prepend = "Received: from local by destination (above-run)\r\nAuthentication-Results: destination.example; dkim2=pass\r\nDKIM-Signature: v=1; d=destination.example; s=sel; b=above-run\r\n"
	original.Hops[1].UnsignedAbove = "Received: from remote by local (between-run-and-previous)\r\nX-Local-Trace: between\r\nReturn-Path: <forwarded@local.example>\r\nAuto-Submitted: no\r\n"
	original.Hops[0].UnsignedAbove = "X-Remote-Trace: above-previous\r\n"
	report, _ := mustRebuild(t, propagationSpec{original: original})
	_, _, embedded := mustParseRebuilt(t, report.Bytes())
	headers := embedded.Headers()
	for _, removed := range []string{"authentication-results", "dkim-signature", "x-local-trace", "return-path", "auto-submitted", "x-remote-trace"} {
		if len(headers.FieldsByName(removed)) != 0 {
			t.Fatalf("hash-excluded field %q above the previous hop survived", removed)
		}
	}
	received := headers.FieldsByName("received")
	if len(received) != 1 || string(received[0].UnfoldedValue()) != " from origin by remote (below-previous)" {
		t.Fatalf("received fields=%d", len(received))
	}
	trace := headers.FieldsByName("x-origin-trace")
	if len(trace) != 1 || string(trace[0].UnfoldedValue()) != " below-previous" {
		t.Fatalf("x-origin-trace fields=%d", len(trace))
	}
	if strings.Contains(string(report.Bytes()), "above-run") || strings.Contains(string(report.Bytes()), "between") || strings.Contains(string(report.Bytes()), "above-previous") {
		t.Fatal("rebuilt report leaks fields above the previous hop")
	}
}

// TestRebuildStatusAndEnvelopeCopyRules proves 4.X.Y and 5.X.Y status codes
// are copied, other codes fall back to 5.0.0, a valid ENVID is copied, an
// invalid ENVID is dropped, and Original-Recipient is copied only when it
// names the previous rt= path.
func TestRebuildStatusAndEnvelopeCopyRules(t *testing.T) {
	cases := []struct {
		name          string
		status        string
		envelopeID    string
		orcpt         string
		wantStatus    string
		wantEnvelope  bool
		wantOriginal  bool
		wantOriginalV string
	}{
		{"permanent status", "5.2.2", "", "", "5.2.2", false, false, ""},
		{"transient status", rebuildTransientStatus, "", "", rebuildTransientStatus, false, false, ""},
		{"success class falls back", "2.1.5", "", "", "5.0.0", false, false, ""},
		{"valid envelope id", receivedFailedStatus, "envid-12345+2Bx", "", receivedFailedStatus, true, false, ""},
		{"invalid envelope id", receivedFailedStatus, "not xtext", "", receivedFailedStatus, false, false, ""},
		{"matching original recipient", receivedFailedStatus, "", rebuildMatchingORCPT, receivedFailedStatus, false, true, rebuildMatchingORCPT},
		{"foreign original recipient", receivedFailedStatus, "", "rfc822;other@local.example", receivedFailedStatus, false, false, ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			message := "Reporting-MTA: dns; destination.example\r\n"
			if testCase.envelopeID != "" {
				message = "Original-Envelope-Id: " + testCase.envelopeID + "\r\n" + message
			}
			group := ""
			if testCase.orcpt != "" {
				group += "Original-Recipient: " + testCase.orcpt + "\r\n"
			}
			group += "Final-Recipient: rfc822; " + receivedDestinationRaw + "\r\nAction: failed\r\nStatus: " + testCase.status + "\r\n" +
				"Remote-MTA: dns; " + rebuildRemoteMTAMarker + "\r\nDiagnostic-Code: smtp; 550 " + rebuildUpstreamMarker + "\r\n"
			report, _ := mustRebuild(t, propagationSpec{original: defaultPropagationOriginal(rebuildFullRecipe), deliveryStatus: message + "\r\n" + group})
			_, status, _ := mustParseRebuilt(t, report.Bytes())
			recipient := status.recipients[0]
			if string(recipient.status) != testCase.wantStatus || status.hasEnvelopeID != testCase.wantEnvelope || recipient.hasOriginal != testCase.wantOriginal {
				t.Fatalf("status=%q envelope=%t original=%t", recipient.status, status.hasEnvelopeID, recipient.hasOriginal)
			}
			if testCase.wantEnvelope && string(status.envelopeID) != testCase.envelopeID {
				t.Fatalf("envelope id=%q", status.envelopeID)
			}
			if testCase.wantOriginal && string(recipient.originalRecipient) != testCase.wantOriginalV {
				t.Fatalf("original recipient=%q", recipient.originalRecipient)
			}
			body := string(report.Bytes())
			if strings.Contains(body, rebuildUpstreamMarker) || strings.Contains(body, rebuildRemoteMTAMarker) {
				t.Fatal("rebuilt report carries upstream diagnostic bytes")
			}
		})
	}
}

// TestReportGenerationClosedTemplateAndFieldSets proves the fixed English
// human part, the required RFC 3464 fields, the absence of every forbidden
// field, CRLF discipline, and determinism.
func TestReportGenerationClosedTemplateAndFieldSets(t *testing.T) {
	spec := propagationSpec{original: defaultPropagationOriginal(rebuildFullRecipe)}
	first, _ := mustRebuild(t, spec)
	second, _ := mustRebuild(t, spec)
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("rebuild is not deterministic for identical inputs")
	}
	raw := first.Bytes()
	if bytes.Contains(bytes.ReplaceAll(raw, []byte("\r\n"), nil), []byte("\n")) || bytes.Contains(bytes.ReplaceAll(raw, []byte("\r\n"), nil), []byte("\r")) {
		t.Fatal("rebuilt report contains a bare CR or LF")
	}
	parsed, _, _ := mustParseRebuilt(t, raw)
	human := parsed.HumanReadable()
	if human.ContentType() != "text/plain" {
		t.Fatalf("human part type=%q", human.ContentType())
	}
	contentType, _ := human.Headers().LastFieldByName("content-type")
	language, ok := human.Headers().LastFieldByName("content-language")
	if !ok || string(language.UnfoldedValue()) != " en" || string(contentType.UnfoldedValue()) != " text/plain; charset=us-ascii" {
		t.Fatalf("human part headers type=%q language=%q", contentType.UnfoldedValue(), language.UnfoldedValue())
	}
	want := propagationHumanText(rebuildReportingMTA, propagationLanguageEnglish)
	if string(human.BodyBytes()) != want || !strings.Contains(want, rebuildReportingMTA) || strings.Contains(want, rebuildUpstreamMarker) {
		t.Fatalf("human part=%q", human.BodyBytes())
	}
	machine := string(parsed.DeliveryStatus().BodyBytes())
	for _, required := range []string{"Reporting-MTA: dns; ", "Final-Recipient: rfc822; ", "Action: failed", "Status: "} {
		if !strings.Contains(machine, required) {
			t.Fatalf("machine part lacks %q: %q", required, machine)
		}
	}
	for _, forbidden := range []string{"Remote-MTA", "Diagnostic-Code", "Will-Retry-Until", "Last-Attempt-Date", "Arrival-Date", "Final-Log-ID", "X-Postfix"} {
		if strings.Contains(machine, forbidden) {
			t.Fatalf("machine part carries forbidden field %q", forbidden)
		}
	}
	for _, unknown := range []propagationLanguage{"", "de", "EN"} {
		if unknown.Known() {
			t.Fatalf("language %q is registered", unknown)
		}
	}
}

// TestReportGenerationUpstreamBytesAreOnlyStatusAndEnvelope proves the status
// code, the ENVID, and the conditional Original-Recipient are the only bytes
// derived from the received report outside the embedded original.
func TestReportGenerationUpstreamBytesAreOnlyStatusAndEnvelope(t *testing.T) {
	deliveryStatus := "Original-Envelope-Id: envid-777\r\nReporting-MTA: dns; destination.example\r\n" +
		"Received-From-MTA: dns; " + rebuildUpstreamMarker + ".example\r\n\r\n" +
		"Original-Recipient: rfc822;user@local.example\r\nFinal-Recipient: rfc822; " + receivedDestinationRaw + "\r\nAction: failed\r\nStatus: 5.7.1\r\n" +
		"Remote-MTA: dns; " + rebuildRemoteMTAMarker + "\r\nDiagnostic-Code: smtp; 550 " + rebuildUpstreamMarker + "\r\n" +
		"Last-Attempt-Date: Tue, 14 Nov 2023 22:13:20 +0000\r\n"
	report, _ := mustRebuild(t, propagationSpec{original: defaultPropagationOriginal(rebuildFullRecipe), deliveryStatus: deliveryStatus})
	parsed, _, _ := mustParseRebuilt(t, report.Bytes())
	outside := string(parsed.RawMessage().Headers().OriginalBytes()) + string(parsed.HumanReadable().RawBytes()) + string(parsed.DeliveryStatus().RawBytes())
	for _, marker := range []string{rebuildUpstreamMarker, rebuildRemoteMTAMarker, "destination.example", "22:13:20"} {
		if strings.Contains(outside, marker) {
			t.Fatalf("upstream bytes %q reached the rebuilt report", marker)
		}
	}
	machine := string(parsed.DeliveryStatus().BodyBytes())
	if machine != "Original-Envelope-Id: envid-777\r\nReporting-MTA: dns; "+rebuildReportingMTA+"\r\n\r\nOriginal-Recipient: rfc822;user@local.example\r\nFinal-Recipient: rfc822; user@local.example\r\nAction: failed\r\nStatus: 5.7.1\r\n" {
		t.Fatalf("machine part=%q", machine)
	}
}

// TestHeaderOnlySerializerRoundTrip proves the header-only writer emits the
// exact reconstructed header block with header-only framing and rejects
// empty blocks and invalid states.
func TestHeaderOnlySerializerRoundTrip(t *testing.T) {
	message, err := rawmsg.Parse([]byte("From: a@example\r\nSubject: folded\r\n continued\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	state, err := recipe.NewState(message)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := serializeHeadersOnly(state)
	if err != nil || !bytes.Equal(rendered, message.Headers().OriginalBytes()) {
		t.Fatalf("serializeHeadersOnly()=%q error=%v", rendered, err)
	}
	reparsed, err := rawmsg.Parse(rendered)
	if err != nil || reparsed.Framing() != rawmsg.MessageFramingHeaderOnly || reparsed.Headers().Len() != 2 {
		t.Fatalf("reparsed framing=%q fields=%d error=%v", reparsed.Framing(), reparsed.Headers().Len(), err)
	}
	rendered[0] = 'X'
	if again, _ := serializeHeadersOnly(state); !bytes.Equal(again, message.Headers().OriginalBytes()) {
		t.Fatal("serializer exposed shared storage")
	}
	if _, err := serializeHeadersOnly(recipe.State{}); err == nil {
		t.Fatal("invalid state serialized")
	}
	empty, err := rawmsg.NewReconstructedHeaderBlock(nil, rawmsg.DefaultParserOptions())
	if err != nil {
		t.Fatal(err)
	}
	emptyState, err := recipe.NewHeadersOnlyState(empty)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serializeHeadersOnly(emptyState); err == nil {
		t.Fatal("empty header block serialized")
	}
	complete, err := serializeComplete(state)
	if err != nil || !bytes.Equal(complete, message.RawBytes()) {
		t.Fatalf("serializeComplete()=%q error=%v", complete, err)
	}
	if _, err := serializeComplete(emptyState); err == nil {
		t.Fatal("body-unavailable state serialized as complete")
	}
}

// TestRebuildNotReconstructableCauses proves descent and previous-hop
// failures that pass the evaluation still fail closed inside the rebuild.
func TestRebuildNotReconstructableCauses(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(dsntest.Original) dsntest.Original
		outcome RebuildOutcome
		failure RebuildFailure
	}{
		{"hash mismatch during re-proof", func(original dsntest.Original) dsntest.Original {
			// The forwarder signed a recipe that restores a state other than the one m=1 hashes.
			original.Revisions[0].Recipe = `{"h":{"subject":[{"d":[" wrong"]}]},"b":[{"d":["origin body"]}]}`
			return original
		}, RebuildNotReconstructable, RebuildFailureHashMismatch},
		{"malformed recipe", func(original dsntest.Original) dsntest.Original {
			original.Revisions[0].Recipe = `{"h":{"subject":[{"x":1}]}}`
			return original
		}, RebuildNotReconstructable, RebuildFailureRecipeInvalid},
		{"previous hop signature fails", func(original dsntest.Original) dsntest.Original {
			original.Hops[0].CorruptSignature = true
			return original
		}, RebuildNotReconstructable, RebuildFailurePreviousHopUnverified},
		{"previous hop later than completion", func(original dsntest.Original) dsntest.Original {
			original.Hops[0].Timestamp = original.Hops[1].Timestamp + 1
			return original
		}, RebuildNotReconstructable, RebuildFailurePreviousHopTimestamp},
		{"previous hop beyond maximum age", func(original dsntest.Original) dsntest.Original {
			original.Hops[0].Timestamp = original.Hops[1].Timestamp - 15*24*3600
			return original
		}, RebuildNotReconstructable, RebuildFailurePreviousHopTimestamp},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			spec := propagationSpec{original: testCase.mutate(defaultPropagationOriginal(rebuildFullRecipe))}
			evaluator := mustRebuildEvaluator(t, "")
			raw, recipient := spec.build(t)
			evaluation, err := evaluator.Evaluate(context.Background(), ReceivedRequest{Raw: raw, OuterRecipient: []byte(recipient), Authority: newReceivedAuthority(receivedLocalDomain)})
			if err != nil || evaluation.Propagation() != PropagationEligible {
				t.Fatalf("evaluation propagation=%q error=%v", evaluation.Propagation(), err)
			}
			report, err := evaluator.Rebuild(context.Background(), rebuildRequest(evaluation))
			if err != nil || report.Outcome() != testCase.outcome || report.Failure() != testCase.failure || !report.Valid() {
				t.Fatalf("Rebuild() outcome=%q failure=%q valid=%t error=%v", report.Outcome(), report.Failure(), report.Valid(), err)
			}
			if report.Bytes() != nil || report.NextHopRecipient() != nil || report.SigningDomain() != "" {
				t.Fatal("failed rebuild exposed output")
			}
		})
	}
}

// TestRebuildTemporaryAndForbiddenOutcomes proves a temporary key failure at
// the previous hop is temporary and a null previous sender never rebuilds.
func TestRebuildTemporaryAndForbiddenOutcomes(t *testing.T) {
	evaluator := mustRebuildEvaluator(t, receivedRemoteDomain)
	evaluation := mustEvaluate(t, evaluator, propagationSpec{original: defaultPropagationOriginal(rebuildFullRecipe)})
	if evaluation.Propagation() != PropagationEligible {
		t.Fatalf("evaluation propagation=%q", evaluation.Propagation())
	}
	report, err := evaluator.Rebuild(context.Background(), rebuildRequest(evaluation))
	if err != nil || report.Outcome() != RebuildTemporary || !report.Valid() {
		t.Fatalf("temporary rebuild outcome=%q error=%v", report.Outcome(), err)
	}
	nullSender := defaultPropagationOriginal(rebuildFullRecipe)
	nullSender.Hops[0].MailFrom = "<>"
	forbidden := mustEvaluate(t, mustRebuildEvaluator(t, ""), propagationSpec{original: nullSender})
	if forbidden.Propagation() != PropagationForbiddenNullPreviousSender {
		t.Fatalf("null sender propagation=%q", forbidden.Propagation())
	}
	if _, err := mustRebuildEvaluator(t, "").Rebuild(context.Background(), rebuildRequest(forbidden)); !IsRebuildErrorCode(err, RebuildErrorNotEligible) {
		t.Fatalf("Rebuild(forbidden evaluation) error=%v", err)
	}
}

// TestRebuildRejectsInvalidRequests proves preflight validation of the
// evaluation, reporting MTA, timestamp, token, and cancellation.
func TestRebuildRejectsInvalidRequests(t *testing.T) {
	evaluator := mustRebuildEvaluator(t, "")
	evaluation := mustEvaluate(t, evaluator, propagationSpec{original: defaultPropagationOriginal(rebuildFullRecipe)})
	valid := rebuildRequest(evaluation)
	for name, mutate := range map[string]func(*RebuildRequest){
		"zero evaluation":         func(r *RebuildRequest) { r.Evaluation = ReceivedEvaluation{} },
		"uppercase reporting mta": func(r *RebuildRequest) { r.ReportingMTA = "MTA.local.example" },
		"empty reporting mta":     func(r *RebuildRequest) { r.ReportingMTA = "" },
		"zero timestamp":          func(r *RebuildRequest) { r.Timestamp = 0 },
		"empty token":             func(r *RebuildRequest) { r.MessageIDToken = nil },
		"token with specials":     func(r *RebuildRequest) { r.MessageIDToken = []byte("bad token<>") },
		"short token":             func(r *RebuildRequest) { r.MessageIDToken = []byte("abc") },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			if _, err := evaluator.Rebuild(context.Background(), request); !IsRebuildErrorCode(err, RebuildErrorInvalidRequest) && !IsRebuildErrorCode(err, RebuildErrorNotEligible) {
				t.Fatalf("invalid request accepted: %v", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := evaluator.Rebuild(ctx, valid); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled rebuild error=%v", err)
	}
	if _, err := (ReceivedEvaluator{}).Rebuild(context.Background(), valid); err == nil {
		t.Fatal("zero evaluator rebuilt")
	}
	notLocal := mustEvaluate(t, evaluator, propagationSpec{original: defaultPropagationOriginal(rebuildFullRecipe), outerSigner: receivedOtherDomain})
	if notLocal.Propagation() == PropagationEligible {
		t.Fatal("misaligned outer signer is eligible")
	}
	if _, err := evaluator.Rebuild(context.Background(), rebuildRequest(notLocal)); !IsRebuildErrorCode(err, RebuildErrorNotEligible) {
		t.Fatalf("ineligible evaluation error=%v", err)
	}
}

// TestRebuildImmutabilityPrivacyAndConcurrency proves output accessors
// return copies, formatting is redacted, errors carry no content, and
// concurrent rebuilds of one evaluation are independent.
func TestRebuildImmutabilityPrivacyAndConcurrency(t *testing.T) {
	report, evaluation := mustRebuild(t, propagationSpec{original: defaultPropagationOriginal(rebuildFullRecipe)})
	first := report.Bytes()
	first[0] = 'Z'
	if bytes.Equal(report.Bytes(), first) {
		t.Fatal("Bytes() exposed shared storage")
	}
	next := report.NextHopRecipient()
	next[1] = 'Z'
	if bytes.Equal(report.NextHopRecipient(), next) {
		t.Fatal("NextHopRecipient() exposed shared storage")
	}
	if rendered := sprintReport(report); rendered != strings.Repeat(rebuiltReportRedactedText+" ", 2)+rebuiltReportRedactedText || report.GoString() != rebuiltReportRedactedText {
		t.Fatalf("formatting leaked: %q", rendered)
	}
	shape := regexp.MustCompile(`^dsn rebuild error: code=[a-z_]+$`)
	if err := newRebuildError(RebuildErrorInvalidRequest, nil); !shape.MatchString(err.Error()) {
		t.Fatalf("error shape=%q", err.Error())
	}
	evaluator := mustRebuildEvaluator(t, "")
	var wait sync.WaitGroup
	results := make([][]byte, 8)
	for index := range results {
		wait.Add(1)
		go func(slot int) {
			defer wait.Done()
			rebuilt, err := evaluator.Rebuild(context.Background(), rebuildRequest(evaluation))
			if err == nil && rebuilt.Outcome() == RebuildRebuilt {
				results[slot] = rebuilt.Bytes()
			}
		}(index)
	}
	wait.Wait()
	for _, result := range results {
		if !bytes.Equal(result, report.Bytes()) {
			t.Fatal("concurrent rebuild produced different bytes")
		}
	}
}

// sprintReport formats a report through the fmt verbs.
func sprintReport(report RebuiltReport) string {
	return fmt.Sprintf("%v %s %+v", report, report, report)
}

// TestRebuildHistoricalOutcomeMapping proves every historical-target outcome
// maps onto its own closed rebuild failure, so custody and null-sender
// outcomes are never reported as an alignment failure of the previous hop.
func TestRebuildHistoricalOutcomeMapping(t *testing.T) {
	for outcome, want := range map[verify.HistoricalTargetOutcome]RebuildFailure{
		verify.HistoricalTargetHashMismatch:        RebuildFailurePreviousHopUnverified,
		verify.HistoricalTargetSignatureUnverified: RebuildFailurePreviousHopUnverified,
		verify.HistoricalTargetTimestampRejected:   RebuildFailurePreviousHopTimestamp,
		verify.HistoricalTargetAlignmentRejected:   RebuildFailurePreviousHopAlignment,
		verify.HistoricalTargetCustodyRejected:     RebuildFailureCustodyRejected,
		verify.HistoricalTargetNullSender:          RebuildFailureNullPreviousSender,
	} {
		report, stop := rebuildReportForHistoricalOutcome(outcome)
		if !stop || report.Outcome() != RebuildNotReconstructable || report.Failure() != want {
			t.Fatalf("outcome %q mapped to %q/%q", outcome, report.Outcome(), report.Failure())
		}
	}
	if report, stop := rebuildReportForHistoricalOutcome(verify.HistoricalTargetTemporary); !stop || report.Outcome() != RebuildTemporary {
		t.Fatal("temporary outcome did not stop as temporary")
	}
	if _, stop := rebuildReportForHistoricalOutcome(verify.HistoricalTargetVerified); stop {
		t.Fatal("verified outcome stopped the rebuild")
	}
}

// TestRebuildErrorVocabulary proves the closed rebuild vocabularies and the typed error wiring.
func TestRebuildErrorVocabulary(t *testing.T) {
	for _, code := range []RebuildErrorCode{RebuildErrorInvalidRequest, RebuildErrorNotEligible, RebuildErrorCanceled, RebuildErrorInternal} {
		if !code.Known() {
			t.Fatalf("code %q unknown", code)
		}
	}
	if RebuildErrorCode("x").Known() || RebuildOutcome("x").Known() || RebuildFailure("x").Known() {
		t.Fatal("unknown vocabulary value accepted")
	}
	for _, outcome := range []RebuildOutcome{RebuildRebuilt, RebuildNotReconstructable, RebuildTemporary} {
		if !outcome.Known() {
			t.Fatalf("outcome %q unknown", outcome)
		}
	}
	for _, failure := range []RebuildFailure{
		RebuildFailureRecipeInvalid, RebuildFailureApplicationInvalid, RebuildFailureSourceUnavailable, RebuildFailureLimitExceeded,
		RebuildFailureHashMismatch, RebuildFailureUnsupportedHash, RebuildFailurePreviousHopUnverified, RebuildFailurePreviousHopTimestamp,
		RebuildFailurePreviousHopAlignment, RebuildFailureCustodyRejected, RebuildFailureNullPreviousSender, RebuildFailureAmbiguousPreviousRecipient,
		RebuildFailureSourceRoute, RebuildFailureProtocolFieldsAltered, RebuildFailureInternal,
	} {
		if !failure.Known() {
			t.Fatalf("failure %q unknown", failure)
		}
	}
	var typed *RebuildError
	if err := newRebuildError(RebuildErrorCanceled, context.Canceled); !errors.As(err, &typed) || !errors.Is(err, context.Canceled) || typed.Code() != RebuildErrorCanceled {
		t.Fatalf("typed error wiring=%v", err)
	}
	if verify.RunDescentFailure("").Known() {
		t.Fatal("empty descent failure known")
	}
}

// TestRebuildRefusesSourceRoutedPreviousHopPaths proves a previous hop rt= or
// mf= carrying an obsolete RFC 5321 source route is not reconstructable and
// that no source route can reach Final-Recipient or To:.
func TestRebuildRefusesSourceRoutedPreviousHopPaths(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*dsntest.Hop)
	}{
		{"source routed rt=", func(hop *dsntest.Hop) { hop.Recipients = []string{"<@relay.example:user@local.example>"} }},
		{"source routed mf=", func(hop *dsntest.Hop) { hop.MailFrom = "<@relay.example,@second.example:sender@remote.example>" }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			original := defaultPropagationOriginal(rebuildFullRecipe)
			testCase.mutate(&original.Hops[0])
			evaluator := mustRebuildEvaluator(t, "")
			evaluation := mustEvaluate(t, evaluator, propagationSpec{original: original})
			if evaluation.Propagation() != PropagationEligible {
				t.Fatalf("evaluation propagation=%q embedded=%q", evaluation.Propagation(), evaluation.Embedded())
			}
			report, err := evaluator.Rebuild(context.Background(), rebuildRequest(evaluation))
			if err != nil || report.Outcome() != RebuildNotReconstructable || report.Failure() != RebuildFailureSourceRoute || !report.Valid() {
				t.Fatalf("Rebuild() outcome=%q failure=%q error=%v", report.Outcome(), report.Failure(), err)
			}
			if report.Bytes() != nil || report.NextHopRecipient() != nil {
				t.Fatal("source-routed rebuild exposed output")
			}
		})
	}
	input := propagationReportInput{
		reportingMTA: rebuildReportingMTA, timestamp: rebuildTimestamp, token: []byte(rebuildToken),
		nextHop: []byte("<@relay.example:sender@remote.example>"), finalRecipient: []byte("user@local.example"),
		status: []byte(receivedFailedStatus), originalContentType: ContentTypeRFC822Headers, originalHeaders: []byte("Subject: x\r\n"),
	}
	if input.valid() {
		t.Fatal("report input accepted a source-routed next hop")
	}
	input.nextHop, input.finalRecipient = []byte(rebuildPreviousSender), []byte("@relay.example:user@local.example")
	if input.valid() {
		t.Fatal("report input accepted a source-routed final recipient")
	}
}

// TestRebuildSMTPUTF8FollowsHeaderFields proves SMTPUTF8 is required exactly
// when a header field of the rebuilt DSN carries a non-ASCII byte, that an
// 8-bit body alone only sets the separate 8BITMIME fact, and that an EAI
// previous hop mf= fails closed at signature parsing before any rebuild.
func TestRebuildSMTPUTF8FollowsHeaderFields(t *testing.T) {
	utf8Header := defaultPropagationOriginal(rebuildFullRecipe)
	utf8Header.Headers = "X-Origin-Note: caf\xc3\xa9\r\n" + utf8Header.Headers
	utf8Header.Revisions[0].Headers = "X-Origin-Note: caf\xc3\xa9\r\n" + utf8Header.Revisions[0].Headers
	report, _ := mustRebuild(t, propagationSpec{original: utf8Header})
	if !report.SMTPUTF8Required() || report.EightBitMIMERequired() {
		t.Fatalf("utf8 header smtputf8=%t 8bitmime=%t", report.SMTPUTF8Required(), report.EightBitMIMERequired())
	}
	eightBitBody := defaultPropagationOriginal(`{"h":{"subject":[{"d":[" origin"]}]},"b":[{"d":["café body"]}]}`)
	eightBitBody.Revisions[0].Body = "caf\xc3\xa9 body\r\n"
	report, _ = mustRebuild(t, propagationSpec{original: eightBitBody})
	if report.SMTPUTF8Required() || !report.EightBitMIMERequired() {
		t.Fatalf("8-bit body smtputf8=%t 8bitmime=%t", report.SMTPUTF8Required(), report.EightBitMIMERequired())
	}
	headersOnly, _ := mustRebuild(t, propagationSpec{original: eightBitBody, headersOnly: true})
	if headersOnly.SMTPUTF8Required() || headersOnly.EightBitMIMERequired() {
		t.Fatal("headers-only degradation kept a body transport fact")
	}
	if (RebuiltReport{}).EightBitMIMERequired() || notReconstructableReport(RebuildFailureInternal).SMTPUTF8Required() {
		t.Fatal("failed report exposed transport facts")
	}
	eai := propagationSpec{original: defaultPropagationOriginal(rebuildFullRecipe), mutate: func(raw []byte) []byte {
		return bytes.Replace(raw, []byte("mf="+base64.StdEncoding.EncodeToString([]byte(rebuildPreviousSender))), []byte("mf="+base64.StdEncoding.EncodeToString([]byte("<s\xc3\xa9nder@remote.example>"))), 1)
	}}
	if raw, _ := eai.build(t); bytes.Equal(raw, mustRawSpec(t, propagationSpec{original: defaultPropagationOriginal(rebuildFullRecipe)})) {
		t.Fatal("EAI mutation did not apply")
	}
	evaluation := mustEvaluate(t, mustRebuildEvaluator(t, ""), eai)
	if evaluation.Embedded() != EmbeddedUnverified || evaluation.Propagation() == PropagationEligible {
		t.Fatalf("EAI previous mf= embedded=%q propagation=%q", evaluation.Embedded(), evaluation.Propagation())
	}
}

// headerNames lists the lowercase field names of a header block in wire order.
func headerNames(headers rawmsg.HeaderBlock) []string {
	names := make([]string, 0, headers.Len())
	for _, field := range headers.Fields() {
		names = append(names, field.NameLower())
	}
	return names
}

// TestRebuildKeepsWireOrderForUntouchedNames proves the rebuilt header block
// keeps the pruned wire order for every name the run's recipes did not touch
// while a recipe-rewritten name follows the applier's regrouping at the
// position of its first wire occurrence, and a name the recipe restores
// without a wire anchor is appended after the wire-ordered fields.
func TestRebuildKeepsWireOrderForUntouchedNames(t *testing.T) {
	trace := "Received: from origin by remote (below-previous)\r\nX-Origin-Trace: below-previous\r\n"
	original := defaultPropagationOriginal(rebuildHeaderRecipe)
	original.Headers = trace + "From: sender@remote.example\r\nSubject: forwarded\r\nMessage-ID: <origin@remote.example>\r\nTo: user@local.example\r\n"
	original.Revisions[0].Headers = trace + "From: sender@remote.example\r\nSubject: origin\r\nMessage-ID: <origin@remote.example>\r\nTo: user@local.example\r\n"
	original.Revisions[0].Body = rebuildCurrentBody
	report, _ := mustRebuild(t, propagationSpec{original: original})
	_, _, embedded := mustParseRebuilt(t, report.Bytes())
	want := []string{"dkim2-signature", "message-instance", "received", "x-origin-trace", rebuildFromName, rebuildSubjectName, rebuildMessageIDName, "to"}
	if got := headerNames(embedded.Headers()); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("rebuilt header order=%v want=%v", got, want)
	}
	subject, _ := embedded.Headers().LastFieldByName(rebuildSubjectName)
	if string(subject.UnfoldedValue()) != rebuildOriginSubject {
		t.Fatalf("subject=%q", subject.UnfoldedValue())
	}
	restored := defaultPropagationOriginal(`{"h":{"x-restored":[{"d":[" value"]}],"subject":[{"d":[" origin"]}]},"b":[{"d":["origin body"]}]}`)
	restored.Headers = trace + rebuildCurrentHeaders
	restored.Revisions[0].Headers = trace + "From: sender@remote.example\r\nSubject: origin\r\nMessage-ID: <origin@remote.example>\r\nX-Restored: value\r\n"
	report, _ = mustRebuild(t, propagationSpec{original: restored})
	_, _, embedded = mustParseRebuilt(t, report.Bytes())
	want = []string{"dkim2-signature", "message-instance", "received", "x-origin-trace", rebuildFromName, rebuildSubjectName, rebuildMessageIDName, "x-restored"}
	if got := headerNames(embedded.Headers()); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("restored header order=%v want=%v", got, want)
	}
	untouched, _ := mustRebuild(t, propagationSpec{original: bodyRecipeOriginal()})
	_, _, embedded = mustParseRebuilt(t, untouched.Bytes())
	if got := headerNames(embedded.Headers()); strings.Join(got, ",") != "dkim2-signature,message-instance,from,subject,message-id" {
		t.Fatalf("body-only recipe header order=%v", got)
	}
}

// TestRebuildWireOrderFailsClosedOnDivergentUntouchedGroups proves the
// wire-order restoration refuses a floor state whose untouched name group
// differs from the pruned wire group instead of guessing an order.
func TestRebuildWireOrderFailsClosedOnDivergentUntouchedGroups(t *testing.T) {
	options := rawmsg.DefaultParserOptions()
	pruned, err := rawmsg.NewReconstructedHeaderBlock([][]byte{[]byte("A: 1\r\n"), []byte("B: 1\r\n"), []byte("A: 2\r\n")}, options)
	if err != nil {
		t.Fatal(err)
	}
	floorHeaders, err := rawmsg.NewReconstructedHeaderBlock([][]byte{[]byte("A: 2\r\n"), []byte("A: 1\r\n"), []byte("B: rewritten\r\n")}, options)
	if err != nil {
		t.Fatal(err)
	}
	floor, err := recipe.NewHeadersOnlyState(floorHeaders)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restoreWireOrder(pruned, floor, []string{"b"}); err == nil {
		t.Fatal("divergent untouched group accepted")
	}
	ordered, err := restoreWireOrder(pruned, floor, []string{"a", "b"})
	if err != nil {
		t.Fatalf("restoreWireOrder() error=%v", err)
	}
	if got := headerNames(ordered.Headers()); strings.Join(got, ",") != "a,a,b" || !bytes.Equal(ordered.Headers().Fields()[0].OriginalBytes(), []byte("A: 2\r\n")) {
		t.Fatalf("rewritten groups order=%v", got)
	}
}

// TestPropagationFixedPartsBoundCoversWorstCase proves the fixed outer,
// human, and machine parts of a rebuilt report never exceed the exported
// bound even with every bounded value at its ceiling, and that an
// Original-Recipient beyond its ceiling is refused rather than rendered.
func TestPropagationFixedPartsBoundCoversWorstCase(t *testing.T) {
	label := strings.Repeat("a", 63)
	reportingMTA := strings.Repeat(label+".", 3) + strings.Repeat("g", 61)
	if len(reportingMTA) != 253 {
		t.Fatalf("reporting mta length=%d", len(reportingMTA))
	}
	nextHop := "<" + strings.Repeat("x", 64) + "@" + strings.Repeat("d", 62) + "." + strings.Repeat("e", 63) + "." + strings.Repeat("f", 60) + ">"
	if len(nextHop) > signature.MaxEnvelopePathBytes || !signature.ValidEnvelopePath([]byte(nextHop), false) {
		t.Fatalf("next hop length=%d", len(nextHop))
	}
	input := propagationReportInput{
		reportingMTA: reportingMTA, timestamp: rebuildTimestamp, token: []byte(strings.Repeat("t", propagationMaxTokenBytes)),
		nextHop: []byte(nextHop), finalRecipient: []byte(nextHop[1 : len(nextHop)-1]), status: []byte("5.7.1"),
		envelopeID: []byte(strings.Repeat("+2B", propagationMaxEnvelopeIDBytes/3)), hasEnvelopeID: true,
		originalRecipient: []byte("rfc822;" + strings.Repeat("+2B", 64) + "@" + nextHop[strings.IndexByte(nextHop, '@')+1:len(nextHop)-1]), hasOriginal: true,
		originalContentType: ContentTypeRFC822Headers, originalHeaders: []byte("Subject: x\r\n"),
	}
	rendered, err := renderPropagationReport(input)
	if err != nil {
		t.Fatalf("renderPropagationReport() error=%v", err)
	}
	if fixed := len(rendered.raw) - len(input.originalHeaders); fixed > PropagationFixedPartsBound {
		t.Fatalf("fixed parts=%d exceed bound %d", fixed, PropagationFixedPartsBound)
	}
	oversized := input
	oversized.originalRecipient = []byte("rfc822;" + strings.Repeat("+2B", propagationMaxOriginalRecipientBytes/3))
	if oversized.valid() {
		t.Fatal("oversized Original-Recipient accepted")
	}
	if _, err := renderPropagationReport(oversized); err == nil {
		t.Fatal("oversized Original-Recipient rendered")
	}
}

// TestRebuildBoundsSizeAmplification proves the rebuild refuses to emit a
// report larger than the received report plus the fixed parts, the size
// property the specification guarantees, and that a rebuilt report stays
// within that bound even when the descent restores large signed fields.
func TestRebuildBoundsSizeAmplification(t *testing.T) {
	pad := "X-Pad: " + strings.Repeat("p", 900) + "\r\n"
	restored := defaultPropagationOriginal(`{"h":{"subject":[{"d":[" origin"]}],"x-pad":[{"c":[1,1]}]},"b":[{"d":["origin body"]}]}`)
	restored.Headers = pad + rebuildCurrentHeaders
	restored.Revisions[0].Headers = pad + rebuildOriginHeaders
	spec := propagationSpec{original: restored}
	report, evaluation := mustRebuild(t, spec)
	received := len(mustRawSpec(t, spec))
	if len(report.Bytes()) > received+PropagationFixedPartsBound {
		t.Fatal("rebuilt report exceeds the received report plus the fixed parts")
	}
	evaluator := mustRebuildEvaluator(t, "")
	shrunk := evaluation
	shrunk.receivedBytes = len(report.Bytes()) - PropagationFixedPartsBound - 1
	limited, err := evaluator.Rebuild(context.Background(), rebuildRequest(shrunk))
	if err != nil || limited.Outcome() != RebuildNotReconstructable || limited.Failure() != RebuildFailureLimitExceeded || limited.Bytes() != nil {
		t.Fatalf("over-bound rebuild outcome=%q failure=%q error=%v", limited.Outcome(), limited.Failure(), err)
	}
	exact := evaluation
	exact.receivedBytes = len(report.Bytes()) - PropagationFixedPartsBound
	if again, err := evaluator.Rebuild(context.Background(), rebuildRequest(exact)); err != nil || again.Outcome() != RebuildRebuilt {
		t.Fatalf("at-bound rebuild outcome=%q error=%v", again.Outcome(), err)
	}
}
