package httpjson

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
)

const testInboundNoneReport = "mx.example.test; dkim2=none"

// noneCountingProvider records every key lookup so the NONE path can prove
// that it performs no DNS work.
type noneCountingProvider struct{ calls atomic.Int64 }

// LookupPublicKey counts one lookup and reports a temporary failure.
func (p *noneCountingProvider) LookupPublicKey(context.Context, dkim2.PublicKeyQuery) (dkim2.PublicKeyResult, error) {
	p.calls.Add(1)
	return dkim2.PublicKeyResult{}, dkim2.NewTemporaryProviderError()
}

// noneCountingReplay records every replay coordination so the NONE path can
// prove that it performs no replay work.
type noneCountingReplay struct{ calls atomic.Int64 }

// Coordinate counts one replay call and fails closed.
func (r *noneCountingReplay) Coordinate(context.Context, app.DomainResult) (app.ReplayOutcome, error) {
	r.calls.Add(1)
	return app.ReplayOutcome{}, &app.InboundProcessorError{}
}

// startNoneProcessServer serves /v1/process with a counting key provider and
// the supplied replay service.
func startNoneProcessServer(t *testing.T, mode config.PolicyMode, replay app.ReplayService) (*httptest.Server, *noneCountingProvider) {
	t.Helper()
	provider := &noneCountingProvider{}
	verifier, err := dkim2.NewVerifier(provider, dkim2.WithoutSubdomainFromAuthorization())
	if err != nil {
		t.Fatal("NONE verifier construction failed")
	}
	domain, err := app.NewDomainProcessor(verifier, mode)
	if err != nil {
		t.Fatal("NONE domain processor construction failed")
	}
	processor, err := app.NewInboundProcessor(domain, replay)
	if err != nil {
		t.Fatal("NONE inbound processor construction failed")
	}
	adapter, err := newStrictAdapter(&adapterReadinessStub{}, processor)
	if err != nil {
		t.Fatal("NONE adapter construction failed")
	}
	server := httptest.NewServer(generated.Handler(generated.NewStrictHandler(
		adapter,
		[]generated.StrictMiddlewareFunc{testWorkingSetMiddleware},
	)))
	t.Cleanup(server.Close)
	return server, provider
}

// postNoneProcess sends one process request and returns status and body.
func postNoneProcess(t *testing.T, server *httptest.Server, raw string, authority string) (int, []byte) {
	t.Helper()
	reporting := ""
	if authority != "" {
		reporting = `,"reporting":{"authserv_id":"` + authority + `"}`
	}
	body := `{"api_version":"v1","draft":"` + dkim2.DraftIdentifier + `",` +
		`"message":{"raw_rfc5322_base64":"` + base64.StdEncoding.EncodeToString([]byte(raw)) +
		`","fidelity":"raw_rfc5322"},` +
		`"smtp":{"mail_from":"<sender@example.test>","rcpt_to":["<rcpt@example.test>"]}` + reporting + `}`
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+testProcessPath, strings.NewReader(body))
	if err != nil {
		t.Fatal("NONE request construction failed")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal("NONE request failed")
	}
	wireBody, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal("NONE response read failed")
	}
	return response.StatusCode, wireBody
}

// TestStrictHandlerReturnsNoneWithoutDKIM2Fields proves the Draft-09 Section
// 14.1 NONE contract: HTTP 200 with the exact closed NONE shape, the bare
// dkim2=none report only when an authority is configured, and no verifier,
// policy, replay, or DNS work even under strict policy.
func TestStrictHandlerReturnsNoneWithoutDKIM2Fields(t *testing.T) {
	const unsigned = "From: sender@example.test\r\nSubject: unsigned\r\n\r\nbody\r\n"
	for _, testCase := range []struct {
		name      string
		mode      config.PolicyMode
		wantMode  generated.PolicyResultMode
		authority string
		report    string
	}{
		{name: "strict with authority", mode: config.PolicyStrict, wantMode: generated.Strict, authority: "mx.example.test", report: testInboundNoneReport},
		{name: "permissive without authority", mode: config.PolicyPermissive, wantMode: generated.Permissive},
		{name: "testing with authority", mode: config.PolicyTesting, wantMode: generated.Testing, authority: "mx.example.test", report: testInboundNoneReport},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			replay := &noneCountingReplay{}
			server, provider := startNoneProcessServer(t, testCase.mode, replay)
			status, body := postNoneProcess(t, server, unsigned, testCase.authority)
			if status != http.StatusOK {
				t.Fatalf("NONE status = %d body=%q", status, body)
			}
			if string(body) != noneWireGolden(string(testCase.wantMode), testCase.report) {
				t.Fatalf("NONE wire body = %s", body)
			}
			if provider.calls.Load() != 0 || replay.calls.Load() != 0 {
				t.Fatalf("NONE performed DNS=%d replay=%d work", provider.calls.Load(), replay.calls.Load())
			}
		})
	}
}

// noneWireGolden returns the exact committed NONE response body for one
// policy mode and optional report, so the wire contract is frozen byte for
// byte rather than re-derived from the production builder.
func noneWireGolden(mode string, report string) string {
	actions := `[]`
	if report != "" {
		actions = `[{"name":"Authentication-Results","type":"add_header","value":"` + report + `"}]`
	}
	return `{"actions":` + actions + `,"api_version":"v1",` +
		`"authentication":{"primary_reason":"none","state":"NONE"},"disposition":"continue",` +
		`"draft":"draft-ietf-dkim-dkim2-spec-09",` +
		`"policy":{"feedback":{"history_coverage":"not_evaluated","relay_required":false,"requested":false},` +
		`"findings":[{"reason":"none","severity":"info"}],"mode":"` + mode + `","primary_reason":"none","verdict":"continue"},` +
		`"replay":{"class":"not_checked"},` +
		`"verification":{"checks":[{"class":"protocol","reason":"none"}],"custody_structure":"not_evaluated",` +
		`"historical_content":"not_evaluated","historical_signatures":"not_evaluated","primary_reason":"none",` +
		`"scope":"current","signature_sets":[],"state":"NONE"}}`
}

// TestStrictHandlerVerifiesPartialDKIM2Message proves a message carrying only
// one DKIM2 field family is not NONE and keeps the verified error path.
func TestStrictHandlerVerifiesPartialDKIM2Message(t *testing.T) {
	const partial = "Message-Instance: v=1; i=1; m=1; h=sha256:" +
		"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\r\n" +
		"From: sender@example.test\r\nSubject: partial\r\n\r\nbody\r\n"
	server, _ := startNoneProcessServer(t, config.PolicyTesting, app.NewDisabledReplayCoordinator())
	status, body := postNoneProcess(t, server, partial, "mx.example.test")
	if status != http.StatusOK {
		t.Fatalf("partial status = %d body=%q", status, body)
	}
	var decoded generated.ProcessResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal("partial response was not a generated ProcessResponse")
	}
	if decoded.Verification.State == generated.NONE || decoded.Authentication.State == generated.NONE ||
		decoded.Verification.State == generated.PASS || decoded.Policy.PrimaryReason == generated.PolicyReasonNone {
		t.Fatalf("partial DKIM2 message reported %q/%q", decoded.Verification.State, decoded.Policy.PrimaryReason)
	}
}

// TestValidProcessResponseRejectsIncoherentNone proves the wire guard admits
// only the exact closed NONE shape and binds the report to it.
func TestValidProcessResponseRejectsIncoherentNone(t *testing.T) {
	base := func() generated.ProcessResponse {
		response, err := newNoneProcessResponse(generated.Strict, "mx.example.test")
		if err != nil {
			t.Fatal("NONE response construction failed")
		}
		return response
	}
	if !validProcessResponse(base()) {
		t.Fatal("canonical NONE response rejected")
	}
	if bare, err := newNoneProcessResponse(generated.Testing, ""); err != nil || !validProcessResponse(bare) || len(bare.Actions) != 0 {
		t.Fatal("reportless NONE response rejected or carried an action")
	}
	if _, err := newNoneProcessResponse("", "mx.example.test"); err == nil {
		t.Fatal("NONE response admitted an unknown policy mode")
	}
	mutations := map[string]func(*generated.ProcessResponse){
		"accept verdict": func(r *generated.ProcessResponse) {
			r.Policy.Verdict, r.Disposition = generated.PolicyResultVerdictAccept, generated.DispositionAccept
		},
		"reject verdict": func(r *generated.ProcessResponse) {
			r.Policy.Verdict, r.Disposition, r.Actions = generated.PolicyResultVerdictReject, generated.DispositionReject, nil
		},
		"policy reason":    func(r *generated.ProcessResponse) { r.Policy.PrimaryReason = generated.ProtocolPass },
		"finding severity": func(r *generated.ProcessResponse) { r.Policy.Findings[0].Severity = generated.Permanent },
		"feedback":         func(r *generated.ProcessResponse) { r.Policy.Feedback.Requested = true },
		"verification reason": func(r *generated.ProcessResponse) {
			r.Verification.PrimaryReason = generated.VerificationReasonMissingProtocol
		},
		"authentication state": func(r *generated.ProcessResponse) {
			r.Authentication.State = generated.PERMERROR
		},
		"verified state": func(r *generated.ProcessResponse) { r.Verification.State = generated.PERMERROR },
		"signature set": func(r *generated.ProcessResponse) {
			r.Verification.SignatureSets = []generated.SignatureSetResult{{
				Algorithm: generated.Unknown, Status: generated.SignatureSetResultStatusPermerror,
				Reason: generated.VerificationReasonUnsupportedAlgorithm,
			}}
		},
		"report with reason": func(r *generated.ProcessResponse) {
			r.Actions[0].Value = "mx.example.test; dkim2=none (reason=missing_protocol)"
		},
		"pass report":      func(r *generated.ProcessResponse) { r.Actions[0].Value = testInboundPassReport },
		"second action":    func(r *generated.ProcessResponse) { r.Actions = append(r.Actions, r.Actions[0]) },
		"non A-R action":   func(r *generated.ProcessResponse) { r.Actions[0].Name = generated.DKIM2Signature },
		"replay class":     func(r *generated.ProcessResponse) { r.Replay.Class = generated.Disabled },
		"delivery status":  func(r *generated.ProcessResponse) { r.DeliveryStatus = &generated.DeliveryStatusProjection{} },
		"verifier present": func(r *generated.ProcessResponse) { r.VerifierProjection = &generated.VerifierProjection{} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			response := base()
			mutate(&response)
			if validProcessResponse(response) {
				t.Fatal("incoherent NONE response accepted")
			}
		})
	}
	verified := base()
	verified.Verification.State, verified.Authentication.State = generated.PERMERROR, generated.PERMERROR
	verified.Verification.PrimaryReason = generated.VerificationReasonMissingProtocol
	verified.Authentication.PrimaryReason = generated.AuthenticationResultPrimaryReasonMissingProtocol
	verified.Actions = nil
	if validProcessResponse(verified) {
		t.Fatal("verified response admitted the NONE-only policy reason")
	}
}
