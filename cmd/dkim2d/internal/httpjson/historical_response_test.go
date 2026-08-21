package httpjson

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
)

// TestStrictHandlerReturnsMultiInstanceTestingContinue proves the generated HTTP
// boundary serializes the exact multi-hop policy row that production reached.
func TestStrictHandlerReturnsMultiInstanceTestingContinue(t *testing.T) {
	const timestamp = int64(1_700_000_000)
	raw, key := signedMultiInstanceResponseMessage(t, timestamp)
	verifier, err := dkim2.NewVerifier(
		selectedMatrixProvider{key: key, outcome: selectedProviderFound},
		dkim2.WithVerificationClock(func() time.Time { return time.Unix(timestamp, 0) }),
	)
	if err != nil {
		t.Fatal("historical HTTP verifier construction failed")
	}
	domain, err := app.NewDomainProcessor(verifier, config.PolicyTesting)
	if err != nil {
		t.Fatal("historical HTTP domain processor construction failed")
	}
	processor, err := app.NewInboundProcessor(domain, app.NewDisabledReplayCoordinator())
	if err != nil {
		t.Fatal("historical HTTP inbound processor construction failed")
	}
	adapter, err := newStrictAdapter(&adapterReadinessStub{}, processor)
	if err != nil {
		t.Fatal("historical HTTP adapter construction failed")
	}
	server := httptest.NewServer(generated.Handler(generated.NewStrictHandler(
		adapter,
		[]generated.StrictMiddlewareFunc{testWorkingSetMiddleware},
	)))
	t.Cleanup(server.Close)

	body := `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04",` +
		`"message":{"raw_rfc5322_base64":"` + base64.StdEncoding.EncodeToString(raw) +
		`","fidelity":"milter_reconstructed_crlf"},` +
		`"smtp":{"mail_from":"<sender@example.test>","rcpt_to":["<rcpt@example.test>"]},` +
		`"reporting":{"authserv_id":"mx.example.test"}}`
	request, err := http.NewRequestWithContext(
		t.Context(), http.MethodPost, server.URL+testProcessPath, strings.NewReader(body),
	)
	if err != nil {
		t.Fatal("historical HTTP request construction failed")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal("historical HTTP request failed")
	}
	wireBody, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("historical HTTP response status=%d read=%v close=%v", response.StatusCode, readErr, closeErr)
	}
	var decoded generated.ProcessResponse
	if err = json.Unmarshal(wireBody, &decoded); err != nil {
		t.Fatal("historical HTTP response was not generated ProcessResponse JSON")
	}
	if decoded.Verification.State != generated.PASS || decoded.Verification.Scope != generated.Chain ||
		decoded.Policy.Mode != generated.Testing || decoded.Policy.Verdict != generated.PolicyResultVerdictContinue ||
		decoded.Policy.DoNotModify != generated.PolicyResultDoNotModifyNotRequested ||
		decoded.Policy.DoNotExplode != generated.PolicyResultDoNotExplodeNotRequested ||
		decoded.Policy.Feedback.HistoryCoverage != generated.PolicyFeedbackHistoryCoverageComplete ||
		decoded.Replay.Class != generated.NotChecked || decoded.Disposition != generated.DispositionContinue ||
		len(decoded.Actions) != 1 || decoded.Actions[0].Type != generated.AddHeader ||
		decoded.Actions[0].Name != generated.AuthenticationResults ||
		decoded.Actions[0].Value != testInboundPassReport {
		t.Fatal("historical HTTP response changed the authenticated continue row")
	}
}

// TestMapDomainResultAcceptsAuthenticatedMultiInstancePolicy proves a verified
// multi-instance result cannot fail only while projecting its local policy.
func TestMapDomainResultAcceptsAuthenticatedMultiInstancePolicy(t *testing.T) {
	const timestamp = int64(1_700_000_000)
	raw, key := signedMultiInstanceResponseMessage(t, timestamp)
	verifier, err := dkim2.NewVerifier(
		selectedMatrixProvider{key: key, outcome: selectedProviderFound},
		dkim2.WithVerificationClock(func() time.Time { return time.Unix(timestamp, 0) }),
	)
	if err != nil {
		t.Fatal("historical verifier construction failed")
	}
	result, err := verifier.Verify(context.Background(), dkim2.NewVerifyRequest(
		raw, []byte("<sender@example.test>"), [][]byte{[]byte("<rcpt@example.test>")},
	))
	if err != nil || !result.Valid() || result.State() != dkim2.ResultStatePASS ||
		result.Scope() != dkim2.VerificationScopeChain {
		t.Fatalf("historical verification = %q/%q, error = %v", result.State(), result.Scope(), err)
	}
	decision, err := dkim2.EvaluatePolicy(result, dkim2.WithPolicyMode(dkim2.PolicyModeTesting))
	if err != nil || !decision.Valid() || decision.Verdict() != dkim2.PolicyVerdictContinue ||
		decision.DoNotModifyCompliance() != dkim2.PolicyComplianceNotRequested ||
		decision.DoNotExplodeCompliance() != dkim2.PolicyComplianceNotRequested ||
		decision.FeedbackIntent().HistoryCoverage() != dkim2.PolicyHistoryComplete {
		t.Fatal("authentic historical policy decision was incoherent")
	}

	projection, err := MapDomainResult(result, decision)
	if err != nil {
		t.Fatalf("authentic historical result did not map: %v", err)
	}
	_, policy, valid := projection.domainValues()
	if !valid || policy.DoNotModify != generated.PolicyResultDoNotModifyNotRequested ||
		policy.DoNotExplode != generated.PolicyResultDoNotExplodeNotRequested ||
		policy.Feedback.HistoryCoverage != generated.PolicyFeedbackHistoryCoverageComplete {
		t.Fatal("historical policy projection changed authenticated coverage")
	}
}

// signedMultiInstanceResponseMessage constructs one deterministic-shape m=2
// message whose authenticated recipe removes the current body for m=1.
func signedMultiInstanceResponseMessage(t testing.TB, timestamp int64) ([]byte, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal("historical RSA key generation failed")
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatal("historical canonicalizer construction failed")
	}
	current, err := rawmsg.Parse([]byte("From: sender@example.test\r\nSubject: current history\r\n\r\nbody line\r\n"))
	if err != nil {
		t.Fatal("historical current message parse failed")
	}
	previous, err := rawmsg.Parse([]byte("From: sender@example.test\r\nSubject: current history\r\n\r\n"))
	if err != nil {
		t.Fatal("historical previous message parse failed")
	}
	currentHeader, _ := canonicalizer.HeaderHashFromMessage(current)
	currentBody, _ := canonicalizer.BodyHashFromMessage(current)
	previousHeader, _ := canonicalizer.HeaderHashFromMessage(previous)
	previousBody, _ := canonicalizer.BodyHashFromMessage(previous)
	currentHeaderDigest, currentHeaderOK := currentHeader.Digest()
	currentBodyDigest, currentBodyOK := currentBody.Digest()
	previousHeaderDigest, previousHeaderOK := previousHeader.Digest()
	previousBodyDigest, previousBodyOK := previousBody.Digest()
	if !currentHeaderOK || !currentBodyOK || !previousHeaderOK || !previousBodyOK {
		t.Fatal("historical canonical digest unavailable")
	}
	build := func(signature string) string {
		return "From: sender@example.test\r\nSubject: current history\r\n" +
			"Message-Instance: m=1; h=sha256:" + previousHeaderDigest.Base64() + ":" + previousBodyDigest.Base64() + ";\r\n" +
			"Message-Instance: m=2; h=sha256:" + currentHeaderDigest.Base64() + ":" + currentBodyDigest.Base64() +
			"; r=" + base64.StdEncoding.EncodeToString([]byte(`{"b":[]}`)) + ";\r\n" +
			"DKIM2-Signature: i=1; m=2; t=" + strconv.FormatInt(timestamp, 10) +
			"; mf=PHNlbmRlckBleGFtcGxlLnRlc3Q+; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; d=example.test; s=selector.test:rsa-sha256:" + signature +
			";\r\n\r\nbody line\r\n"
	}
	placeholder := base64.StdEncoding.EncodeToString(make([]byte, 128))
	unsigned, err := rawmsg.Parse([]byte(build(placeholder)))
	if err != nil {
		t.Fatal("historical unsigned message parse failed")
	}
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{
		Headers: unsigned.Headers(), TargetSequence: 1,
	})
	if err != nil {
		t.Fatal("historical signature input failed")
	}
	digest := sha256.Sum256(input.Bytes())
	sealed, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal("historical signature failed")
	}
	return []byte(build(base64.StdEncoding.EncodeToString(sealed))), &key.PublicKey
}
