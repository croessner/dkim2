package testclient

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/testclient/generated"
)

const deliveryStatusAcceptResponse = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","operation":"delivery_status","result":"pass","disposition":"accept","actions":[{"type":"add_header","name":"Message-Instance","value":"v=1; i=1; h=sha256:synthetic"},{"type":"add_header","name":"DKIM2-Signature","value":"v=1; a=ed25519-sha256; d=example.test; s=test; b=synthetic"}]}`

// TestGeneratedDSNSignRequestUsesDedicatedClientAndCapability proves DSN
// fixtures cannot reuse the ordinary signing request or credential boundary.
func TestGeneratedDSNSignRequestUsesDedicatedClientAndCapability(t *testing.T) {
	t.Parallel()
	fidelity := string(generated.RawRfc5322)
	request, err := generatedDSNSignRequest(fixtureDSNSignInput{
		OuterMessageBase64: operationFixtureMessageBase64,
		OuterFidelity:      &fidelity,
		OuterMailFrom:      "<>",
		OuterRecipients:    []string{operationFixtureRecipient},
		OriginalMailFrom:   operationFixtureSender,
		OriginalRecipients: []string{operationFixtureRecipient},
		Tenant:             operationFixtureTenant,
		Domain:             operationFixtureDomain,
	})
	if err != nil {
		t.Fatal("DSN generated request construction failed")
	}
	doer := &captureDoer{response: func(_ *http.Request) *http.Response {
		return buildHostileResponse(http.StatusOK, mediaTypeJSON, deliveryStatusAcceptResponse)
	}}
	runtime, err := NewRuntimeWithDoer("http://127.0.0.1:8080", doer)
	if err != nil {
		t.Fatal("runtime construction failed")
	}
	defer func() { _ = runtime.Close() }()
	var value [32]byte
	value[0] = 1
	capability, err := newCapability(value)
	if err != nil {
		t.Fatal("capability construction failed")
	}
	capability.operation = OperationDSNSign
	capability.header = capabilityHeaderForOperation(OperationDSNSign)
	defer func() { _ = capability.Close() }()
	fact, err := runtime.CallDSNSign(context.Background(), request, capability.EditRequest)
	if err != nil || fact.DSNSign == nil || fact.Sign != nil || fact.Revise != nil ||
		fact.Operation != OperationDSNSign {
		t.Fatal("DSN response lost route correlation")
	}
	recorded := doer.lastRequest()
	if recorded == nil || recorded.URL.Path != dsnSignPath ||
		len(recorded.Header.Values(dsnSignCapabilityHeader)) != 1 ||
		len(recorded.Header.Values(capabilityHeader)) != 0 {
		t.Fatal("DSN request escaped its dedicated capability boundary")
	}
	var document map[string]json.RawMessage
	if json.NewDecoder(recorded.Body).Decode(&document) != nil ||
		document["message"] == nil || document["outer_smtp"] == nil ||
		document["original_smtp"] == nil || document["context"] == nil ||
		document["smtp"] != nil {
		t.Fatal("DSN request did not preserve the dedicated generated DTO shape")
	}
}

// TestDSNFixtureAdmissionRequiresDistinctNullPathFacts proves DSN fixture
// validation remains offline while enforcing its dedicated envelope shape.
func TestDSNFixtureAdmissionRequiresDistinctNullPathFacts(t *testing.T) {
	t.Parallel()
	fidelity := string(generated.RawRfc5322)
	operation := string(generated.DeliveryStatus)
	result := "pass"
	disposition := "accept"
	actions := []fixtureExpectedAction{
		{Type: "add_header", Name: "Message-Instance", Value: "v=1; i=1; h=sha256:synthetic"},
		{Type: "add_header", Name: "DKIM2-Signature", Value: "v=1; b=synthetic"},
	}
	valid := fixtureCase{
		Case: "delivery-status", Kind: caseDSNSign,
		DSNSign: &fixtureDSNSignInput{
			OuterMessageBase64: operationFixtureMessageBase64,
			OuterFidelity:      &fidelity,
			OuterMailFrom:      "<>", OuterRecipients: []string{operationFixtureRecipient},
			OriginalMailFrom:   operationFixtureSender,
			OriginalRecipients: []string{operationFixtureRecipient},
			Tenant:             operationFixtureTenant, Domain: operationFixtureDomain,
		},
		Expect: fixtureExpectation{
			HTTPStatus: 200, Operation: &operation, Result: &result,
			Disposition: &disposition, Actions: &actions,
		},
	}
	if _, err := validateFixtureCase(valid); err != nil {
		t.Fatal("valid isolated DSN fixture rejected")
	}
	invalid := valid
	invalid.DSNSign = &fixtureDSNSignInput{}
	if _, err := validateFixtureCase(invalid); ExitClassOf(err) != ExitFixture {
		t.Fatal("empty DSN fixture accepted")
	}
	invalid = valid
	invalid.DSNSign = &fixtureDSNSignInput{
		OuterMessageBase64: operationFixtureMessageBase64,
		OuterFidelity:      &fidelity, OuterMailFrom: operationFixtureSender,
		OuterRecipients:    []string{operationFixtureRecipient},
		OriginalMailFrom:   operationFixtureSender,
		OriginalRecipients: []string{operationFixtureRecipient},
		Tenant:             operationFixtureTenant, Domain: operationFixtureDomain,
	}
	if _, err := validateFixtureCase(invalid); ExitClassOf(err) != ExitFixture {
		t.Fatal("non-null DSN outer envelope accepted")
	}
}

// TestDSNCapabilityEditorRejectsOrdinaryRoutes proves the distinct credential
// cannot be replayed by generated normal signing operations.
func TestDSNCapabilityEditorRejectsOrdinaryRoutes(t *testing.T) {
	t.Parallel()
	var value [32]byte
	value[0] = 1
	capability, err := newCapability(value)
	if err != nil {
		t.Fatal("capability construction failed")
	}
	capability.operation = OperationDSNSign
	capability.header = capabilityHeaderForOperation(OperationDSNSign)
	defer func() { _ = capability.Close() }()
	request := mustRequest(t, http.MethodPost, "http://127.0.0.1:8080"+dsnSignPath)
	if err := capability.EditRequest(t.Context(), request); err != nil {
		t.Fatal("DSN capability rejected its own route")
	}
	ordinary := mustRequest(t, http.MethodPost, "http://127.0.0.1:8080"+signPath)
	if err := capability.EditRequest(t.Context(), ordinary); ExitClassOf(err) != ExitInternal {
		t.Fatal("DSN capability escaped onto ordinary signing route")
	}
	if strings.Contains(capability.String(), "\x01") {
		t.Fatal("DSN capability diagnostics exposed protected bytes")
	}
}
