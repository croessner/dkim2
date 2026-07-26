package httpjson

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const validMinimalProcessJSON = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","message":{"raw_rfc5322_base64":""},"smtp":{"mail_from":"","rcpt_to":[""]}}`

// TestRequestValidatorUsesEmbeddedContractAndPrivateAuthentication proves the runtime seam.
func TestRequestValidatorUsesEmbeddedContractAndPrivateAuthentication(t *testing.T) {
	t.Parallel()
	validator, err := NewRequestValidator()
	if err != nil {
		t.Fatalf("NewRequestValidator() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/v1/process", nil)
	request.Header.Set(headerContentType, testContentTypeJSON)
	if err := validator.ValidateProcess(request, []byte(validMinimalProcessJSON)); !IsValidationError(err) {
		t.Fatalf("unauthenticated ValidateProcess() error = %v", err)
	}
	request = request.WithContext(context.WithValue(request.Context(), localCapabilityMarker{}, true))
	if err := validator.ValidateProcess(request, []byte(validMinimalProcessJSON)); err != nil {
		t.Fatalf("ValidateProcess() error = %v", err)
	}
}

// TestRequestValidatorClosesSchemaFailuresWithoutDetails covers generated-contract rejection.
func TestRequestValidatorClosesSchemaFailuresWithoutDetails(t *testing.T) {
	t.Parallel()
	validator, err := NewRequestValidator()
	if err != nil {
		t.Fatalf("NewRequestValidator() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/v1/process", nil)
	request.Header.Set(headerContentType, testContentTypeJSON)
	request = request.WithContext(context.WithValue(request.Context(), localCapabilityMarker{}, true))
	for _, body := range []string{
		`{}`,
		`{"api_version":"v2"}`,
		`{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","unknown":true}`,
	} {
		if err := validator.ValidateProcess(request, []byte(body)); !IsValidationError(err) || err.Error() != validatorErrorText {
			t.Fatalf("ValidateProcess(%q) error = %v", body, err)
		}
	}
}

// TestRequestValidatorBindsOnlyTheExactProcessOperation proves route confinement.
func TestRequestValidatorBindsOnlyTheExactProcessOperation(t *testing.T) {
	t.Parallel()
	validator, err := NewRequestValidator()
	if err != nil {
		t.Fatalf("NewRequestValidator() error = %v", err)
	}
	for _, target := range []struct {
		method string
		url    string
	}{
		{method: http.MethodGet, url: "http://127.0.0.1:8080/healthz"},
		{method: http.MethodPost, url: "http://127.0.0.1:8080/healthz"},
		{method: http.MethodGet, url: "http://127.0.0.1:8080/v1/process"},
		{method: http.MethodPost, url: "http://127.0.0.1:8080/readyz"},
	} {
		request := httptest.NewRequest(target.method, target.url, nil)
		request.Header.Set(headerContentType, testContentTypeJSON)
		request = request.WithContext(context.WithValue(request.Context(), localCapabilityMarker{}, true))
		if err := validator.ValidateProcess(request, []byte(validMinimalProcessJSON)); !IsValidationError(err) {
			t.Fatalf("%s %s error = %v", target.method, target.url, err)
		}
	}
}
