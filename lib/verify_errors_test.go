package dkim2

import (
	"errors"
	"strings"
	"testing"
)

// TestProviderErrorClassesAreClosedAndMachineReadable verifies typed classification.
func TestProviderErrorClassesAreClosedAndMachineReadable(t *testing.T) {
	classes := []ProviderErrorClass{ProviderErrorClassTemporary, ProviderErrorClassPermanent}
	want := []string{string(ProviderErrorClassTemporary), string(ProviderErrorClassPermanent)}
	for index, class := range classes {
		if string(class) != want[index] || !class.Known() {
			t.Fatalf("class %d = %q known=%v", index, class, class.Known())
		}
	}
	if ProviderErrorClass("").Known() || ProviderErrorClass("future-secret-token").Known() {
		t.Fatal("zero or unknown provider-error class reported known")
	}

	tests := []struct {
		name  string
		err   error
		class ProviderErrorClass
	}{
		{name: "temporary", err: NewTemporaryProviderError(), class: ProviderErrorClassTemporary},
		{name: "permanent", err: NewPermanentProviderError(), class: ProviderErrorClassPermanent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var classified ClassifiedProviderError
			if !errors.As(tt.err, &classified) {
				t.Fatal("provider error does not implement ClassifiedProviderError")
			}
			if classified.ProviderErrorClass() != tt.class {
				t.Fatalf("ProviderErrorClass() = %q", classified.ProviderErrorClass())
			}
			if ProviderErrorClassOf(tt.err) != tt.class {
				t.Fatalf("ProviderErrorClassOf() = %q", ProviderErrorClassOf(tt.err))
			}
		})
	}
	if ProviderErrorClassOf(errors.New("temporary")) != "" {
		t.Fatal("unclassified text error acquired a provider class")
	}
}

// TestPublicErrorsAreBoundedAndSecretSafe verifies diagnostics retain no input or cause.
func TestPublicErrorsAreBoundedAndSecretSafe(t *testing.T) {
	toxic := "RAW-PATH-SELECTOR-KEY-PROVIDER-SECRET"
	tests := []struct {
		name string
		err  error
	}{
		{name: "invalid provider", err: newAPIError(APIErrorCodeInvalidProvider)},
		{name: "invalid option", err: newAPIError(APIErrorCodeInvalidOption)},
		{name: "invalid request", err: newAPIError(APIErrorCodeInvalidRequest)},
		{name: "temporary provider", err: NewTemporaryProviderError()},
		{name: "permanent provider", err: NewPermanentProviderError()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := tt.err.Error()
			if strings.Contains(text, toxic) || len(text) > 80 {
				t.Fatalf("Error() is unsafe or unbounded: %q", text)
			}
			if errors.Unwrap(tt.err) != nil {
				t.Fatal("public error retained a cause")
			}
		})
	}
}

// TestAPIErrorCodesAreClosedAndSupportErrorsIs verifies bounded misuse errors.
func TestAPIErrorCodesAreClosedAndSupportErrorsIs(t *testing.T) {
	codes := []APIErrorCode{APIErrorCodeInvalidProvider, APIErrorCodeInvalidOption, APIErrorCodeInvalidRequest}
	want := []string{"invalid_provider", "invalid_option", "invalid_request"}
	for index, code := range codes {
		if string(code) != want[index] || !code.Known() {
			t.Fatalf("code %d = %q known=%v", index, code, code.Known())
		}
		err := newAPIError(code)
		if !errors.Is(err, &APIError{code: code}) {
			t.Fatalf("errors.Is() did not match code %q", code)
		}
		if err.Code() != code {
			t.Fatalf("Code() = %q", err.Code())
		}
	}
	if APIErrorCode("").Known() || APIErrorCode("future-secret-token").Known() {
		t.Fatal("zero or unknown API error code reported known")
	}
}

// TestNilPublicErrorsAreSafe verifies nil receivers stay bounded.
func TestNilPublicErrorsAreSafe(t *testing.T) {
	var apiErr *APIError
	if apiErr.Error() != "dkim2 API error" || apiErr.Code() != "" {
		t.Fatal("nil APIError receiver returned unsafe values")
	}
	var providerErr *providerError
	if providerErr.Error() != "public key provider error" || providerErr.ProviderErrorClass() != "" {
		t.Fatal("nil provider-error receiver returned unsafe values")
	}
}
