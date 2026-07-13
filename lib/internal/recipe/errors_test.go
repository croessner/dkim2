package recipe

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const toxicLimitMarker = "secret_marker"

// TestErrorContractBoundsLocationsAndExcludesSecrets verifies typed secret-safe diagnostics.
func TestErrorContractBoundsLocationsAndExcludesSecrets(t *testing.T) {
	err := newError(ErrorCodeInvalidLiteral, ErrorLocation{Offset: -1, StepIndex: -2, MemberIndex: -3, HeaderOrdinal: -4, BodyLine: -5}, ErrorDetails{
		Class: ErrorClassSchema, LimitName: toxicLimitMarker, Expected: -1, Actual: -2,
		Dimension: Dimension("secret@example.test"), StepKind: StepKind("private-body"),
	}, errors.New("password raw recipe"))
	if !errors.Is(err, &Error{code: ErrorCodeInvalidLiteral}) || !IsErrorCode(err, ErrorCodeInvalidLiteral) {
		t.Fatalf("typed matching failed: %v", err)
	}
	if got := err.Location(); got != (ErrorLocation{}) {
		t.Fatalf("Location() = %#v, want zero-clamped", got)
	}
	text := err.Error()
	for _, forbidden := range []string{toxicLimitMarker, "secret@example.test", "private-body", "password", "raw recipe"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("Error() leaked %q in %q", forbidden, text)
		}
	}
	if errors.Unwrap(err) != nil || err.Code() != ErrorCodeInvalidLiteral || !err.Class().Known() {
		t.Fatalf("error accessors invalid: %#v", err)
	}
	for _, rendered := range []string{fmt.Sprint(err), fmt.Sprintf("%+v", err)} {
		if strings.Contains(rendered, "password") || strings.Contains(rendered, "raw recipe") {
			t.Fatalf("formatted chain leaked toxic cause: %q", rendered)
		}
	}
}

// TestErrorLimitNamesUseAClosedAllowlist verifies syntactically plausible input tokens remain redacted.
func TestErrorLimitNamesUseAClosedAllowlist(t *testing.T) {
	for _, toxic := range []string{"password", toxicLimitMarker, strings.Repeat("a", 80)} {
		err := newError(ErrorCodeLimitExceeded, ErrorLocation{}, ErrorDetails{LimitName: toxic}, nil)
		if strings.Contains(err.Error(), toxic) || err.LimitName() != "" {
			t.Fatalf("toxic limit name escaped: %q / %q", err.Error(), err.LimitName())
		}
	}
	err := newError(ErrorCodeLimitExceeded, ErrorLocation{}, ErrorDetails{LimitName: limitNameMaxJSONTokens}, nil)
	if err.LimitName() != limitNameMaxJSONTokens || !strings.Contains(err.Error(), limitNameMaxJSONTokens) {
		t.Fatalf("closed limit missing: %q", err.Error())
	}
}

// TestErrorCodesAndClassesAreClosed verifies zero and future diagnostics cannot pass validation.
func TestErrorCodesAndClassesAreClosed(t *testing.T) {
	if ErrorCode("").Known() || ErrorCode("future").Known() || !ErrorCodeLimitExceeded.Known() {
		t.Fatal("error code vocabulary is not closed")
	}
	if ErrorClass("").Known() || ErrorClass("future").Known() || !ErrorClassLimit.Known() {
		t.Fatal("error class vocabulary is not closed")
	}
}

// TestEveryRecipeErrorCodeHasAnExplicitOperationalClass verifies the complete mapping.
func TestEveryRecipeErrorCodeHasAnExplicitOperationalClass(t *testing.T) {
	tests := []struct {
		code  ErrorCode
		class ErrorClass
	}{
		{code: ErrorCodeInvalidOptions, class: ErrorClassOptions},
		{code: ErrorCodeInvalidState, class: ErrorClassState},
		{code: ErrorCodeLimitExceeded, class: ErrorClassLimit},
		{code: ErrorCodeInvalidJSON, class: ErrorClassSyntax},
		{code: ErrorCodeDuplicateMember, class: ErrorClassSyntax},
		{code: ErrorCodeInvalidTopLevel, class: ErrorClassSyntax},
		{code: ErrorCodeMissingRecipeDimension, class: ErrorClassSchema},
		{code: ErrorCodeInvalidHeaderName, class: ErrorClassSchema},
		{code: ErrorCodeHeaderNameCollision, class: ErrorClassSchema},
		{code: ErrorCodeInvalidHeaderRecipe, class: ErrorClassSchema},
		{code: ErrorCodeInvalidBodyRecipe, class: ErrorClassSchema},
		{code: ErrorCodeInvalidStep, class: ErrorClassSchema},
		{code: ErrorCodeInvalidCopyRange, class: ErrorClassRange},
		{code: ErrorCodeCopyRangeOrder, class: ErrorClassRange},
		{code: ErrorCodeCopyRangeOutOfBounds, class: ErrorClassRange},
		{code: ErrorCodeInvalidLiteral, class: ErrorClassSchema},
		{code: ErrorCodeSourceUnavailable, class: ErrorClassSource},
	}

	for _, tc := range tests {
		t.Run(string(tc.code), func(t *testing.T) {
			if got := classForCode(tc.code); got != tc.class {
				t.Fatalf("classForCode(%q) = %q, want %q", tc.code, got, tc.class)
			}
		})
	}
	if got := classForCode(ErrorCode("future")); got != ErrorClassState {
		t.Fatalf("unknown code class = %q, want fail-safe %q", got, ErrorClassState)
	}
}
