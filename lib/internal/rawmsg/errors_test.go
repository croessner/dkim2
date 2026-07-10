package rawmsg

import (
	"errors"
	"strings"
	"testing"
)

// TestParserErrorExposesStructuredClassification verifies typed parser errors.
func TestParserErrorExposesStructuredClassification(t *testing.T) {
	err := NewParserError(
		ErrorCodeBareLF,
		ErrorLocation{Offset: 12, Line: 2, Column: 4},
		ParserErrorDetails{
			Reason:     ErrorReasonPolicy,
			PolicyName: string(LineEndingPolicyStrictCRLF),
		},
	)

	if err.Code() != ErrorCodeBareLF {
		t.Fatalf("Code = %q, want %q", err.Code(), ErrorCodeBareLF)
	}
	if err.Location() != (ErrorLocation{Offset: 12, Line: 2, Column: 4}) {
		t.Fatalf("Location = %#v", err.Location())
	}
	if err.ReasonClass() != ErrorReasonPolicy {
		t.Fatalf("ReasonClass = %q, want %q", err.ReasonClass(), ErrorReasonPolicy)
	}
	if err.PolicyName() != string(LineEndingPolicyStrictCRLF) {
		t.Fatalf("PolicyName = %q", err.PolicyName())
	}
	if !IsParserErrorCode(err, ErrorCodeBareLF) {
		t.Fatal("IsParserErrorCode did not match direct parser error")
	}

	var parserErr *ParserError
	if !errors.As(err, &parserErr) {
		t.Fatal("errors.As did not expose ParserError")
	}
	if !errors.Is(err, NewParserError(ErrorCodeBareLF, ErrorLocation{}, ParserErrorDetails{})) {
		t.Fatal("errors.Is did not match parser error code")
	}
}

// TestParserErrorStringIsBoundedAndSecretSafe verifies diagnostics omit raw context.
func TestParserErrorStringIsBoundedAndSecretSafe(t *testing.T) {
	rawValue := "Subject: private body token password secret@example.test"
	err := NewParserError(
		ErrorCode("private body token"),
		ErrorLocation{Offset: 64, Line: 3, Column: 1},
		ParserErrorDetails{
			Reason:     ErrorReasonMalformed,
			PolicyName: rawValue,
			LimitName:  rawValue,
			Limit:      1024,
		},
	)

	message := err.Error()
	for _, forbidden := range []string{"private body", "password", "secret@example.test", rawValue} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("error string leaked raw context %q in %q", forbidden, message)
		}
	}
	if !strings.Contains(message, "code=redacted") {
		t.Fatalf("error string %q does not redact unsafe code", message)
	}
	if !strings.Contains(message, "offset=64") {
		t.Fatalf("error string %q does not contain bounded location", message)
	}
}
