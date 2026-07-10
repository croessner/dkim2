package verify

import (
	"errors"
	"strings"
	"testing"
)

// TestErrorStringIsBoundedAndSecretSafe verifies diagnostics avoid raw values.
func TestErrorStringIsBoundedAndSecretSafe(t *testing.T) {
	err := newError(ErrorCodeLimitExceeded, ErrorLocation{
		Check:          CheckKindSignature,
		SignatureIndex: -7,
		TargetSequence: 3,
		InstanceNumber: 2,
	}, ErrorDetails{
		Class:      ErrorClassLimit,
		Algorithm:  "rsa-sha256:raw-signature-secret",
		Status:     CheckStatus("decoded recipient list"),
		LimitName:  "max_signature_sets:secret",
		Limit:      -1,
		Count:      -2,
		TargetName: "dkim2_signature raw header value",
	}, errors.New("raw body secret should remain wrapped only"))

	text := err.Error()
	for _, forbidden := range []string{
		"raw-signature-secret",
		"decoded recipient list",
		"max_signature_sets:secret",
		"raw header value",
		"raw body secret",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("Error() leaked %q in %q", forbidden, text)
		}
	}
	if !strings.Contains(text, "code=limit_exceeded") || !strings.Contains(text, "class=limit") {
		t.Fatalf("Error() = %q, want stable code and class", text)
	}
	if err.Location().SignatureIndex != 0 {
		t.Fatalf("SignatureIndex = %d, want clamped zero", err.Location().SignatureIndex)
	}
	if err.Limit() != 0 || err.Count() != 0 {
		t.Fatalf("Limit/Count = %d/%d, want clamped zero", err.Limit(), err.Count())
	}
	if err.Algorithm() != "redacted" {
		t.Fatalf("Algorithm() = %q, want redacted", err.Algorithm())
	}
	if err.Status() != "" {
		t.Fatalf("Status() = %q, want empty unsafe status", err.Status())
	}
	if !errors.Is(err, &Error{code: ErrorCodeLimitExceeded}) {
		t.Fatal("errors.Is did not match verification error code")
	}
	if !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatal("IsErrorCode did not match verification error code")
	}
}
