package dkim2

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// TestPolicyFacadeDoesNotReparseOrEchoToxicOptions proves the public seam has no parser dependency and bounded diagnostics.
func TestPolicyFacadeDoesNotReparseOrEchoToxicOptions(t *testing.T) {
	const toxic = "TOXIC-DOMAIN\r\nDKIM2-Signature: f=feedback"
	decision, err := EvaluatePolicy(VerifyResult{}, WithPolicyMode(PolicyMode(toxic)))
	if !decision.IsZero() || !errors.Is(err, &PolicyError{code: PolicyErrorInvalidOption}) || strings.Contains(err.Error(), toxic) {
		t.Fatalf("toxic option result/error = %#v/%v", decision, err)
	}
	source, readErr := os.ReadFile("policy.go")
	if readErr != nil {
		t.Fatal("policy facade source unavailable")
	}
	for _, forbidden := range []string{"internal/parser", "internal/rawmsg", "internal/signature", "Parse(", "f="} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("policy facade contains forbidden reparse marker %q", forbidden)
		}
	}
}
