package main

import (
	"errors"
	"testing"
)

// TestPublicDiagnosticRedactsArbitraryText verifies reference diagnostics stay bounded.
func TestPublicDiagnosticRedactsArbitraryText(t *testing.T) {
	if got := publicDiagnostic(errors.New("secret /tmp/value")); got != "unknown" {
		t.Fatalf("publicDiagnostic() = %q", got)
	}
	if got := publicDiagnostic(errors.New("issues_tba")); got != "issues_tba" {
		t.Fatalf("publicDiagnostic() = %q", got)
	}
}
