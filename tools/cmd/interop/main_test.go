package main

import (
	"errors"
	"testing"
)

// TestRunRejectsCallerSelectedOperations freezes the closed command surface.
func TestRunRejectsCallerSelectedOperations(t *testing.T) {
	for _, arguments := range [][]string{
		nil,
		{"discover", "--command", "sh"},
		{"--root", ".", "check", "extra"},
		{"--root", ".", "publish"},
	} {
		if err := run(arguments); err == nil {
			t.Fatalf("run(%q) accepted caller authority", arguments)
		}
	}
}

// TestPublicDiagnosticRedactsUnboundedErrors freezes content-free diagnostics.
func TestPublicDiagnosticRedactsUnboundedErrors(t *testing.T) {
	if got := publicDiagnostic(errors.New("secret marker /local/path")); got != "unknown" {
		t.Fatalf("publicDiagnostic leaked hostile content: %q", got)
	}
	if got := publicDiagnostic(errors.New("registry_url")); got != "registry_url" {
		t.Fatalf("publicDiagnostic = %q", got)
	}
}
