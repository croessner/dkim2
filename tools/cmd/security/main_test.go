package main

import (
	"errors"
	"testing"
)

// TestRunRejectsUnknownAndArgumentSelectingOperations freezes the closed command surface.
func TestRunRejectsUnknownAndArgumentSelectingOperations(t *testing.T) {
	for _, arguments := range [][]string{
		nil,
		{unknownDiagnostic},
		{operationFuzz, "extra"},
		{"--root", ".", operationFuzz, "--target", "FuzzAnything"},
	} {
		if err := run(arguments); err == nil {
			t.Fatalf("run(%q) accepted an invalid operation", arguments)
		}
	}
}

// TestPublicErrorRejectsRawAndMarkerBearingDiagnostics protects command output.
func TestPublicErrorRejectsRawAndMarkerBearingDiagnostics(t *testing.T) {
	for _, testCase := range []struct {
		err  error
		want string
	}{
		{err: errors.New("fuzz_failure"), want: "fuzz_failure"},
		{err: errors.New("fuzz_failure_007"), want: "fuzz_failure_007"},
		{err: errors.New("raw /protected/ marker"), want: unknownDiagnostic},
		{err: nil, want: unknownDiagnostic},
	} {
		if got := publicError(testCase.err); got != testCase.want {
			t.Fatalf("publicError() = %q, want %q", got, testCase.want)
		}
	}
}
