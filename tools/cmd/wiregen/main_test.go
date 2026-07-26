package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const (
	testOutputFlag  = "-output"
	testOutputName  = "out.go"
	testPackageFlag = "-package"
	testPackageName = "wire"
)

// TestRenderIsDeterministic proves target generation is byte-stable.
func TestRenderIsDeterministic(t *testing.T) {
	t.Parallel()

	first, err := render("wire")
	if err != nil {
		t.Fatalf("render first wrapper: %v", err)
	}
	second, err := render("wire")
	if err != nil {
		t.Fatalf("render second wrapper: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("successive wrapper renders differ")
	}
}

// TestRenderParity proves both target-local packages originate from identical
// behavior when their package names match.
func TestRenderParity(t *testing.T) {
	t.Parallel()

	server, err := render("wire")
	if err != nil {
		t.Fatalf("render server wrapper: %v", err)
	}
	client, err := render("wire")
	if err != nil {
		t.Fatalf("render client wrapper: %v", err)
	}
	if !bytes.Equal(server, client) {
		t.Fatal("server and client wrappers differ")
	}
}

// TestRunWritesOnlyACompleteWrapper verifies deterministic file replacement.
func TestRunWritesOnlyACompleteWrapper(t *testing.T) {
	t.Parallel()

	outputPath := filepath.Join(t.TempDir(), "nested", "protected_string.gen.go")
	if err := run([]string{testPackageFlag, testPackageName, testOutputFlag, outputPath}); err != nil {
		t.Fatalf("run generator: %v", err)
	}

	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read generated wrapper: %v", err)
	}
	want, err := render(testPackageName)
	if err != nil {
		t.Fatalf("render expected wrapper: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("written wrapper differs from rendered source")
	}
}

// TestRunRejectsUnboundedArguments verifies the command has a closed input
// surface.
func TestRunRejectsUnboundedArguments(t *testing.T) {
	t.Parallel()

	testCases := [][]string{
		nil,
		{testPackageFlag, testPackageName},
		{testOutputFlag, testOutputName},
		{testPackageFlag, "package", testOutputFlag, testOutputName},
		{testPackageFlag, "wire; injected", testOutputFlag, testOutputName},
		{testPackageFlag, testPackageName, testOutputFlag, testOutputName, "extra"},
	}
	for _, arguments := range testCases {
		if err := run(arguments); err == nil {
			t.Fatalf("run(%q) unexpectedly succeeded", arguments)
		}
	}
}
