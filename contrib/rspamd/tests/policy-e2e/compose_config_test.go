//go:build ignore

// Copyright 2026 Christian Roessner
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestComposedFixturePreservesNumericKinds proves real YAML loading retains integer and fractional sample contracts.
func TestComposedFixturePreservesNumericKinds(t *testing.T) {
	root := t.TempDir()
	input, output := filepath.Join(root, "input.yml"), filepath.Join(root, "output.yml")
	if err := os.WriteFile(input, []byte("policy:\n  api:\n    clients: []\nthreshold: 20.0\nhops: 20\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := run([]string{output, input}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}

	var actual map[string]any
	if err := yaml.Unmarshal(data, &actual); err != nil {
		t.Fatal(err)
	}

	if _, ok := actual["threshold"].(float64); !ok {
		t.Fatalf("double threshold became %T", actual["threshold"])
	}

	if _, ok := actual["hops"].(int); !ok {
		t.Fatalf("integer bound became %T", actual["hops"])
	}
}
