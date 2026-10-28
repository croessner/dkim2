package tools_test

import (
	"bytes"
	"testing"
)

// TestGateTestsBypassTheResultCache freezes uncached gate test runs, because
// the go test cache does not track repository inputs outside a module root.
func TestGateTestsBypassTheResultCache(t *testing.T) {
	makefile := readRepositoryFile(t, "Makefile", 1<<20)
	for _, required := range [][]byte{
		[]byte("GATE_TEST_FLAGS := -count=1\n"),
		[]byte("(cd $$module && go test $(GATE_TEST_FLAGS) ./...); \\\n\tdone\n\n# The tools module"),
		[]byte("test-tools:\n\t@set -e; for module in $(TOOL_MODULES); do \\\n\t\techo \"==> go test $$module/...\"; \\\n\t\t(cd $$module && go test $(GATE_TEST_FLAGS) ./...); \\\n"),
		[]byte("(cd $$module && go test $(GATE_TEST_FLAGS) -race ./...); \\\n"),
	} {
		if !bytes.Contains(makefile, required) {
			t.Fatalf("Makefile gate test recipe lost uncached execution: %q", required)
		}
	}
	for _, edge := range []struct {
		target       string
		prerequisite string
	}{
		{target: "guardrails", prerequisite: "test"},
		{target: "guardrails", prerequisite: "test-tools"},
		{target: "guardrails", prerequisite: "race"},
	} {
		prerequisites, ok := makefileRulePrerequisites(makefile, edge.target)
		if !ok || !slicesContainExact(prerequisites, edge.prerequisite) {
			t.Fatalf("Makefile target %s omitted gate %s", edge.target, edge.prerequisite)
		}
	}
}

// TestModuleProofReconstructionRunsInTheModuleProofGate keeps the host-cache
// dependent private proxy test bound to the gate that owns that precondition.
func TestModuleProofReconstructionRunsInTheModuleProofGate(t *testing.T) {
	makefile := readRepositoryFile(t, "Makefile", 1<<20)
	if !bytes.Contains(makefile, []byte(
		"test-module-proof:\n\t@go -C tools test $(GATE_TEST_FLAGS) -tags moduleproof ./internal/reference\n",
	)) {
		t.Fatal("Makefile lost the module-proof reconstruction test gate")
	}
	prerequisites, ok := makefileRulePrerequisites(makefile, "check-reference")
	if !ok || !slicesContainExact(prerequisites, "test-module-proof") {
		t.Fatal("check-reference no longer runs the module-proof reconstruction test")
	}
	source := readRepositoryFile(t, "tools/internal/reference/proxy_moduleproof_test.go", 1<<20)
	if !bytes.HasPrefix(source, []byte("//go:build moduleproof\n")) ||
		!bytes.Contains(source, []byte("func TestBuildPrivateProxyIsDeterministicAndConfined(t *testing.T) {")) {
		t.Fatal("module-proof reconstruction test is no longer bound to the moduleproof tag")
	}
}
