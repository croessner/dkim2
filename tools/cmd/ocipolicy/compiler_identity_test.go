package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestInspectBinaryBuildRequiresMeasuredCompilerAndExperiment proves real embedded build identity and rejects compiler drift.
func TestInspectBinaryBuildRequiresMeasuredCompilerAndExperiment(t *testing.T) {
	directory := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  "module github.com/croessner/dkim2/cmd/dkim2d\n\ngo 1.27\n\ntoolchain go1.27.0\n",
		"main.go": "package main\nfunc main() {}\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(directory, "dkim2d")
	command := exec.Command("go", "build", "-mod=mod", "-buildvcs=false", "-trimpath", "-ldflags=-buildid=", "-o", binary, ".")
	command.Dir = directory
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch key {
		case "GOWORK", "GOTOOLCHAIN", "GOEXPERIMENT", "CGO_ENABLED", "GOOS", "GOARCH", "GOAMD64", "GOFLAGS", "GOENV":
		default:
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env, "GOWORK=off", "GOTOOLCHAIN=local", "GOEXPERIMENT=runtimesecret", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOAMD64=v1", "GOFLAGS=", "GOENV=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compiler probe failed: %v: %s", err, output)
	}
	content, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = inspectBinaryBuild("dkim2d", "linux/amd64", content); err != nil {
		t.Fatalf("real compiler identity rejected: %v", err)
	}
	stale := bytes.ReplaceAll(content, []byte("go1.27.0"), []byte("go1.26.6"))
	if bytes.Equal(stale, content) {
		t.Fatal("compiler probe lacks embedded identity")
	}
	if _, err = inspectBinaryBuild("dkim2d", "linux/amd64", stale); err == nil {
		t.Fatal("stale compiler identity accepted")
	}
	altered := bytes.ReplaceAll(content, []byte("runtimesecret"), []byte("runtimeother"))
	if _, err = inspectBinaryBuild("dkim2d", "linux/amd64", altered); err == nil {
		t.Fatal("altered experiment identity accepted")
	}
}
