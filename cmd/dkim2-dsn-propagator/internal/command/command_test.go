package command

import (
	"bytes"
	"strings"
	"testing"
)

// execute runs one isolated command tree and returns its exit and streams.
func execute(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	exit := Execute(args, &stdout, &stderr)
	return exit, stdout.String(), stderr.String()
}

// TestCommandShapeIsFrozen proves the exact public command surface.
func TestCommandShapeIsFrozen(t *testing.T) {
	exit, stdout, _ := execute("--help")
	if exit != 0 {
		t.Fatalf("help exit %d", exit)
	}
	for _, expected := range []string{
		"dkim2-dsn-propagator serve --config <absolute-path>",
		"dkim2-dsn-propagator validate --config <absolute-path>",
		"dkim2-dsn-propagator probe --config <absolute-path>",
	} {
		if !strings.Contains(stdout, expected) {
			t.Fatalf("missing %q in %q", expected, stdout)
		}
	}
}

// TestUsageErrorsAreContentFree proves diagnostics never echo caller input.
func TestUsageErrorsAreContentFree(t *testing.T) {
	exit, _, stderr := execute("serve", "--config", "relative/path.yaml")
	if exit == 0 {
		t.Fatal("a relative configuration path was accepted")
	}
	if strings.Contains(stderr, "relative/path.yaml") {
		t.Fatalf("diagnostic echoed caller input: %q", stderr)
	}
	exit, _, stderr = execute("unknown")
	if exit != 2 || strings.Contains(stderr, "unknown") {
		t.Fatalf("unknown command exit %d stderr %q", exit, stderr)
	}
}

// TestCompletionSurfaceRefused proves hidden Cobra surfaces are not exposed.
func TestCompletionSurfaceRefused(t *testing.T) {
	for _, args := range [][]string{
		{"completion", "bash"}, {"__complete", "serve"}, {"__completeNoDesc"},
	} {
		if exit, _, _ := execute(args...); exit != 2 {
			t.Fatalf("completion surface %v exit %d", args, exit)
		}
	}
}

// TestVersionSurface proves the frozen version template.
func TestVersionSurface(t *testing.T) {
	exit, stdout, _ := execute("--version")
	if exit != 0 || !strings.HasPrefix(stdout, "dkim2-dsn-propagator ") {
		t.Fatalf("version exit %d stdout %q", exit, stdout)
	}
}
