package command

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/testclient"
)

// TestCommandSurfaceFreezesInitialSubcommands checks the closed command shape.
func TestCommandSurfaceFreezesInitialSubcommands(t *testing.T) {
	t.Parallel()
	root := NewRoot(&bytes.Buffer{}, &bytes.Buffer{})
	names := make([]string, 0, len(root.Commands()))
	for _, command := range root.Commands() {
		if !command.IsAvailableCommand() {
			continue
		}
		names = append(names, command.Name())
	}
	if !slices.Equal(names, []string{commandFixture, commandSmoke}) {
		t.Fatalf("unexpected root command surface")
	}
	fixture, _, err := root.Find([]string{commandFixture})
	if err != nil {
		t.Fatal("fixture group unavailable")
	}
	names = names[:0]
	for _, command := range fixture.Commands() {
		names = append(names, command.Name())
	}
	if !slices.Equal(names, []string{"run", "validate"}) {
		t.Fatal("unexpected fixture command surface")
	}
}

// TestFixtureValidationDoesNotOpenCapabilityOrNetwork proves the complete
// command boundary remains offline even when both paths name absent resources.
func TestFixtureValidationDoesNotOpenCapabilityOrNetwork(t *testing.T) {
	t.Parallel()
	fixturePath := filepath.Join(t.TempDir(), "fixture.json")
	fixture := `{"schema":"dkim2ctl.fixture.v1","draft":"draft-ietf-dkim-dkim2-spec-05",` +
		`"fixture":"offline","cases":[{"case":"health","kind":"health",` +
		`"expect":{"http_status":200,"health_status":"alive"}}]}`
	if err := os.WriteFile(fixturePath, []byte(fixture), 0o600); err != nil {
		t.Fatal("write offline fixture")
	}
	missingCapability := filepath.Join(t.TempDir(), "missing-capability")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Execute([]string{
		"--server-url", "http://127.0.0.1:1",
		"--capability-file", missingCapability,
		"fixture", "validate", fixturePath,
	}, &stdout, &stderr)
	if code != int(testclient.ExitOK) || stderr.Len() != 0 ||
		!bytes.Contains(stdout.Bytes(), []byte(`"fixture":"offline"`)) {
		t.Fatal("offline fixture validation accessed an external resource")
	}
}

// TestUsageFailureProducesNoProtectedDiagnostic checks stable command failure.
func TestUsageFailureProducesNoProtectedDiagnostic(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Execute([]string{"--server-url", "http://example.test:8080", "smoke"}, &stdout, &stderr); code != int(testclient.ExitUsage) {
		t.Fatal("unexpected usage exit")
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"error_class":"usage"`)) || stderr.Len() != 0 {
		t.Fatal("usage validation did not emit only the stable JSONL diagnostic")
	}
}

// TestUnknownRootArgumentFailsWithoutEcho freezes fail-closed root dispatch.
func TestUnknownRootArgumentFailsWithoutEcho(t *testing.T) {
	t.Parallel()
	const marker = "privacy-container-output-7f3c9a2d"
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Execute([]string{marker}, &stdout, &stderr); code != int(testclient.ExitUsage) {
		t.Fatal("unknown root argument did not fail with usage status")
	}
	if bytes.Contains(stdout.Bytes(), []byte(marker)) ||
		bytes.Contains(stderr.Bytes(), []byte(marker)) {
		t.Fatal("unknown root argument leaked into command output")
	}
}
