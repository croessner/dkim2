package command

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const subprocessMarker = "DKIM2CTL_TEST_SUBPROCESS"

// TestCommandSubprocess validates stable stdout, empty stderr, and exit status.
func TestCommandSubprocess(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "private-path-marker.json")
	fixture := `{"schema":"dkim2ctl.fixture.v1","draft":"draft-ietf-dkim-dkim2-spec-04","fixture":"subprocess","cases":[{"case":"health","kind":"health","expect":{"http_status":200,"health_status":"alive"}}]}`
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal("write subprocess fixture")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("locate test executable")
	}
	command := exec.Command(executable, "-test.run=TestCommandSubprocessHelper", "--",
		"fixture", "validate", path)
	command.Env = append(os.Environ(), subprocessMarker+"=1")
	var stderr strings.Builder
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		t.Fatal("subprocess validation failed")
	}
	if stderr.Len() != 0 || strings.Contains(string(output), "private-path-marker") ||
		!strings.Contains(string(output), `"fixture":"subprocess"`) {
		t.Fatal("subprocess output violated stable privacy contract")
	}
}

// TestCommandSubprocessHelper provides the isolated command process boundary.
func TestCommandSubprocessHelper(t *testing.T) {
	if os.Getenv(subprocessMarker) != "1" {
		t.Skip("helper process")
	}
	separator := 0
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index + 1
			break
		}
	}
	os.Exit(Execute(os.Args[separator:], os.Stdout, os.Stderr))
}
