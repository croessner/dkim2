package filter

import (
	"bytes"
	"context"
	"os"
	"testing"
)

// TestPrivateWorkspaceUsesExactModesAndUnlinksBeforeOutput proves transient
// mail bytes have confined ownership and no surviving pathname at stdout time.
func TestPrivateWorkspaceUsesExactModesAndUnlinksBeforeOutput(t *testing.T) {
	parent := t.TempDir()
	workspace, err := newPrivateWorkspace(parent)
	if err != nil {
		t.Fatal("private workspace construction failed")
	}
	defer func() { _ = workspace.close() }()
	root := workspace.root
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o700 {
		t.Fatal("private workspace mode changed")
	}
	for _, file := range []*os.File{workspace.input, workspace.output} {
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() ||
			info.Mode().Perm() != 0o600 {
			t.Fatal("private spool file mode changed")
		}
	}
	message := []byte("Subject: private\n\nbody\x00\n")
	captured, err := workspace.capture(bytes.NewReader(message))
	if err != nil || !bytes.Equal(captured, message) {
		t.Fatal("private input spool changed message bytes")
	}
	defer clear(captured)
	if err := workspace.prepareOutput(captured); err != nil {
		t.Fatal("private output proof failed")
	}
	if err := workspace.seal(); err != nil {
		t.Fatal("private workspace unlink failed")
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("private workspace path survived before stdout")
	}
	var output bytes.Buffer
	if err := workspace.stream(context.Background(), &output); err != nil ||
		!bytes.Equal(output.Bytes(), message) {
		t.Fatal("unlinked private output could not stream exact message")
	}
}
