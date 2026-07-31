package inbound

import (
	"bytes"
	"strings"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/ipc"
)

// TestProjectRequestCopiesObservedEvidence proves the IPC and adapter ownership
// boundaries cannot alias mutable receive-time data.
func TestProjectRequestCopiesObservedEvidence(t *testing.T) {
	request, err := ipc.NewRequest(
		[]byte(strings.Repeat("a", ipc.BuildIDBytes)), ipc.SourceLocalScanObserved,
		ipc.SessionBSMTP, []byte("192.0.2.1"), 25, []byte("mail.example"),
		[]byte("esmtp"), []byte("<sender@example>"),
		[][]byte{[]byte("<recipient@example>")}, [][]byte{[]byte("Subject: value\n")},
		[]byte("body\n"),
	)
	if err != nil {
		t.Fatal("valid IPC request failed")
	}
	projected, err := ProjectRequest(request)
	if err != nil {
		t.Fatal("valid IPC projection failed")
	}
	if projected.Session() != 2 || !bytes.Equal(projected.MailFrom(), []byte("<sender@example>")) {
		t.Fatal("session or envelope projection drifted")
	}
}
