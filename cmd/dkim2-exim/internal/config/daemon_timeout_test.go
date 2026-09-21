package config

import (
	"strings"
	"testing"
	"time"
)

// withDaemonTimeout returns one valid signing document carrying an explicit
// daemon call deadline.
func withDaemonTimeout(value string) string {
	return strings.Replace(
		validSign,
		"  sign_capability_file:",
		"  request_timeout: "+value+"\n  sign_capability_file:",
		1,
	)
}

// TestDaemonRequestTimeoutCoversDaemonRequestDeadline proves the filter can
// outwait the longest deadline dkim2d may spend on one SMTP-sized message.
// A shorter ceiling aborts the call from the client side and discards the
// daemon's own bounded availability answer.
func TestDaemonRequestTimeoutCoversDaemonRequestDeadline(t *testing.T) {
	snapshot, err := DecodeForOperation([]byte(withDaemonTimeout("1m30s")), OperationSign)
	if err != nil {
		t.Fatalf("daemon call deadline above the daemon request deadline rejected: %v", err)
	}
	if snapshot.DaemonTimeout() != 90*time.Second {
		t.Fatalf("DaemonTimeout() = %s, want 1m30s", snapshot.DaemonTimeout())
	}
	if maximumDaemonRequestTimeout <= daemonRequestDeadlineCeiling {
		t.Fatal("filter ceiling must exceed the daemon request-deadline ceiling")
	}
}

// TestDaemonRequestTimeoutBoundsStayClosed proves the exact ceiling is
// admitted and every larger, smaller or non-canonical value still fails
// closed. The filter accepts only Go's canonical duration rendering, so
// "180s" remains invalid while "3m0s" is the same deadline spelled exactly.
func TestDaemonRequestTimeoutBoundsStayClosed(t *testing.T) {
	if _, err := DecodeForOperation([]byte(withDaemonTimeout("3m0s")), OperationSign); err != nil {
		t.Fatalf("exact daemon call ceiling rejected: %v", err)
	}
	for _, value := range []string{"3m1s", "0s", "50ms", "-1s", "180s"} {
		if _, err := DecodeForOperation([]byte(withDaemonTimeout(value)), OperationSign); err == nil {
			t.Fatalf("daemon call deadline %q accepted outside its bounds", value)
		}
	}
}
