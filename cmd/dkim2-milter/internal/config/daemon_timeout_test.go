package config

import (
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/resource"
)

// withRequestTimeout returns one valid originator document carrying an
// explicit daemon call deadline.
func withRequestTimeout(value string) string {
	return strings.Replace(
		validConfig(ModeOriginator),
		"  capability_file: /tmp/dkim2-milter.cap\n",
		"  capability_file: /tmp/dkim2-milter.cap\n  request_timeout: "+value+"\n",
		1,
	)
}

// TestDaemonRequestTimeoutCoversDaemonRequestDeadline proves the adapter can
// outwait the longest deadline dkim2d may spend on one SMTP-sized message.
// A shorter ceiling aborts the call from the client side, which discards the
// daemon's own bounded availability answer and reports an indeterminate
// operation instead.
func TestDaemonRequestTimeoutCoversDaemonRequestDeadline(t *testing.T) {
	snapshot, err := Load(writeConfig(t, withRequestTimeout("90s")))
	if err != nil {
		t.Fatalf("daemon call deadline above the daemon request deadline rejected: %v", err)
	}
	if snapshot.RequestTimeout() != 90*time.Second {
		t.Fatalf("RequestTimeout() = %s, want 90s", snapshot.RequestTimeout())
	}
	if resource.MaximumDaemonRequestTimeout <= resource.DaemonRequestDeadlineCeiling {
		t.Fatal("adapter ceiling must exceed the daemon request-deadline ceiling")
	}
}

// TestDaemonRequestTimeoutBoundsStayClosed proves the exact ceiling is
// admitted and every larger or smaller value still fails closed.
func TestDaemonRequestTimeoutBoundsStayClosed(t *testing.T) {
	if _, err := Load(writeConfig(t, withRequestTimeout("180s"))); err != nil {
		t.Fatalf("exact daemon call ceiling rejected: %v", err)
	}
	for _, value := range []string{"181s", "0s", "50ms", "-1s"} {
		if _, err := Load(writeConfig(t, withRequestTimeout(value))); err == nil {
			t.Fatalf("daemon call deadline %q accepted outside its bounds", value)
		}
	}
}
