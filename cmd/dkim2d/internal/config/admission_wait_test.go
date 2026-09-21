package config

import (
	"strings"
	"testing"
	"time"
)

// withAdmissionWait returns one valid document carrying an explicit bounded
// wait for a process admission permit.
func withAdmissionWait(value string) string {
	return strings.Replace(
		memoryYAML("1", "capability"),
		"  max_in_flight: 1\n",
		"  max_in_flight: 1\n  admission_wait: "+value+"\n",
		1,
	)
}

// TestAdmissionWaitIsConfigurableWithinTheRequestDeadline proves an operator
// can queue a request for as long as the handler itself may run. A waiter owns
// no working-set reservation and no request body, so the wait is bounded by
// server.max_waiters and by the request deadline rather than by memory. The
// former one-second ceiling turned every concurrent arrival into an immediate
// overload answer whenever one SMTP-sized operation was in progress.
func TestAdmissionWaitIsConfigurableWithinTheRequestDeadline(t *testing.T) {
	clearStableEnvironment(t)
	for _, value := range []string{"0s", "1s", "30s", "60s"} {
		snapshot, err := Load([]byte(withAdmissionWait(value)), FlagValues{})
		if err != nil {
			t.Fatalf("admission_wait %q rejected: %v", value, err)
		}
		want, parseErr := time.ParseDuration(value)
		if parseErr != nil {
			t.Fatalf("test duration %q invalid", value)
		}
		if got := snapshot.Server().AdmissionWait(); got != want {
			t.Fatalf("AdmissionWait() = %s, want %s", got, want)
		}
	}
}

// TestAdmissionWaitStaysClosedAboveItsBounds proves the wait can never exceed
// the request deadline that governs the same request, nor the closed ceiling.
func TestAdmissionWaitStaysClosedAboveItsBounds(t *testing.T) {
	clearStableEnvironment(t)
	for _, value := range []string{"61s", "121s", "-1s"} {
		if _, err := Load([]byte(withAdmissionWait(value)), FlagValues{}); CodeOf(err) != CodeInvalidField {
			t.Fatalf("admission_wait %q accepted, code = %s", value, CodeOf(err))
		}
	}
}
