package config

import (
	"strings"
	"testing"
)

// TestReplayCountDirectDeliveriesConfiguration proves the local replay policy
// option defaults off, accepts YAML and environment values, rejects malformed
// booleans, and is forbidden with the disabled replay backend.
func TestReplayCountDirectDeliveriesConfiguration(t *testing.T) {
	snapshot, err := Load([]byte(redisYAML()), FlagValues{})
	if err != nil || snapshot.Replay().CountDirectDeliveries() {
		t.Fatalf("direct-delivery counting must default off: error=%v", err)
	}
	document := strings.Replace(redisYAML(), "  epoch: 1\n", "  epoch: 1\n  count_direct_deliveries: true\n", 1)
	snapshot, err = Load([]byte(document), FlagValues{})
	if err != nil || !snapshot.Replay().CountDirectDeliveries() {
		t.Fatalf("explicit direct-delivery counting was not enabled: error=%v", err)
	}
	t.Setenv("DKIM2D_REPLAY_COUNT_DIRECT_DELIVERIES", "false")
	snapshot, err = Load([]byte(document), FlagValues{})
	if err != nil || snapshot.Replay().CountDirectDeliveries() {
		t.Fatal("environment override did not disable direct-delivery counting")
	}
	t.Setenv("DKIM2D_REPLAY_COUNT_DIRECT_DELIVERIES", "maybe")
	if _, err := Load([]byte(document), FlagValues{}); err == nil {
		t.Fatal("malformed direct-delivery boolean accepted")
	}
	disabled := strings.Replace(disabledYAML(), "  backend: disabled\n", "  backend: disabled\n  count_direct_deliveries: true\n", 1)
	if _, err := Load([]byte(disabled), FlagValues{}); err == nil {
		t.Fatal("direct-delivery counting accepted without a replay store")
	}
}
