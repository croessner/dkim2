package config

import (
	"strings"
	"testing"
)

// TestBatchRevisionConfigurationRequiresSigningAuthority preserves default-disabled and isolated-route behavior.
func TestBatchRevisionConfigurationRequiresSigningAuthority(t *testing.T) {
	clearStableEnvironment(t)
	disabled, err := Load([]byte(disabledYAML()), FlagValues{})
	if err != nil || disabled.Server().BatchReviseEnabled() {
		t.Fatal("batch enabled by default")
	}
	field := "  batch_revise_capability_file: /secure/" + testGeneration + "/batch-revise-capability\n"
	if _, err := Load([]byte(strings.Replace(disabledYAML(), "server:\n", "server:\n"+field, 1)), FlagValues{}); CodeOf(err) != CodeInvalidMatrix {
		t.Fatal("batch admitted without signing authority")
	}
	only := signingYAML()
	for _, name := range []string{"  sign_capability_file:", "  revise_capability_file:", "  dsn_sign_capability_file:"} {
		only = removeYAMLField(only, name)
	}
	only = strings.Replace(only, "server:\n", "server:\n"+field, 1)
	snapshot, err := Load([]byte(only), FlagValues{})
	if err != nil || !snapshot.Server().BatchReviseEnabled() || !snapshot.Server().SigningRouteEnabled() ||
		!snapshot.SigningDatasourceConsumed() || snapshot.Server().ReviseEnabled() || snapshot.Server().SignEnabled() {
		t.Fatal("batch-only configuration invalid")
	}
}

// TestBatchRevisionResourceSettingsDefaultToSharedSizing proves the working
// set and batch aggregate keep their defaults, accept the production values,
// and refuse an aggregate below the message ceiling or without the route.
func TestBatchRevisionResourceSettingsDefaultToSharedSizing(t *testing.T) {
	clearStableEnvironment(t)
	field := "  batch_revise_capability_file: /secure/" + testGeneration + "/batch-revise-capability\n"
	base := strings.Replace(signingYAML(), "server:\n", "server:\n"+field, 1)
	snapshot, err := Load([]byte(base), FlagValues{})
	if err != nil || snapshot.Server().WorkingSetBytes() != 8<<30 ||
		snapshot.Server().BatchAggregateBytes() != 0 || snapshot.Server().BatchMaxInFlight() != 1 {
		t.Fatalf("defaults working_set=%d aggregate=%d permits=%d code=%s",
			snapshot.Server().WorkingSetBytes(), snapshot.Server().BatchAggregateBytes(),
			snapshot.Server().BatchMaxInFlight(), CodeOf(err))
	}
	production := strings.Replace(base, "server:\n", "server:\n  message_bytes: 117440512\n  max_in_flight: 2\n"+
		"  working_set_bytes: 12884901888\n  batch_revision:\n    max_aggregate_message_bytes: 469762048\n    max_in_flight: 1\n", 1)
	snapshot, err = Load([]byte(production), FlagValues{})
	if err != nil || snapshot.Server().WorkingSetBytes() != 12<<30 ||
		snapshot.Server().BatchAggregateBytes() != 469762048 || snapshot.Server().BatchMaxInFlight() != 1 {
		t.Fatalf("production batch settings code=%s", CodeOf(err))
	}
	for name, replacement := range map[string]string{
		"aggregate below message": "  message_bytes: 117440512\n  batch_revision:\n    max_aggregate_message_bytes: 117440511\n",
		"aggregate above ceiling": "  batch_revision:\n    max_aggregate_message_bytes: 536870913\n",
		"budget below minimum":    "  working_set_bytes: 1073741823\n",
		"budget above maximum":    "  working_set_bytes: 68719476737\n",
		"zero batch permits":      "  batch_revision:\n    max_in_flight: 0\n",
		"nine batch permits":      "  batch_revision:\n    max_in_flight: 9\n",
	} {
		if _, err := Load([]byte(strings.Replace(base, "server:\n", "server:\n"+replacement, 1)), FlagValues{}); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	withoutRoute := strings.Replace(signingYAML(), "server:\n",
		"server:\n  batch_revision:\n    max_aggregate_message_bytes: 268435456\n", 1)
	if _, err := Load([]byte(withoutRoute), FlagValues{}); err == nil {
		t.Fatal("batch aggregate accepted without the batch revision route")
	}
	t.Setenv("DKIM2D_SERVER_BATCH_REVISION_MAX_AGGREGATE_MESSAGE_BYTES", "268435456")
	environment, err := Load([]byte(base), FlagValues{})
	if err != nil || environment.Server().BatchAggregateBytes() != 268435456 {
		t.Fatalf("environment batch aggregate code=%s", CodeOf(err))
	}
}
