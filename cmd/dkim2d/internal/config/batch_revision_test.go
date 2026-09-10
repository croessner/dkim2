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
