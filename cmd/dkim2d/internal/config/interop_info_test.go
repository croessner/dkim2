package config

import (
	"strings"
	"testing"
)

// TestInteropInfoConfiguration proves opt-in, environment expansion, and strict boolean validation.
func TestInteropInfoConfiguration(t *testing.T) {
	snapshot, err := Load([]byte(signingYAML()), FlagValues{})
	if err != nil || snapshot.Signing().Policies().InteropInfoEnabled() {
		t.Fatal("interop info must default off")
	}
	document := strings.Replace(signingYAML(), "  backend: flat_file", "  backend: flat_file\n  interop_info:\n    enabled: ${INTEROP_ENABLED}", 1)
	t.Setenv("INTEROP_ENABLED", "true")
	snapshot, err = Load([]byte(document), FlagValues{})
	if err != nil || !snapshot.Signing().Policies().InteropInfoEnabled() {
		t.Fatal("interop placeholder was not enabled")
	}
	t.Setenv("DKIM2D_SIGNING_INTEROP_INFO_ENABLED", "false")
	snapshot, err = Load([]byte(document), FlagValues{})
	if err != nil || snapshot.Signing().Policies().InteropInfoEnabled() {
		t.Fatal("environment override did not disable interop info")
	}
	t.Setenv("DKIM2D_SIGNING_INTEROP_INFO_ENABLED", "invalid")
	if _, err = Load([]byte(document), FlagValues{}); err == nil {
		t.Fatal("invalid interop boolean accepted")
	}
}
