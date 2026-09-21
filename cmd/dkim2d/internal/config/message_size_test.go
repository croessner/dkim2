package config

import (
	"strings"
	"testing"
)

// TestSMTPMessageSizeConfiguration proves the daemon accepts an explicit
// SMTP-sized limit through its validated configuration boundary.
func TestSMTPMessageSizeConfiguration(t *testing.T) {
	clearStableEnvironment(t)
	document := strings.Replace(disabledYAML(), "server:\n", "server:\n  message_bytes: 104857600\n", 1)
	snapshot, err := Load([]byte(document), FlagValues{})
	if err != nil || snapshot.Server().MessageBytes() != 100<<20 {
		t.Fatal("100 MiB daemon configuration rejected")
	}
	t.Setenv("DKIM2D_SERVER_MESSAGE_BYTES", "67108864")
	snapshot, err = Load([]byte(document), FlagValues{})
	if err != nil || snapshot.Server().MessageBytes() != 64<<20 {
		t.Fatal("environment did not override YAML message size")
	}
	for _, invalid := range []string{"0", "134217729", "-1", "unlimited"} {
		t.Setenv("DKIM2D_SERVER_MESSAGE_BYTES", invalid)
		if _, err := Load([]byte(document), FlagValues{}); err == nil {
			t.Fatal("invalid message size accepted")
		}
	}
}
