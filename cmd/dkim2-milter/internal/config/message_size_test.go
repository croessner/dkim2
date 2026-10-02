package config

import (
	"strings"
	"testing"
)

// TestSMTPMessageSizeConfiguration proves the adapter admits an explicitly
// budgeted 100 MiB message without weakening its aggregate memory admission.
func TestSMTPMessageSizeConfiguration(t *testing.T) {
	document := strings.Replace(validConfig(ModeOriginator), "server:\n", "server:\n  max_buffered_bytes: 1073741824\n", 1)
	document += "limits:\n  message_bytes: 104857600\n"
	snapshot, err := Load(writeConfig(t, document))
	if err != nil || snapshot.MessageBytes() != 100<<20 {
		t.Fatal("100 MiB Milter configuration rejected")
	}
	document = strings.Replace(document, "1073741824", "268435456", 1)
	if _, err := Load(writeConfig(t, document)); err == nil {
		t.Fatal("insufficient working-set budget accepted")
	}
}

// TestProductionMessageSizeConfiguration pins the documented 112 MiB adapter
// values: the 1 GiB budget and a call deadline above the daemon's 120 seconds.
func TestProductionMessageSizeConfiguration(t *testing.T) {
	document := strings.Replace(validConfig(ModeOriginator), "server:\n", "server:\n  max_buffered_bytes: 1073741824\n", 1)
	document = strings.Replace(document, "daemon:\n", "daemon:\n  request_timeout: 150s\n", 1)
	document += "limits:\n  message_bytes: 117440512\n"
	snapshot, err := Load(writeConfig(t, document))
	if err != nil || snapshot.MessageBytes() != 117440512 {
		t.Fatalf("112 MiB Milter configuration rejected: %v", err)
	}
}
