//go:build linux || darwin

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/testsupport"
)

// writeConfiguration stores one document below trusted repository ancestry.
func writeConfiguration(t *testing.T, document string) string {
	t.Helper()
	root := testsupport.TrustedTempDirectory(t)
	path := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal("configuration fixture failed")
	}
	return path
}

// baseDocument returns one minimal complete valid configuration.
func baseDocument() string {
	return "version: dkim2-dsn-propagator-config-v1\n" +
		"server:\n  socket: /run/dkim2/propagator.sock\n" +
		"daemon:\n" +
		"  endpoint: http://127.0.0.1:8080\n" +
		"  capability_file: /etc/dkim2/propagate.key\n" +
		"reinjection:\n  endpoint: smtp://127.0.0.1:10025\n" +
		"propagation:\n  tenant: tenant-a\n  reporting_mta: mta.example\n"
}

// TestLoadDefaults proves the frozen default policy of every stable path.
func TestLoadDefaults(t *testing.T) {
	snapshot, err := Load(writeConfiguration(t, baseDocument()))
	if err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	if snapshot.Version() != configVersion ||
		snapshot.SocketMode() != 0o660 ||
		snapshot.ShutdownTimeout() != 10*time.Second ||
		snapshot.MaxConnections() != 128 ||
		snapshot.MaxInFlightTransactions() != 64 ||
		snapshot.RequestTimeout() != 5*time.Second ||
		snapshot.CommitTimeout() != 2*time.Second ||
		snapshot.PendingLease() != 120*time.Second ||
		snapshot.ConnectTimeout() != 5*time.Second ||
		snapshot.CommandTimeout() != 5*time.Second ||
		snapshot.DataTimeout() != 30*time.Second ||
		snapshot.MessageBytes() != 33_554_432 ||
		snapshot.LogLevel() != "info" ||
		snapshot.MetricsEndpoint() != "" ||
		snapshot.PermanentFailureReply() != PermanentFailureReject {
		t.Fatalf("default policy drifted: %+v", snapshot.Effective())
	}
	if snapshot.Tenant() != "tenant-a" || snapshot.ReportingMTA() != "mta.example" ||
		snapshot.Socket() != "/run/dkim2/propagator.sock" ||
		snapshot.DaemonEndpoint() != "http://127.0.0.1:8080" ||
		snapshot.ReinjectionEndpoint() != "smtp://127.0.0.1:10025" ||
		snapshot.CapabilityFile() != "/etc/dkim2/propagate.key" {
		t.Fatal("validated identity was not preserved")
	}
}

// TestPolicyKnob proves the single adapter policy vocabulary.
func TestPolicyKnob(t *testing.T) {
	document := baseDocument() + "  permanent_failure_reply: discard\n"
	snapshot, err := Load(writeConfiguration(t, document))
	if err != nil || snapshot.PermanentFailureReply() != PermanentFailureDiscard {
		t.Fatalf("discard policy rejected: %v", err)
	}
	document = baseDocument() + "  permanent_failure_reply: fail_open\n"
	if _, err := Load(writeConfiguration(t, document)); !IsError(err) {
		t.Fatal("an unknown policy value was accepted")
	}
}

// TestTransactionBudgetBelowLease proves the retry-interval invariant.
func TestTransactionBudgetBelowLease(t *testing.T) {
	document := baseDocument() +
		"  permanent_failure_reply: reject\n" +
		"limits:\n  message_bytes: 1048576\n"
	document = strings.Replace(
		document,
		"daemon:\n  endpoint: http://127.0.0.1:8080\n",
		"daemon:\n  endpoint: http://127.0.0.1:8080\n  pending_lease: 10s\n",
		1,
	)
	if _, err := Load(writeConfiguration(t, document)); !IsError(err) {
		t.Fatal("a transaction budget beyond the daemon lease was accepted")
	}
}

// TestRejectedDocuments freezes the strict document and value grammar.
func TestRejectedDocuments(t *testing.T) {
	documents := map[string]string{
		"wrong root version":       strings.Replace(baseDocument(), configVersion, "other-v1", 1),
		"unknown key":              baseDocument() + "unknown: 1\n",
		"missing tenant":           strings.Replace(baseDocument(), "  tenant: tenant-a\n", "", 1),
		"missing reporter":         strings.Replace(baseDocument(), "  reporting_mta: mta.example\n", "", 1),
		"hostname daemon":          strings.Replace(baseDocument(), "http://127.0.0.1:8080", "http://daemon.example:8080", 1),
		"hostname reinject":        strings.Replace(baseDocument(), "smtp://127.0.0.1:10025", "smtp://relay.example:25", 1),
		"http reinject":            strings.Replace(baseDocument(), "smtp://127.0.0.1:10025", "http://127.0.0.1:10025", 1),
		"relative socket":          strings.Replace(baseDocument(), "/run/dkim2/propagator.sock", "run/propagator.sock", 1),
		"capability equals socket": strings.Replace(baseDocument(), "/etc/dkim2/propagate.key", "/run/dkim2/propagator.sock", 1),
		"uppercase tenant":         strings.Replace(baseDocument(), "tenant-a", "Tenant-A", 1),
		"uppercase reporter":       strings.Replace(baseDocument(), "mta.example", "MTA.example", 1),
		"unknown log level":        baseDocument() + "observability:\n  logging:\n    level: trace\n",
		"public metrics":           baseDocument() + "observability:\n  metrics:\n    endpoint: 0.0.0.0:9100\n",
		"non-canonical mode":       baseDocument() + "server2:\n  x: 1\n",
		"duplicate key":            baseDocument() + "version: dkim2-dsn-propagator-config-v1\n",
		"yaml anchor":              "version: &a dkim2-dsn-propagator-config-v1\n",
		"empty document":           "",
	}
	for name, document := range documents {
		if _, err := Load(writeConfiguration(t, document)); err == nil {
			t.Fatalf("%s: an invalid document was accepted", name)
		}
	}
}

// TestEnvironmentBindingAndConflicts proves the exact declared binding shape.
func TestEnvironmentBindingAndConflicts(t *testing.T) {
	t.Setenv("DKIM2_DSN_PROPAGATOR_OBSERVABILITY_LOGGING_LEVEL", "debug")
	snapshot, err := Load(writeConfiguration(t, baseDocument()))
	if err != nil || snapshot.LogLevel() != "debug" {
		t.Fatalf("declared environment binding ignored: %v", err)
	}
	document := baseDocument() + "observability:\n  logging:\n    level: warn\n"
	if _, err := Load(writeConfiguration(t, document)); !IsError(err) {
		t.Fatal("a conflicting environment and document value was accepted")
	}
}

// TestPlaceholderExpansion proves fail-closed scalar placeholder handling.
func TestPlaceholderExpansion(t *testing.T) {
	t.Setenv("DKIM2_TEST_TENANT", "tenant-b")
	document := strings.Replace(baseDocument(), "tenant-a", "${DKIM2_TEST_TENANT}", 1)
	snapshot, err := Load(writeConfiguration(t, document))
	if err != nil || snapshot.Tenant() != "tenant-b" {
		t.Fatalf("placeholder expansion failed: %v", err)
	}
	missing := strings.Replace(baseDocument(), "tenant-a", "${DKIM2_TEST_ABSENT}", 1)
	if _, err := Load(writeConfiguration(t, missing)); !IsError(err) {
		t.Fatal("a missing placeholder was expanded")
	}
	versioned := strings.Replace(baseDocument(), configVersion, "${DKIM2_TEST_TENANT}", 1)
	if _, err := Load(writeConfiguration(t, versioned)); !IsError(err) {
		t.Fatal("the frozen root version accepted a placeholder")
	}
}

// TestPlaceholderNeverExpandsMapKeys proves keys stay literal.
func TestPlaceholderNeverExpandsMapKeys(t *testing.T) {
	t.Setenv("DKIM2_TEST_KEY", "tenant")
	document := strings.Replace(
		baseDocument(), "  tenant: tenant-a\n", "  ${DKIM2_TEST_KEY}: tenant-a\n", 1,
	)
	if _, err := Load(writeConfiguration(t, document)); !IsError(err) {
		t.Fatal("a map key was expanded")
	}
}

// TestSnapshotRedaction proves configuration never renders its values.
func TestSnapshotRedaction(t *testing.T) {
	snapshot, err := Load(writeConfiguration(t, baseDocument()))
	if err != nil {
		t.Fatal("valid configuration rejected")
	}
	rendered := snapshot.String() + snapshot.GoString()
	if strings.Contains(rendered, "tenant-a") || strings.Contains(rendered, "127.0.0.1") {
		t.Fatalf("configuration leaked values: %q", rendered)
	}
	if _, err := snapshot.MarshalJSON(); err == nil {
		t.Fatal("configuration serialization was permitted")
	}
	if _, err := snapshot.MarshalText(); err == nil {
		t.Fatal("configuration text serialization was permitted")
	}
	effective := snapshot.Effective()
	if effective.PermanentFailureReply != "reject" || effective.MetricsEnabled {
		t.Fatalf("effective view drifted: %+v", effective)
	}
}

// TestProtectedFileRules proves the descriptor-confined read policy.
func TestProtectedFileRules(t *testing.T) {
	root := testsupport.TrustedTempDirectory(t)
	path := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(path, []byte(baseDocument()), 0o666); err != nil {
		t.Fatal("fixture failed")
	}
	if _, err := Load(path); !IsError(err) {
		t.Fatal("a world-writable configuration was read")
	}
	if _, err := Load("relative.yaml"); !IsError(err) {
		t.Fatal("a relative configuration path was read")
	}
	link := filepath.Join(root, "link.yaml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal("symlink fixture failed")
	}
	if _, err := Load(link); !IsError(err) {
		t.Fatal("a symlinked configuration was read")
	}
}
