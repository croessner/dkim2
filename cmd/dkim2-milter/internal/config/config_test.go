package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/milter"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/testsupport"
)

const privacyMarker = "milter-private-marker"

// writeConfig writes one test-owned absolute configuration path.
func writeConfig(t *testing.T, document string) string {
	t.Helper()
	directory := trustedTempDirectory(t)
	path := filepath.Join(directory, "milter.yaml")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// trustedTempDirectory creates fixtures below repository-owned safe ancestry.
func trustedTempDirectory(t *testing.T) string {
	t.Helper()
	return testsupport.TrustedTempDirectory(t)
}

// validConfig returns one minimal strict configuration for the requested mode.
func validConfig(mode Mode) string {
	signing := ""
	if mode != ModeInbound {
		signing = "\nsigning:\n  tenant: tenant-a\n  domain: example.test"
		if mode == ModeOriginator {
			signing += "\n  dsn_domain: dsn.example.test"
		}
	}
	return fmt.Sprintf(`version: dkim2-milter-config-v1
server:
  socket: /tmp/dkim2-milter.sock
daemon:
  endpoint: http://127.0.0.1:8080
  capability_file: /tmp/dkim2-milter.cap
mode: %s%s
`, mode, signing)
}

// TestLoadModeMatrixAndDefaults proves every supported mode and its conditional fields.
func TestLoadModeMatrixAndDefaults(t *testing.T) {
	for _, mode := range []Mode{ModeInbound, ModeOriginator, ModeOrdinaryTransit} {
		snapshot, err := Load(writeConfig(t, validConfig(mode)))
		if err != nil {
			t.Fatalf("Load(%s): %v", mode, err)
		}
		if snapshot.Version() != configVersion || snapshot.Mode() != mode ||
			snapshot.SocketMode() != 0o660 || snapshot.ShutdownTimeout() != 10*time.Second ||
			snapshot.MaxConnections() != 128 || snapshot.MaxInFlightMessages() != 64 ||
			snapshot.MaxBufferedBytes() != 268_435_456 ||
			snapshot.RequestTimeout() != 2*time.Second ||
			snapshot.MaxBufferedBytes()/8 < snapshot.MessageBytes() ||
			snapshot.FailureMode() != FailureTempfail ||
			snapshot.MessageBytes() != 33_554_432 || snapshot.HeaderBytes() != 1_048_576 ||
			snapshot.HeaderCount() != 2000 || snapshot.HeaderFieldBytes() != 65_536 ||
			snapshot.RecipientCount() != 2000 || snapshot.LogLevel() != defaultLogLevel {
			t.Fatalf("unexpected defaults for %s: %#v", mode, snapshot.Effective())
		}
		if mode == ModeInbound {
			if snapshot.Tenant() != "" || snapshot.Domain() != "" ||
				snapshot.DomainSource() != milter.DomainSourceStatic {
				t.Fatal("inbound mode retained signing identity")
			}
		} else if snapshot.Tenant() != "tenant-a" || snapshot.Domain() != "example.test" ||
			snapshot.DomainSource() != milter.DomainSourceStatic {
			t.Fatal("signing mode lost its required identity")
		}
		if mode == ModeOriginator && snapshot.DSNDomain() != "dsn.example.test" {
			t.Fatal("originator mode lost its explicit DSN signing authority")
		}
		if mode != ModeOriginator && snapshot.DSNDomain() != "" {
			t.Fatal("non-originator mode retained a DSN signing authority")
		}
	}
}

// TestLoadAcceptsOriginatorEnvelopeSenderDomainSelection proves the bounded multi-domain route.
func TestLoadAcceptsOriginatorEnvelopeSenderDomainSelection(t *testing.T) {
	document := strings.Replace(
		validConfig(ModeOriginator),
		"  domain: example.test",
		"  domain_source: envelope_sender",
		1,
	)
	snapshot, err := Load(writeConfig(t, document))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Tenant() != "tenant-a" || snapshot.Domain() != "" ||
		snapshot.DomainSource() != milter.DomainSourceEnvelopeSender ||
		snapshot.DSNDomain() != "dsn.example.test" {
		t.Fatal("originator envelope-sender selection was not retained exactly")
	}
}

// TestLoadRejectsStrictYAMLViolations proves unambiguous canonical input handling.
func TestLoadRejectsStrictYAMLViolations(t *testing.T) {
	base := validConfig(ModeInbound)
	tests := map[string]string{
		"unknown key":       base + "unknown: true\n",
		"dotted alias":      base + "server.socket: /tmp/other.sock\n",
		"case variant":      strings.Replace(base, "server:", "Server:", 1),
		"duplicate key":     strings.Replace(base, "mode: inbound", "mode: inbound\nmode: inbound", 1),
		"anchor":            strings.Replace(base, "inbound", "&mode inbound", 1),
		"alias":             strings.Replace(base, "mode: inbound", "mode: &mode inbound\nfailure:\n  mode: *mode", 1),
		"explicit tag":      strings.Replace(base, "inbound", "!!str inbound", 1),
		"multiple document": base + "---\nmode: inbound\n",
		"null":              strings.Replace(base, "mode: inbound", "mode: null", 1),
		"weak integer":      base + "limits:\n  header_count: 02\n",
		"quoted integer":    base + "limits:\n  header_count: \"2000\"\n",
		"weak boolean":      base + "authentication_results:\n  enabled: YES\n",
		"quoted boolean":    base + "authentication_results:\n  enabled: \"false\"\n",
		"sequence":          strings.Replace(base, "mode: inbound", "mode: [inbound]", 1),
		"expanded map key":  base + "\"${" + privacyMarker + "}\": value\n",
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, document)); !IsError(err) {
				t.Fatalf("Load() error = %v, want bounded config error", err)
			}
		})
	}
}

// TestLoadBindsEnvironmentWithoutOverrideAmbiguity proves exact names and conflicts.
func TestLoadBindsEnvironmentWithoutOverrideAmbiguity(t *testing.T) {
	document := validConfig(ModeInbound)
	t.Setenv("DKIM2_MILTER_FAILURE_MODE", "fail_open")
	snapshot, err := Load(writeConfig(t, document))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.FailureMode() != FailureOpen {
		t.Fatal("canonical environment binding was not applied")
	}

	t.Setenv("DKIM2_MILTER_MODE", "inbound")
	if _, err := Load(writeConfig(t, document)); !IsError(err) {
		t.Fatal("YAML/environment duplicate source was accepted")
	}
}

// TestLoadExpandsScalarPlaceholdersBeforeValidation proves complete and missing expansion.
func TestLoadExpandsScalarPlaceholdersBeforeValidation(t *testing.T) {
	t.Setenv("MILTER_TEST_SOCKET", "/tmp/expanded-dkim2-milter.sock")
	t.Setenv("MILTER_TEST_CONNECTIONS", "256")
	document := strings.Replace(
		validConfig(ModeInbound),
		"  socket: /tmp/dkim2-milter.sock",
		"  socket: ${MILTER_TEST_SOCKET}\n  max_connections: ${MILTER_TEST_CONNECTIONS}",
		1,
	)
	snapshot, err := Load(writeConfig(t, document))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Socket() != "/tmp/expanded-dkim2-milter.sock" ||
		snapshot.MaxConnections() != 256 {
		t.Fatal("placeholder was not expanded before validation")
	}
	document = strings.Replace(document, "MILTER_TEST_SOCKET", "MISSING_MILTER_SOCKET", 1)
	if _, err := Load(writeConfig(t, document)); !IsError(err) {
		t.Fatal("missing placeholder was accepted")
	}
	mixed := strings.Replace(
		validConfig(ModeInbound),
		"  socket: /tmp/dkim2-milter.sock",
		"  socket: /tmp/dkim2-milter.sock\n  max_connections: 1${MILTER_TEST_CONNECTIONS}",
		1,
	)
	if _, err := Load(writeConfig(t, mixed)); !IsError(err) {
		t.Fatal("mixed numeric placeholder was accepted")
	}
}

// TestLoadRejectsNoncanonicalEnvironmentScalars proves strings do not bypass typed grammar.
func TestLoadRejectsNoncanonicalEnvironmentScalars(t *testing.T) {
	t.Setenv("DKIM2_MILTER_SERVER_MAX_CONNECTIONS", "0128")
	if _, err := Load(writeConfig(t, validConfig(ModeInbound))); !IsError(err) {
		t.Fatal("noncanonical environment integer was accepted")
	}
}

// TestLoadBoundsDirectEnvironmentBeforeViper proves scalar work is capped early.
func TestLoadBoundsDirectEnvironmentBeforeViper(t *testing.T) {
	t.Setenv(
		"DKIM2_MILTER_SERVER_SOCKET",
		"/"+strings.Repeat("x", maxConfigurationScalar+1),
	)
	if _, err := Load(writeConfig(t, validConfig(ModeInbound))); !IsError(err) {
		t.Fatal("oversized direct environment scalar was accepted")
	}
}

// TestLoadBoundsPlaceholderBeforeCopy proves substitution cannot over-allocate.
func TestLoadBoundsPlaceholderBeforeCopy(t *testing.T) {
	t.Setenv("MILTER_OVERSIZED_PLACEHOLDER", strings.Repeat("x", maxConfigurationScalar+1))
	document := strings.Replace(
		validConfig(ModeInbound),
		"/tmp/dkim2-milter.sock",
		"${MILTER_OVERSIZED_PLACEHOLDER}",
		1,
	)
	if _, err := Load(writeConfig(t, document)); !IsError(err) {
		t.Fatal("oversized placeholder substitution was accepted")
	}
}

// TestLoadRejectsConditionalMatrixViolations proves mode and reporting exclusivity.
func TestLoadRejectsConditionalMatrixViolations(t *testing.T) {
	tests := map[string]string{
		"inbound signing": validConfig(ModeInbound) +
			"signing:\n  tenant: tenant-a\n  domain: example.test\n",
		"signing missing tenant": strings.Replace(
			validConfig(ModeOriginator), "  tenant: tenant-a\n", "", 1,
		),
		"signing missing domain": strings.Replace(
			validConfig(ModeOrdinaryTransit), "  domain: example.test", "", 1,
		),
		"originator missing DSN authority": strings.Replace(
			validConfig(ModeOriginator), "  dsn_domain: dsn.example.test\n", "", 1,
		),
		"originator noncanonical DSN authority": strings.Replace(
			validConfig(ModeOriginator), "dsn.example.test", "DSN.example.test", 1,
		),
		"transit DSN authority": strings.Replace(
			validConfig(ModeOrdinaryTransit),
			"  domain: example.test",
			"  domain: example.test\n  dsn_domain: dsn.example.test",
			1,
		),
		"inbound DSN authority": validConfig(ModeInbound) +
			"signing:\n  dsn_domain: dsn.example.test\n",
		"originator dynamic domain with static domain": strings.Replace(
			validConfig(ModeOriginator),
			"  domain: example.test",
			"  domain: example.test\n  domain_source: envelope_sender",
			1,
		),
		"transit dynamic domain": strings.Replace(
			validConfig(ModeOrdinaryTransit),
			"  domain: example.test",
			"  domain_source: envelope_sender",
			1,
		),
		"inbound explicit domain source": validConfig(ModeInbound) +
			"signing:\n  domain_source: static\n",
		"unknown domain source": strings.Replace(
			validConfig(ModeOriginator),
			"  domain: example.test",
			"  domain_source: sender_header",
			1,
		),
		"inbound group policy": validConfig(ModeInbound) +
			"signing:\n  allow_recipient_group: true\n",
		"inbound explicit group default": validConfig(ModeInbound) +
			"signing:\n  allow_recipient_group: false\n",
		"signing recipient group disclosure": strings.Replace(
			validConfig(ModeOriginator),
			"  domain: example.test",
			"  domain: example.test\n  allow_recipient_group: true",
			1,
		),
		"reporting missing id": validConfig(ModeInbound) +
			"authentication_results:\n  enabled: true\n",
		"reporting id disabled": validConfig(ModeInbound) +
			"authentication_results:\n  authserv_id: auth.example\n",
		"empty reporting id disabled": validConfig(ModeInbound) +
			"authentication_results:\n  authserv_id: \"\"\n",
		"reporting in signing mode": validConfig(ModeOriginator) +
			"authentication_results:\n  enabled: true\n  authserv_id: auth.example\n",
		"explicit reporting default in signing mode": validConfig(ModeOriginator) +
			"authentication_results:\n  enabled: false\n",
		"noncanonical authserv id": validConfig(ModeInbound) +
			"authentication_results:\n  enabled: true\n  authserv_id: Auth.Example\n",
		"noncanonical tenant": strings.Replace(
			validConfig(ModeOriginator), "tenant-a", "Tenant-A", 1,
		),
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, document)); !IsError(err) {
				t.Fatalf("Load() error = %v, want matrix failure", err)
			}
		})
	}
	t.Run("empty environment reporting id disabled", func(t *testing.T) {
		t.Setenv("DKIM2_MILTER_AUTHENTICATION_RESULTS_AUTHSERV_ID", "")
		if _, err := Load(writeConfig(t, validConfig(ModeInbound))); !IsError(err) {
			t.Fatal("disabled reporting accepted an explicitly empty environment authserv-id")
		}
	})
}

// TestLoadBoundsAndEndpointGrammar proves stable numeric and authority limits.
func TestLoadBoundsAndEndpointGrammar(t *testing.T) {
	base := validConfig(ModeInbound)
	tests := map[string]string{
		"zero connections": strings.Replace(
			base,
			"  socket: /tmp/dkim2-milter.sock",
			"  socket: /tmp/dkim2-milter.sock\n  max_connections: 0",
			1,
		),
		"too many messages": strings.Replace(
			base,
			"server:\n  socket: /tmp/dkim2-milter.sock",
			"server:\n  socket: /tmp/dkim2-milter.sock\n  max_connections: 1\n  max_in_flight_messages: 2",
			1,
		),
		"wide message": base + "limits:\n  message_bytes: 33554433\n",
		"buffer below message": strings.Replace(
			base,
			"  socket: /tmp/dkim2-milter.sock",
			"  socket: /tmp/dkim2-milter.sock\n  max_buffered_bytes: 1048576",
			1,
		),
		"hostname endpoint": strings.Replace(base, "127.0.0.1", "localhost", 1),
		"mapped endpoint":   strings.Replace(base, "127.0.0.1", "[::ffff:127.0.0.1]", 1),
		"long ipv6 endpoint": strings.Replace(
			base, "127.0.0.1", "[0:0:0:0:0:0:0:1]", 1,
		),
		"query endpoint":       strings.Replace(base, ":8080", ":8080?secret="+privacyMarker, 1),
		"empty query endpoint": strings.Replace(base, ":8080", ":8080?", 1),
		"empty fragment endpoint": strings.Replace(
			base,
			"endpoint: http://127.0.0.1:8080",
			"endpoint: \"http://127.0.0.1:8080#\"",
			1,
		),
		"encoded path endpoint": strings.Replace(base, ":8080", ":8080/%23", 1),
		"unsafe socket mode": strings.Replace(
			base,
			"server:\n  socket: /tmp/dkim2-milter.sock",
			"server:\n  socket: /tmp/dkim2-milter.sock\n  socket_mode: \"0666\"",
			1,
		),
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, document)); !IsError(err) {
				t.Fatalf("Load() error = %v, want bounded validation failure", err)
			}
		})
	}
}

// TestLoadRejectsInsufficientEOMWorkingSet proves every accepted process byte
// cap can carry the configured maximum message and envelope through its reply.
func TestLoadRejectsInsufficientEOMWorkingSet(t *testing.T) {
	insufficient := strings.Replace(
		validConfig(ModeInbound),
		"  socket: /tmp/dkim2-milter.sock",
		"  socket: /tmp/dkim2-milter.sock\n"+
			"  max_buffered_bytes: 33554432\n"+
			"limits:\n"+
			"  message_bytes: 4194304\n"+
			"  recipient_count: 1",
		1,
	)
	if _, err := Load(writeConfig(t, insufficient)); !IsError(err) {
		t.Fatalf("Load() error = %v, want aggregate EOM working-set rejection", err)
	}
	sufficient := strings.Replace(
		insufficient,
		"max_buffered_bytes: 33554432",
		"max_buffered_bytes: 58919936",
		1,
	)
	if _, err := Load(writeConfig(t, sufficient)); err != nil {
		t.Fatalf("Load() exact aggregate EOM boundary error = %v", err)
	}
}

// TestSnapshotFormattingAndEffectiveConfigAreSecretSafe proves all formatter verbs.
func TestSnapshotFormattingAndEffectiveConfigAreSecretSafe(t *testing.T) {
	document := strings.Replace(validConfig(ModeOriginator), "tenant-a", privacyMarker, 1)
	document = strings.Replace(document, "/tmp/dkim2-milter.cap", "/tmp/"+privacyMarker, 1)
	snapshot, err := Load(writeConfig(t, document))
	if err != nil {
		t.Fatal(err)
	}
	formatted := fmt.Sprintf("%v %#v %s %q %+v", snapshot, snapshot, snapshot, snapshot, snapshot)
	if strings.Contains(formatted, privacyMarker) || formatted != strings.Repeat(redacted+" ", 4)+redacted {
		t.Fatalf("unsafe snapshot formatting: %q", formatted)
	}
	if _, err := json.Marshal(snapshot); !IsError(err) {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	formatSubjects := []any{
		&snapshot,
		snapshot,
		*snapshot.state,
		any(snapshot),
		struct{ Value any }{Value: snapshot},
		struct{ Value Snapshot }{Value: snapshot},
	}
	for _, subject := range formatSubjects {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if output := fmt.Sprintf(format, subject); strings.Contains(output, privacyMarker) ||
				strings.Contains(output, snapshot.CapabilityFile()) ||
				strings.Contains(output, snapshot.DaemonEndpoint()) {
				t.Fatalf("format %q traversed a snapshot holder: %q", format, output)
			}
		}
	}
	for _, subject := range formatSubjects {
		if output, marshalErr := json.Marshal(subject); marshalErr == nil ||
			strings.Contains(string(output), privacyMarker) {
			t.Fatal("snapshot holder serialization did not fail closed")
		}
		if marshaler, ok := subject.(interface{ MarshalText() ([]byte, error) }); ok {
			if output, marshalErr := marshaler.MarshalText(); marshalErr == nil ||
				strings.Contains(string(output), privacyMarker) {
				t.Fatal("snapshot holder text serialization did not fail closed")
			}
		}
	}
	effective, err := json.Marshal(snapshot.Effective())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(effective), privacyMarker) ||
		strings.Contains(string(effective), snapshot.Socket()) ||
		strings.Contains(string(effective), snapshot.DaemonEndpoint()) {
		t.Fatalf("effective config leaked protected data: %s", effective)
	}
	view := snapshot.Effective()
	if view.SocketMode != "0660" || view.ShutdownTimeout != "10s" ||
		view.MaxConnections != 128 || view.MaxInFlightMessages != 64 ||
		view.MaxBufferedBytes != 268_435_456 || view.RequestTimeout != "2s" {
		t.Fatalf("effective config omitted safe runtime bounds: %#v", view)
	}
	err = fmt.Errorf("outer: %w", &Error{})
	if !errors.Is(err, &Error{}) || strings.Contains(err.Error(), privacyMarker) {
		t.Fatal("bounded error classification failed")
	}
}

// FuzzConfigurationManifestParsingNeverPanics exercises bounded strict YAML admission.
func FuzzConfigurationManifestParsingNeverPanics(f *testing.F) {
	f.Add([]byte(validConfig(ModeInbound)))
	f.Add([]byte("version: dkim2-milter-config-v1\nmode: inbound\n"))
	f.Add([]byte{0, 0xff, '\n'})
	f.Fuzz(func(t *testing.T, document []byte) {
		if len(document) > maxConfigurationBytes {
			document = document[:maxConfigurationBytes]
		}
		values, err := preflightYAML(document)
		if err != nil {
			return
		}
		if len(values) > len(stableFieldSpecs()) {
			t.Fatalf("preflight retained %d values", len(values))
		}
	})
}
