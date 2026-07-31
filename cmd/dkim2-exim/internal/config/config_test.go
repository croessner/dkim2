//nolint:goconst // Repeated exact schema literals keep registry drift tests independent.
package config

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
)

const validInbound = `version: dkim2-exim-config-v1
inbound:
  socket: /run/dkim2-exim/service.sock
  peer_uid: 100
  allowed_build_ids:
    - aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
daemon:
  endpoint: http://127.0.0.1:8080
  process_capability_file: /run/dkim2-exim/process.cap
`

const validSign = `version: dkim2-exim-config-v1
daemon:
  endpoint: http://127.0.0.1:8080
  sign_capability_file: /run/dkim2-exim/sign.cap
signing:
  tenant: tenant.example
  domain: example.test
`

// TestStableRegistryAndDefaultsAreLiteral freezes the public configuration vocabulary.
func TestStableRegistryAndDefaultsAreLiteral(t *testing.T) {
	paths := []string{
		"version", "inbound.socket", "inbound.socket_mode", "inbound.peer_uid",
		"inbound.allowed_build_ids", "inbound.request_timeout", "inbound.max_connections",
		"inbound.max_in_flight_messages", "inbound.max_buffered_bytes", "daemon.endpoint",
		"daemon.process_capability_file", "daemon.sign_capability_file",
		"daemon.revise_capability_file", "daemon.request_timeout", "signing.tenant",
		"signing.domain", "authentication_results.enabled", "authentication_results.authserv_id",
		"failure.inbound", "evidence.enabled", "evidence.root", "evidence.key_file",
		"evidence.readiness_file", "evidence.retention", "evidence.max_records",
		"evidence.max_bytes", "limits.message_bytes", "limits.header_bytes",
		"limits.header_count", "limits.header_field_bytes", "limits.recipient_count",
		"observability.logging.level", "observability.logging.destination",
		"observability.metrics.endpoint",
	}
	if !slices.Equal(stablePaths(), paths) {
		t.Fatal("stable configuration path registry drifted")
	}
	defaults := map[string]string{
		"inbound.socket_mode": "0600", "inbound.request_timeout": "3s",
		"inbound.max_connections": "128", "inbound.max_in_flight_messages": "64",
		"inbound.max_buffered_bytes": "268435456", "daemon.request_timeout": "2s",
		"authentication_results.enabled": "false", "failure.inbound": "tempfail",
		"evidence.enabled": "false", "evidence.retention": "14d",
		"evidence.max_records": "100000", "evidence.max_bytes": "536870912",
		"limits.message_bytes": "33554432", "limits.header_bytes": "1048576",
		"limits.header_count": "2000", "limits.header_field_bytes": "65536",
		"limits.recipient_count": "2000", "observability.logging.level": "info",
	}
	if !maps.Equal(stableDefaults(), defaults) {
		t.Fatal("stable configuration default registry drifted")
	}
}

// TestUnixgramDestinationUsesSocketPathBound proves config and runtime share the kernel pathname ceiling.
func TestUnixgramDestinationUsesSocketPathBound(t *testing.T) {
	exact := "/" + strings.Repeat("a", 102)
	if !validDestination("unixgram:" + exact) {
		t.Fatal("exact Unix socket pathname bound was rejected")
	}
	if validDestination("unixgram:" + exact + "a") {
		t.Fatal("one-over Unix socket pathname bound was accepted")
	}
}

// FuzzDecode proves arbitrary configuration bytes remain panic-free and fail closed.
func FuzzDecode(f *testing.F) {
	f.Add([]byte(validSign))
	f.Add([]byte("version: dkim2-exim-config-v1\n"))
	f.Fuzz(func(_ *testing.T, document []byte) {
		_, _ = Decode(document)
	})
}

// TestDecodeRejectsStrictConfigurationDrift proves invalid configuration is content-free.
func TestDecodeRejectsStrictConfigurationDrift(t *testing.T) {
	for _, document := range []string{
		strings.Replace(validInbound, "version: dkim2-exim-config-v1", "version: bad", 1),
		validInbound + "unknown: value\n",
		strings.Replace(validInbound, "peer_uid: 100", "peer_uid: 0100", 1),
		strings.Replace(validInbound, "allowed_build_ids:\n", "allowed_build_ids: []\n#", 1),
		strings.Replace(validInbound, "endpoint: http://127.0.0.1:8080", "endpoint: http://localhost:8080", 1),
	} {
		_, err := Decode([]byte(document))
		var configErr *Error
		if !errors.As(err, &configErr) || err.Error() != "dkim2-exim configuration failure" {
			t.Fatal("strict configuration drift leaked or was accepted")
		}
	}
}

// TestDecodeBuildsRedactedInboundSnapshot proves defaults and route authority stay bounded.
func TestDecodeBuildsRedactedInboundSnapshot(t *testing.T) {
	snapshot, err := Decode([]byte(validInbound))
	if err != nil {
		t.Fatal("valid inbound configuration rejected")
	}
	if err := snapshot.ForOperation(OperationInbound); err != nil {
		t.Fatal("inbound authority rejected")
	}
	if snapshot.String() != redacted || snapshot.Effective().MaxConnections != 128 || snapshot.InboundSocketMode() != 0o600 {
		t.Fatal("redaction or stable defaults drifted")
	}
	if capability := snapshot.CapabilityPath(OperationInbound); capability != "/run/dkim2-exim/process.cap" {
		t.Fatal("inbound capability selection drifted")
	}
}

// TestDecodeExpandsScalarsButRejectsMissingValues proves placeholders cannot escape validation.
func TestDecodeExpandsScalarsButRejectsMissingValues(t *testing.T) {
	t.Setenv("DKIM2_EXIM_SOCKET", "/run/dkim2-exim/service.sock")
	document := strings.Replace(validInbound, "/run/dkim2-exim/service.sock", "${DKIM2_EXIM_SOCKET}", 1)
	if _, err := Decode([]byte(document)); err != nil {
		t.Fatal("present scalar placeholder rejected")
	}
	document = strings.Replace(document, "${DKIM2_EXIM_SOCKET}", "${MISSING_DKIM2_EXIM_SOCKET}", 1)
	if _, err := Decode([]byte(document)); err == nil {
		t.Fatal("missing scalar placeholder accepted")
	}
}

// TestDecodeRejectsCapabilityCrossRouteUse proves a filter cannot use inbound authority.
func TestDecodeRejectsCapabilityCrossRouteUse(t *testing.T) {
	if _, err := Decode([]byte(validInbound)); err != nil {
		t.Fatal("fixture rejected")
	}
	document := strings.Replace(validInbound, "process_capability_file", "sign_capability_file", 1)
	if _, err := DecodeForOperation([]byte(document), OperationSign); err == nil {
		t.Fatal("inbound-shaped sign configuration accepted")
	}
}

// TestDecodeForOperationKeepsFiltersMinimal proves filter configuration has no inbound authority.
func TestDecodeForOperationKeepsFiltersMinimal(t *testing.T) {
	snapshot, err := DecodeForOperation([]byte(validSign), OperationSign)
	if err != nil || snapshot.ForOperation(OperationSign) != nil {
		t.Fatal("minimal sign configuration rejected")
	}
	for _, document := range []string{
		strings.Replace(validSign, "domain: example.test", "domain: Example.test", 1),
		validSign + "limits:\n  recipient_count: 2\n",
		validSign + "evidence:\n  retention: 1h\n",
		validSign + "inbound:\n  socket: /run/dkim2-exim/service.sock\n",
	} {
		if _, err := DecodeForOperation([]byte(document), OperationSign); err == nil {
			t.Fatal("filter cross-mode or noncanonical authority accepted")
		}
	}
}

// TestDecodeRejectsNonCanonicalLiteralEndpoints proves host aliases and mapped forms stay closed.
func TestDecodeRejectsNonCanonicalLiteralEndpoints(t *testing.T) {
	for _, endpoint := range []string{"http://localhost:8080", "http://127.000.000.001:8080", "http://[::ffff:127.0.0.1]:8080", "http://127.0.0.1:08080"} {
		document := strings.Replace(validInbound, "http://127.0.0.1:8080", endpoint, 1)
		if _, err := Decode([]byte(document)); err == nil {
			t.Fatal("noncanonical literal endpoint accepted")
		}
	}
}

// TestDecodeRejectsQuotedTypedScalars proves YAML cannot bypass typed validation.
func TestDecodeRejectsQuotedTypedScalars(t *testing.T) {
	for _, document := range []string{
		strings.Replace(validInbound, "peer_uid: 100", "peer_uid: \"100\"", 1),
		validInbound + "evidence:\n  enabled: \"false\"\n",
	} {
		if _, err := Decode([]byte(document)); err == nil {
			t.Fatal("quoted typed scalar accepted")
		}
	}
}

// TestDecodeRejectsDuplicateEnvironmentSource proves declared Viper bindings stay unambiguous.
func TestDecodeRejectsDuplicateEnvironmentSource(t *testing.T) {
	t.Setenv("DKIM2_EXIM_DAEMON_ENDPOINT", "http://127.0.0.1:8080")
	if _, err := Decode([]byte(validInbound)); err == nil {
		t.Fatal("YAML and declared environment duplicate accepted")
	}
}

// TestDecodeAcceptsCanonicalTypedEnvironment proves declared typed bindings use schema parsing.
func TestDecodeAcceptsCanonicalTypedEnvironment(t *testing.T) {
	t.Setenv("DKIM2_EXIM_INBOUND_PEER_UID", "100")
	document := strings.Replace(validInbound, "  peer_uid: 100\n", "", 1)
	if _, err := Decode([]byte(document)); err != nil {
		t.Fatal("canonical typed environment binding rejected")
	}
}

// TestDecodeAcceptsCanonicalBuildListEnvironment proves list provenance remains explicit.
func TestDecodeAcceptsCanonicalBuildListEnvironment(t *testing.T) {
	t.Setenv("DKIM2_EXIM_INBOUND_ALLOWED_BUILD_IDS", strings.Repeat("a", 64))
	document := strings.Replace(
		validInbound,
		"  allowed_build_ids:\n    - aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
		"",
		1,
	)
	if _, err := Decode([]byte(document)); err != nil {
		t.Fatal("canonical build-ID environment list rejected")
	}
}

// TestDecodeAcceptsWholeTypedPlaceholder proves expansion precedes typed validation.
func TestDecodeAcceptsWholeTypedPlaceholder(t *testing.T) {
	t.Setenv("EXIM_TEST_UID", "100")
	document := strings.Replace(validInbound, "peer_uid: 100", "peer_uid: ${EXIM_TEST_UID}", 1)
	if _, err := Decode([]byte(document)); err != nil {
		t.Fatal("whole typed placeholder rejected")
	}
}

// TestDecodeBoundsExpansionAndFreezesVersion proves substitutions stay scalar-bounded.
func TestDecodeBoundsExpansionAndFreezesVersion(t *testing.T) {
	t.Setenv("EXIM_OVERSIZED", strings.Repeat("x", 4097))
	document := strings.Replace(validInbound, "/run/dkim2-exim/service.sock", "${EXIM_OVERSIZED}", 1)
	if _, err := Decode([]byte(document)); err == nil {
		t.Fatal("oversized scalar placeholder accepted")
	}
	t.Setenv("EXIM_VERSION", Version)
	document = strings.Replace(validInbound, Version, "${EXIM_VERSION}", 1)
	if _, err := Decode([]byte(document)); err == nil {
		t.Fatal("expandable version accepted")
	}
}

// TestDecodeFilterTimeoutIsIndependent proves inbound nesting applies only to inbound service.
func TestDecodeFilterTimeoutIsIndependent(t *testing.T) {
	document := strings.Replace(validSign, "sign_capability_file:", "request_timeout: 8s\n  sign_capability_file:", 1)
	if _, err := DecodeForOperation([]byte(document), OperationSign); err != nil {
		t.Fatal("valid filter timeout was compared with the unused inbound default")
	}
}

// TestDecodeInboundWorkingSetExactBoundary proves the independent default arithmetic.
func TestDecodeInboundWorkingSetExactBoundary(t *testing.T) {
	const exact = int64(267_511_296)
	document := strings.Replace(validInbound, "  allowed_build_ids:\n", "  max_buffered_bytes: 267511296\n  allowed_build_ids:\n", 1)
	snapshot, err := Decode([]byte(document))
	if err != nil || snapshot.InboundReservation() != exact {
		t.Fatal("exact independently calculated working set rejected")
	}
	oneUnder := strings.Replace(document, "267511296", "267511295", 1)
	if _, err := Decode([]byte(oneUnder)); err == nil {
		t.Fatal("one-under aggregate working set accepted")
	}
}

// TestWorkingSetRejectsCheckedArithmeticOverflow proves the service formula fails closed.
func TestWorkingSetRejectsCheckedArithmeticOverflow(t *testing.T) {
	maximum := int64(^uint64(0) >> 1)
	if _, ok := checkedAdd(maximum, 1); ok {
		t.Fatal("service addition overflow accepted")
	}
	if _, ok := checkedMultiply(maximum, 2); ok {
		t.Fatal("service multiplication overflow accepted")
	}
}
