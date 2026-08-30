package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

const testGeneration = "0123456789abcdef0123456789abcdef"

const testValkeyAddress = "127.0.0.1:6379"

const testSigningUseOriginator = "originator"

const (
	testValuePath = "value"
	duration120s  = "120s"
	duration121s  = "121s"
	duration31s   = "31s"
	duration99ms  = "99ms"
	duration999ms = "999ms"
)

// TestLoadDisabledAppliesOnlyCommonDefaults proves the closed disabled matrix.
func TestLoadDisabledAppliesOnlyCommonDefaults(t *testing.T) {
	clearStableEnvironment(t)
	snapshot, err := Load([]byte(disabledYAML()), FlagValues{})
	if err != nil {
		t.Fatalf("Load() failed with code %s", CodeOf(err))
	}
	if !snapshot.Valid() || snapshot.Backend() != ReplayDisabled || snapshot.PolicyMode() != PolicyStrict {
		t.Fatal("Load() did not construct the expected closed snapshot")
	}
	if snapshot.Server().Listen() != defaultListenAddress ||
		snapshot.Server().MaxInFlight() != 1 ||
		snapshot.DNS().LookupTimeout() != 5*time.Second ||
		snapshot.DNS().MaxCacheEntries() != 4096 ||
		snapshot.DNS().PositiveTTLCap() != time.Hour ||
		snapshot.DNS().NegativeTTLCap() != 5*time.Minute ||
		snapshot.DNS().StableErrorTTLCap() != time.Minute {
		t.Fatal("Load() did not apply exact common defaults")
	}
	if snapshot.Replay().Enabled() {
		t.Fatal("disabled backend materialized replay configuration")
	}
}

// TestSigningConfigurationIsDefaultDisabledAndConditionallyComplete freezes
// the no-open configuration authority before protected traversal.
func TestSigningConfigurationIsDefaultDisabledAndConditionallyComplete(t *testing.T) { //nolint:gocyclo // One table-like test covers the closed configuration matrix.
	clearStableEnvironment(t)
	disabled, err := Load([]byte(disabledYAML()), FlagValues{})
	if err != nil || disabled.Signing().Enabled() ||
		disabled.Server().SignCapabilityFile() != "" ||
		disabled.Server().ReviseCapabilityFile() != "" ||
		disabled.Server().DSNSignCapabilityFile() != "" {
		t.Fatal("default-disabled signing configuration widened authority")
	}
	enabled, err := Load([]byte(signingYAML()), FlagValues{})
	if err != nil || !enabled.Signing().Enabled() ||
		enabled.Signing().Backend() != SigningFlatFile ||
		enabled.Signing().ReloadInterval() != 30*time.Second ||
		enabled.Signing().AllowRecipientGroup() ||
		enabled.Signing().LimitProfile() != limitProfileSmall ||
		enabled.Signing().MaxLoadBytes() != 16<<20 {
		t.Fatalf("enabled signing configuration failed with code %s", CodeOf(err))
	}
	productionDocument := strings.Replace(
		signingYAML(), "  backend: flat_file",
		"  backend: flat_file\n  limit_profile: production\n  max_load_bytes: 134217728", 1,
	)
	production, err := Load([]byte(productionDocument), FlagValues{})
	if err != nil || production.Signing().LimitProfile() != limitProfileProduction || production.Signing().MaxLoadBytes() != 128<<20 {
		t.Fatalf("production signing limits failed with code %s", CodeOf(err))
	}
	for _, unsafeLimits := range []string{
		strings.Replace(signingYAML(), "  backend: flat_file", "  backend: flat_file\n  limit_profile: unlimited", 1),
		strings.Replace(signingYAML(), "  backend: flat_file", "  backend: flat_file\n  limit_profile: production", 1),
		strings.Replace(signingYAML(), "  backend: flat_file", "  backend: flat_file\n  max_load_bytes: 536870913", 1),
	} {
		if _, loadErr := Load([]byte(unsafeLimits), FlagValues{}); loadErr == nil {
			t.Fatal("unsafe datasource limit profile accepted")
		}
	}
	signOnly, err := Load(
		[]byte(removeYAMLField(
			removeYAMLField(signingYAML(), "  revise_capability_file:"),
			"  dsn_sign_capability_file:",
		)),
		FlagValues{},
	)
	if err != nil || !signOnly.Server().SignEnabled() || signOnly.Server().ReviseEnabled() ||
		signOnly.Server().DSNSignEnabled() {
		t.Fatalf("sign-only route configuration failed with code %s", CodeOf(err))
	}
	reviseOnly, err := Load(
		[]byte(removeYAMLField(
			removeYAMLField(signingYAML(), "  sign_capability_file:"),
			"  dsn_sign_capability_file:",
		)),
		FlagValues{},
	)
	if err != nil || reviseOnly.Server().SignEnabled() || !reviseOnly.Server().ReviseEnabled() ||
		reviseOnly.Server().DSNSignEnabled() {
		t.Fatalf("revise-only route configuration failed with code %s", CodeOf(err))
	}
	dsnOnly, err := Load(
		[]byte(removeYAMLField(
			removeYAMLField(signingYAML(), "  sign_capability_file:"),
			"  revise_capability_file:",
		)),
		FlagValues{},
	)
	if err != nil || dsnOnly.Server().SignEnabled() || dsnOnly.Server().ReviseEnabled() ||
		!dsnOnly.Server().DSNSignEnabled() {
		t.Fatalf("DSN-only route configuration failed with code %s", CodeOf(err))
	}
	for _, mutation := range []string{
		strings.Replace(signingYAML(), "  private_manifest_file:", "  unknown_private_manifest_file:", 1),
		strings.Replace(signingYAML(), "  revise_capability_file:", "  unknown_revise_capability_file:", 1),
		strings.Replace(signingYAML(), "  dsn_sign_capability_file:", "  unknown_dsn_sign_capability_file:", 1),
		removeYAMLField(
			removeYAMLField(
				removeYAMLField(signingYAML(), "  sign_capability_file:"),
				"  revise_capability_file:",
			),
			"  dsn_sign_capability_file:",
		),
		strings.Replace(
			signingYAML(),
			"  dsn_sign_capability_file: /secure/"+testGeneration+"/dsn-sign-capability",
			"  dsn_sign_capability_file: /secure/"+testGeneration+"/sign-capability",
			1,
		),
		strings.Replace(signingYAML(), "/private-manifest", "/datasource", 1),
		strings.Replace(signingYAML(), "  backend: flat_file", "  backend: disabled", 1),
	} {
		if _, loadErr := Load([]byte(mutation), FlagValues{}); loadErr == nil {
			t.Fatal("signing conditional matrix accepted an incomplete or conflicting state")
		}
	}
}

// TestSigningFlagPolicyMapsExactUsesAndPreservesDisabledDefaults proves the closed six-leaf contract.
func TestSigningFlagPolicyMapsExactUsesAndPreservesDisabledDefaults(t *testing.T) {
	clearStableEnvironment(t)
	disabled, err := Load([]byte(disabledYAML()), FlagValues{})
	if err != nil {
		t.Fatalf("Load(disabled) code = %s", CodeOf(err))
	}
	policies := disabled.Signing().Policies()
	for name, policy := range map[string]SigningFlagPolicyConfig{
		testSigningUseOriginator: policies.Originator(),
		"ordinary_transit":       policies.OrdinaryTransit(),
		"delivery_status":        policies.DeliveryStatus(),
	} {
		if policy.DoNotModify() || policy.DoNotExplode() {
			t.Fatalf("omitted %s policy enabled a flag", name)
		}
	}

	document := strings.Replace(signingYAML(), "  backend: flat_file", `  backend: flat_file
  policy:
    originator:
      donotmodify: true
      donotexplode: false
    ordinary_transit:
      donotmodify: false
      donotexplode: true
    delivery_status:
      donotmodify: true
      donotexplode: true`, 1)
	enabled, err := Load([]byte(document), FlagValues{})
	if err != nil {
		t.Fatalf("Load(policy) code = %s", CodeOf(err))
	}
	policies = enabled.Signing().Policies()
	if !policies.Originator().DoNotModify() || policies.Originator().DoNotExplode() ||
		policies.OrdinaryTransit().DoNotModify() || !policies.OrdinaryTransit().DoNotExplode() ||
		!policies.DeliveryStatus().DoNotModify() || !policies.DeliveryStatus().DoNotExplode() {
		t.Fatal("signing policy leaves mapped to the wrong use")
	}

	overrides := []struct {
		name string
		read func(SigningPoliciesConfig) bool
	}{
		{envSigningPolicyOriginatorDoNotModify, func(p SigningPoliciesConfig) bool { return p.Originator().DoNotModify() }},
		{envSigningPolicyOriginatorDoNotExplode, func(p SigningPoliciesConfig) bool { return p.Originator().DoNotExplode() }},
		{envSigningPolicyTransitDoNotModify, func(p SigningPoliciesConfig) bool { return p.OrdinaryTransit().DoNotModify() }},
		{envSigningPolicyTransitDoNotExplode, func(p SigningPoliciesConfig) bool { return p.OrdinaryTransit().DoNotExplode() }},
		{envSigningPolicyDeliveryDoNotModify, func(p SigningPoliciesConfig) bool { return p.DeliveryStatus().DoNotModify() }},
		{envSigningPolicyDeliveryDoNotExplode, func(p SigningPoliciesConfig) bool { return p.DeliveryStatus().DoNotExplode() }},
	}
	for _, override := range overrides {
		t.Setenv(override.name, "true")
		environment, loadErr := Load([]byte(signingYAML()), FlagValues{})
		if loadErr != nil || !override.read(environment.Signing().Policies()) {
			t.Fatalf("environment policy override %s failed with code %s", override.name, CodeOf(loadErr))
		}
	}
	t.Setenv(envSigningPolicyDeliveryDoNotExplode, "not-a-boolean")
	if _, loadErr := Load([]byte(signingYAML()), FlagValues{}); loadErr == nil {
		t.Fatal("invalid signing policy environment boolean was accepted")
	}
}

// TestSigningFlagPolicyFailsClosedForDisabledAndUnknownPolicy proves unsafe policy input is rejected.
func TestSigningFlagPolicyFailsClosedForDisabledAndUnknownPolicy(t *testing.T) {
	clearStableEnvironment(t)
	for _, document := range []string{
		strings.Replace(disabledYAML(), "signing:\n", "signing:\n", 1) + "signing:\n  policy:\n    originator:\n      donotmodify: true\n",
		strings.Replace(signingYAML(), "  backend: flat_file", "  backend: flat_file\n  policy:\n    originator:\n      exploded: false", 1),
		strings.Replace(signingYAML(), "  backend: flat_file", "  backend: flat_file\n  policy:\n    default:\n      donotmodify: true", 1),
	} {
		if _, err := Load([]byte(document), FlagValues{}); err == nil {
			t.Fatal("unsafe signing policy input was accepted")
		}
	}
	falseOnly := disabledYAML() + "signing:\n  policy:\n    originator:\n      donotmodify: false\n"
	if _, err := Load([]byte(falseOnly), FlagValues{}); err != nil {
		t.Fatalf("explicit false disabled policy failed with code %s", CodeOf(err))
	}
}

// TestNetworkSigningConfigurationIsConditionalAndVerified proves network
// providers require exact backend-specific fields and reject irrelevant ones.
func TestNetworkSigningConfigurationIsConditionalAndVerified(t *testing.T) {
	clearStableEnvironment(t)
	ldapSnapshot, err := Load([]byte(ldapSigningYAML()), FlagValues{})
	ldapConfig, ldapEnabled := ldapSnapshot.Signing().LDAP()
	if err != nil || !ldapEnabled || ldapSnapshot.Signing().Backend() != SigningLDAP ||
		ldapConfig.Transport() != "starttls" || ldapConfig.PageSize() != 128 ||
		ldapConfig.LoadDeadline() != 5*time.Second {
		t.Fatalf("LDAP signing configuration failed with code %s", CodeOf(err))
	}
	postgresSnapshot, err := Load([]byte(postgresqlSigningYAML()), FlagValues{})
	postgresConfig, postgresEnabled := postgresSnapshot.Signing().PostgreSQL()
	if err != nil || !postgresEnabled ||
		postgresSnapshot.Signing().Backend() != SigningPostgreSQL ||
		postgresConfig.MaxConnections() != 2 ||
		postgresConfig.IdleConnections() != 1 {
		t.Fatalf("PostgreSQL signing configuration failed with code %s", CodeOf(err))
	}
	mysqlSnapshot, err := Load([]byte(mysqlSigningYAML()), FlagValues{})
	mysqlConfig, mysqlEnabled := mysqlSnapshot.Signing().MySQL()
	if err != nil || !mysqlEnabled ||
		mysqlSnapshot.Signing().Backend() != SigningMySQL ||
		mysqlConfig.ServerName() != "mysql.example" ||
		mysqlConfig.MaxConnections() != 2 || mysqlConfig.IdleConnections() != 1 {
		t.Fatalf("MySQL signing configuration failed with code %s", CodeOf(err))
	}
	for _, document := range []string{
		strings.Replace(ldapSigningYAML(), "    transport: starttls", "    transport: plaintext", 1),
		strings.Replace(ldapSigningYAML(), "    address: 127.0.0.1:636", "    address: ldap.example:636", 1),
		strings.Replace(ldapSigningYAML(), "  backend: ldap", "  backend: ldap\n  private_manifest_file: /secure/"+testGeneration+"/private-manifest", 1),
		strings.Replace(ldapSigningYAML(), "  backend: ldap", "  backend: ldap\n  datasource_file: /secure/"+testGeneration+"/datasource", 1),
		strings.Replace(postgresqlSigningYAML(), "    max_connections: 2", "    max_connections: 5", 1),
		strings.Replace(postgresqlSigningYAML(), "    database: dkim2", "    database: dkim2;drop", 1),
		strings.Replace(mysqlSigningYAML(), "    max_connections: 2", "    max_connections: 5", 1),
		strings.Replace(mysqlSigningYAML(), "    database: dkim2", "    database: dkim2;drop", 1),
		strings.Replace(mysqlSigningYAML(), "  backend: mysql", "  backend: mysql\n  postgresql:\n    address: 127.0.0.1:5432", 1),
		strings.Replace(mysqlSigningYAML(), "  backend: mysql", "  backend: disabled", 1),
	} {
		if _, loadErr := Load([]byte(document), FlagValues{}); loadErr == nil {
			t.Fatal("network signing matrix accepted unsafe or irrelevant input")
		}
	}
}

// removeYAMLField removes one exact single-line test field.
func removeYAMLField(document, prefix string) string {
	lines := strings.Split(document, "\n")
	for index, line := range lines {
		if strings.HasPrefix(line, prefix) {
			return strings.Join(append(lines[:index], lines[index+1:]...), "\n")
		}
	}
	return document
}

// TestSigningConfigurationRejectsRecipientGroups proves the reserved
// compatibility path cannot enable signing without per-message Bcc evidence.
func TestSigningConfigurationRejectsRecipientGroups(t *testing.T) {
	clearStableEnvironment(t)
	t.Setenv("TEST_ALLOW_RECIPIENT_GROUP", canonicalTrue)
	document := strings.Replace(
		signingYAML(),
		"  backend: flat_file",
		"  backend: flat_file\n  allow_recipient_group: ${TEST_ALLOW_RECIPIENT_GROUP}",
		1,
	)
	if _, err := Load([]byte(document), FlagValues{}); err == nil {
		t.Fatal("Load() accepted reserved recipient-group signing")
	} else if CodeOf(err) != CodeInvalidField {
		t.Fatalf("Load() returned code %s for reserved recipient-group signing", CodeOf(err))
	}
}

// TestLoadMemoryExpandsExactTypedPlaceholders proves one-pass typed expansion.
func TestLoadMemoryExpandsExactTypedPlaceholders(t *testing.T) {
	clearStableEnvironment(t)
	t.Setenv("TEST_EPOCH", "42")
	t.Setenv("TEST_CAPABILITY_NAME", "capability")
	snapshot, err := Load([]byte(memoryYAML("${TEST_EPOCH}", "${TEST_CAPABILITY_NAME}")), FlagValues{})
	if err != nil {
		t.Fatalf("Load() failed with code %s", CodeOf(err))
	}
	if snapshot.Replay().Epoch() != 42 || !snapshot.Replay().Enabled() {
		t.Fatal("Load() did not preserve the expanded typed value")
	}
	if snapshot.Server().CapabilityFile() != "/secure/"+testGeneration+"/capability" {
		t.Fatal("Load() did not expand the destination string")
	}
}

// TestLoadRejectsBackendPresenceViolations proves hidden lower-precedence
// forbidden keys remain fail-closed.
func TestLoadRejectsBackendPresenceViolations(t *testing.T) {
	clearStableEnvironment(t)
	t.Setenv("DKIM2D_REPLAY_HMAC_KEY_FILE", "/secure/"+testGeneration+"/hmac")
	_, err := Load([]byte(disabledYAML()), NewFlagValues("", false, "", false, "disabled", true))
	if CodeOf(err) != CodeInvalidMatrix {
		t.Fatalf("Load() returned code %s for a forbidden lower source", CodeOf(err))
	}
}

// TestLoadRejectsWeakScalarConversions proves native spelling and placeholder
// provenance cannot be weakened into Viper coercion.
func TestLoadRejectsWeakScalarConversions(t *testing.T) {
	clearStableEnvironment(t)
	tests := []string{
		memoryYAML(`"1"`, "capability"),
		strings.Replace(memoryYAML("1", "capability"), "max_in_flight: 1", "max_in_flight: 01", 1),
		strings.Replace(memoryYAML("1", "capability"), "read_timeout: "+defaultReadTimeout, "read_timeout: \"30 s\"", 1),
	}
	for _, document := range tests {
		if _, err := Load([]byte(document), FlagValues{}); err == nil {
			t.Fatal("Load() accepted a weak scalar conversion")
		}
	}
}

// TestLoadRejectsCrossFieldAndAuthorityViolations freezes bounded typed checks.
func TestLoadRejectsCrossFieldAndAuthorityViolations(t *testing.T) {
	clearStableEnvironment(t)
	headerAfterRead := strings.Replace(memoryYAML("1", "capability"), "read_header_timeout: 5s", "read_header_timeout: 30s", 1)
	headerAfterRead = strings.Replace(headerAfterRead, "read_timeout: "+defaultReadTimeout, "read_timeout: 29s", 1)
	tests := []string{
		strings.Replace(memoryYAML("1", "capability"), "listen: "+defaultListenAddress, "listen: 0.0.0.0:8080", 1),
		headerAfterRead,
		strings.Replace(memoryYAML("1", "capability"), "read_timeout: "+defaultReadTimeout, "read_timeout: 61s", 1),
		strings.Replace(memoryYAML("1", "capability"), "write_timeout: 65s", "write_timeout: 60s", 1),
		strings.Replace(memoryYAML("1", "capability"), "max_in_flight: 1", "max_in_flight: 3", 1),
	}
	for _, document := range tests {
		if _, err := Load([]byte(document), FlagValues{}); CodeOf(err) != CodeInvalidField {
			t.Fatalf("Load() returned code %s for an invalid bound", CodeOf(err))
		}
	}
}

// TestHTTPDeadlineEqualityAndListenerClasses freezes exact production
// cross-field acceptance and loopback-only authority policy.
func TestHTTPDeadlineEqualityAndListenerClasses(t *testing.T) {
	clearStableEnvironment(t)
	equal := memoryYAML("1", "capability")
	equal = strings.Replace(equal, "read_header_timeout: 5s", "read_header_timeout: 1s", 1)
	equal = strings.Replace(equal, "read_timeout: "+defaultReadTimeout, "read_timeout: 1s", 1)
	equal = strings.Replace(equal, "request_deadline: 60s", "request_deadline: 1s", 1)
	equal = strings.Replace(equal, "write_timeout: 65s", "write_timeout: 2s", 1)
	if _, err := Load([]byte(equal), FlagValues{}); err != nil {
		t.Fatalf("Load() rejected exact deadline equality with code %s", CodeOf(err))
	}
	for _, listener := range []string{
		"localhost:8080", "0.0.0.0:8080", "[::]:8080",
		"[::ffff:127.0.0.1]:8080", "[fe80::1%lo0]:8080",
		"127.000.000.001:8080", "127.0.0.1:0", "127.0.0.1:08080",
	} {
		document := strings.Replace(memoryYAML("1", "capability"), "listen: "+defaultListenAddress, "listen: \""+listener+"\"", 1)
		if _, err := Load([]byte(document), FlagValues{}); CodeOf(err) != CodeInvalidField {
			t.Fatal("Load() accepted a forbidden listener class")
		}
	}
}

// TestPrivateNetworkListenerRequiresExplicitMode freezes the opt-in private-address boundary.
func TestPrivateNetworkListenerRequiresExplicitMode(t *testing.T) {
	clearStableEnvironment(t)
	base := memoryYAML("1", "capability")
	tlsFields := "  listener_mode: tls_private_network\n" +
		"  tls:\n" +
		"    certificate_file: /secure/" + testGeneration + "/server-cert.pem\n" +
		"    private_key_file: /secure/" + testGeneration + "/server-key.pem\n" +
		"    ca_file: /secure/" + testGeneration + "/server-ca.pem\n" +
		"    server_name: dkim2d-inbound"
	private := strings.Replace(base, "listen: "+defaultListenAddress,
		"listen: 10.73.0.2:8080\n"+tlsFields, 1)
	snapshot, err := Load([]byte(private), FlagValues{})
	if err != nil || snapshot.Server().Listen() != "10.73.0.2:8080" || !snapshot.Server().PrivateNetwork() {
		t.Fatal("Load() rejected the explicit private-network listener")
	}
	for _, document := range []string{
		strings.Replace(base, "listen: "+defaultListenAddress, "listen: 0.0.0.0:8080", 1),
		strings.Replace(base, "listen: "+defaultListenAddress,
			"listen: 127.0.0.1:8080\n"+tlsFields, 1),
		strings.Replace(base, "listen: "+defaultListenAddress,
			"listen: 192.0.2.1:8080\n"+tlsFields, 1),
		strings.Replace(base, "listen: "+defaultListenAddress,
			"listen: 0.0.0.0:8080\n"+tlsFields, 1),
	} {
		if _, loadErr := Load([]byte(document), FlagValues{}); CodeOf(loadErr) != CodeInvalidField {
			t.Fatal("Load() accepted a listener outside its selected mode")
		}
	}
}

// TestProtectedPathGenerationInvariants freezes lexical generation grouping
// before descriptor-safe ownership checks.
func TestProtectedPathGenerationInvariants(t *testing.T) {
	clearStableEnvironment(t)
	tests := []string{
		strings.Replace(memoryYAML("1", "capability"), "/secure/"+testGeneration+"/capability", "/secure/ffffffffffffffffffffffffffffffff/capability", 1),
		strings.Replace(memoryYAML("1", "capability"), "/secure/"+testGeneration+"/capability", "/secure/"+testGeneration+"/nested/capability", 1),
		strings.Replace(memoryYAML("1", "capability"), "/secure/"+testGeneration+"/hmac", "/other/"+testGeneration+"/hmac", 1),
		strings.Replace(memoryYAML("1", "capability"), "/secure/"+testGeneration+"/hmac", "/secure/"+testGeneration+"/capability", 1),
	}
	for _, document := range tests {
		if _, err := Load([]byte(document), FlagValues{}); CodeOf(err) != CodeInvalidField {
			t.Fatal("Load() accepted an invalid protected-path relation")
		}
	}
}

// TestLoadValkeyDelegatesAttestation proves the complete required matrix and
// M12 persistence constructor are used together.
func TestLoadValkeyDelegatesAttestation(t *testing.T) {
	clearStableEnvironment(t)
	snapshot, err := Load([]byte(valkeyYAML()), FlagValues{})
	if err != nil {
		t.Fatalf("Load() failed with code %s", CodeOf(err))
	}
	value, present := snapshot.Replay().Valkey()
	if !present || value.Address() != testValkeyAddress ||
		value.ApplicationUsername() != "application" ||
		value.AuditorUsername() != "auditor" {
		t.Fatal("Load() did not construct the exact Valkey configuration")
	}
	if _, present := snapshot.Replay().OperatorAttestation(); !present {
		t.Fatal("Load() did not retain the validated operator attestation")
	}
}

// TestConfigurationFormattingAndSerializationStayContentFree proves opaque
// wrappers cannot leak user-controlled values through ordinary diagnostics.
func TestConfigurationFormattingAndSerializationStayContentFree(t *testing.T) {
	clearStableEnvironment(t)
	const marker = "private-config-marker"
	flags := NewFlagValues(marker, true, marker, true, marker, true)
	document := strings.Replace(valkeyYAML(), "application_username: application", "application_username: "+marker, 1)
	document = strings.Replace(document, "application-password", marker+"-password", 1)
	snapshot, err := Load([]byte(document), FlagValues{})
	if err != nil {
		t.Fatalf("Load() failed with code %s", CodeOf(err))
	}
	valkeyConfig, present := snapshot.Replay().Valkey()
	if !present {
		t.Fatal("Load() omitted selected Valkey configuration")
	}
	values := []any{
		flags, &flags, []any{flags},
		snapshot, &snapshot, []any{snapshot},
		snapshot.Server(), &snapshot.state.server, []any{snapshot.Server()},
		snapshot.DNS(), []any{snapshot.DNS()},
		snapshot.Replay(), []any{snapshot.Replay()},
		valkeyConfig, []any{valkeyConfig},
		snapshot.PolicyMode(), snapshot.Backend(),
	}
	for _, value := range values {
		for _, format := range []string{"%s", "%q", "%v", "%+v", "%#v", "%x", "%p"} {
			if strings.Contains(fmt.Sprintf(format, value), marker) {
				t.Fatalf("configuration formatting exposed a marker for %T with %s", value, format)
			}
		}
	}
	for _, value := range []any{
		flags, snapshot, snapshot.Server(), snapshot.DNS(), snapshot.Replay(),
		valkeyConfig, snapshot.PolicyMode(), snapshot.Backend(),
	} {
		if _, marshalErr := json.Marshal(value); CodeOf(marshalErr) != CodeSerialization {
			t.Fatalf("%T allowed JSON serialization", value)
		}
		if marshaler, ok := value.(interface{ MarshalText() ([]byte, error) }); !ok {
			t.Fatalf("%T lacks text-serialization rejection", value)
		} else if _, marshalErr := marshaler.MarshalText(); CodeOf(marshalErr) != CodeSerialization {
			t.Fatalf("%T allowed text serialization", value)
		}
	}
}

// TestLoadedSnapshotDoesNotRereadEnvironment proves the immutable snapshot
// owns its selected values after construction.
func TestLoadedSnapshotDoesNotRereadEnvironment(t *testing.T) {
	clearStableEnvironment(t)
	t.Setenv("DKIM2D_POLICY_MODE", "permissive")
	snapshot, err := Load([]byte(disabledYAML()), FlagValues{})
	if err != nil {
		t.Fatalf("Load() failed with code %s", CodeOf(err))
	}
	t.Setenv("DKIM2D_POLICY_MODE", "testing")
	if snapshot.PolicyMode() != PolicyPermissive {
		t.Fatal("snapshot reread an environment source")
	}
}

// TestSourceAndExpansionAggregatesAreIndependent proves shadowed sources and
// expanded winners are each bounded by their own aggregate accounting pass.
func TestSourceAndExpansionAggregatesAreIndependent(t *testing.T) {
	stableNames := []string{
		"DKIM2D_REPLAY_VALKEY_ADDRESS",
		"DKIM2D_REPLAY_VALKEY_SERVER_NAME",
		"DKIM2D_REPLAY_VALKEY_CA_FILE",
		"DKIM2D_REPLAY_VALKEY_APPLICATION_USERNAME",
		"DKIM2D_REPLAY_VALKEY_APPLICATION_PASSWORD_FILE",
	}
	t.Run("pre expansion", func(t *testing.T) {
		clearStableEnvironment(t)
		for _, name := range stableNames {
			t.Setenv(name, strings.Repeat("x", 60_000))
		}
		if _, err := Load([]byte(disabledYAML()), FlagValues{}); CodeOf(err) != CodeInvalidField {
			t.Fatalf("Load() returned code %s for oversized source aggregate", CodeOf(err))
		}
	})
	t.Run("post expansion", func(t *testing.T) {
		clearStableEnvironment(t)
		t.Setenv("LARGE_EXPANSION", strings.Repeat("x", 60_000))
		for _, name := range stableNames {
			t.Setenv(name, "${LARGE_EXPANSION}")
		}
		if _, err := Load([]byte(disabledYAML()), FlagValues{}); CodeOf(err) != CodeInvalidField {
			t.Fatalf("Load() returned code %s for oversized expansion aggregate", CodeOf(err))
		}
	})
}

// TestValkeyMappedIPv6MatchesM12Grammar prevents the command-layer validator
// from narrowing a canonical authority accepted by the M12 owner.
func TestValkeyMappedIPv6MatchesM12Grammar(t *testing.T) {
	clearStableEnvironment(t)
	document := strings.Replace(valkeyYAML(), "address: "+testValkeyAddress, "address: \"[::ffff:192.0.2.1]:6379\"", 1)
	document = strings.Replace(document, "server_name: replay.example", "server_name: \"::ffff:192.0.2.1\"", 1)
	if _, err := Load([]byte(document), FlagValues{}); err != nil {
		t.Fatalf("Load() narrowed the M12 authority grammar with code %s", CodeOf(err))
	}
}

// TestBackendMatrixExhaustivelyChecksPresence freezes every required,
// optional, and forbidden backend key independently of typed defaults.
func TestBackendMatrixExhaustivelyChecksPresence(t *testing.T) {
	common := []string{pathConfigVersion, pathProtectedGeneration, pathServerCapability}
	allReplay := make([]string, 0)
	allValkey := make([]string, 0)
	for _, spec := range stableFieldSpecs() {
		if strings.HasPrefix(spec.path, "replay.") {
			allReplay = append(allReplay, spec.path)
		}
		if strings.HasPrefix(spec.path, "replay.valkey.") {
			allValkey = append(allValkey, spec.path)
		}
	}
	t.Run("disabled forbidden", func(t *testing.T) {
		base := append(append([]string(nil), common...), pathReplayBackend)
		if err := validateBackendMatrix(ReplayDisabled, explicitPresence(base...), nil); err != nil {
			t.Fatal("valid disabled matrix was rejected")
		}
		for _, path := range allReplay {
			if path == pathReplayBackend {
				continue
			}
			present := append(append([]string(nil), base...), path)
			if err := validateBackendMatrix(ReplayDisabled, explicitPresence(present...), nil); CodeOf(err) != CodeInvalidMatrix {
				t.Fatal("disabled matrix accepted a forbidden replay key")
			}
		}
	})
	t.Run("memory required and forbidden", func(t *testing.T) {
		required := append(append([]string(nil), common...), pathReplayBackend, "replay.hmac_key_file", "replay.epoch")
		if err := validateBackendMatrix(ReplayMemory, explicitPresence(required...), nil); err != nil {
			t.Fatal("valid memory matrix was rejected")
		}
		for index := range required {
			missing := append([]string(nil), required[:index]...)
			missing = append(missing, required[index+1:]...)
			if err := validateBackendMatrix(ReplayMemory, explicitPresence(missing...), nil); CodeOf(err) != CodeInvalidMatrix {
				t.Fatal("memory matrix accepted a missing required key")
			}
		}
		for _, path := range append(allValkey, "replay.revalidate_interval") {
			present := append(append([]string(nil), required...), path)
			if err := validateBackendMatrix(ReplayMemory, explicitPresence(present...), nil); CodeOf(err) != CodeInvalidMatrix {
				t.Fatal("memory matrix accepted a forbidden key")
			}
		}
		for _, path := range []string{
			pathReplayRetention, pathReplayMaxEntries, pathReplayMaxWaiters,
			pathReplayPruneBudget, pathReplayMaxInFlight,
			pathReplayMaxAdmission,
		} {
			present := append(append([]string(nil), required...), path)
			if err := validateBackendMatrix(ReplayMemory, explicitPresence(present...), nil); err != nil {
				t.Fatal("memory matrix rejected an optional key")
			}
		}
	})
	t.Run("valkey required", func(t *testing.T) {
		required := []string{
			pathConfigVersion, pathProtectedGeneration, pathServerCapability,
			pathReplayHMACFile, pathReplayEpoch,
			pathValkeyAddress, pathValkeyServerName, pathValkeyCAFile,
			pathValkeyApplicationUser, pathValkeyApplicationPass,
			pathValkeyAuditorUser, pathValkeyAuditorPass,
			pathAttestationPersistence,
			pathAttestationFsync,
			pathAttestationSave,
			pathAttestationMinReplicas,
			pathAttestationMaxLag,
			pathAttestationLossWindow,
			pathAttestationRotation,
			pathAttestationNoGlobalExactlyOnce, pathAttestationDedicatedDeployment,
			pathAttestationDedicatedDatabase, pathAttestationDirectIPAuthority,
			pathAttestationNoSubstitution, pathAttestationStandaloneAuthority,
			pathAttestationSharedDraft, pathAttestationSharedAlgorithm,
			pathAttestationSharedNamespace, pathAttestationSharedEpoch,
			pathAttestationSharedSecretSet, pathAttestationSharedRetention,
		}
		values := map[string]rawValue{
			"replay.valkey.attestation.persistence_mode": {text: "rdb"},
		}
		if err := validateBackendMatrix(ReplayValkey, explicitPresence(required...), values); err != nil {
			t.Fatal("valid Valkey matrix was rejected")
		}
		for index := range required {
			missing := append([]string(nil), required[:index]...)
			missing = append(missing, required[index+1:]...)
			if err := validateBackendMatrix(ReplayValkey, explicitPresence(missing...), values); CodeOf(err) != CodeInvalidMatrix {
				t.Fatal("Valkey matrix accepted a missing required key")
			}
		}
		for _, path := range []string{
			pathReplayBackend, pathReplayRetention, pathReplayMaxEntries,
			pathReplayMaxWaiters, pathReplayPruneBudget,
			pathReplayMaxInFlight, pathReplayMaxAdmission,
			pathReplayRevalidate, pathValkeyDialTimeout,
			pathValkeyTCPKeepalive, pathValkeyWriteTimeout,
		} {
			present := append(append([]string(nil), required...), path)
			if err := validateBackendMatrix(ReplayValkey, explicitPresence(present...), values); err != nil {
				t.Fatal("Valkey matrix rejected an optional key")
			}
		}
	})
}

// TestValkeyAttestationPresenceIsExhaustive proves explicit zero is distinct
// from absence and every trusted assertion is required.
func TestValkeyAttestationPresenceIsExhaustive(t *testing.T) {
	clearStableEnvironment(t)
	requiredLines := []string{
		"      persistence_mode: rdb\n",
		"      append_fsync_policy: inactive\n",
		"      save_schedule: \"60 1\"\n",
		"      min_replicas_to_write: 0\n",
		"      min_replicas_max_lag_seconds: 30\n",
		"      loss_window_acceptance: asynchronous_acknowledged\n",
		"      rotation_state: unchanged\n",
		"      no_global_exactly_once_claim: true\n",
		"      dedicated_deployment: true\n",
		"      dedicated_database_zero: true\n",
		"      direct_ip_authority: true\n",
		"      no_endpoint_substitution: true\n",
		"      standalone_authority: true\n",
		"      shared_draft: true\n",
		"      shared_algorithm: true\n",
		"      shared_namespace: true\n",
		"      shared_epoch: true\n",
		"      shared_secret_set: true\n",
		"      shared_retention: true\n",
	}
	for _, line := range requiredLines {
		document := strings.Replace(valkeyYAML(), line, "", 1)
		if _, err := Load([]byte(document), FlagValues{}); err == nil {
			t.Fatal("Load() accepted a missing attestation leaf")
		}
	}
	aof := strings.Replace(valkeyYAML(), "persistence_mode: rdb", "persistence_mode: aof", 1)
	aof = strings.Replace(aof, "append_fsync_policy: inactive", "append_fsync_policy: always", 1)
	aof = strings.Replace(aof, "      save_schedule: \"60 1\"\n", "", 1)
	if _, err := Load([]byte(aof), FlagValues{}); err != nil {
		t.Fatalf("Load() rejected valid AOF absence with code %s", CodeOf(err))
	}
	aofWithSave := strings.Replace(aof, "      min_replicas_to_write: 0\n", "      save_schedule: \"60 1\"\n      min_replicas_to_write: 0\n", 1)
	if _, err := Load([]byte(aofWithSave), FlagValues{}); CodeOf(err) != CodeInvalidMatrix {
		t.Fatal("Load() accepted forbidden AOF save_schedule")
	}
}

// TestScalarLexicalAndRangeTables freezes canonical boolean, integer, and
// duration syntax at and around every shared conversion boundary.
func TestScalarLexicalAndRangeTables(t *testing.T) {
	uintCases := []struct {
		text string
		ok   bool
	}{
		{text: "0", ok: true}, {text: "1", ok: true}, {text: "4294967295", ok: true},
		{text: ""}, {text: "00"}, {text: "01"}, {text: "+1"}, {text: "-1"},
		{text: "1_0"}, {text: " 1"}, {text: "1 "}, {text: "18446744073709551616"},
	}
	for _, test := range uintCases {
		values := map[string]rawValue{testValuePath: {text: test.text, kind: scalarString, source: SourceEnvironment}}
		_, err := uintValue(values, testValuePath, 0, ^uint64(0))
		if (err == nil) != test.ok {
			t.Fatal("uint lexical table decision changed")
		}
	}
	durationCases := []struct {
		text      string
		allowZero bool
		ok        bool
	}{
		{text: "1ms", ok: true}, {text: "1s", ok: true}, {text: "1m", ok: true},
		{text: "1h", ok: true}, {text: "0s", allowZero: true, ok: true},
		{text: "0s"}, {text: "01s"}, {text: "1us"}, {text: "1.0s"},
		{text: "+1s"}, {text: " 1s"}, {text: "1 s"},
	}
	for _, test := range durationCases {
		if canonicalDuration(test.text, test.allowZero) != test.ok {
			t.Fatal("duration lexical table decision changed")
		}
	}
	for _, text := range []string{canonicalTrue, canonicalFalse} {
		values := map[string]rawValue{testValuePath: {text: text, kind: scalarString, source: SourceEnvironment}}
		if _, err := boolValue(values, testValuePath); err != nil {
			t.Fatal("canonical boolean was rejected")
		}
	}
	for _, text := range []string{"TRUE", "False", "0", "1", " true"} {
		values := map[string]rawValue{testValuePath: {text: text, kind: scalarString, source: SourceEnvironment}}
		if _, err := boolValue(values, testValuePath); CodeOf(err) != CodeInvalidField {
			t.Fatal("noncanonical boolean was accepted")
		}
	}
	uintRanges := []struct {
		path string
		min  uint64
		max  uint64
	}{
		{path: pathServerMaxInFlight, min: 1, max: 2},
		{path: pathServerMaxWaiters, min: 0, max: 1024},
		{path: pathDNSMaxConcurrent, min: 1, max: 1024},
		{path: pathDNSCacheMaxEntries, min: 0, max: 65_536},
		{path: pathReplayEpoch, min: 1, max: 4_294_967_295},
		{path: pathReplayMaxEntries, min: 1, max: 1_048_576},
		{path: pathReplayMaxWaiters, min: 1, max: 65_536},
		{path: pathReplayPruneBudget, min: 1, max: 65_536},
		{path: pathReplayMaxInFlight, min: 1, max: 65_536},
		{path: pathReplayMaxAdmission, min: 1, max: 65_536},
		{path: pathAttestationMinReplicas, min: 0, max: 3},
		{path: pathAttestationMaxLag, min: 1, max: 3600},
	}
	for _, bounds := range uintRanges {
		for _, valid := range []uint64{bounds.min, bounds.max} {
			values := map[string]rawValue{bounds.path: {text: fmt.Sprint(valid), kind: scalarString, source: SourceEnvironment}}
			if _, err := uintValue(values, bounds.path, bounds.min, bounds.max); err != nil {
				t.Fatal("uint boundary was rejected")
			}
		}
		if bounds.min > 0 {
			values := map[string]rawValue{bounds.path: {text: fmt.Sprint(bounds.min - 1), kind: scalarString, source: SourceEnvironment}}
			if _, err := uintValue(values, bounds.path, bounds.min, bounds.max); err == nil {
				t.Fatal("uint below minimum was accepted")
			}
		}
		values := map[string]rawValue{bounds.path: {text: fmt.Sprint(bounds.max + 1), kind: scalarString, source: SourceEnvironment}}
		if _, err := uintValue(values, bounds.path, bounds.min, bounds.max); err == nil {
			t.Fatal("uint above maximum was accepted")
		}
	}
	durationRanges := []struct {
		path      string
		min       time.Duration
		max       time.Duration
		minText   string
		maxText   string
		belowText string
		aboveText string
		allowZero bool
	}{
		{path: pathServerReadHeader, min: time.Second, max: 30 * time.Second, minText: "1s", maxText: defaultReadTimeout, belowText: duration999ms, aboveText: duration31s},
		{path: pathServerRead, min: time.Second, max: 120 * time.Second, minText: "1s", maxText: duration120s, belowText: duration999ms, aboveText: duration121s},
		{path: pathServerWrite, min: time.Second, max: 180 * time.Second, minText: "1s", maxText: "180s", belowText: duration999ms, aboveText: "181s"},
		{path: pathServerDeadline, min: time.Second, max: 120 * time.Second, minText: "1s", maxText: duration120s, belowText: duration999ms, aboveText: duration121s},
		{path: pathServerShutdown, min: time.Second, max: 120 * time.Second, minText: "1s", maxText: duration120s, belowText: duration999ms, aboveText: duration121s},
		{path: pathServerAdmissionWait, min: 0, max: time.Second, minText: "0s", maxText: "1s", belowText: "", aboveText: "1001ms", allowZero: true},
		{path: pathDNSLookupTimeout, min: time.Millisecond, max: 30 * time.Second, minText: "1ms", maxText: defaultReadTimeout, belowText: "0s", aboveText: "30001ms"},
		{path: pathDNSPositiveTTLCap, min: 0, max: 24 * time.Hour, minText: "0s", maxText: "24h", aboveText: "25h", allowZero: true},
		{path: pathDNSNegativeTTLCap, min: 0, max: time.Hour, minText: "0s", maxText: "1h", aboveText: "61m", allowZero: true},
		{path: pathDNSStableErrorTTLCap, min: 0, max: 5 * time.Minute, minText: "0s", maxText: "5m", aboveText: "301s", allowZero: true},
		{path: pathReplayRetention, min: time.Second, max: 720 * time.Hour, minText: "1s", maxText: "720h", belowText: "0s", aboveText: "721h"},
		{path: pathReplayRevalidate, min: 10 * time.Second, max: 60 * time.Second, minText: "10s", maxText: defaultDeadline, belowText: "9s", aboveText: "61s"},
		{path: pathValkeyDialTimeout, min: 100 * time.Millisecond, max: 30 * time.Second, minText: defaultAdmissionWait, maxText: defaultReadTimeout, belowText: duration99ms, aboveText: duration31s},
		{path: pathValkeyTCPKeepalive, min: time.Second, max: 5 * time.Minute, minText: "1s", maxText: "5m", belowText: duration999ms, aboveText: "301s"},
		{path: pathValkeyWriteTimeout, min: 100 * time.Millisecond, max: 30 * time.Second, minText: defaultAdmissionWait, maxText: defaultReadTimeout, belowText: duration99ms, aboveText: duration31s},
	}
	for _, bounds := range durationRanges {
		for _, valid := range []string{bounds.minText, bounds.maxText} {
			values := map[string]rawValue{bounds.path: {text: valid, kind: scalarString, source: SourceEnvironment}}
			if _, err := durationValue(values, bounds.path, bounds.min, bounds.max, bounds.allowZero); err != nil {
				t.Fatal("duration boundary was rejected")
			}
		}
		for _, invalid := range []string{bounds.belowText, bounds.aboveText} {
			if invalid == "" {
				continue
			}
			values := map[string]rawValue{bounds.path: {text: invalid, kind: scalarString, source: SourceEnvironment}}
			if _, err := durationValue(values, bounds.path, bounds.min, bounds.max, bounds.allowZero); err == nil {
				t.Fatal("duration outside range was accepted")
			}
		}
	}
}

// TestLoadPlaceholderPresence distinguishes missing from present-empty values.
func TestLoadPlaceholderPresence(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		clearStableEnvironment(t)
		if _, err := Load([]byte(memoryYAML("${MISSING_EPOCH}", "capability")), FlagValues{}); CodeOf(err) != CodeInvalidPlaceholder {
			t.Fatal("missing placeholder did not fail closed")
		}
	})
	t.Run("present empty", func(t *testing.T) {
		clearStableEnvironment(t)
		t.Setenv("EMPTY_EPOCH", "")
		if _, err := Load([]byte(memoryYAML("${EMPTY_EPOCH}", "capability")), FlagValues{}); CodeOf(err) != CodeInvalidField {
			t.Fatal("present-empty placeholder did not reach typed validation")
		}
	})
}

// TestLoadClonesCallerBytes proves later caller mutation cannot alter a snapshot.
func TestLoadClonesCallerBytes(t *testing.T) {
	clearStableEnvironment(t)
	data := []byte(disabledYAML())
	snapshot, err := Load(data, FlagValues{})
	if err != nil {
		t.Fatalf("Load() failed with code %s", CodeOf(err))
	}
	for index := range data {
		data[index] = 'x'
	}
	if snapshot.Backend() != ReplayDisabled || snapshot.Generation() != testGeneration {
		t.Fatal("caller mutation altered the loaded snapshot")
	}
}

// explicitPresence returns one synthetic explicit-YAML presence map.
func explicitPresence(paths ...string) map[string]Presence {
	result := make(map[string]Presence, len(paths))
	for _, path := range paths {
		result[path] = Presence{YAML: true, Winner: SourceYAML}
	}
	return result
}

// FuzzLoadStrict exercises the complete bounded YAML, merge, expansion, and
// typed-validation pipeline without allowing panics or ambient bindings.
func FuzzLoadStrict(f *testing.F) {
	clearStableEnvironmentF(f)
	f.Add([]byte(disabledYAML()))
	f.Add([]byte(memoryYAML("1", "capability")))
	f.Add([]byte(valkeyYAML()))
	f.Add([]byte(disabledYAML() + `
observability:
  tracing:
    exporter: otlp_http
    endpoint: https://metrics.example:4318/v1/traces
    ca_file: /secure/` + testGeneration + `/otlp-ca
`))
	f.Add([]byte("config: ["))
	f.Fuzz(func(t *testing.T, data []byte) {
		snapshot, err := Load(data, FlagValues{})
		if err == nil && !snapshot.Valid() {
			t.Fatal("Load() returned an invalid successful snapshot")
		}
	})
}

// clearStableEnvironmentF isolates the typed fuzz pipeline from ambient config.
func clearStableEnvironmentF(f *testing.F) {
	f.Helper()
	for _, spec := range stableFieldSpecs() {
		if spec.env == "" {
			continue
		}
		value, present := os.LookupEnv(spec.env)
		if !present {
			continue
		}
		if err := os.Unsetenv(spec.env); err != nil {
			f.Fatal("failed to isolate configuration environment")
		}
		name := spec.env
		f.Cleanup(func() {
			if err := os.Setenv(name, value); err != nil {
				f.Error("failed to restore configuration environment")
			}
		})
	}
}

// disabledYAML returns one minimal valid explicit-disabled document.
func disabledYAML() string {
	return `config:
  version: dkim2d-config-v1
protected:
  generation: ` + testGeneration + `
server:
  capability_file: /secure/` + testGeneration + `/capability
replay:
  backend: disabled
`
}

// signingYAML returns one complete same-generation flat-file signing document.
func signingYAML() string {
	return `config:
  version: dkim2d-config-v1
protected:
  generation: ` + testGeneration + `
server:
  capability_file: /secure/` + testGeneration + `/capability
  sign_capability_file: /secure/` + testGeneration + `/sign-capability
  revise_capability_file: /secure/` + testGeneration + `/revise-capability
  dsn_sign_capability_file: /secure/` + testGeneration + `/dsn-sign-capability
replay:
  backend: disabled
signing:
  backend: flat_file
  datasource_file: /secure/` + testGeneration + `/datasource
  private_manifest_file: /secure/` + testGeneration + `/private-manifest
`
}

// ldapSigningYAML returns one complete verified LDAP signing document.
func ldapSigningYAML() string {
	return `config:
  version: dkim2d-config-v1
protected:
  generation: ` + testGeneration + `
server:
  capability_file: /secure/` + testGeneration + `/capability
  sign_capability_file: /secure/` + testGeneration + `/sign-capability
replay:
  backend: disabled
signing:
  backend: ldap
  ldap:
    address: 127.0.0.1:636
    server_name: ldap.example
    ca_file: /secure/` + testGeneration + `/ldap-ca
    transport: starttls
    bind_dn: cn=runtime,dc=example,dc=test
    password_file: /secure/` + testGeneration + `/ldap-password
    base_dn: ou=dkim2,dc=example,dc=test
`
}

// postgresqlSigningYAML returns one complete verified PostgreSQL signing document.
func postgresqlSigningYAML() string {
	return `config:
  version: dkim2d-config-v1
protected:
  generation: ` + testGeneration + `
server:
  capability_file: /secure/` + testGeneration + `/capability
  sign_capability_file: /secure/` + testGeneration + `/sign-capability
replay:
  backend: disabled
signing:
  backend: postgresql
  postgresql:
    address: 127.0.0.1:5432
    server_name: postgresql.example
    ca_file: /secure/` + testGeneration + `/postgresql-ca
    database: dkim2
    user: dkim2_runtime
    password_file: /secure/` + testGeneration + `/postgresql-password
    max_connections: 2
    idle_connections: 1
`
}

// mysqlSigningYAML returns one complete verified MySQL signing document.
func mysqlSigningYAML() string {
	return `config:
  version: dkim2d-config-v1
protected:
  generation: ` + testGeneration + `
server:
  capability_file: /secure/` + testGeneration + `/capability
  sign_capability_file: /secure/` + testGeneration + `/sign-capability
replay:
  backend: disabled
signing:
  backend: mysql
  mysql:
    address: 127.0.0.1:3306
    server_name: mysql.example
    ca_file: /secure/` + testGeneration + `/mysql-ca
    database: dkim2
    user: dkim2_runtime
    password_file: /secure/` + testGeneration + `/mysql-password
    max_connections: 2
    idle_connections: 1
`
}

// memoryYAML returns one valid memory document with caller-selected scalar cases.
func memoryYAML(epoch, capabilityName string) string {
	return `config:
  version: dkim2d-config-v1
protected:
  generation: ` + testGeneration + `
server:
  listen: 127.0.0.1:8080
  capability_file: /secure/` + testGeneration + `/` + capabilityName + `
  read_header_timeout: 5s
  read_timeout: 30s
  write_timeout: 65s
  request_deadline: 60s
  max_in_flight: 1
replay:
  backend: memory
  hmac_key_file: /secure/` + testGeneration + `/hmac
  epoch: ` + epoch + `
`
}

// valkeyYAML returns one complete valid Valkey document.
func valkeyYAML() string {
	return `config:
  version: dkim2d-config-v1
protected:
  generation: ` + testGeneration + `
server:
  capability_file: /secure/` + testGeneration + `/capability
replay:
  hmac_key_file: /secure/` + testGeneration + `/hmac
  epoch: 1
  valkey:
    address: 127.0.0.1:6379
    server_name: replay.example
    ca_file: /secure/` + testGeneration + `/ca
    application_username: application
    application_password_file: /secure/` + testGeneration + `/application-password
    auditor_username: auditor
    auditor_password_file: /secure/` + testGeneration + `/auditor-password
    attestation:
      persistence_mode: rdb
      append_fsync_policy: inactive
      save_schedule: "60 1"
      min_replicas_to_write: 0
      min_replicas_max_lag_seconds: 30
      loss_window_acceptance: asynchronous_acknowledged
      rotation_state: unchanged
      no_global_exactly_once_claim: true
      dedicated_deployment: true
      dedicated_database_zero: true
      direct_ip_authority: true
      no_endpoint_substitution: true
      standalone_authority: true
      shared_draft: true
      shared_algorithm: true
      shared_namespace: true
      shared_epoch: true
      shared_secret_set: true
      shared_retention: true
`
}
