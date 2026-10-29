package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2"
)

const (
	testGeneration = "0123456789abcdef0123456789abcdef"
	testTenant     = "tenant-a"
)

const testRedisAddress = "redis.internal:6379"

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

// TestRemovedDraft06SigningFlagKeysFailWithMigrationGuidance reproduces the
// Draft-07 Section 10.10 removal of donotmodify and donotexplode: every former
// signing.policy.<use>.donotmodify|donotexplode key and its DKIM2D_*
// environment variable fails closed with fixed, value-free migration guidance,
// even when set to false and even under a disabled signer.
func TestRemovedDraft06SigningFlagKeysFailWithMigrationGuidance(t *testing.T) {
	clearStableEnvironment(t)
	if _, err := Load([]byte(signingYAML()), FlagValues{}); err != nil {
		t.Fatalf("Load(signing) without removed keys code = %s", CodeOf(err))
	}
	const secretMarker = "removed-key-secret-marker"
	fields := make([]removedField, 0, 6)
	for _, field := range removedFields() {
		if field.guidance == removedDraft06FlagGuidance {
			fields = append(fields, field)
		}
	}
	if len(fields) != 6 {
		t.Fatalf("removed Draft-06 field count = %d, want 6", len(fields))
	}
	for _, field := range fields {
		segments := strings.Split(field.path, ".")
		if len(segments) != 4 || segments[0] != "signing" || segments[1] != "policy" {
			t.Fatalf("removed path %q is outside signing.policy", field.path)
		}
		leaf := "  policy:\n    " + segments[2] + ":\n      " + segments[3] + ": "
		for name, document := range map[string]string{
			"signing true":   strings.Replace(signingYAML(), "  backend: flat_file", "  backend: flat_file\n"+leaf+"true", 1),
			"signing false":  strings.Replace(signingYAML(), "  backend: flat_file", "  backend: flat_file\n"+leaf+"false", 1),
			"disabled false": disabledYAML() + "signing:\n" + leaf + "false\n",
			"secret value":   strings.Replace(signingYAML(), "  backend: flat_file", "  backend: flat_file\n"+leaf+"\""+secretMarker+"\"", 1),
		} {
			_, err := Load([]byte(document), FlagValues{})
			assertRemovedFieldError(t, err, field.path, secretMarker, name)
		}
		t.Run(field.env, func(t *testing.T) {
			t.Setenv(field.env, secretMarker)
			_, err := Load([]byte(signingYAML()), FlagValues{})
			assertRemovedFieldError(t, err, field.env, secretMarker, "environment")
		})
	}
	unknown := strings.Replace(signingYAML(), "  backend: flat_file", "  backend: flat_file\n  policy:\n    originator:\n      exploded: false", 1)
	if _, err := Load([]byte(unknown), FlagValues{}); CodeOf(err) != CodeInvalidYAML {
		t.Fatalf("unknown signing policy key code = %s, want %s", CodeOf(err), CodeInvalidYAML)
	}
}

// assertRemovedFieldError checks one removed-key failure names the exact key,
// carries Draft-07 migration guidance, and never echoes the configured value.
func assertRemovedFieldError(t *testing.T, err error, key, secretMarker, name string) {
	t.Helper()
	if CodeOf(err) != CodeRemovedField {
		t.Fatalf("%s %s code = %s, want %s", key, name, CodeOf(err), CodeRemovedField)
	}
	migration, ok := MigrationOf(err)
	if !ok || !strings.Contains(migration, key+" was removed in Draft-07") ||
		!strings.Contains(migration, "donotmodify and donotexplode") || !strings.Contains(migration, "delete this setting") {
		t.Fatalf("%s %s migration = %q", key, name, migration)
	}
	if !strings.HasPrefix(err.Error(), string(CodeRemovedField)+": ") || strings.Contains(err.Error(), secretMarker) {
		t.Fatalf("%s %s error = %q", key, name, err.Error())
	}
}

// TestDeliveryStatusUnsignedOriginalPolicyDefaultsToRejectAndFailsClosed
// proves the delivery-status compatibility policy is an explicit opt-in with
// a fail-closed default, an exact closed vocabulary, and no effect on a
// daemon whose signing backend is disabled.
func TestDeliveryStatusUnsignedOriginalPolicyDefaultsToRejectAndFailsClosed(t *testing.T) {
	clearStableEnvironment(t)
	for name, document := range map[string]string{"disabled": disabledYAML(), "signing": signingYAML()} {
		snapshot, err := Load([]byte(document), FlagValues{})
		if err != nil || snapshot.Signing().Policies().DeliveryStatusUnsignedOriginal() != UnsignedOriginalReject {
			t.Fatalf("omitted %s policy did not default to reject: code=%s", name, CodeOf(err))
		}
	}
	if (SigningPoliciesConfig{}).DeliveryStatusUnsignedOriginal() != UnsignedOriginalReject {
		t.Fatal("absent policy view relaxed the unsigned-original policy")
	}
	withPolicy := func(value string) string {
		return strings.Replace(signingYAML(), "  backend: flat_file",
			"  backend: flat_file\n  policy:\n    delivery_status:\n      unsigned_original: "+value, 1)
	}
	for value, want := range map[string]UnsignedOriginalPolicy{
		"reject": UnsignedOriginalReject, "continue": UnsignedOriginalContinue,
	} {
		snapshot, err := Load([]byte(withPolicy(value)), FlagValues{})
		if err != nil || snapshot.Signing().Policies().DeliveryStatusUnsignedOriginal() != want {
			t.Fatalf("unsigned_original %q code=%s", value, CodeOf(err))
		}
		if snapshot.Signing().Policies().OriginatorNullSender() != NullSenderReject {
			t.Fatal("unsigned_original changed the originator null-sender policy")
		}
	}
	for _, value := range []string{"accept", "Continue", "CONTINUE", "true", "\"\"", "\"reject \"", "sign"} {
		if _, err := Load([]byte(withPolicy(value)), FlagValues{}); err == nil {
			t.Fatalf("unknown unsigned_original value %q was accepted", value)
		}
	}
	disabledContinue := disabledYAML() + "signing:\n  policy:\n    delivery_status:\n      unsigned_original: continue\n"
	if _, err := Load([]byte(disabledContinue), FlagValues{}); CodeOf(err) != CodeInvalidMatrix {
		t.Fatalf("continue under a disabled signer code=%s", CodeOf(err))
	}
	disabledReject := disabledYAML() + "signing:\n  policy:\n    delivery_status:\n      unsigned_original: reject\n"
	if _, err := Load([]byte(disabledReject), FlagValues{}); err != nil {
		t.Fatalf("explicit reject under a disabled signer code=%s", CodeOf(err))
	}
	t.Setenv(envSigningPolicyDeliveryUnsigned, "continue")
	environment, err := Load([]byte(signingYAML()), FlagValues{})
	if err != nil || environment.Signing().Policies().DeliveryStatusUnsignedOriginal() != UnsignedOriginalContinue {
		t.Fatalf("environment unsigned_original override code=%s", CodeOf(err))
	}
	t.Setenv(envSigningPolicyDeliveryUnsigned, "permit")
	if _, err := Load([]byte(signingYAML()), FlagValues{}); err == nil {
		t.Fatal("invalid unsigned_original environment value was accepted")
	}
}

// TestDeliveryStatusReportingDomainIsExplicitCanonicalAndFailsClosed proves
// the reporting-MTA DSN identity is absent by default, accepts only one
// canonical DNS domain, and is refused by a daemon whose signer is disabled.
func TestDeliveryStatusReportingDomainIsExplicitCanonicalAndFailsClosed(t *testing.T) {
	clearStableEnvironment(t)
	for name, document := range map[string]string{"disabled backend": disabledYAML(), "flat-file backend": signingYAML()} {
		snapshot, err := Load([]byte(document), FlagValues{})
		if _, ok := snapshot.Signing().Policies().DeliveryStatusReportingIdentity(); err != nil || ok {
			t.Fatalf("omitted %s reporting_domain selected an identity: code=%s", name, CodeOf(err))
		}
	}
	if _, ok := (SigningPoliciesConfig{}).DeliveryStatusReportingIdentity(); ok {
		t.Fatal("absent policy view selected a reporting identity")
	}
	withDomain := func(value string) string {
		return strings.Replace(signingYAML(), "  backend: flat_file",
			"  backend: flat_file\n  policy:\n    delivery_status:\n      reporting_domain: "+value, 1)
	}
	snapshot, err := Load([]byte(withDomain("reports.example.test")), FlagValues{})
	identity, ok := snapshot.Signing().Policies().DeliveryStatusReportingIdentity()
	want, wantErr := dkim2.NewDSNIdentity("reports.example.test")
	if err != nil || !ok || wantErr != nil || identity != want {
		t.Fatalf("reporting_domain ok=%t code=%s", ok, CodeOf(err))
	}
	if snapshot.Signing().Policies().DeliveryStatusUnsignedOriginal() != UnsignedOriginalReject {
		t.Fatal("reporting_domain changed the unsigned-original policy")
	}
	for _, value := range []string{"\"\"", "Reports.Example.Test", "reports.example.test.", "\"*.example.test\"", "user@example.test", "\"192.0.2.1\"", "localhost", "test", "\"reports example.test\""} {
		if _, err := Load([]byte(withDomain(value)), FlagValues{}); CodeOf(err) != CodeInvalidField {
			t.Fatalf("invalid reporting_domain %q code=%s", value, CodeOf(err))
		}
	}
	disabled := disabledYAML() + "signing:\n  policy:\n    delivery_status:\n      reporting_domain: reports.example.test\n"
	if _, err := Load([]byte(disabled), FlagValues{}); CodeOf(err) != CodeInvalidMatrix {
		t.Fatalf("reporting_domain under a disabled signer code=%s", CodeOf(err))
	}
	t.Setenv(envSigningPolicyDeliveryReporting, "reports.example.test")
	environment, err := Load([]byte(signingYAML()), FlagValues{})
	if identity, ok := environment.Signing().Policies().DeliveryStatusReportingIdentity(); err != nil || !ok || identity != want {
		t.Fatalf("environment reporting_domain override ok=%t code=%s", ok, CodeOf(err))
	}
}

// TestOriginatorNullSenderPolicyDefaultsToRejectAndFailsClosed proves the
// originator null-sender policy is reject unless header_from is spelled
// exactly, and that a disabled signer refuses the relaxation.
func TestOriginatorNullSenderPolicyDefaultsToRejectAndFailsClosed(t *testing.T) {
	clearStableEnvironment(t)
	for name, document := range map[string]string{"disabled backend": disabledYAML(), "flat-file signing": signingYAML()} {
		snapshot, err := Load([]byte(document), FlagValues{})
		if err != nil || snapshot.Signing().Policies().OriginatorNullSender() != NullSenderReject {
			t.Fatalf("omitted %s null_sender did not default to reject: code=%s", name, CodeOf(err))
		}
	}
	if (SigningPoliciesConfig{}).OriginatorNullSender() != NullSenderReject {
		t.Fatal("absent policy view relaxed the null-sender policy")
	}
	withPolicy := func(value string) string {
		return strings.Replace(signingYAML(), "  backend: flat_file",
			"  backend: flat_file\n  policy:\n    originator:\n      null_sender: "+value, 1)
	}
	for value, want := range map[string]NullSenderPolicy{
		valueNullSenderReject: NullSenderReject, valueNullSenderHeaderFrom: NullSenderHeaderFrom,
	} {
		snapshot, err := Load([]byte(withPolicy(value)), FlagValues{})
		if err != nil || snapshot.Signing().Policies().OriginatorNullSender() != want {
			t.Fatalf("null_sender %q code=%s", value, CodeOf(err))
		}
		if snapshot.Signing().Policies().DeliveryStatusUnsignedOriginal() != UnsignedOriginalReject {
			t.Fatal("null_sender changed another signing policy")
		}
	}
	for _, value := range []string{"accept", "Header_From", "HEADER_FROM", "header-from", "true", "\"\"", "\"reject \"", "envelope_sender"} {
		if _, err := Load([]byte(withPolicy(value)), FlagValues{}); err == nil {
			t.Fatalf("unknown null_sender value %q was accepted", value)
		}
	}
	disabledHeaderFrom := disabledYAML() + "signing:\n  policy:\n    originator:\n      null_sender: header_from\n"
	if _, err := Load([]byte(disabledHeaderFrom), FlagValues{}); CodeOf(err) != CodeInvalidMatrix {
		t.Fatalf("header_from under a disabled signer code=%s", CodeOf(err))
	}
	t.Setenv(envSigningPolicyOriginatorNullSender, "header_from")
	environment, err := Load([]byte(signingYAML()), FlagValues{})
	if err != nil || environment.Signing().Policies().OriginatorNullSender() != NullSenderHeaderFrom {
		t.Fatalf("environment null_sender override code=%s", CodeOf(err))
	}
	t.Setenv(envSigningPolicyOriginatorNullSender, "permit")
	if _, err := Load([]byte(signingYAML()), FlagValues{}); err == nil {
		t.Fatal("invalid null_sender environment value was accepted")
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
		strings.Replace(memoryYAML("1", "capability"), "max_in_flight: 1", "max_in_flight: 65", 1),
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

// TestConfigurationFormattingAndSerializationStayContentFree proves opaque
// wrappers cannot leak user-controlled values through ordinary diagnostics.
func TestConfigurationFormattingAndSerializationStayContentFree(t *testing.T) {
	clearStableEnvironment(t)
	const marker = "private-config-marker"
	flags := NewFlagValues(marker, true, marker, true, marker, true)
	document := strings.Replace(redisYAML(), "username: application", "username: "+marker, 1)
	document = strings.Replace(document, "redis-password", marker+"-password", 1)
	document = strings.Replace(document, "address: "+testRedisAddress, "address: "+marker+".internal:6379", 1)
	snapshot, err := Load([]byte(document), FlagValues{})
	if err != nil {
		t.Fatalf("Load() failed with code %s", CodeOf(err))
	}
	redisConfig, present := snapshot.Replay().Redis()
	if !present {
		t.Fatal("Load() omitted selected Redis configuration")
	}
	values := []any{
		flags, &flags, []any{flags},
		snapshot, &snapshot, []any{snapshot},
		snapshot.Server(), &snapshot.state.server, []any{snapshot.Server()},
		snapshot.DNS(), []any{snapshot.DNS()},
		snapshot.Replay(), []any{snapshot.Replay()},
		redisConfig, []any{redisConfig}, redisConfig.Mode(),
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
		redisConfig, snapshot.PolicyMode(), snapshot.Backend(),
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
		"DKIM2D_REPLAY_REDIS_" + "STANDALONE_ADDRESS",
		"DKIM2D_REPLAY_REDIS_" + "TLS_SERVER_NAME",
		"DKIM2D_REPLAY_REDIS_" + "TLS_CA_FILE",
		"DKIM2D_REPLAY_REDIS_" + "AUTH_USERNAME",
		"DKIM2D_REPLAY_REDIS_" + "AUTH_PASSWORD_FILE",
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

// TestBackendMatrixExhaustivelyChecksPresence freezes every required,
// optional, and forbidden backend key independently of typed defaults.
func TestBackendMatrixExhaustivelyChecksPresence(t *testing.T) {
	common := []string{pathConfigVersion, pathProtectedGeneration, pathServerCapability}
	allReplay := make([]string, 0)
	allRedis := make([]string, 0)
	for _, spec := range stableFieldSpecs() {
		if strings.HasPrefix(spec.path, "replay.") {
			allReplay = append(allReplay, spec.path)
		}
		if strings.HasPrefix(spec.path, redisPathPrefix) {
			allRedis = append(allRedis, spec.path)
		}
	}
	if len(allRedis) != 33 {
		t.Fatalf("replay.redis schema has %d paths, want 33", len(allRedis))
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
		for _, path := range allRedis {
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
	t.Run("redis required", func(t *testing.T) {
		required := []string{
			pathConfigVersion, pathProtectedGeneration, pathServerCapability,
			pathReplayHMACFile, pathReplayEpoch, pathRedisStandaloneAddress,
		}
		values := map[string]rawValue{
			pathRedisMode:       {text: valueRedisStandalone, kind: scalarString, source: SourceDefault},
			pathRedisTLSEnabled: {text: canonicalTrue, kind: scalarBool, source: SourceDefault},
		}
		if err := validateBackendMatrix(ReplayRedis, explicitPresence(required...), values); err != nil {
			t.Fatal("valid Redis matrix was rejected")
		}
		for index := range required {
			missing := append([]string(nil), required[:index]...)
			missing = append(missing, required[index+1:]...)
			if err := validateBackendMatrix(ReplayRedis, explicitPresence(missing...), values); CodeOf(err) != CodeInvalidMatrix {
				t.Fatal("Redis matrix accepted a missing required key")
			}
		}
		for _, path := range []string{
			pathReplayBackend, pathReplayRetention, pathReplayMaxEntries,
			pathReplayMaxWaiters, pathReplayPruneBudget,
			pathReplayMaxInFlight, pathReplayMaxAdmission, pathReplayCountDirect,
			pathRedisMode, pathRedisAuthPasswordFile,
			pathRedisDatabaseNumber, pathRedisKeyPrefix, pathRedisProtocol,
			pathRedisTLSEnabled, pathRedisTLSCAFile, pathRedisTLSServerName,
			pathRedisTLSMinVersion, pathRedisTLSInsecureSkipVerify,
			pathRedisPoolSize, pathRedisMinIdleConnections, pathRedisPoolTimeout,
			pathRedisDialTimeout, pathRedisReadTimeout, pathRedisWriteTimeout,
			pathRedisRetriesMaxAttempts, pathRedisRetriesMinBackoff, pathRedisRetriesMaxBackoff,
			pathRedisHealthInterval, pathRedisHealthTimeout, pathRedisHealthFailureThreshold,
			pathRedisRequireNoEviction,
		} {
			present := append(append([]string(nil), required...), path)
			if err := validateBackendMatrix(ReplayRedis, explicitPresence(present...), values); err != nil {
				t.Fatalf("Redis matrix rejected optional key %s", path)
			}
		}
		for _, path := range allRedis {
			if !strings.HasPrefix(path, redisPathPrefix+"sentinel.") && !strings.HasPrefix(path, redisPathPrefix+"cluster.") {
				continue
			}
			present := append(append([]string(nil), required...), path)
			if err := validateBackendMatrix(ReplayRedis, explicitPresence(present...), values); CodeOf(err) != CodeInvalidMatrix {
				t.Fatalf("standalone Redis matrix accepted forbidden key %s", path)
			}
		}
	})
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
		{path: pathRedisClusterMaxRedirects, min: 1, max: 16},
		{path: pathRedisDatabaseNumber, min: 0, max: 15},
		{path: pathRedisProtocol, min: 2, max: 3},
		{path: pathRedisPoolSize, min: 1, max: 1024},
		{path: pathRedisRetriesMaxAttempts, min: 1, max: 10},
		{path: pathRedisHealthFailureThreshold, min: 1, max: 10},
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
		{path: pathRedisPoolTimeout, min: time.Millisecond, max: 30 * time.Second, minText: duration1ms, maxText: defaultReadTimeout, belowText: "0s", aboveText: duration31s},
		{path: pathRedisDialTimeout, min: 100 * time.Millisecond, max: 30 * time.Second, minText: defaultAdmissionWait, maxText: defaultReadTimeout, belowText: duration99ms, aboveText: duration31s},
		{path: pathRedisReadTimeout, min: 100 * time.Millisecond, max: 30 * time.Second, minText: defaultAdmissionWait, maxText: defaultReadTimeout, belowText: duration99ms, aboveText: duration31s},
		{path: pathRedisWriteTimeout, min: 100 * time.Millisecond, max: 30 * time.Second, minText: defaultAdmissionWait, maxText: defaultReadTimeout, belowText: duration99ms, aboveText: duration31s},
		{path: pathRedisRetriesMinBackoff, min: time.Millisecond, max: 5 * time.Second, minText: duration1ms, maxText: "5s", belowText: "0s", aboveText: "5001ms"},
		{path: pathRedisRetriesMaxBackoff, min: time.Millisecond, max: 5 * time.Second, minText: duration1ms, maxText: "5s", belowText: "0s", aboveText: "5001ms"},
		{path: pathRedisHealthInterval, min: time.Second, max: time.Minute, minText: "1s", maxText: defaultDeadline, belowText: duration999ms, aboveText: "61s"},
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
	f.Add([]byte(redisYAML()))
	f.Add([]byte(redisSentinelYAML()))
	f.Add([]byte(redisClusterYAML()))
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

// propagationYAML returns the signing document with the propagation capability.
func propagationYAML() string {
	return strings.Replace(
		propagationYAMLWithDisabledReplay(),
		"replay:\n  backend: disabled\n",
		"replay:\n  backend: memory\n  hmac_key_file: /secure/"+testGeneration+"/hmac\n  epoch: 1\n",
		1,
	)
}

// propagationYAMLWithDisabledReplay returns the signing document with the
// propagation capability over the explicitly disabled replay backend, the
// one combination the matrix must refuse.
func propagationYAMLWithDisabledReplay() string {
	return strings.Replace(
		signingYAML(),
		"  dsn_sign_capability_file: /secure/"+testGeneration+"/dsn-sign-capability\n",
		"  dsn_sign_capability_file: /secure/"+testGeneration+"/dsn-sign-capability\n"+
			"  dsn_propagate_capability_file: /secure/"+testGeneration+"/dsn-propagate-capability\n",
		1,
	)
}

// TestLoadValidatesReceivedDSNAndPropagationFields freezes the typed rules of
// the process default tenant, the propagation capability, and the pending
// lease: the tenant must be canonical, the lease is bounded and only
// meaningful with the propagation capability, the fifth capability stays
// distinct, propagation refuses the disabled replay backend because the
// two-phase coordinate is its only replay bound, and propagation otherwise
// stands alone. It does not require the
// delivery-status route capability, because propagation needs the tenant's
// delivery_status datasource profile rather than the /v1/dsn/sign route, and
// a missing profile is already answered permerror/discard at request time.
func TestLoadValidatesReceivedDSNAndPropagationFields(t *testing.T) {
	clearStableEnvironment(t)
	base, err := Load([]byte(signingYAML()), FlagValues{})
	if err != nil || base.ProcessDefaultTenant() != "" || base.Server().DSNPropagateEnabled() ||
		base.PropagationPendingLease() != 120*time.Second {
		t.Fatalf("defaults: tenant=%q propagate=%t lease=%s code=%s", base.ProcessDefaultTenant(), base.Server().DSNPropagateEnabled(), base.PropagationPendingLease(), CodeOf(err))
	}
	tenant := signingYAML() + "process:\n  default_tenant: " + testTenant + "\n"
	snapshot, err := Load([]byte(tenant), FlagValues{})
	if err != nil || snapshot.ProcessDefaultTenant() != testTenant {
		t.Fatalf("default tenant: %q code=%s", snapshot.ProcessDefaultTenant(), CodeOf(err))
	}
	standalone := removeYAMLField(propagationYAML(), "  dsn_sign_capability_file:")
	snapshot, err = Load([]byte(standalone), FlagValues{})
	if err != nil || !snapshot.Server().DSNPropagateEnabled() {
		t.Fatalf("propagation without the delivery-status route: code=%s", CodeOf(err))
	}
	enabled := propagationYAML() + "dsn_propagation:\n  pending_lease: 30s\n"
	snapshot, err = Load([]byte(enabled), FlagValues{})
	if err != nil || !snapshot.Server().DSNPropagateEnabled() ||
		snapshot.Server().DSNPropagateCapabilityFile() != "/secure/"+testGeneration+"/dsn-propagate-capability" ||
		snapshot.PropagationPendingLease() != 30*time.Second {
		t.Fatalf("propagation: enabled=%t lease=%s code=%s", snapshot.Server().DSNPropagateEnabled(), snapshot.PropagationPendingLease(), CodeOf(err))
	}
	for name, testCase := range map[string]struct {
		document string
		code     Code
	}{
		"non-canonical tenant":             {signingYAML() + "process:\n  default_tenant: \"Tenant A\"\n", CodeInvalidField},
		"lease without capability":         {signingYAML() + "dsn_propagation:\n  pending_lease: 30s\n", CodeInvalidMatrix},
		"propagation with disabled replay": {propagationYAMLWithDisabledReplay(), CodeInvalidMatrix},
		"lease below bound":                {propagationYAML() + "dsn_propagation:\n  pending_lease: 500ms\n", CodeInvalidField},
		"lease above bound":                {propagationYAML() + "dsn_propagation:\n  pending_lease: 2h\n", CodeInvalidField},
		"propagation capability equal to another": {
			strings.Replace(propagationYAML(), "/dsn-propagate-capability", "/dsn-sign-capability", 1), CodeInvalidField,
		},
	} {
		if _, loadErr := Load([]byte(testCase.document), FlagValues{}); CodeOf(loadErr) != testCase.code {
			t.Fatalf("%s: code %s, want %s", name, CodeOf(loadErr), testCase.code)
		}
	}
}
