package config

import (
	"os"
	"testing"
)

const mergeTestYAML = `config:
  version: dkim2d-config-v1
protected:
  generation: 0123456789abcdef0123456789abcdef
server:
  listen: 127.0.0.1:9000
  capability_file: /protected/capability
  max_in_flight: 2
policy:
  mode: permissive
replay:
  backend: memory
`

const syntheticMergeMarker = "marker"

// TestMergeValuesPreservesPrecedenceAndPresence proves explicit empty values,
// closed flags, typed defaults, and independent source presence.
func TestMergeValuesPreservesPrecedenceAndPresence(t *testing.T) {
	clearStableEnvironment(t)
	t.Setenv("DKIM2D_SERVER_LISTEN", "127.0.0.1:9100")
	t.Setenv("DKIM2D_POLICY_MODE", "")
	t.Setenv("DKIM2D_REPLAY_BACKEND", "valkey")

	yamlValues := mergeTestYAMLValues()
	flags := NewFlagValues("127.0.0.1:9200", true, "", false, "disabled", true)
	merged, presence, err := mergeValues([]byte(mergeTestYAML), yamlValues, flags)
	if err != nil {
		t.Fatalf("merge failed with code %s", CodeOf(err))
	}

	assertRawValue(t, merged, "server.listen", "127.0.0.1:9200", scalarString, SourceFlag)
	assertRawValue(t, merged, "policy.mode", "", scalarString, SourceEnvironment)
	assertRawValue(t, merged, "replay.backend", "disabled", scalarString, SourceFlag)
	assertRawValue(t, merged, "server.max_in_flight", "2", scalarUint, SourceYAML)
	assertRawValue(t, merged, "server.read_timeout", "30s", scalarString, SourceDefault)

	listenPresence := presence["server.listen"]
	if !listenPresence.YAML || !listenPresence.Environment || !listenPresence.Flag || listenPresence.Winner != SourceFlag {
		t.Fatal("listen presence did not preserve all explicit layers")
	}
	policyPresence := presence["policy.mode"]
	if !policyPresence.YAML || !policyPresence.Environment || policyPresence.Flag || policyPresence.Winner != SourceEnvironment {
		t.Fatal("policy presence did not preserve an explicit empty environment override")
	}
	defaultPresence := presence["server.read_timeout"]
	if defaultPresence.Explicit() || defaultPresence.Winner != SourceDefault {
		t.Fatal("default was incorrectly recorded as explicit")
	}
	missingPresence := presence["replay.epoch"]
	if missingPresence.Explicit() || missingPresence.Winner != 0 {
		t.Fatal("required missing value gained a source")
	}
}

// TestMergeValuesUsesOnlyLiteralEnvironmentBindings proves YAML-only and
// unrelated environment names cannot enter the checked merge.
func TestMergeValuesUsesOnlyLiteralEnvironmentBindings(t *testing.T) {
	clearStableEnvironment(t)
	t.Setenv("CONFIG.VERSION", "wrong-version")
	t.Setenv("DKIM2D_CONFIG_VERSION", "wrong-version")
	t.Setenv("DKIM2D_PROTECTED_GENERATION", "ffffffffffffffffffffffffffffffff")

	merged, presence, err := mergeValues([]byte(mergeTestYAML), mergeTestYAMLValues(), FlagValues{})
	if err != nil {
		t.Fatalf("merge failed with code %s", CodeOf(err))
	}
	assertRawValue(t, merged, "config.version", configVersion, scalarString, SourceYAML)
	assertRawValue(t, merged, "protected.generation", "0123456789abcdef0123456789abcdef", scalarString, SourceYAML)
	if presence["config.version"].Environment || presence["protected.generation"].Environment {
		t.Fatal("YAML-only paths accepted an environment source")
	}
}

// TestMergeValuesRejectsUnknownOrInvalidSources proves the owned map cannot
// smuggle undeclared paths or post-preflight provenance.
func TestMergeValuesRejectsUnknownOrInvalidSources(t *testing.T) {
	clearStableEnvironment(t)
	tests := []struct {
		name   string
		mutate func(map[string]rawValue)
	}{
		{
			name: "unknown path",
			mutate: func(values map[string]rawValue) {
				values["server.unknown"] = rawValue{text: syntheticMergeMarker, kind: scalarString, source: SourceYAML}
			},
		},
		{
			name: "invalid provenance",
			mutate: func(values map[string]rawValue) {
				values[pathServerListen] = rawValue{text: syntheticMergeMarker, kind: scalarString, source: SourceEnvironment}
			},
		},
		{
			name: "invalid scalar kind",
			mutate: func(values map[string]rawValue) {
				values["server.listen"] = rawValue{text: "marker", kind: 0, source: SourceYAML}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := mergeTestYAMLValues()
			test.mutate(values)
			_, _, err := mergeValues([]byte(mergeTestYAML), values, FlagValues{})
			if CodeOf(err) != CodeInvalidSource {
				t.Fatalf("unexpected failure code %s", CodeOf(err))
			}
		})
	}
}

// TestMergeValuesRequiresViperEquality proves the retained YAML bytes and
// preflight-owned scalar map must describe the same value.
func TestMergeValuesRequiresViperEquality(t *testing.T) {
	clearStableEnvironment(t)
	values := mergeTestYAMLValues()
	values["server.listen"] = rawValue{
		text:   "127.0.0.1:9999",
		kind:   scalarString,
		source: SourceYAML,
	}
	_, _, err := mergeValues([]byte(mergeTestYAML), values, FlagValues{})
	if err == nil {
		t.Fatal("Viper equality mismatch was accepted")
	}
	if CodeOf(err) != CodeInternal {
		t.Fatalf("unexpected failure code %s", CodeOf(err))
	}
}

// TestStableFieldBindings proves the literal environment allowlist and closed
// three-flag surface remain mechanically aligned with stable paths.
func TestStableFieldBindings(t *testing.T) {
	specs := stableFieldSpecs()
	golden := stableFieldGoldenContract()
	if len(specs) != len(golden) {
		t.Fatal("stable configuration field count drifted")
	}
	flags := make(map[string]string)
	for index, spec := range specs {
		expected := golden[index]
		if spec.path != expected.path || spec.env != expected.environment {
			t.Fatal("literal environment binding drifted")
		}
		if spec.yamlOnly != (expected.environment == "") {
			t.Fatal("YAML-only source binding drifted")
		}
		if spec.flag != "" {
			flags[spec.flag] = spec.path
		}
	}
	expectedFlags := map[string]string{
		"listen":         "server.listen",
		"policy-mode":    "policy.mode",
		"replay-backend": "replay.backend",
	}
	if len(flags) != len(expectedFlags) {
		t.Fatal("configuration flag count drifted")
	}
	for name, path := range expectedFlags {
		if flags[name] != path {
			t.Fatal("configuration flag binding drifted")
		}
	}
}

// TestStablePathSetIsExact prevents a mechanically well-named path from
// silently widening the stable operator surface.
func TestStablePathSetIsExact(t *testing.T) {
	specs := stableFieldSpecs()
	golden := stableFieldGoldenContract()
	if len(specs) != 112 || len(specs) != len(golden) {
		t.Fatal("stable path count changed")
	}
	for index, expected := range golden {
		if specs[index].path != expected.path {
			t.Fatal("stable path set or ordering changed")
		}
	}
}

// TestStableDefaultsAreExact freezes every 0.1.x typed default independently.
func TestStableDefaultsAreExact(t *testing.T) {
	actual := make(map[string]string)
	for _, spec := range stableFieldSpecs() {
		if spec.hasDefault {
			actual[spec.path] = spec.defaultVal
		}
	}
	expectedCount := 0
	for _, expected := range stableFieldGoldenContract() {
		if expected.hasDefault {
			expectedCount++
			if actual[expected.path] != expected.defaultValue {
				t.Fatal("stable default value changed")
			}
		}
	}
	if len(actual) != expectedCount {
		t.Fatal("stable default count changed")
	}
}

// stableFieldGolden is one spec-derived configuration oracle independent of production constants.
type stableFieldGolden struct {
	path         string
	environment  string
	defaultValue string
	hasDefault   bool
}

// stableFieldGoldenContract freezes the reviewed stable paths, bindings, and defaults.
func stableFieldGoldenContract() []stableFieldGolden {
	return []stableFieldGolden{
		{path: "config.version"},
		{path: "protected.generation"},
		{path: "server.listen", environment: "DKIM2D_SERVER_LISTEN", defaultValue: "127.0.0.1:8080", hasDefault: true},
		{path: "server.capability_file", environment: "DKIM2D_SERVER_CAPABILITY_FILE"},
		{path: "server.sign_capability_file", environment: "DKIM2D_SERVER_SIGN_CAPABILITY_FILE"},
		{path: "server.revise_capability_file", environment: "DKIM2D_SERVER_REVISE_CAPABILITY_FILE"},
		{path: "server.dsn_sign_capability_file", environment: "DKIM2D_SERVER_DSN_SIGN_CAPABILITY_FILE"},
		{path: "server.read_header_timeout", environment: "DKIM2D_SERVER_READ_HEADER_TIMEOUT", defaultValue: "5s", hasDefault: true},
		{path: "server.read_timeout", environment: "DKIM2D_SERVER_READ_TIMEOUT", defaultValue: "30" + "s", hasDefault: true},
		{path: "server.write_timeout", environment: "DKIM2D_SERVER_WRITE_TIMEOUT", defaultValue: "65s", hasDefault: true},
		{path: "server.request_deadline", environment: "DKIM2D_SERVER_REQUEST_DEADLINE", defaultValue: "60s", hasDefault: true},
		{path: "server.shutdown_timeout", environment: "DKIM2D_SERVER_SHUTDOWN_TIMEOUT", defaultValue: "30" + "s", hasDefault: true},
		{path: "server.max_in_flight", environment: "DKIM2D_SERVER_MAX_IN_FLIGHT", defaultValue: "1", hasDefault: true},
		{path: "server.max_waiters", environment: "DKIM2D_SERVER_MAX_WAITERS", defaultValue: "64", hasDefault: true},
		{path: "server.admission_wait", environment: "DKIM2D_SERVER_ADMISSION_WAIT", defaultValue: "100ms", hasDefault: true},
		{path: "policy.mode", environment: "DKIM2D_POLICY_MODE", defaultValue: "strict", hasDefault: true},
		{path: "dns.lookup_timeout", environment: "DKIM2D_DNS_LOOKUP_TIMEOUT", defaultValue: "5s", hasDefault: true},
		{path: "dns.max_concurrent_lookups", environment: "DKIM2D_DNS_MAX_CONCURRENT_LOOKUPS", defaultValue: "64", hasDefault: true},
		{path: "dns.cache.max_entries", environment: "DKIM2D_DNS_CACHE_MAX_ENTRIES", defaultValue: "4096", hasDefault: true},
		{path: "dns.cache.positive_ttl_cap", environment: "DKIM2D_DNS_CACHE_POSITIVE_TTL_CAP", defaultValue: "1h", hasDefault: true},
		{path: "dns.cache.negative_ttl_cap", environment: "DKIM2D_DNS_CACHE_NEGATIVE_TTL_CAP", defaultValue: "5m", hasDefault: true},
		{path: "dns.cache.stable_error_ttl_cap", environment: "DKIM2D_DNS_CACHE_STABLE_ERROR_TTL_CAP", defaultValue: "1m", hasDefault: true},
		{path: "replay.backend", environment: "DKIM2D_REPLAY_BACKEND", defaultValue: "valkey", hasDefault: true},
		{path: "replay.hmac_key_file", environment: "DKIM2D_REPLAY_HMAC_KEY_FILE"},
		{path: "replay.epoch", environment: "DKIM2D_REPLAY_EPOCH"},
		{path: "replay.retention", environment: "DKIM2D_REPLAY_RETENTION", defaultValue: "336h", hasDefault: true},
		{path: "replay.limits.max_entries", environment: "DKIM2D_REPLAY_LIMITS_MAX_ENTRIES", defaultValue: "65536", hasDefault: true},
		{path: "replay.limits.max_waiters", environment: "DKIM2D_REPLAY_LIMITS_MAX_WAITERS", defaultValue: "1024", hasDefault: true},
		{path: "replay.limits.prune_budget", environment: "DKIM2D_REPLAY_LIMITS_PRUNE_BUDGET", defaultValue: "4096", hasDefault: true},
		{path: "replay.limits.max_in_flight", environment: "DKIM2D_REPLAY_LIMITS_MAX_IN_FLIGHT", defaultValue: "1024", hasDefault: true},
		{path: "replay.limits.max_admission_waiters", environment: "DKIM2D_REPLAY_LIMITS_MAX_ADMISSION_WAITERS", defaultValue: "1024", hasDefault: true},
		{path: "replay.revalidate_interval", environment: "DKIM2D_REPLAY_REVALIDATE_INTERVAL", defaultValue: "30" + "s", hasDefault: true},
		{path: "signing.backend", environment: "DKIM2D_SIGNING_BACKEND", defaultValue: "disabled", hasDefault: true},
		{path: "signing.datasource_file", environment: "DKIM2D_SIGNING_DATASOURCE_FILE"},
		{path: "signing.private_manifest_file", environment: "DKIM2D_SIGNING_PRIVATE_MANIFEST_FILE"},
		{path: "signing.reload_interval", environment: "DKIM2D_SIGNING_RELOAD_INTERVAL", defaultValue: "30" + "s", hasDefault: true},
		// Keep the golden literal independent of the production default constant.
		{path: "signing.allow_recipient_group", environment: "DKIM2D_SIGNING_ALLOW_RECIPIENT_GROUP", defaultValue: "false", hasDefault: true}, //nolint:goconst
		{path: "signing.limit_profile", environment: "DKIM2D_SIGNING_LIMIT_PROFILE", defaultValue: limitProfileSmall, hasDefault: true},
		{path: "signing.max_load_bytes", environment: "DKIM2D_SIGNING_MAX_LOAD_BYTES", defaultValue: "16777216", hasDefault: true},
		{path: "signing.policy.originator.donotmodify", environment: envSigningPolicyOriginatorDoNotModify, defaultValue: "false", hasDefault: true},
		{path: "signing.policy.originator.donotexplode", environment: envSigningPolicyOriginatorDoNotExplode, defaultValue: "false", hasDefault: true},
		{path: "signing.policy.ordinary_transit.donotmodify", environment: envSigningPolicyTransitDoNotModify, defaultValue: "false", hasDefault: true},
		{path: "signing.policy.ordinary_transit.donotexplode", environment: envSigningPolicyTransitDoNotExplode, defaultValue: "false", hasDefault: true},
		{path: "signing.policy.delivery_status.donotmodify", environment: envSigningPolicyDeliveryDoNotModify, defaultValue: "false", hasDefault: true},
		{path: "signing.policy.delivery_status.donotexplode", environment: envSigningPolicyDeliveryDoNotExplode, defaultValue: "false", hasDefault: true},
		{path: "signing.ldap.address", environment: "DKIM2D_SIGNING_LDAP_ADDRESS"},
		{path: "signing.ldap.server_name", environment: "DKIM2D_SIGNING_LDAP_SERVER_NAME"},
		{path: "signing.ldap.ca_file", environment: "DKIM2D_SIGNING_LDAP_CA_FILE"},
		{path: "signing.ldap.transport", environment: "DKIM2D_SIGNING_LDAP_TRANSPORT"},
		{path: "signing.ldap.bind_dn", environment: "DKIM2D_SIGNING_LDAP_BIND_DN"},
		{path: "signing.ldap.password_file", environment: "DKIM2D_SIGNING_LDAP_PASSWORD_FILE"},
		{path: "signing.ldap.base_dn", environment: "DKIM2D_SIGNING_LDAP_BASE_DN"},
		{path: "signing.ldap.page_size", environment: "DKIM2D_SIGNING_LDAP_PAGE_SIZE", defaultValue: "128", hasDefault: true},
		{path: "signing.ldap.load_deadline", environment: "DKIM2D_SIGNING_LDAP_LOAD_DEADLINE", defaultValue: "5s", hasDefault: true},
		{path: "signing.postgresql.address", environment: "DKIM2D_SIGNING_POSTGRESQL_ADDRESS"},
		{path: "signing.postgresql.server_name", environment: "DKIM2D_SIGNING_POSTGRESQL_SERVER_NAME"},
		{path: "signing.postgresql.ca_file", environment: "DKIM2D_SIGNING_POSTGRESQL_CA_FILE"},
		{path: "signing.postgresql.database", environment: "DKIM2D_SIGNING_POSTGRESQL_DATABASE"},
		{path: "signing.postgresql.user", environment: "DKIM2D_SIGNING_POSTGRESQL_USER"},
		{path: "signing.postgresql.password_file", environment: "DKIM2D_SIGNING_POSTGRESQL_PASSWORD_FILE"},
		{path: "signing.postgresql.page_size", environment: "DKIM2D_SIGNING_POSTGRESQL_PAGE_SIZE", defaultValue: "128", hasDefault: true},
		{path: "signing.postgresql.load_deadline", environment: "DKIM2D_SIGNING_POSTGRESQL_LOAD_DEADLINE", defaultValue: "5s", hasDefault: true},
		{path: "signing.postgresql.max_connections", environment: "DKIM2D_SIGNING_POSTGRESQL_MAX_CONNECTIONS", defaultValue: "2", hasDefault: true},
		{path: "signing.postgresql.idle_connections", environment: "DKIM2D_SIGNING_POSTGRESQL_IDLE_CONNECTIONS", defaultValue: "1", hasDefault: true},
		{path: "signing.mysql.address", environment: "DKIM2D_SIGNING_MYSQL_ADDRESS"},
		{path: "signing.mysql.server_name", environment: "DKIM2D_SIGNING_MYSQL_SERVER_NAME"},
		{path: "signing.mysql.ca_file", environment: "DKIM2D_SIGNING_MYSQL_CA_FILE"},
		{path: "signing.mysql.database", environment: "DKIM2D_SIGNING_MYSQL_DATABASE"},
		{path: "signing.mysql.user", environment: "DKIM2D_SIGNING_MYSQL_USER"},
		{path: "signing.mysql.password_file", environment: "DKIM2D_SIGNING_MYSQL_PASSWORD_FILE"},
		{path: "signing.mysql.page_size", environment: "DKIM2D_SIGNING_MYSQL_PAGE_SIZE", defaultValue: "128", hasDefault: true},
		{path: "signing.mysql.load_deadline", environment: "DKIM2D_SIGNING_MYSQL_LOAD_DEADLINE", defaultValue: "5s", hasDefault: true},
		{path: "signing.mysql.max_connections", environment: "DKIM2D_SIGNING_MYSQL_MAX_CONNECTIONS", defaultValue: "2", hasDefault: true},
		{path: "signing.mysql.idle_connections", environment: "DKIM2D_SIGNING_MYSQL_IDLE_CONNECTIONS", defaultValue: "1", hasDefault: true},
		{path: "replay.valkey.address", environment: "DKIM2D_REPLAY_" + "VALKEY_ADDRESS"},
		{path: "replay.valkey.server_name", environment: "DKIM2D_REPLAY_" + "VALKEY_SERVER_NAME"},
		{path: "replay.valkey.ca_file", environment: "DKIM2D_REPLAY_" + "VALKEY_CA_FILE"},
		{path: "replay.valkey.application_username", environment: "DKIM2D_REPLAY_" + "VALKEY_APPLICATION_USERNAME"},
		{path: "replay.valkey.application_password_file", environment: "DKIM2D_REPLAY_" + "VALKEY_APPLICATION_PASSWORD_FILE"},
		{path: "replay.valkey.auditor_username", environment: "DKIM2D_REPLAY_VALKEY_AUDITOR_USERNAME"},
		{path: "replay.valkey.auditor_password_file", environment: "DKIM2D_REPLAY_VALKEY_AUDITOR_PASSWORD_FILE"},
		{path: "replay.valkey.dial_timeout", environment: "DKIM2D_REPLAY_VALKEY_DIAL_TIMEOUT", defaultValue: "2s", hasDefault: true},
		{path: "replay.valkey.tcp_keepalive", environment: "DKIM2D_REPLAY_VALKEY_TCP_KEEPALIVE", defaultValue: "30" + "s", hasDefault: true},
		{path: "replay.valkey.connection_write_timeout", environment: "DKIM2D_REPLAY_VALKEY_CONNECTION_WRITE_TIMEOUT", defaultValue: "2s", hasDefault: true},
		{path: "replay.valkey.attestation.persistence_mode", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_PERSISTENCE_MODE"},
		{path: "replay.valkey.attestation.append_fsync_policy", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_APPEND_FSYNC_POLICY"},
		{path: "replay.valkey.attestation.save_schedule", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_SAVE_SCHEDULE"},
		{path: "replay.valkey.attestation.min_replicas_to_write", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_MIN_REPLICAS_TO_WRITE"},
		{path: "replay.valkey.attestation.min_replicas_max_lag_seconds", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_MIN_REPLICAS_MAX_LAG_SECONDS"},
		{path: "replay.valkey.attestation.loss_window_acceptance", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_LOSS_WINDOW_ACCEPTANCE"},
		{path: "replay.valkey.attestation.rotation_state", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_ROTATION_STATE"},
		{path: "replay.valkey.attestation.no_global_exactly_once_claim", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_NO_GLOBAL_EXACTLY_ONCE_CLAIM"},
		{path: "replay.valkey.attestation.dedicated_deployment", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_DEDICATED_DEPLOYMENT"},
		{path: "replay.valkey.attestation.dedicated_database_zero", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_DEDICATED_DATABASE_ZERO"},
		{path: "replay.valkey.attestation.direct_ip_authority", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_DIRECT_IP_AUTHORITY"},
		{path: "replay.valkey.attestation.no_endpoint_substitution", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_NO_ENDPOINT_SUBSTITUTION"},
		{path: "replay.valkey.attestation.standalone_authority", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_STANDALONE_AUTHORITY"},
		{path: "replay.valkey.attestation.shared_draft", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_SHARED_DRAFT"},
		{path: "replay.valkey.attestation.shared_algorithm", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_SHARED_ALGORITHM"},
		{path: "replay.valkey.attestation.shared_namespace", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_SHARED_NAMESPACE"},
		{path: "replay.valkey.attestation.shared_epoch", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_SHARED_EPOCH"},
		{path: "replay.valkey.attestation.shared_secret_set", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_SHARED_SECRET_SET"},
		{path: "replay.valkey.attestation.shared_retention", environment: "DKIM2D_REPLAY_VALKEY_ATTESTATION_SHARED_RETENTION"},
		{path: "observability.logging.level", environment: "DKIM2D_OBSERVABILITY_LOGGING_LEVEL", defaultValue: "info", hasDefault: true},
		{path: "observability.debug.message_shape", environment: "DKIM2D_OBSERVABILITY_DEBUG_MESSAGE_SHAPE", defaultValue: "false", hasDefault: true},
		{path: "observability.debug.dns", environment: "DKIM2D_OBSERVABILITY_DEBUG_DNS", defaultValue: "false", hasDefault: true},
		{path: "observability.debug.replay", environment: "DKIM2D_OBSERVABILITY_DEBUG_REPLAY", defaultValue: "false", hasDefault: true},
		{path: "observability.tracing.exporter", environment: "DKIM2D_OBSERVABILITY_TRACING_EXPORTER", defaultValue: "none", hasDefault: true},
		{path: "observability.tracing.endpoint", environment: "DKIM2D_OBSERVABILITY_TRACING_ENDPOINT"},
		{path: "observability.tracing.ca_file", environment: "DKIM2D_OBSERVABILITY_TRACING_CA_FILE"},
		{path: "observability.tracing.sample_per_million", environment: "DKIM2D_OBSERVABILITY_TRACING_SAMPLE_PER_MILLION"},
		{path: "observability.tracing.export_timeout", environment: "DKIM2D_OBSERVABILITY_TRACING_EXPORT_TIMEOUT"},
	}
}

// mergeTestYAMLValues returns the preflight-owned leaves for mergeTestYAML.
func mergeTestYAMLValues() map[string]rawValue {
	return map[string]rawValue{
		pathConfigVersion:        {text: configVersion, kind: scalarString, source: SourceYAML},
		pathProtectedGeneration:  {text: "0123456789abcdef0123456789abcdef", kind: scalarString, source: SourceYAML},
		pathServerListen:         {text: "127.0.0.1:9000", kind: scalarString, source: SourceYAML},
		"server.capability_file": {text: "/protected/capability", kind: scalarString, source: SourceYAML},
		pathServerMaxInFlight:    {text: "2", kind: scalarUint, source: SourceYAML},
		pathPolicyMode:           {text: "permissive", kind: scalarString, source: SourceYAML},
		pathReplayBackend:        {text: "memory", kind: scalarString, source: SourceYAML},
	}
}

// assertRawValue checks one owned merge value without formatting its contents.
func assertRawValue(t *testing.T, values map[string]rawValue, path, text string, kind scalarKind, source Source) {
	t.Helper()
	value, present := values[path]
	if !present {
		t.Fatal("expected merged value is absent")
	}
	if value.text != text || value.kind != kind || value.source != source {
		t.Fatal("merged value did not match the expected source and scalar")
	}
}

// clearStableEnvironment isolates literal environment-source tests.
func clearStableEnvironment(t *testing.T) {
	t.Helper()
	for _, spec := range stableFieldSpecs() {
		if spec.env == "" {
			continue
		}
		value, present := os.LookupEnv(spec.env)
		if !present {
			continue
		}
		if err := os.Unsetenv(spec.env); err != nil {
			t.Fatal("failed to isolate configuration environment")
		}
		name := spec.env
		t.Cleanup(func() {
			if err := os.Setenv(name, value); err != nil {
				t.Fatal("failed to restore configuration environment")
			}
		})
	}
}
