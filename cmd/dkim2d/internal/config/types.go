package config

import (
	"fmt"
	"io"
	"strings"
)

const (
	limitProfileSmall      = "small"
	limitProfileProduction = "production"
	configVersion          = "dkim2d-config-v1"

	snapshotRedactedText = "dkim2d_config_snapshot"

	pathConfigVersion           = "config.version"
	pathProtectedGeneration     = "protected.generation"
	pathServerListen            = "server.listen"
	pathServerCapability        = "server.capability_file"
	pathServerSignCapability    = "server.sign_capability_file"
	pathServerReviseCapability  = "server.revise_capability_file"
	pathServerDSNSignCapability = "server.dsn_sign_capability_file"
	pathServerReadHeader        = "server.read_header_timeout"
	pathServerRead              = "server.read_timeout"
	pathServerWrite             = "server.write_timeout"
	pathServerDeadline          = "server.request_deadline"
	pathServerShutdown          = "server.shutdown_timeout"
	pathServerMaxInFlight       = "server.max_in_flight"
	pathServerMaxWaiters        = "server.max_waiters"
	pathServerAdmissionWait     = "server.admission_wait"
	pathPolicyMode              = "policy.mode"
	pathDNSLookupTimeout        = "dns.lookup_timeout"
	pathDNSMaxConcurrent        = "dns.max_concurrent_lookups"
	pathDNSCacheMaxEntries      = "dns.cache.max_entries"
	pathDNSPositiveTTLCap       = "dns.cache.positive_ttl_cap"
	pathDNSNegativeTTLCap       = "dns.cache.negative_ttl_cap"
	pathDNSStableErrorTTLCap    = "dns.cache.stable_error_ttl_cap"
	pathReplayBackend           = "replay.backend"
	pathReplayHMACFile          = "replay.hmac_key_file"
	pathReplayEpoch             = "replay.epoch"
	pathReplayRetention         = "replay.retention"
	pathReplayMaxEntries        = "replay.limits.max_entries"
	pathReplayMaxWaiters        = "replay.limits.max_waiters"
	pathReplayPruneBudget       = "replay.limits.prune_budget"
	pathReplayMaxInFlight       = "replay.limits.max_in_flight"
	pathReplayMaxAdmission      = "replay.limits.max_admission_waiters"
	pathReplayRevalidate        = "replay.revalidate_interval"
	pathSigningBackend          = "signing.backend"
	pathSigningDatasource       = "signing.datasource_file"
	pathSigningManifest         = "signing.private_manifest_file"
	pathSigningReload           = "signing.reload_interval"
	pathSigningAllowGroup       = "signing.allow_recipient_group"
	pathSigningLimitProfile     = "signing.limit_profile"
	pathSigningMaxLoadBytes     = "signing.max_load_bytes"
	pathSigningLDAPAddress      = "signing.ldap.address"
	pathSigningLDAPServerName   = "signing.ldap.server_name"
	pathSigningLDAPCAFile       = "signing.ldap.ca_file"
	pathSigningLDAPTransport    = "signing.ldap.transport"
	pathSigningLDAPBindDN       = "signing.ldap.bind_dn"
	pathSigningLDAPPassword     = "signing.ldap.password_file"
	pathSigningLDAPBaseDN       = "signing.ldap.base_dn"
	pathSigningLDAPPageSize     = "signing.ldap.page_size"
	pathSigningLDAPDeadline     = "signing.ldap.load_deadline"
	pathSigningPGAddress        = "signing.postgresql.address"
	pathSigningPGServerName     = "signing.postgresql.server_name"
	pathSigningPGCAFile         = "signing.postgresql.ca_file"
	pathSigningPGDatabase       = "signing.postgresql.database"
	pathSigningPGUser           = "signing.postgresql.user"
	pathSigningPGPassword       = "signing.postgresql.password_file"
	pathSigningPGPageSize       = "signing.postgresql.page_size"
	pathSigningPGDeadline       = "signing.postgresql.load_deadline"
	pathSigningPGMaxConns       = "signing.postgresql.max_connections"
	pathSigningPGIdleConns      = "signing.postgresql.idle_connections"
	pathSigningMySQLAddress     = "signing.mysql.address"
	pathSigningMySQLServerName  = "signing.mysql.server_name"
	pathSigningMySQLCAFile      = "signing.mysql.ca_file"
	pathSigningMySQLDatabase    = "signing.mysql.database"
	pathSigningMySQLUser        = "signing.mysql.user"
	pathSigningMySQLPassword    = "signing.mysql.password_file"
	pathSigningMySQLPageSize    = "signing.mysql.page_size"
	pathSigningMySQLDeadline    = "signing.mysql.load_deadline"
	pathSigningMySQLMaxConns    = "signing.mysql.max_connections"
	pathSigningMySQLIdleConns   = "signing.mysql.idle_connections"

	pathValkeyAddress          = "replay.valkey.address"
	pathValkeyServerName       = "replay.valkey.server_name"
	pathValkeyCAFile           = "replay.valkey.ca_file"
	pathValkeyApplicationUser  = "replay.valkey.application_username"
	pathValkeyApplicationPass  = "replay.valkey.application_password_file"
	pathValkeyAuditorUser      = "replay.valkey.auditor_username"
	pathValkeyAuditorPass      = "replay.valkey.auditor_password_file"
	pathValkeyDialTimeout      = "replay.valkey.dial_timeout"
	pathValkeyTCPKeepalive     = "replay.valkey.tcp_keepalive"
	pathValkeyWriteTimeout     = "replay.valkey.connection_write_timeout"
	pathAttestationPersistence = "replay.valkey.attestation.persistence_mode"
	pathAttestationFsync       = "replay.valkey.attestation.append_fsync_policy"
	pathAttestationSave        = "replay.valkey.attestation.save_schedule"
	pathAttestationMinReplicas = "replay.valkey.attestation.min_replicas_to_write"
	pathAttestationMaxLag      = "replay.valkey.attestation.min_replicas_max_lag_seconds"
	pathAttestationLossWindow  = "replay.valkey.attestation.loss_window_acceptance"
	pathAttestationRotation    = "replay.valkey.attestation.rotation_state"

	defaultListenAddress = "127.0.0.1:8080"
	defaultReadHeader    = "5s"
	defaultReadTimeout   = "30s"
	defaultWriteTimeout  = "65s"
	defaultDeadline      = "60s"
	defaultAdmissionWait = "100ms"

	valuePolicyStrict    = "strict"
	valueBackendValkey   = "valkey"
	valueBackendDisabled = "disabled"
	valuePersistenceRDB  = "rdb"

	flagListen        = "listen"
	flagPolicyMode    = "policy-mode"
	flagReplayBackend = "replay-backend"

	canonicalTrue  = "true"
	canonicalFalse = "false"
	canonicalInfo  = "info"
	canonicalNone  = "none"

	pathAttestationNoGlobalExactlyOnce = "replay.valkey.attestation.no_global_exactly_once_claim"
	pathAttestationDedicatedDeployment = "replay.valkey.attestation.dedicated_deployment"
	pathAttestationDedicatedDatabase   = "replay.valkey.attestation.dedicated_database_zero"
	pathAttestationDirectIPAuthority   = "replay.valkey.attestation.direct_ip_authority"
	pathAttestationNoSubstitution      = "replay.valkey.attestation.no_endpoint_substitution"
	pathAttestationStandaloneAuthority = "replay.valkey.attestation.standalone_authority"
	pathAttestationSharedDraft         = "replay.valkey.attestation.shared_draft"
	pathAttestationSharedAlgorithm     = "replay.valkey.attestation.shared_algorithm"
	pathAttestationSharedNamespace     = "replay.valkey.attestation.shared_namespace"
	pathAttestationSharedEpoch         = "replay.valkey.attestation.shared_epoch"
	pathAttestationSharedSecretSet     = "replay.valkey.attestation.shared_secret_set"
	pathAttestationSharedRetention     = "replay.valkey.attestation.shared_retention"
	pathLoggingLevel                   = "observability.logging.level"
	pathDebugMessageShape              = "observability.debug.message_shape"
	pathDebugDNS                       = "observability.debug.dns"
	pathDebugReplay                    = "observability.debug.replay"
	pathTracingExporter                = "observability.tracing.exporter"
	pathTracingEndpoint                = "observability.tracing.endpoint"
	pathTracingCAFile                  = "observability.tracing.ca_file"
	pathTracingSamplePerMillion        = "observability.tracing.sample_per_million"
	pathTracingExportTimeout           = "observability.tracing.export_timeout"
)

// Source identifies the winning configuration layer without retaining its value.
type Source uint8

const (
	// SourceDefault identifies one typed default.
	SourceDefault Source = iota + 1
	// SourceYAML identifies one explicit YAML scalar.
	SourceYAML
	// SourceEnvironment identifies one explicitly bound environment value.
	SourceEnvironment
	// SourceFlag identifies one explicitly changed command flag.
	SourceFlag
)

// Presence records every explicit source independently of the winning value.
type Presence struct {
	YAML        bool
	Environment bool
	Flag        bool
	Winner      Source
}

// Explicit reports whether any operator-controlled source supplied the path.
func (p Presence) Explicit() bool {
	return p.YAML || p.Environment || p.Flag
}

type flagValue struct {
	value   string
	changed bool
}

// FlagValues contains the only configuration-bearing command flags.
type FlagValues struct {
	state *flagValuesState
}

type flagValuesState struct {
	listen        flagValue
	policyMode    flagValue
	replayBackend flagValue
}

// NewFlagValues clones the three permitted configuration flags into an opaque value.
func NewFlagValues(listen string, listenChanged bool, policyMode string, policyModeChanged bool, replayBackend string, replayBackendChanged bool) FlagValues {
	return FlagValues{
		state: &flagValuesState{
			listen:        flagValue{value: strings.Clone(listen), changed: listenChanged},
			policyMode:    flagValue{value: strings.Clone(policyMode), changed: policyModeChanged},
			replayBackend: flagValue{value: strings.Clone(replayBackend), changed: replayBackendChanged},
		},
	}
}

// String returns a content-free flag representation.
func (FlagValues) String() string { return snapshotRedactedText }

// GoString returns a content-free flag representation.
func (FlagValues) GoString() string { return snapshotRedactedText }

// Format prevents formatting verbs from exposing flag values.
func (FlagValues) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, snapshotRedactedText)
}

// MarshalJSON rejects serialization of configuration flags.
func (FlagValues) MarshalJSON() ([]byte, error) {
	return nil, newError(CodeSerialization)
}

// MarshalText rejects serialization of configuration flags.
func (FlagValues) MarshalText() ([]byte, error) {
	return nil, newError(CodeSerialization)
}

type scalarKind uint8

const (
	scalarString scalarKind = iota + 1
	scalarBool
	scalarUint
	scalarExpanded
)

type valueKind uint8

const (
	valueString valueKind = iota + 1
	valueBool
	valueUint
	valueDuration
)

type rawValue struct {
	text   string
	kind   scalarKind
	source Source
}

type fieldSpec struct {
	path       string
	env        string
	flag       string
	kind       valueKind
	defaultVal string
	hasDefault bool
	yamlOnly   bool
}

// stableFieldSpecs returns one fresh immutable-by-ownership configuration schema.
func stableFieldSpecs() []fieldSpec {
	return []fieldSpec{
		{path: pathConfigVersion, kind: valueString, yamlOnly: true},
		{path: pathProtectedGeneration, kind: valueString, yamlOnly: true},
		{path: pathServerListen, env: "DKIM2D_SERVER_LISTEN", flag: flagListen, kind: valueString, defaultVal: defaultListenAddress, hasDefault: true},
		{path: pathServerCapability, env: "DKIM2D_SERVER_CAPABILITY_FILE", kind: valueString},
		{path: pathServerSignCapability, env: "DKIM2D_SERVER_SIGN_CAPABILITY_FILE", kind: valueString},
		{path: pathServerReviseCapability, env: "DKIM2D_SERVER_REVISE_CAPABILITY_FILE", kind: valueString},
		{path: pathServerDSNSignCapability, env: "DKIM2D_SERVER_DSN_SIGN_CAPABILITY_FILE", kind: valueString},
		{path: pathServerReadHeader, env: "DKIM2D_SERVER_READ_HEADER_TIMEOUT", kind: valueDuration, defaultVal: defaultReadHeader, hasDefault: true},
		{path: pathServerRead, env: "DKIM2D_SERVER_READ_TIMEOUT", kind: valueDuration, defaultVal: defaultReadTimeout, hasDefault: true},
		{path: pathServerWrite, env: "DKIM2D_SERVER_WRITE_TIMEOUT", kind: valueDuration, defaultVal: defaultWriteTimeout, hasDefault: true},
		{path: pathServerDeadline, env: "DKIM2D_SERVER_REQUEST_DEADLINE", kind: valueDuration, defaultVal: defaultDeadline, hasDefault: true},
		{path: pathServerShutdown, env: "DKIM2D_SERVER_SHUTDOWN_TIMEOUT", kind: valueDuration, defaultVal: defaultReadTimeout, hasDefault: true},
		{path: pathServerMaxInFlight, env: "DKIM2D_SERVER_MAX_IN_FLIGHT", kind: valueUint, defaultVal: "1", hasDefault: true},
		{path: pathServerMaxWaiters, env: "DKIM2D_SERVER_MAX_WAITERS", kind: valueUint, defaultVal: "64", hasDefault: true},
		{path: pathServerAdmissionWait, env: "DKIM2D_SERVER_ADMISSION_WAIT", kind: valueDuration, defaultVal: defaultAdmissionWait, hasDefault: true},
		{path: pathPolicyMode, env: "DKIM2D_POLICY_MODE", flag: flagPolicyMode, kind: valueString, defaultVal: valuePolicyStrict, hasDefault: true},
		{path: pathDNSLookupTimeout, env: "DKIM2D_DNS_LOOKUP_TIMEOUT", kind: valueDuration, defaultVal: defaultReadHeader, hasDefault: true},
		{path: pathDNSMaxConcurrent, env: "DKIM2D_DNS_MAX_CONCURRENT_LOOKUPS", kind: valueUint, defaultVal: "64", hasDefault: true},
		{path: pathDNSCacheMaxEntries, env: "DKIM2D_DNS_CACHE_MAX_ENTRIES", kind: valueUint, defaultVal: "4096", hasDefault: true},
		{path: pathDNSPositiveTTLCap, env: "DKIM2D_DNS_CACHE_POSITIVE_TTL_CAP", kind: valueDuration, defaultVal: "1h", hasDefault: true},
		{path: pathDNSNegativeTTLCap, env: "DKIM2D_DNS_CACHE_NEGATIVE_TTL_CAP", kind: valueDuration, defaultVal: "5m", hasDefault: true},
		{path: pathDNSStableErrorTTLCap, env: "DKIM2D_DNS_CACHE_STABLE_ERROR_TTL_CAP", kind: valueDuration, defaultVal: "1m", hasDefault: true},
		{path: pathReplayBackend, env: "DKIM2D_REPLAY_BACKEND", flag: flagReplayBackend, kind: valueString, defaultVal: valueBackendValkey, hasDefault: true},
		{path: pathReplayHMACFile, env: "DKIM2D_REPLAY_HMAC_KEY_FILE", kind: valueString},
		{path: pathReplayEpoch, env: "DKIM2D_REPLAY_EPOCH", kind: valueUint},
		{path: pathReplayRetention, env: "DKIM2D_REPLAY_RETENTION", kind: valueDuration, defaultVal: "336h", hasDefault: true},
		{path: pathReplayMaxEntries, env: "DKIM2D_REPLAY_LIMITS_MAX_ENTRIES", kind: valueUint, defaultVal: "65536", hasDefault: true},
		{path: pathReplayMaxWaiters, env: "DKIM2D_REPLAY_LIMITS_MAX_WAITERS", kind: valueUint, defaultVal: "1024", hasDefault: true},
		{path: pathReplayPruneBudget, env: "DKIM2D_REPLAY_LIMITS_PRUNE_BUDGET", kind: valueUint, defaultVal: "4096", hasDefault: true},
		{path: pathReplayMaxInFlight, env: "DKIM2D_REPLAY_LIMITS_MAX_IN_FLIGHT", kind: valueUint, defaultVal: "1024", hasDefault: true},
		{path: pathReplayMaxAdmission, env: "DKIM2D_REPLAY_LIMITS_MAX_ADMISSION_WAITERS", kind: valueUint, defaultVal: "1024", hasDefault: true},
		{path: pathReplayRevalidate, env: "DKIM2D_REPLAY_REVALIDATE_INTERVAL", kind: valueDuration, defaultVal: defaultReadTimeout, hasDefault: true},
		{path: pathSigningBackend, env: "DKIM2D_SIGNING_BACKEND", kind: valueString, defaultVal: valueBackendDisabled, hasDefault: true},
		{path: pathSigningDatasource, env: "DKIM2D_SIGNING_DATASOURCE_FILE", kind: valueString},
		{path: pathSigningManifest, env: "DKIM2D_SIGNING_PRIVATE_MANIFEST_FILE", kind: valueString},
		{path: pathSigningReload, env: "DKIM2D_SIGNING_RELOAD_INTERVAL", kind: valueDuration, defaultVal: defaultReadTimeout, hasDefault: true},
		{path: pathSigningAllowGroup, env: "DKIM2D_SIGNING_ALLOW_RECIPIENT_GROUP", kind: valueBool, defaultVal: canonicalFalse, hasDefault: true},
		{path: pathSigningLimitProfile, env: "DKIM2D_SIGNING_LIMIT_PROFILE", kind: valueString, defaultVal: limitProfileSmall, hasDefault: true},
		{path: pathSigningMaxLoadBytes, env: "DKIM2D_SIGNING_MAX_LOAD_BYTES", kind: valueUint, defaultVal: "16777216", hasDefault: true},
		{path: pathSigningLDAPAddress, env: "DKIM2D_SIGNING_LDAP_ADDRESS", kind: valueString},
		{path: pathSigningLDAPServerName, env: "DKIM2D_SIGNING_LDAP_SERVER_NAME", kind: valueString},
		{path: pathSigningLDAPCAFile, env: "DKIM2D_SIGNING_LDAP_CA_FILE", kind: valueString},
		{path: pathSigningLDAPTransport, env: "DKIM2D_SIGNING_LDAP_TRANSPORT", kind: valueString},
		{path: pathSigningLDAPBindDN, env: "DKIM2D_SIGNING_LDAP_BIND_DN", kind: valueString},
		{path: pathSigningLDAPPassword, env: "DKIM2D_SIGNING_LDAP_PASSWORD_FILE", kind: valueString},
		{path: pathSigningLDAPBaseDN, env: "DKIM2D_SIGNING_LDAP_BASE_DN", kind: valueString},
		{path: pathSigningLDAPPageSize, env: "DKIM2D_SIGNING_LDAP_PAGE_SIZE", kind: valueUint, defaultVal: "128", hasDefault: true},
		{path: pathSigningLDAPDeadline, env: "DKIM2D_SIGNING_LDAP_LOAD_DEADLINE", kind: valueDuration, defaultVal: "5s", hasDefault: true},
		{path: pathSigningPGAddress, env: "DKIM2D_SIGNING_POSTGRESQL_ADDRESS", kind: valueString},
		{path: pathSigningPGServerName, env: "DKIM2D_SIGNING_POSTGRESQL_SERVER_NAME", kind: valueString},
		{path: pathSigningPGCAFile, env: "DKIM2D_SIGNING_POSTGRESQL_CA_FILE", kind: valueString},
		{path: pathSigningPGDatabase, env: "DKIM2D_SIGNING_POSTGRESQL_DATABASE", kind: valueString},
		{path: pathSigningPGUser, env: "DKIM2D_SIGNING_POSTGRESQL_USER", kind: valueString},
		{path: pathSigningPGPassword, env: "DKIM2D_SIGNING_POSTGRESQL_PASSWORD_FILE", kind: valueString},
		{path: pathSigningPGPageSize, env: "DKIM2D_SIGNING_POSTGRESQL_PAGE_SIZE", kind: valueUint, defaultVal: "128", hasDefault: true},
		{path: pathSigningPGDeadline, env: "DKIM2D_SIGNING_POSTGRESQL_LOAD_DEADLINE", kind: valueDuration, defaultVal: "5s", hasDefault: true},
		{path: pathSigningPGMaxConns, env: "DKIM2D_SIGNING_POSTGRESQL_MAX_CONNECTIONS", kind: valueUint, defaultVal: "2", hasDefault: true},
		{path: pathSigningPGIdleConns, env: "DKIM2D_SIGNING_POSTGRESQL_IDLE_CONNECTIONS", kind: valueUint, defaultVal: "1", hasDefault: true},
		{path: pathSigningMySQLAddress, env: "DKIM2D_SIGNING_MYSQL_ADDRESS", kind: valueString},
		{path: pathSigningMySQLServerName, env: "DKIM2D_SIGNING_MYSQL_SERVER_NAME", kind: valueString},
		{path: pathSigningMySQLCAFile, env: "DKIM2D_SIGNING_MYSQL_CA_FILE", kind: valueString},
		{path: pathSigningMySQLDatabase, env: "DKIM2D_SIGNING_MYSQL_DATABASE", kind: valueString},
		{path: pathSigningMySQLUser, env: "DKIM2D_SIGNING_MYSQL_USER", kind: valueString},
		{path: pathSigningMySQLPassword, env: "DKIM2D_SIGNING_MYSQL_PASSWORD_FILE", kind: valueString},
		{path: pathSigningMySQLPageSize, env: "DKIM2D_SIGNING_MYSQL_PAGE_SIZE", kind: valueUint, defaultVal: "128", hasDefault: true},
		{path: pathSigningMySQLDeadline, env: "DKIM2D_SIGNING_MYSQL_LOAD_DEADLINE", kind: valueDuration, defaultVal: "5s", hasDefault: true},
		{path: pathSigningMySQLMaxConns, env: "DKIM2D_SIGNING_MYSQL_MAX_CONNECTIONS", kind: valueUint, defaultVal: "2", hasDefault: true},
		{path: pathSigningMySQLIdleConns, env: "DKIM2D_SIGNING_MYSQL_IDLE_CONNECTIONS", kind: valueUint, defaultVal: "1", hasDefault: true},
		{path: pathValkeyAddress, env: "DKIM2D_REPLAY_VALKEY_ADDRESS", kind: valueString},
		{path: pathValkeyServerName, env: "DKIM2D_REPLAY_VALKEY_SERVER_NAME", kind: valueString},
		{path: pathValkeyCAFile, env: "DKIM2D_REPLAY_VALKEY_CA_FILE", kind: valueString},
		{path: pathValkeyApplicationUser, env: "DKIM2D_REPLAY_VALKEY_APPLICATION_USERNAME", kind: valueString},
		{path: pathValkeyApplicationPass, env: "DKIM2D_REPLAY_VALKEY_APPLICATION_PASSWORD_FILE", kind: valueString},
		{path: pathValkeyAuditorUser, env: "DKIM2D_REPLAY_VALKEY_AUDITOR_USERNAME", kind: valueString},
		{path: pathValkeyAuditorPass, env: "DKIM2D_REPLAY_VALKEY_AUDITOR_PASSWORD_FILE", kind: valueString},
		{path: pathValkeyDialTimeout, env: "DKIM2D_REPLAY_VALKEY_DIAL_TIMEOUT", kind: valueDuration, defaultVal: "2s", hasDefault: true},
		{path: pathValkeyTCPKeepalive, env: "DKIM2D_REPLAY_VALKEY_TCP_KEEPALIVE", kind: valueDuration, defaultVal: defaultReadTimeout, hasDefault: true},
		{path: pathValkeyWriteTimeout, env: "DKIM2D_REPLAY_VALKEY_CONNECTION_WRITE_TIMEOUT", kind: valueDuration, defaultVal: "2s", hasDefault: true},
		{path: pathAttestationPersistence, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_PERSISTENCE_MODE", kind: valueString},
		{path: pathAttestationFsync, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_APPEND_FSYNC_POLICY", kind: valueString},
		{path: pathAttestationSave, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_SAVE_SCHEDULE", kind: valueString},
		{path: pathAttestationMinReplicas, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_MIN_REPLICAS_TO_WRITE", kind: valueUint},
		{path: pathAttestationMaxLag, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_MIN_REPLICAS_MAX_LAG_SECONDS", kind: valueUint},
		{path: pathAttestationLossWindow, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_LOSS_WINDOW_ACCEPTANCE", kind: valueString},
		{path: pathAttestationRotation, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_ROTATION_STATE", kind: valueString},
		{path: pathAttestationNoGlobalExactlyOnce, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_NO_GLOBAL_EXACTLY_ONCE_CLAIM", kind: valueBool},
		{path: pathAttestationDedicatedDeployment, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_DEDICATED_DEPLOYMENT", kind: valueBool},
		{path: pathAttestationDedicatedDatabase, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_DEDICATED_DATABASE_ZERO", kind: valueBool},
		{path: pathAttestationDirectIPAuthority, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_DIRECT_IP_AUTHORITY", kind: valueBool},
		{path: pathAttestationNoSubstitution, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_NO_ENDPOINT_SUBSTITUTION", kind: valueBool},
		{path: pathAttestationStandaloneAuthority, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_STANDALONE_AUTHORITY", kind: valueBool},
		{path: pathAttestationSharedDraft, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_SHARED_DRAFT", kind: valueBool},
		{path: pathAttestationSharedAlgorithm, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_SHARED_ALGORITHM", kind: valueBool},
		{path: pathAttestationSharedNamespace, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_SHARED_NAMESPACE", kind: valueBool},
		{path: pathAttestationSharedEpoch, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_SHARED_EPOCH", kind: valueBool},
		{path: pathAttestationSharedSecretSet, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_SHARED_SECRET_SET", kind: valueBool},
		{path: pathAttestationSharedRetention, env: "DKIM2D_REPLAY_VALKEY_ATTESTATION_SHARED_RETENTION", kind: valueBool},
		{path: pathLoggingLevel, env: "DKIM2D_OBSERVABILITY_LOGGING_LEVEL", kind: valueString, defaultVal: canonicalInfo, hasDefault: true},
		{path: pathDebugMessageShape, env: "DKIM2D_OBSERVABILITY_DEBUG_MESSAGE_SHAPE", kind: valueBool, defaultVal: canonicalFalse, hasDefault: true},
		{path: pathDebugDNS, env: "DKIM2D_OBSERVABILITY_DEBUG_DNS", kind: valueBool, defaultVal: canonicalFalse, hasDefault: true},
		{path: pathDebugReplay, env: "DKIM2D_OBSERVABILITY_DEBUG_REPLAY", kind: valueBool, defaultVal: canonicalFalse, hasDefault: true},
		{path: pathTracingExporter, env: "DKIM2D_OBSERVABILITY_TRACING_EXPORTER", kind: valueString, defaultVal: canonicalNone, hasDefault: true},
		{path: pathTracingEndpoint, env: "DKIM2D_OBSERVABILITY_TRACING_ENDPOINT", kind: valueString},
		{path: pathTracingCAFile, env: "DKIM2D_OBSERVABILITY_TRACING_CA_FILE", kind: valueString},
		{path: pathTracingSamplePerMillion, env: "DKIM2D_OBSERVABILITY_TRACING_SAMPLE_PER_MILLION", kind: valueUint},
		{path: pathTracingExportTimeout, env: "DKIM2D_OBSERVABILITY_TRACING_EXPORT_TIMEOUT", kind: valueDuration},
	}
}

// Snapshot contains one immutable structurally opaque typed configuration.
type Snapshot struct {
	state *snapshotState
}

// String returns a content-free snapshot representation.
func (Snapshot) String() string { return snapshotRedactedText }

// GoString returns a content-free snapshot representation.
func (Snapshot) GoString() string { return snapshotRedactedText }

// Format prevents formatting verbs from exposing configuration values.
func (Snapshot) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, snapshotRedactedText)
}

// MarshalJSON rejects serialization of effective configuration.
func (Snapshot) MarshalJSON() ([]byte, error) {
	return nil, newError(CodeSerialization)
}

// MarshalText rejects serialization of effective configuration.
func (Snapshot) MarshalText() ([]byte, error) {
	return nil, newError(CodeSerialization)
}
