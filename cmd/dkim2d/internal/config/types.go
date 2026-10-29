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

	pathConfigVersion                     = "config.version"
	pathProtectedGeneration               = "protected.generation"
	pathServerListen                      = "server.listen"
	pathServerListenerMode                = "server.listener_mode"
	pathServerTLSCertificate              = "server.tls.certificate_file"
	pathServerTLSPrivateKey               = "server.tls.private_key_file"
	pathServerTLSCA                       = "server.tls.ca_file"
	pathServerTLSServerName               = "server.tls.server_name"
	pathServerCapability                  = "server.capability_file"
	pathServerSignCapability              = "server.sign_capability_file"
	pathServerReviseCapability            = "server.revise_capability_file"
	pathServerBatchReviseCapability       = "server.batch_revise_capability_file"
	pathServerDSNSignCapability           = "server.dsn_sign_capability_file"
	pathServerDSNPropagateCapability      = "server.dsn_propagate_capability_file"
	pathServerReadHeader                  = "server.read_header_timeout"
	pathServerRead                        = "server.read_timeout"
	pathServerWrite                       = "server.write_timeout"
	pathServerDeadline                    = "server.request_deadline"
	pathServerShutdown                    = "server.shutdown_timeout"
	pathServerMaxInFlight                 = "server.max_in_flight"
	pathServerMessageBytes                = "server.message_bytes"
	pathServerMaxWaiters                  = "server.max_waiters"
	pathServerWorkingSetBytes             = "server.working_set_bytes"
	pathServerBatchAggregateBytes         = "server.batch_revision.max_aggregate_message_bytes"
	pathServerBatchMaxInFlight            = "server.batch_revision.max_in_flight"
	pathServerAdmissionWait               = "server.admission_wait"
	pathPolicyMode                        = "policy.mode"
	pathProcessDefaultTenant              = "process.default_tenant"
	pathDSNPropagationPendingLease        = "dsn_propagation.pending_lease"
	pathDNSLookupTimeout                  = "dns.lookup_timeout"
	pathDNSMaxConcurrent                  = "dns.max_concurrent_lookups"
	pathDNSCacheMaxEntries                = "dns.cache.max_entries"
	pathDNSPositiveTTLCap                 = "dns.cache.positive_ttl_cap"
	pathDNSNegativeTTLCap                 = "dns.cache.negative_ttl_cap"
	pathDNSStableErrorTTLCap              = "dns.cache.stable_error_ttl_cap"
	pathReplayBackend                     = "replay.backend"
	pathReplayHMACFile                    = "replay.hmac_key_file"
	pathReplayEpoch                       = "replay.epoch"
	pathReplayRetention                   = "replay.retention"
	pathReplayMaxEntries                  = "replay.limits.max_entries"
	pathReplayMaxWaiters                  = "replay.limits.max_waiters"
	pathReplayPruneBudget                 = "replay.limits.prune_budget"
	pathReplayMaxInFlight                 = "replay.limits.max_in_flight"
	pathReplayMaxAdmission                = "replay.limits.max_admission_waiters"
	pathReplayCountDirect                 = "replay.count_direct_deliveries"
	pathSigningBackend                    = "signing.backend"
	pathSigningDatasource                 = "signing.datasource_file"
	pathSigningManifest                   = "signing.private_manifest_file"
	pathSigningReload                     = "signing.reload_interval"
	pathSigningAllowGroup                 = "signing.allow_recipient_group"
	pathSigningLimitProfile               = "signing.limit_profile"
	pathSigningMaxLoadBytes               = "signing.max_load_bytes"
	pathSigningInteropInfo                = "signing.interop_info.enabled"
	envSigningInteropInfo                 = "DKIM2D_SIGNING_INTEROP_INFO_ENABLED"
	pathSigningPolicyOriginatorNullSender = "signing.policy.originator.null_sender"
	pathSigningPolicyDeliveryUnsigned     = "signing.policy.delivery_status.unsigned_original"
	pathSigningPolicyDeliveryReporting    = "signing.policy.delivery_status.reporting_domain"
	envSigningPolicyOriginatorNullSender  = "DKIM2D_SIGNING_POLICY_ORIGINATOR_NULL_SENDER"
	envSigningPolicyDeliveryUnsigned      = "DKIM2D_SIGNING_POLICY_DELIVERY_STATUS_UNSIGNED_ORIGINAL"
	envSigningPolicyDeliveryReporting     = "DKIM2D_SIGNING_POLICY_DELIVERY_STATUS_REPORTING_DOMAIN"
	pathSigningLDAPAddress                = "signing.ldap.address"
	pathSigningLDAPServerName             = "signing.ldap.server_name"
	pathSigningLDAPCAFile                 = "signing.ldap.ca_file"
	pathSigningLDAPTransport              = "signing.ldap.transport"
	pathSigningLDAPBindDN                 = "signing.ldap.bind_dn"
	pathSigningLDAPPassword               = "signing.ldap.password_file"
	pathSigningLDAPBaseDN                 = "signing.ldap.base_dn"
	pathSigningLDAPPageSize               = "signing.ldap.page_size"
	pathSigningLDAPDeadline               = "signing.ldap.load_deadline"
	pathSigningPGAddress                  = "signing.postgresql.address"
	pathSigningPGServerName               = "signing.postgresql.server_name"
	pathSigningPGCAFile                   = "signing.postgresql.ca_file"
	pathSigningPGDatabase                 = "signing.postgresql.database"
	pathSigningPGUser                     = "signing.postgresql.user"
	pathSigningPGPassword                 = "signing.postgresql.password_file"
	pathSigningPGPageSize                 = "signing.postgresql.page_size"
	pathSigningPGDeadline                 = "signing.postgresql.load_deadline"
	pathSigningPGMaxConns                 = "signing.postgresql.max_connections"
	pathSigningPGIdleConns                = "signing.postgresql.idle_connections"
	pathSigningMySQLAddress               = "signing.mysql.address"
	pathSigningMySQLServerName            = "signing.mysql.server_name"
	pathSigningMySQLCAFile                = "signing.mysql.ca_file"
	pathSigningMySQLDatabase              = "signing.mysql.database"
	pathSigningMySQLUser                  = "signing.mysql.user"
	pathSigningMySQLPassword              = "signing.mysql.password_file"
	pathSigningMySQLPageSize              = "signing.mysql.page_size"
	pathSigningMySQLDeadline              = "signing.mysql.load_deadline"
	pathSigningMySQLMaxConns              = "signing.mysql.max_connections"
	pathSigningMySQLIdleConns             = "signing.mysql.idle_connections"

	pathRedisMode                   = "replay.redis.mode"
	pathRedisStandaloneAddress      = "replay.redis.standalone.address"
	pathRedisSentinelMasterName     = "replay.redis.sentinel.master_name"
	pathRedisSentinelAddresses      = "replay.redis.sentinel.addresses"
	pathRedisSentinelUsername       = "replay.redis.sentinel.username"
	pathRedisSentinelPasswordFile   = "replay.redis.sentinel.password_file"
	pathRedisClusterAddresses       = "replay.redis.cluster.addresses"
	pathRedisClusterMaxRedirects    = "replay.redis.cluster.max_redirects"
	pathRedisAuthUsername           = "replay.redis.auth.username"
	pathRedisAuthPasswordFile       = "replay.redis.auth.password_file"
	pathRedisDatabaseNumber         = "replay.redis.database_number"
	pathRedisKeyPrefix              = "replay.redis.key_prefix"
	pathRedisProtocol               = "replay.redis.protocol"
	pathRedisTLSEnabled             = "replay.redis.tls.enabled"
	pathRedisTLSCAFile              = "replay.redis.tls.ca_file"
	pathRedisTLSCertificate         = "replay.redis.tls.cert"
	pathRedisTLSKey                 = "replay.redis.tls.key"
	pathRedisTLSServerName          = "replay.redis.tls.server_name"
	pathRedisTLSMinVersion          = "replay.redis.tls.min_tls_version"
	pathRedisTLSInsecureSkipVerify  = "replay.redis.tls.insecure_skip_verify"
	pathRedisPoolSize               = "replay.redis.pool_size"
	pathRedisMinIdleConnections     = "replay.redis.min_idle_connections"
	pathRedisPoolTimeout            = "replay.redis.pool_timeout"
	pathRedisDialTimeout            = "replay.redis.dial_timeout"
	pathRedisReadTimeout            = "replay.redis.read_timeout"
	pathRedisWriteTimeout           = "replay.redis.write_timeout"
	pathRedisRetriesMaxAttempts     = "replay.redis.retries.max_attempts"
	pathRedisRetriesMinBackoff      = "replay.redis.retries.min_backoff"
	pathRedisRetriesMaxBackoff      = "replay.redis.retries.max_backoff"
	pathRedisHealthInterval         = "replay.redis.health.interval"
	pathRedisHealthTimeout          = "replay.redis.health.timeout"
	pathRedisHealthFailureThreshold = "replay.redis.health.failure_threshold"
	pathRedisRequireNoEviction      = "replay.redis.require_noeviction"

	valueRedisStandalone = "standalone"
	valueRedisSentinel   = "sentinel"
	valueRedisCluster    = "cluster"
	valueTLS12           = "TLS1.2"
	valueTLS13           = "TLS1.3"

	defaultListenAddress = "127.0.0.1:8080"
	defaultListenerMode  = "loopback"
	defaultReadHeader    = "5s"
	defaultReadTimeout   = "30s"
	defaultWriteTimeout  = "65s"
	defaultDeadline      = "60s"
	defaultAdmissionWait = "100ms"
	// defaultWorkingSetBytes is the 8 GiB process working-set budget.
	defaultWorkingSetBytes = "8589934592"
	// defaultPendingLease is the propagation reservation lease. It must exceed
	// the adapter's daemon timeout plus its re-injection and commit timeouts,
	// so that a retry inside the lease is deferred rather than served twice.
	defaultPendingLease = "120s"

	valuePolicyStrict    = "strict"
	valueListenerPrivate = "tls_private_network"
	valueBackendDisabled = "disabled"
	valueBackendRedis    = "redis"

	valueUnsignedOriginalReject   = "reject"
	valueUnsignedOriginalContinue = "continue"

	valueNullSenderReject     = "reject"
	valueNullSenderHeaderFrom = "header_from"

	flagListen        = "listen"
	flagPolicyMode    = "policy-mode"
	flagReplayBackend = "replay-backend"

	canonicalTrue  = "true"
	canonicalFalse = "false"
	canonicalInfo  = "info"
	canonicalNone  = "none"

	pathLoggingLevel            = "observability.logging.level"
	pathDebugMessageShape       = "observability.debug.message_shape"
	pathDebugDNS                = "observability.debug.dns"
	pathDebugReplay             = "observability.debug.replay"
	pathTracingExporter         = "observability.tracing.exporter"
	pathTracingEndpoint         = "observability.tracing.endpoint"
	pathTracingCAFile           = "observability.tracing.ca_file"
	pathTracingSamplePerMillion = "observability.tracing.sample_per_million"
	pathTracingExportTimeout    = "observability.tracing.export_timeout"
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
		{path: pathServerListenerMode, env: "DKIM2D_SERVER_LISTENER_MODE", kind: valueString, defaultVal: defaultListenerMode, hasDefault: true},
		{path: pathServerTLSCertificate, env: "DKIM2D_SERVER_TLS_CERTIFICATE_FILE", kind: valueString},
		{path: pathServerTLSPrivateKey, env: "DKIM2D_SERVER_TLS_PRIVATE_KEY_FILE", kind: valueString},
		{path: pathServerTLSCA, env: "DKIM2D_SERVER_TLS_CA_FILE", kind: valueString},
		{path: pathServerTLSServerName, env: "DKIM2D_SERVER_TLS_SERVER_NAME", kind: valueString},
		{path: pathServerCapability, env: "DKIM2D_SERVER_CAPABILITY_FILE", kind: valueString},
		{path: pathServerSignCapability, env: "DKIM2D_SERVER_SIGN_CAPABILITY_FILE", kind: valueString},
		{path: pathServerReviseCapability, env: "DKIM2D_SERVER_REVISE_CAPABILITY_FILE", kind: valueString},
		{path: pathServerBatchReviseCapability, env: "DKIM2D_SERVER_BATCH_REVISE_CAPABILITY_FILE", kind: valueString},
		{path: pathServerDSNSignCapability, env: "DKIM2D_SERVER_DSN_SIGN_CAPABILITY_FILE", kind: valueString},
		{path: pathServerDSNPropagateCapability, env: "DKIM2D_SERVER_DSN_PROPAGATE_CAPABILITY_FILE", kind: valueString},
		{path: pathServerReadHeader, env: "DKIM2D_SERVER_READ_HEADER_TIMEOUT", kind: valueDuration, defaultVal: defaultReadHeader, hasDefault: true},
		{path: pathServerRead, env: "DKIM2D_SERVER_READ_TIMEOUT", kind: valueDuration, defaultVal: defaultReadTimeout, hasDefault: true},
		{path: pathServerWrite, env: "DKIM2D_SERVER_WRITE_TIMEOUT", kind: valueDuration, defaultVal: defaultWriteTimeout, hasDefault: true},
		{path: pathServerDeadline, env: "DKIM2D_SERVER_REQUEST_DEADLINE", kind: valueDuration, defaultVal: defaultDeadline, hasDefault: true},
		{path: pathServerShutdown, env: "DKIM2D_SERVER_SHUTDOWN_TIMEOUT", kind: valueDuration, defaultVal: defaultReadTimeout, hasDefault: true},
		{path: pathServerMaxInFlight, env: "DKIM2D_SERVER_MAX_IN_FLIGHT", kind: valueUint, defaultVal: "1", hasDefault: true},
		{path: pathServerMessageBytes, env: "DKIM2D_SERVER_MESSAGE_BYTES", kind: valueUint, defaultVal: "33554432", hasDefault: true},
		{path: pathServerMaxWaiters, env: "DKIM2D_SERVER_MAX_WAITERS", kind: valueUint, defaultVal: "64", hasDefault: true},
		{path: pathServerWorkingSetBytes, env: "DKIM2D_SERVER_WORKING_SET_BYTES", kind: valueUint, defaultVal: defaultWorkingSetBytes, hasDefault: true},
		{path: pathServerBatchAggregateBytes, env: "DKIM2D_SERVER_BATCH_REVISION_MAX_AGGREGATE_MESSAGE_BYTES", kind: valueUint, defaultVal: "0", hasDefault: true},
		{path: pathServerBatchMaxInFlight, env: "DKIM2D_SERVER_BATCH_REVISION_MAX_IN_FLIGHT", kind: valueUint, defaultVal: "1", hasDefault: true},
		{path: pathServerAdmissionWait, env: "DKIM2D_SERVER_ADMISSION_WAIT", kind: valueDuration, defaultVal: defaultAdmissionWait, hasDefault: true},
		{path: pathPolicyMode, env: "DKIM2D_POLICY_MODE", flag: flagPolicyMode, kind: valueString, defaultVal: valuePolicyStrict, hasDefault: true},
		{path: pathProcessDefaultTenant, env: "DKIM2D_PROCESS_DEFAULT_TENANT", kind: valueString},
		{path: pathDSNPropagationPendingLease, env: "DKIM2D_DSN_PROPAGATION_PENDING_LEASE", kind: valueDuration, defaultVal: defaultPendingLease, hasDefault: true},
		{path: pathDNSLookupTimeout, env: "DKIM2D_DNS_LOOKUP_TIMEOUT", kind: valueDuration, defaultVal: defaultReadHeader, hasDefault: true},
		{path: pathDNSMaxConcurrent, env: "DKIM2D_DNS_MAX_CONCURRENT_LOOKUPS", kind: valueUint, defaultVal: "64", hasDefault: true},
		{path: pathDNSCacheMaxEntries, env: "DKIM2D_DNS_CACHE_MAX_ENTRIES", kind: valueUint, defaultVal: "4096", hasDefault: true},
		{path: pathDNSPositiveTTLCap, env: "DKIM2D_DNS_CACHE_POSITIVE_TTL_CAP", kind: valueDuration, defaultVal: "1h", hasDefault: true},
		{path: pathDNSNegativeTTLCap, env: "DKIM2D_DNS_CACHE_NEGATIVE_TTL_CAP", kind: valueDuration, defaultVal: "5m", hasDefault: true},
		{path: pathDNSStableErrorTTLCap, env: "DKIM2D_DNS_CACHE_STABLE_ERROR_TTL_CAP", kind: valueDuration, defaultVal: "1m", hasDefault: true},
		{path: pathReplayBackend, env: "DKIM2D_REPLAY_BACKEND", flag: flagReplayBackend, kind: valueString, defaultVal: valueBackendRedis, hasDefault: true},
		{path: pathReplayHMACFile, env: "DKIM2D_REPLAY_HMAC_KEY_FILE", kind: valueString},
		{path: pathReplayEpoch, env: "DKIM2D_REPLAY_EPOCH", kind: valueUint},
		{path: pathReplayRetention, env: "DKIM2D_REPLAY_RETENTION", kind: valueDuration, defaultVal: "336h", hasDefault: true},
		{path: pathReplayMaxEntries, env: "DKIM2D_REPLAY_LIMITS_MAX_ENTRIES", kind: valueUint, defaultVal: "65536", hasDefault: true},
		{path: pathReplayMaxWaiters, env: "DKIM2D_REPLAY_LIMITS_MAX_WAITERS", kind: valueUint, defaultVal: "1024", hasDefault: true},
		{path: pathReplayPruneBudget, env: "DKIM2D_REPLAY_LIMITS_PRUNE_BUDGET", kind: valueUint, defaultVal: "4096", hasDefault: true},
		{path: pathReplayMaxInFlight, env: "DKIM2D_REPLAY_LIMITS_MAX_IN_FLIGHT", kind: valueUint, defaultVal: "1024", hasDefault: true},
		{path: pathReplayMaxAdmission, env: "DKIM2D_REPLAY_LIMITS_MAX_ADMISSION_WAITERS", kind: valueUint, defaultVal: "1024", hasDefault: true},
		{path: pathReplayCountDirect, env: "DKIM2D_REPLAY_COUNT_DIRECT_DELIVERIES", kind: valueBool, defaultVal: canonicalFalse, hasDefault: true},
		{path: pathRedisMode, env: "DKIM2D_REPLAY_REDIS_MODE", kind: valueString, defaultVal: valueRedisStandalone, hasDefault: true},
		{path: pathRedisStandaloneAddress, env: "DKIM2D_REPLAY_REDIS_STANDALONE_ADDRESS", kind: valueString},
		{path: pathRedisSentinelMasterName, env: "DKIM2D_REPLAY_REDIS_SENTINEL_MASTER_NAME", kind: valueString},
		{path: pathRedisSentinelAddresses, env: "DKIM2D_REPLAY_REDIS_SENTINEL_ADDRESSES", kind: valueString},
		{path: pathRedisSentinelUsername, env: "DKIM2D_REPLAY_REDIS_SENTINEL_USERNAME", kind: valueString},
		{path: pathRedisSentinelPasswordFile, env: "DKIM2D_REPLAY_REDIS_SENTINEL_PASSWORD_FILE", kind: valueString},
		{path: pathRedisClusterAddresses, env: "DKIM2D_REPLAY_REDIS_CLUSTER_ADDRESSES", kind: valueString},
		{path: pathRedisClusterMaxRedirects, env: "DKIM2D_REPLAY_REDIS_CLUSTER_MAX_REDIRECTS", kind: valueUint, defaultVal: "8", hasDefault: true},
		{path: pathRedisAuthUsername, env: "DKIM2D_REPLAY_REDIS_AUTH_USERNAME", kind: valueString},
		{path: pathRedisAuthPasswordFile, env: "DKIM2D_REPLAY_REDIS_AUTH_PASSWORD_FILE", kind: valueString},
		{path: pathRedisDatabaseNumber, env: "DKIM2D_REPLAY_REDIS_DATABASE_NUMBER", kind: valueUint, defaultVal: "0", hasDefault: true},
		{path: pathRedisKeyPrefix, env: "DKIM2D_REPLAY_REDIS_KEY_PREFIX", kind: valueString},
		{path: pathRedisProtocol, env: "DKIM2D_REPLAY_REDIS_PROTOCOL", kind: valueUint, defaultVal: "3", hasDefault: true},
		{path: pathRedisTLSEnabled, env: "DKIM2D_REPLAY_REDIS_TLS_ENABLED", kind: valueBool, defaultVal: canonicalTrue, hasDefault: true},
		{path: pathRedisTLSCAFile, env: "DKIM2D_REPLAY_REDIS_TLS_CA_FILE", kind: valueString},
		{path: pathRedisTLSCertificate, env: "DKIM2D_REPLAY_REDIS_TLS_CERT", kind: valueString},
		{path: pathRedisTLSKey, env: "DKIM2D_REPLAY_REDIS_TLS_KEY", kind: valueString},
		{path: pathRedisTLSServerName, env: "DKIM2D_REPLAY_REDIS_TLS_SERVER_NAME", kind: valueString},
		{path: pathRedisTLSMinVersion, env: "DKIM2D_REPLAY_REDIS_TLS_MIN_TLS_VERSION", kind: valueString, defaultVal: valueTLS12, hasDefault: true},
		{path: pathRedisTLSInsecureSkipVerify, env: "DKIM2D_REPLAY_REDIS_TLS_INSECURE_SKIP_VERIFY", kind: valueBool, defaultVal: canonicalFalse, hasDefault: true},
		{path: pathRedisPoolSize, env: "DKIM2D_REPLAY_REDIS_POOL_SIZE", kind: valueUint, defaultVal: "20", hasDefault: true},
		{path: pathRedisMinIdleConnections, env: "DKIM2D_REPLAY_REDIS_MIN_IDLE_CONNECTIONS", kind: valueUint, defaultVal: "2", hasDefault: true},
		{path: pathRedisPoolTimeout, env: "DKIM2D_REPLAY_REDIS_POOL_TIMEOUT", kind: valueDuration, defaultVal: "2s", hasDefault: true},
		{path: pathRedisDialTimeout, env: "DKIM2D_REPLAY_REDIS_DIAL_TIMEOUT", kind: valueDuration, defaultVal: "2s", hasDefault: true},
		{path: pathRedisReadTimeout, env: "DKIM2D_REPLAY_REDIS_READ_TIMEOUT", kind: valueDuration, defaultVal: "2s", hasDefault: true},
		{path: pathRedisWriteTimeout, env: "DKIM2D_REPLAY_REDIS_WRITE_TIMEOUT", kind: valueDuration, defaultVal: "2s", hasDefault: true},
		{path: pathRedisRetriesMaxAttempts, env: "DKIM2D_REPLAY_REDIS_RETRIES_MAX_ATTEMPTS", kind: valueUint, defaultVal: "3", hasDefault: true},
		{path: pathRedisRetriesMinBackoff, env: "DKIM2D_REPLAY_REDIS_RETRIES_MIN_BACKOFF", kind: valueDuration, defaultVal: "50ms", hasDefault: true},
		{path: pathRedisRetriesMaxBackoff, env: "DKIM2D_REPLAY_REDIS_RETRIES_MAX_BACKOFF", kind: valueDuration, defaultVal: "500ms", hasDefault: true},
		{path: pathRedisHealthInterval, env: "DKIM2D_REPLAY_REDIS_HEALTH_INTERVAL", kind: valueDuration, defaultVal: "5s", hasDefault: true},
		{path: pathRedisHealthTimeout, env: "DKIM2D_REPLAY_REDIS_HEALTH_TIMEOUT", kind: valueDuration, defaultVal: "2s", hasDefault: true},
		{path: pathRedisHealthFailureThreshold, env: "DKIM2D_REPLAY_REDIS_HEALTH_FAILURE_THRESHOLD", kind: valueUint, defaultVal: "3", hasDefault: true},
		{path: pathRedisRequireNoEviction, env: "DKIM2D_REPLAY_REDIS_REQUIRE_NOEVICTION", kind: valueBool, defaultVal: canonicalTrue, hasDefault: true},
		{path: pathSigningBackend, env: "DKIM2D_SIGNING_BACKEND", kind: valueString, defaultVal: valueBackendDisabled, hasDefault: true},
		{path: pathSigningDatasource, env: "DKIM2D_SIGNING_DATASOURCE_FILE", kind: valueString},
		{path: pathSigningManifest, env: "DKIM2D_SIGNING_PRIVATE_MANIFEST_FILE", kind: valueString},
		{path: pathSigningReload, env: "DKIM2D_SIGNING_RELOAD_INTERVAL", kind: valueDuration, defaultVal: defaultReadTimeout, hasDefault: true},
		{path: pathSigningAllowGroup, env: "DKIM2D_SIGNING_ALLOW_RECIPIENT_GROUP", kind: valueBool, defaultVal: canonicalFalse, hasDefault: true},
		{path: pathSigningLimitProfile, env: "DKIM2D_SIGNING_LIMIT_PROFILE", kind: valueString, defaultVal: limitProfileSmall, hasDefault: true},
		{path: pathSigningMaxLoadBytes, env: "DKIM2D_SIGNING_MAX_LOAD_BYTES", kind: valueUint, defaultVal: "16777216", hasDefault: true},
		{path: pathSigningInteropInfo, env: envSigningInteropInfo, kind: valueBool, defaultVal: canonicalFalse, hasDefault: true},
		{path: pathSigningPolicyOriginatorNullSender, env: envSigningPolicyOriginatorNullSender, kind: valueString, defaultVal: valueNullSenderReject, hasDefault: true},
		{path: pathSigningPolicyDeliveryUnsigned, env: envSigningPolicyDeliveryUnsigned, kind: valueString, defaultVal: valueUnsignedOriginalReject, hasDefault: true},
		{path: pathSigningPolicyDeliveryReporting, env: envSigningPolicyDeliveryReporting, kind: valueString},
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
