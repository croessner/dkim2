package config

import (
	"fmt"
	"io"
	"time"

	"slices"

	"github.com/croessner/dkim2"
)

const typedConfigRedactedText = "dkim2d_typed_config"

// MessageBytes returns the configured raw SMTP message ceiling.
func (c ServerConfig) MessageBytes() int {
	if c.state == nil {
		return 0
	}
	return c.state.messageBytes
}

// ServerConfig is one immutable structurally opaque HTTP configuration view.
type ServerConfig struct {
	state *serverState
}

// DNSConfig is one immutable structurally opaque DNS configuration view.
type DNSConfig struct {
	state *dnsState
}

// ReplayConfig is one immutable structurally opaque replay configuration view.
type ReplayConfig struct {
	state *replayState
}

// SigningConfig is one immutable structurally opaque signing configuration view.
type SigningConfig struct {
	state *signingState
}

// SigningPoliciesConfig is one immutable view of daemon-owned signing policies.
type SigningPoliciesConfig struct {
	state *signingPoliciesState
}

// LDAPSigningConfig is one immutable structurally opaque LDAP configuration view.
type LDAPSigningConfig struct {
	state *ldapSigningState
}

// SQLSigningConfig is one immutable structurally opaque network SQL configuration view.
type SQLSigningConfig struct {
	state *sqlSigningState
}

// PostgreSQLSigningConfig is the PostgreSQL-specific SQL configuration view.
type PostgreSQLSigningConfig = SQLSigningConfig

// MySQLSigningConfig is the MySQL and MariaDB-specific SQL configuration view.
type MySQLSigningConfig = SQLSigningConfig

// RedisConfig is one immutable structurally opaque Redis-provider configuration view.
type RedisConfig struct {
	state *redisState
}

// ObservabilityConfig is one immutable structurally opaque telemetry configuration view.
type ObservabilityConfig struct {
	state *observabilityState
}

// TracingConfig is one immutable structurally opaque trace configuration view.
type TracingConfig struct {
	state *tracingState
}

// Server returns the immutable HTTP configuration.
func (s Snapshot) Server() ServerConfig {
	if s.state == nil {
		return ServerConfig{}
	}
	return ServerConfig{state: &s.state.server}
}

// DNS returns the immutable DNS configuration.
func (s Snapshot) DNS() DNSConfig {
	if s.state == nil {
		return DNSConfig{}
	}
	return DNSConfig{state: &s.state.dns}
}

// Replay returns the immutable replay configuration.
func (s Snapshot) Replay() ReplayConfig {
	if s.state == nil {
		return ReplayConfig{}
	}
	return ReplayConfig{state: &s.state.replay}
}

// Signing returns the immutable signing-provider configuration.
func (s Snapshot) Signing() SigningConfig {
	if s.state == nil {
		return SigningConfig{}
	}
	return SigningConfig{state: &s.state.signing}
}

// Observability returns the immutable operational telemetry configuration.
func (s Snapshot) Observability() ObservabilityConfig {
	if s.state == nil {
		return ObservabilityConfig{}
	}
	return ObservabilityConfig{state: &s.state.observability}
}

// LogLevel returns the closed structured-log threshold.
func (c ObservabilityConfig) LogLevel() LogLevel {
	if c.state == nil {
		return 0
	}
	return c.state.logLevel
}

// DebugMessageShape reports whether bounded message-shape buckets are enabled.
func (c ObservabilityConfig) DebugMessageShape() bool {
	return c.state != nil && c.state.debugMessageShape
}

// DebugDNS reports whether bounded DNS completion events are enabled.
func (c ObservabilityConfig) DebugDNS() bool {
	return c.state != nil && c.state.debugDNS
}

// DebugReplay reports whether bounded replay completion events are enabled.
func (c ObservabilityConfig) DebugReplay() bool {
	return c.state != nil && c.state.debugReplay
}

// Tracing returns the immutable tracing configuration.
func (c ObservabilityConfig) Tracing() TracingConfig {
	if c.state == nil {
		return TracingConfig{}
	}
	return TracingConfig{state: &c.state.tracing}
}

// Exporter returns the closed tracing exporter selection.
func (c TracingConfig) Exporter() TracingExporter {
	if c.state == nil {
		return 0
	}
	return c.state.exporter
}

// Endpoint returns the validated direct HTTPS OTLP endpoint.
func (c TracingConfig) Endpoint() string {
	if c.state == nil {
		return ""
	}
	return c.state.endpoint
}

// CAFile returns the protected tracing trust-root path.
func (c TracingConfig) CAFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.caFile
}

// SamplePerMillion returns the bounded sampling numerator.
func (c TracingConfig) SamplePerMillion() uint32 {
	if c.state == nil {
		return 0
	}
	return c.state.samplePerMillion
}

// ExportTimeout returns the bounded exporter timeout.
func (c TracingConfig) ExportTimeout() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.exportTimeout
}

// Listen returns the canonical listener authority selected by configuration.
func (c ServerConfig) Listen() string {
	if c.state == nil {
		return ""
	}
	return c.state.listen
}

// PrivateNetwork reports whether the explicit private-container-network listener mode is enabled.
func (c ServerConfig) PrivateNetwork() bool {
	return c.state != nil && c.state.privateNetwork
}

// TLSCertificateFile returns the protected server certificate path for private-network mode.
func (c ServerConfig) TLSCertificateFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.tlsCertificateFile
}

// TLSPrivateKeyFile returns the protected server private-key path for private-network mode.
func (c ServerConfig) TLSPrivateKeyFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.tlsPrivateKeyFile
}

// TLSCAFile returns the protected internal-PKI trust-root path for private-network mode.
func (c ServerConfig) TLSCAFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.tlsCAFile
}

// TLSServerName returns the certificate DNS identity required by private-network mode.
func (c ServerConfig) TLSServerName() string {
	if c.state == nil {
		return ""
	}
	return c.state.tlsServerName
}

// CapabilityFile returns the protected process-capability path.
func (c ServerConfig) CapabilityFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.capabilityFile
}

// SignCapabilityFile returns the protected originator-signing capability path.
func (c ServerConfig) SignCapabilityFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.signCapabilityFile
}

// ReviseCapabilityFile returns the protected revision capability path.
func (c ServerConfig) ReviseCapabilityFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.reviseCapabilityFile
}

// DSNSignCapabilityFile returns the protected delivery-status signing capability path.
func (c ServerConfig) DSNSignCapabilityFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.dsnSignCapabilityFile
}

// ProcessDefaultTenant returns the fallback tenant of the process route. An
// empty value means no tenant is available and locality is not evaluated.
func (s Snapshot) ProcessDefaultTenant() string {
	if s.state == nil {
		return ""
	}
	return s.state.process.defaultTenant
}

// PropagationPendingLease returns the validated propagation reservation lease.
func (s Snapshot) PropagationPendingLease() time.Duration {
	if s.state == nil {
		return 0
	}
	return s.state.propagation.pendingLease
}

// DSNPropagateCapabilityFile returns the protected delivery-status
// propagation capability path.
func (c ServerConfig) DSNPropagateCapabilityFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.dsnPropagateCapabilityFile
}

// DSNPropagateEnabled reports whether delivery-status propagation has
// explicit capability authority. The route is unreachable without it.
func (c ServerConfig) DSNPropagateEnabled() bool {
	return c.state != nil && c.state.dsnPropagateCapabilityFile != ""
}

// SignEnabled reports whether the originator route has explicit capability authority.
func (c ServerConfig) SignEnabled() bool {
	return c.state != nil && c.state.signCapabilityFile != ""
}

// ReviseEnabled reports whether the revision route has explicit capability authority.
func (c ServerConfig) ReviseEnabled() bool {
	return c.state != nil && c.state.reviseCapabilityFile != ""
}

// DSNSignEnabled reports whether delivery-status signing has explicit capability authority.
func (c ServerConfig) DSNSignEnabled() bool {
	return c.state != nil && c.state.dsnSignCapabilityFile != ""
}

// SigningRouteEnabled reports whether any capability authorizes a route that
// invokes the signing application service directly: sign, revise, batch revise,
// or DSN sign. Propagation is deliberately excluded: it owns a separate
// capability and a separate service seam.
func (c ServerConfig) SigningRouteEnabled() bool {
	return c.SignEnabled() || c.ReviseEnabled() || c.BatchReviseEnabled() || c.DSNSignEnabled()
}

// AnyRouteCapability reports whether any route capability beyond the process
// capability is configured, propagation included. It is the single authority
// on whether the daemon must construct a signer at all.
func (c ServerConfig) AnyRouteCapability() bool {
	return c.SigningRouteEnabled() || c.DSNPropagateEnabled()
}

// SigningDatasourceConsumed reports whether at least one configured consumer
// needs the signing datasource: a signing or propagation route capability, or
// the received-DSN locality tenant of /v1/process. A configured datasource
// without any consumer is refused at load, so this never reports a silent
// no-op backend.
func (s Snapshot) SigningDatasourceConsumed() bool {
	return s.Signing().Enabled() &&
		signingDatasourceConsumed(s.Server().AnyRouteCapability(), s.ProcessDefaultTenant())
}

// signingDatasourceConsumed is the one rule shared by the document loader,
// the protected-generation loader, and the runtime handoff: a datasource is
// valid exactly when a route capability or the locality tenant consumes it.
func signingDatasourceConsumed(anyRouteCapability bool, defaultTenant string) bool {
	return anyRouteCapability || defaultTenant != ""
}

// Backend returns the selected signing backend.
func (c SigningConfig) Backend() SigningBackend {
	if c.state == nil {
		return 0
	}
	return c.state.backend
}

// Enabled reports whether daemon signing is configured.
func (c SigningConfig) Enabled() bool {
	return c.state != nil && c.state.backend != SigningDisabled
}

// Policies returns the immutable use-specific signing policies.
func (c SigningConfig) Policies() SigningPoliciesConfig {
	if c.state == nil {
		return SigningPoliciesConfig{}
	}
	return SigningPoliciesConfig{state: &c.state.policies}
}

// DeliveryStatusUnsignedOriginal returns the delivery-status compatibility
// policy for a returned original without any DKIM2-Signature header field.
// An absent configuration view reports the fail-closed reject default.
func (c SigningPoliciesConfig) DeliveryStatusUnsignedOriginal() UnsignedOriginalPolicy {
	if c.state == nil {
		return UnsignedOriginalReject
	}
	return c.state.unsignedOriginal
}

// DeliveryStatusReportingIdentity returns the operator-configured
// reporting-MTA identity that signs Postfix-generated DSNs, and whether one is
// configured. Without it, DSN signing keeps the embedded original's d=.
func (c SigningPoliciesConfig) DeliveryStatusReportingIdentity() (dkim2.DSNIdentity, bool) {
	if c.state == nil || !c.state.reportingIdentity.Valid() {
		return dkim2.DSNIdentity{}, false
	}
	return c.state.reportingIdentity, true
}

// InteropInfoEnabled reports whether outgoing signing emits unsigned interop diagnostics.
func (c SigningPoliciesConfig) InteropInfoEnabled() bool {
	return c.state != nil && c.state.interopInfo
}

// OriginatorNullSender returns the originator null-sender policy. An absent
// configuration view reports the fail-closed reject default.
func (c SigningPoliciesConfig) OriginatorNullSender() NullSenderPolicy {
	if c.state == nil {
		return NullSenderReject
	}
	return c.state.nullSender
}

// LDAP returns the selected verified LDAP configuration.
func (c SigningConfig) LDAP() (LDAPSigningConfig, bool) {
	if c.state == nil || c.state.backend != SigningLDAP {
		return LDAPSigningConfig{}, false
	}
	return LDAPSigningConfig{state: &c.state.ldap}, true
}

// PostgreSQL returns the selected verified PostgreSQL configuration.
func (c SigningConfig) PostgreSQL() (PostgreSQLSigningConfig, bool) {
	if c.state == nil || c.state.backend != SigningPostgreSQL {
		return PostgreSQLSigningConfig{}, false
	}
	return PostgreSQLSigningConfig{state: &c.state.postgresql}, true
}

// MySQL returns the selected verified MySQL or MariaDB configuration.
func (c SigningConfig) MySQL() (MySQLSigningConfig, bool) {
	if c.state == nil || c.state.backend != SigningMySQL {
		return MySQLSigningConfig{}, false
	}
	return MySQLSigningConfig{state: &c.state.mysql}, true
}

// Address returns the direct LDAP endpoint.
func (c LDAPSigningConfig) Address() string {
	if c.state == nil {
		return ""
	}
	return c.state.address
}

// ServerName returns the separately verified LDAP TLS identity.
func (c LDAPSigningConfig) ServerName() string {
	if c.state == nil {
		return ""
	}
	return c.state.serverName
}

// CAFile returns the protected LDAP trust-root path.
func (c LDAPSigningConfig) CAFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.caFile
}

// Transport returns the exact verified LDAP TLS mode.
func (c LDAPSigningConfig) Transport() string {
	if c.state == nil {
		return ""
	}
	return c.state.transport
}

// BindDN returns the protected LDAP bind identity.
func (c LDAPSigningConfig) BindDN() string {
	if c.state == nil {
		return ""
	}
	return c.state.bindDN
}

// PasswordFile returns the protected LDAP bind-secret path.
func (c LDAPSigningConfig) PasswordFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.passwordFile
}

// BaseDN returns the protected exact DKIM2 LDAP base.
func (c LDAPSigningConfig) BaseDN() string {
	if c.state == nil {
		return ""
	}
	return c.state.baseDN
}

// PageSize returns the bounded LDAP page size.
func (c LDAPSigningConfig) PageSize() uint16 {
	if c.state == nil {
		return 0
	}
	return c.state.pageSize
}

// LoadDeadline returns the immutable LDAP load budget.
func (c LDAPSigningConfig) LoadDeadline() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.loadDeadline
}

// Address returns the direct network SQL endpoint.
func (c SQLSigningConfig) Address() string {
	if c.state == nil {
		return ""
	}
	return c.state.address
}

// ServerName returns the separately verified network SQL TLS identity.
func (c SQLSigningConfig) ServerName() string {
	if c.state == nil {
		return ""
	}
	return c.state.serverName
}

// CAFile returns the protected network SQL trust-root path.
func (c SQLSigningConfig) CAFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.caFile
}

// Database returns the exact network SQL database.
func (c SQLSigningConfig) Database() string {
	if c.state == nil {
		return ""
	}
	return c.state.database
}

// User returns the least-privilege network SQL runtime principal.
func (c SQLSigningConfig) User() string {
	if c.state == nil {
		return ""
	}
	return c.state.user
}

// PasswordFile returns the protected network SQL password path.
func (c SQLSigningConfig) PasswordFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.passwordFile
}

// PageSize returns the bounded network SQL keyset page size.
func (c SQLSigningConfig) PageSize() uint16 {
	if c.state == nil {
		return 0
	}
	return c.state.pageSize
}

// LoadDeadline returns the immutable network SQL load budget.
func (c SQLSigningConfig) LoadDeadline() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.loadDeadline
}

// MaxConnections returns the bounded network SQL pool size.
func (c SQLSigningConfig) MaxConnections() uint8 {
	if c.state == nil {
		return 0
	}
	return c.state.maxConnections
}

// IdleConnections returns the bounded network SQL idle pool size.
func (c SQLSigningConfig) IdleConnections() uint8 {
	if c.state == nil {
		return 0
	}
	return c.state.idleConnections
}

// DatasourceFile returns the protected signing-profile datasource path.
func (c SigningConfig) DatasourceFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.datasourceFile
}

// PrivateManifestFile returns the protected private-key manifest path.
func (c SigningConfig) PrivateManifestFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.privateManifestFile
}

// ReloadInterval returns the bounded compound-generation reload interval.
func (c SigningConfig) ReloadInterval() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.reloadInterval
}

// AllowRecipientGroup reports whether explicit multi-recipient signing is enabled.
func (c SigningConfig) AllowRecipientGroup() bool {
	return c.state != nil && c.state.allowRecipientGroup
}

// LimitProfile returns the exact atomic datasource limit profile name.
func (c SigningConfig) LimitProfile() string {
	if c.state == nil {
		return ""
	}
	return c.state.limitProfile
}

// MaxLoadBytes returns the bounded complete network snapshot byte budget.
func (c SigningConfig) MaxLoadBytes() uint32 {
	if c.state == nil {
		return 0
	}
	return c.state.maxLoadBytes
}

// ReadHeaderTimeout returns the bounded request-header timeout.
func (c ServerConfig) ReadHeaderTimeout() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.readHeaderTimeout
}

// ReadTimeout returns the bounded whole-request read timeout.
func (c ServerConfig) ReadTimeout() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.readTimeout
}

// WriteTimeout returns the bounded response write timeout.
func (c ServerConfig) WriteTimeout() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.writeTimeout
}

// RequestDeadline returns the daemon-owned handler deadline.
func (c ServerConfig) RequestDeadline() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.requestDeadline
}

// ShutdownTimeout returns the inner graceful-shutdown budget.
func (c ServerConfig) ShutdownTimeout() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.shutdownTimeout
}

// MaxInFlight returns the process admission permit count.
func (c ServerConfig) MaxInFlight() uint8 {
	if c.state == nil {
		return 0
	}
	return c.state.maxInFlight
}

// MaxWaiters returns the process admission waiter limit.
func (c ServerConfig) MaxWaiters() uint16 {
	if c.state == nil {
		return 0
	}
	return c.state.maxWaiters
}

// WorkingSetBytes returns the process working-set budget every admission
// permit reserves from.
func (c ServerConfig) WorkingSetBytes() uint64 {
	if c.state == nil {
		return 0
	}
	return c.state.workingSetBytes
}

// BatchAggregateBytes returns the dedicated batch-revision aggregate, or zero
// when batch requests share the single-message sizing.
func (c ServerConfig) BatchAggregateBytes() int {
	if c.state == nil {
		return 0
	}
	return c.state.batchAggregateBytes
}

// BatchMaxInFlight returns the dedicated batch-revision permit count. It is
// consulted only when BatchAggregateBytes is nonzero.
func (c ServerConfig) BatchMaxInFlight() uint8 {
	if c.state == nil {
		return 0
	}
	return c.state.batchMaxInFlight
}

// AdmissionWait returns the process admission waiting budget.
func (c ServerConfig) AdmissionWait() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.admissionWait
}

// LookupTimeout returns the bounded DNS lookup budget.
func (c DNSConfig) LookupTimeout() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.lookupTimeout
}

// MaxConcurrentLookups returns the bounded DNS lookup concurrency.
func (c DNSConfig) MaxConcurrentLookups() uint16 {
	if c.state == nil {
		return 0
	}
	return c.state.maxConcurrentLookups
}

// MaxCacheEntries returns the bounded process-local DNS outcome capacity.
func (c DNSConfig) MaxCacheEntries() uint32 {
	if c.state == nil {
		return 0
	}
	return c.state.maxCacheEntries
}

// PositiveTTLCap returns the maximum positive DNS cache lifetime.
func (c DNSConfig) PositiveTTLCap() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.positiveTTLCap
}

// NegativeTTLCap returns the maximum authoritative absence cache lifetime.
func (c DNSConfig) NegativeTTLCap() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.negativeTTLCap
}

// StableErrorTTLCap returns the maximum stable malformed-state cache lifetime.
func (c DNSConfig) StableErrorTTLCap() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.stableErrorTTLCap
}

// Backend returns the selected replay backend.
func (c ReplayConfig) Backend() ReplayBackend {
	if c.state == nil {
		return 0
	}
	return c.state.backend
}

// Enabled reports whether replay state is configured.
func (c ReplayConfig) Enabled() bool {
	return c.state != nil && c.state.hasReplayConfig
}

// HMACKeyFile returns the protected replay-HMAC path.
func (c ReplayConfig) HMACKeyFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.hmacKeyFile
}

// Epoch returns the replay identity epoch.
func (c ReplayConfig) Epoch() uint32 {
	if c.state == nil {
		return 0
	}
	return c.state.epoch
}

// Retention returns the replay retention interval.
func (c ReplayConfig) Retention() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.retention
}

// CountDirectDeliveries reports whether local replay policy also counts
// messages authenticated only by the originator's i=1 signature.
func (c ReplayConfig) CountDirectDeliveries() bool {
	return c.state != nil && c.state.countDirect
}

// MaxEntries returns the replay entry bound.
func (c ReplayConfig) MaxEntries() uint32 {
	if c.state == nil {
		return 0
	}
	return c.state.maxEntries
}

// MaxWaiters returns the replay coalescing waiter bound.
func (c ReplayConfig) MaxWaiters() uint32 {
	if c.state == nil {
		return 0
	}
	return c.state.maxWaiters
}

// PruneBudget returns the replay pruning work bound.
func (c ReplayConfig) PruneBudget() uint32 {
	if c.state == nil {
		return 0
	}
	return c.state.pruneBudget
}

// MaxInFlight returns the replay admission permit bound.
func (c ReplayConfig) MaxInFlight() uint32 {
	if c.state == nil {
		return 0
	}
	return c.state.maxInFlight
}

// MaxAdmissionWaiters returns the replay admission waiter bound.
func (c ReplayConfig) MaxAdmissionWaiters() uint32 {
	if c.state == nil {
		return 0
	}
	return c.state.maxAdmissionWaiters
}

// Redis returns the immutable Redis configuration and whether it is selected.
func (c ReplayConfig) Redis() (RedisConfig, bool) {
	if c.state == nil || !c.state.hasRedisConfig {
		return RedisConfig{}, false
	}
	return RedisConfig{state: &c.state.redis}, true
}

// Mode returns the selected Redis topology.
func (c RedisConfig) Mode() RedisMode {
	if c.state == nil {
		return 0
	}
	return c.state.mode
}

// StandaloneAddress returns the standalone host:port, empty in other modes.
func (c RedisConfig) StandaloneAddress() string {
	if c.state == nil {
		return ""
	}
	return c.state.standaloneAddress
}

// SentinelMasterName returns the monitored master name, empty outside Sentinel mode.
func (c RedisConfig) SentinelMasterName() string {
	if c.state == nil {
		return ""
	}
	return c.state.sentinelMasterName
}

// SentinelAddresses returns a fresh copy of the parsed Sentinel host:port list.
func (c RedisConfig) SentinelAddresses() []string {
	if c.state == nil {
		return nil
	}
	return slices.Clone(c.state.sentinelAddresses)
}

// SentinelUsername returns the optional Sentinel ACL user name.
func (c RedisConfig) SentinelUsername() string {
	if c.state == nil {
		return ""
	}
	return c.state.sentinelUsername
}

// SentinelPasswordFile returns the optional protected Sentinel password path.
func (c RedisConfig) SentinelPasswordFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.sentinelPasswordFile
}

// ClusterAddresses returns a fresh copy of the parsed cluster seed host:port list.
func (c RedisConfig) ClusterAddresses() []string {
	if c.state == nil {
		return nil
	}
	return slices.Clone(c.state.clusterAddresses)
}

// ClusterMaxRedirects returns the bounded cluster redirect budget.
func (c RedisConfig) ClusterMaxRedirects() int {
	if c.state == nil {
		return 0
	}
	return int(c.state.clusterMaxRedirects)
}

// Username returns the optional data-path ACL user name.
func (c RedisConfig) Username() string {
	if c.state == nil {
		return ""
	}
	return c.state.username
}

// PasswordFile returns the optional protected data-path password path.
func (c RedisConfig) PasswordFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.passwordFile
}

// DatabaseNumber returns the selected logical database; always 0 in cluster mode.
func (c RedisConfig) DatabaseNumber() int {
	if c.state == nil {
		return 0
	}
	return int(c.state.databaseNumber)
}

// KeyPrefix returns the validated prefix prepended to every replay key.
func (c RedisConfig) KeyPrefix() string {
	if c.state == nil {
		return ""
	}
	return c.state.keyPrefix
}

// Protocol returns the RESP protocol version, 2 or 3.
func (c RedisConfig) Protocol() int {
	if c.state == nil {
		return 0
	}
	return int(c.state.protocol)
}

// TLSEnabled reports whether connections use TLS.
func (c RedisConfig) TLSEnabled() bool {
	return c.state != nil && c.state.tlsEnabled
}

// TLSCAFile returns the optional protected trust-root path; empty selects system roots.
func (c RedisConfig) TLSCAFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.tlsCAFile
}

// TLSCertificateFile returns the optional protected client-certificate path.
func (c RedisConfig) TLSCertificateFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.tlsCertificateFile
}

// TLSKeyFile returns the optional protected client-key path.
func (c RedisConfig) TLSKeyFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.tlsKeyFile
}

// TLSServerName returns the optional verification identity applied to every node.
func (c RedisConfig) TLSServerName() string {
	if c.state == nil {
		return ""
	}
	return c.state.tlsServerName
}

// TLSMinVersion returns the crypto/tls minimum version constant, zero without TLS.
func (c RedisConfig) TLSMinVersion() uint16 {
	if c.state == nil {
		return 0
	}
	return c.state.tlsMinVersion
}

// TLSInsecureSkipVerify reports whether peer verification is disabled.
func (c RedisConfig) TLSInsecureSkipVerify() bool {
	return c.state != nil && c.state.tlsInsecureSkipVerify
}

// PoolSize returns the bounded connection-pool size.
func (c RedisConfig) PoolSize() int {
	if c.state == nil {
		return 0
	}
	return int(c.state.poolSize)
}

// MinIdleConnections returns the idle-connection floor, at most PoolSize.
func (c RedisConfig) MinIdleConnections() int {
	if c.state == nil {
		return 0
	}
	return int(c.state.minIdleConnections)
}

// PoolTimeout returns the bounded wait for a pooled connection.
func (c RedisConfig) PoolTimeout() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.poolTimeout
}

// DialTimeout returns the bounded connection-establishment timeout.
func (c RedisConfig) DialTimeout() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.dialTimeout
}

// ReadTimeout returns the bounded reply read timeout.
func (c RedisConfig) ReadTimeout() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.readTimeout
}

// WriteTimeout returns the bounded command write timeout.
func (c RedisConfig) WriteTimeout() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.writeTimeout
}

// RetryMaxAttempts returns the total command attempts including the first.
func (c RedisConfig) RetryMaxAttempts() int {
	if c.state == nil {
		return 0
	}
	return int(c.state.retryMaxAttempts)
}

// RetryMinBackoff returns the minimum retry backoff.
func (c RedisConfig) RetryMinBackoff() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.retryMinBackoff
}

// RetryMaxBackoff returns the maximum retry backoff.
func (c RedisConfig) RetryMaxBackoff() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.retryMaxBackoff
}

// HealthInterval returns the start-to-start health-probe interval.
func (c RedisConfig) HealthInterval() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.healthInterval
}

// HealthTimeout returns the per-probe timeout, shorter than HealthInterval.
func (c RedisConfig) HealthTimeout() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.healthTimeout
}

// HealthFailureThreshold returns the consecutive probe failures that mark the store unhealthy.
func (c RedisConfig) HealthFailureThreshold() int {
	if c.state == nil {
		return 0
	}
	return int(c.state.healthFailures)
}

// RequireNoEviction reports whether startup requires the noeviction policy on every master.
func (c RedisConfig) RequireNoEviction() bool {
	return c.state != nil && c.state.requireNoEviction
}

// String returns a content-free typed configuration representation.
func (ServerConfig) String() string { return typedConfigRedactedText }

// GoString returns a content-free typed configuration representation.
func (ServerConfig) GoString() string { return typedConfigRedactedText }

// Format prevents formatting verbs from exposing server configuration.
func (ServerConfig) Format(state fmt.State, _ rune) { writeRedacted(state) }

// MarshalJSON rejects serialization of server configuration.
func (ServerConfig) MarshalJSON() ([]byte, error) { return nil, newError(CodeSerialization) }

// MarshalText rejects serialization of server configuration.
func (ServerConfig) MarshalText() ([]byte, error) { return nil, newError(CodeSerialization) }

// String returns a content-free typed configuration representation.
func (DNSConfig) String() string { return typedConfigRedactedText }

// GoString returns a content-free typed configuration representation.
func (DNSConfig) GoString() string { return typedConfigRedactedText }

// Format prevents formatting verbs from exposing DNS configuration.
func (DNSConfig) Format(state fmt.State, _ rune) { writeRedacted(state) }

// MarshalJSON rejects serialization of DNS configuration.
func (DNSConfig) MarshalJSON() ([]byte, error) { return nil, newError(CodeSerialization) }

// MarshalText rejects serialization of DNS configuration.
func (DNSConfig) MarshalText() ([]byte, error) { return nil, newError(CodeSerialization) }

// String returns a content-free typed configuration representation.
func (ReplayConfig) String() string { return typedConfigRedactedText }

// GoString returns a content-free typed configuration representation.
func (ReplayConfig) GoString() string { return typedConfigRedactedText }

// Format prevents formatting verbs from exposing replay configuration.
func (ReplayConfig) Format(state fmt.State, _ rune) { writeRedacted(state) }

// MarshalJSON rejects serialization of replay configuration.
func (ReplayConfig) MarshalJSON() ([]byte, error) { return nil, newError(CodeSerialization) }

// MarshalText rejects serialization of replay configuration.
func (ReplayConfig) MarshalText() ([]byte, error) { return nil, newError(CodeSerialization) }

// String returns a content-free typed configuration representation.
func (RedisConfig) String() string { return typedConfigRedactedText }

// GoString returns a content-free typed configuration representation.
func (RedisConfig) GoString() string { return typedConfigRedactedText }

// Format prevents formatting verbs from exposing Redis configuration.
func (RedisConfig) Format(state fmt.State, _ rune) { writeRedacted(state) }

// MarshalJSON rejects serialization of Redis configuration.
func (RedisConfig) MarshalJSON() ([]byte, error) { return nil, newError(CodeSerialization) }

// MarshalText rejects serialization of Redis configuration.
func (RedisConfig) MarshalText() ([]byte, error) { return nil, newError(CodeSerialization) }

// String returns a content-free typed configuration representation.
func (ObservabilityConfig) String() string { return typedConfigRedactedText }

// GoString returns a content-free typed configuration representation.
func (ObservabilityConfig) GoString() string { return typedConfigRedactedText }

// Format prevents formatting verbs from exposing observability configuration.
func (ObservabilityConfig) Format(state fmt.State, _ rune) { writeRedacted(state) }

// MarshalJSON rejects serialization of observability configuration.
func (ObservabilityConfig) MarshalJSON() ([]byte, error) { return nil, newError(CodeSerialization) }

// MarshalText rejects serialization of observability configuration.
func (ObservabilityConfig) MarshalText() ([]byte, error) { return nil, newError(CodeSerialization) }

// String returns a content-free typed configuration representation.
func (TracingConfig) String() string { return typedConfigRedactedText }

// GoString returns a content-free typed configuration representation.
func (TracingConfig) GoString() string { return typedConfigRedactedText }

// Format prevents formatting verbs from exposing tracing configuration.
func (TracingConfig) Format(state fmt.State, _ rune) { writeRedacted(state) }

// MarshalJSON rejects serialization of tracing configuration.
func (TracingConfig) MarshalJSON() ([]byte, error) { return nil, newError(CodeSerialization) }

// MarshalText rejects serialization of tracing configuration.
func (TracingConfig) MarshalText() ([]byte, error) { return nil, newError(CodeSerialization) }

// writeRedacted emits only the fixed typed-configuration marker.
func writeRedacted(state fmt.State) {
	_, _ = io.WriteString(state, typedConfigRedactedText)
}
