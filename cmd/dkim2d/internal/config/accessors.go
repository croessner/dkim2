package config

import (
	"fmt"
	"io"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/replay/valkey"
)

const typedConfigRedactedText = "dkim2d_typed_config"

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

// ValkeyConfig is one immutable structurally opaque Valkey configuration view.
type ValkeyConfig struct {
	state *valkeyState
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

// Listen returns the canonical loopback listener authority.
func (c ServerConfig) Listen() string {
	if c.state == nil {
		return ""
	}
	return c.state.listen
}

// CapabilityFile returns the protected process-capability path.
func (c ServerConfig) CapabilityFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.capabilityFile
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

// RevalidateInterval returns the Valkey authority revalidation interval.
func (c ReplayConfig) RevalidateInterval() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.revalidateInterval
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

// Valkey returns the immutable Valkey configuration and whether it is selected.
func (c ReplayConfig) Valkey() (ValkeyConfig, bool) {
	if c.state == nil || !c.state.hasValkeyConfig {
		return ValkeyConfig{}, false
	}
	return ValkeyConfig{state: &c.state.valkey}, true
}

// OperatorAttestation returns the validated M12 deployment attestation.
func (c ReplayConfig) OperatorAttestation() (valkey.OperatorAttestation, bool) {
	if c.state == nil || !c.state.hasValkeyConfig {
		return valkey.OperatorAttestation{}, false
	}
	return c.state.operatorAttestation, true
}

// Address returns the canonical direct Valkey authority.
func (c ValkeyConfig) Address() string {
	if c.state == nil {
		return ""
	}
	return c.state.address
}

// ServerName returns the exact TLS peer identity.
func (c ValkeyConfig) ServerName() string {
	if c.state == nil {
		return ""
	}
	return c.state.serverName
}

// CAFile returns the protected trust-root path.
func (c ValkeyConfig) CAFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.caFile
}

// ApplicationUsername returns the application ACL identity.
func (c ValkeyConfig) ApplicationUsername() string {
	if c.state == nil {
		return ""
	}
	return c.state.applicationUsername
}

// ApplicationPasswordFile returns the protected application-password path.
func (c ValkeyConfig) ApplicationPasswordFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.applicationPasswordFile
}

// AuditorUsername returns the auditor ACL identity.
func (c ValkeyConfig) AuditorUsername() string {
	if c.state == nil {
		return ""
	}
	return c.state.auditorUsername
}

// AuditorPasswordFile returns the protected auditor-password path.
func (c ValkeyConfig) AuditorPasswordFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.auditorPasswordFile
}

// DialTimeout returns the bounded Valkey dial timeout.
func (c ValkeyConfig) DialTimeout() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.dialTimeout
}

// TCPKeepalive returns the bounded Valkey TCP keepalive.
func (c ValkeyConfig) TCPKeepalive() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.tcpKeepalive
}

// ConnectionWriteTimeout returns the bounded Valkey write timeout.
func (c ValkeyConfig) ConnectionWriteTimeout() time.Duration {
	if c.state == nil {
		return 0
	}
	return c.state.connectionWriteTimeout
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
func (ValkeyConfig) String() string { return typedConfigRedactedText }

// GoString returns a content-free typed configuration representation.
func (ValkeyConfig) GoString() string { return typedConfigRedactedText }

// Format prevents formatting verbs from exposing Valkey configuration.
func (ValkeyConfig) Format(state fmt.State, _ rune) { writeRedacted(state) }

// MarshalJSON rejects serialization of Valkey configuration.
func (ValkeyConfig) MarshalJSON() ([]byte, error) { return nil, newError(CodeSerialization) }

// MarshalText rejects serialization of Valkey configuration.
func (ValkeyConfig) MarshalText() ([]byte, error) { return nil, newError(CodeSerialization) }

// writeRedacted emits only the fixed typed-configuration marker.
func writeRedacted(state fmt.State) {
	_, _ = io.WriteString(state, typedConfigRedactedText)
}
