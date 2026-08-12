package valkey

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	dkim2 "github.com/croessner/dkim2"
	valkeygo "github.com/valkey-io/valkey-go"
)

const (
	clientConfigRedactedText  = "valkey_client_config"
	auditorConfigRedactedText = "valkey_auditor_config"
	replayNamespace           = "dkim2:replay:v1:"
)

// Topology identifies one closed Valkey deployment shape.
type Topology uint8

const (
	// TopologyStandalonePrimary selects one direct standalone primary.
	TopologyStandalonePrimary Topology = iota + 1
	// TopologyCluster is reserved and rejected by the current authority model.
	TopologyCluster
)

// clientConfigValues owns normalized production application-client inputs.
type clientConfigValues struct {
	mu                  sync.Mutex
	closed              bool
	Endpoint            string
	Topology            Topology
	Database            int
	ClientName          string
	DisableCache        bool
	DisableRetry        bool
	TLSServerName       string
	RootCertificatesDER [][]byte
	Username            string
	Password            []byte
	DialTimeout         time.Duration
	TCPKeepAlive        time.Duration
	ConnWriteTimeout    time.Duration
	Draft               string
	Algorithm           string
	Namespace           string
	Epoch               uint32
	MinimumRetention    time.Duration
	MaximumRetention    time.Duration
	Limits              dkim2.ReplayLimits
}

// ClientConfig is an opaque, copy-safe production application-client input.
type ClientConfig struct {
	values *clientConfigValues
}

// auditorConfigValues owns only protected ephemeral-auditor credentials.
type auditorConfigValues struct {
	mu       sync.Mutex
	closed   bool
	Username string
	Password []byte
}

// AuditorConfig is an opaque, copy-safe ephemeral-auditor credential input.
type AuditorConfig struct {
	values *auditorConfigValues
}

// cloneDER creates an independent nested byte-slice snapshot without validation.
func cloneDER(input [][]byte) [][]byte {
	if input == nil {
		return nil
	}
	output := make([][]byte, len(input))
	for index := range input {
		output[index] = append([]byte(nil), input[index]...)
	}
	return output
}

// cloneBoundedDER rejects oversized trust input before allocating owned copies.
func cloneBoundedDER(input [][]byte) ([][]byte, bool) {
	if len(input) < 1 || len(input) > 128 {
		return nil, false
	}
	total := 0
	for _, der := range input {
		if len(der) < 1 || len(der) > 64*1024 || total > 256*1024-len(der) {
			return nil, false
		}
		total += len(der)
	}
	return cloneDER(input), true
}

// snapshot clones one live client input while serializing release.
func (c ClientConfig) snapshot() (*clientConfigValues, bool) {
	if c.values == nil {
		return nil, false
	}
	c.values.mu.Lock()
	defer c.values.mu.Unlock()
	if c.values.closed {
		return nil, false
	}
	snapshot := &clientConfigValues{
		Endpoint:            c.values.Endpoint,
		Topology:            c.values.Topology,
		Database:            c.values.Database,
		ClientName:          c.values.ClientName,
		DisableCache:        c.values.DisableCache,
		DisableRetry:        c.values.DisableRetry,
		TLSServerName:       c.values.TLSServerName,
		RootCertificatesDER: cloneDER(c.values.RootCertificatesDER),
		Username:            c.values.Username,
		Password:            append([]byte(nil), c.values.Password...),
		DialTimeout:         c.values.DialTimeout,
		TCPKeepAlive:        c.values.TCPKeepAlive,
		ConnWriteTimeout:    c.values.ConnWriteTimeout,
		Draft:               c.values.Draft,
		Algorithm:           c.values.Algorithm,
		Namespace:           c.values.Namespace,
		Epoch:               c.values.Epoch,
		MinimumRetention:    c.values.MinimumRetention,
		MaximumRetention:    c.values.MaximumRetention,
		Limits:              c.values.Limits,
	}
	return snapshot, true
}

// Close releases protected client inputs shared by all copied values.
func (c ClientConfig) Close() {
	if c.values == nil {
		return
	}
	c.values.mu.Lock()
	defer c.values.mu.Unlock()
	if c.values.closed {
		return
	}
	clear(c.values.Password)
	c.values.Password = nil
	for index := range c.values.RootCertificatesDER {
		clear(c.values.RootCertificatesDER[index])
		c.values.RootCertificatesDER[index] = nil
	}
	c.values.RootCertificatesDER = nil
	c.values.Endpoint = ""
	c.values.TLSServerName = ""
	c.values.Username = ""
	c.values.closed = true
}

// snapshot clones one live auditor input while serializing release.
func (c AuditorConfig) snapshot() (*auditorConfigValues, bool) {
	if c.values == nil {
		return nil, false
	}
	c.values.mu.Lock()
	defer c.values.mu.Unlock()
	if c.values.closed {
		return nil, false
	}
	return &auditorConfigValues{
		Username: c.values.Username,
		Password: append([]byte(nil), c.values.Password...),
	}, true
}

// Close releases protected auditor credentials shared by all copied values.
func (c AuditorConfig) Close() {
	if c.values == nil {
		return
	}
	c.values.mu.Lock()
	defer c.values.mu.Unlock()
	if c.values.closed {
		return
	}
	clear(c.values.Password)
	c.values.Password = nil
	c.values.Username = ""
	c.values.closed = true
}

// validatedClientConfig owns immutable authority and application credentials.
type validatedClientConfig struct {
	endpoint         string
	tlsServerName    string
	rootCertificates *x509.CertPool
	username         string
	password         []byte
	dialTimeout      time.Duration
	tcpKeepAlive     time.Duration
	connWriteTimeout time.Duration
	epoch            uint32
	limits           dkim2.ReplayLimits
}

// auditAuthority owns only the immutable password-free transport authority.
type auditAuthority struct {
	endpoint         string
	tlsServerName    string
	rootCertificates *x509.CertPool
	dialTimeout      time.Duration
	tcpKeepAlive     time.Duration
}

// validatedAuditorConfig owns one bounded credential clone.
type validatedAuditorConfig struct {
	username string
	password []byte
}

// NewClientConfig clones and retains one complete opaque application-client input.
func NewClientConfig(
	endpoint string,
	tlsServerName string,
	rootCertificatesDER [][]byte,
	username string,
	password []byte,
	dialTimeout time.Duration,
	tcpKeepAlive time.Duration,
	connWriteTimeout time.Duration,
	epoch uint32,
	limits dkim2.ReplayLimits,
) ClientConfig {
	if len(password) < 1 || len(password) > 1024 {
		return ClientConfig{}
	}
	roots, ok := cloneBoundedDER(rootCertificatesDER)
	if !ok {
		return ClientConfig{}
	}
	return ClientConfig{values: &clientConfigValues{
		Endpoint:            endpoint,
		Topology:            TopologyStandalonePrimary,
		Database:            0,
		ClientName:          "",
		DisableCache:        true,
		DisableRetry:        true,
		TLSServerName:       tlsServerName,
		RootCertificatesDER: roots,
		Username:            username,
		Password:            append([]byte(nil), password...),
		DialTimeout:         dialTimeout,
		TCPKeepAlive:        tcpKeepAlive,
		ConnWriteTimeout:    connWriteTimeout,
		Draft:               dkim2.DraftIdentifier,
		Algorithm:           dkim2.ReplayKeyAlgorithm,
		Namespace:           replayNamespace,
		Epoch:               epoch,
		MinimumRetention:    time.Second,
		MaximumRetention:    30 * 24 * time.Hour,
		Limits:              limits,
	}}
}

// validateClientConfig clones and proves every local authority invariant.
func validateClientConfig(config ClientConfig) (validatedClientConfig, error) {
	input, live := config.snapshot()
	if !live {
		return validatedClientConfig{}, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	defer func() {
		clear(input.Password)
		for index := range input.RootCertificatesDER {
			clear(input.RootCertificatesDER[index])
		}
	}()
	if input.Topology != TopologyStandalonePrimary ||
		input.Database != 0 ||
		input.ClientName != "" ||
		!input.DisableCache ||
		!input.DisableRetry ||
		input.Draft != dkim2.DraftIdentifier ||
		input.Algorithm != dkim2.ReplayKeyAlgorithm ||
		input.Namespace != replayNamespace ||
		input.Epoch == 0 ||
		input.MinimumRetention != time.Second ||
		input.MaximumRetention != 30*24*time.Hour {
		return validatedClientConfig{}, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	resolvedLimits, err := resolveAdmissionLimits(input.Limits)
	if err != nil {
		return validatedClientConfig{}, err
	}
	if !validCanonicalEndpoint(input.Endpoint) ||
		!validTLSServerName(input.TLSServerName) ||
		!validUsername(input.Username) ||
		len(input.Password) < 1 || len(input.Password) > 1024 ||
		input.DialTimeout < 100*time.Millisecond ||
		input.DialTimeout > 30*time.Second ||
		input.TCPKeepAlive < time.Second ||
		input.TCPKeepAlive > 5*time.Minute ||
		input.ConnWriteTimeout < 100*time.Millisecond ||
		input.ConnWriteTimeout > 30*time.Second {
		return validatedClientConfig{}, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	roots, err := cloneAndValidateRoots(input.RootCertificatesDER)
	if err != nil {
		return validatedClientConfig{}, err
	}
	defer func() {
		for index := range roots {
			clear(roots[index])
		}
	}()
	pool, err := poolFromValidatedRoots(roots)
	if err != nil {
		return validatedClientConfig{}, err
	}
	return validatedClientConfig{
		endpoint:         input.Endpoint,
		tlsServerName:    input.TLSServerName,
		rootCertificates: pool,
		username:         input.Username,
		password:         append([]byte(nil), input.Password...),
		dialTimeout:      input.DialTimeout,
		tcpKeepAlive:     input.TCPKeepAlive,
		connWriteTimeout: input.ConnWriteTimeout,
		epoch:            input.Epoch,
		limits:           resolvedLimits,
	}, nil
}

// resolveAdmissionLimits applies exact defaults and rejects widened Valkey admission caps.
func resolveAdmissionLimits(limits dkim2.ReplayLimits) (dkim2.ReplayLimits, error) {
	if limits.MaxEntries == 0 {
		limits.MaxEntries = 65_536
	}
	if limits.MaxWaiters == 0 {
		limits.MaxWaiters = 1024
	}
	if limits.PruneBudget == 0 {
		limits.PruneBudget = 4096
	}
	if limits.MaxInFlight == 0 {
		limits.MaxInFlight = 1024
	}
	if limits.MaxAdmissionWaiters == 0 {
		limits.MaxAdmissionWaiters = 1024
	}
	if err := limits.Validate(); err != nil {
		return dkim2.ReplayLimits{}, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	return limits, nil
}

// NewAuditorConfig clones and retains one opaque credentials-only input.
func NewAuditorConfig(username string, password []byte) AuditorConfig {
	if len(password) < 1 || len(password) > 1024 {
		return AuditorConfig{}
	}
	return AuditorConfig{values: &auditorConfigValues{
		Username: username,
		Password: append([]byte(nil), password...),
	}}
}

// validateAuditorConfig clones one credentials-only protected value.
func validateAuditorConfig(config AuditorConfig) (validatedAuditorConfig, error) {
	input, live := config.snapshot()
	if !live {
		return validatedAuditorConfig{}, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	defer clear(input.Password)
	if !validUsername(input.Username) ||
		len(input.Password) < 1 ||
		len(input.Password) > 1024 {
		return validatedAuditorConfig{}, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	return validatedAuditorConfig{
		username: input.Username,
		password: append([]byte(nil), input.Password...),
	}, nil
}

// option builds one fresh complete restrictive valkey-go option value.
func (c validatedClientConfig) option() valkeygo.ClientOption {
	return valkeygo.ClientOption{
		TLSConfig: c.tlsConfig(),
		Dialer: net.Dialer{
			Timeout:   c.dialTimeout,
			KeepAlive: c.tcpKeepAlive,
		},
		Username:          c.username,
		Password:          string(c.password),
		ClientSetInfo:     make([]string, 0),
		InitAddress:       []string{c.endpoint},
		ConnWriteTimeout:  c.connWriteTimeout,
		DisableRetry:      true,
		DisableCache:      true,
		ForceSingleClient: true,
	}
}

// tlsConfig constructs one fresh exact peer-verification policy without credentials.
func (c validatedClientConfig) tlsConfig() *tls.Config {
	return strictTLSConfig(c.tlsServerName, c.rootCertificates)
}

// auditAuthority projects the least transport authority from validated application state.
func (c validatedClientConfig) auditAuthority() auditAuthority {
	return auditAuthority{
		endpoint:         c.endpoint,
		tlsServerName:    c.tlsServerName,
		rootCertificates: c.rootCertificates.Clone(),
		dialTimeout:      c.dialTimeout,
		tcpKeepAlive:     c.tcpKeepAlive,
	}
}

// clone returns an independently owned authority for one factory invocation.
func (a auditAuthority) clone() auditAuthority {
	a.rootCertificates = a.rootCertificates.Clone()
	return a
}

// tlsConfig constructs one fresh exact auditor peer-verification policy.
func (a auditAuthority) tlsConfig() *tls.Config {
	return strictTLSConfig(a.tlsServerName, a.rootCertificates)
}

// strictTLSConfig constructs the shared exact TLS 1.3 peer-verification policy.
func strictTLSConfig(serverName string, roots *x509.CertPool) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		RootCAs:                roots.Clone(),
		ServerName:             serverName,
		SessionTicketsDisabled: true,
	}
}

// poolFromValidatedRoots constructs one private pool from validated owned DER.
func poolFromValidatedRoots(roots [][]byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, der := range roots {
		certificate, err := x509.ParseCertificate(append([]byte(nil), der...))
		if err != nil {
			return nil, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
		pool.AddCert(certificate)
	}
	return pool, nil
}

// clearPassword best-effort clears the application credential clone.
func (c *validatedClientConfig) clearPassword() {
	if c == nil {
		return
	}
	clear(c.password)
	c.password = nil
}

// clear best-effort clears one ephemeral auditor credential clone.
func (c *validatedAuditorConfig) clear() {
	if c == nil {
		return
	}
	clear(c.password)
	c.password = nil
}

// validCanonicalEndpoint proves one direct canonical IP-literal authority.
func validCanonicalEndpoint(endpoint string) bool {
	if len(endpoint) < 1 || len(endpoint) > 47 {
		return false
	}
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" || portText == "" {
		return false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != portText {
		return false
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" || address.String() != host {
		return false
	}
	canonical := net.JoinHostPort(address.String(), portText)
	return canonical == endpoint
}

// ValidAuthority validates the password-free direct authority and separated ACL identities.
func ValidAuthority(endpoint, serverName, applicationUsername, auditorUsername string) bool {
	return validCanonicalEndpoint(endpoint) &&
		validTLSServerName(serverName) &&
		validUsername(applicationUsername) &&
		validUsername(auditorUsername) &&
		applicationUsername != auditorUsername
}

// validTLSServerName proves one canonical IP or lowercase ASCII DNS name.
func validTLSServerName(name string) bool {
	if len(name) < 1 || len(name) > 253 {
		return false
	}
	if address, err := netip.ParseAddr(name); err == nil {
		return address.Zone() == "" && address.String() == name
	}
	if strings.HasSuffix(name, ".") {
		return false
	}
	labels := strings.SplitSeq(name, ".")
	for label := range labels {
		if len(label) < 1 || len(label) > 63 ||
			!asciiLetterOrDigit(label[0]) ||
			!asciiLetterOrDigit(label[len(label)-1]) {
			return false
		}
		for index := range len(label) {
			value := label[index]
			if !asciiLetterOrDigit(value) && value != '-' {
				return false
			}
		}
	}
	return true
}

// asciiLetterOrDigit reports the frozen lowercase DNS-label alphabet.
func asciiLetterOrDigit(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

// validUsername proves one bounded application or auditor principal.
func validUsername(username string) bool {
	if len(username) < 1 || len(username) > 128 {
		return false
	}
	for index := range len(username) {
		value := username[index]
		if value >= 'A' && value <= 'Z' ||
			value >= 'a' && value <= 'z' ||
			value >= '0' && value <= '9' ||
			value == '.' || value == '_' || value == '-' {
			continue
		}
		return false
	}
	return true
}

// cloneAndValidateRoots validates exact bounded CA DER and retains owned copies.
func cloneAndValidateRoots(input [][]byte) ([][]byte, error) {
	if len(input) < 1 || len(input) > 128 {
		return nil, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	total := 0
	for _, der := range input {
		if len(der) < 1 || len(der) > 64*1024 || total > 256*1024-len(der) {
			return nil, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
		}
		total += len(der)
	}
	seen := make(map[string]struct{}, len(input))
	roots := make([][]byte, len(input))
	for index, der := range input {
		identity := string(der)
		if _, duplicate := seen[identity]; duplicate {
			return nil, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
		}
		seen[identity] = struct{}{}
		certificate, err := x509.ParseCertificate(der)
		if err != nil || !certificate.BasicConstraintsValid || !certificate.IsCA ||
			certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
		}
		roots[index] = append([]byte(nil), der...)
	}
	return roots, nil
}

// String returns one content-free client configuration representation.
func (ClientConfig) String() string { return clientConfigRedactedText }

// GoString returns one content-free client configuration representation.
func (ClientConfig) GoString() string { return clientConfigRedactedText }

// Format prevents formatting verbs from exposing client configuration.
func (ClientConfig) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, clientConfigRedactedText)
}

// MarshalJSON rejects serialization of protected client configuration.
func (ClientConfig) MarshalJSON() ([]byte, error) {
	return nil, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
}

// MarshalText rejects serialization of protected client configuration.
func (ClientConfig) MarshalText() ([]byte, error) {
	return nil, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
}

// String returns one content-free auditor configuration representation.
func (AuditorConfig) String() string { return auditorConfigRedactedText }

// GoString returns one content-free auditor configuration representation.
func (AuditorConfig) GoString() string { return auditorConfigRedactedText }

// Format prevents formatting verbs from exposing auditor credentials.
func (AuditorConfig) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, auditorConfigRedactedText)
}

// MarshalJSON rejects serialization of protected auditor credentials.
func (AuditorConfig) MarshalJSON() ([]byte, error) {
	return nil, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
}

// MarshalText rejects serialization of protected auditor credentials.
func (AuditorConfig) MarshalText() ([]byte, error) {
	return nil, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
}
