package redisstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"sync"
	"time"

	dkim2 "github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/replay/redisgrammar"
)

const (
	configRedactedText  = "redis_replay_config"
	secretsRedactedText = "redis_replay_secrets"

	maximumSentinelAddresses   = redisgrammar.MaxSentinelAddresses
	maximumClusterAddresses    = redisgrammar.MaxClusterAddresses
	maximumSecretBytes         = 1024
	maximumPEMBytes            = redisgrammar.MaxClientPEMBytes
	maximumRootCertificates    = 128
	maximumRootCertificateDER  = 64 * 1024
	maximumRootCertificateSum  = 256 * 1024
	maximumDatabaseNumber      = 15
	maximumClusterRedirects    = 16
	maximumPoolSize            = 1024
	maximumAttempts            = 10
	maximumHealthThreshold     = 10
	minimumNetworkTimeout      = 100 * time.Millisecond
	maximumNetworkTimeout      = 30 * time.Second
	minimumPoolTimeout         = time.Millisecond
	maximumRetryBackoff        = 5 * time.Second
	minimumHealthInterval      = time.Second
	maximumHealthInterval      = 60 * time.Second
	minimumRetentionBound      = time.Second
	maximumRetentionBound      = 30 * 24 * time.Hour
	defaultClusterRedirects    = 8
	defaultPoolSize            = 20
	defaultMinIdleConnections  = 2
	defaultNetworkTimeout      = 2 * time.Second
	defaultMaxAttempts         = 3
	defaultMinRetryBackoff     = 50 * time.Millisecond
	defaultMaxRetryBackoff     = 500 * time.Millisecond
	defaultHealthInterval      = 5 * time.Second
	defaultHealthTimeout       = 2 * time.Second
	defaultHealthFailureCount  = 3
	defaultProtocol            = 3
	defaultLimitMaxEntries     = 65_536
	defaultLimitMaxWaiters     = 1024
	defaultLimitPruneBudget    = 4096
	defaultLimitMaxInFlight    = 1024
	defaultLimitAdmissionQueue = 1024
)

// Mode identifies one closed Redis-compatible deployment topology.
type Mode uint8

const (
	// ModeStandalone selects one directly addressed primary.
	ModeStandalone Mode = iota + 1
	// ModeSentinel selects the primary that Sentinel reports for one master name.
	ModeSentinel
	// ModeCluster selects a Redis Cluster addressed through seed nodes.
	ModeCluster
)

// TLSVersion identifies one closed minimum TLS protocol version.
type TLSVersion uint16

const (
	// TLSVersion12 requires at least TLS 1.2.
	TLSVersion12 TLSVersion = tls.VersionTLS12
	// TLSVersion13 requires TLS 1.3.
	TLSVersion13 TLSVersion = tls.VersionTLS13
)

// TLSConfig contains the non-secret transport security settings. Trust roots
// and the client certificate pair arrive through Secrets.
type TLSConfig struct {
	Enabled            bool
	ServerName         string
	MinVersion         TLSVersion
	InsecureSkipVerify bool
}

// HealthConfig contains the health-probe policy.
type HealthConfig struct {
	Interval         time.Duration
	Timeout          time.Duration
	FailureThreshold int
}

// Config is the plain, non-secret provider configuration that the daemon
// builds from its typed configuration. Every field is validated by Validate
// and again by NewStore; nothing in it is retained by reference.
type Config struct {
	Mode                Mode
	StandaloneAddress   string
	SentinelMasterName  string
	SentinelAddresses   []string
	SentinelUsername    string
	ClusterAddresses    []string
	ClusterMaxRedirects int
	Username            string
	DatabaseNumber      int
	KeyPrefix           string
	Protocol            int
	TLS                 TLSConfig
	PoolSize            int
	MinIdleConnections  int
	PoolTimeout         time.Duration
	DialTimeout         time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	MaxAttempts         int
	MinRetryBackoff     time.Duration
	MaxRetryBackoff     time.Duration
	Health              HealthConfig
	RequireNoEviction   bool
	MinimumRetention    time.Duration
	MaximumRetention    time.Duration
	Limits              dkim2.ReplayLimits
}

// DefaultConfig returns the documented defaults for one standalone primary
// at address. Callers override fields before calling NewStore.
func DefaultConfig(address string) Config {
	return Config{
		Mode:                ModeStandalone,
		StandaloneAddress:   address,
		ClusterMaxRedirects: defaultClusterRedirects,
		Protocol:            defaultProtocol,
		TLS:                 TLSConfig{Enabled: true, MinVersion: TLSVersion12},
		PoolSize:            defaultPoolSize,
		MinIdleConnections:  defaultMinIdleConnections,
		PoolTimeout:         defaultNetworkTimeout,
		DialTimeout:         defaultNetworkTimeout,
		ReadTimeout:         defaultNetworkTimeout,
		WriteTimeout:        defaultNetworkTimeout,
		MaxAttempts:         defaultMaxAttempts,
		MinRetryBackoff:     defaultMinRetryBackoff,
		MaxRetryBackoff:     defaultMaxRetryBackoff,
		Health: HealthConfig{
			Interval:         defaultHealthInterval,
			Timeout:          defaultHealthTimeout,
			FailureThreshold: defaultHealthFailureCount,
		},
		RequireNoEviction: true,
		MinimumRetention:  minimumRetentionBound,
		MaximumRetention:  maximumRetentionBound,
	}
}

// String returns one content-free configuration representation.
func (Config) String() string { return configRedactedText }

// GoString returns one content-free configuration representation.
func (Config) GoString() string { return configRedactedText }

// Format prevents formatting verbs from exposing addresses or names.
func (Config) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, configRedactedText) }

// MarshalText rejects serialization of provider configuration.
func (Config) MarshalText() ([]byte, error) {
	return nil, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
}

// MarshalJSON rejects serialization of provider configuration.
func (Config) MarshalJSON() ([]byte, error) {
	return nil, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
}

// Validate checks every non-secret invariant without touching the network.
// It returns a content-free misconfigured replay error on any violation.
func (c Config) Validate() error {
	_, err := validateConfig(c)
	return err
}

// Secrets carries protected material borrowed from the daemon's protected
// generation. NewStore copies what it needs; the caller keeps ownership of
// and clears its own slices.
type Secrets struct {
	Password             []byte
	SentinelPassword     []byte
	ClientCertificatePEM []byte
	ClientKeyPEM         []byte
	RootsDER             [][]byte
}

// String returns one content-free secrets representation.
func (Secrets) String() string { return secretsRedactedText }

// GoString returns one content-free secrets representation.
func (Secrets) GoString() string { return secretsRedactedText }

// Format prevents formatting verbs from exposing protected material.
func (Secrets) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, secretsRedactedText) }

// MarshalText rejects serialization of protected material.
func (Secrets) MarshalText() ([]byte, error) {
	return nil, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
}

// MarshalJSON rejects serialization of protected material.
func (Secrets) MarshalJSON() ([]byte, error) {
	return nil, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
}

// validatedConfig owns one proven, normalized, non-secret configuration.
type validatedConfig struct {
	mode                Mode
	addresses           []string
	sentinelMasterName  string
	sentinelAddresses   []string
	sentinelUsername    string
	clusterMaxRedirects int
	username            string
	databaseNumber      int
	keyPrefix           string
	protocol            int
	tls                 TLSConfig
	poolSize            int
	minIdleConnections  int
	poolTimeout         time.Duration
	dialTimeout         time.Duration
	readTimeout         time.Duration
	writeTimeout        time.Duration
	maxAttempts         int
	minRetryBackoff     time.Duration
	maxRetryBackoff     time.Duration
	health              HealthConfig
	requireNoEviction   bool
	minimumRetention    time.Duration
	maximumRetention    time.Duration
	limits              dkim2.ReplayLimits
}

// misconfigured returns the content-free construction refusal.
func misconfigured() error {
	return dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
}

// validateConfig proves every non-secret invariant and returns owned copies.
func validateConfig(c Config) (validatedConfig, error) { //nolint:gocyclo // One closed pass keeps every bound visible beside its rule.
	validated := validatedConfig{
		mode:                c.Mode,
		sentinelMasterName:  c.SentinelMasterName,
		sentinelUsername:    c.SentinelUsername,
		clusterMaxRedirects: c.ClusterMaxRedirects,
		username:            c.Username,
		databaseNumber:      c.DatabaseNumber,
		keyPrefix:           c.KeyPrefix,
		protocol:            c.Protocol,
		tls:                 c.TLS,
		poolSize:            c.PoolSize,
		minIdleConnections:  c.MinIdleConnections,
		poolTimeout:         c.PoolTimeout,
		dialTimeout:         c.DialTimeout,
		readTimeout:         c.ReadTimeout,
		writeTimeout:        c.WriteTimeout,
		maxAttempts:         c.MaxAttempts,
		minRetryBackoff:     c.MinRetryBackoff,
		maxRetryBackoff:     c.MaxRetryBackoff,
		health:              c.Health,
		requireNoEviction:   c.RequireNoEviction,
		minimumRetention:    c.MinimumRetention,
		maximumRetention:    c.MaximumRetention,
	}
	switch c.Mode {
	case ModeStandalone:
		if !redisgrammar.ValidAddress(c.StandaloneAddress) || len(c.SentinelAddresses) != 0 || len(c.ClusterAddresses) != 0 ||
			c.SentinelMasterName != "" || c.SentinelUsername != "" {
			return validatedConfig{}, misconfigured()
		}
		validated.addresses = []string{c.StandaloneAddress}
	case ModeSentinel:
		addresses, ok := validAddressList(c.SentinelAddresses, maximumSentinelAddresses)
		if !ok || c.StandaloneAddress != "" || len(c.ClusterAddresses) != 0 ||
			!redisgrammar.ValidMasterName(c.SentinelMasterName) ||
			c.SentinelUsername != "" && !redisgrammar.ValidUsername(c.SentinelUsername) {
			return validatedConfig{}, misconfigured()
		}
		validated.sentinelAddresses = addresses
	case ModeCluster:
		addresses, ok := validAddressList(c.ClusterAddresses, maximumClusterAddresses)
		if !ok || c.StandaloneAddress != "" || len(c.SentinelAddresses) != 0 ||
			c.SentinelMasterName != "" || c.SentinelUsername != "" || c.DatabaseNumber != 0 {
			return validatedConfig{}, misconfigured()
		}
		validated.addresses = addresses
	default:
		return validatedConfig{}, misconfigured()
	}
	if c.ClusterMaxRedirects < 1 || c.ClusterMaxRedirects > maximumClusterRedirects ||
		c.Username != "" && !redisgrammar.ValidUsername(c.Username) ||
		c.DatabaseNumber < 0 || c.DatabaseNumber > maximumDatabaseNumber ||
		!redisgrammar.ValidKeyPrefix(c.KeyPrefix) ||
		c.Protocol != 2 && c.Protocol != 3 ||
		!validTLSConfig(c.TLS) ||
		c.PoolSize < 1 || c.PoolSize > maximumPoolSize ||
		c.MinIdleConnections < 0 || c.MinIdleConnections > c.PoolSize ||
		c.PoolTimeout < minimumPoolTimeout || c.PoolTimeout > maximumNetworkTimeout ||
		!validNetworkTimeout(c.DialTimeout) || !validNetworkTimeout(c.ReadTimeout) ||
		!validNetworkTimeout(c.WriteTimeout) ||
		c.MaxAttempts < 1 || c.MaxAttempts > maximumAttempts ||
		c.MinRetryBackoff < 0 || c.MaxRetryBackoff < c.MinRetryBackoff ||
		c.MaxRetryBackoff > maximumRetryBackoff ||
		c.Health.Interval < minimumHealthInterval || c.Health.Interval > maximumHealthInterval ||
		c.Health.Timeout <= 0 || c.Health.Timeout >= c.Health.Interval ||
		c.Health.FailureThreshold < 1 || c.Health.FailureThreshold > maximumHealthThreshold ||
		c.MinimumRetention < minimumRetentionBound || c.MaximumRetention > maximumRetentionBound ||
		c.MinimumRetention > c.MaximumRetention {
		return validatedConfig{}, misconfigured()
	}
	limits, err := resolveAdmissionLimits(c.Limits)
	if err != nil {
		return validatedConfig{}, err
	}
	validated.limits = limits
	return validated, nil
}

// singleAttempt reports whether the client can dispatch one write at most
// once. Only then does a server error reply prove that the write never
// executed; the cluster client re-routes network failures independently of
// MaxRetries, so cluster mode never qualifies.
func (c validatedConfig) singleAttempt() bool {
	return c.maxAttempts == 1 && c.mode != ModeCluster
}

// clientMaxRetries encodes max_attempts in go-redis terms, where zero selects
// the library default and -1 disables retries.
func (c validatedConfig) clientMaxRetries() int {
	if c.maxAttempts <= 1 {
		return -1
	}
	return c.maxAttempts - 1
}

// resolveAdmissionLimits applies exact defaults and rejects widened admission caps.
func resolveAdmissionLimits(limits dkim2.ReplayLimits) (dkim2.ReplayLimits, error) {
	if limits.MaxEntries == 0 {
		limits.MaxEntries = defaultLimitMaxEntries
	}
	if limits.MaxWaiters == 0 {
		limits.MaxWaiters = defaultLimitMaxWaiters
	}
	if limits.PruneBudget == 0 {
		limits.PruneBudget = defaultLimitPruneBudget
	}
	if limits.MaxInFlight == 0 {
		limits.MaxInFlight = defaultLimitMaxInFlight
	}
	if limits.MaxAdmissionWaiters == 0 {
		limits.MaxAdmissionWaiters = defaultLimitAdmissionQueue
	}
	if err := limits.Validate(); err != nil {
		return dkim2.ReplayLimits{}, misconfigured()
	}
	return limits, nil
}

// validNetworkTimeout applies the shared dial, read, and write timeout bound.
func validNetworkTimeout(timeout time.Duration) bool {
	return timeout >= minimumNetworkTimeout && timeout <= maximumNetworkTimeout
}

// validTLSConfig enforces that TLS options are only meaningful when enabled.
func validTLSConfig(config TLSConfig) bool {
	if !config.Enabled {
		return config.ServerName == "" && config.MinVersion == 0 && !config.InsecureSkipVerify
	}
	if config.MinVersion != TLSVersion12 && config.MinVersion != TLSVersion13 {
		return false
	}
	return config.ServerName == "" || redisgrammar.ValidServerName(config.ServerName)
}

// validAddressList proves one bounded duplicate-free list under the shared
// grammar and returns an owned copy so the store never aliases caller state.
func validAddressList(addresses []string, maximum int) ([]string, bool) {
	if !redisgrammar.ValidAddressList(addresses, maximum) {
		return nil, false
	}
	return append([]string(nil), addresses...), true
}

// credentialVault owns the protected data-user password for the life of one
// store. go-redis asks for credentials on every dial through
// CredentialsProviderContext, so the password exists as a Go string only for
// the duration of one connection handshake; the vault itself keeps bytes
// that Close clears.
type credentialVault struct {
	mu       sync.Mutex
	username string
	password []byte
	closed   bool
}

// newCredentialVault validates and copies one optional username/password pair.
func newCredentialVault(username string, password []byte) (*credentialVault, error) {
	if len(password) > maximumSecretBytes || username != "" && len(password) == 0 {
		return nil, misconfigured()
	}
	return &credentialVault{username: username, password: append([]byte(nil), password...)}, nil
}

// provide returns the current credentials for one dial and fails after close.
func (v *credentialVault) provide(context.Context) (string, string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return "", "", dkim2.NewReplayError(dkim2.ReplayErrorClosed)
	}
	return v.username, string(v.password), nil
}

// clear best-effort clears the owned password and rejects later dials.
func (v *credentialVault) clear() {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	clear(v.password)
	v.password = nil
	v.closed = true
}

// validateSentinelPassword checks the optional Sentinel credential against
// the configured Sentinel username. go-redis accepts the Sentinel password
// only as a string option, which is the documented residual.
func validateSentinelPassword(config validatedConfig, password []byte) error {
	if len(password) > maximumSecretBytes ||
		config.mode != ModeSentinel && len(password) != 0 ||
		config.sentinelUsername != "" && len(password) == 0 {
		return misconfigured()
	}
	return nil
}

// buildTLSConfig validates protected trust and client-certificate material
// and returns one fresh client TLS policy, or nil when TLS is disabled.
func buildTLSConfig(config TLSConfig, secrets Secrets) (*tls.Config, error) {
	hasPair := len(secrets.ClientCertificatePEM) != 0 || len(secrets.ClientKeyPEM) != 0
	if !config.Enabled {
		if hasPair || len(secrets.RootsDER) != 0 {
			return nil, misconfigured()
		}
		return nil, nil
	}
	result := &tls.Config{
		MinVersion:         uint16(config.MinVersion),
		ServerName:         config.ServerName,
		InsecureSkipVerify: config.InsecureSkipVerify, //nolint:gosec // Explicit operator opt-in; the daemon warns at startup.
	}
	if len(secrets.RootsDER) != 0 {
		pool, err := rootPool(secrets.RootsDER)
		if err != nil {
			return nil, err
		}
		result.RootCAs = pool
	}
	if hasPair {
		if len(secrets.ClientCertificatePEM) == 0 || len(secrets.ClientKeyPEM) == 0 ||
			len(secrets.ClientCertificatePEM) > maximumPEMBytes || len(secrets.ClientKeyPEM) > maximumPEMBytes {
			return nil, misconfigured()
		}
		certificate, err := tls.X509KeyPair(secrets.ClientCertificatePEM, secrets.ClientKeyPEM)
		if err != nil {
			return nil, misconfigured()
		}
		result.Certificates = []tls.Certificate{certificate}
	}
	return result, nil
}

// rootPool validates bounded duplicate-free CA DER and builds a private pool.
func rootPool(roots [][]byte) (*x509.CertPool, error) {
	if len(roots) > maximumRootCertificates {
		return nil, misconfigured()
	}
	total := 0
	seen := make(map[string]struct{}, len(roots))
	pool := x509.NewCertPool()
	for _, der := range roots {
		if len(der) < 1 || len(der) > maximumRootCertificateDER || total > maximumRootCertificateSum-len(der) {
			return nil, misconfigured()
		}
		total += len(der)
		if _, duplicate := seen[string(der)]; duplicate {
			return nil, misconfigured()
		}
		seen[string(der)] = struct{}{}
		certificate, err := x509.ParseCertificate(append([]byte(nil), der...))
		if err != nil || !certificate.BasicConstraintsValid || !certificate.IsCA ||
			certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, misconfigured()
		}
		pool.AddCert(certificate)
	}
	return pool, nil
}
