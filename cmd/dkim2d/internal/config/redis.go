package config

import (
	"crypto/tls"
	"strings"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/replay/redisgrammar"
)

const (
	// redisPathPrefix is the YAML subtree of the Redis-compatible provider.
	redisPathPrefix = "replay.redis."
	// maxRedisSentinelAddresses bounds the comma-separated Sentinel list.
	maxRedisSentinelAddresses = redisgrammar.MaxSentinelAddresses
	// maxRedisClusterAddresses bounds the comma-separated cluster seed list.
	maxRedisClusterAddresses = redisgrammar.MaxClusterAddresses
)

// RedisMode identifies one closed Redis deployment topology.
type RedisMode uint8

const (
	// RedisStandalone addresses one directly reachable server.
	RedisStandalone RedisMode = iota + 1
	// RedisSentinel resolves the current master through Sentinel.
	RedisSentinel
	// RedisCluster addresses a Redis Cluster through seed nodes.
	RedisCluster
)

// Label returns the fixed low-cardinality schema spelling of the topology.
func (m RedisMode) Label() string {
	switch m {
	case RedisStandalone:
		return valueRedisStandalone
	case RedisSentinel:
		return valueRedisSentinel
	case RedisCluster:
		return valueRedisCluster
	default:
		return ""
	}
}

// redisState is the validated replay.redis subtree. Address lists are parsed
// exactly once; accessors hand out clones.
type redisState struct {
	mode                  RedisMode
	standaloneAddress     string
	sentinelMasterName    string
	sentinelAddresses     []string
	sentinelUsername      string
	sentinelPasswordFile  string
	clusterAddresses      []string
	clusterMaxRedirects   uint8
	username              string
	passwordFile          string
	databaseNumber        uint8
	keyPrefix             string
	protocol              uint8
	tlsEnabled            bool
	tlsCAFile             string
	tlsCertificateFile    string
	tlsKeyFile            string
	tlsServerName         string
	tlsMinVersion         uint16
	tlsInsecureSkipVerify bool
	poolSize              uint16
	minIdleConnections    uint16
	poolTimeout           time.Duration
	dialTimeout           time.Duration
	readTimeout           time.Duration
	writeTimeout          time.Duration
	retryMaxAttempts      uint8
	retryMinBackoff       time.Duration
	retryMaxBackoff       time.Duration
	healthInterval        time.Duration
	healthTimeout         time.Duration
	healthFailures        uint8
	requireNoEviction     bool
}

// protectedPaths returns every configured protected Redis path in a fixed
// order. Optional paths that are not configured are omitted.
func (s redisState) protectedPaths() []string {
	paths := make([]string, 0, 5)
	for _, path := range []string{
		s.passwordFile, s.sentinelPasswordFile, s.tlsCAFile, s.tlsCertificateFile, s.tlsKeyFile,
	} {
		if path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}

// validateRedisMatrix enforces the mode-dependent presence rules of the
// replay.redis subtree before typed parsing. Required and forbidden keys are
// judged by explicit operator presence, never by defaults.
func validateRedisMatrix(presence map[string]Presence, values map[string]rawValue) error {
	explicit := func(path string) bool { return presence[path].Explicit() }
	var required []string
	var forbidden []string
	switch text(values, pathRedisMode) {
	case valueRedisStandalone:
		required = []string{pathRedisStandaloneAddress}
		forbidden = []string{redisPathPrefix + "sentinel.", redisPathPrefix + "cluster."}
	case valueRedisSentinel:
		required = []string{pathRedisSentinelMasterName, pathRedisSentinelAddresses}
		forbidden = []string{redisPathPrefix + "standalone.", redisPathPrefix + "cluster."}
	case valueRedisCluster:
		required = []string{pathRedisClusterAddresses}
		forbidden = []string{redisPathPrefix + "standalone.", redisPathPrefix + "sentinel."}
	default:
		return newError(CodeInvalidField)
	}
	if !requiredExplicit(presence, required...) {
		return newError(CodeInvalidMatrix)
	}
	for _, prefix := range forbidden {
		if explicitPrefix(presence, prefix) {
			return newError(CodeInvalidMatrix)
		}
	}
	if explicit(pathRedisAuthUsername) && !explicit(pathRedisAuthPasswordFile) ||
		explicit(pathRedisSentinelUsername) && !explicit(pathRedisSentinelPasswordFile) ||
		explicit(pathRedisTLSCertificate) != explicit(pathRedisTLSKey) {
		return newError(CodeInvalidMatrix)
	}
	tlsEnabled, err := boolValue(values, pathRedisTLSEnabled)
	if err != nil {
		return err
	}
	if !tlsEnabled {
		for path, source := range presence {
			if strings.HasPrefix(path, redisPathPrefix+"tls.") && path != pathRedisTLSEnabled && source.Explicit() {
				return newError(CodeInvalidMatrix)
			}
		}
	}
	return nil
}

// parseRedis validates the typed replay.redis subtree. The common protected
// paths (capability and replay HMAC) take part in the same-generation and
// distinct-path proof together with every configured Redis secret path.
//
//nolint:gocyclo // The closed per-field Redis schema is intentionally explicit.
func parseRedis(values map[string]rawValue, generation string, commonPaths ...string) (redisState, error) {
	var result redisState
	switch text(values, pathRedisMode) {
	case valueRedisStandalone:
		result.mode = RedisStandalone
		result.standaloneAddress = text(values, pathRedisStandaloneAddress)
		if !validRedisAddress(result.standaloneAddress) {
			return redisState{}, newError(CodeInvalidField)
		}
	case valueRedisSentinel:
		result.mode = RedisSentinel
		result.sentinelMasterName = text(values, pathRedisSentinelMasterName)
		if !validRedisMasterName(result.sentinelMasterName) {
			return redisState{}, newError(CodeInvalidField)
		}
		addresses, err := parseRedisAddressList(text(values, pathRedisSentinelAddresses), maxRedisSentinelAddresses)
		if err != nil {
			return redisState{}, err
		}
		result.sentinelAddresses = addresses
		result.sentinelUsername = text(values, pathRedisSentinelUsername)
		result.sentinelPasswordFile = text(values, pathRedisSentinelPasswordFile)
	case valueRedisCluster:
		result.mode = RedisCluster
		addresses, err := parseRedisAddressList(text(values, pathRedisClusterAddresses), maxRedisClusterAddresses)
		if err != nil {
			return redisState{}, err
		}
		result.clusterAddresses = addresses
	default:
		return redisState{}, newError(CodeInvalidField)
	}
	redirects, err := uintValue(values, pathRedisClusterMaxRedirects, 1, 16)
	if err != nil {
		return redisState{}, err
	}
	result.clusterMaxRedirects = uint8(redirects)
	result.username = text(values, pathRedisAuthUsername)
	result.passwordFile = text(values, pathRedisAuthPasswordFile)
	if result.username != "" && !validRedisUsername(result.username) ||
		result.sentinelUsername != "" && !validRedisUsername(result.sentinelUsername) {
		return redisState{}, newError(CodeInvalidField)
	}
	database, err := uintValue(values, pathRedisDatabaseNumber, 0, 15)
	if err != nil || result.mode == RedisCluster && database != 0 {
		return redisState{}, newError(CodeInvalidField)
	}
	result.databaseNumber = uint8(database)
	result.keyPrefix = text(values, pathRedisKeyPrefix)
	if !validRedisKeyPrefix(result.keyPrefix) {
		return redisState{}, newError(CodeInvalidField)
	}
	protocol, err := uintValue(values, pathRedisProtocol, 2, 3)
	if err != nil {
		return redisState{}, err
	}
	result.protocol = uint8(protocol)
	if err := parseRedisTLS(values, &result); err != nil {
		return redisState{}, err
	}
	if err := parseRedisPool(values, &result); err != nil {
		return redisState{}, err
	}
	if err := parseRedisRetriesAndHealth(values, &result); err != nil {
		return redisState{}, err
	}
	paths := append(append([]string(nil), commonPaths...), result.protectedPaths()...)
	if !sameGenerationPaths(generation, paths...) || !allDistinct(paths) {
		return redisState{}, newError(CodeInvalidField)
	}
	return result, nil
}

// parseRedisTLS validates the client TLS selection. A disabled TLS
// configuration carries no trust, identity, or verification settings; the
// matrix already refused explicit ones.
func parseRedisTLS(values map[string]rawValue, result *redisState) error {
	enabled, err := boolValue(values, pathRedisTLSEnabled)
	if err != nil {
		return err
	}
	insecure, err := boolValue(values, pathRedisTLSInsecureSkipVerify)
	if err != nil {
		return err
	}
	if !enabled {
		if insecure {
			return newError(CodeInvalidField)
		}
		return nil
	}
	switch text(values, pathRedisTLSMinVersion) {
	case valueTLS12:
		result.tlsMinVersion = tls.VersionTLS12
	case valueTLS13:
		result.tlsMinVersion = tls.VersionTLS13
	default:
		return newError(CodeInvalidField)
	}
	serverName := text(values, pathRedisTLSServerName)
	if serverName != "" && !validRedisServerName(serverName) {
		return newError(CodeInvalidField)
	}
	result.tlsEnabled = true
	result.tlsInsecureSkipVerify = insecure
	result.tlsServerName = serverName
	result.tlsCAFile = text(values, pathRedisTLSCAFile)
	result.tlsCertificateFile = text(values, pathRedisTLSCertificate)
	result.tlsKeyFile = text(values, pathRedisTLSKey)
	if (result.tlsCertificateFile == "") != (result.tlsKeyFile == "") {
		return newError(CodeInvalidField)
	}
	return nil
}

// parseRedisPool validates connection-pool sizing and per-operation timeouts.
func parseRedisPool(values map[string]rawValue, result *redisState) error {
	poolSize, err := uintValue(values, pathRedisPoolSize, 1, 1024)
	if err != nil {
		return err
	}
	minIdle, err := uintValue(values, pathRedisMinIdleConnections, 0, 1024)
	if err != nil || minIdle > poolSize {
		return newError(CodeInvalidField)
	}
	poolTimeout, err := durationValue(values, pathRedisPoolTimeout, time.Millisecond, 30*time.Second, false)
	if err != nil {
		return err
	}
	dialTimeout, err := durationValue(values, pathRedisDialTimeout, 100*time.Millisecond, 30*time.Second, false)
	if err != nil {
		return err
	}
	readTimeout, err := durationValue(values, pathRedisReadTimeout, 100*time.Millisecond, 30*time.Second, false)
	if err != nil {
		return err
	}
	writeTimeout, err := durationValue(values, pathRedisWriteTimeout, 100*time.Millisecond, 30*time.Second, false)
	if err != nil {
		return err
	}
	result.poolSize = uint16(poolSize)
	result.minIdleConnections = uint16(minIdle)
	result.poolTimeout = poolTimeout
	result.dialTimeout = dialTimeout
	result.readTimeout = readTimeout
	result.writeTimeout = writeTimeout
	return nil
}

// parseRedisRetriesAndHealth validates the bounded retry budget, the health
// probe cadence, and the eviction-policy requirement. The probe timeout must
// be strictly shorter than its start-to-start interval.
func parseRedisRetriesAndHealth(values map[string]rawValue, result *redisState) error {
	attempts, err := uintValue(values, pathRedisRetriesMaxAttempts, 1, 10)
	if err != nil {
		return err
	}
	minBackoff, err := durationValue(values, pathRedisRetriesMinBackoff, time.Millisecond, 5*time.Second, false)
	if err != nil {
		return err
	}
	maxBackoff, err := durationValue(values, pathRedisRetriesMaxBackoff, time.Millisecond, 5*time.Second, false)
	if err != nil || minBackoff > maxBackoff {
		return newError(CodeInvalidField)
	}
	interval, err := durationValue(values, pathRedisHealthInterval, time.Second, time.Minute, false)
	if err != nil {
		return err
	}
	timeout, err := durationValue(values, pathRedisHealthTimeout, 100*time.Millisecond, time.Minute, false)
	if err != nil || timeout >= interval {
		return newError(CodeInvalidField)
	}
	failures, err := uintValue(values, pathRedisHealthFailureThreshold, 1, 10)
	if err != nil {
		return err
	}
	requireNoEviction, err := boolValue(values, pathRedisRequireNoEviction)
	if err != nil {
		return err
	}
	result.retryMaxAttempts = uint8(attempts)
	result.retryMinBackoff = minBackoff
	result.retryMaxBackoff = maxBackoff
	result.healthInterval = interval
	result.healthTimeout = timeout
	result.healthFailures = uint8(failures)
	result.requireNoEviction = requireNoEviction
	return nil
}

// parseRedisAddressList splits one comma-separated host:port list, trims
// each element, and admits it only under the shared provider grammar, so the
// list a configuration loads with is exactly the list the provider accepts.
func parseRedisAddressList(value string, maximum int) ([]string, error) {
	if strings.TrimSpace(value) == "" || strings.Count(value, ",")+1 > maximum {
		return nil, newError(CodeInvalidField)
	}
	parts := strings.Split(value, ",")
	addresses := make([]string, 0, len(parts))
	for _, part := range parts {
		addresses = append(addresses, strings.TrimSpace(part))
	}
	if !redisgrammar.ValidAddressList(addresses, maximum) {
		return nil, newError(CodeInvalidField)
	}
	return addresses, nil
}

// validRedisAddress delegates one host:port element to the shared grammar.
func validRedisAddress(value string) bool { return redisgrammar.ValidAddress(value) }

// validRedisServerName delegates the TLS verification identity to the shared grammar.
func validRedisServerName(value string) bool { return redisgrammar.ValidServerName(value) }

// validRedisUsername delegates one ACL user name to the shared grammar.
func validRedisUsername(value string) bool { return redisgrammar.ValidUsername(value) }

// validRedisMasterName delegates one Sentinel master name to the shared grammar.
func validRedisMasterName(value string) bool { return redisgrammar.ValidMasterName(value) }

// validRedisKeyPrefix delegates the operator key prefix to the shared grammar.
func validRedisKeyPrefix(value string) bool { return redisgrammar.ValidKeyPrefix(value) }
