package redisstore

import (
	"context"
	"crypto/tls"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/maintnotifications"
)

const maximumClusterPrimaries = 1024

// infoClient is the read-only seam one startup check uses on one primary.
type infoClient interface {
	Info(ctx context.Context, sections ...string) *redis.StringCmd
}

// backend is the narrow topology-neutral command seam the store uses. The
// scripting subset exists only because redis.Script.Run requires it; Do only
// ever receives the pinned argument vectors built in commands.go.
type backend interface {
	redis.Scripter
	Do(ctx context.Context, args ...any) *redis.Cmd
	// pingPrimaries sends PING to every primary of the topology.
	pingPrimaries(ctx context.Context) error
	// eachPrimary invokes inspect sequentially with a client bound to each primary.
	eachPrimary(ctx context.Context, inspect func(context.Context, infoClient) error) error
	Close() error
}

// discardClientLogger drops every go-redis internal log line. go-redis logs
// addresses and raw error text, which the daemon must never emit, so the
// provider routes the library logger to nothing and reports through its own
// content-free error taxonomy instead.
type discardClientLogger struct{}

// Printf discards one go-redis internal log line.
func (discardClientLogger) Printf(context.Context, string, ...any) {}

// init installs the discarding go-redis logger before any client exists.
// redis.SetLogger mutates a process-global inside go-redis that is read
// without synchronization by client goroutines, so it is set exactly once at
// package initialization instead of per store; the provider owns no other
// package-level mutable state.
func init() {
	redis.SetLogger(discardClientLogger{})
}

// singleBackend adapts one standalone or Sentinel-failover client.
type singleBackend struct {
	redis.Scripter
	client *redis.Client
}

// Do dispatches one pinned argument vector.
func (b singleBackend) Do(ctx context.Context, args ...any) *redis.Cmd {
	return b.client.Do(ctx, args...)
}

// pingPrimaries sends PING to the one addressed or Sentinel-reported primary.
func (b singleBackend) pingPrimaries(ctx context.Context) error {
	return b.client.Ping(ctx).Err()
}

// eachPrimary inspects the one addressed or Sentinel-reported primary.
func (b singleBackend) eachPrimary(ctx context.Context, inspect func(context.Context, infoClient) error) error {
	return inspect(ctx, b.client)
}

// Close releases the owned client and its pool.
func (b singleBackend) Close() error {
	return b.client.Close()
}

// clusterBackend adapts one cluster client.
type clusterBackend struct {
	redis.Scripter
	client *redis.ClusterClient
}

// Do dispatches one pinned argument vector through slot routing.
func (b clusterBackend) Do(ctx context.Context, args ...any) *redis.Cmd {
	return b.client.Do(ctx, args...)
}

// pingPrimaries sends PING to every current primary; any failure is one failure.
func (b clusterBackend) pingPrimaries(ctx context.Context) error {
	return b.client.ForEachMaster(ctx, func(ctx context.Context, primary *redis.Client) error {
		return primary.Ping(ctx).Err()
	})
}

// eachPrimary collects the current primary node clients without I/O inside
// the concurrent callback, orders them deterministically, and inspects them
// one after another so violation counts are reproducible.
func (b clusterBackend) eachPrimary(ctx context.Context, inspect func(context.Context, infoClient) error) error {
	var mu sync.Mutex
	primaries := make([]*redis.Client, 0, 8)
	overflow := false
	if err := b.client.ForEachMaster(ctx, func(_ context.Context, primary *redis.Client) error {
		mu.Lock()
		defer mu.Unlock()
		if len(primaries) >= maximumClusterPrimaries {
			overflow = true
			return nil
		}
		primaries = append(primaries, primary)
		return nil
	}); err != nil {
		return err
	}
	if overflow || len(primaries) == 0 {
		return misconfigured()
	}
	slices.SortFunc(primaries, func(left, right *redis.Client) int {
		return strings.Compare(left.Options().Addr, right.Options().Addr)
	})
	for _, primary := range primaries {
		if err := inspect(ctx, primary); err != nil {
			return err
		}
	}
	return nil
}

// Close releases the owned cluster client and every node pool.
func (b clusterBackend) Close() error {
	return b.client.Close()
}

// disabledMaintenanceNotifications returns a fresh config that keeps
// go-redis from enabling CLIENT MAINT_NOTIFICATIONS on any connection.
func disabledMaintenanceNotifications() *maintnotifications.Config {
	return &maintnotifications.Config{Mode: maintnotifications.ModeDisabled}
}

// cloneTLS returns an independent TLS policy for one client, or nil.
func cloneTLS(config *tls.Config) *tls.Config {
	if config == nil {
		return nil
	}
	return config.Clone()
}

// newProductionBackend constructs the concrete go-redis client for one
// validated topology. Client name and CLIENT SETINFO are disabled, replicas
// are never read, cluster routing policies (which would fetch COMMAND) are
// disabled, and credentials are produced by the vault on every dial.
//
// dial is nil in production, which selects the go-redis TCP dialer; tests
// inject an in-process transport to exercise the real client retry loop.
func newProductionBackend(
	config validatedConfig,
	vault *credentialVault,
	tlsConfig *tls.Config,
	sentinelPassword []byte,
	dial func(context.Context, string, string) (net.Conn, error),
) backend {
	switch config.mode {
	case ModeStandalone:
		client := redis.NewClient(&redis.Options{
			Addr:                       config.addresses[0],
			Dialer:                     dial,
			Protocol:                   config.protocol,
			CredentialsProviderContext: vault.provide,
			DB:                         config.databaseNumber,
			MaxRetries:                 config.clientMaxRetries(),
			MinRetryBackoff:            config.minRetryBackoff,
			MaxRetryBackoff:            config.maxRetryBackoff,
			DialTimeout:                config.dialTimeout,
			ReadTimeout:                config.readTimeout,
			WriteTimeout:               config.writeTimeout,
			ContextTimeoutEnabled:      true,
			PoolSize:                   config.poolSize,
			MinIdleConns:               config.minIdleConnections,
			PoolTimeout:                config.poolTimeout,
			TLSConfig:                  cloneTLS(tlsConfig),
			DisableIdentity:            true,
			MaintNotificationsConfig:   disabledMaintenanceNotifications(),
		})
		return singleBackend{Scripter: client, client: client}
	case ModeSentinel:
		client := redis.NewFailoverClient(newFailoverOptions(config, vault, tlsConfig, sentinelPassword, dial))
		return singleBackend{Scripter: client, client: client}
	default:
		client := redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:                      slices.Clone(config.addresses),
			Dialer:                     dial,
			MaxRedirects:               config.clusterMaxRedirects,
			ReadOnly:                   false,
			RouteByLatency:             false,
			RouteRandomly:              false,
			Protocol:                   config.protocol,
			CredentialsProviderContext: vault.provide,
			MaxRetries:                 config.clientMaxRetries(),
			MinRetryBackoff:            config.minRetryBackoff,
			MaxRetryBackoff:            config.maxRetryBackoff,
			DialTimeout:                config.dialTimeout,
			ReadTimeout:                config.readTimeout,
			WriteTimeout:               config.writeTimeout,
			ContextTimeoutEnabled:      true,
			PoolSize:                   config.poolSize,
			MinIdleConns:               config.minIdleConnections,
			PoolTimeout:                config.poolTimeout,
			TLSConfig:                  cloneTLS(tlsConfig),
			DisableRoutingPolicies:     true,
			DisableIdentity:            true,
			MaintNotificationsConfig:   disabledMaintenanceNotifications(),
		})
		return clusterBackend{Scripter: client, client: client}
	}
}

// newFailoverOptions builds the Sentinel client options: the master is the
// only routing target (no replica, latency, random, or disconnected-replica
// routing), the data credentials come from the vault on every dial, and the
// Sentinel password is copied into an immutable string, which is the
// documented residual; the caller clears its byte copy afterwards.
func newFailoverOptions(
	config validatedConfig,
	vault *credentialVault,
	tlsConfig *tls.Config,
	sentinelPassword []byte,
	dial func(context.Context, string, string) (net.Conn, error),
) *redis.FailoverOptions {
	return &redis.FailoverOptions{
		MasterName:                 config.sentinelMasterName,
		Dialer:                     dial,
		SentinelAddrs:              slices.Clone(config.sentinelAddresses),
		SentinelUsername:           config.sentinelUsername,
		SentinelPassword:           string(sentinelPassword),
		ReplicaOnly:                false,
		RouteByLatency:             false,
		RouteRandomly:              false,
		UseDisconnectedReplicas:    false,
		Protocol:                   config.protocol,
		CredentialsProviderContext: vault.provide,
		DB:                         config.databaseNumber,
		MaxRetries:                 config.clientMaxRetries(),
		MinRetryBackoff:            config.minRetryBackoff,
		MaxRetryBackoff:            config.maxRetryBackoff,
		DialTimeout:                config.dialTimeout,
		ReadTimeout:                config.readTimeout,
		WriteTimeout:               config.writeTimeout,
		ContextTimeoutEnabled:      true,
		PoolSize:                   config.poolSize,
		MinIdleConns:               config.minIdleConnections,
		PoolTimeout:                config.poolTimeout,
		TLSConfig:                  cloneTLS(tlsConfig),
		DisableIdentity:            true,
	}
}
