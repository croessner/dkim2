package redisstore

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	dkim2 "github.com/croessner/dkim2"
	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/maintnotifications"
)

const syntheticPasswordMarker = "SYNTHETIC-REDIS-PASSWORD-MARKER"

// TestProviderValuesNeverRenderOrSerialize proves constant formatting and refused marshaling.
func TestProviderValuesNeverRenderOrSerialize(t *testing.T) {
	store := newTestStore(t, newFakeBackend())
	config := testConfig()
	config.StandaloneAddress = "10.9.8.7:6379"
	config.Username = "secret-user"
	secrets := Secrets{Password: []byte(syntheticPasswordMarker)}
	for name, value := range map[string]any{
		"store": store, "store value": *store, "config": config, "secrets": secrets,
	} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			rendered := fmt.Sprintf(format, value)
			for _, forbidden := range []string{"10.9.8.7", "secret-user", syntheticPasswordMarker, testKeyPrefix} {
				if strings.Contains(rendered, forbidden) {
					t.Fatalf("%s %s rendered %q", name, format, forbidden)
				}
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatalf("%s JSON serialization accepted", name)
		}
	}
}

// TestErrorsNeverCarryServerOrKeyDetail proves every mapped error is a bare taxonomy member.
func TestErrorsNeverCarryServerOrKeyDetail(t *testing.T) {
	fake := newFakeBackend()
	fake.reply = func([]any) *redis.Cmd {
		return redis.NewCmdResult(nil, syntheticServerError("ERR "+syntheticPasswordMarker+" 10.9.8.7:6379"))
	}
	store := newTestStore(t, fake)
	key, storage := testReplayKey(t, false)
	_, err := store.CheckAndRemember(context.Background(), key, testRetention(t))
	for _, forbidden := range []string{syntheticPasswordMarker, "10.9.8.7", storage, "dkim2:replay"} {
		if strings.Contains(err.Error(), forbidden) || strings.Contains(fmt.Sprintf("%+v", err), forbidden) {
			t.Fatalf("error leaked %q", forbidden)
		}
	}
	if !dkim2.IsReplayError(err) {
		t.Fatal("mapped error is not a direct taxonomy member")
	}
}

// TestProductionClientOptionsAreRestrictive proves the go-redis options for
// every topology: no client name, no CLIENT SETINFO, no maintenance
// notifications, context deadlines honoured, credentials only via the vault,
// and no replica or latency routing.
func TestProductionClientOptionsAreRestrictive(t *testing.T) {
	vault, err := newCredentialVault(testUsername, []byte(syntheticPasswordMarker))
	if err != nil {
		t.Fatal(err)
	}
	base := testConfig()
	base.MinIdleConnections = 0
	base.MaxAttempts = 1
	validated, err := validateConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	standalone := newProductionBackend(validated, vault, nil, nil, nil).(singleBackend)
	defer func() { _ = standalone.Close() }()
	requireRestrictiveOptions(t, standalone.client.Options())

	sentinelConfig := base
	sentinelConfig.Mode, sentinelConfig.StandaloneAddress = ModeSentinel, ""
	sentinelConfig.SentinelMasterName = testSentinelMaster
	sentinelConfig.SentinelAddresses = []string{testSentinelAddress}
	validated, err = validateConfig(sentinelConfig)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := newProductionBackend(validated, vault, nil, nil, nil).(singleBackend)
	defer func() { _ = sentinel.Close() }()
	if options := sentinel.client.Options(); options.Password != "" || options.ClientName != "" ||
		!options.DisableIdentity || !options.ContextTimeoutEnabled || options.CredentialsProviderContext == nil {
		t.Fatal("sentinel options are not restrictive")
	}

	clusterConfig := base
	clusterConfig.Mode, clusterConfig.StandaloneAddress = ModeCluster, ""
	clusterConfig.ClusterAddresses = []string{testClusterAddress}
	validated, err = validateConfig(clusterConfig)
	if err != nil {
		t.Fatal(err)
	}
	cluster := newProductionBackend(validated, vault, nil, nil, nil).(clusterBackend)
	defer func() { _ = cluster.Close() }()
	options := cluster.client.Options()
	if options.Password != "" || options.ClientName != "" || !options.DisableIdentity ||
		!options.ContextTimeoutEnabled || options.CredentialsProviderContext == nil ||
		options.ReadOnly || options.RouteByLatency || options.RouteRandomly || !options.DisableRoutingPolicies ||
		options.MaxRedirects != defaultClusterRedirects || options.MaxRetries != -1 ||
		options.MaintNotificationsConfig == nil || options.MaintNotificationsConfig.Mode != maintnotifications.ModeDisabled {
		t.Fatal("cluster options are not restrictive")
	}
}

// requireRestrictiveOptions checks one standalone option set. go-redis
// normalizes the configured MaxRetries of -1 (one attempt) to zero.
func requireRestrictiveOptions(t *testing.T, options *redis.Options) {
	t.Helper()
	if options.Password != "" || options.Username != "" || options.ClientName != "" || !options.DisableIdentity ||
		!options.ContextTimeoutEnabled || options.CredentialsProviderContext == nil || options.MaxRetries != 0 ||
		options.Protocol != 3 || options.MaintNotificationsConfig == nil ||
		options.MaintNotificationsConfig.Mode != maintnotifications.ModeDisabled ||
		options.ClientSideCache != nil || options.ClientSideCacheConfig != nil {
		t.Fatal("standalone options are not restrictive")
	}
	username, password, err := options.CredentialsProviderContext(context.Background())
	if err != nil || username != testUsername || password != syntheticPasswordMarker {
		t.Fatal("credentials provider does not read the vault")
	}
}

// TestSentinelFailoverOptionsPinMasterRoutingAndSentinelCredential proves the
// Sentinel options route only to the master, carry the configured Sentinel
// username and exactly the construction-time Sentinel password, and that the
// construction copy of that password is cleared once the client exists while
// the caller-owned secret is left untouched.
func TestSentinelFailoverOptionsPinMasterRoutingAndSentinelCredential(t *testing.T) {
	const sentinelUsername = "sentinel-user"
	const sentinelPassword = "SYNTHETIC-SENTINEL-PASSWORD"
	config := testConfig()
	config.MinIdleConnections = 0
	config.Mode, config.StandaloneAddress = ModeSentinel, ""
	config.SentinelMasterName = testSentinelMaster
	config.SentinelAddresses = []string{testSentinelAddress}
	config.SentinelUsername = sentinelUsername
	caller := []byte(sentinelPassword)
	var (
		options  *redis.FailoverOptions
		lentCopy []byte
	)
	fake := newFakeBackend()
	deps := fakeDependencies(fake)
	deps.newBackend = func(validated validatedConfig, vault *credentialVault, material *constructionMaterial) backend {
		lentCopy = material.sentinelPassword
		options = newFailoverOptions(validated, vault, material.config, material.sentinelPassword, nil)
		return fake
	}
	store, err := newStoreWithDependencies(context.Background(), config, Secrets{SentinelPassword: caller}, deps)
	if err != nil {
		t.Fatalf("construct sentinel store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	if options == nil || options.ReplicaOnly || options.RouteByLatency || options.RouteRandomly ||
		options.UseDisconnectedReplicas || !options.DisableIdentity || !options.ContextTimeoutEnabled ||
		options.ClientName != "" || options.Username != "" || options.Password != "" ||
		options.CredentialsProviderContext == nil || options.MasterName != testSentinelMaster {
		t.Fatal("sentinel failover options are not restrictive")
	}
	if options.SentinelUsername != sentinelUsername || options.SentinelPassword != sentinelPassword {
		t.Fatal("sentinel credential does not equal the construction material")
	}
	if len(lentCopy) != len(sentinelPassword) || strings.Trim(string(lentCopy), "\x00") != "" {
		t.Fatal("construction copy of the sentinel password was not cleared")
	}
	if string(caller) != sentinelPassword {
		t.Fatal("construction modified the caller-owned sentinel secret")
	}
}
