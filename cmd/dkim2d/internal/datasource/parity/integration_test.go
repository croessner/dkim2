//go:build datasourceintegration

package parity

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	datasourceldap "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/ldap"
	datasourcepostgresql "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/postgresql"
	datasourceruntime "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/runtime"
	"github.com/croessner/dkim2/provider"
)

type integrationRegistry struct {
	generation uint64
	bindings   []provider.Binding
}

// Load returns the exact synthetic protected registry requested by the loader.
func (r integrationRegistry) Load(
	_ context.Context,
	generation uint64,
) (datasourceruntime.Registry, error) {
	if generation != r.generation {
		return nil, errors.New("synthetic registry generation mismatch")
	}
	return r, nil
}

// Generation returns the exact synthetic protected-registry generation.
func (r integrationRegistry) Generation(context.Context) (uint64, error) {
	return r.generation, nil
}

// Bindings returns a detached copy of the synthetic registry bindings.
func (r integrationRegistry) Bindings() []provider.Binding {
	return append([]provider.Binding(nil), r.bindings...)
}

// Close completes the synthetic registry lifecycle.
func (integrationRegistry) Close(context.Context) error { return nil }

// SignDigest is unreachable because the integration qualification resolves but
// never signs with the synthetic public-only credential.
func (integrationRegistry) SignDigest(
	context.Context,
	dkim2.PrivateKeyHandle,
	dkim2.PrivateKeySignRequest,
) (dkim2.PrivateKeySignResult, error) {
	return dkim2.PrivateKeySignResult{}, dkim2.NewTemporaryProviderError()
}

// TestDisposableNetworkProviderParity qualifies both verified-TLS provider
// clients against invocation-owned services and one shared logical dataset.
func TestDisposableNetworkProviderParity(t *testing.T) {
	rootCAs := integrationRoots(t)
	registry := integrationRegistryValue(t)
	ldapLoader := integrationLDAPLoader(t, rootCAs, registry, integrationPassword(t, "DKIM2_LDAP_PASSWORD"))
	postgresqlLoader := integrationPostgreSQLLoader(
		t, rootCAs, registry, integrationPassword(t, "DKIM2_POSTGRESQL_PASSWORD"),
	)

	first := loadIntegrationCandidate(t, ldapLoader)
	second := loadIntegrationCandidate(t, postgresqlLoader)
	for name, candidate := range map[string]datasourceruntime.Candidate{
		"ldap": first, "postgresql": second,
	} {
		t.Run(name, func(t *testing.T) {
			if !candidate.Valid() || candidate.Dataset.Generation() != 1 {
				t.Fatal("provider returned an invalid generation")
			}
			resolver, err := candidate.Dataset.NewSigningResolver(
				candidate.Bindings, time.Now().UTC(),
			)
			if err != nil {
				t.Fatal("construct provider-neutral resolver")
			}
			defer func() {
				if err := resolver.Close(context.Background()); err != nil {
					t.Error("close provider-neutral resolver")
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			profile, err := resolver.ResolvePolicy(
				ctx, testTenant, testDomain, provider.ProfileUseOriginator,
				time.Now().UTC(),
			)
			if err != nil || !profile.Valid() {
				t.Fatal("resolve exact shared provider policy")
			}
		})
	}
}

// TestDisposableNetworkProviderDenials proves invalid authentication, invalid
// server identity, and caller cancellation fail closed without backend detail.
func TestDisposableNetworkProviderDenials(t *testing.T) {
	rootCAs := integrationRoots(t)
	registry := integrationRegistryValue(t)
	t.Run("ldap_authentication", func(t *testing.T) {
		loader := integrationLDAPLoader(t, rootCAs, registry, []byte("wrong-password"))
		requireUnavailableIntegrationLoad(t, loader)
	})
	t.Run("postgresql_authentication", func(t *testing.T) {
		loader := integrationPostgreSQLLoader(t, rootCAs, registry, []byte("wrong-password"))
		requireUnavailableIntegrationLoad(t, loader)
	})
	t.Run("ldap_server_identity", func(t *testing.T) {
		t.Setenv("DKIM2_LDAP_SERVER_NAME", "wrong.integration.test")
		loader := integrationLDAPLoader(
			t, rootCAs, registry, integrationPassword(t, "DKIM2_LDAP_PASSWORD"),
		)
		requireUnavailableIntegrationLoad(t, loader)
	})
	t.Run("postgresql_server_identity", func(t *testing.T) {
		t.Setenv("DKIM2_POSTGRESQL_SERVER_NAME", "wrong.integration.test")
		loader := integrationPostgreSQLLoader(
			t, rootCAs, registry, integrationPassword(t, "DKIM2_POSTGRESQL_PASSWORD"),
		)
		requireUnavailableIntegrationLoad(t, loader)
	})
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := integrationLDAPLoader(
			t, rootCAs, registry, integrationPassword(t, "DKIM2_LDAP_PASSWORD"),
		).Load(ctx); provider.ErrorCodeOf(err) != provider.ErrorCodeCancelled {
			t.Fatal("LDAP cancellation was not preserved")
		}
		if _, err := integrationPostgreSQLLoader(
			t, rootCAs, registry, integrationPassword(t, "DKIM2_POSTGRESQL_PASSWORD"),
		).Load(ctx); provider.ErrorCodeOf(err) != provider.ErrorCodeCancelled {
			t.Fatal("PostgreSQL cancellation was not preserved")
		}
	})
}

// integrationRoots loads the invocation-owned CA without widening trust.
func integrationRoots(t *testing.T) *x509.CertPool {
	t.Helper()
	content, err := os.ReadFile(integrationEnvironment(t, "DKIM2_DATASOURCE_CA"))
	if err != nil {
		t.Fatal("read integration CA")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(content) {
		t.Fatal("parse integration CA")
	}
	return pool
}

// integrationRegistryValue constructs the exact opaque registry binding shared
// by the two network providers.
func integrationRegistryValue(t *testing.T) integrationRegistry {
	t.Helper()
	spki, err := base64.StdEncoding.Strict().DecodeString(
		integrationEnvironment(t, "DKIM2_DATASOURCE_SPKI"),
	)
	if err != nil {
		t.Fatal("decode integration SPKI")
	}
	handle, err := dkim2.NewPrivateKeyHandle([]byte(testHandle))
	if err != nil {
		t.Fatal("construct integration handle")
	}
	binding, err := provider.NewBinding(
		testTenant, testDomain, provider.ProfileUseOriginator, testHandle,
		handle, provider.AlgorithmEd25519SHA256, sha256.Sum256(spki),
	)
	if err != nil {
		t.Fatal("construct integration binding")
	}
	return integrationRegistry{generation: 1, bindings: []provider.Binding{binding}}
}

// integrationLDAPLoader builds one verified-TLS, deadline-bounded LDAP loader.
func integrationLDAPLoader(
	t *testing.T,
	rootCAs *x509.CertPool,
	registry integrationRegistry,
	password []byte,
) *datasourceldap.Loader {
	t.Helper()
	connector, err := datasourceldap.NewGoLDAPConnector(datasourceldap.ConnectionConfig{
		Address:    integrationAddress(t, "DKIM2_LDAP_PORT"),
		ServerName: integrationEnvironment(t, "DKIM2_LDAP_SERVER_NAME"),
		BaseDN:     "ou=dkim2,dc=integration,dc=test",
		BindDN:     "cn=runtime,ou=services,dc=integration,dc=test",
		Password:   password, RootCAs: rootCAs,
	})
	if err != nil {
		t.Fatal("construct LDAP connector")
	}
	loader, err := datasourceldap.NewLoader(
		connector, registry, provider.DefaultLimits(), 1, 4<<20, 10*time.Second,
	)
	if err != nil {
		t.Fatal("construct LDAP loader")
	}
	return loader
}

// integrationPostgreSQLLoader builds one verified-TLS, repeatable-read loader.
func integrationPostgreSQLLoader(
	t *testing.T,
	rootCAs *x509.CertPool,
	registry integrationRegistry,
	password []byte,
) *datasourcepostgresql.Loader {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := datasourcepostgresql.OpenPool(ctx, datasourcepostgresql.ConnectionConfig{
		Address:    integrationAddress(t, "DKIM2_POSTGRESQL_PORT"),
		ServerName: integrationEnvironment(t, "DKIM2_POSTGRESQL_SERVER_NAME"),
		Database:   "dkim2", User: "dkim2_runtime_login", Password: password,
		RootCAs: rootCAs, ConnectTimeout: 5 * time.Second,
		MaxConnections: 2, IdleConnections: 0,
	})
	if err != nil {
		t.Fatal("construct PostgreSQL pool")
	}
	loader, err := datasourcepostgresql.NewLoader(
		pool, registry, provider.DefaultLimits(), 1, 4<<20, 10*time.Second,
	)
	if err != nil {
		pool.Close()
		t.Fatal("construct PostgreSQL loader")
	}
	t.Cleanup(loader.Close)
	return loader
}

// loadIntegrationCandidate loads one complete candidate with a finite deadline.
func loadIntegrationCandidate(
	t *testing.T,
	loader interface {
		Load(context.Context) (datasourceruntime.Candidate, error)
	},
) datasourceruntime.Candidate {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	candidate, err := loader.Load(ctx)
	if err != nil {
		t.Fatalf("load disposable provider: %v", provider.ErrorCodeOf(err))
	}
	return candidate
}

// requireUnavailableIntegrationLoad requires one content-free unavailable result.
func requireUnavailableIntegrationLoad(
	t *testing.T,
	loader interface {
		Load(context.Context) (datasourceruntime.Candidate, error)
	},
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	candidate, err := loader.Load(ctx)
	if candidate.Valid() || provider.ErrorCodeOf(err) != provider.ErrorCodeUnavailable {
		t.Fatal("denied provider load did not fail closed")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("raw context error escaped provider boundary")
	}
}

// integrationPassword detaches one synthetic password from the environment.
func integrationPassword(t *testing.T, name string) []byte {
	t.Helper()
	return []byte(integrationEnvironment(t, name))
}

// integrationAddress constructs one local single-authority endpoint.
func integrationAddress(t *testing.T, portName string) string {
	t.Helper()
	port := integrationEnvironment(t, portName)
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		t.Fatal("invalid integration port")
	}
	return "127.0.0.1:" + port
}

// integrationEnvironment requires one nonempty harness-owned scalar.
func integrationEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("missing integration environment %s", name)
	}
	return value
}
