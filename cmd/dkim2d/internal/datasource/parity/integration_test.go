//go:build datasourceintegration

package parity

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	datasourceldap "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/ldap"
	datasourcepostgresql "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/postgresql"
	datasourceruntime "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/runtime"
	"github.com/croessner/dkim2/provider"
)

// TestDisposableNetworkProviderParity qualifies both verified-TLS provider
// clients against invocation-owned services and one shared logical dataset.
func TestDisposableNetworkProviderParity(t *testing.T) {
	rootCAs := integrationRoots(t)
	ldapLoader := integrationLDAPLoader(t, rootCAs, integrationPassword(t, "DKIM2_LDAP_PASSWORD"))
	postgresqlLoader := integrationPostgreSQLLoader(
		t, rootCAs, integrationPassword(t, "DKIM2_POSTGRESQL_PASSWORD"),
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
	t.Run("ldap_authentication", func(t *testing.T) {
		loader := integrationLDAPLoader(t, rootCAs, []byte("wrong-password"))
		requireUnavailableIntegrationLoad(t, loader)
	})
	t.Run("postgresql_authentication", func(t *testing.T) {
		loader := integrationPostgreSQLLoader(t, rootCAs, []byte("wrong-password"))
		requireUnavailableIntegrationLoad(t, loader)
	})
	t.Run("ldap_server_identity", func(t *testing.T) {
		t.Setenv("DKIM2_LDAP_SERVER_NAME", "wrong.integration.test")
		loader := integrationLDAPLoader(
			t, rootCAs, integrationPassword(t, "DKIM2_LDAP_PASSWORD"),
		)
		requireUnavailableIntegrationLoad(t, loader)
	})
	t.Run("postgresql_server_identity", func(t *testing.T) {
		t.Setenv("DKIM2_POSTGRESQL_SERVER_NAME", "wrong.integration.test")
		loader := integrationPostgreSQLLoader(
			t, rootCAs, integrationPassword(t, "DKIM2_POSTGRESQL_PASSWORD"),
		)
		requireUnavailableIntegrationLoad(t, loader)
	})
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := integrationLDAPLoader(
			t, rootCAs, integrationPassword(t, "DKIM2_LDAP_PASSWORD"),
		).Load(ctx); provider.ErrorCodeOf(err) != provider.ErrorCodeCancelled {
			t.Fatal("LDAP cancellation was not preserved")
		}
		if _, err := integrationPostgreSQLLoader(
			t, rootCAs, integrationPassword(t, "DKIM2_POSTGRESQL_PASSWORD"),
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

// integrationLDAPLoader builds one verified-TLS, deadline-bounded LDAP loader.
func integrationLDAPLoader(
	t *testing.T,
	rootCAs *x509.CertPool,
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
		connector, provider.DefaultLimits(), 1, 4<<20, 10*time.Second,
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
		pool, provider.DefaultLimits(), 1, 4<<20, 10*time.Second,
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
