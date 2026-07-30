//go:build datasourceintegration

package migration

import (
	"context"
	"encoding/pem"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestDisposableMigrationBootstrapPublishers proves real absent-to-first
// publication fencing against digest-pinned LDAP and PostgreSQL services.
func TestDisposableMigrationBootstrapPublishers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	roots := integrationPublicationRoots(t)
	_, plan, imported := publicationFixture(t)
	plan.Generation = "1"
	plan.ExpectedCurrent = "0"
	candidate, err := BuildPublicationCandidate(plan, imported)
	if err != nil {
		t.Fatal("build bootstrap publication candidate")
	}
	defer clearCandidateRows(&candidate.rows)

	t.Run("ldap-pointerless-nonempty", func(t *testing.T) {
		publisher, closePublisher := integrationLDAPPublisher(
			t, ctx, roots, "ou=dkim2-corrupt,dc=integration,dc=test",
		)
		defer func() { _ = closePublisher() }()
		if current, err := publisher.Current(ctx); err == nil || current != 0 {
			t.Fatal("LDAP pointerless nonempty backend was accepted as empty")
		}
	})
	t.Run("ldap", func(t *testing.T) {
		first, closeFirst := integrationLDAPPublisher(
			t, ctx, roots, "ou=dkim2-empty,dc=integration,dc=test",
		)
		defer func() { _ = closeFirst() }()
		second, closeSecond := integrationLDAPPublisher(
			t, ctx, roots, "ou=dkim2-empty,dc=integration,dc=test",
		)
		defer func() { _ = closeSecond() }()
		assertConcurrentBootstrapWinner(t, ctx, first, second, candidate)
		current, err := first.Current(ctx)
		if err != nil || current != 1 {
			t.Fatal("LDAP bootstrap did not publish generation one")
		}
	})
	t.Run("postgresql-pointerless-nonempty", func(t *testing.T) {
		publisher, closePublisher := integrationPostgreSQLPublisher(
			t, ctx, roots, "dkim2_corrupt",
		)
		defer func() { _ = closePublisher() }()
		if current, err := publisher.Current(ctx); err == nil || current != 0 {
			t.Fatal("PostgreSQL pointerless nonempty backend was accepted as empty")
		}
	})
	t.Run("postgresql", func(t *testing.T) {
		first, closeFirst := integrationPostgreSQLPublisher(t, ctx, roots, "dkim2_empty")
		defer func() { _ = closeFirst() }()
		second, closeSecond := integrationPostgreSQLPublisher(t, ctx, roots, "dkim2_empty")
		defer func() { _ = closeSecond() }()
		assertConcurrentBootstrapWinner(t, ctx, first, second, candidate)
		current, err := first.Current(ctx)
		if err != nil || current != 1 {
			t.Fatal("PostgreSQL bootstrap did not publish generation one")
		}
	})
}

// assertConcurrentBootstrapWinner requires one and only one first publisher.
func assertConcurrentBootstrapWinner(
	t *testing.T,
	ctx context.Context,
	first Publisher,
	second Publisher,
	candidate PublicationCandidate,
) {
	t.Helper()
	for _, publisher := range []Publisher{first, second} {
		current, err := publisher.Current(ctx)
		if err != nil || current != 0 {
			t.Fatal("disposable backend was not provably empty")
		}
	}
	var successes atomic.Int32
	var wait sync.WaitGroup
	for _, publisher := range []Publisher{first, second} {
		current := publisher
		wait.Add(1)
		go func() {
			defer wait.Done()
			if current.Publish(ctx, 0, candidate) == nil {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("bootstrap winner count = %d, want 1", successes.Load())
	}
}

// integrationLDAPPublisher opens one disposable administrative publication connection.
func integrationLDAPPublisher(
	t *testing.T,
	ctx context.Context,
	roots [][]byte,
	baseDN string,
) (*LDAPPublisher, func() error) {
	t.Helper()
	port := os.Getenv("DKIM2_LDAP_PORT")
	if port == "" {
		t.Fatal("LDAP integration port unavailable")
	}
	publisher, closePublisher, err := NewLDAPPublisherClient(
		ctx,
		SourceConfig{
			Address:    net.JoinHostPort("127.0.0.1", port),
			ServerName: "ldap.integration.test", Transport: ldapTransportSecure,
			BindDN: "cn=admin,dc=integration,dc=test",
			BaseDN: baseDN, PageSize: 128,
		},
		[]byte("synthetic-ldap-admin-password"),
		roots,
	)
	if err != nil {
		t.Fatal("open LDAP bootstrap publisher")
	}
	return publisher, closePublisher
}

// integrationPostgreSQLPublisher opens one disposable least-authority connection.
func integrationPostgreSQLPublisher(
	t *testing.T,
	ctx context.Context,
	roots [][]byte,
	database string,
) (*PostgreSQLPublisher, func() error) {
	t.Helper()
	port := os.Getenv("DKIM2_POSTGRESQL_PORT")
	if port == "" {
		t.Fatal("PostgreSQL integration port unavailable")
	}
	publisher, closePublisher, err := NewPostgreSQLPublisherClient(
		ctx,
		PostgreSQLPublicationConfig{
			Address:    net.JoinHostPort("127.0.0.1", port),
			ServerName: "postgresql.integration.test",
			Database:   database, User: "dkim2_publisher_login",
			CAFile: "/protected/ca", PasswordFile: "/protected/password",
		},
		[]byte("synthetic-postgresql-publisher-password"),
		roots,
	)
	if err != nil {
		t.Fatal("open PostgreSQL bootstrap publisher")
	}
	return publisher, closePublisher
}

// integrationPublicationRoots decodes one invocation-owned CA certificate.
func integrationPublicationRoots(t *testing.T) [][]byte {
	t.Helper()
	document, err := os.ReadFile(os.Getenv("DKIM2_DATASOURCE_CA"))
	if err != nil {
		t.Fatal("read integration CA")
	}
	block, rest := pem.Decode(document)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("decode integration CA")
	}
	return [][]byte{append([]byte(nil), block.Bytes...)}
}
