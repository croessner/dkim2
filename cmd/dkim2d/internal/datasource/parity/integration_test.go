//go:build datasourceintegration

package parity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	datasourceldap "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/ldap"
	datasourcemysql "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/mysql"
	datasourcepostgresql "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/postgresql"
	datasourceruntime "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/runtime"
	"github.com/croessner/dkim2/provider"
)

type disposableEd25519PublicKeys struct {
	key               ed25519.PublicKey
	lookups           atomic.Int64
	domainMismatch    atomic.Int64
	selectorMismatch  atomic.Int64
	algorithmMismatch atomic.Int64
}

// LookupPublicKey returns only the invocation-owned exact Ed25519 key.
func (p *disposableEd25519PublicKeys) LookupPublicKey(
	_ context.Context,
	query dkim2.PublicKeyQuery,
) (dkim2.PublicKeyResult, error) {
	p.lookups.Add(1)
	if query.SigningDomain() != testDomain {
		p.domainMismatch.Add(1)
	}
	if query.Selector() != testSelector {
		p.selectorMismatch.Add(1)
	}
	if query.Algorithm() != dkim2.AlgorithmEd25519SHA256 {
		p.algorithmMismatch.Add(1)
	}
	if query.SigningDomain() != testDomain || query.Selector() != testSelector ||
		query.Algorithm() != dkim2.AlgorithmEd25519SHA256 {
		return dkim2.MissingPublicKey(query.Algorithm()), nil
	}
	return dkim2.FoundEd25519PublicKey(p.key), nil
}

// TestDisposableNetworkProviderParity qualifies both verified-TLS provider
// clients against invocation-owned services and one shared logical dataset.
func TestDisposableNetworkProviderParity(t *testing.T) {
	rootCAs := integrationRoots(t)
	ldapLoader := integrationLDAPLoader(t, rootCAs, integrationPassword(t, "DKIM2_LDAP_PASSWORD"))
	postgresqlLoader := integrationPostgreSQLLoader(
		t, rootCAs, integrationPassword(t, "DKIM2_POSTGRESQL_PASSWORD"),
	)
	mysqlLoader := integrationMySQLLoader(
		t, rootCAs, "DKIM2_MYSQL_PORT", "DKIM2_MYSQL_SERVER_NAME",
		integrationPassword(t, "DKIM2_MYSQL_PASSWORD"),
	)
	mariaDBLoader := integrationMySQLLoader(
		t, rootCAs, "DKIM2_MARIADB_PORT", "DKIM2_MARIADB_SERVER_NAME",
		integrationPassword(t, "DKIM2_MARIADB_PASSWORD"),
	)

	first := loadIntegrationCandidate(t, ldapLoader)
	second := loadIntegrationCandidate(t, postgresqlLoader)
	third := loadIntegrationCandidate(t, mysqlLoader)
	fourth := loadIntegrationCandidate(t, mariaDBLoader)
	sqlGeneration := uint64(1)
	if configured := os.Getenv("DKIM2_SQL_EXPECTED_GENERATION"); configured != "" {
		parsed, err := strconv.ParseUint(configured, 10, 64)
		if err != nil || parsed == 0 {
			t.Fatal("invalid expected SQL integration generation")
		}
		sqlGeneration = parsed
	}
	for name, candidate := range map[string]datasourceruntime.Candidate{
		"ldap": first, "postgresql": second, "mysql": third, "mariadb": fourth,
	} {
		t.Run(name, func(t *testing.T) {
			expectedGeneration := sqlGeneration
			if name == "ldap" {
				expectedGeneration = 1
			}
			if !candidate.Valid() || candidate.Dataset.Generation() != expectedGeneration {
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

// TestDisposableNetworkRuntimeSigning loads every current provider generation
// through the real runtime, proves readiness, signs, and verifies one message.
func TestDisposableNetworkRuntimeSigning(t *testing.T) {
	rootCAs := integrationRoots(t)
	loaders := map[string]datasourceruntime.Loader{
		"ldap": integrationLDAPLoader(t, rootCAs, integrationPassword(t, "DKIM2_LDAP_PASSWORD")),
		"postgresql": integrationPostgreSQLLoader(
			t, rootCAs, integrationPassword(t, "DKIM2_POSTGRESQL_PASSWORD"),
		),
		"mysql": integrationMySQLLoader(
			t, rootCAs, "DKIM2_MYSQL_PORT", "DKIM2_MYSQL_SERVER_NAME",
			integrationPassword(t, "DKIM2_MYSQL_PASSWORD"),
		),
		"mariadb": integrationMySQLLoader(
			t, rootCAs, "DKIM2_MARIADB_PORT", "DKIM2_MARIADB_SERVER_NAME",
			integrationPassword(t, "DKIM2_MARIADB_PASSWORD"),
		),
	}
	publicKeys := disposableIntegrationPublicKeys(t)
	for name, loader := range loaders {
		current := loader
		t.Run(name, func(t *testing.T) {
			proveDisposableRuntimeSignature(t, current, publicKeys)
		})
	}
	observed, ok := publicKeys.(*disposableEd25519PublicKeys)
	if !ok || observed.lookups.Load() != 12 ||
		observed.domainMismatch.Load() != 0 ||
		observed.selectorMismatch.Load() != 0 ||
		observed.algorithmMismatch.Load() != 0 {
		t.Fatal("disposable public-key lookup observations were not exact")
	}
}

// proveDisposableRuntimeSignature requires one ready leased current generation
// and a complete originator signature that passes current verification.
func proveDisposableRuntimeSignature(
	t *testing.T,
	loader datasourceruntime.Loader,
	publicKeys dkim2.PublicKeyProvider,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	runtime, err := datasourceruntime.New(ctx, loader, 10*time.Second)
	cancel()
	if err != nil || !runtime.Ready() {
		t.Fatal("disposable datasource runtime is not ready")
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		if closeErr := runtime.Close(closeCtx); closeErr != nil {
			t.Error("close disposable datasource runtime")
		}
	}()
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	lease, err := runtime.Acquire(ctx)
	cancel()
	if err != nil {
		t.Fatal("acquire disposable runtime lease")
	}
	dataset, generation, err := lease.Dataset()
	if err != nil || dataset == nil || generation == 0 || generation != dataset.Generation() {
		lease.Release()
		t.Fatal("runtime lease generation is incoherent")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	profile, err := lease.ResolvePolicy(
		ctx, testTenant, testDomain, provider.ProfileUseOriginator, time.Now().UTC(),
	)
	cancel()
	if err != nil || !profile.Valid() {
		lease.Release()
		t.Fatal("runtime lease did not resolve the current policy")
	}
	raw := []byte("From: sender@example.test\r\nTo: recipient@example.net\r\nSubject: disposable runtime\r\n\r\nbody\r\n")
	reverse := []byte("<sender@example.test>")
	recipients := [][]byte{[]byte("<recipient@example.net>")}
	proveDisposableDirectSignature(
		t, lease, publicKeys, profile, raw, reverse, recipients,
	)
	lease.Release()
	service, err := app.NewDatasourceSigningService(publicKeys, runtime, false)
	if err != nil {
		t.Fatal("construct disposable datasource signing service")
	}
	request, err := app.NewOperationRequest(
		app.OperationSign, raw, reverse, recipients, testTenant, testDomain,
		app.FidelityRawRFC5322,
	)
	if err != nil {
		t.Fatal("construct disposable runtime signing request")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	assessment, err := service.Sign(ctx, request)
	cancel()
	result, ok := assessment.Result()
	if err != nil || !assessment.Applicable() || !ok || !result.Valid() ||
		result.Result() != app.OperationPass || result.Disposition() != app.OperationAccept {
		lookups, domainMismatch, selectorMismatch, algorithmMismatch := int64(-1), int64(-1), int64(-1), int64(-1)
		if observed, typeOK := publicKeys.(*disposableEd25519PublicKeys); typeOK {
			lookups = observed.lookups.Load()
			domainMismatch = observed.domainMismatch.Load()
			selectorMismatch = observed.selectorMismatch.Load()
			algorithmMismatch = observed.algorithmMismatch.Load()
		}
		t.Fatalf(
			"disposable runtime signing failed: assessment_valid=%t applicable=%t result_present=%t result_valid=%t class=%s disposition=%s error_present=%t lookups=%d domain_mismatch=%d selector_mismatch=%d algorithm_mismatch=%d",
			assessment.Valid(), assessment.Applicable(), ok, result.Valid(), result.Result(),
			result.Disposition(), err != nil, lookups, domainMismatch, selectorMismatch, algorithmMismatch,
		)
	}
	signed := insertDisposableRuntimeFields(result.Fields(), raw)
	verifier, err := dkim2.NewVerifier(publicKeys)
	if err != nil {
		t.Fatal("construct disposable runtime verifier")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	verification, err := verifier.Verify(ctx, dkim2.NewVerifyRequest(signed, reverse, recipients))
	cancel()
	if err != nil || verification.State() != dkim2.ResultStatePASS {
		t.Fatal("disposable runtime signature did not verify")
	}
}

type disposableExactAuthorizer struct {
	recipients [][]byte
}

// Authorize approves only the direct reproducer's exact policy and disclosure queries.
func (a disposableExactAuthorizer) Authorize(
	ctx context.Context,
	query dkim2.SigningAuthorizationQuery,
) (dkim2.SigningAuthorizationResult, error) {
	if err := ctx.Err(); err != nil {
		return dkim2.SigningAuthorizationResult{}, err
	}
	if !query.Valid() ||
		(query.Purpose() != dkim2.SigningAuthorizationPolicy &&
			query.Purpose() != dkim2.SigningAuthorizationRecipientDisclosure) ||
		(query.Purpose() == dkim2.SigningAuthorizationRecipientDisclosure &&
			!equalDisposableRecipients(a.recipients, query.Recipients())) {
		return dkim2.DenySigning(query), nil
	}
	return dkim2.AuthorizeSigning(query), nil
}

// proveDisposableDirectSignature isolates the runtime signer from the app adapter.
func proveDisposableDirectSignature(
	t *testing.T,
	lease *datasourceruntime.Lease,
	publicKeys dkim2.PublicKeyProvider,
	profile dkim2.SigningProfile,
	raw []byte,
	reverse []byte,
	recipients [][]byte,
) {
	t.Helper()
	signer, err := dkim2.NewSigner(
		publicKeys,
		dkim2.NewRequestRouteAuthority(),
		disposableExactAuthorizer{recipients: recipients},
		lease,
	)
	if err != nil {
		t.Fatal("direct runtime signer construction failed")
	}
	source, err := dkim2.NewSigningSource(raw)
	if err != nil {
		t.Fatal("direct runtime signing source failed")
	}
	entry, err := dkim2.NewOriginatorRouteEntry(
		source, reverse, recipients, dkim2.RouteDisclosureSingle,
		[]byte("datasource-integration"),
	)
	if err != nil {
		t.Fatal("direct runtime route entry failed")
	}
	fanout, err := dkim2.NewRouteFanoutRequest([]dkim2.RouteEntry{entry})
	if err != nil {
		t.Fatal("direct runtime fanout request failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, tickets, err := signer.PlanRouteFanout(ctx, fanout)
	cancel()
	if err != nil || len(tickets) != 1 || !tickets[0].Valid() {
		t.Fatalf("direct runtime signing phase=route_plan code=%s", disposableSigningCode(err))
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	result, recovery, err := signer.SignOriginator(
		ctx,
		dkim2.NewOriginatorSigningRequest(
			raw, reverse, recipients, tickets[0], profile, dkim2.SigningMetadata{},
			dkim2.SigningTransportFinalNetworkPreDotStuffing,
		),
	)
	cancel()
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf("direct runtime signing phase=sign_originator code=%s", disposableSigningCode(err))
	}
}

// disposableSigningCode returns only the bounded signing classification.
func disposableSigningCode(err error) dkim2.SigningErrorCode {
	var signingErr *dkim2.SigningError
	if errors.As(err, &signingErr) && signingErr != nil {
		return signingErr.Code()
	}
	return ""
}

// equalDisposableRecipients compares exact ordered envelope recipients.
func equalDisposableRecipients(expected, actual [][]byte) bool {
	if len(expected) != len(actual) {
		return false
	}
	for index := range expected {
		if !bytes.Equal(expected[index], actual[index]) {
			return false
		}
	}
	return true
}

// disposableIntegrationPublicKeys loads the exact invocation-owned SPKI.
func disposableIntegrationPublicKeys(t *testing.T) dkim2.PublicKeyProvider {
	t.Helper()
	encoded, err := os.ReadFile(integrationEnvironment(t, "DKIM2_DATASOURCE_PUBLIC_SPKI"))
	if err != nil {
		t.Fatal("read disposable public SPKI")
	}
	parsed, err := x509.ParsePKIXPublicKey(encoded)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(key) != ed25519.PublicKeySize {
		clear(encoded)
		t.Fatal("parse disposable Ed25519 public SPKI")
	}
	detached := append(ed25519.PublicKey(nil), key...)
	expected := append(ed25519.PublicKey(nil), detached...)
	clear(encoded)
	if !bytes.Equal(detached, expected) {
		clear(detached)
		clear(expected)
		t.Fatal("detached Ed25519 public key changed with cleared SPKI source")
	}
	clear(expected)
	return &disposableEd25519PublicKeys{key: detached}
}

// insertDisposableRuntimeFields reproduces validated end-of-header insertion.
func insertDisposableRuntimeFields(fields []app.CompletedField, raw []byte) []byte {
	separator := bytes.Index(raw, []byte("\r\n\r\n"))
	if separator < 0 {
		return nil
	}
	insertion := separator + len("\r\n")
	output := make([]byte, 0, len(raw)+1024)
	output = append(output, raw[:insertion]...)
	for _, field := range fields {
		output = append(output, field.Bytes()...)
	}
	return append(output, raw[insertion:]...)
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
	for _, backend := range []struct {
		name       string
		port       string
		serverName string
		password   string
	}{
		{"mysql", "DKIM2_MYSQL_PORT", "DKIM2_MYSQL_SERVER_NAME", "DKIM2_MYSQL_PASSWORD"},
		{"mariadb", "DKIM2_MARIADB_PORT", "DKIM2_MARIADB_SERVER_NAME", "DKIM2_MARIADB_PASSWORD"},
	} {
		current := backend
		t.Run(current.name+"_authentication", func(t *testing.T) {
			requireUnavailableIntegrationMySQLOpen(
				t, rootCAs, current.port, current.serverName, []byte("wrong-password"),
			)
		})
		t.Run(current.name+"_server_identity", func(t *testing.T) {
			t.Setenv(current.serverName, "wrong.integration.test")
			requireUnavailableIntegrationMySQLOpen(
				t, rootCAs, current.port, current.serverName,
				integrationPassword(t, current.password),
			)
		})
	}
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
		for _, backend := range []struct {
			name       string
			port       string
			serverName string
			password   string
		}{
			{"MySQL", "DKIM2_MYSQL_PORT", "DKIM2_MYSQL_SERVER_NAME", "DKIM2_MYSQL_PASSWORD"},
			{"MariaDB", "DKIM2_MARIADB_PORT", "DKIM2_MARIADB_SERVER_NAME", "DKIM2_MARIADB_PASSWORD"},
		} {
			if _, err := integrationMySQLLoader(
				t, rootCAs, backend.port, backend.serverName,
				integrationPassword(t, backend.password),
			).Load(ctx); provider.ErrorCodeOf(err) != provider.ErrorCodeCancelled {
				t.Fatalf("%s cancellation was not preserved", backend.name)
			}
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

// integrationMySQLLoader builds one verified-TLS, repeatable-read MySQL-family loader.
func integrationMySQLLoader(
	t *testing.T,
	rootCAs *x509.CertPool,
	portName string,
	serverName string,
	password []byte,
) *datasourcemysql.Loader {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := datasourcemysql.OpenPool(ctx, datasourcemysql.ConnectionConfig{
		Address:    integrationAddress(t, portName),
		ServerName: integrationEnvironment(t, serverName),
		Database:   "dkim2", User: "dkim2_runtime_login", Password: password,
		RootCAs: rootCAs, ConnectTimeout: 5 * time.Second,
		MaxConnections: 2, IdleConnections: 0,
	})
	if err != nil {
		t.Fatal("construct MySQL-family pool")
	}
	loader, err := datasourcemysql.NewLoader(
		pool, provider.DefaultLimits(), 1, 4<<20, 10*time.Second,
	)
	if err != nil {
		pool.Close()
		t.Fatal("construct MySQL-family loader")
	}
	t.Cleanup(loader.Close)
	return loader
}

// requireUnavailableIntegrationMySQLOpen requires one content-free connection denial.
func requireUnavailableIntegrationMySQLOpen(
	t *testing.T,
	rootCAs *x509.CertPool,
	portName string,
	serverName string,
	password []byte,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pool, err := datasourcemysql.OpenPool(ctx, datasourcemysql.ConnectionConfig{
		Address:    integrationAddress(t, portName),
		ServerName: integrationEnvironment(t, serverName),
		Database:   "dkim2", User: "dkim2_runtime_login", Password: password,
		RootCAs: rootCAs, ConnectTimeout: 2 * time.Second,
		MaxConnections: 1, IdleConnections: 0,
	})
	if pool != nil {
		pool.Close()
		t.Fatal("denied MySQL-family connection returned a pool")
	}
	if err == nil || err.Error() != "mysql pool unavailable" {
		t.Fatal("denied MySQL-family connection did not fail closed")
	}
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
