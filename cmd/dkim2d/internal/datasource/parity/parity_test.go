package parity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	datasourceldap "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/ldap"
	datasourcepostgresql "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/postgresql"
	"github.com/croessner/dkim2/provider"
	signingflatfile "github.com/croessner/dkim2/provider/flatfile"
)

const (
	testTenant                  = "tenant"
	testDomain                  = "example.test"
	testProfile                 = "profile"
	testHandle                  = "handle"
	testSelector                = "selector"
	testLDAPGenerationAttribute = "dkim2Generation"
	testLDAPProfileAttribute    = "dkim2ProfileID"
	testActiveStatus            = "active"
	testAlgorithm               = "ed25519-sha256"
	testProfileUse              = "originator"
)

type resolver interface {
	Resolve(context.Context, string, string, time.Time) (dkim2.SigningProfile, error)
}

type neutralResolver struct {
	value *provider.SigningResolver
}

// Resolve projects one exact originator selection.
func (r neutralResolver) Resolve(
	ctx context.Context,
	tenant string,
	domain string,
	at time.Time,
) (dkim2.SigningProfile, error) {
	return r.value.ResolvePolicy(
		ctx, tenant, domain, provider.ProfileUseOriginator, at,
	)
}

type flatResolver struct {
	value *signingflatfile.Resolver
}

// Resolve projects one exact flat-file originator selection.
func (r flatResolver) Resolve(
	ctx context.Context,
	tenant string,
	domain string,
	at time.Time,
) (dkim2.SigningProfile, error) {
	return r.value.ResolvePolicy(
		ctx, tenant, domain, signingflatfile.PolicyOriginator, at,
	)
}

// TestSharedProviderParity runs one normalized exact-resolution contract over
// memory, flat-file, LDAP, and PostgreSQL projections.
func TestSharedProviderParity(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate shared key")
	}
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal("encode public key")
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
	clear(private)
	if err != nil {
		t.Fatal("encode private key")
	}
	defer clear(pkcs8)
	at := time.Now().UTC()
	handle, err := dkim2.NewPrivateKeyHandle([]byte(testHandle))
	if err != nil {
		t.Fatal("construct handle")
	}
	digest := sha256.Sum256(spki)
	binding, err := provider.NewBinding(
		testTenant, testDomain, provider.ProfileUseOriginator, testHandle,
		handle, provider.AlgorithmEd25519SHA256, digest,
	)
	if err != nil {
		t.Fatal("construct neutral binding")
	}
	flatBinding, err := signingflatfile.NewBinding(
		testTenant, testDomain, signingflatfile.PolicyOriginator, testHandle,
		handle, dkim2.AlgorithmEd25519SHA256, digest,
	)
	if err != nil {
		t.Fatal("construct flat-file binding")
	}
	memoryDataset, err := directDataset(spki)
	if err != nil {
		t.Fatal("construct memory dataset")
	}
	ldapDataset, err := datasourceldap.MapDataset(
		ldapRecords(spki), provider.DefaultLimits(),
	)
	if err != nil {
		t.Fatal("construct LDAP dataset")
	}
	postgresqlDataset, err := datasourcepostgresql.MapDataset(
		postgresqlRows(spki, pkcs8), provider.DefaultLimits(),
	)
	if err != nil {
		t.Fatal("construct PostgreSQL dataset")
	}
	resolvers := map[string]resolver{}
	for name, dataset := range map[string]*provider.Dataset{
		"memory": memoryDataset, "ldap": ldapDataset, "postgresql": postgresqlDataset,
	} {
		projected, projectErr := dataset.NewSigningResolver(
			[]provider.Binding{binding}, at,
		)
		if projectErr != nil {
			t.Fatalf("%s projection failed", name)
		}
		resolvers[name] = neutralResolver{value: projected}
	}
	flat, err := signingflatfile.Open(
		flatDocument(t, spki), []signingflatfile.Binding{flatBinding}, at,
	)
	if err != nil {
		t.Fatal("construct flat-file resolver")
	}
	resolvers["flat_file"] = flatResolver{value: flat}

	for name, candidate := range resolvers {
		t.Run(name, func(t *testing.T) {
			profile, resolveErr := candidate.Resolve(
				context.Background(), testTenant, testDomain, at,
			)
			if resolveErr != nil || !profile.Valid() {
				t.Fatalf("exact active selection failed: %v", resolveErr)
			}
			for _, request := range []struct {
				tenant string
				domain string
			}{
				{tenant: "other", domain: testDomain},
				{tenant: testTenant, domain: "other.test"},
			} {
				result, requestErr := candidate.Resolve(
					context.Background(), request.tenant, request.domain, at,
				)
				if requestErr == nil || result.Valid() {
					t.Fatal("nonexact request resolved")
				}
			}
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			result, cancelErr := candidate.Resolve(
				cancelled, testTenant, testDomain, at,
			)
			if cancelErr == nil || result.Valid() {
				t.Fatal("cancelled request resolved")
			}
		})
	}
}

// directDataset builds the shared memory corpus.
func directDataset(spki []byte) (*provider.Dataset, error) {
	credential, err := provider.NewCredential(
		testSelector, provider.AlgorithmEd25519SHA256, spki, testHandle,
		provider.DefaultLimits(),
	)
	if err != nil {
		return nil, err
	}
	profile, err := provider.NewProfile(
		testProfile, testDomain, provider.RecordStatusActive,
		[]provider.Credential{credential}, time.Time{}, time.Time{},
		provider.DefaultLimits(),
	)
	if err != nil {
		return nil, err
	}
	policy, err := provider.NewPolicy(
		testTenant, testDomain, provider.ProfileUseOriginator, testProfile,
		provider.RecordStatusActive, provider.RolloutEnforce,
		provider.CompatibilityStrict, "", provider.DefaultLimits(),
	)
	if err != nil {
		return nil, err
	}
	return provider.NewDataset(
		1, []string{testHandle}, []provider.Profile{profile},
		[]provider.Policy{policy}, provider.DefaultLimits(),
	)
}

// ldapRecords projects the shared corpus into exact LDAP records.
func ldapRecords(spki []byte) datasourceldap.DatasetRecords {
	value := func(text string) [][]byte { return [][]byte{[]byte(text)} }
	metadata := func() datasourceldap.Entry {
		return datasourceldap.Entry{
			Class: datasourceldap.RecordClassDataset,
			Attributes: map[string][][]byte{
				"dkim2SchemaVersion":        value("dkim2-datasource-v2"),
				testLDAPGenerationAttribute: value("1"),
				"dkim2DatasetState":         value("committed"),
			},
		}
	}
	return datasourceldap.DatasetRecords{
		Current: metadata(), Root: metadata(),
		Handles: []datasourceldap.Entry{{
			Class: datasourceldap.RecordClassHandle,
			Attributes: map[string][][]byte{
				testLDAPGenerationAttribute: value("1"), "dkim2HandleID": value(testHandle),
			},
		}},
		Profiles: []datasourceldap.Entry{{
			Class: datasourceldap.RecordClassProfile,
			Attributes: map[string][][]byte{
				testLDAPGenerationAttribute: value("1"), testLDAPProfileAttribute: value(testProfile),
				"dkim2SigningDomain": value(testDomain), "dkim2RecordStatus": value(testActiveStatus),
			},
		}},
		Credentials: []datasourceldap.Entry{{
			Class: datasourceldap.RecordClassCredential,
			Attributes: map[string][][]byte{
				testLDAPGenerationAttribute: value("1"), testLDAPProfileAttribute: value(testProfile),
				"dkim2Algorithm": value(testAlgorithm), "dkim2Selector": value(testSelector),
				"dkim2PublicKeySPKI": [][]byte{append([]byte(nil), spki...)},
				"dkim2HandleID":      value(testHandle),
			},
		}},
		Policies: []datasourceldap.Entry{{
			Class: datasourceldap.RecordClassPolicy,
			Attributes: map[string][][]byte{
				testLDAPGenerationAttribute: value("1"), "dkim2TenantID": value(testTenant),
				"dkim2SigningDomain": value(testDomain), "dkim2ProfileUse": value(testProfileUse),
				testLDAPProfileAttribute: value(testProfile), "dkim2RecordStatus": value(testActiveStatus),
				"dkim2Rollout": value("enforce"), "dkim2Compatibility": value("strict"),
			},
		}},
	}
}

// postgresqlRows projects the shared corpus into exact SQL rows.
func postgresqlRows(spki, pkcs8 []byte) datasourcepostgresql.DatasetRows {
	metadata := datasourcepostgresql.MetadataRow{
		Generation: "1", SchemaVersion: "dkim2-datasource-v2",
		DatasetState: "committed",
	}
	return datasourcepostgresql.DatasetRows{
		Current: metadata, Final: metadata,
		Handles: []datasourcepostgresql.HandleRow{{
			Generation: "1", HandleID: testHandle,
		}},
		Profiles: []datasourcepostgresql.ProfileRow{{
			Generation: "1", ProfileID: testProfile, Domain: testDomain, Status: testActiveStatus,
		}},
		Credentials: []datasourcepostgresql.CredentialRow{{
			Generation: "1", ProfileID: testProfile, Algorithm: testAlgorithm,
			Selector: testSelector, PublicKeySPKI: append([]byte(nil), spki...),
			HandleID: testHandle,
		}},
		Policies: []datasourcepostgresql.PolicyRow{{
			Generation: "1", TenantID: testTenant, Domain: testDomain,
			Use: testProfileUse, ProfileID: testProfile, Status: testActiveStatus,
			Rollout: "enforce", Compatibility: "strict",
		}},
		KeyMaterial: []datasourcepostgresql.KeyMaterialRow{{
			Generation: "1", TenantID: testTenant, Domain: testDomain,
			Use: testProfileUse, HandleID: testHandle, Algorithm: testAlgorithm,
			PublicSPKI: append([]byte(nil), spki...), PrivatePKCS8: append([]byte(nil), pkcs8...),
		}},
	}
}

// flatDocument serializes the shared corpus in the authoritative flat-file shape.
func flatDocument(t *testing.T, spki []byte) []byte {
	t.Helper()
	document, err := json.Marshal(map[string]any{
		"version": "dkim2-datasource-v1",
		"handles": []any{map[string]any{"id": testHandle}},
		"profiles": []any{map[string]any{
			"id": testProfile, "domain": testDomain, "status": testActiveStatus,
			"credentials": []any{map[string]any{
				"algorithm": testAlgorithm, "selector": testSelector,
				"public_key_spki": base64.StdEncoding.EncodeToString(spki),
				"handle_id":       testHandle,
			}},
		}},
		"policies": []any{map[string]any{
			"tenant_id": testTenant, "domain": testDomain, "use": testProfileUse,
			"profile_id": testProfile, "status": testActiveStatus, "rollout": "enforce",
			"compatibility": "strict",
		}},
	})
	if err != nil {
		t.Fatal("serialize flat corpus")
	}
	return document
}
