package parity

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	datasourceldap "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/ldap"
	datasourcepostgresql "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/postgresql"
	"github.com/croessner/dkim2/provider"
	signingflatfile "github.com/croessner/dkim2/provider/flatfile"
)

// parityCredential is one credential of the shared three-algorithm corpus.
type parityCredential struct {
	algorithm provider.Algorithm
	selector  string
	handle    string
	spki      []byte
	pkcs8     []byte
}

// threeAlgorithmCorpus returns one RSA, Ed25519, and ML-DSA-44 credential
// with distinct selectors and handles.
func threeAlgorithmCorpus(t *testing.T) []parityCredential {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mlKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	credentials := []parityCredential{
		{algorithm: provider.AlgorithmMLDSA44, selector: "pq", handle: "handle-ml"},
		{algorithm: provider.AlgorithmEd25519SHA256, selector: "ed", handle: "handle-ed"},
		{algorithm: provider.AlgorithmRSASHA256, selector: "rsa", handle: "handle-rsa"},
	}
	for index, private := range []crypto.Signer{mlKey, edPrivate, rsaKey} {
		credentials[index].spki, err = x509.MarshalPKIXPublicKey(private.Public())
		if err != nil {
			t.Fatal(err)
		}
		credentials[index].pkcs8, err = x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
	}
	return credentials
}

// TestSharedProviderParityThreeAlgorithmProfile proves memory, flat-file,
// LDAP, and the SQL snapshot mapper (PostgreSQL; MySQL and MariaDB share the
// same snapshot owner) accept one profile with rsa-sha256, ed25519-sha256,
// and mldsa44 credentials through the same domain contract, and that every
// provider rejects it when the credential bound is narrowed to two.
func TestSharedProviderParityThreeAlgorithmProfile(t *testing.T) {
	corpus := threeAlgorithmCorpus(t)
	at := time.Now().UTC()
	var bindings []provider.Binding
	var flatBindings []signingflatfile.Binding
	for _, credential := range corpus {
		handle, err := dkim2.NewPrivateKeyHandle([]byte(credential.handle))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(credential.spki)
		binding, err := provider.NewBinding(testTenant, testDomain, provider.ProfileUseOriginator,
			credential.handle, handle, credential.algorithm, digest)
		if err != nil {
			t.Fatalf("provider.NewBinding(%s) error = %v", credential.algorithm, err)
		}
		bindings = append(bindings, binding)
		flatBinding, err := signingflatfile.NewBinding(testTenant, testDomain, signingflatfile.PolicyOriginator,
			credential.handle, handle, dkim2.Algorithm(credential.algorithm), digest)
		if err != nil {
			t.Fatalf("signingflatfile.NewBinding(%s) error = %v", credential.algorithm, err)
		}
		flatBindings = append(flatBindings, flatBinding)
	}
	for _, limits := range []provider.Limits{provider.DefaultLimits(), narrowedCredentialLimits()} {
		wantValid := limits.MaxCredentialsPerProfile >= 3
		datasets := map[string]func() (*provider.Dataset, error){
			"memory": func() (*provider.Dataset, error) { return threeAlgorithmDataset(corpus, limits) },
			"ldap": func() (*provider.Dataset, error) {
				return datasourceldap.MapDataset(threeAlgorithmLDAPRecords(corpus), limits)
			},
			"sql": func() (*provider.Dataset, error) {
				return datasourcepostgresql.MapDataset(threeAlgorithmSQLRows(corpus), limits)
			},
		}
		for name, build := range datasets {
			dataset, err := build()
			if !wantValid {
				if err == nil {
					t.Fatalf("%s accepted three credentials under a bound of two", name)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s dataset error = %v", name, err)
			}
			resolver, err := dataset.NewSigningResolver(bindings, at)
			if err != nil {
				t.Fatalf("%s projection error = %v", name, err)
			}
			profile, err := resolver.ResolvePolicy(context.Background(), testTenant, testDomain, provider.ProfileUseOriginator, at)
			if err != nil || !profile.Valid() {
				t.Fatalf("%s resolution error = %v", name, err)
			}
		}
	}
	flat, err := signingflatfile.Open(threeAlgorithmFlatDocument(t, corpus), flatBindings, at)
	if err != nil {
		t.Fatalf("flat-file Open() error = %v", err)
	}
	profile, err := flat.ResolvePolicy(context.Background(), testTenant, testDomain, signingflatfile.PolicyOriginator, at)
	if err != nil || !profile.Valid() {
		t.Fatalf("flat-file resolution error = %v", err)
	}
}

// narrowedCredentialLimits returns default limits with two credentials per profile.
func narrowedCredentialLimits() provider.Limits {
	limits := provider.DefaultLimits()
	limits.MaxCredentialsPerProfile = 2
	return limits
}

// threeAlgorithmDataset builds the corpus through the provider-neutral constructors.
func threeAlgorithmDataset(corpus []parityCredential, limits provider.Limits) (*provider.Dataset, error) {
	credentials := make([]provider.Credential, 0, len(corpus))
	handles := make([]string, 0, len(corpus))
	for _, entry := range corpus {
		credential, err := provider.NewCredential(entry.selector, entry.algorithm, entry.spki, entry.handle, limits)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
		handles = append(handles, entry.handle)
	}
	profile, err := provider.NewProfile(testProfile, testDomain, provider.RecordStatusActive,
		credentials, time.Time{}, time.Time{}, limits)
	if err != nil {
		return nil, err
	}
	policy, err := provider.NewPolicy(testTenant, testDomain, provider.ProfileUseOriginator, testProfile,
		provider.RecordStatusActive, provider.RolloutEnforce, provider.CompatibilityStrict, "", limits)
	if err != nil {
		return nil, err
	}
	return provider.NewDataset(1, handles, []provider.Profile{profile}, []provider.Policy{policy}, limits)
}

// threeAlgorithmLDAPRecords projects the corpus into exact LDAP records.
func threeAlgorithmLDAPRecords(corpus []parityCredential) datasourceldap.DatasetRecords {
	records := ldapRecords(corpus[0].spki)
	value := func(text string) [][]byte { return [][]byte{[]byte(text)} }
	records.Handles, records.Credentials = nil, nil
	for _, entry := range corpus {
		records.Handles = append(records.Handles, datasourceldap.Entry{
			Class: datasourceldap.RecordClassHandle,
			Attributes: map[string][][]byte{
				testLDAPGenerationAttribute: value("1"), testLDAPHandleAttribute: value(entry.handle),
			},
		})
		records.Credentials = append(records.Credentials, datasourceldap.Entry{
			Class: datasourceldap.RecordClassCredential,
			Attributes: map[string][][]byte{
				testLDAPGenerationAttribute: value("1"), testLDAPProfileAttribute: value(testProfile),
				"dkim2Algorithm": value(string(entry.algorithm)), "dkim2Selector": value(entry.selector),
				"dkim2PublicKeySPKI":    [][]byte{append([]byte(nil), entry.spki...)},
				testLDAPHandleAttribute: value(entry.handle),
			},
		})
	}
	return records
}

// threeAlgorithmSQLRows projects the corpus into exact SQL snapshot rows.
func threeAlgorithmSQLRows(corpus []parityCredential) datasourcepostgresql.DatasetRows {
	rows := postgresqlRows(corpus[0].spki, nil)
	rows.Handles, rows.Credentials, rows.KeyMaterial = nil, nil, nil
	for _, entry := range corpus {
		rows.Handles = append(rows.Handles, datasourcepostgresql.HandleRow{Generation: "1", HandleID: entry.handle})
		rows.Credentials = append(rows.Credentials, datasourcepostgresql.CredentialRow{
			Generation: "1", ProfileID: testProfile, Algorithm: string(entry.algorithm),
			Selector: entry.selector, PublicKeySPKI: append([]byte(nil), entry.spki...), HandleID: entry.handle,
		})
		rows.KeyMaterial = append(rows.KeyMaterial, datasourcepostgresql.KeyMaterialRow{
			Generation: "1", TenantID: testTenant, Domain: testDomain,
			Use: testProfileUse, HandleID: entry.handle, Algorithm: string(entry.algorithm),
			PublicSPKI: append([]byte(nil), entry.spki...), PrivatePKCS8: append([]byte(nil), entry.pkcs8...),
		})
	}
	return rows
}

// threeAlgorithmFlatDocument serializes the corpus in the flat-file shape.
func threeAlgorithmFlatDocument(t *testing.T, corpus []parityCredential) []byte {
	t.Helper()
	handles := make([]any, 0, len(corpus))
	credentials := make([]any, 0, len(corpus))
	// The flat-file format requires credentials in canonical signing order:
	// rsa-sha256, ed25519-sha256, then mldsa44.
	ordered := slices.Clone(corpus)
	slices.SortFunc(ordered, func(left, right parityCredential) int {
		leftRank, _ := left.algorithm.SigningRank()
		rightRank, _ := right.algorithm.SigningRank()
		return leftRank - rightRank
	})
	for _, entry := range ordered {
		handles = append(handles, map[string]any{"id": entry.handle})
		credentials = append(credentials, map[string]any{
			"algorithm": string(entry.algorithm), "selector": entry.selector,
			"public_key_spki": base64.StdEncoding.EncodeToString(entry.spki), "handle_id": entry.handle,
		})
	}
	document, err := json.Marshal(map[string]any{
		"version": "dkim2-datasource-v1",
		"handles": handles,
		"profiles": []any{map[string]any{
			"id": testProfile, testDomainField: testDomain, testStatusField: testActiveStatus, "credentials": credentials,
		}},
		"policies": []any{map[string]any{
			"tenant_id": testTenant, testDomainField: testDomain, "use": testProfileUse,
			"profile_id": testProfile, testStatusField: testActiveStatus, "rollout": testRollout,
			"compatibility": testCompatibility,
		}},
	})
	if err != nil {
		t.Fatal("serialize flat corpus")
	}
	return document
}
