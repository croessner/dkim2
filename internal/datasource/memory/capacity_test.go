package memory

import (
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/datasource"
)

// TestNewLoadsFullyLoadedThreeAlgorithmInstallation proves every shipped
// limit profile can hold its own maximum: MaxProfiles profiles that each carry
// one credential per signable algorithm (rsa-sha256, ed25519-sha256,
// mldsa44), every credential with its own key handle, and MaxPolicies
// policies. A credential handle is never shared between credentials, so the
// handle bound must cover MaxProfiles*MaxCredentialsPerProfile.
func TestNewLoadsFullyLoadedThreeAlgorithmInstallation(t *testing.T) {
	keys := map[datasource.Algorithm][]byte{
		datasource.AlgorithmRSASHA256:     memoryPublicKeySPKI(t, datasource.AlgorithmRSASHA256),
		datasource.AlgorithmEd25519SHA256: memoryPublicKeySPKI(t, datasource.AlgorithmEd25519SHA256),
		datasource.AlgorithmMLDSA44:       memoryMLDSA44SPKI(t),
	}
	for name, limits := range map[string]datasource.Limits{
		"default":    datasource.DefaultLimits(),
		"production": datasource.ProductionLimits(),
	} {
		t.Run(name, func(t *testing.T) {
			if testing.Short() && name == "production" {
				t.Skip("production-sized snapshot skipped in short mode")
			}
			handles, profiles, policies := fullyLoadedSnapshot(t, limits, keys)
			provider, err := New(memoryTestGeneration, handles, profiles, policies, limits)
			if err != nil || provider == nil || !provider.Valid() {
				t.Fatalf("New(fully loaded %s) error = %v", name, err)
			}
			usage, err := provider.Usage()
			if err != nil || usage.Profiles() != limits.MaxProfiles ||
				usage.Credentials() != limits.MaxProfiles*limits.MaxCredentialsPerProfile ||
				usage.Handles() != limits.MaxHandles || usage.Policies() != limits.MaxPolicies ||
				usage.Records() != limits.MaxRecords {
				t.Fatalf("Usage() = %#v, %v", usage, err)
			}
		})
	}
}

// fullyLoadedSnapshot builds one snapshot at exactly the configured profile,
// credential, handle, and policy maxima with distinct handles.
func fullyLoadedSnapshot(
	t *testing.T,
	limits datasource.Limits,
	keys map[datasource.Algorithm][]byte,
) ([]datasource.KeyHandleID, []datasource.Profile, []datasource.Policy) {
	t.Helper()
	algorithms := []datasource.Algorithm{
		datasource.AlgorithmRSASHA256, datasource.AlgorithmEd25519SHA256, datasource.AlgorithmMLDSA44,
	}
	if limits.MaxCredentialsPerProfile != len(algorithms) || limits.MaxPolicies%limits.MaxProfiles != 0 {
		t.Fatal("fixture assumes one credential per signable algorithm and whole policy tenants")
	}
	handles := make([]datasource.KeyHandleID, 0, limits.MaxProfiles*len(algorithms))
	profiles := make([]datasource.Profile, 0, limits.MaxProfiles)
	policies := make([]datasource.Policy, 0, limits.MaxPolicies)
	tenants := limits.MaxPolicies / limits.MaxProfiles
	for index := range limits.MaxProfiles {
		domain := fmt.Sprintf("d%d.test", index)
		credentials := make([]datasource.Credential, 0, len(algorithms))
		for slot, algorithm := range algorithms {
			handle := mustMemoryHandleID(t, fmt.Sprintf("handle.%d.%d", index, slot))
			credential, err := datasource.NewCredential(
				fmt.Sprintf("s%d", slot), algorithm, keys[algorithm], handle, limits,
			)
			if err != nil {
				t.Fatalf("NewCredential(%d/%s) error = %v", index, algorithm, err)
			}
			handles = append(handles, handle)
			credentials = append(credentials, credential)
		}
		profile, err := datasource.NewProfile(
			mustMemoryProfileID(t, fmt.Sprintf("profile.%d", index)), domain,
			datasource.RecordStatusActive, credentials, time.Time{}, time.Time{}, limits,
		)
		if err != nil {
			t.Fatalf("NewProfile(%d) error = %v", index, err)
		}
		profiles = append(profiles, profile)
		for tenant := range tenants {
			policies = append(policies, mustMemoryPolicy(
				t, fmt.Sprintf("tenant.%d", tenant), domain, datasource.ProfileUseOriginator,
				profile.ID(), datasource.RecordStatusActive, datasource.RolloutEnforce, limits,
			))
		}
	}
	return handles, profiles, policies
}

// memoryMLDSA44SPKI returns deterministic valid ML-DSA-44 public-key DER.
func memoryMLDSA44SPKI(t *testing.T) []byte {
	t.Helper()
	seed := sha256.Sum256([]byte("memory-capacity-mldsa44"))
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed[:])
	if err != nil {
		t.Fatalf("mldsa.NewPrivateKey() error = %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	return der
}
