package domainadmin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

type delayedEntropy struct{ delay time.Duration }

// Read returns entropy only after the configured delay.
func (r delayedEntropy) Read(value []byte) (int, error) {
	time.Sleep(r.delay)
	for index := range value {
		value[index] = 1
	}
	return len(value), nil
}

// TestKeyGeneratorBuildsCanonicalEd25519DomainAddition freezes the protected path.
func TestKeyGeneratorBuildsCanonicalEd25519DomainAddition(t *testing.T) {
	intent := testIntent(t, provider.AlgorithmEd25519SHA256)
	allocation := keysetAllocation(t, intent)
	defer allocation.Close() //nolint:errcheck // Test cleanup has no recovery.
	generator, err := newKeyGenerator(KeyPolicy{RSAModulusBits: 2048, RSAExponent: approvedRSAExponent}, DefaultLimits(), rand.Reader)
	if err != nil {
		t.Fatal("key generator fixture rejected")
	}
	keySet, err := generator.Generate(context.Background(), allocation)
	if err != nil {
		t.Fatal("canonical Ed25519 generation rejected")
	}
	defer keySet.Close() //nolint:errcheck // Test cleanup has no recovery.
	if duplicate, duplicateErr := generator.Generate(t.Context(), allocation); duplicateErr == nil || duplicate != nil {
		t.Fatal("consumed identity allocation generated a second key set")
	}
	addition, err := keySet.DomainAddition(t.Context())
	if err != nil {
		t.Fatal("generated key set did not build domain addition")
	}
	defer addition.Close() //nolint:errcheck // Test cleanup has no recovery.
	snapshot, err := addition.NewSnapshot(datasourceadmin.SchemaVersionV3, 1)
	if err != nil {
		t.Fatal("generated domain addition failed shared validation")
	}
	_ = snapshot.Close()
}

// TestKeyGeneratorRequiresSuccessfulPlanIssuance freezes the allocation lifecycle order.
func TestKeyGeneratorRequiresSuccessfulPlanIssuance(t *testing.T) {
	allocation := keysetAllocation(t, testIntent(t, provider.AlgorithmEd25519SHA256))
	defer allocation.Close() //nolint:errcheck // Test cleanup has no recovery.
	allocation.mu.Lock()
	allocation.planState = allocationPlanAllocated
	allocation.mu.Unlock()
	generator, err := newKeyGenerator(DefaultKeyPolicy(), DefaultLimits(), &incrementingEntropy{})
	if err != nil {
		t.Fatal("key generator fixture rejected")
	}
	if keys, err := generator.Generate(t.Context(), allocation); CodeOf(err) != CodeConflict || keys != nil {
		t.Fatal("unplanned allocation generated keys")
	}
	if err := allocation.reservePlanIssuance(); err != nil {
		t.Fatal("reserve plan fixture")
	}
	result := make(chan error, 1)
	go func() {
		keys, generateErr := generator.Generate(t.Context(), allocation)
		if keys != nil {
			_ = keys.Close()
		}
		result <- generateErr
	}()
	if CodeOf(<-result) != CodeConflict {
		t.Fatal("concurrent key generation crossed an in-flight plan computation")
	}
	allocation.mu.Lock()
	if allocation.consumed {
		allocation.mu.Unlock()
		t.Fatal("invalid lifecycle order consumed allocation")
	}
	allocation.mu.Unlock()
}

// TestKeyGeneratorKeepsAllocationBoundToExactIntent freezes the confused-deputy boundary.
func TestKeyGeneratorKeepsAllocationBoundToExactIntent(t *testing.T) {
	bound := testIntent(t, provider.AlgorithmEd25519SHA256)
	other, err := newIntent(intentDocument{
		Version: intentVersion, Domain: "other.example.test", TenantID: "other-tenant",
		ProfileUse: testAdminProfileUse, Algorithms: []string{string(provider.AlgorithmEd25519SHA256)},
		Rollout: testAdminRollout, Compatibility: testAdminCompat,
	})
	if err != nil || bound.equal(other) {
		t.Fatal("distinct canonical intent fixture rejected")
	}
	allocation := keysetAllocation(t, bound)
	defer allocation.Close() //nolint:errcheck // Test cleanup has no recovery.
	generator, _ := newKeyGenerator(DefaultKeyPolicy(), DefaultLimits(), rand.Reader)
	keySet, err := generator.Generate(t.Context(), allocation)
	if err != nil {
		t.Fatal("bound generation rejected")
	}
	defer keySet.Close() //nolint:errcheck // Test cleanup has no recovery.
	addition, err := keySet.DomainAddition(t.Context())
	if err != nil {
		t.Fatal("bound domain addition rejected")
	}
	defer addition.Close() //nolint:errcheck // Test cleanup has no recovery.
	snapshot, err := addition.NewSnapshot(datasourceadmin.SchemaVersionV3, 1)
	if err != nil {
		t.Fatal("bound domain snapshot rejected")
	}
	defer snapshot.Close() //nolint:errcheck // Test cleanup has no recovery.
	retainedBoundIntent := false
	if err := snapshot.WithRows(t.Context(), func(rows datasourceadmin.Rows) error {
		retainedBoundIntent = len(rows.Profiles) == 1 && len(rows.Policies) == 1 &&
			rows.Profiles[0].Domain == bound.Domain() && rows.Policies[0].TenantID == bound.TenantID() &&
			rows.Profiles[0].Domain != other.Domain() && rows.Policies[0].TenantID != other.TenantID()
		return nil
	}); err != nil || !retainedBoundIntent {
		t.Fatal("generated domain addition substituted another valid intent")
	}
}

// TestKeyGeneratorBuildsApprovedRSAAndRejectsUnsafePolicy freezes RSA policy.
func TestKeyGeneratorBuildsApprovedRSAAndRejectsUnsafePolicy(t *testing.T) {
	limits := DefaultLimits()
	for _, policy := range []KeyPolicy{
		{RSAModulusBits: 1024, RSAExponent: approvedRSAExponent},
		{RSAModulusBits: 2048, RSAExponent: 3},
	} {
		if generator, err := NewKeyGenerator(policy, limits); err == nil || generator != nil {
			t.Fatal("unsafe RSA policy accepted")
		}
	}
	intent := testIntent(t, provider.AlgorithmRSASHA256)
	allocation := keysetAllocation(t, intent)
	defer allocation.Close() //nolint:errcheck // Test cleanup has no recovery.
	generator, err := NewKeyGenerator(KeyPolicy{RSAModulusBits: 2048, RSAExponent: approvedRSAExponent}, limits)
	if err != nil {
		t.Fatal("approved RSA policy rejected")
	}
	keySet, err := generator.Generate(t.Context(), allocation)
	if err != nil {
		t.Fatal("approved RSA generation rejected")
	}
	_ = keySet.Close()
}

// TestKeyGeneratorAppliesInternalDeadlineAndRejectsEntropyFailure freezes bounds.
func TestKeyGeneratorAppliesInternalDeadlineAndRejectsEntropyFailure(t *testing.T) {
	intent := testIntent(t, provider.AlgorithmEd25519SHA256)
	limits := DefaultLimits()
	limits.BackendDeadline = 5 * time.Millisecond
	generator, err := newKeyGenerator(KeyPolicy{RSAModulusBits: 2048, RSAExponent: approvedRSAExponent}, limits, delayedEntropy{delay: 15 * time.Millisecond})
	if err != nil {
		t.Fatal("deadline generator fixture rejected")
	}
	if !generationFails(t, generator, intent) {
		t.Fatal("background generation bypassed internal deadline")
	}
	generator, _ = newKeyGenerator(KeyPolicy{RSAModulusBits: 2048, RSAExponent: approvedRSAExponent}, DefaultLimits(), failingEntropy{})
	if !generationFails(t, generator, intent) {
		t.Fatal("entropy failure returned a partial key set")
	}
	for _, source := range []entropyReader{errorAfterBytesEntropy{}, noProgressEntropy{}, invalidCountEntropy(-1), invalidCountEntropy(1)} {
		generator, _ = newKeyGenerator(KeyPolicy{RSAModulusBits: 2048, RSAExponent: approvedRSAExponent}, DefaultLimits(), source)
		allocation := keysetAllocation(t, intent)
		done := make(chan bool, 1)
		go func(allocation *IdentityAllocation) {
			keySet, generationErr := generator.Generate(context.Background(), allocation)
			_ = allocation.Close()
			done <- generationErr != nil && keySet == nil
		}(allocation)
		select {
		case rejected := <-done:
			if !rejected {
				t.Fatal("ambiguous entropy source produced a key set")
			}
		case <-time.After(time.Second):
			t.Fatal("ambiguous entropy source did not terminate key generation")
		}
	}
}

// generationFails consumes one fresh allocation and reports a complete generation failure.
func generationFails(t *testing.T, generator *KeyGenerator, intent Intent) bool {
	t.Helper()
	allocation := keysetAllocation(t, intent)
	defer allocation.Close() //nolint:errcheck // Test cleanup has no recovery.
	keySet, err := generator.Generate(context.Background(), allocation)
	if keySet != nil {
		_ = keySet.Close()
	}
	healthy, _ := newKeyGenerator(DefaultKeyPolicy(), DefaultLimits(), rand.Reader)
	retry, retryErr := healthy.Generate(context.Background(), allocation)
	if retry != nil {
		_ = retry.Close()
	}
	return err != nil && keySet == nil && retryErr != nil && retry == nil
}

// TestGeneratedKeyValidationRejectsNoncanonicalAndErasesBuffers freezes cleanup.
func TestGeneratedKeyValidationRejectsNoncanonicalAndErasesBuffers(t *testing.T) {
	intent := testIntent(t, provider.AlgorithmEd25519SHA256)
	allocation := keysetAllocation(t, intent)
	defer allocation.Close() //nolint:errcheck // Test cleanup has no recovery.
	generator, _ := newKeyGenerator(KeyPolicy{RSAModulusBits: 2048, RSAExponent: approvedRSAExponent}, DefaultLimits(), rand.Reader)
	keySet, err := generator.Generate(t.Context(), allocation)
	if err != nil {
		t.Fatal("key set fixture rejected")
	}
	malformed := cloneGeneratedCredentials(keySet.credentials)
	malformed[0].privatePKCS8 = append(malformed[0].privatePKCS8, 0)
	if err := validateGeneratedCredentials(t.Context(), 1, intent, malformed); err == nil {
		t.Fatal("noncanonical PKCS8 accepted")
	}
	clearGeneratedCredentials(malformed)
	otherPublic, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate mismatch fixture")
	}
	otherSPKI, err := x509.MarshalPKIXPublicKey(otherPublic)
	if err != nil {
		clear(otherPrivate)
		t.Fatal("marshal mismatch fixture")
	}
	mismatch := cloneGeneratedCredentials(keySet.credentials)
	clear(mismatch[0].publicSPKI)
	mismatch[0].publicSPKI = append([]byte(nil), otherSPKI...)
	if err := validateGeneratedCredentials(t.Context(), 1, intent, mismatch); err == nil {
		clearGeneratedCredentials(mismatch)
		clear(otherPrivate)
		clear(otherSPKI)
		t.Fatal("valid but mismatched public and private keys accepted")
	}
	clearGeneratedCredentials(mismatch)
	clear(otherPrivate)
	clear(otherSPKI)
	retained := keySet.credentials[0].privatePKCS8
	if err := keySet.Close(); err != nil {
		t.Fatal("close generated key set")
	}
	for _, octet := range retained {
		if octet != 0 {
			t.Fatal("generated private bytes survived close")
		}
	}
	partial := []generatedCredential{{publicSPKI: []byte{1, 2}, privatePKCS8: []byte{3, 4}}}
	public, private := partial[0].publicSPKI, partial[0].privatePKCS8
	clearGeneratedCredentials(partial)
	if public[0] != 0 || private[0] != 0 {
		t.Fatal("partial generated set survived failure cleanup")
	}
}

// TestGeneratedKeyOwnersRejectToxicGenericSinks freezes diagnostics.
func TestGeneratedKeyOwnersRejectToxicGenericSinks(t *testing.T) {
	marker := "toxic-generated-private-marker"
	keySet := &KeySet{profileID: marker, generation: 1, credentials: []generatedCredential{{privatePKCS8: []byte(marker), publicSPKI: []byte(marker)}}}
	policy := DefaultKeyPolicy()
	allocator, _ := NewIdentityAllocator(DefaultLimits())
	generator, _ := NewKeyGenerator(DefaultKeyPolicy(), DefaultLimits())
	for _, value := range []any{keySet, policy, allocator, generator, struct{ KeySet *KeySet }{KeySet: keySet}} {
		rendered := fmt.Sprintf("%+v", value)
		if !strings.Contains(rendered, redacted) || strings.Contains(rendered, marker) {
			t.Fatal("generated key owner reached formatting sink")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("generated key owner reached JSON sink")
		}
	}
	_ = keySet.Close()
}

// keysetAllocation constructs one exact protected allocation for key generation.
func keysetAllocation(t *testing.T, intent Intent) *IdentityAllocation {
	t.Helper()
	operation, err := datasourceadmin.NewOperationBinding("aebagbafaydqqcikbmga2dqpca")
	if err != nil {
		t.Fatal("operation fixture rejected")
	}
	credentials := make([]AllocatedIdentity, 0, len(intent.Algorithms()))
	for _, algorithm := range intent.Algorithms() {
		prefix, prefixErr := selectorPrefix(algorithm)
		if prefixErr != nil {
			t.Fatal("selector prefix fixture rejected")
		}
		suffix := "generated"
		if algorithm == provider.AlgorithmRSASHA256 {
			suffix = "generated-rsa"
		}
		credentials = append(credentials, AllocatedIdentity{algorithm: algorithm, handleID: "handle-" + suffix, selector: prefix + suffix})
	}
	return &IdentityAllocation{operation: operation, intent: intent.clone(), profileID: "profile-generated", credentials: credentials, candidateGeneration: 1, planState: allocationPlanReady}
}
