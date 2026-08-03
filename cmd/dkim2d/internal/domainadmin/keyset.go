package domainadmin

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"sync"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"github.com/croessner/dkim2/provider"
)

const approvedRSAExponent = 65537

// KeyPolicy is the closed native-key generation policy.
type KeyPolicy struct {
	RSAModulusBits int
	RSAExponent    int
}

// DefaultKeyPolicy returns the recommended native-key generation policy.
func DefaultKeyPolicy() KeyPolicy {
	return KeyPolicy{RSAModulusBits: 3072, RSAExponent: approvedRSAExponent}
}

// Validate rejects unapproved RSA modulus or exponent choices.
func (p KeyPolicy) Validate() error {
	if (p.RSAModulusBits != 2048 && p.RSAModulusBits != 3072 && p.RSAModulusBits != 4096) ||
		p.RSAExponent != approvedRSAExponent {
		return newError(CodeInvalidLimits)
	}
	return nil
}

// String returns a constant protected key-policy representation.
func (KeyPolicy) String() string { return redacted }

// GoString returns a constant protected key-policy representation.
func (KeyPolicy) GoString() string { return redacted }

// Format prevents key-size policy from reaching formatting sinks.
func (KeyPolicy) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic key-policy serialization.
func (KeyPolicy) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }

type generatedCredential struct {
	identity     AllocatedIdentity
	publicSPKI   []byte
	privatePKCS8 []byte
}

// KeySet owns one complete validated generated native credential set.
type KeySet struct {
	mu          sync.Mutex
	intent      Intent
	profileID   string
	generation  uint64
	credentials []generatedCredential
	closed      bool
}

// KeyGenerationInput owns one persisted-plan-derived fixed identity set for a single preparation attempt.
type KeyGenerationInput struct {
	mu          sync.Mutex
	intent      Intent
	profileID   string
	generation  uint64
	credentials []AllocatedIdentity
	consumed    bool
	closed      bool
}

// KeyGenerator owns approved policy and cryptographic entropy.
type KeyGenerator struct {
	policy  KeyPolicy
	limits  Limits
	entropy entropyReader
}

// NewKeyGenerator constructs the production crypto/rand native-key generator.
func NewKeyGenerator(policy KeyPolicy, limits Limits) (*KeyGenerator, error) {
	return newKeyGenerator(policy, limits, rand.Reader)
}

// newKeyGenerator constructs one native-key generator over the entropy test seam.
func newKeyGenerator(policy KeyPolicy, limits Limits, entropy entropyReader) (*KeyGenerator, error) {
	if policy.Validate() != nil || limits.Validate() != nil || entropy == nil {
		return nil, newError(CodeInvalidLimits)
	}
	return &KeyGenerator{policy: policy, limits: limits, entropy: entropy}, nil
}

// Generate derives the exact allocation-bound intent and validates one complete native key set.
func (g *KeyGenerator) Generate(
	ctx context.Context,
	allocation *IdentityAllocation,
) (*KeySet, error) {
	if g == nil || ctx == nil || ctx.Err() != nil || allocation == nil || g.policy.Validate() != nil || g.limits.Validate() != nil {
		return nil, newError(CodeInvalidLimits)
	}
	allocation.mu.Lock()
	if allocation.closed || allocation.planState != allocationPlanReady || allocation.consumed || allocation.candidateGeneration == 0 {
		allocation.mu.Unlock()
		return nil, newError(CodeConflict)
	}
	allocation.consumed = true
	intent := allocation.intent.clone()
	profileID := allocation.profileID
	generation := allocation.candidateGeneration
	identities := append([]AllocatedIdentity(nil), allocation.credentials...)
	allocation.mu.Unlock()
	return g.generateOwned(ctx, intent, profileID, generation, identities)
}

// GeneratePlanned generates fresh keys for one persisted preparing journal while retaining fixed identifiers.
func (g *KeyGenerator) GeneratePlanned(
	ctx context.Context,
	input *KeyGenerationInput,
) (*KeySet, error) {
	if g == nil || ctx == nil || ctx.Err() != nil || input == nil ||
		g.policy.Validate() != nil || g.limits.Validate() != nil {
		return nil, newError(CodeInvalidLimits)
	}
	input.mu.Lock()
	if input.closed || input.consumed || !input.intent.valid() || input.generation == 0 {
		input.mu.Unlock()
		return nil, newError(CodeConflict)
	}
	input.consumed = true
	intent := input.intent.clone()
	profileID := input.profileID
	generation := input.generation
	identities := append([]AllocatedIdentity(nil), input.credentials...)
	input.mu.Unlock()
	return g.generateOwned(ctx, intent, profileID, generation, identities)
}

// generateOwned validates and consumes one detached fixed identity projection.
func (g *KeyGenerator) generateOwned(
	ctx context.Context,
	intent Intent,
	profileID string,
	generation uint64,
	identities []AllocatedIdentity,
) (*KeySet, error) {
	defer clearAllocatedIdentities(identities)
	if !intent.valid() {
		return nil, newError(CodeConflict)
	}
	bounded, cancel := context.WithTimeout(ctx, g.limits.BackendDeadline)
	defer cancel()
	algorithms := intent.Algorithms()
	if len(identities) == 0 || len(identities) != len(algorithms) {
		return nil, newError(CodeConflict)
	}
	generated := make([]generatedCredential, 0, len(identities))
	for index, identity := range identities {
		if identity.algorithm != algorithms[index] {
			clearGeneratedCredentials(generated)
			return nil, newError(CodeConflict)
		}
		if bounded.Err() != nil {
			clearGeneratedCredentials(generated)
			return nil, newError(CodeUnavailable)
		}
		credential, err := g.generateCredential(bounded, identity)
		if err != nil {
			clearGeneratedCredentials(generated)
			return nil, err
		}
		generated = append(generated, credential)
	}
	if err := validateGeneratedCredentials(bounded, generation, intent, generated); err != nil {
		clearGeneratedCredentials(generated)
		return nil, err
	}
	return &KeySet{
		intent: intent, profileID: profileID, generation: generation, credentials: generated,
	}, nil
}

// Close erases one plan-derived key-generation input.
func (i *KeyGenerationInput) Close() error {
	if i == nil {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return nil
	}
	clearAllocatedIdentities(i.credentials)
	i.credentials = nil
	i.intent = Intent{}
	i.profileID = ""
	i.generation = 0
	i.consumed = true
	i.closed = true
	return nil
}

// String returns a constant protected key-generation-input representation.
func (*KeyGenerationInput) String() string { return redacted }

// GoString returns a constant protected key-generation-input representation.
func (*KeyGenerationInput) GoString() string { return redacted }

// Format prevents persisted identifiers from reaching formatting sinks.
func (*KeyGenerationInput) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic key-generation-input serialization.
func (*KeyGenerationInput) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }

// generateCredential creates canonical PKCS#8 and derived SPKI for one algorithm.
func (g *KeyGenerator) generateCredential(
	ctx context.Context,
	identity AllocatedIdentity,
) (generatedCredential, error) {
	var private crypto.PrivateKey
	var public any
	var err error
	reader := contextEntropyReader{ctx: ctx, source: g.entropy}
	switch identity.algorithm {
	case provider.AlgorithmEd25519SHA256:
		var publicKey ed25519.PublicKey
		publicKey, private, err = ed25519.GenerateKey(reader)
		public = publicKey
	case provider.AlgorithmRSASHA256:
		var privateKey *rsa.PrivateKey
		privateKey, err = rsa.GenerateKey(reader, g.policy.RSAModulusBits)
		if err == nil && (privateKey == nil || privateKey.E != g.policy.RSAExponent ||
			privateKey.N.BitLen() != g.policy.RSAModulusBits) {
			err = newError(CodeUnavailable)
		}
		private = privateKey
		if privateKey != nil {
			public = &privateKey.PublicKey
		}
	default:
		return generatedCredential{}, newError(CodeInvalidIntent)
	}
	if private != nil {
		defer signingstore.ClearPrivateKey(private)
	}
	if err != nil || ctx.Err() != nil {
		return generatedCredential{}, newError(CodeUnavailable)
	}
	privatePKCS8, privateErr := x509.MarshalPKCS8PrivateKey(private)
	publicSPKI, publicErr := x509.MarshalPKIXPublicKey(public)
	if privateErr != nil || publicErr != nil || len(privatePKCS8) == 0 || len(publicSPKI) == 0 {
		clear(privatePKCS8)
		clear(publicSPKI)
		return generatedCredential{}, newError(CodeUnavailable)
	}
	return generatedCredential{
		identity: identity, publicSPKI: publicSPKI, privatePKCS8: privatePKCS8,
	}, nil
}

// validateGeneratedCredentials reuses the exact native registry equivalence owner.
func validateGeneratedCredentials(
	ctx context.Context,
	generation uint64,
	intent Intent,
	credentials []generatedCredential,
) error {
	if ctx == nil || ctx.Err() != nil || generation == 0 || len(credentials) == 0 {
		return newError(CodeUnavailable)
	}
	materials := make([]*signingstore.NativeKeyMaterial, 0, len(credentials))
	defer func() {
		for _, material := range materials {
			_ = material.Close()
		}
	}()
	for _, credential := range credentials {
		material, err := signingstore.NewNativeKeyMaterial(
			generation, intent.TenantID(), intent.Domain(), intent.ProfileUse(),
			credential.identity.handleID, credential.identity.algorithm,
			credential.publicSPKI, credential.privatePKCS8,
		)
		if err != nil {
			return newError(CodeUnavailable)
		}
		materials = append(materials, material)
	}
	registry, err := signingstore.OpenNativeRegistry(generation, materials)
	if err != nil || registry == nil {
		return newError(CodeUnavailable)
	}
	if err := registry.Close(ctx); err != nil {
		return newError(CodeUnavailable)
	}
	return nil
}

// DomainAddition constructs one separately owned validated append-domain value.
func (k *KeySet) DomainAddition(ctx context.Context) (*datasourceadmin.DomainAddition, error) {
	if k == nil || ctx == nil || ctx.Err() != nil {
		return nil, newError(CodeConflict)
	}
	k.mu.Lock()
	if k.closed {
		k.mu.Unlock()
		return nil, newError(CodeConflict)
	}
	intent, profileID := k.intent, k.profileID
	credentials := cloneGeneratedCredentials(k.credentials)
	k.mu.Unlock()
	defer clearGeneratedCredentials(credentials)
	algorithms := intent.Algorithms()
	planIntent := datasourceadmin.PlanIntent{
		Version: intent.Version(), Domain: intent.Domain(), TenantID: intent.TenantID(),
		ProfileUse: intent.ProfileUse().String(), Rollout: intent.Rollout().String(),
		Compatibility: intent.Compatibility().String(),
	}
	for _, algorithm := range algorithms {
		planIntent.Algorithms = append(planIntent.Algorithms, string(algorithm))
	}
	values := make([]datasourceadmin.DomainCredential, 0, len(credentials))
	for _, credential := range credentials {
		values = append(values, datasourceadmin.DomainCredential{
			Algorithm: string(credential.identity.algorithm), HandleID: credential.identity.handleID,
			Selector: credential.identity.selector, PublicSPKI: credential.publicSPKI,
			PrivatePKCS8: credential.privatePKCS8,
		})
	}
	addition, err := datasourceadmin.NewDomainAddition(planIntent, profileID, values)
	if err != nil {
		return nil, newError(CodeUnavailable)
	}
	return addition, nil
}

// cloneGeneratedCredentials detaches every generated public and private buffer.
func cloneGeneratedCredentials(values []generatedCredential) []generatedCredential {
	result := make([]generatedCredential, 0, len(values))
	for _, value := range values {
		value.publicSPKI = append([]byte(nil), value.publicSPKI...)
		value.privatePKCS8 = append([]byte(nil), value.privatePKCS8...)
		result = append(result, value)
	}
	return result
}

// clearGeneratedCredentials erases every retained generated key buffer.
func clearGeneratedCredentials(values []generatedCredential) {
	for index := range values {
		clear(values[index].publicSPKI)
		clear(values[index].privatePKCS8)
		values[index] = generatedCredential{}
	}
	clear(values)
}

// Close erases and releases every generated native key.
func (k *KeySet) Close() error {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil
	}
	clearGeneratedCredentials(k.credentials)
	k.credentials = nil
	k.intent = Intent{}
	k.profileID = ""
	k.generation = 0
	k.closed = true
	return nil
}

// String returns a constant protected generated-key-set representation.
func (*KeySet) String() string { return redacted }

// GoString returns a constant protected generated-key-set representation.
func (*KeySet) GoString() string { return redacted }

// Format prevents generated key material from reaching formatting sinks.
func (*KeySet) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic generated-key-set serialization.
func (*KeySet) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }

// String returns a constant protected key-generator representation.
func (*KeyGenerator) String() string { return redacted }

// GoString returns a constant protected key-generator representation.
func (*KeyGenerator) GoString() string { return redacted }

// Format prevents generation policy and entropy state from reaching formatting sinks.
func (*KeyGenerator) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic key-generator serialization.
func (*KeyGenerator) MarshalJSON() ([]byte, error) { return nil, newError(CodeProtectedInput) }
