package verify

import (
	"context"
	"strings"
)

const staticKeyProviderSource = "static"

// StaticKey describes one deterministic in-memory public verification key.
type StaticKey struct {
	// Domain is the canonical d= signing domain.
	Domain string
	// Selector is the canonical s= selector.
	Selector string
	// Algorithm is the canonical signature algorithm.
	Algorithm Algorithm
	// Material is the algorithm-specific public key value.
	Material any
	// Metadata carries bounded provider facts without key bytes.
	Metadata KeyMetadata
}

// StaticKeyProvider resolves public keys from deterministic in-memory tuples.
type StaticKeyProvider struct {
	keys   map[keyLookupTuple]PublicKey
	policy AlgorithmPolicy
}

// StaticKeyProviderOption mutates static provider construction settings.
type StaticKeyProviderOption func(*staticKeyProviderConfig)

type staticKeyProviderConfig struct {
	policy AlgorithmPolicy
}

type keyLookupTuple struct {
	domain    string
	selector  string
	algorithm Algorithm
}

// WithStaticKeyAlgorithmPolicy replaces static provider key-validation policy.
func WithStaticKeyAlgorithmPolicy(policy AlgorithmPolicy) StaticKeyProviderOption {
	return func(config *staticKeyProviderConfig) {
		config.policy = policy
	}
}

// NewStaticKeyProvider constructs a deterministic static public-key provider.
func NewStaticKeyProvider(keys []StaticKey, options ...StaticKeyProviderOption) (StaticKeyProvider, error) {
	config := staticKeyProviderConfig{
		policy: DefaultAlgorithmPolicy(),
	}
	for _, option := range options {
		if option != nil {
			option(&config)
		}
	}
	if err := config.policy.Validate(); err != nil {
		return StaticKeyProvider{}, err
	}

	provider := StaticKeyProvider{
		keys:   make(map[keyLookupTuple]PublicKey, len(keys)),
		policy: config.policy,
	}
	for _, key := range keys {
		tuple, err := canonicalKeyLookup(key.Domain, key.Selector, key.Algorithm)
		if err != nil {
			return StaticKeyProvider{}, err
		}
		if _, exists := provider.keys[tuple]; exists {
			return StaticKeyProvider{}, ambiguousKeyError(tuple.algorithm)
		}

		material, status, err := validatePublicKeyMaterial(tuple.algorithm, key.Material, provider.policy)
		if err != nil {
			return StaticKeyProvider{}, err
		}
		metadata := sanitizeKeyMetadata(key.Metadata)
		metadata.Status = status
		provider.keys[tuple] = PublicKey{
			Algorithm: tuple.algorithm,
			Material:  material,
			Metadata:  metadata,
		}
	}

	return provider, nil
}

// LookupKey resolves one public key by canonical domain, selector, and algorithm.
func (p StaticKeyProvider) LookupKey(ctx context.Context, query KeyQuery) (PublicKey, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return publicKeyResult(query.Algorithm, nil, KeyStatusProviderError), providerError(query.Algorithm, err)
		}
	}

	tuple, err := canonicalKeyLookup(query.Domain, query.Selector, query.Algorithm)
	if err != nil {
		return publicKeyResult(query.Algorithm, nil, KeyStatusInvalid), err
	}
	switch status := p.algorithmPolicy().ClassifyAlgorithm(tuple.algorithm); status {
	case KeyStatusFound:
	case KeyStatusUnsupportedAlgorithm:
		return publicKeyResult(tuple.algorithm, nil, status), unsupportedAlgorithmError(tuple.algorithm)
	default:
		return publicKeyResult(tuple.algorithm, nil, status), disabledAlgorithmError(tuple.algorithm)
	}

	key, ok := p.keys[tuple]
	if !ok {
		return publicKeyResult(tuple.algorithm, nil, KeyStatusMissing), missingKeyError(tuple.algorithm)
	}

	return clonePublicKey(key), nil
}

// canonicalKeyLookup normalizes parser-shaped key lookup tokens.
func canonicalKeyLookup(domain string, selector string, algorithm Algorithm) (keyLookupTuple, error) {
	tuple := keyLookupTuple{
		domain:    canonicalLookupToken(domain),
		selector:  canonicalLookupToken(selector),
		algorithm: Algorithm(canonicalLookupToken(string(algorithm))),
	}
	if tuple.domain == "" || tuple.selector == "" || tuple.algorithm == "" {
		return keyLookupTuple{}, invalidKeyError(tuple.algorithm)
	}

	return tuple, nil
}

// canonicalLookupToken lowercases safe ASCII lookup tokens from parser-owned values.
func canonicalLookupToken(value string) string {
	if value == "" {
		return ""
	}

	lowered := strings.ToLower(value)
	if safeDiagnosticToken(lowered) != lowered {
		return ""
	}

	return lowered
}

// clonePublicKey returns a public key with independent supported key material.
func clonePublicKey(key PublicKey) PublicKey {
	key.Material = clonePublicKeyMaterial(key.Material)
	key.Metadata = sanitizeKeyMetadata(key.Metadata)

	return key
}

// publicKeyResult constructs bounded non-success key lookup facts.
func publicKeyResult(algorithm Algorithm, material any, status KeyStatus) PublicKey {
	return PublicKey{
		Algorithm: Algorithm(canonicalLookupToken(string(algorithm))),
		Material:  clonePublicKeyMaterial(material),
		Metadata: KeyMetadata{
			Status: status,
			Source: staticKeyProviderSource,
		},
	}
}

// sanitizeKeyMetadata bounds provider metadata before storage or return.
func sanitizeKeyMetadata(metadata KeyMetadata) KeyMetadata {
	if !metadata.Status.Known() {
		metadata.Status = KeyStatusFound
	}
	metadata.Source = safeDiagnosticToken(metadata.Source)
	if metadata.Source == "" {
		metadata.Source = staticKeyProviderSource
	}

	return metadata
}

// algorithmPolicy returns provider policy or the static default for zero values.
func (p StaticKeyProvider) algorithmPolicy() AlgorithmPolicy {
	if len(p.policy.AllowedAlgorithms) == 0 || p.policy.MinRSABits == 0 {
		return DefaultAlgorithmPolicy()
	}

	return p.policy
}
