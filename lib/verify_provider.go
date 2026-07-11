package dkim2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"math/big"
)

// Algorithm identifies a bounded DKIM2 signature algorithm family.
type Algorithm string

const (
	// AlgorithmRSASHA256 identifies RSA-SHA256 verification.
	AlgorithmRSASHA256 Algorithm = "rsa-sha256"
	// AlgorithmEd25519SHA256 identifies Ed25519-SHA256 verification.
	AlgorithmEd25519SHA256 Algorithm = "ed25519-sha256"
	// AlgorithmUnknown represents an unrecognized message-derived algorithm without retaining its spelling.
	AlgorithmUnknown Algorithm = "unknown"
)

// Known reports whether the algorithm is in the closed public vocabulary.
func (a Algorithm) Known() bool {
	switch a {
	case AlgorithmRSASHA256, AlgorithmEd25519SHA256, AlgorithmUnknown:
		return true
	default:
		return false
	}
}

// PublicKeyStatus identifies a closed key lookup outcome.
type PublicKeyStatus string

const (
	// PublicKeyStatusFound reports exactly one declared public key.
	PublicKeyStatusFound PublicKeyStatus = "found"
	// PublicKeyStatusMissing reports no matching public key.
	PublicKeyStatusMissing PublicKeyStatus = "missing"
	// PublicKeyStatusInvalid reports provider-detected invalid public key state.
	PublicKeyStatusInvalid PublicKeyStatus = "invalid"
	// PublicKeyStatusAmbiguous reports more than one matching public key.
	PublicKeyStatusAmbiguous PublicKeyStatus = "ambiguous"
	// PublicKeyStatusRevoked reports an explicitly empty DNS public key.
	PublicKeyStatusRevoked PublicKeyStatus = "revoked"
	// PublicKeyStatusUnsupportedKeyType reports an unrecognized DNS key type.
	PublicKeyStatusUnsupportedKeyType PublicKeyStatus = "unsupported_key_type"
	// PublicKeyStatusAlgorithmMismatch reports disagreement between requested algorithm and DNS key type.
	PublicKeyStatusAlgorithmMismatch PublicKeyStatus = "algorithm_mismatch"
)

// Known reports whether the status is in the closed provider vocabulary.
func (s PublicKeyStatus) Known() bool {
	switch s {
	case PublicKeyStatusFound, PublicKeyStatusMissing, PublicKeyStatusInvalid, PublicKeyStatusAmbiguous,
		PublicKeyStatusRevoked, PublicKeyStatusUnsupportedKeyType, PublicKeyStatusAlgorithmMismatch:
		return true
	default:
		return false
	}
}

// PublicKeyQuery contains only canonical values needed for injected key lookup.
type PublicKeyQuery struct {
	signingDomain string
	selector      string
	algorithm     Algorithm
}

// newPublicKeyQuery constructs an immutable query from parser-validated canonical values.
func newPublicKeyQuery(signingDomain, selector string, algorithm Algorithm) PublicKeyQuery {
	return PublicKeyQuery{
		signingDomain: signingDomain,
		selector:      selector,
		algorithm:     algorithm,
	}
}

// SigningDomain returns the canonical signing domain required for lookup.
func (q PublicKeyQuery) SigningDomain() string {
	return q.signingDomain
}

// Selector returns the canonical selector required for lookup.
func (q PublicKeyQuery) Selector() string {
	return q.selector
}

// Algorithm returns the bounded signature algorithm required for lookup.
func (q PublicKeyQuery) Algorithm() Algorithm {
	return q.algorithm
}

// PublicKeyResult is a closed immutable provider outcome with explicit public-key variants.
type PublicKeyResult struct {
	status     PublicKeyStatus
	algorithm  Algorithm
	rsaKey     *rsa.PublicKey
	ed25519Key ed25519.PublicKey
	metadata   KeyPolicyMetadata
}

// KeyPolicyMetadata carries bounded DNS key declarations without raw record data.
type KeyPolicyMetadata struct {
	testingDeclared        bool
	strictIdentityDeclared bool
}

// newKeyPolicyMetadata constructs immutable DNS policy metadata.
func newKeyPolicyMetadata(testingDeclared, strictIdentityDeclared bool) KeyPolicyMetadata {
	return KeyPolicyMetadata{testingDeclared: testingDeclared, strictIdentityDeclared: strictIdentityDeclared}
}

// TestingDeclared reports whether the DNS key record declared t=y.
func (m KeyPolicyMetadata) TestingDeclared() bool { return m.testingDeclared }

// StrictIdentityDeclared reports whether the DNS key record declared t=s.
func (m KeyPolicyMetadata) StrictIdentityDeclared() bool { return m.strictIdentityDeclared }

// StrictIdentityApplicable reports false because active DKIM2 i= is a numeric sequence.
func (m KeyPolicyMetadata) StrictIdentityApplicable() bool { return false }

// FoundRSAPublicKey constructs a found RSA-SHA256 result with cloned public material.
func FoundRSAPublicKey(key *rsa.PublicKey) PublicKeyResult {
	return PublicKeyResult{
		status:    PublicKeyStatusFound,
		algorithm: AlgorithmRSASHA256,
		rsaKey:    cloneRSAPublicKey(key),
	}
}

// FoundEd25519PublicKey constructs a found Ed25519-SHA256 result with cloned public material.
func FoundEd25519PublicKey(key ed25519.PublicKey) PublicKeyResult {
	return PublicKeyResult{
		status:     PublicKeyStatusFound,
		algorithm:  AlgorithmEd25519SHA256,
		ed25519Key: ed25519.PublicKey(bytes.Clone(key)),
	}
}

// MissingPublicKey constructs a key-not-found result without key material.
func MissingPublicKey(algorithm Algorithm) PublicKeyResult {
	return PublicKeyResult{status: PublicKeyStatusMissing, algorithm: algorithm}
}

// InvalidPublicKey constructs an invalid-key result without key material.
func InvalidPublicKey(algorithm Algorithm) PublicKeyResult {
	return PublicKeyResult{status: PublicKeyStatusInvalid, algorithm: algorithm}
}

// AmbiguousPublicKey constructs an ambiguous-key result without key material.
func AmbiguousPublicKey(algorithm Algorithm) PublicKeyResult {
	return PublicKeyResult{status: PublicKeyStatusAmbiguous, algorithm: algorithm}
}

// RevokedPublicKey constructs an explicitly revoked result without key material.
func RevokedPublicKey(algorithm Algorithm) PublicKeyResult {
	return PublicKeyResult{status: PublicKeyStatusRevoked, algorithm: algorithm}
}

// UnsupportedKeyTypePublicKey constructs an unsupported DNS key-type result without material.
func UnsupportedKeyTypePublicKey(algorithm Algorithm) PublicKeyResult {
	return PublicKeyResult{status: PublicKeyStatusUnsupportedKeyType, algorithm: algorithm}
}

// AlgorithmMismatchPublicKey constructs a requested-algorithm mismatch result without material.
func AlgorithmMismatchPublicKey(algorithm Algorithm) PublicKeyResult {
	return PublicKeyResult{status: PublicKeyStatusAlgorithmMismatch, algorithm: algorithm}
}

// withKeyPolicyMetadata attaches bounded DNS declarations to one provider result.
func withKeyPolicyMetadata(result PublicKeyResult, metadata KeyPolicyMetadata) PublicKeyResult {
	result.metadata = metadata
	return result
}

// Status returns the declared closed lookup outcome.
func (r PublicKeyResult) Status() PublicKeyStatus {
	return r.status
}

// Algorithm returns the declared bounded algorithm family.
func (r PublicKeyResult) Algorithm() Algorithm {
	return r.algorithm
}

// KeyPolicyMetadata returns immutable bounded DNS key declarations.
func (r PublicKeyResult) KeyPolicyMetadata() KeyPolicyMetadata { return r.metadata }

// RSAPublicKey returns an independent RSA public-key copy when that variant is present.
func (r PublicKeyResult) RSAPublicKey() (*rsa.PublicKey, bool) {
	if r.rsaKey == nil {
		return nil, false
	}

	return cloneRSAPublicKey(r.rsaKey), true
}

// Ed25519PublicKey returns an independent Ed25519 public-key copy when that variant is present.
func (r PublicKeyResult) Ed25519PublicKey() (ed25519.PublicKey, bool) {
	if r.ed25519Key == nil {
		return nil, false
	}

	return ed25519.PublicKey(bytes.Clone(r.ed25519Key)), true
}

// IsZero reports whether no declared provider outcome is present.
func (r PublicKeyResult) IsZero() bool {
	return r.status == "" && r.algorithm == "" && r.rsaKey == nil && r.ed25519Key == nil && r.metadata == (KeyPolicyMetadata{})
}

// PublicKeyProvider resolves static public-key intent without exposing provider-specific models.
//
// The legal return matrix is closed: a zero result may accompany either the
// active caller context error or a classified temporary or permanent provider
// error; a declared found, missing, invalid, or ambiguous result must accompany
// a nil error. Revoked, unsupported-key-type, and algorithm-mismatch results
// also carry no material and accompany nil error. Every other pair is a provider contract violation. Implementations
// must not place raw causes, provider metadata, private keys, or signer objects
// in either return value. A provider-owned deadline while the caller context is
// live is valid only when classified temporary; permanent or unclassified
// deadline errors are provider contract violations.
type PublicKeyProvider interface {
	LookupPublicKey(context.Context, PublicKeyQuery) (PublicKeyResult, error)
}

// cloneRSAPublicKey deep-clones RSA public material without retaining provider storage.
func cloneRSAPublicKey(key *rsa.PublicKey) *rsa.PublicKey {
	if key == nil {
		return nil
	}

	clone := &rsa.PublicKey{E: key.E}
	if key.N != nil {
		clone.N = new(big.Int).Set(key.N)
	}

	return clone
}
