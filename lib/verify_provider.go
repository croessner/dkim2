package dkim2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
)

const (
	publicKeyQueryRedactedText  = "dkim2.PublicKeyQuery{redacted}"
	publicKeyResultRedactedText = "dkim2.PublicKeyResult{redacted}"
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
	state *publicKeyQueryState
}

type publicKeyQueryState struct {
	signingDomain string
	selector      string
	algorithm     Algorithm
}

// newPublicKeyQuery constructs an immutable query from parser-validated canonical values.
func newPublicKeyQuery(signingDomain, selector string, algorithm Algorithm) PublicKeyQuery {
	return PublicKeyQuery{
		state: &publicKeyQueryState{
			signingDomain: signingDomain,
			selector:      selector,
			algorithm:     algorithm,
		},
	}
}

// SigningDomain returns the canonical signing domain required for lookup.
func (q PublicKeyQuery) SigningDomain() string {
	if q.state == nil {
		return ""
	}
	return q.state.signingDomain
}

// Selector returns the canonical selector required for lookup.
func (q PublicKeyQuery) Selector() string {
	if q.state == nil {
		return ""
	}
	return q.state.selector
}

// Algorithm returns the bounded signature algorithm required for lookup.
func (q PublicKeyQuery) Algorithm() Algorithm {
	if q.state == nil {
		return ""
	}
	return q.state.algorithm
}

// String returns a constant representation without DNS owner identifiers.
func (PublicKeyQuery) String() string { return publicKeyQueryRedactedText }

// GoString returns a constant representation without DNS owner identifiers.
func (PublicKeyQuery) GoString() string { return publicKeyQueryRedactedText }

// Format prevents formatting from traversing DNS owner identifiers.
func (PublicKeyQuery) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, publicKeyQueryRedactedText)
}

// MarshalJSON rejects serialization of DNS query identifiers.
func (PublicKeyQuery) MarshalJSON() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// MarshalText rejects diagnostic serialization of DNS query identifiers.
func (PublicKeyQuery) MarshalText() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// PublicKeyResult is a closed immutable provider outcome with explicit public-key variants.
type PublicKeyResult struct {
	state *publicKeyResultState
}

type publicKeyResultState struct {
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
	return PublicKeyResult{state: &publicKeyResultState{
		status:    PublicKeyStatusFound,
		algorithm: AlgorithmRSASHA256,
		rsaKey:    cloneRSAPublicKey(key),
	}}
}

// FoundEd25519PublicKey constructs a found Ed25519-SHA256 result with cloned public material.
func FoundEd25519PublicKey(key ed25519.PublicKey) PublicKeyResult {
	return PublicKeyResult{state: &publicKeyResultState{
		status:     PublicKeyStatusFound,
		algorithm:  AlgorithmEd25519SHA256,
		ed25519Key: ed25519.PublicKey(bytes.Clone(key)),
	}}
}

// MissingPublicKey constructs a key-not-found result without key material.
func MissingPublicKey(algorithm Algorithm) PublicKeyResult {
	return newPublicKeyResult(PublicKeyStatusMissing, algorithm)
}

// InvalidPublicKey constructs an invalid-key result without key material.
func InvalidPublicKey(algorithm Algorithm) PublicKeyResult {
	return newPublicKeyResult(PublicKeyStatusInvalid, algorithm)
}

// AmbiguousPublicKey constructs an ambiguous-key result without key material.
func AmbiguousPublicKey(algorithm Algorithm) PublicKeyResult {
	return newPublicKeyResult(PublicKeyStatusAmbiguous, algorithm)
}

// RevokedPublicKey constructs an explicitly revoked result without key material.
func RevokedPublicKey(algorithm Algorithm) PublicKeyResult {
	return newPublicKeyResult(PublicKeyStatusRevoked, algorithm)
}

// UnsupportedKeyTypePublicKey constructs an unsupported DNS key-type result without material.
func UnsupportedKeyTypePublicKey(algorithm Algorithm) PublicKeyResult {
	return newPublicKeyResult(PublicKeyStatusUnsupportedKeyType, algorithm)
}

// AlgorithmMismatchPublicKey constructs a requested-algorithm mismatch result without material.
func AlgorithmMismatchPublicKey(algorithm Algorithm) PublicKeyResult {
	return newPublicKeyResult(PublicKeyStatusAlgorithmMismatch, algorithm)
}

// newPublicKeyResult constructs one material-free provider outcome.
func newPublicKeyResult(status PublicKeyStatus, algorithm Algorithm) PublicKeyResult {
	return PublicKeyResult{state: &publicKeyResultState{status: status, algorithm: algorithm}}
}

// withKeyPolicyMetadata attaches bounded DNS declarations to one provider result.
func withKeyPolicyMetadata(result PublicKeyResult, metadata KeyPolicyMetadata) PublicKeyResult {
	if result.state == nil {
		return result
	}
	state := *result.state
	state.metadata = metadata
	return PublicKeyResult{state: &state}
}

// Status returns the declared closed lookup outcome.
func (r PublicKeyResult) Status() PublicKeyStatus {
	if r.state == nil {
		return ""
	}
	return r.state.status
}

// Algorithm returns the declared bounded algorithm family.
func (r PublicKeyResult) Algorithm() Algorithm {
	if r.state == nil {
		return ""
	}
	return r.state.algorithm
}

// KeyPolicyMetadata returns immutable bounded DNS key declarations.
func (r PublicKeyResult) KeyPolicyMetadata() KeyPolicyMetadata {
	if r.state == nil {
		return KeyPolicyMetadata{}
	}
	return r.state.metadata
}

// RSAPublicKey returns an independent RSA public-key copy when that variant is present.
func (r PublicKeyResult) RSAPublicKey() (*rsa.PublicKey, bool) {
	if r.state == nil || r.state.rsaKey == nil {
		return nil, false
	}

	return cloneRSAPublicKey(r.state.rsaKey), true
}

// Ed25519PublicKey returns an independent Ed25519 public-key copy when that variant is present.
func (r PublicKeyResult) Ed25519PublicKey() (ed25519.PublicKey, bool) {
	if r.state == nil || r.state.ed25519Key == nil {
		return nil, false
	}

	return ed25519.PublicKey(bytes.Clone(r.state.ed25519Key)), true
}

// IsZero reports whether no declared provider outcome is present.
func (r PublicKeyResult) IsZero() bool {
	return r.state == nil
}

// String returns a constant representation without public-key material.
func (PublicKeyResult) String() string { return publicKeyResultRedactedText }

// GoString returns a constant representation without public-key material.
func (PublicKeyResult) GoString() string { return publicKeyResultRedactedText }

// Format prevents formatting from traversing public-key material.
func (PublicKeyResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, publicKeyResultRedactedText)
}

// MarshalJSON rejects serialization of provider result material.
func (PublicKeyResult) MarshalJSON() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// MarshalText rejects diagnostic serialization of provider result material.
func (PublicKeyResult) MarshalText() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
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
