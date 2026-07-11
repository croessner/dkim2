package keyresolver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"math/big"

	"github.com/croessner/dkim2/internal/verify"
)

// KeyOutcomeStatus identifies one closed structural key-decoding result.
type KeyOutcomeStatus string

const (
	// KeyOutcomeFound reports detached structurally valid public-key material.
	KeyOutcomeFound KeyOutcomeStatus = "found"
	// KeyOutcomeRevoked reports an explicitly empty DNS p= value.
	KeyOutcomeRevoked KeyOutcomeStatus = "revoked"
	// KeyOutcomeInvalid reports malformed supported public-key material.
	KeyOutcomeInvalid KeyOutcomeStatus = "invalid"
	// KeyOutcomeUnsupportedKeyType reports an unrecognized but syntactically valid k= value.
	KeyOutcomeUnsupportedKeyType KeyOutcomeStatus = "unsupported_key_type"
	// KeyOutcomeAlgorithmMismatch reports disagreement between requested algorithm and supported k=.
	KeyOutcomeAlgorithmMismatch KeyOutcomeStatus = "algorithm_mismatch"
	// KeyOutcomeMissing reports authoritative DNS name or data absence.
	KeyOutcomeMissing KeyOutcomeStatus = "missing"
	// KeyOutcomeAmbiguous reports multiple usable TXT resource records.
	KeyOutcomeAmbiguous KeyOutcomeStatus = "ambiguous"
	// KeyOutcomeTemporary reports an explicitly typed retryable transport failure.
	KeyOutcomeTemporary KeyOutcomeStatus = "temporary"
	// KeyOutcomePermanent reports an explicitly typed stable local failure.
	KeyOutcomePermanent KeyOutcomeStatus = "permanent"
	// KeyOutcomeProviderContract reports contradictory or unclassified injected state.
	KeyOutcomeProviderContract KeyOutcomeStatus = "provider_contract"
)

// Known reports whether the status belongs to the closed decoder vocabulary.
func (s KeyOutcomeStatus) Known() bool {
	switch s {
	case KeyOutcomeFound, KeyOutcomeRevoked, KeyOutcomeInvalid, KeyOutcomeUnsupportedKeyType, KeyOutcomeAlgorithmMismatch,
		KeyOutcomeMissing, KeyOutcomeAmbiguous, KeyOutcomeTemporary, KeyOutcomePermanent, KeyOutcomeProviderContract:
		return true
	default:
		return false
	}
}

// KeyOutcome stores detached key material or one exact permanent non-success state.
type KeyOutcome struct {
	status      KeyOutcomeStatus
	algorithm   Algorithm
	material    any
	metadata    Metadata
	initialized bool
}

// Status returns the closed structural decoding result.
func (o KeyOutcome) Status() KeyOutcomeStatus { return o.status }

// Algorithm returns the requested supported verification algorithm.
func (o KeyOutcome) Algorithm() Algorithm { return o.algorithm }

// Material returns an independent copy of supported public-key material.
func (o KeyOutcome) Material() any { return cloneKeyMaterial(o.material) }

// Metadata returns immutable bounded DNS key declarations.
func (o KeyOutcome) Metadata() Metadata { return o.metadata }

// Valid reports whether the outcome is initialized and internally coherent.
func (o KeyOutcome) Valid() bool {
	if !o.initialized || !o.status.Known() || !o.algorithm.Known() || !o.metadata.Valid() {
		return false
	}
	switch o.status {
	case KeyOutcomeFound:
		switch o.algorithm {
		case AlgorithmRSASHA256:
			key, ok := o.material.(*rsa.PublicKey)
			return ok && verify.ValidRSAPublicKeyStructure(key)
		case AlgorithmEd25519SHA256:
			key, ok := o.material.(ed25519.PublicKey)
			return ok && len(key) == ed25519.PublicKeySize
		default:
			return false
		}
	case KeyOutcomeRevoked, KeyOutcomeInvalid, KeyOutcomeUnsupportedKeyType, KeyOutcomeAlgorithmMismatch,
		KeyOutcomeMissing, KeyOutcomeAmbiguous, KeyOutcomeTemporary, KeyOutcomePermanent, KeyOutcomeProviderContract:
		return o.material == nil
	default:
		return false
	}
}

// IsZero reports whether the outcome carries no initialized resolver state.
func (o KeyOutcome) IsZero() bool {
	return !o.initialized && o.status == "" && o.algorithm == "" && o.material == nil && !o.metadata.Valid()
}

// newStatusOutcome constructs one material-free initialized resolver result.
func newStatusOutcome(status KeyOutcomeStatus, algorithm Algorithm, metadata Metadata) KeyOutcome {
	return KeyOutcome{status: status, algorithm: algorithm, metadata: metadata, initialized: true}
}

// DecodeKey decodes one parsed DNS record for a supported requested algorithm.
func DecodeKey(record Record, requested Algorithm) (KeyOutcome, error) {
	if !record.Valid() || !requested.Known() {
		return KeyOutcome{}, newResolverError(ErrorClassContract)
	}
	base := KeyOutcome{algorithm: requested, metadata: record.Metadata(), initialized: true}
	switch record.Status() {
	case RecordStatusRevoked:
		base.status = KeyOutcomeRevoked
		return base, nil
	case RecordStatusUnsupportedKeyType:
		base.status = KeyOutcomeUnsupportedKeyType
		return base, nil
	case RecordStatusKeyData:
	default:
		return KeyOutcome{}, newResolverError(ErrorClassContract)
	}
	if !keyTypeMatchesAlgorithm(record.KeyType(), requested) {
		base.status = KeyOutcomeAlgorithmMismatch
		return base, nil
	}

	data := record.PublicKeyData()
	switch requested {
	case AlgorithmRSASHA256:
		key, err := x509.ParsePKCS1PublicKey(data)
		if err != nil || !verify.ValidRSAPublicKeyStructure(key) {
			base.status = KeyOutcomeInvalid
			return base, nil
		}
		base.status = KeyOutcomeFound
		base.material = cloneRSAKey(key)
		return base, nil
	case AlgorithmEd25519SHA256:
		if len(data) != ed25519.PublicKeySize {
			base.status = KeyOutcomeInvalid
			return base, nil
		}
		base.status = KeyOutcomeFound
		base.material = ed25519.PublicKey(bytes.Clone(data))
		return base, nil
	default:
		return KeyOutcome{}, newResolverError(ErrorClassContract)
	}
}

// keyTypeMatchesAlgorithm reports exact supported algorithm and DNS k= coherence.
func keyTypeMatchesAlgorithm(keyType KeyType, algorithm Algorithm) bool {
	return keyType == KeyTypeRSA && algorithm == AlgorithmRSASHA256 ||
		keyType == KeyTypeEd25519 && algorithm == AlgorithmEd25519SHA256
}

// cloneKeyMaterial returns a detached copy of supported key material.
func cloneKeyMaterial(material any) any {
	switch key := material.(type) {
	case *rsa.PublicKey:
		return cloneRSAKey(key)
	case ed25519.PublicKey:
		return ed25519.PublicKey(bytes.Clone(key))
	default:
		return nil
	}
}

// cloneRSAKey returns an independent RSA public key.
func cloneRSAKey(key *rsa.PublicKey) *rsa.PublicKey {
	if key == nil || key.N == nil {
		return nil
	}
	return &rsa.PublicKey{N: new(big.Int).Set(key.N), E: key.E}
}
