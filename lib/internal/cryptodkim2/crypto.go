package cryptodkim2

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"math/big"

	"github.com/croessner/dkim2/internal/signature"
)

const (
	hardMinRSABits        = 1024
	hardMaxRSABits        = 8192
	requiredRSAExponent   = 65537
	hardMaxSignatureBytes = 1024
)

// Limits contains narrowable crypto policy and fixed algorithm contracts.
type Limits struct {
	// MinRSABits is the narrowable lower RSA modulus bound.
	MinRSABits int
	// MaxRSABits is the fixed upper RSA modulus bound.
	MaxRSABits int
	// RequiredRSAExponent is the fixed RSA public exponent.
	RequiredRSAExponent int
	// MaxSignatureBytes is the fixed encoded signature-byte ceiling.
	MaxSignatureBytes int
}

// DefaultLimits returns the exact shared DKIM2 cryptographic limits.
func DefaultLimits() Limits {
	return Limits{
		MinRSABits: hardMinRSABits, MaxRSABits: hardMaxRSABits,
		RequiredRSAExponent: requiredRSAExponent, MaxSignatureBytes: hardMaxSignatureBytes,
	}
}

// Validate rejects widened or incoherent cryptographic limits.
func (l Limits) Validate() error {
	if l.MinRSABits < hardMinRSABits || l.MaxRSABits > hardMaxRSABits || l.MinRSABits > l.MaxRSABits ||
		l.RequiredRSAExponent != requiredRSAExponent || l.MaxSignatureBytes <= 0 || l.MaxSignatureBytes > hardMaxSignatureBytes ||
		l.MaxSignatureBytes < (l.MaxRSABits+7)/8 {
		return newError(ErrorCodeInvalidOptions)
	}
	return nil
}

// normalized fills zero limits with restrictive defaults.
func (l Limits) normalized() (Limits, error) {
	defaults := DefaultLimits()
	if l.MinRSABits == 0 {
		l.MinRSABits = defaults.MinRSABits
	}
	if l.MaxRSABits == 0 {
		l.MaxRSABits = defaults.MaxRSABits
	}
	if l.RequiredRSAExponent == 0 {
		l.RequiredRSAExponent = defaults.RequiredRSAExponent
	}
	if l.MaxSignatureBytes == 0 {
		l.MaxSignatureBytes = defaults.MaxSignatureBytes
	}
	if err := l.Validate(); err != nil {
		return Limits{}, err
	}
	return l, nil
}

// ValidatePublicKey validates algorithm matching and returns detached key material.
func ValidatePublicKey(algorithm signature.Algorithm, material any, limits Limits) (any, error) {
	resolved, err := limits.normalized()
	if err != nil {
		return nil, err
	}
	if !algorithm.Known() {
		return nil, newError(ErrorCodeUnsupportedAlgorithm)
	}
	switch algorithm {
	case signature.AlgorithmRSASHA256:
		key, ok := material.(*rsa.PublicKey)
		if !ok {
			return nil, newError(ErrorCodeWrongKeyType)
		}
		if !ValidRSAPublicKeyStructure(key) {
			return nil, newError(ErrorCodeInvalidKey)
		}
		bits := key.N.BitLen()
		if key.E != resolved.RequiredRSAExponent || bits < resolved.MinRSABits || bits > resolved.MaxRSABits {
			return nil, newError(ErrorCodeKeyPolicyRejected)
		}
		return cloneRSAKey(key), nil
	case signature.AlgorithmEd25519SHA256:
		key, ok := material.(ed25519.PublicKey)
		if !ok {
			return nil, newError(ErrorCodeWrongKeyType)
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, newError(ErrorCodeInvalidKey)
		}
		return ed25519.PublicKey(bytes.Clone(key)), nil
	default:
		return nil, newError(ErrorCodeUnsupportedAlgorithm)
	}
}

// ValidRSAPublicKeyStructure reports whether key satisfies basic RFC 8017 shape invariants.
func ValidRSAPublicKeyStructure(key *rsa.PublicKey) bool {
	return key != nil && key.N != nil && key.N.Sign() > 0 && key.N.Bit(0) == 1 &&
		key.E >= 3 && key.E%2 == 1 && big.NewInt(int64(key.E)).Cmp(key.N) < 0
}

// ValidateSignatureLength enforces algorithm-specific completed signature lengths.
func ValidateSignatureLength(algorithm signature.Algorithm, material any, length int, limits Limits) error {
	resolved, err := limits.normalized()
	if err != nil {
		return err
	}
	if length <= 0 || length > resolved.MaxSignatureBytes {
		return newError(ErrorCodeInvalidSignatureLength)
	}
	validated, err := ValidatePublicKey(algorithm, material, resolved)
	if err != nil {
		return err
	}
	return validateSignatureLengthValidated(algorithm, validated, length, resolved)
}

// validateSignatureLengthValidated checks length after key validation and detachment.
func validateSignatureLengthValidated(algorithm signature.Algorithm, validated any, length int, resolved Limits) error {
	if !algorithm.Known() {
		return newError(ErrorCodeUnsupportedAlgorithm)
	}
	if length <= 0 || length > resolved.MaxSignatureBytes {
		return newError(ErrorCodeInvalidSignatureLength)
	}
	switch key := validated.(type) {
	case *rsa.PublicKey:
		if length != key.Size() {
			return newError(ErrorCodeInvalidSignatureLength)
		}
	case ed25519.PublicKey:
		if length != ed25519.SignatureSize {
			return newError(ErrorCodeInvalidSignatureLength)
		}
	default:
		return newError(ErrorCodeWrongKeyType)
	}
	return nil
}

// VerifyDigest validates all inputs and verifies one SHA-256 digest signature.
func VerifyDigest(algorithm signature.Algorithm, material any, digest, signatureBytes []byte, limits Limits) error {
	if len(digest) != crypto.SHA256.Size() {
		return newError(ErrorCodeInvalidDigestLength)
	}
	resolved, err := limits.normalized()
	if err != nil {
		return err
	}
	validated, err := ValidatePublicKey(algorithm, material, resolved)
	if err != nil {
		return err
	}
	if err := validateSignatureLengthValidated(algorithm, validated, len(signatureBytes), resolved); err != nil {
		return err
	}
	switch key := validated.(type) {
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, signatureBytes) != nil {
			return newError(ErrorCodeSignatureMismatch)
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(key, digest, signatureBytes) {
			return newError(ErrorCodeSignatureMismatch)
		}
	default:
		return newError(ErrorCodeWrongKeyType)
	}
	return nil
}

// SelfVerifyDigest applies the same strict verification contract to a newly created signature.
func SelfVerifyDigest(algorithm signature.Algorithm, material any, digest, signatureBytes []byte, limits Limits) error {
	return VerifyDigest(algorithm, material, digest, signatureBytes, limits)
}

// ClonePublicKey returns detached supported key material or nil for unknown types.
func ClonePublicKey(material any) any {
	switch key := material.(type) {
	case *rsa.PublicKey:
		return cloneRSAKey(key)
	case ed25519.PublicKey:
		return ed25519.PublicKey(bytes.Clone(key))
	default:
		return nil
	}
}

// cloneRSAKey returns one detached RSA public key.
func cloneRSAKey(key *rsa.PublicKey) *rsa.PublicKey {
	if key == nil || key.N == nil {
		return nil
	}
	return &rsa.PublicKey{N: new(big.Int).Set(key.N), E: key.E}
}
