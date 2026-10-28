package cryptodkim2

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"math/big"

	"github.com/croessner/dkim2/internal/signature"
)

const (
	// MinSigningRSABits is the local signing floor: new signing credentials
	// and loaded signing profiles require RSA moduli of at least 2048 bits
	// (Draft-08 Section 3.2 SHOULD made a local MUST). Verification keeps the
	// 1024 to 8192 bit bounds of Limits.
	MinSigningRSABits   = 2048
	hardMinRSABits      = 1024
	hardMaxRSABits      = 8192
	requiredRSAExponent = 65537
	// maxRSASignatureBytes is the rsa-sha256 value size of the largest
	// admitted 8192-bit modulus.
	maxRSASignatureBytes = hardMaxRSABits / 8
	// hardMaxSignatureBytes is the largest per-algorithm signature value:
	// the fixed 2420-octet mldsa44 signature. Every algorithm additionally
	// has its own exact or modulus-derived bound (see MaxSignatureBytesFor).
	hardMaxSignatureBytes = MLDSA44SignatureBytes
)

// Limits contains narrowable crypto policy and fixed algorithm contracts.
type Limits struct {
	// MinRSABits is the narrowable lower RSA modulus bound.
	MinRSABits int
	// MaxRSABits is the fixed upper RSA modulus bound.
	MaxRSABits int
	// RequiredRSAExponent is the fixed RSA public exponent.
	RequiredRSAExponent int
	// MaxSignatureBytes is the narrowable decoded signature-byte ceiling
	// across all algorithms. Narrowing it below an algorithm's exact size
	// makes that algorithm unusable for the narrowed contract.
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
	case signature.AlgorithmMLDSA44:
		key, ok := material.(*mldsa.PublicKey)
		if !ok {
			return nil, newError(ErrorCodeWrongKeyType)
		}
		if !validMLDSA44PublicKey(key) {
			return nil, newError(ErrorCodeInvalidKey)
		}
		return key, nil
	default:
		return nil, newError(ErrorCodeUnsupportedAlgorithm)
	}
}

// ExpectedSignatureBytes returns the exact decoded signature size one
// validated public key produces: the modulus size for RSA, 64 octets for
// Ed25519, and 2420 octets for ML-DSA-44. Other material reports false.
func ExpectedSignatureBytes(validated any) (int, bool) {
	switch key := validated.(type) {
	case *rsa.PublicKey:
		if key == nil || key.N == nil {
			return 0, false
		}
		return key.Size(), true
	case ed25519.PublicKey:
		return ed25519.SignatureSize, true
	case *mldsa.PublicKey:
		return MLDSA44SignatureBytes, validMLDSA44PublicKey(key)
	default:
		return 0, false
	}
}

// SigningKeyBelowFloor reports the modulus size of an RSA public key below
// MinSigningRSABits; other algorithms and keys at or above the floor report
// false.
func SigningKeyBelowFloor(material any) (int, bool) {
	key, ok := material.(*rsa.PublicKey)
	if !ok || key == nil || key.N == nil {
		return 0, false
	}
	bits := key.N.BitLen()
	return bits, bits < MinSigningRSABits
}

// MaxSignatureBytesFor returns the per-algorithm decoded signature bound:
// the modulus size of the largest admitted RSA key (1024 octets) for
// rsa-sha256, exactly 64 octets for ed25519-sha256, and exactly 2420 octets
// for mldsa44. Unknown algorithms have no bound and return zero.
func MaxSignatureBytesFor(algorithm signature.Algorithm) int {
	switch algorithm {
	case signature.AlgorithmRSASHA256:
		return maxRSASignatureBytes
	case signature.AlgorithmEd25519SHA256:
		return ed25519.SignatureSize
	case signature.AlgorithmMLDSA44:
		return MLDSA44SignatureBytes
	default:
		return 0
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
	if length <= 0 || length > resolved.MaxSignatureBytes || length > MaxSignatureBytesFor(algorithm) {
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
	case *mldsa.PublicKey:
		if length != MLDSA44SignatureBytes {
			return newError(ErrorCodeInvalidSignatureLength)
		}
	default:
		return newError(ErrorCodeWrongKeyType)
	}
	return nil
}

// VerifyRepresentative validates all inputs and verifies one signature over
// the algorithm's message representative of a Section 12.8 signature input
// (see MessageRepresentative): the 32-byte SHA-256 digest for rsa-sha256 and
// ed25519-sha256, and the complete input bytes for mldsa44, which uses pure
// ML-DSA.Verify (FIPS 204 Algorithm 3) with the context string "DKIM2".
func VerifyRepresentative(algorithm signature.Algorithm, material any, representative, signatureBytes []byte, limits Limits) error {
	if !ValidRepresentativeLength(algorithm, len(representative)) {
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
		if rsa.VerifyPKCS1v15(key, crypto.SHA256, representative, signatureBytes) != nil {
			return newError(ErrorCodeSignatureMismatch)
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(key, representative, signatureBytes) {
			return newError(ErrorCodeSignatureMismatch)
		}
	case *mldsa.PublicKey:
		if !verifyMLDSA44(key, representative, signatureBytes) {
			return newError(ErrorCodeSignatureMismatch)
		}
	default:
		return newError(ErrorCodeWrongKeyType)
	}
	return nil
}

// SelfVerifyRepresentative applies the same strict verification contract to
// a newly created signature.
func SelfVerifyRepresentative(algorithm signature.Algorithm, material any, representative, signatureBytes []byte, limits Limits) error {
	return VerifyRepresentative(algorithm, material, representative, signatureBytes, limits)
}

// ClonePublicKey returns detached supported key material or nil for unknown types.
func ClonePublicKey(material any) any {
	switch key := material.(type) {
	case *rsa.PublicKey:
		return cloneRSAKey(key)
	case ed25519.PublicKey:
		return ed25519.PublicKey(bytes.Clone(key))
	case *mldsa.PublicKey:
		// An *mldsa.PublicKey is immutable and safe for concurrent use, so
		// sharing it detaches as well as a copy and avoids re-expanding the
		// key on the verification path.
		if !validMLDSA44PublicKey(key) {
			return nil
		}
		return key
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

// MessageRepresentative returns the exact bytes algorithm passes to its
// signing or verification primitive for one Section 12.8 signature input. It
// is the single representative owner for signer and verifier:
//
//   - rsa-sha256 and ed25519-sha256 (Sections 3.2 and 3.3) sign the 32-byte
//     SHA-256 digest of the input;
//   - mldsa44 (Section 3.4) is pure ML-DSA: the input bytes are signed
//     directly without being hashed first, so the representative is a
//     detached copy of the complete input.
//
// Unknown algorithms and an empty input fail closed.
func MessageRepresentative(algorithm signature.Algorithm, input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, newError(ErrorCodeInvalidDigestLength)
	}
	switch {
	case !algorithm.Signable():
		return nil, newError(ErrorCodeUnsupportedAlgorithm)
	case SignsInputDirectly(algorithm):
		return bytes.Clone(input), nil
	default:
		sum := sha256.Sum256(input)
		return sum[:], nil
	}
}

// SignsInputDirectly reports whether algorithm signs the complete Section
// 12.8 input instead of its SHA-256 digest: true only for pure mldsa44
// (Section 3.4, "DKIM2 does not use HashML-DSA").
func SignsInputDirectly(algorithm signature.Algorithm) bool {
	return algorithm == signature.AlgorithmMLDSA44
}

// ValidRepresentativeLength reports whether length is a coherent message
// representative size for algorithm: exactly 32 octets (SHA-256) for
// rsa-sha256 and ed25519-sha256, and any nonempty Section 12.8 input for
// mldsa44. The caller bounds the input size before it is produced.
func ValidRepresentativeLength(algorithm signature.Algorithm, length int) bool {
	switch {
	case !algorithm.Signable():
		return false
	case SignsInputDirectly(algorithm):
		return length > 0
	default:
		return length == crypto.SHA256.Size()
	}
}

// PublicKeysEqual compares exact algorithm-specific public key material for
// every signable algorithm.
func PublicKeysEqual(left, right any) bool {
	switch l := left.(type) {
	case *rsa.PublicKey:
		r, ok := right.(*rsa.PublicKey)
		return ok && l != nil && r != nil && l.N != nil && r.N != nil && l.E == r.E && l.N.Cmp(r.N) == 0
	case ed25519.PublicKey:
		r, ok := right.(ed25519.PublicKey)
		return ok && len(l) == ed25519.PublicKeySize && bytes.Equal(l, r)
	case *mldsa.PublicKey:
		r, ok := right.(*mldsa.PublicKey)
		return ok && validMLDSA44PublicKey(l) && validMLDSA44PublicKey(r) && l.Equal(r)
	default:
		return false
	}
}

// ParseSigningPublicKeySPKI decodes one canonical SubjectPublicKeyInfo for a
// signable algorithm: a crypto/x509 encoding that round-trips byte for byte
// for rsa-sha256, ed25519-sha256, and mldsa44 (OID 2.16.840.1.101.3.4.3.17).
// Unknown algorithms fail closed; a parsed key of another type or ML-DSA
// parameter set is rejected by ValidatePublicKey. It is the single SPKI owner
// for stored signing credentials.
func ParseSigningPublicKeySPKI(algorithm signature.Algorithm, spki []byte) (any, error) {
	if !algorithm.Signable() {
		return nil, newError(ErrorCodeUnsupportedAlgorithm)
	}
	if algorithm == signature.AlgorithmMLDSA44 {
		if err := MLDSA44Available(); err != nil {
			return nil, err
		}
	}
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, newError(ErrorCodeInvalidKey)
	}
	canonical, err := x509.MarshalPKIXPublicKey(parsed)
	if err != nil || !bytes.Equal(canonical, spki) {
		return nil, newError(ErrorCodeInvalidKey)
	}
	return parsed, nil
}
