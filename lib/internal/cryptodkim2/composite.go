package cryptodkim2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
)

const (
	// mldsa44PublicKeyBytes is the FIPS 204 ML-DSA-44 public key size.
	mldsa44PublicKeyBytes = 1312
	// mldsa44SignatureBytes is the FIPS 204 ML-DSA-44 signature size.
	mldsa44SignatureBytes = 2420
	// CompositePublicKeyBytes is the raw DNS p= size of an
	// mldsa44-ed25519-sha512 key: the ML-DSA-44 public key followed by the
	// Ed25519 public key.
	CompositePublicKeyBytes = mldsa44PublicKeyBytes + ed25519.PublicKeySize
	// CompositeSignatureBytes is the mldsa44-ed25519-sha512 signature size:
	// the ML-DSA-44 signature followed by the Ed25519 signature.
	CompositeSignatureBytes = mldsa44SignatureBytes + ed25519.SignatureSize
)

// CompositeAvailable reports an error when the cryptographic runtime cannot
// provide ML-DSA-44, for example under the Go FIPS 140-3 module v1.0.0.
func CompositeAvailable() error {
	if _, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), make([]byte, mldsa.PrivateKeySize)); err != nil {
		return newError(ErrorCodeUnsupportedAlgorithm)
	}
	return nil
}

// CompositePublicKey is one detached mldsa44-ed25519-sha512 public key. It
// owns both component keys and is immutable after construction.
type CompositePublicKey struct {
	mldsa *mldsa.PublicKey
	ed    ed25519.PublicKey
}

// ParseCompositePublicKey decodes the raw component concatenation used in
// DNS p= values. It requires exactly the ML-DSA-44 key size plus the Ed25519
// key size; an SPKI wrapper, another ML-DSA parameter set, or trailing bytes
// fail.
func ParseCompositePublicKey(raw []byte) (CompositePublicKey, error) {
	if len(raw) != CompositePublicKeyBytes {
		return CompositePublicKey{}, newError(ErrorCodeInvalidKey)
	}
	mlKey, err := mldsa.NewPublicKey(mldsa.MLDSA44(), raw[:mldsa44PublicKeyBytes])
	if err != nil {
		return CompositePublicKey{}, newError(ErrorCodeInvalidKey)
	}
	return CompositePublicKey{mldsa: mlKey, ed: ed25519.PublicKey(bytes.Clone(raw[mldsa44PublicKeyBytes:]))}, nil
}

// Bytes returns the raw component concatenation of the composite key.
func (k CompositePublicKey) Bytes() []byte {
	if !k.valid() {
		return nil
	}
	return append(k.mldsa.Bytes(), k.ed...)
}

// valid reports whether both component keys are present and sized.
func (k CompositePublicKey) valid() bool {
	return k.mldsa != nil && len(k.ed) == ed25519.PublicKeySize
}

// clone returns a detached copy of the composite key.
func (k CompositePublicKey) clone() CompositePublicKey {
	if !k.valid() {
		return CompositePublicKey{}
	}
	parsed, err := ParseCompositePublicKey(k.Bytes())
	if err != nil {
		return CompositePublicKey{}
	}
	return parsed
}

// verifyComposite applies Draft-07 Section 3.4: pure ML-DSA-44 with an empty
// application context and PureEd25519 both verify the same 64-byte SHA-512
// digest, and the signature is the ML-DSA-44 value immediately followed by
// the Ed25519 value. Both halves must verify; there is no fallback to another
// composite construction. The DNS-01 reference to the LAMPS composite
// construction conflicts with this procedure and is a documented limitation.
func verifyComposite(key CompositePublicKey, digest, signatureBytes []byte) bool {
	if !key.valid() || len(signatureBytes) != CompositeSignatureBytes {
		return false
	}
	mlOK := mldsa.Verify(key.mldsa, digest, signatureBytes[:mldsa44SignatureBytes], &mldsa.Options{}) == nil
	edOK := ed25519.Verify(key.ed, digest, signatureBytes[mldsa44SignatureBytes:])
	return mlOK && edOK
}
