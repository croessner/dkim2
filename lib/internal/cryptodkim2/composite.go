package cryptodkim2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"sync"
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

// compositeAvailability caches the one-time ML-DSA-44 runtime probe.
var compositeAvailability = sync.OnceValue(func() bool {
	_, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), make([]byte, mldsa.PrivateKeySize))
	return err == nil
})

// CompositeAvailable reports an error when the cryptographic runtime cannot
// provide ML-DSA-44, for example under the Go FIPS 140-3 module v1.0.0.
func CompositeAvailable() error {
	if !compositeAvailability() {
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

// clone returns a detached copy of the composite key. The parsed ML-DSA
// public key is immutable and shared, so only the Ed25519 slice is copied and
// no key expansion is repeated on the verification hot path.
func (k CompositePublicKey) clone() CompositePublicKey {
	if !k.valid() {
		return CompositePublicKey{}
	}
	return CompositePublicKey{mldsa: k.mldsa, ed: ed25519.PublicKey(bytes.Clone(k.ed))}
}

// compositePrefix and compositeLabel are the fixed domain separators of the
// draft-ietf-lamps-pq-composite-sigs id-MLDSA44-Ed25519-SHA512 construction.
const (
	compositePrefix = "CompositeAlgorithmSignatures2025"
	compositeLabel  = "COMPSIG-MLDSA44-Ed25519-SHA512"
)

// compositeRepresentative builds the LAMPS message representative
// M' = Prefix || Label || len(ctx) || ctx || SHA-512(M) for the empty
// application context DKIM2 uses. digest is SHA-512 over the Section 12.8
// signature input.
func compositeRepresentative(digest []byte) []byte {
	representative := make([]byte, 0, len(compositePrefix)+len(compositeLabel)+1+len(digest))
	representative = append(representative, compositePrefix...)
	representative = append(representative, compositeLabel...)
	representative = append(representative, 0)
	return append(representative, digest...)
}

// verifyComposite verifies mldsa44-ed25519-sha512 under the
// draft-ietf-lamps-pq-composite-sigs construction that DNS-01 cites and that
// the DKIM2 interoperability round uses (Draft-07 Section 3.4 does not yet
// spell out the representative): ML-DSA-44 verifies the message
// representative with the composite label as its context, PureEd25519
// verifies the same representative, and the signature is the ML-DSA-44 value
// immediately followed by the Ed25519 value. Both halves must verify; there
// is no fallback to another construction.
func verifyComposite(key CompositePublicKey, digest, signatureBytes []byte) bool {
	if !key.valid() || len(signatureBytes) != CompositeSignatureBytes {
		return false
	}
	representative := compositeRepresentative(digest)
	mlOK := mldsa.Verify(key.mldsa, representative, signatureBytes[:mldsa44SignatureBytes], &mldsa.Options{Context: compositeLabel}) == nil
	edOK := ed25519.Verify(key.ed, representative, signatureBytes[mldsa44SignatureBytes:])
	return mlOK && edOK
}
