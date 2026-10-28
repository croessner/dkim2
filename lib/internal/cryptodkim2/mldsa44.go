package cryptodkim2

import (
	"crypto/mldsa"
	"sync"
)

const (
	// MLDSA44PublicKeyBytes is the exact FIPS 204 ML-DSA-44 public-key size.
	// Draft-08 Section 14.5: any other length is a malformed key.
	MLDSA44PublicKeyBytes = mldsa.MLDSA44PublicKeySize
	// MLDSA44SignatureBytes is the exact FIPS 204 ML-DSA-44 signature size
	// (3228 base64 characters, Draft-08 Section 3.4).
	MLDSA44SignatureBytes = mldsa.MLDSA44SignatureSize
	// MLDSA44Context is the Draft-08 Section 3.4 ML-DSA context string: the
	// five ASCII octets "DKIM2" without terminator, used for signing and
	// verifying.
	MLDSA44Context = "DKIM2"
)

// mldsa44Availability caches the one-time ML-DSA-44 runtime probe. The
// FIPS 140-3 Go Cryptographic Module v1.0.0 does not provide ML-DSA, so
// key construction fails there.
var mldsa44Availability = sync.OnceValue(func() bool {
	seed := make([]byte, mldsa.PrivateKeySize)
	seed[0] = 1
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	clear(seed)
	if err != nil {
		return false
	}
	public, err := mldsa.NewPublicKey(mldsa.MLDSA44(), key.PublicKey().Bytes())
	return err == nil && public.Equal(key.PublicKey())
})

// MLDSA44Available reports ErrorCodeAlgorithmUnavailable when the
// cryptographic runtime cannot provide ML-DSA-44, for example a binary built
// against the FIPS 140-3 Go Cryptographic Module v1.0.0. Every surface that
// enables mldsa44 (verifier algorithm policy, signing credentials, stored
// public keys) calls it so the feature fails closed at construction instead
// of silently degrading.
func MLDSA44Available() error {
	if !mldsa44Availability() {
		return newError(ErrorCodeAlgorithmUnavailable)
	}
	return nil
}

// ParseMLDSA44PublicKey decodes the raw FIPS 204 ML-DSA-44 public-key
// encoding carried in DNS p= values and returns an immutable key. Any length
// other than exactly 1312 octets, or an encoding crypto/mldsa rejects, is
// ErrorCodeInvalidKey; an unavailable runtime is
// ErrorCodeAlgorithmUnavailable.
func ParseMLDSA44PublicKey(raw []byte) (*mldsa.PublicKey, error) {
	if err := MLDSA44Available(); err != nil {
		return nil, err
	}
	if len(raw) != MLDSA44PublicKeyBytes {
		return nil, newError(ErrorCodeInvalidKey)
	}
	key, err := mldsa.NewPublicKey(mldsa.MLDSA44(), raw)
	if err != nil {
		return nil, newError(ErrorCodeInvalidKey)
	}
	return key, nil
}

// MLDSA44SignerOptions returns the signing options every mldsa44 signer uses:
// pure ML-DSA.Sign over the message representative with the Draft-08
// Section 3.4 context string "DKIM2". A custody signer passes them to the
// hedged (randomized) crypto/mldsa PrivateKey.Sign; the deterministic variant
// is not used in production.
func MLDSA44SignerOptions() *mldsa.Options {
	return &mldsa.Options{Context: MLDSA44Context}
}

// validMLDSA44PublicKey reports whether key is a non-nil ML-DSA-44 key.
// crypto/mldsa only constructs keys from exact-size encodings, so the
// parameter set fixes the 1312-octet encoding.
func validMLDSA44PublicKey(key *mldsa.PublicKey) bool {
	return key != nil && key.Parameters() == mldsa.MLDSA44()
}

// verifyMLDSA44 verifies one pure ML-DSA-44 signature (FIPS 204 Algorithm 3)
// over the complete Section 12.8 input with the "DKIM2" context string.
func verifyMLDSA44(key *mldsa.PublicKey, input, signatureBytes []byte) bool {
	if !validMLDSA44PublicKey(key) || len(signatureBytes) != MLDSA44SignatureBytes {
		return false
	}
	return mldsa.Verify(key, input, signatureBytes, MLDSA44SignerOptions()) == nil
}
