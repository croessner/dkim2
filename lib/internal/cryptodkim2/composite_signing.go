package cryptodkim2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"io"

	"github.com/croessner/dkim2/internal/signature"
)

const (
	// compositeSeedBytes is the size of each component seed: the FIPS 204
	// ML-DSA-44 seed xi and the RFC 8032 Ed25519 seed.
	compositeSeedBytes = 32
	// CompositePrivateKeyBytes is the raw composite private key: the ML-DSA-44
	// seed followed by the Ed25519 seed.
	CompositePrivateKeyBytes = 2 * compositeSeedBytes
)

// compositePKCS8Prefix is the fixed DER prefix of an id-MLDSA44-Ed25519-SHA512
// (OID 1.3.6.1.5.5.7.6.39) PKCS#8 OneAsymmetricKey whose privateKey OCTET
// STRING holds the 64-byte seed concatenation.
var compositePKCS8Prefix = []byte{
	0x30, 0x51, 0x02, 0x01, 0x00, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06,
	0x27, 0x04, 0x40,
}

// compositeSPKIPrefix is the fixed DER prefix of an id-MLDSA44-Ed25519-SHA512
// SubjectPublicKeyInfo whose BIT STRING holds the raw 1344-byte public key.
var compositeSPKIPrefix = []byte{
	0x30, 0x82, 0x05, 0x51, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x27,
	0x03, 0x82, 0x05, 0x41, 0x00,
}

// CompositePrivateKey is one mldsa44-ed25519-sha512 signing key. It owns both
// expanded component keys and the seeds they derive from; the zero value is
// invalid.
type CompositePrivateKey struct {
	mldsa *mldsa.PrivateKey
	ed    ed25519.PrivateKey
	seeds []byte
}

// NewCompositePrivateKey derives a composite key from the 64-byte seed
// concatenation (ML-DSA-44 seed, then Ed25519 seed). The input is copied.
func NewCompositePrivateKey(seeds []byte) (CompositePrivateKey, error) {
	if len(seeds) != CompositePrivateKeyBytes {
		return CompositePrivateKey{}, newError(ErrorCodeInvalidKey)
	}
	mlKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seeds[:compositeSeedBytes])
	if err != nil {
		return CompositePrivateKey{}, newError(ErrorCodeInvalidKey)
	}
	return CompositePrivateKey{
		mldsa: mlKey,
		ed:    ed25519.NewKeyFromSeed(seeds[compositeSeedBytes:]),
		seeds: bytes.Clone(seeds),
	}, nil
}

// GenerateCompositePrivateKey creates a fresh composite key from the system
// random source.
func GenerateCompositePrivateKey() (CompositePrivateKey, error) {
	seeds := make([]byte, CompositePrivateKeyBytes)
	defer clear(seeds)
	if _, err := io.ReadFull(rand.Reader, seeds); err != nil {
		return CompositePrivateKey{}, newError(ErrorCodeInvalidKey)
	}
	return NewCompositePrivateKey(seeds)
}

// ParseCompositePKCS8 decodes the exact id-MLDSA44-Ed25519-SHA512 PKCS#8
// encoding. Any other algorithm, extra attributes, or trailing bytes fail.
func ParseCompositePKCS8(der []byte) (CompositePrivateKey, error) {
	if len(der) != len(compositePKCS8Prefix)+CompositePrivateKeyBytes || !bytes.HasPrefix(der, compositePKCS8Prefix) {
		return CompositePrivateKey{}, newError(ErrorCodeInvalidKey)
	}
	return NewCompositePrivateKey(der[len(compositePKCS8Prefix):])
}

// MarshalPKCS8 returns the exact id-MLDSA44-Ed25519-SHA512 PKCS#8 encoding.
// The result carries secret seed material and must be cleared by the caller.
func (k CompositePrivateKey) MarshalPKCS8() []byte {
	if !k.valid() {
		return nil
	}
	return append(bytes.Clone(compositePKCS8Prefix), k.seeds...)
}

// PublicKey returns the composite public key of k.
func (k CompositePrivateKey) PublicKey() CompositePublicKey {
	if !k.valid() {
		return CompositePublicKey{}
	}
	return CompositePublicKey{mldsa: k.mldsa.PublicKey(), ed: bytes.Clone(k.ed.Public().(ed25519.PublicKey))}
}

// Clear overwrites the retained seeds and Ed25519 key. The expanded ML-DSA-44
// key is owned by crypto/mldsa and cannot be zeroed; it is only released with
// k, so Clear is not a complete scrub of derived key material. Copies of k
// share the seed and Ed25519 backing arrays.
func (k *CompositePrivateKey) Clear() {
	if k == nil {
		return
	}
	clear(k.seeds)
	clear(k.ed)
	*k = CompositePrivateKey{}
}

// valid reports whether both component keys and their seeds are present.
func (k CompositePrivateKey) valid() bool {
	return k.mldsa != nil && len(k.ed) == ed25519.PrivateKeySize && len(k.seeds) == CompositePrivateKeyBytes
}

// SignCompositeDigest signs one 64-byte SHA-512 digest of the Section 12.8
// signature input under the draft-ietf-lamps-pq-composite-sigs
// id-MLDSA44-Ed25519-SHA512 construction: ML-DSA-44 signs the message
// representative with the composite label as its context (hedged, with fresh
// randomness), PureEd25519 signs the same representative, and the result is
// the ML-DSA-44 signature immediately followed by the Ed25519 signature. The
// signature is self-verified before it is returned.
func SignCompositeDigest(key CompositePrivateKey, digest []byte) ([]byte, error) {
	if !key.valid() {
		return nil, newError(ErrorCodeWrongKeyType)
	}
	if len(digest) != digestBytes(signature.AlgorithmMLDSA44Ed25519SHA512) {
		return nil, newError(ErrorCodeInvalidDigestLength)
	}
	representative := compositeRepresentative(digest)
	mlSignature, err := key.mldsa.Sign(rand.Reader, representative, &mldsa.Options{Context: compositeLabel})
	if err != nil || len(mlSignature) != mldsa44SignatureBytes {
		return nil, newError(ErrorCodeSignatureMismatch)
	}
	signatureBytes := append(mlSignature, ed25519.Sign(key.ed, representative)...)
	if !verifyComposite(key.PublicKey(), digest, signatureBytes) {
		return nil, newError(ErrorCodeSignatureMismatch)
	}
	return signatureBytes, nil
}

// ParseCompositeSPKI decodes the exact id-MLDSA44-Ed25519-SHA512
// SubjectPublicKeyInfo encoding into a composite public key.
func ParseCompositeSPKI(der []byte) (CompositePublicKey, error) {
	if len(der) != len(compositeSPKIPrefix)+CompositePublicKeyBytes || !bytes.HasPrefix(der, compositeSPKIPrefix) {
		return CompositePublicKey{}, newError(ErrorCodeInvalidKey)
	}
	return ParseCompositePublicKey(der[len(compositeSPKIPrefix):])
}

// MarshalSPKI returns the exact id-MLDSA44-Ed25519-SHA512
// SubjectPublicKeyInfo encoding of k.
func (k CompositePublicKey) MarshalSPKI() []byte {
	raw := k.Bytes()
	if raw == nil {
		return nil
	}
	return append(bytes.Clone(compositeSPKIPrefix), raw...)
}
