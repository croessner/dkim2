package dkim2

import (
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/cryptodkim2"
	"github.com/croessner/dkim2/internal/signing"
)

// CompositeSigningCredential is one immutable mldsa44-ed25519-sha512 public
// credential paired with an opaque private-key handle.
type CompositeSigningCredential struct{ value signing.Credential }

// NewCompositeSigningCredential validates and snapshots one
// mldsa44-ed25519-sha512 credential. publicKey is the raw 1344-byte DNS p=
// form: the ML-DSA-44 public key followed by the Ed25519 public key.
func NewCompositeSigningCredential(selector string, publicKey []byte, handle PrivateKeyHandle) (CompositeSigningCredential, error) {
	key, err := cryptodkim2.ParseCompositePublicKey(publicKey)
	if err != nil {
		return CompositeSigningCredential{}, newSigningError(SigningErrorInvalidRequest)
	}
	value, err := signing.NewCredential(selector, signing.AlgorithmMLDSA44Ed25519SHA512, key, handle.value, signing.DefaultLimits())
	if err != nil {
		return CompositeSigningCredential{}, mapSigningError(err)
	}
	return CompositeSigningCredential{value: value}, nil
}

// Valid reports whether the composite credential remains coherent.
func (c CompositeSigningCredential) Valid() bool {
	return c.value.Valid() && c.value.Algorithm() == signing.AlgorithmMLDSA44Ed25519SHA512
}

// String returns a constant secret-safe credential summary.
func (c CompositeSigningCredential) String() string {
	return "dkim2.CompositeSigningCredential{redacted}"
}

// GoString returns the constant secret-safe credential Go representation.
func (c CompositeSigningCredential) GoString() string { return c.String() }

// Format routes every credential formatting form through the redacted summary.
func (c CompositeSigningCredential) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, c.String())
}

// SigningCredential is one public credential of any signable algorithm:
// RSASigningCredential, Ed25519SigningCredential, or
// CompositeSigningCredential.
type SigningCredential interface {
	signingCredential() signing.Credential
}

// signingCredential returns the internal RSA credential.
func (c RSASigningCredential) signingCredential() signing.Credential { return c.value }

// signingCredential returns the internal Ed25519 credential.
func (c Ed25519SigningCredential) signingCredential() signing.Credential { return c.value }

// signingCredential returns the internal composite credential.
func (c CompositeSigningCredential) signingCredential() signing.Credential { return c.value }

// NewCompositeSigningProfile constructs a single-algorithm
// mldsa44-ed25519-sha512 profile.
func NewCompositeSigningProfile(domain string, credential CompositeSigningCredential) (SigningProfile, error) {
	return newSigningProfile(domain, []signing.Credential{credential.value})
}

// NewMultiSigningProfile constructs a profile with at most one credential per
// signable algorithm. The signer emits one signature set per credential in
// canonical order: rsa-sha256, ed25519-sha256, then mldsa44-ed25519-sha512.
func NewMultiSigningProfile(domain string, credentials ...SigningCredential) (SigningProfile, error) {
	internal := make([]signing.Credential, 0, len(credentials))
	for _, credential := range credentials {
		if nilSigningCallback(credential) {
			return SigningProfile{}, newSigningError(SigningErrorInvalidRequest)
		}
		internal = append(internal, credential.signingCredential())
	}
	return newSigningProfile(domain, internal)
}

// CompositeSigningKey is one mldsa44-ed25519-sha512 private key held by a
// key custodian that implements PrivateKeySigner. The library owns the LAMPS
// composite construction, so a custodian signs through SignDigest instead of
// rebuilding it. The zero value is invalid.
type CompositeSigningKey struct {
	key cryptodkim2.CompositePrivateKey
}

// GenerateCompositeSigningKey creates a fresh composite key from the system
// random source.
func GenerateCompositeSigningKey() (CompositeSigningKey, error) {
	key, err := cryptodkim2.GenerateCompositePrivateKey()
	if err != nil {
		return CompositeSigningKey{}, newSigningError(SigningErrorInvalidRequest)
	}
	return CompositeSigningKey{key: key}, nil
}

// GenerateCompositeSigningKeyFrom creates a fresh composite key from 64 bytes
// of the supplied entropy source, for key custodians that own their entropy.
func GenerateCompositeSigningKeyFrom(random io.Reader) (CompositeSigningKey, error) {
	key, err := cryptodkim2.GenerateCompositePrivateKeyFrom(random)
	if err != nil {
		return CompositeSigningKey{}, newSigningError(SigningErrorInvalidRequest)
	}
	return CompositeSigningKey{key: key}, nil
}

// ParseCompositeSigningKeyPKCS8 decodes the exact id-MLDSA44-Ed25519-SHA512
// (OID 1.3.6.1.5.5.7.6.39) PKCS#8 encoding of the two 32-byte seeds.
func ParseCompositeSigningKeyPKCS8(der []byte) (CompositeSigningKey, error) {
	key, err := cryptodkim2.ParseCompositePKCS8(der)
	if err != nil {
		return CompositeSigningKey{}, newSigningError(SigningErrorInvalidRequest)
	}
	return CompositeSigningKey{key: key}, nil
}

// MarshalPKCS8 returns the exact PKCS#8 encoding. The result carries secret
// seed material; the caller must clear it after storing it.
func (k CompositeSigningKey) MarshalPKCS8() []byte { return k.key.MarshalPKCS8() }

// PublicKey returns the raw 1344-byte DNS p= public key.
func (k CompositeSigningKey) PublicKey() []byte { return k.key.PublicKey().Bytes() }

// PublicKeySPKI returns the exact id-MLDSA44-Ed25519-SHA512
// SubjectPublicKeyInfo encoding of the public key.
func (k CompositeSigningKey) PublicKeySPKI() []byte { return k.key.PublicKey().MarshalSPKI() }

// Valid reports whether the key holds both component keys.
func (k CompositeSigningKey) Valid() bool { return k.key.Valid() }

// SignDigest signs one composite PrivateKeySignRequest under the LAMPS
// construction and returns the 2484-byte signature as a callback result.
func (k CompositeSigningKey) SignDigest(request PrivateKeySignRequest) (PrivateKeySignResult, error) {
	if !request.Valid() || request.Algorithm() != AlgorithmMLDSA44Ed25519SHA512 {
		return PrivateKeySignResult{}, newSigningError(SigningErrorInvalidRequest)
	}
	signatureBytes, err := cryptodkim2.SignCompositeDigest(k.key, request.digest)
	if err != nil {
		return PrivateKeySignResult{}, newSigningError(SigningErrorInvalidRequest)
	}
	return NewPrivateKeySignResult(signatureBytes), nil
}

// Clear overwrites the retained seeds. The expanded ML-DSA-44 key is owned by
// crypto/mldsa and is released only with k.
func (k *CompositeSigningKey) Clear() {
	if k == nil {
		return
	}
	k.key.Clear()
}

// ParseCompositePublicKeySPKI decodes the exact id-MLDSA44-Ed25519-SHA512
// SubjectPublicKeyInfo encoding into the raw 1344-byte DNS p= form.
func ParseCompositePublicKeySPKI(der []byte) ([]byte, error) {
	key, err := cryptodkim2.ParseCompositeSPKI(der)
	if err != nil {
		return nil, newSigningError(SigningErrorInvalidRequest)
	}
	return key.Bytes(), nil
}

// MarshalCompositePublicKeySPKI encodes the raw 1344-byte DNS p= form as the
// exact id-MLDSA44-Ed25519-SHA512 SubjectPublicKeyInfo.
func MarshalCompositePublicKeySPKI(raw []byte) ([]byte, error) {
	key, err := cryptodkim2.ParseCompositePublicKey(raw)
	if err != nil {
		return nil, newSigningError(SigningErrorInvalidRequest)
	}
	return key.MarshalSPKI(), nil
}

// String returns a constant secret-safe key summary.
func (k CompositeSigningKey) String() string { return "dkim2.CompositeSigningKey{redacted}" }

// GoString returns the constant secret-safe key Go representation.
func (k CompositeSigningKey) GoString() string { return k.String() }

// Format routes every key formatting form through the redacted summary.
func (k CompositeSigningKey) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, k.String())
}
