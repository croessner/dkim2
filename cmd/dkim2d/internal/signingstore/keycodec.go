package signingstore

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"io"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/provider"
)

// parsePKCS8PrivateKey is the keystore's single PKCS#8 owner. It decodes one
// unencrypted PKCS#8 DER private key for exactly the expected signing
// algorithm and returns it with its canonical public SPKI through
// crypto/x509. Only RSA, Ed25519, and ML-DSA-44 keys are admitted; any other
// key type or algorithm fails closed. When canonical is true the DER must
// re-encode byte for byte. An ML-DSA-44 key must always be the canonical
// seed-only PKCS#8 form (OID 2.16.840.1.101.3.4.3.17, privateKey [0] holding
// the 32-byte seed) that crypto/x509 and opendkim-manage-go produce.
func parsePKCS8PrivateKey(
	der []byte,
	algorithm dkim2.Algorithm,
	canonical bool,
) (crypto.PrivateKey, []byte, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, nil, &Error{}
	}
	if _, isMLDSA := key.(*mldsa.PrivateKey); canonical || isMLDSA {
		encoded, marshalErr := x509.MarshalPKCS8PrivateKey(key)
		equal := marshalErr == nil && bytes.Equal(encoded, der)
		clear(encoded)
		if !equal {
			clearPrivateKey(key)
			return nil, nil, &Error{}
		}
	}
	if !privateKeyMatchesAlgorithm(key, algorithm) {
		clearPrivateKey(key)
		return nil, nil, &Error{}
	}
	spki, err := publicSPKI(key)
	if err != nil {
		clearPrivateKey(key)
		return nil, nil, &Error{}
	}
	return key, spki, nil
}

// custodyAlgorithm maps one admitted datasource credential algorithm to the
// signing algorithm of the same name; anything else maps to unknown.
func custodyAlgorithm(algorithm provider.Algorithm) dkim2.Algorithm {
	if _, err := provider.ParseAlgorithm(string(algorithm)); err != nil {
		return dkim2.AlgorithmUnknown
	}
	return dkim2.Algorithm(algorithm)
}

// privateKeyMatchesAlgorithm enforces the closed key-type, size, and
// algorithm pairing accepted for signing custody.
func privateKeyMatchesAlgorithm(key crypto.PrivateKey, algorithm dkim2.Algorithm) bool {
	switch typed := key.(type) {
	case *rsa.PrivateKey:
		return algorithm == dkim2.AlgorithmRSASHA256 && typed.Validate() == nil &&
			typed.N.BitLen() >= 1024 && len(typed.Primes) == 2
	case ed25519.PrivateKey:
		return algorithm == dkim2.AlgorithmEd25519SHA256 && len(typed) == ed25519.PrivateKeySize
	case *mldsa.PrivateKey:
		return algorithm == dkim2.AlgorithmMLDSA44 && validMLDSA44PrivateKey(typed)
	default:
		return false
	}
}

// validMLDSA44PrivateKey proves an ML-DSA-44 parameter set and a nonzero
// 32-byte seed. The seed copy returned by crypto/mldsa is cleared.
func validMLDSA44PrivateKey(key *mldsa.PrivateKey) bool {
	if key == nil || key.PublicKey().Parameters() != mldsa.MLDSA44() {
		return false
	}
	seed := key.Bytes()
	defer clear(seed)
	return len(seed) == mldsa.PrivateKeySize && !allZero(seed)
}

// allZero reports whether every byte of value is zero.
func allZero(value []byte) bool {
	var accumulated byte
	for _, item := range value {
		accumulated |= item
	}
	return accumulated == 0
}

// marshalPKCS8PrivateKey returns the canonical unencrypted PKCS#8 DER of one
// custody key. The result carries secret material the caller must clear.
func marshalPKCS8PrivateKey(key crypto.PrivateKey) ([]byte, error) {
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, &Error{}
	}
	return encoded, nil
}

// publicSPKI derives canonical public material from one validated private key.
func publicSPKI(key crypto.PrivateKey) ([]byte, error) {
	var public any
	switch typed := key.(type) {
	case *rsa.PrivateKey:
		public = &typed.PublicKey
	case ed25519.PrivateKey:
		public = typed.Public()
	case *mldsa.PrivateKey:
		public = typed.PublicKey()
	default:
		return nil, &Error{}
	}
	encoded, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, &Error{}
	}
	return encoded, nil
}

// rsaGenerationExponent is the only RSA public exponent custody generates.
const rsaGenerationExponent = 65537

// GeneratePrivateKey creates one fresh custody key for algorithm from random
// and returns its canonical PKCS#8 DER and public SPKI. rsaBits selects the
// exact RSA modulus size and is ignored for other algorithms. An ML-DSA-44
// key is derived from a 32-byte seed read from random, so injected test
// readers stay deterministic exactly as for the other algorithms; an all-zero
// seed is rejected. The PKCS#8 result carries secret material the caller must
// clear.
func GeneratePrivateKey(
	algorithm provider.Algorithm,
	random io.Reader,
	rsaBits int,
) (privatePKCS8 []byte, spki []byte, err error) {
	if random == nil {
		return nil, nil, &Error{}
	}
	selected := custodyAlgorithm(algorithm)
	var key crypto.PrivateKey
	switch selected {
	case dkim2.AlgorithmRSASHA256:
		var rsaKey *rsa.PrivateKey
		rsaKey, err = rsa.GenerateKey(random, rsaBits)
		if err == nil && (rsaKey.N.BitLen() != rsaBits || rsaKey.E != rsaGenerationExponent) {
			err = &Error{}
		}
		if rsaKey != nil {
			key = rsaKey
		}
	case dkim2.AlgorithmEd25519SHA256:
		_, key, err = ed25519.GenerateKey(random)
	case dkim2.AlgorithmMLDSA44:
		key, err = generateMLDSA44PrivateKey(random)
	default:
		return nil, nil, &Error{}
	}
	if err != nil || !privateKeyMatchesAlgorithm(key, selected) {
		clearPrivateKey(key)
		return nil, nil, &Error{}
	}
	defer clearPrivateKey(key)
	privatePKCS8, err = marshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, &Error{}
	}
	spki, err = publicSPKI(key)
	if err != nil {
		clear(privatePKCS8)
		return nil, nil, &Error{}
	}
	return privatePKCS8, spki, nil
}

// generateMLDSA44PrivateKey derives one ML-DSA-44 key from a nonzero 32-byte
// seed read from random. The seed buffer is cleared; the expanded key stays
// inside crypto/mldsa (see clearPrivateKey).
func generateMLDSA44PrivateKey(random io.Reader) (*mldsa.PrivateKey, error) {
	seed := make([]byte, mldsa.PrivateKeySize)
	defer clear(seed)
	if _, err := io.ReadFull(random, seed); err != nil || allZero(seed) {
		return nil, &Error{}
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	if err != nil {
		return nil, &Error{}
	}
	return key, nil
}
