package signingstore

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"io"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/provider"
)

// parsePKCS8PrivateKey is the keystore's single PKCS#8 owner. It decodes one
// unencrypted PKCS#8 DER private key for exactly the expected signing
// algorithm and returns it with its canonical public SPKI through
// crypto/x509. Only RSA and Ed25519 keys are admitted; any other key type or
// algorithm fails closed. When canonical is true the DER must re-encode byte
// for byte.
func parsePKCS8PrivateKey(
	der []byte,
	algorithm dkim2.Algorithm,
	canonical bool,
) (crypto.PrivateKey, []byte, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, nil, &Error{}
	}
	if canonical {
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
	default:
		return false
	}
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
// exact RSA modulus size and is ignored for other algorithms. The PKCS#8
// result carries secret material the caller must clear.
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
