package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"math/big"
)

// ClassifyAlgorithm reports the fail-closed policy state for algorithm.
func (p AlgorithmPolicy) ClassifyAlgorithm(algorithm Algorithm) KeyStatus {
	switch {
	case !knownAlgorithm(algorithm):
		return KeyStatusUnsupportedAlgorithm
	case !p.Allows(algorithm):
		return KeyStatusPolicyRejected
	default:
		return KeyStatusFound
	}
}

// validatePublicKeyMaterial checks public-key type and policy before crypto use.
func validatePublicKeyMaterial(algorithm Algorithm, material any, policy AlgorithmPolicy) (any, KeyStatus, error) {
	switch status := policy.ClassifyAlgorithm(algorithm); status {
	case KeyStatusFound:
	case KeyStatusUnsupportedAlgorithm:
		return nil, status, unsupportedAlgorithmError(algorithm)
	default:
		return nil, status, disabledAlgorithmError(algorithm)
	}

	switch algorithm {
	case AlgorithmRSASHA256:
		return validateRSAPublicKey(material, policy.MinRSABits)
	case AlgorithmEd25519SHA256:
		return validateEd25519PublicKey(material)
	default:
		return nil, KeyStatusUnsupportedAlgorithm, unsupportedAlgorithmError(algorithm)
	}
}

// validateRSAPublicKey checks RSA public-key shape and verifier size policy.
func validateRSAPublicKey(material any, minBits int) (any, KeyStatus, error) {
	key, ok := material.(*rsa.PublicKey)
	if !ok {
		return nil, KeyStatusWrongType, wrongKeyTypeError(AlgorithmRSASHA256)
	}
	if key == nil || key.N == nil || key.N.Sign() <= 0 || key.E <= 1 || key.E%2 == 0 {
		return nil, KeyStatusInvalid, invalidKeyError(AlgorithmRSASHA256)
	}
	if key.N.BitLen() < minBits {
		return nil, KeyStatusPolicyRejected, keyPolicyRejectedError(AlgorithmRSASHA256)
	}

	return cloneRSAPublicKey(key), KeyStatusFound, nil
}

// validateEd25519PublicKey checks Ed25519 public-key type and fixed length.
func validateEd25519PublicKey(material any) (any, KeyStatus, error) {
	key, ok := material.(ed25519.PublicKey)
	if !ok {
		return nil, KeyStatusWrongType, wrongKeyTypeError(AlgorithmEd25519SHA256)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, KeyStatusInvalid, invalidKeyError(AlgorithmEd25519SHA256)
	}

	return ed25519.PublicKey(bytes.Clone(key)), KeyStatusFound, nil
}

// clonePublicKeyMaterial returns provider-owned copies of supported key material.
func clonePublicKeyMaterial(material any) any {
	switch key := material.(type) {
	case *rsa.PublicKey:
		return cloneRSAPublicKey(key)
	case ed25519.PublicKey:
		return ed25519.PublicKey(bytes.Clone(key))
	default:
		return material
	}
}

// cloneRSAPublicKey returns an independent RSA public-key value.
func cloneRSAPublicKey(key *rsa.PublicKey) *rsa.PublicKey {
	if key == nil {
		return nil
	}

	return &rsa.PublicKey{
		N: new(big.Int).Set(key.N),
		E: key.E,
	}
}
