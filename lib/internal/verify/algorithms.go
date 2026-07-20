package verify

import "github.com/croessner/dkim2/internal/cryptodkim2"

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

	limits := cryptodkim2.DefaultLimits()
	limits.MinRSABits = policy.MinRSABits
	limits.MaxRSABits = policy.MaxRSABits
	validated, err := cryptodkim2.ValidatePublicKey(algorithm, material, limits)
	if err == nil {
		return validated, KeyStatusFound, nil
	}
	switch cryptodkim2.ErrorCodeOf(err) {
	case cryptodkim2.ErrorCodeUnsupportedAlgorithm:
		return nil, KeyStatusUnsupportedAlgorithm, unsupportedAlgorithmError(algorithm)
	case cryptodkim2.ErrorCodeWrongKeyType:
		return nil, KeyStatusWrongType, wrongKeyTypeError(algorithm)
	case cryptodkim2.ErrorCodeKeyPolicyRejected:
		return nil, KeyStatusPolicyRejected, keyPolicyRejectedError(algorithm)
	default:
		return nil, KeyStatusInvalid, invalidKeyError(algorithm)
	}
}

// clonePublicKeyMaterial returns provider-owned copies of supported key material.
func clonePublicKeyMaterial(material any) any {
	return cryptodkim2.ClonePublicKey(material)
}
