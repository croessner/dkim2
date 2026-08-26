package canonical

import (
	"crypto/sha256"
	"crypto/sha512"
)

// Digest calculates the selected supported Message-Instance digest over canonical bytes.
func (c Canonicalizer) Digest(input ByteInput) (Digest, error) {
	if err := c.validateDigestInput(input, KindBodyHashInput, KindHeaderHashInput); err != nil {
		return Digest{}, err
	}
	switch c.options.HashAlgorithm {
	case HashAlgorithmSHA256:
		sum := sha256.Sum256(input.Bytes())
		return NewDigest(HashAlgorithmSHA256, sum[:])
	case HashAlgorithmSHA512:
		sum := sha512.Sum512(input.Bytes())
		return NewDigest(HashAlgorithmSHA512, sum[:])
	default:
		return Digest{}, newError(ErrorCodeUnsupportedAlgorithm, ErrorLocation{Kind: input.Kind()}, ErrorDetails{
			Class:     ErrorClassAlgorithm,
			Algorithm: c.options.HashAlgorithm,
		}, nil)
	}
}

// SHA256Digest calculates the fixed Section 9.6 signature-input SHA-256 digest.
func (c Canonicalizer) SHA256Digest(input ByteInput) (Digest, error) {
	if err := c.validateDigestInput(input, KindSignatureInput); err != nil {
		return Digest{}, err
	}
	sum := sha256.Sum256(input.Bytes())

	return NewDigest(HashAlgorithmSHA256, sum[:])
}

// validateDigestInput enforces constructed receiver state and purpose-specific byte kinds.
func (c Canonicalizer) validateDigestInput(input ByteInput, allowedKinds ...Kind) error {
	if err := c.options.Validate(); err != nil {
		return err
	}
	for _, allowedKind := range allowedKinds {
		if input.Kind() == allowedKind {
			return nil
		}
	}
	return newError(ErrorCodeInternalMisuse, ErrorLocation{Kind: input.Kind()}, ErrorDetails{
		Class:      ErrorClassInternal,
		TargetName: "digest_input_kind",
	}, nil)
}
