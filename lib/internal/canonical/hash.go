package canonical

import "crypto/sha256"

// SHA256Digest calculates a SHA-256 digest for canonical byte input.
func (c Canonicalizer) SHA256Digest(input ByteInput) (Digest, error) {
	if c.options.HashAlgorithm != HashAlgorithmSHA256 {
		return Digest{}, newError(ErrorCodeUnsupportedAlgorithm, ErrorLocation{Kind: input.Kind()}, ErrorDetails{
			Class:     ErrorClassAlgorithm,
			Algorithm: c.options.HashAlgorithm,
		}, nil)
	}

	sum := sha256.Sum256(input.Bytes())

	return NewSHA256Digest(sum[:])
}
