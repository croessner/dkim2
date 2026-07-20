package signature

import (
	"bytes"

	"github.com/croessner/dkim2/internal/tagvalue"
)

const ed25519SignatureBytes = 64

// parseSignatureSets parses comma-separated s= selector signatures.
func parseSignatureSets(value string, limits Limits, fieldIndex int) ([]Set, error) {
	parts := splitCommaList([]byte(value))
	if len(parts) == 0 {
		return nil, malformedSignatureSetError(fieldIndex, 0)
	}
	if len(parts) > limits.MaxSignatureSets {
		return nil, newError(ErrorCodeLimitExceeded, ErrorLocation{FieldIndex: fieldIndex}, ErrorDetails{
			Class:     ErrorClassLimit,
			TagName:   "s",
			LimitName: "max_signature_sets",
			Limit:     limits.MaxSignatureSets,
			Count:     len(parts),
		}, nil)
	}

	seenAlgorithms := make(map[string]struct{}, len(parts))
	seenSelectors := make(map[string]struct{}, len(parts))
	sets := make([]Set, 0, len(parts))
	for i, part := range parts {
		set, err := parseSignatureSet(part, limits.TagLimits, fieldIndex, i)
		if err != nil {
			return nil, err
		}
		if _, exists := seenAlgorithms[set.algorithm]; exists {
			return nil, newError(ErrorCodeDuplicateSignatureAlgorithm, ErrorLocation{FieldIndex: fieldIndex, SignatureIndex: i}, ErrorDetails{
				Class:   ErrorClassDuplicate,
				TagName: "s",
			}, nil)
		}
		if _, exists := seenSelectors[set.selector]; exists {
			return nil, newError(ErrorCodeDuplicateSelector, ErrorLocation{FieldIndex: fieldIndex, SignatureIndex: i}, ErrorDetails{
				Class:   ErrorClassDuplicate,
				TagName: "s",
			}, nil)
		}

		seenAlgorithms[set.algorithm] = struct{}{}
		seenSelectors[set.selector] = struct{}{}
		sets = append(sets, set)
	}

	return sets, nil
}

// parseSignatureSet parses one selector:algorithm:signature tuple.
func parseSignatureSet(input []byte, limits tagvalue.Limits, fieldIndex int, signatureIndex int) (Set, error) {
	components := bytes.Split(input, []byte{':'})
	if len(components) != 3 {
		return Set{}, malformedSignatureSetError(fieldIndex, signatureIndex)
	}

	rawSelector, _ := trimWSP(components[0])
	rawAlgorithm, _ := trimWSP(components[1])
	rawSignature, _ := trimWSP(components[2])
	selector, ok := canonicalDNSName(rawSelector)
	if !ok {
		return Set{}, malformedSignatureSetError(fieldIndex, signatureIndex)
	}
	algorithm, ok := canonicalTokenName(rawAlgorithm)
	if !ok || len(rawSignature) == 0 {
		return Set{}, malformedSignatureSetError(fieldIndex, signatureIndex)
	}

	signature, err := tagvalue.ParseBase64String(rawSignature, limits)
	if err != nil {
		return Set{}, newError(ErrorCodeInvalidSignatureBase64, ErrorLocation{FieldIndex: fieldIndex, SignatureIndex: signatureIndex}, ErrorDetails{
			TagName: "s",
		}, err)
	}

	set := Set{
		selector:       selector,
		algorithm:      algorithm,
		knownAlgorithm: knownSignatureAlgorithm(algorithm),
		signature:      signature,
	}
	if Algorithm(algorithm) == AlgorithmEd25519SHA256 && signature.DecodedLen() != ed25519SignatureBytes {
		return Set{}, newError(ErrorCodeInvalidSignatureLength, ErrorLocation{FieldIndex: fieldIndex, SignatureIndex: signatureIndex}, ErrorDetails{
			TagName: "s",
			Limit:   ed25519SignatureBytes,
			Count:   signature.DecodedLen(),
		}, nil)
	}

	return set, nil
}

// knownSignatureAlgorithm reports whether algorithm is parser-known.
func knownSignatureAlgorithm(algorithm string) bool {
	return Algorithm(algorithm).Known()
}

// malformedSignatureSetError constructs a bounded s= syntax failure.
func malformedSignatureSetError(fieldIndex int, signatureIndex int) *Error {
	return newError(ErrorCodeMalformedSignatureSet, ErrorLocation{FieldIndex: fieldIndex, SignatureIndex: signatureIndex}, ErrorDetails{
		TagName: "s",
	}, nil)
}
