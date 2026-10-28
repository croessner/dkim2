package signature

import (
	"bytes"

	"github.com/croessner/dkim2/internal/combine"
	"github.com/croessner/dkim2/internal/tagvalue"
)

const ed25519SignatureBytes = 64

// parseSignatureSets parses the Draft-08 Section 10.9 s= value (sig-any of
// sig-all groups of sig-set) into sets in field order and their group
// layout. The max_signature_sets bound counts sets across all groups and is
// enforced before any set content is parsed; a selector must not repeat
// anywhere in the field, while several sets may share one algorithm.
func parseSignatureSets(value string, limits Limits, fieldIndex int) ([]Set, combine.Layout, error) {
	if len(value) == 0 {
		return nil, combine.Layout{}, malformedSignatureSetError(fieldIndex, 0)
	}
	if count := combine.CountSets([]byte(value)); count > limits.MaxSignatureSets {
		return nil, combine.Layout{}, newError(ErrorCodeLimitExceeded, ErrorLocation{FieldIndex: fieldIndex}, ErrorDetails{
			Class:     ErrorClassLimit,
			TagName:   "s",
			LimitName: "max_signature_sets",
			Limit:     limits.MaxSignatureSets,
			Count:     count,
		}, nil)
	}
	parts, layout, ok := combine.Split([]byte(value))
	if !ok {
		return nil, combine.Layout{}, malformedSignatureSetError(fieldIndex, 0)
	}

	selectors := newSelectorUniqueness(len(parts))
	sets := make([]Set, 0, len(parts))
	for i, part := range parts {
		set, err := parseSignatureSet(part, limits.TagLimits, fieldIndex, i)
		if err != nil {
			return nil, combine.Layout{}, err
		}
		if err := selectors.add(set.selector, fieldIndex, i); err != nil {
			return nil, combine.Layout{}, err
		}
		sets = append(sets, set)
	}
	if err := rejectAlternativeSignatureGroups(layout, fieldIndex); err != nil {
		return nil, combine.Layout{}, err
	}

	return sets, layout, nil
}

// rejectAlternativeSignatureGroups fails closed on more than one sig-all
// group until the Section 14.6 combination algebra evaluates alternatives.
func rejectAlternativeSignatureGroups(layout combine.Layout, fieldIndex int) error {
	if layout.Groups() > 1 {
		return malformedSignatureSetError(fieldIndex, 0)
	}
	return nil
}

// parseSignatureSet parses one sig-set = selector [FWS] ":" [FWS] sig-name
// [FWS] ":" message-sig. White space may surround selector and sig-name and
// may appear inside or before the message-sig base64string; it may not
// appear inside a selector (an RFC 5321 Domain) or a sig-name textstring.
// The raw selector spelling is kept for the Section 12.8 unsigned target.
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
	algorithm, ok := tagvalue.ParseTextstring(rawAlgorithm)
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
		rawSelector:    string(rawSelector),
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
