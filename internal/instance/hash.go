package instance

import (
	"bytes"

	"github.com/croessner/dkim2/internal/combine"
	"github.com/croessner/dkim2/internal/tagvalue"
)

const (
	sha256HashBytes = 32
	sha512HashBytes = 64
)

type supportedHashAlgorithm struct {
	digestBytes int
}

// parseHashSets parses the Draft-09 Section 9.3 h= value
// (hash-any of hash-all groups of hash-set) into hash sets in field order and
// their group layout. The max_hash_sets bound counts sets across all groups
// and is enforced before any set content is parsed; a hash algorithm name
// must not repeat anywhere in the field.
func parseHashSets(value string, limits Limits, fieldIndex int) ([]HashSet, combine.Layout, error) {
	if len(value) == 0 {
		return nil, combine.Layout{}, malformedHashSetError(fieldIndex, 0)
	}
	if count := combine.CountSets([]byte(value)); count > limits.MaxHashSets {
		return nil, combine.Layout{}, newError(ErrorCodeLimitExceeded, ErrorLocation{FieldIndex: fieldIndex}, ErrorDetails{
			Class:     ErrorClassLimit,
			TagName:   "h",
			LimitName: "max_hash_sets",
			Limit:     limits.MaxHashSets,
			Count:     count,
		}, nil)
	}
	parts, layout, ok := combine.Split([]byte(value))
	if !ok {
		return nil, combine.Layout{}, malformedHashSetError(fieldIndex, 0)
	}

	seen := make(map[string]struct{}, len(parts))
	hashes := make([]HashSet, 0, len(parts))
	for i, part := range parts {
		hashSet, err := parseHashSet(part, limits.TagLimits, fieldIndex, i)
		if err != nil {
			return nil, combine.Layout{}, err
		}
		if _, exists := seen[hashSet.name]; exists {
			return nil, combine.Layout{}, newError(ErrorCodeDuplicateHashName, ErrorLocation{FieldIndex: fieldIndex, HashIndex: i}, ErrorDetails{
				Class:   ErrorClassDuplicate,
				TagName: "h",
			}, nil)
		}
		seen[hashSet.name] = struct{}{}
		hashes = append(hashes, hashSet)
	}

	return hashes, layout, nil
}

// parseHashSet parses one hash-set = hash-name [FWS] ":" header-hash ":"
// body-hash. White space may surround hash-name (the [FWS] around separators
// and the textstring FWS) and may appear inside both base64string values, but
// Draft-09 Section 2.14 forbids it at either end of a base64string and the
// production has no [FWS] next to the hash colons. The only trailing white
// space admitted after body-hash belongs to the following separator or tag
// terminator.
func parseHashSet(input []byte, tagLimits tagvalue.Limits, fieldIndex int, hashIndex int) (HashSet, error) {
	components := bytes.Split(input, []byte{':'})
	if len(components) != 3 {
		return HashSet{}, malformedHashSetError(fieldIndex, hashIndex)
	}

	rawName, _ := trimWSP(components[0])
	rawHeaderHash := components[1]
	rawBodyHash := trimTrailingWSP(components[2])
	name, ok := tagvalue.ParseTextstring(rawName)
	if !ok || !base64Edges(rawHeaderHash) || !base64Edges(rawBodyHash) {
		return HashSet{}, malformedHashSetError(fieldIndex, hashIndex)
	}
	if !validUnknownHashComponent(rawHeaderHash) || !validUnknownHashComponent(rawBodyHash) {
		return HashSet{}, malformedHashSetError(fieldIndex, hashIndex)
	}

	algorithm, known := supportedHashAlgorithmForName(name)
	hashSet := HashSet{
		name:            name,
		known:           known,
		headerHashValue: bytes.Clone(rawHeaderHash),
		bodyHashValue:   bytes.Clone(rawBodyHash),
	}
	headerHash, err := parseHashBase64(rawHeaderHash, tagLimits, fieldIndex, hashIndex)
	if err != nil {
		return HashSet{}, err
	}
	bodyHash, err := parseHashBase64(rawBodyHash, tagLimits, fieldIndex, hashIndex)
	if err != nil {
		return HashSet{}, err
	}
	hashSet.headerHash = headerHash
	hashSet.bodyHash = bodyHash
	if !hashSet.known {
		return hashSet, nil
	}
	if headerHash.DecodedLen() != algorithm.digestBytes {
		return HashSet{}, invalidHashLengthError(fieldIndex, hashIndex, algorithm.digestBytes, headerHash.DecodedLen())
	}
	if bodyHash.DecodedLen() != algorithm.digestBytes {
		return HashSet{}, invalidHashLengthError(fieldIndex, hashIndex, algorithm.digestBytes, bodyHash.DecodedLen())
	}

	return hashSet, nil
}

// parseHashBase64 parses one known or future hash component as strict base64string.
func parseHashBase64(input []byte, limits tagvalue.Limits, fieldIndex int, hashIndex int) (tagvalue.Base64String, error) {
	parsed, err := tagvalue.ParseBase64String(input, limits)
	if err != nil {
		return tagvalue.Base64String{}, newError(ErrorCodeInvalidHashBase64, ErrorLocation{FieldIndex: fieldIndex, HashIndex: hashIndex}, ErrorDetails{
			TagName: "h",
		}, err)
	}
	return parsed, nil
}

// invalidHashLengthError reports a supported digest with the wrong decoded size.
func invalidHashLengthError(fieldIndex int, hashIndex int, expectedLength int, decodedLength int) *Error {
	return newError(ErrorCodeInvalidHashLength, ErrorLocation{FieldIndex: fieldIndex, HashIndex: hashIndex}, ErrorDetails{
		TagName: "h",
		Limit:   expectedLength,
		Count:   decodedLength,
	}, nil)
}

// supportedHashAlgorithmForName resolves the fixed Draft-09 digest-size invariant.
func supportedHashAlgorithmForName(name string) (supportedHashAlgorithm, bool) {
	switch name {
	case HashAlgorithmSHA256:
		return supportedHashAlgorithm{digestBytes: sha256HashBytes}, true
	case HashAlgorithmSHA512:
		return supportedHashAlgorithm{digestBytes: sha512HashBytes}, true
	default:
		return supportedHashAlgorithm{}, false
	}
}

// base64Edges reports whether a raw base64string component is non-empty and
// neither begins nor ends with white space (Draft-09 Section 2.14).
func base64Edges(component []byte) bool {
	return len(component) > 0 && !isWSP(component[0]) && !isWSP(component[len(component)-1])
}

// trimTrailingWSP removes the separator or terminator white space that may
// follow the last component of one hash-set.
func trimTrailingWSP(input []byte) []byte {
	end := len(input)
	for end > 0 && isWSP(input[end-1]) {
		end--
	}
	return input[:end]
}

// malformedHashSetError constructs a bounded h= syntax error.
func malformedHashSetError(fieldIndex int, hashIndex int) *Error {
	return newError(ErrorCodeMalformedHashSet, ErrorLocation{FieldIndex: fieldIndex, HashIndex: hashIndex}, ErrorDetails{
		TagName: "h",
	}, nil)
}

// validUnknownHashComponent rejects control-bearing hash components while permitting WSP.
// Draft-09 admits FWS inside base64string values; alphabet and padding remain
// owned by tagvalue.ParseBase64String after it strips interior WSP.
func validUnknownHashComponent(input []byte) bool {
	for _, b := range input {
		if (b < 32 && !isWSP(b)) || b == 127 {
			return false
		}
	}

	return true
}

// trimWSP removes DKIM2-permitted surrounding space and tab bytes.
func trimWSP(input []byte) ([]byte, int) {
	start := 0
	for start < len(input) && isWSP(input[start]) {
		start++
	}

	end := len(input)
	for end > start && isWSP(input[end-1]) {
		end--
	}

	return input[start:end], start
}

// isWSP reports whether b is RFC 5322 white space allowed around hash sets.
func isWSP(b byte) bool {
	return b == ' ' || b == '\t'
}
