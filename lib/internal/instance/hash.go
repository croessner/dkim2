package instance

import (
	"bytes"

	"github.com/croessner/dkim2/internal/tagvalue"
)

const sha256HashBytes = 32

// parseHashSets parses the Message-Instance h= hash-set list.
func parseHashSets(value string, limits Limits, fieldIndex int) ([]HashSet, error) {
	parts := splitHashSetList([]byte(value))
	if len(parts) == 0 {
		return nil, newError(ErrorCodeMalformedHashSet, ErrorLocation{FieldIndex: fieldIndex}, ErrorDetails{
			TagName: "h",
		}, nil)
	}
	if len(parts) > limits.MaxHashSets {
		return nil, newError(ErrorCodeLimitExceeded, ErrorLocation{FieldIndex: fieldIndex}, ErrorDetails{
			Class:     ErrorClassLimit,
			TagName:   "h",
			LimitName: "max_hash_sets",
			Limit:     limits.MaxHashSets,
			Count:     len(parts),
		}, nil)
	}

	seen := make(map[string]struct{}, len(parts))
	hashes := make([]HashSet, 0, len(parts))
	for i, part := range parts {
		hashSet, err := parseHashSet(part, limits.TagLimits, fieldIndex, i)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[hashSet.name]; exists {
			return nil, newError(ErrorCodeDuplicateHashName, ErrorLocation{FieldIndex: fieldIndex, HashIndex: i}, ErrorDetails{
				Class:   ErrorClassDuplicate,
				TagName: "h",
			}, nil)
		}
		seen[hashSet.name] = struct{}{}
		hashes = append(hashes, hashSet)
	}

	return hashes, nil
}

// parseHashSet parses one hash-name:header-hash:body-hash tuple.
func parseHashSet(input []byte, tagLimits tagvalue.Limits, fieldIndex int, hashIndex int) (HashSet, error) {
	components := bytes.Split(input, []byte{':'})
	if len(components) != 3 {
		return HashSet{}, malformedHashSetError(fieldIndex, hashIndex)
	}

	rawName, _ := trimWSP(components[0])
	rawHeaderHash, _ := trimWSP(components[1])
	rawBodyHash, _ := trimWSP(components[2])
	name, ok := canonicalHashName(rawName)
	if !ok || len(rawHeaderHash) == 0 || len(rawBodyHash) == 0 {
		return HashSet{}, malformedHashSetError(fieldIndex, hashIndex)
	}
	if !validUnknownHashComponent(rawHeaderHash) || !validUnknownHashComponent(rawBodyHash) {
		return HashSet{}, malformedHashSetError(fieldIndex, hashIndex)
	}

	hashSet := HashSet{
		name:            name,
		known:           name == HashAlgorithmSHA256,
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
	if headerHash.DecodedLen() != sha256HashBytes {
		return HashSet{}, invalidHashLengthError(fieldIndex, hashIndex, headerHash.DecodedLen())
	}
	if bodyHash.DecodedLen() != sha256HashBytes {
		return HashSet{}, invalidHashLengthError(fieldIndex, hashIndex, bodyHash.DecodedLen())
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

// invalidHashLengthError reports a baseline sha256 digest with the wrong decoded size.
func invalidHashLengthError(fieldIndex int, hashIndex int, decodedLength int) *Error {
	return newError(ErrorCodeInvalidHashLength, ErrorLocation{FieldIndex: fieldIndex, HashIndex: hashIndex}, ErrorDetails{
		TagName: "h",
		Limit:   sha256HashBytes,
		Count:   decodedLength,
	}, nil)
}

// splitHashSetList splits the h= value at comma separators.
func splitHashSetList(input []byte) [][]byte {
	if len(input) == 0 {
		return nil
	}

	return bytes.Split(input, []byte{','})
}

// malformedHashSetError constructs a bounded h= syntax error.
func malformedHashSetError(fieldIndex int, hashIndex int) *Error {
	return newError(ErrorCodeMalformedHashSet, ErrorLocation{FieldIndex: fieldIndex, HashIndex: hashIndex}, ErrorDetails{
		TagName: "h",
	}, nil)
}

// canonicalHashName validates and lowercases one hash algorithm name.
func canonicalHashName(input []byte) (string, bool) {
	if len(input) == 0 {
		return "", false
	}

	output := make([]byte, len(input))
	for i, b := range input {
		if b >= 'A' && b <= 'Z' {
			output[i] = b + ('a' - 'A')
			continue
		}
		if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b == '-' {
			output[i] = b
			continue
		}

		return "", false
	}

	return string(output), true
}

// validUnknownHashComponent rejects control-bearing hash components while permitting WSP.
// Draft-04 admits FWS inside base64string values; alphabet and padding remain
// owned by tagvalue.ParseBase64String after it strips WSP.
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
