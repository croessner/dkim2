package instance

import (
	"bytes"
	"slices"

	"github.com/croessner/dkim2/internal/tagvalue"
)

const (
	// HeaderName is the lowercase rawmsg name for Message-Instance fields.
	HeaderName = "message-instance"
	// HashAlgorithmSHA256 is the baseline known Message-Instance hash name.
	HashAlgorithmSHA256 = "sha256"
	maxHashSetsHard     = 16
	maxInstancesHard    = 128
)

// HashSelectionStatus identifies baseline SHA-256 selection state.
type HashSelectionStatus string

const (
	// HashSelectionStatusSelected reports one usable SHA-256 tuple.
	HashSelectionStatusSelected HashSelectionStatus = "selected"
	// HashSelectionStatusMissing reports no SHA-256 or unknown hash tuple.
	HashSelectionStatusMissing HashSelectionStatus = "missing"
	// HashSelectionStatusUnsupported reports only unknown hash algorithms.
	HashSelectionStatusUnsupported HashSelectionStatus = "unsupported"
)

// Known reports whether status belongs to the closed selection vocabulary.
func (s HashSelectionStatus) Known() bool {
	return s == HashSelectionStatusSelected || s == HashSelectionStatusMissing || s == HashSelectionStatusUnsupported
}

// Limits contains fail-closed Message-Instance parser resource settings.
type Limits struct {
	// TagLimits bounds shared DKIM2 tag-list and base64string parsing.
	TagLimits tagvalue.Limits
	// MaxHashSets bounds comma-separated h= hash sets.
	MaxHashSets int
	// MaxInstances bounds Message-Instance fields in one message.
	MaxInstances int
}

// DefaultLimits returns restrictive Message-Instance parser defaults.
func DefaultLimits() Limits {
	return Limits{
		TagLimits:    tagvalue.DefaultLimits(),
		MaxHashSets:  maxHashSetsHard,
		MaxInstances: maxInstancesHard,
	}
}

// Validate rejects unsafe Message-Instance parser limit values.
func (l Limits) Validate() error {
	if l.MaxHashSets <= 0 || l.MaxHashSets > maxHashSetsHard {
		return newError(ErrorCodeInvalidOptions, ErrorLocation{}, ErrorDetails{
			Class:     ErrorClassInvariant,
			LimitName: "max_hash_sets",
			Limit:     l.MaxHashSets,
		}, nil)
	}
	if l.MaxInstances <= 0 || l.MaxInstances > maxInstancesHard {
		return newError(ErrorCodeInvalidOptions, ErrorLocation{}, ErrorDetails{
			Class: ErrorClassInvariant, LimitName: LimitNameMaxInstances, Limit: l.MaxInstances,
		}, nil)
	}

	return nil
}

// MessageInstance stores one immutable parsed Message-Instance field.
type MessageInstance struct {
	number      uint64
	hashes      []HashSet
	recipe      tagvalue.Base64String
	hasRecipe   bool
	headerIndex int
}

// Number returns the parsed m= Message-Instance number.
func (m MessageInstance) Number() uint64 {
	return m.number
}

// HeaderIndex returns the raw header occurrence index.
func (m MessageInstance) HeaderIndex() int {
	return m.headerIndex
}

// HashSets returns immutable copies of h= hash sets in field order.
func (m MessageInstance) HashSets() []HashSet {
	return cloneHashSets(m.hashes)
}

// Recipe returns the parsed r= base64 container when present.
func (m MessageInstance) Recipe() (tagvalue.Base64String, bool) {
	if !m.hasRecipe {
		return tagvalue.Base64String{}, false
	}

	return m.recipe, true
}

// SHA256HashSet selects the single parser-known baseline tuple.
func (m MessageInstance) SHA256HashSet() (HashSet, HashSelectionStatus) {
	sawUnknown := false
	for _, hashSet := range m.hashes {
		if hashSet.name == HashAlgorithmSHA256 && hashSet.known && hashSet.headerHash.DecodedLen() == 32 && hashSet.bodyHash.DecodedLen() == 32 {
			return hashSet.clone(), HashSelectionStatusSelected
		}
		if !hashSet.known {
			sawUnknown = true
		}
	}
	if sawUnknown {
		return HashSet{}, HashSelectionStatusUnsupported
	}
	return HashSet{}, HashSelectionStatusMissing
}

// HashSet stores one immutable h= algorithm/header/body hash tuple.
type HashSet struct {
	name            string
	known           bool
	headerHash      tagvalue.Base64String
	bodyHash        tagvalue.Base64String
	headerHashValue []byte
	bodyHashValue   []byte
}

// Name returns the canonical lowercase hash algorithm name.
func (h HashSet) Name() string {
	return h.name
}

// Known reports whether this hash set uses a parser-known algorithm.
func (h HashSet) Known() bool {
	return h.known
}

// HeaderHash returns the decoded header hash container for known algorithms.
func (h HashSet) HeaderHash() (tagvalue.Base64String, bool) {
	if !h.known {
		return tagvalue.Base64String{}, false
	}

	return h.headerHash, true
}

// BodyHash returns the decoded body hash container for known algorithms.
func (h HashSet) BodyHash() (tagvalue.Base64String, bool) {
	if !h.known {
		return tagvalue.Base64String{}, false
	}

	return h.bodyHash, true
}

// HeaderHashValue returns the parser-owned header hash component bytes.
func (h HashSet) HeaderHashValue() []byte {
	return bytes.Clone(h.headerHashValue)
}

// BodyHashValue returns the parser-owned body hash component bytes.
func (h HashSet) BodyHashValue() []byte {
	return bytes.Clone(h.bodyHashValue)
}

// clone returns a deep copy of one hash set.
func (h HashSet) clone() HashSet {
	h.headerHashValue = bytes.Clone(h.headerHashValue)
	h.bodyHashValue = bytes.Clone(h.bodyHashValue)

	return h
}

// cloneHashSets returns deep copies of parsed hash sets.
func cloneHashSets(input []HashSet) []HashSet {
	if len(input) == 0 {
		return nil
	}

	output := slices.Clone(input)
	for i := range output {
		output[i] = output[i].clone()
	}

	return output
}
