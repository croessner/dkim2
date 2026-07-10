package signature

import (
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
)

// Extract parses all DKIM2-Signature fields from msg with default limits.
func Extract(msg rawmsg.Message) ([]Signature, error) {
	parser, err := NewParser(Limits{})
	if err != nil {
		return nil, err
	}

	return parser.Extract(msg)
}

// Extract parses DKIM2-Signature fields from msg in raw header occurrence order.
func (p Parser) Extract(msg rawmsg.Message) ([]Signature, error) {
	fields := msg.Headers().FieldsByName(HeaderName)
	signatures := make([]Signature, 0, len(fields))
	for _, field := range fields {
		parsed, err := p.ParseField(field)
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, parsed)
	}
	if err := ValidateSequence(signatures); err != nil {
		return nil, err
	}

	return signatures, nil
}

// ValidateSequence validates contiguous DKIM2-Signature i= numbers from origin.
func ValidateSequence(signatures []Signature) error {
	if len(signatures) == 0 {
		return nil
	}

	seen := make(map[uint64]int, len(signatures))
	maxSequence := uint64(0)
	for _, parsed := range signatures {
		sequence := parsed.Sequence()
		if firstIndex, exists := seen[sequence]; exists {
			return newSequenceError(ErrorCodeDuplicateSequence, parsed.HeaderIndex(), sequence, sequence, firstIndex)
		}
		seen[sequence] = parsed.HeaderIndex()
		if sequence > maxSequence {
			maxSequence = sequence
		}
	}
	if _, ok := seen[1]; !ok {
		return newSequenceError(ErrorCodeMissingOrigin, firstSignatureIndex(signatures), 1, lowestObservedSequence(signatures), 0)
	}

	for expected := uint64(1); expected <= maxSequence; expected++ {
		if _, ok := seen[expected]; ok {
			continue
		}

		observed, fieldIndex := nextObservedSequence(signatures, expected)
		return newSequenceError(ErrorCodeSequenceGap, fieldIndex, expected, observed, 0)
	}

	return nil
}

// ValidateInstanceReferences reports instances above every signature m= reference.
func ValidateInstanceReferences(instances []instance.MessageInstance, signatures []Signature) error {
	if len(instances) == 0 || len(signatures) == 0 {
		return nil
	}

	maxReference := uint64(0)
	for _, parsed := range signatures {
		if parsed.InstanceNumber() > maxReference {
			maxReference = parsed.InstanceNumber()
		}
	}

	for _, parsed := range instances {
		if parsed.Number() <= maxReference {
			continue
		}

		return newError(ErrorCodeUnreferencedInstance, ErrorLocation{FieldIndex: parsed.HeaderIndex()}, ErrorDetails{
			TagName:        "m",
			ExpectedNumber: maxReference,
			ObservedNumber: parsed.Number(),
		}, nil)
	}

	return nil
}

// firstSignatureIndex returns the first raw header index in a parsed collection.
func firstSignatureIndex(signatures []Signature) int {
	if len(signatures) == 0 {
		return 0
	}

	return signatures[0].HeaderIndex()
}

// lowestObservedSequence returns the lowest i= number in a parsed collection.
func lowestObservedSequence(signatures []Signature) uint64 {
	lowest := signatures[0].Sequence()
	for _, parsed := range signatures[1:] {
		if parsed.Sequence() < lowest {
			lowest = parsed.Sequence()
		}
	}

	return lowest
}

// nextObservedSequence returns the smallest observed i= number above expected.
func nextObservedSequence(signatures []Signature, expected uint64) (uint64, int) {
	var observed uint64
	fieldIndex := firstSignatureIndex(signatures)
	for _, parsed := range signatures {
		sequence := parsed.Sequence()
		if sequence <= expected {
			continue
		}
		if observed == 0 || sequence < observed {
			observed = sequence
			fieldIndex = parsed.HeaderIndex()
		}
	}

	return observed, fieldIndex
}

// newSequenceError constructs bounded DKIM2-Signature sequence diagnostics.
func newSequenceError(code ErrorCode, fieldIndex int, expected uint64, observed uint64, duplicateOf int) *Error {
	details := ErrorDetails{
		Class:          ErrorClassMalformed,
		TagName:        "i",
		ExpectedNumber: expected,
		ObservedNumber: observed,
	}
	if code == ErrorCodeDuplicateSequence {
		details.Class = ErrorClassDuplicate
		details.Count = duplicateOf + 1
	}

	return newError(code, ErrorLocation{FieldIndex: fieldIndex}, details, nil)
}
