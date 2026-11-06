package signature

import (
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"slices"
)

// OrderBySequence returns a detached semantic i= ordering after complete sequence validation.
func OrderBySequence(signatures []Signature) ([]Signature, error) {
	if err := ValidateSequence(signatures); err != nil {
		return nil, err
	}
	ordered := make([]Signature, len(signatures))
	for _, parsed := range signatures {
		ordered[parsed.Sequence()-1] = parsed
	}
	return slices.Clone(ordered), nil
}

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
	if len(fields) > p.limits.MaxSignatures {
		return nil, newError(ErrorCodeLimitExceeded, ErrorLocation{}, ErrorDetails{
			Class: ErrorClassLimit, LimitName: "max_signatures", Limit: p.limits.MaxSignatures, Count: len(fields),
		}, nil)
	}
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
	if len(signatures) > DefaultLimits().MaxSignatures {
		return newError(ErrorCodeLimitExceeded, ErrorLocation{}, ErrorDetails{
			Class: ErrorClassLimit, LimitName: "max_signatures", Limit: DefaultLimits().MaxSignatures, Count: len(signatures),
		}, nil)
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

	if maxSequence != uint64(len(signatures)) {
		for expected := uint64(1); expected <= uint64(len(signatures)); expected++ {
			if _, ok := seen[expected]; ok {
				continue
			}
			observed, fieldIndex := nextObservedSequence(signatures, expected)
			return newSequenceError(ErrorCodeSequenceGap, fieldIndex, expected, observed, 0)
		}
		return newSequenceError(ErrorCodeSequenceGap, firstSignatureIndex(signatures), uint64(len(signatures)), maxSequence, 0)
	}

	return nil
}

// ValidateInstanceReferences enforces existing nondecreasing m= references and current coverage.
func ValidateInstanceReferences(instances []instance.MessageInstance, signatures []Signature) error {
	if err := instance.ValidateSequence(instances); err != nil {
		return err
	}
	if err := ValidateSequence(signatures); err != nil {
		return err
	}
	if len(instances) == 0 && len(signatures) == 0 {
		return nil
	}
	if len(instances) == 0 {
		return newError(ErrorCodeInvalidInstanceReference, ErrorLocation{FieldIndex: signatures[0].HeaderIndex()}, ErrorDetails{
			TagName: TagNameInstance, ObservedNumber: signatures[0].InstanceNumber(),
		}, nil)
	}
	instanceNumbers := make(map[uint64]struct{}, len(instances))
	highestInstance := uint64(0)
	highestFieldIndex := 0
	for _, parsed := range instances {
		instanceNumbers[parsed.Number()] = struct{}{}
		if parsed.Number() > highestInstance {
			highestInstance = parsed.Number()
			highestFieldIndex = parsed.HeaderIndex()
		}
	}
	if len(signatures) == 0 {
		return newError(ErrorCodeUnreferencedInstance, ErrorLocation{FieldIndex: highestFieldIndex}, ErrorDetails{
			TagName: TagNameInstance, ObservedNumber: highestInstance,
		}, nil)
	}
	ordered, err := OrderBySequence(signatures)
	if err != nil {
		return err
	}
	previousReference := uint64(0)
	for _, parsed := range ordered {
		reference := parsed.InstanceNumber()
		if _, exists := instanceNumbers[reference]; !exists || reference < previousReference {
			return newError(ErrorCodeInvalidInstanceReference, ErrorLocation{FieldIndex: parsed.HeaderIndex()}, ErrorDetails{
				TagName: TagNameInstance, ExpectedNumber: previousReference, ObservedNumber: reference,
			}, nil)
		}
		previousReference = reference
	}
	if previousReference != highestInstance {
		return newError(ErrorCodeUnreferencedInstance, ErrorLocation{FieldIndex: highestFieldIndex}, ErrorDetails{
			TagName:        "m",
			ExpectedNumber: previousReference,
			ObservedNumber: highestInstance,
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
