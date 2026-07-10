package instance

import "github.com/croessner/dkim2/internal/rawmsg"

// Extract parses all Message-Instance fields from msg with default limits.
func Extract(msg rawmsg.Message) ([]MessageInstance, error) {
	parser, err := NewParser(Limits{})
	if err != nil {
		return nil, err
	}

	return parser.Extract(msg)
}

// Extract parses Message-Instance fields from msg in raw header occurrence order.
func (p Parser) Extract(msg rawmsg.Message) ([]MessageInstance, error) {
	fields := msg.Headers().FieldsByName(HeaderName)
	instances := make([]MessageInstance, 0, len(fields))
	for _, field := range fields {
		parsed, err := p.ParseField(field)
		if err != nil {
			return nil, err
		}
		instances = append(instances, parsed)
	}
	if err := ValidateSequence(instances); err != nil {
		return nil, err
	}

	return instances, nil
}

// ValidateSequence validates contiguous Message-Instance m= numbers from origin.
func ValidateSequence(instances []MessageInstance) error {
	if len(instances) == 0 {
		return nil
	}

	seen := make(map[uint64]int, len(instances))
	maxNumber := uint64(0)
	for _, parsed := range instances {
		number := parsed.Number()
		if firstIndex, exists := seen[number]; exists {
			return newSequenceError(ErrorCodeDuplicateNumber, parsed.HeaderIndex(), number, number, firstIndex)
		}
		seen[number] = parsed.HeaderIndex()
		if number > maxNumber {
			maxNumber = number
		}
	}
	if _, ok := seen[1]; !ok {
		return newSequenceError(ErrorCodeMissingOrigin, firstInstanceIndex(instances), 1, lowestObservedNumber(instances), 0)
	}

	for expected := uint64(1); expected <= maxNumber; expected++ {
		if _, ok := seen[expected]; ok {
			continue
		}

		observed, fieldIndex := nextObservedNumber(instances, expected)
		return newSequenceError(ErrorCodeSequenceGap, fieldIndex, expected, observed, 0)
	}

	return nil
}

// firstInstanceIndex returns the first raw header index in a parsed collection.
func firstInstanceIndex(instances []MessageInstance) int {
	if len(instances) == 0 {
		return 0
	}

	return instances[0].HeaderIndex()
}

// lowestObservedNumber returns the lowest m= number in a parsed collection.
func lowestObservedNumber(instances []MessageInstance) uint64 {
	lowest := instances[0].Number()
	for _, parsed := range instances[1:] {
		if parsed.Number() < lowest {
			lowest = parsed.Number()
		}
	}

	return lowest
}

// nextObservedNumber returns the smallest observed m= number above expected.
func nextObservedNumber(instances []MessageInstance, expected uint64) (uint64, int) {
	var observed uint64
	fieldIndex := firstInstanceIndex(instances)
	for _, parsed := range instances {
		number := parsed.Number()
		if number <= expected {
			continue
		}
		if observed == 0 || number < observed {
			observed = number
			fieldIndex = parsed.HeaderIndex()
		}
	}

	return observed, fieldIndex
}

// newSequenceError constructs bounded Message-Instance sequence diagnostics.
func newSequenceError(code ErrorCode, fieldIndex int, expected uint64, observed uint64, duplicateOf int) *Error {
	details := ErrorDetails{
		Class:          ErrorClassMalformed,
		TagName:        "m",
		ExpectedNumber: expected,
		ObservedNumber: observed,
	}
	if code == ErrorCodeDuplicateNumber {
		details.Class = ErrorClassDuplicate
		details.Count = duplicateOf + 1
	}

	return newError(code, ErrorLocation{FieldIndex: fieldIndex}, details, nil)
}
