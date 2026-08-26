package signature

const maxSignatureSetsPerAlgorithm = 2

// signatureSetCardinality owns selector uniqueness and per-algorithm occurrence bounds.
type signatureSetCardinality struct {
	selectors map[string]struct{}
	counts    map[string]int
}

// newSignatureSetCardinality constructs bounded state sized for the enclosing set limit.
func newSignatureSetCardinality(capacity int) signatureSetCardinality {
	return signatureSetCardinality{
		selectors: make(map[string]struct{}, capacity),
		counts:    make(map[string]int, capacity),
	}
}

// add validates one already-canonical selector and algorithm without retaining raw values.
func (c *signatureSetCardinality) add(selector string, algorithm string, fieldIndex int, signatureIndex int) error {
	if _, exists := c.selectors[selector]; exists {
		return newError(ErrorCodeDuplicateSelector, ErrorLocation{FieldIndex: fieldIndex, SignatureIndex: signatureIndex}, ErrorDetails{
			Class:   ErrorClassDuplicate,
			TagName: TagNameSignatures,
		}, nil)
	}
	next := c.counts[algorithm] + 1
	if next > maxSignatureSetsPerAlgorithm {
		return newError(ErrorCodeTooManySignatures, ErrorLocation{FieldIndex: fieldIndex, SignatureIndex: signatureIndex}, ErrorDetails{
			Class:   ErrorClassLimit,
			TagName: TagNameSignatures,
			Limit:   maxSignatureSetsPerAlgorithm,
			Count:   next,
		}, nil)
	}
	c.selectors[selector] = struct{}{}
	c.counts[algorithm] = next
	return nil
}
