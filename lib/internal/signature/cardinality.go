package signature

// selectorUniqueness owns the Draft-08 Section 10.9 rule that a Selector
// appears at most once in one DKIM2-Signature, across every sig-all group.
// Several sets may use the same algorithm with distinct selectors.
type selectorUniqueness struct {
	selectors map[string]struct{}
}

// newSelectorUniqueness constructs bounded state sized for the enclosing set limit.
func newSelectorUniqueness(capacity int) selectorUniqueness {
	return selectorUniqueness{selectors: make(map[string]struct{}, capacity)}
}

// add records one already-canonical selector and rejects a repeat without
// retaining raw values in the error.
func (u *selectorUniqueness) add(selector string, fieldIndex int, signatureIndex int) error {
	if _, exists := u.selectors[selector]; exists {
		return newError(ErrorCodeDuplicateSelector, ErrorLocation{FieldIndex: fieldIndex, SignatureIndex: signatureIndex}, ErrorDetails{
			Class:   ErrorClassDuplicate,
			TagName: TagNameSignatures,
		}, nil)
	}
	u.selectors[selector] = struct{}{}
	return nil
}
