package recipe

import "math"

// Usage records bounded work performed by one parse or apply operation.
type Usage struct {
	decodedBytes int
	emittedBytes int
	items        int
	workUnits    int
	initialized  bool
}

// Valid reports whether usage was initialized with nonnegative bounded counters.
func (u Usage) Valid() bool {
	return u.initialized && u.decodedBytes >= 0 && u.emittedBytes >= 0 && u.items >= 0 && u.workUnits >= 0
}

// DecodedBytes returns charged decoded recipe bytes.
func (u Usage) DecodedBytes() int { return u.decodedBytes }

// EmittedBytes returns charged reconstructed output bytes.
func (u Usage) EmittedBytes() int { return u.emittedBytes }

// Items returns charged structural and emitted items.
func (u Usage) Items() int { return u.items }

// WorkUnits returns total charged operation work.
func (u Usage) WorkUnits() int { return u.workUnits }

// newUsage returns initialized immutable usage, including the valid zero-work case.
func newUsage(decodedBytes, emittedBytes, items, workUnits int) Usage {
	usage := Usage{decodedBytes: decodedBytes, emittedBytes: emittedBytes, items: items, workUnits: workUnits, initialized: true}
	if !usage.Valid() {
		return Usage{}
	}
	return usage
}

type usageCounter struct {
	limits       Limits
	decodedBytes int
	emittedBytes int
	items        int
	workUnits    int
}

// newUsageCounter constructs one counter under resolved recipe limits.
func newUsageCounter(limits Limits) (*usageCounter, error) {
	resolved, err := limits.normalized()
	if err != nil {
		return nil, err
	}
	return &usageCounter{limits: resolved}, nil
}

// usage freezes the counter's current initialized accounting.
func (c *usageCounter) usage() Usage {
	if c == nil {
		return Usage{}
	}
	return newUsage(c.decodedBytes, c.emittedBytes, c.items, c.workUnits)
}

// chargeDecoded transactionally charges decoded bytes and scanning work.
func (c *usageCounter) chargeDecoded(count int) error {
	if c == nil || count < 0 {
		return newError(ErrorCodeInvalidState, ErrorLocation{}, ErrorDetails{Class: ErrorClassState}, nil)
	}
	decoded, ok := checkedAdd(c.decodedBytes, count)
	if !ok || decoded > c.limits.MaxDecodedRecipeBytes {
		return usageLimitError(limitNameMaxDecodedRecipeBytes, c.limits.MaxDecodedRecipeBytes, decoded)
	}
	work, ok := checkedAdd(c.workUnits, count)
	if !ok || work > c.limits.MaxOperationWorkUnits {
		return usageLimitError(limitNameMaxOperationWorkUnits, c.limits.MaxOperationWorkUnits, work)
	}
	c.decodedBytes, c.workUnits = decoded, work
	return nil
}

// chargeEmitted transactionally charges output bytes and emission work.
func (c *usageCounter) chargeEmitted(count int) error {
	if c == nil || count < 0 {
		return newError(ErrorCodeInvalidState, ErrorLocation{}, ErrorDetails{Class: ErrorClassState}, nil)
	}
	emitted, ok := checkedAdd(c.emittedBytes, count)
	if !ok || emitted > c.limits.MaxStateBytes {
		return usageLimitError(limitNameMaxStateBytes, c.limits.MaxStateBytes, emitted)
	}
	work, ok := checkedAdd(c.workUnits, count)
	if !ok || work > c.limits.MaxOperationWorkUnits {
		return usageLimitError(limitNameMaxOperationWorkUnits, c.limits.MaxOperationWorkUnits, work)
	}
	c.emittedBytes, c.workUnits = emitted, work
	return nil
}

// chargeItems transactionally charges item processing and one work unit per item.
func (c *usageCounter) chargeItems(count int) error {
	if c == nil || count < 0 {
		return newError(ErrorCodeInvalidState, ErrorLocation{}, ErrorDetails{Class: ErrorClassState}, nil)
	}
	items, ok := checkedAdd(c.items, count)
	if !ok {
		return usageLimitError(limitNameMaxOperationWorkUnits, c.limits.MaxOperationWorkUnits, math.MaxInt)
	}
	work, ok := checkedAdd(c.workUnits, count)
	if !ok || work > c.limits.MaxOperationWorkUnits {
		return usageLimitError(limitNameMaxOperationWorkUnits, c.limits.MaxOperationWorkUnits, work)
	}
	c.items, c.workUnits = items, work
	return nil
}

// chargeWork transactionally charges work not represented by another counter.
func (c *usageCounter) chargeWork(count int) error {
	if c == nil || count < 0 {
		return newError(ErrorCodeInvalidState, ErrorLocation{}, ErrorDetails{Class: ErrorClassState}, nil)
	}
	work, ok := checkedAdd(c.workUnits, count)
	if !ok || work > c.limits.MaxOperationWorkUnits {
		return usageLimitError(limitNameMaxOperationWorkUnits, c.limits.MaxOperationWorkUnits, work)
	}
	c.workUnits = work
	return nil
}

// checkedAdd adds nonnegative counters without integer overflow.
func checkedAdd(left, right int) (int, bool) {
	if left < 0 || right < 0 || left > math.MaxInt-right {
		return math.MaxInt, false
	}
	return left + right, true
}

// usageLimitError constructs one bounded counter-limit failure.
func usageLimitError(name string, limit, actual int) *Error {
	return newError(ErrorCodeLimitExceeded, ErrorLocation{}, ErrorDetails{
		Class: ErrorClassLimit, LimitName: name, Expected: limit, Actual: actual,
	}, nil)
}
