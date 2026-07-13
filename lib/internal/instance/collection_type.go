package instance

// Collection owns one immutable contiguous Message-Instance sequence.
type Collection struct {
	items       []MessageInstance
	byNumber    map[uint64]int
	highest     uint64
	initialized bool
}

// NewCollection validates and clones one nonempty contiguous sequence.
func NewCollection(items []MessageInstance) (Collection, error) {
	if len(items) == 0 {
		return Collection{}, newError(ErrorCodeMissingOrigin, ErrorLocation{}, ErrorDetails{Class: ErrorClassMalformed}, nil)
	}
	if err := ValidateSequence(items); err != nil {
		return Collection{}, err
	}
	cloned := make([]MessageInstance, len(items))
	byNumber := make(map[uint64]int, len(items))
	var highest uint64
	for index, item := range items {
		cloned[index] = item
		cloned[index].hashes = cloneHashSets(item.hashes)
		byNumber[item.number] = index
		if item.number > highest {
			highest = item.number
		}
	}
	return Collection{items: cloned, byNumber: byNumber, highest: highest, initialized: true}, nil
}

// Valid reports whether the collection is initialized and contiguous.
func (c Collection) Valid() bool {
	return c.initialized && len(c.items) > 0 && len(c.byNumber) == len(c.items) && c.highest == uint64(len(c.items))
}

// Len returns the retained instance count.
func (c Collection) Len() int { return len(c.items) }

// HighestNumber returns the greatest retained m= number.
func (c Collection) HighestNumber() uint64 {
	return c.highest
}

// ByNumber returns one detached instance by m= number.
func (c Collection) ByNumber(number uint64) (MessageInstance, bool) {
	if !c.Valid() {
		return MessageInstance{}, false
	}
	index, ok := c.byNumber[number]
	if !ok || index < 0 || index >= len(c.items) {
		return MessageInstance{}, false
	}
	item := c.items[index]
	item.hashes = cloneHashSets(item.hashes)
	return item, true
}
