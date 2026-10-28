// Package combine owns the Draft-08 AND/OR group structure shared by the
// Message-Instance h= (Section 9.3) and DKIM2-Signature s= (Section 10.9)
// tags: an ordered list of groups separated by "|", each an ordered list of
// sets separated by ",". A "," binds more tightly than "|".
package combine

const (
	// AllSeparator joins the sets of one hash-all or sig-all group.
	AllSeparator byte = ','
	// AnySeparator joins the alternative hash-all or sig-all groups.
	AnySeparator byte = '|'
)

// MaxSets is the hard bound of sets one layout can describe. It equals the
// hard max_hash_sets and max_signature_sets parser bounds, so a layout is a
// fixed-size value without heap state.
const MaxSets = 16

// Layout is the immutable group structure of one parsed or generated h= or
// s= value. Sets are numbered in field order; every group holds at least one
// set and groups are contiguous runs of that order.
type Layout struct {
	sizes  [MaxSets]uint8
	groups uint8
}

// NewLayout constructs a layout from ordered group sizes. It reports false
// when there is no group, a group is empty, or more than MaxSets sets are
// described, because Draft-08 grammar admits no empty group and the local
// bound admits no larger value.
func NewLayout(sizes ...int) (Layout, bool) {
	if len(sizes) == 0 || len(sizes) > MaxSets {
		return Layout{}, false
	}
	layout := Layout{groups: uint8(len(sizes))}
	total := 0
	for index, size := range sizes {
		if size <= 0 || size > MaxSets-total {
			return Layout{}, false
		}
		total += size
		layout.sizes[index] = uint8(size)
	}
	return layout, true
}

// SingleGroup returns the layout of one group holding count sets.
func SingleGroup(count int) (Layout, bool) {
	return NewLayout(count)
}

// Valid reports whether the layout holds at least one non-empty group.
func (l Layout) Valid() bool {
	if l.groups == 0 || int(l.groups) > MaxSets {
		return false
	}
	total := 0
	for index := range int(l.groups) {
		if l.sizes[index] == 0 {
			return false
		}
		total += int(l.sizes[index])
	}
	return total <= MaxSets
}

// Groups returns the number of "|"-separated groups.
func (l Layout) Groups() int { return int(l.groups) }

// Sets returns the number of sets across all groups.
func (l Layout) Sets() int {
	total := 0
	for index := range int(l.groups) {
		total += int(l.sizes[index])
	}
	return total
}

// GroupSizes returns the ordered group sizes.
func (l Layout) GroupSizes() []int {
	sizes := make([]int, l.groups)
	for index := range sizes {
		sizes[index] = int(l.sizes[index])
	}
	return sizes
}

// GroupOf returns the zero-based group index of the set at index in field
// order, or false outside the layout.
func (l Layout) GroupOf(index int) (int, bool) {
	start := 0
	for group := range int(l.groups) {
		size := int(l.sizes[group])
		if index >= start && index < start+size {
			return group, true
		}
		start += size
	}
	return 0, false
}

// Equal reports whether two layouts describe the same group structure.
func (l Layout) Equal(other Layout) bool { return l == other }

// SeparatorBefore returns the separator that precedes the set at index in
// field order: zero for the first set, AnySeparator at a group boundary, and
// AllSeparator inside a group. It returns zero for an index outside the
// layout.
func (l Layout) SeparatorBefore(index int) byte {
	if index <= 0 {
		return 0
	}
	start := 0
	for group := range int(l.groups) {
		size := int(l.sizes[group])
		if index == start {
			return AnySeparator
		}
		if index < start+size {
			return AllSeparator
		}
		start += size
	}
	return 0
}

// Split separates one unfolded h= or s= value into its raw set texts in
// field order and the group layout. The raw texts keep surrounding white
// space for the owning set parser. Split reports false when a group or set is
// empty, which covers leading, trailing, and doubled separators, or when the
// value holds more than MaxSets sets; callers enforce their own narrower
// bound with CountSets first.
func Split(value []byte) ([][]byte, Layout, bool) {
	if len(value) == 0 || CountSets(value) > MaxSets {
		return nil, Layout{}, false
	}
	sets := make([][]byte, 0, 1+countSeparators(value))
	sizes := make([]int, 0, 1)
	setStart, groupSize := 0, 0
	for index := 0; index <= len(value); index++ {
		atEnd := index == len(value)
		if !atEnd && value[index] != AllSeparator && value[index] != AnySeparator {
			continue
		}
		piece := value[setStart:index]
		if onlyWSP(piece) {
			return nil, Layout{}, false
		}
		sets = append(sets, piece)
		groupSize++
		if atEnd || value[index] == AnySeparator {
			sizes = append(sizes, groupSize)
			groupSize = 0
		}
		setStart = index + 1
	}
	layout, ok := NewLayout(sizes...)
	return sets, layout, ok
}

// CountSets returns the number of sets Split would produce, so callers can
// enforce local resource bounds before parsing set contents.
func CountSets(value []byte) int {
	if len(value) == 0 {
		return 0
	}
	return 1 + countSeparators(value)
}

// countSeparators counts "," and "|" bytes.
func countSeparators(value []byte) int {
	count := 0
	for _, b := range value {
		if b == AllSeparator || b == AnySeparator {
			count++
		}
	}
	return count
}

// onlyWSP reports whether input is empty or holds only space and tab bytes.
func onlyWSP(input []byte) bool {
	for _, b := range input {
		if b != ' ' && b != '\t' {
			return false
		}
	}
	return true
}
