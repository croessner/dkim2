package filter

import "testing"

// TestWorkingSetBytesMatchesIndependentOracle proves every simultaneous owner is counted.
func TestWorkingSetBytesMatchesIndependentOracle(t *testing.T) {
	limits := DefaultLimits()
	got, ok := limits.WorkingSetBytes()
	const message = int64(32 << 20)
	const additions = int64(3 * (65_535 + 15 + 2))
	const encoded = ((message + 2) / 3) * 4
	const response = int64(7*(4<<20) + 3*(64<<10))
	const want = 4*message + 5*(message+512) + 2*encoded +
		3*(message+additions) + response + streamBufferBytes
	if !ok || got != want {
		t.Fatal("filter working-set arithmetic drifted")
	}
}

// TestWorkingSetBytesRejectsOneOverAndOverflow proves closed arithmetic boundaries.
func TestWorkingSetBytesRejectsOneOverAndOverflow(t *testing.T) {
	oneOver := DefaultLimits()
	oneOver.MessageBytes++
	if _, ok := oneOver.WorkingSetBytes(); ok {
		t.Fatal("one-over message limit accepted")
	}
	if _, ok := checkedFilterAdd(int64(^uint64(0)>>1), 1); ok {
		t.Fatal("addition overflow accepted")
	}
	if _, ok := checkedFilterMultiply(int64(^uint64(0)>>1), 2); ok {
		t.Fatal("multiplication overflow accepted")
	}
}
