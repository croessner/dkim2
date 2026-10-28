package combine

import (
	"bytes"
	"slices"
	"testing"
)

// TestSplitAcceptsDraft08GroupGrammar pins the hash-any/sig-any grammar:
// "|" separates groups, "," binds more tightly, and [FWS] may surround both
// separators.
func TestSplitAcceptsDraft08GroupGrammar(t *testing.T) {
	tests := []struct {
		name  string
		value string
		sets  []string
		sizes []int
	}{
		{"single set", "a", []string{"a"}, []int{1}},
		{"one all group", "a,b", []string{"a", "b"}, []int{2}},
		{"two any groups", "a|b", []string{"a", "b"}, []int{1, 1}},
		{"comma binds tighter", "a,b|c", []string{"a", "b", "c"}, []int{2, 1}},
		{"wsp around separators", "a \t, b\t|\t c", []string{"a \t", " b\t", "\t c"}, []int{2, 1}},
		{"three groups", "a|b,c|d", []string{"a", "b", "c", "d"}, []int{1, 2, 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sets, layout, ok := Split([]byte(test.value))
			if !ok {
				t.Fatalf("Split(%q) rejected", test.value)
			}
			if len(sets) != len(test.sets) {
				t.Fatalf("Split(%q) sets = %q", test.value, sets)
			}
			for index := range sets {
				if !bytes.Equal(sets[index], []byte(test.sets[index])) {
					t.Fatalf("Split(%q) set %d = %q, want %q", test.value, index, sets[index], test.sets[index])
				}
			}
			if !slices.Equal(layout.GroupSizes(), test.sizes) || layout.Sets() != len(test.sets) || CountSets([]byte(test.value)) != len(test.sets) {
				t.Fatalf("Split(%q) layout = %v", test.value, layout.GroupSizes())
			}
		})
	}
}

// TestSplitRejectsEmptyGroupsAndSeparators pins that empty groups and
// leading, trailing, or doubled separators are syntax errors.
func TestSplitRejectsEmptyGroupsAndSeparators(t *testing.T) {
	for _, value := range []string{"", " ", ",a", "a,", "a,,b", "|a", "a|", "a||b", "a|,b", "a,|b", "a| |b", "a, ,b", "a|\t"} {
		if _, _, ok := Split([]byte(value)); ok {
			t.Fatalf("Split(%q) accepted, want syntax error", value)
		}
	}
}

// TestLayoutSeparatorBefore proves the separator owner returns "," inside a
// group and "|" at group boundaries.
func TestLayoutSeparatorBefore(t *testing.T) {
	layout, ok := NewLayout(2, 1, 2)
	if !ok {
		t.Fatal("NewLayout rejected")
	}
	want := []byte{0, ',', '|', '|', ','}
	for index, separator := range want {
		if got := layout.SeparatorBefore(index); got != separator {
			t.Fatalf("SeparatorBefore(%d) = %q, want %q", index, got, separator)
		}
	}
	if layout.SeparatorBefore(5) != 0 {
		t.Fatal("SeparatorBefore outside layout must be zero")
	}
	if _, ok := NewLayout(); ok {
		t.Fatal("NewLayout() without groups accepted")
	}
	if _, ok := NewLayout(1, 0); ok {
		t.Fatal("NewLayout with an empty group accepted")
	}
	if (Layout{}).Valid() {
		t.Fatal("zero Layout is valid")
	}
}

// FuzzSplit checks that Split never accepts an empty set, that the layout
// always describes the returned sets, and that rejoining the raw sets with
// the layout separators reproduces the input exactly.
func FuzzSplit(f *testing.F) {
	for _, seed := range []string{"a", "a,b|c", " a , b | c ", "|", "a||b", "a,", ""} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		sets, layout, ok := Split(input)
		if !ok {
			return
		}
		if !layout.Valid() || layout.Sets() != len(sets) || CountSets(input) != len(sets) {
			t.Fatalf("layout %v does not describe %d sets", layout.GroupSizes(), len(sets))
		}
		var rejoined []byte
		for index, set := range sets {
			if onlyWSP(set) {
				t.Fatalf("Split accepted empty set %d", index)
			}
			if separator := layout.SeparatorBefore(index); separator != 0 {
				rejoined = append(rejoined, separator)
			}
			rejoined = append(rejoined, set...)
		}
		if !bytes.Equal(rejoined, input) {
			t.Fatalf("rejoined %q != input %q", rejoined, input)
		}
	})
}
