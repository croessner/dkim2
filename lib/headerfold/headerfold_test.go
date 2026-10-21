package headerfold

import (
	"strings"
	"testing"
)

// TestRestoreRebuildsLibraryFoldPoints proves a projected composite signature
// value regains its continuation lines and nothing else changes.
func TestRestoreRebuildsLibraryFoldPoints(t *testing.T) {
	chunk := strings.Repeat("A", 64)
	value := " i=1;\tm=1;\td=example.test;\ts=sel:mldsa44-ed25519-sha512:" +
		strings.TrimSuffix(strings.Repeat(chunk+"\t", 52), "\t") + ";"
	folded := Restore(value)
	if strings.ReplaceAll(folded, "\n", "") != value ||
		strings.Count(folded, "\n\t") != strings.Count(value, "\t") ||
		strings.Contains(folded, "\r") {
		t.Fatal("Restore changed more than the fold points")
	}
	if !WithinLineLimit("DKIM2-Signature", folded) {
		t.Fatal("restored composite signature exceeds the line limit")
	}
	if WithinLineLimit("DKIM2-Signature", value) {
		t.Fatal("unfolded composite signature was accepted as one line")
	}
	if Restore(" v=1; m=1") != " v=1; m=1" || Restore("") != "" {
		t.Fatal("value without fold points changed")
	}
	if Restore("\ti=1;\tm=1") != "\ti=1;\n\tm=1" {
		t.Fatal("leading post-colon TAB was treated as a fold point")
	}
}

// TestWithinLineLimitCountsTheFieldName proves the first physical line
// includes "name:" and the limit is inclusive.
func TestWithinLineLimitCountsTheFieldName(t *testing.T) {
	name := "X"
	exact := strings.Repeat("a", MaxLineOctets-len(name)-1)
	if !WithinLineLimit(name, exact) || WithinLineLimit(name, exact+"a") {
		t.Fatal("first-line limit is not exact")
	}
	if !WithinLineLimit(name, "a\n\t"+strings.Repeat("b", MaxLineOctets-1)) ||
		WithinLineLimit(name, "a\n\t"+strings.Repeat("b", MaxLineOctets)) {
		t.Fatal("continuation-line limit is not exact")
	}
}
