package combine

import "testing"

const (
	pass = ResultPass
	fail = ResultFail
	temp = ResultTempError
	perm = ResultPermError
)

// TestSignaturesFollowSection14_6 pins every Draft-08 Section 14.6 step 6
// and 7 combination rule, including the TEMPERROR precedence cases.
func TestSignaturesFollowSection14_6(t *testing.T) {
	tests := []struct {
		name     string
		sizes    []int
		results  []Result
		want     Result
		decisive int
	}{
		{"single pass", []int{1}, []Result{pass}, pass, 0},
		{"single fail", []int{1}, []Result{fail}, fail, 0},
		{"single temperror", []int{1}, []Result{temp}, temp, 0},
		{"single permerror", []int{1}, []Result{perm}, perm, 0},
		{"a|b with a FAIL and b PASS passes", []int{1, 1}, []Result{fail, pass}, pass, 1},
		{"a,b with b unknown is PERMERROR", []int{2}, []Result{pass, perm}, perm, 1},
		{"a,b with b key-missing and a PASS is PERMERROR", []int{2}, []Result{pass, perm}, perm, 1},
		{"a|b with a key-missing and b PASS passes", []int{1, 1}, []Result{perm, pass}, pass, 1},
		{"sig-all PERMERROR,TEMPERROR is PERMERROR", []int{2}, []Result{perm, temp}, perm, 0},
		{"sig-all PASS,TEMPERROR is TEMPERROR", []int{2}, []Result{pass, temp}, temp, 1},
		{"sig-all FAIL,TEMPERROR is FAIL", []int{2}, []Result{temp, fail}, fail, 1},
		{"sig-all FAIL,PERMERROR is FAIL", []int{2}, []Result{perm, fail}, fail, 1},
		{"sig-all all PASS", []int{3}, []Result{pass, pass, pass}, pass, 0},
		{"sig-any FAIL|TEMPERROR is TEMPERROR", []int{1, 1}, []Result{fail, temp}, temp, 1},
		{"sig-any FAIL|PERMERROR is FAIL", []int{1, 1}, []Result{perm, fail}, fail, 1},
		{"sig-any PERMERROR|PERMERROR is PERMERROR", []int{1, 1}, []Result{perm, perm}, perm, 0},
		{"a,b|c with a,b passing", []int{2, 1}, []Result{pass, pass, fail}, pass, 0},
		// The decisive set lies in the first group whose result equals the
		// overall result: a passing a inside the failing a,b group does not
		// explain the PASS, so c is decisive.
		{"a,b|c with c passing", []int{2, 1}, []Result{pass, fail, pass}, pass, 2},
		{"a,b|c with b failing and c TEMPERROR", []int{2, 1}, []Result{pass, fail, temp}, temp, 2},
		{"a,b|c with a FAIL, b TEMPERROR, c TEMPERROR picks c", []int{2, 1}, []Result{fail, temp, temp}, temp, 2},
		{"a,b|c,d with a TEMPERROR in a FAIL group picks c", []int{2, 2}, []Result{temp, fail, pass, temp}, temp, 3},
		{"a,b|c with a PASS in a TEMPERROR group and c PASS picks c", []int{2, 1}, []Result{pass, temp, pass}, pass, 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			layout, ok := NewLayout(test.sizes...)
			if !ok {
				t.Fatal("NewLayout rejected")
			}
			outcome := Signatures(layout, test.results)
			if !outcome.Valid() || outcome.Result() != test.want || outcome.Decisive() != test.decisive {
				t.Fatalf("Signatures() = %d decisive %d valid %t, want %d decisive %d", outcome.Result(), outcome.Decisive(), outcome.Valid(), test.want, test.decisive)
			}
			if outcome.Pass() != (test.want == pass) {
				t.Fatal("Pass() disagrees with Result()")
			}
		})
	}
}

// TestHashesFollowSection14_7 pins every Draft-08 Section 14.7 step 3 to 5
// combination rule.
func TestHashesFollowSection14_7(t *testing.T) {
	tests := []struct {
		name     string
		sizes    []int
		results  []Result
		want     Result
		decisive int
	}{
		{"single hash-set pass", []int{1}, []Result{pass}, pass, 0},
		{"single hash-set fail", []int{1}, []Result{fail}, fail, 0},
		{"single unknown hash-set is PERMERROR", []int{1}, []Result{perm}, perm, 0},
		{"sha256|x-new with sha256 PASS passes", []int{1, 1}, []Result{pass, perm}, pass, 0},
		{"sha256,x-new is PERMERROR", []int{2}, []Result{pass, perm}, perm, 1},
		{"hash-all with one FAIL and one PERMERROR is FAIL", []int{2}, []Result{perm, fail}, fail, 1},
		{"mismatch in one group and PASS in another passes", []int{1, 1}, []Result{fail, pass}, pass, 1},
		{"hash-any FAIL|PERMERROR is FAIL", []int{1, 1}, []Result{perm, fail}, fail, 1},
		{"hash-any PERMERROR|PERMERROR is PERMERROR", []int{1, 1}, []Result{perm, perm}, perm, 0},
		{"a,b|c with a PASS in a FAIL group and c PASS picks c", []int{2, 1}, []Result{pass, fail, pass}, pass, 2},
		{"a,b|c with a PASS in a PERMERROR group and c PASS picks c", []int{2, 1}, []Result{pass, perm, pass}, pass, 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			layout, ok := NewLayout(test.sizes...)
			if !ok {
				t.Fatal("NewLayout rejected")
			}
			outcome := Hashes(layout, test.results)
			if !outcome.Valid() || outcome.Result() != test.want || outcome.Decisive() != test.decisive {
				t.Fatalf("Hashes() = %d decisive %d valid %t, want %d decisive %d", outcome.Result(), outcome.Decisive(), outcome.Valid(), test.want, test.decisive)
			}
		})
	}
}

// TestHashesNeverYieldTempError pins that a TEMPERROR hash intermediate is a
// contract violation, because Section 14.7 defines none.
func TestHashesNeverYieldTempError(t *testing.T) {
	layout, _ := NewLayout(1, 1)
	if outcome := Hashes(layout, []Result{temp, pass}); outcome.Valid() {
		t.Fatal("Hashes accepted a TEMPERROR intermediate")
	}
}

// TestCombinationRejectsIncoherentInput proves a layout that does not
// describe the intermediates, or an unknown intermediate, fails closed.
func TestCombinationRejectsIncoherentInput(t *testing.T) {
	layout, _ := NewLayout(2)
	for _, results := range [][]Result{{pass}, {pass, pass, pass}, {pass, Result(0)}, {pass, Result(9)}} {
		if Signatures(layout, results).Valid() || Hashes(layout, results).Valid() {
			t.Fatalf("combination accepted %v", results)
		}
	}
	if Signatures(Layout{}, nil).Valid() {
		t.Fatal("combination accepted an invalid layout")
	}
}

// FuzzSignatureCombination checks that the overall signature result always
// equals the intermediate of its decisive set, that the decisive set lies in
// the first group whose own result equals the overall result, and that it is
// the first set in that group carrying that result.
func FuzzSignatureCombination(f *testing.F) {
	f.Add([]byte{2, 1}, []byte{1, 2, 3})
	f.Add([]byte{1, 1, 1}, []byte{4, 3, 2})
	f.Fuzz(func(t *testing.T, sizes []byte, raw []byte) {
		groupSizes := make([]int, len(sizes))
		for index, size := range sizes {
			groupSizes[index] = int(size % 5)
		}
		layout, ok := NewLayout(groupSizes...)
		if !ok || layout.Sets() > len(raw) {
			return
		}
		results := make([]Result, layout.Sets())
		for index := range results {
			results[index] = Result(raw[index]%4 + 1)
		}
		for _, combination := range []func(Layout, []Result) Outcome{Signatures, Hashes} {
			outcome := combination(layout, results)
			if !outcome.Valid() {
				continue
			}
			if results[outcome.Decisive()] != outcome.Result() {
				t.Fatalf("decisive set %d does not carry the overall result", outcome.Decisive())
			}
			assertDecisiveGroup(t, layout, results, outcome, combination)
		}
	})
}

// assertDecisiveGroup checks that the decisive set is the first set carrying
// the overall result inside the first group whose own result, computed by
// the same combination over that group alone, equals the overall result.
func assertDecisiveGroup(t *testing.T, layout Layout, results []Result, outcome Outcome, combination func(Layout, []Result) Outcome) {
	t.Helper()
	start := 0
	for _, size := range layout.GroupSizes() {
		single, _ := NewLayout(size)
		group := combination(single, results[start:start+size])
		if group.Valid() && group.Result() == outcome.Result() {
			for index := start; index < start+size; index++ {
				if results[index] == outcome.Result() {
					if outcome.Decisive() != index {
						t.Fatalf("decisive set %d, want %d", outcome.Decisive(), index)
					}
					return
				}
			}
		}
		start += size
	}
	t.Fatal("no group carries the overall result")
}
