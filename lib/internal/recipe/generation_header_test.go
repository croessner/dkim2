package recipe

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

const (
	testCandidateKeyBytesLabel = "candidate key bytes"
	testComparisonsLabel       = "comparisons"
	testExcludedHeaderName     = "x-test"
	testExactBoundaryLabel     = "exact"
	testInputBytesLabel        = "input bytes"
	testInputItemsLabel        = "input items"
	testOneUnderLabel          = "one under"
	testTotalCopiedItemsLabel  = "total copied items"
)

type selectiveHeaderRelevance struct {
	excluded string
}

// Validate implements an immutable selective HeaderRelevance test double.
func (selectiveHeaderRelevance) Validate() error { return nil }

// IsRelevantHeader excludes one canonical name for omission tests.
func (r selectiveHeaderRelevance) IsRelevantHeader(name string) (bool, error) {
	return name != r.excluded, nil
}

type flippingHeaderRelevance struct {
	mu         sync.Mutex
	calls      int
	flipAfter  int
	errorAfter int
}

type recordingHeaderRelevance struct {
	mu          sync.Mutex
	calls       []string
	excluded    string
	errorName   string
	errorOnCall int
}

// Validate implements HeaderRelevance for ordered full-surface proofs.
func (*recordingHeaderRelevance) Validate() error { return nil }

// IsRelevantHeader records ordered calls and optionally fails one occurrence opaquely.
func (r *recordingHeaderRelevance) IsRelevantHeader(name string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, name)
	occurrences := 0
	for _, called := range r.calls {
		if called == name {
			occurrences++
		}
	}
	if name == r.errorName && occurrences == r.errorOnCall {
		return false, errors.New("protected-callback-marker")
	}
	return name != r.excluded, nil
}

// Validate implements HeaderRelevance for final reclassification tests.
func (*flippingHeaderRelevance) Validate() error { return nil }

// IsRelevantHeader changes after the configured classification call.
func (r *flippingHeaderRelevance) IsRelevantHeader(string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.errorAfter > 0 && r.calls > r.errorAfter {
		return false, errors.New("Subject: protected-callback-marker")
	}
	return r.calls <= r.flipAfter, nil
}

// TestPlanHeadersUsesInverseExactUnfoldedSemantics verifies core draft-04 vectors.
func TestPlanHeadersUsesInverseExactUnfoldedSemantics(t *testing.T) {
	tests := []struct {
		name          string
		previous      []byte
		current       []byte
		wantNames     []string
		wantStepKinds []StepKind
		wantCopies    [][2]int
		wantData      []string
	}{
		{name: "unchanged", previous: []byte("A: same\r\n\r\nbody\r\n"), current: []byte("A: same\r\n\r\nbody\r\n")},
		{name: "case only name", previous: []byte("a: same\r\n\r\nbody\r\n"), current: []byte("A: same\r\n\r\nbody\r\n")},
		{name: "physical folding", previous: []byte("A: one\r\n two\r\n\r\nbody\r\n"), current: []byte("a: one two\r\n\r\nbody\r\n")},
		{name: "replace", previous: []byte("A: previous\r\n\r\nbody\r\n"), current: []byte("A: current\r\n\r\nbody\r\n"), wantNames: []string{"a"}, wantStepKinds: []StepKind{StepKindData}, wantData: []string{" previous"}},
		{name: "empty previous value", previous: []byte("A:\r\n\r\nbody\r\n"), current: []byte("A: current\r\n\r\nbody\r\n"), wantNames: []string{"a"}, wantStepKinds: []StepKind{StepKindData}, wantData: []string{""}},
		{name: "remove current group", previous: []byte("B: retained\r\n\r\nbody\r\n"), current: []byte("A: removed\r\nB: retained\r\n\r\nbody\r\n"), wantNames: []string{"a"}},
		{name: "add previous group", previous: []byte("A: restored\r\nB: retained\r\n\r\nbody\r\n"), current: []byte("B: retained\r\n\r\nbody\r\n"), wantNames: []string{"a"}, wantStepKinds: []StepKind{StepKindData}, wantData: []string{" restored"}},
		{name: "exact unfolded whitespace", previous: []byte("A: one  two\r\n\r\nbody\r\n"), current: []byte("A: one two\r\n\r\nbody\r\n"), wantNames: []string{"a"}, wantStepKinds: []StepKind{StepKindData}, wantData: []string{" one  two"}},
		{name: "mixed coalesced", previous: []byte("A: new-two\r\nA: new-one\r\nA: two\r\nA: one\r\n\r\nbody\r\n"), current: []byte("A: three\r\nA: two\r\nA: one\r\n\r\nbody\r\n"), wantNames: []string{"a"}, wantStepKinds: []StepKind{StepKindCopy, StepKindData}, wantCopies: [][2]int{{1, 2}}, wantData: []string{" new-one", " new-two"}},
		{name: "earliest duplicate monotone", previous: []byte("A: duplicate\r\nA: duplicate\r\n\r\nbody\r\n"), current: []byte("A: duplicate\r\nA: middle\r\nA: duplicate\r\n\r\nbody\r\n"), wantNames: []string{"a"}, wantStepKinds: []StepKind{StepKindCopy, StepKindCopy}, wantCopies: [][2]int{{1, 1}, {3, 3}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, _, err := mustPlanHeaders(t, test.previous, test.current, AllowLiterals, testHeaderRelevance{relevant: true}, GenerationLimits{})
			if err != nil {
				t.Fatalf("planHeaders() code=%s class=%s", recipeTestErrorCode(err), recipeTestErrorClass(err))
			}
			plans := result.headerPlans()
			if got := headerPlanNames(plans); !equalHeaderPlanNames(got, test.wantNames) {
				t.Fatalf("plan names mismatch: got_count=%d want_count=%d", len(got), len(test.wantNames))
			}
			if len(plans) == 0 {
				return
			}
			assertHeaderSteps(t, plans[0].stepsCopy(), test.wantStepKinds, test.wantCopies, test.wantData)
		})
	}
}

// TestPlanHeadersSortsNamesAndOmitsExcludedGroups verifies deterministic relevance handling.
func TestPlanHeadersSortsNamesAndOmitsExcludedGroups(t *testing.T) {
	previous := []byte("Z: old\r\nX-Test: protected-old\r\nA: old\r\n\r\nbody\r\n")
	current := []byte("a: new\r\nX-Test: protected-new\r\nz: new\r\n\r\nbody\r\n")
	result, _, err := mustPlanHeaders(t, previous, current, AllowLiterals, selectiveHeaderRelevance{excluded: testExcludedHeaderName}, GenerationLimits{})
	if err != nil {
		t.Fatalf("planHeaders() code=%s", recipeTestErrorCode(err))
	}
	if got := headerPlanNames(result.headerPlans()); !equalHeaderPlanNames(got, []string{"a", "z"}) {
		t.Fatalf("sorted plan names count=%d", len(got))
	}

	excludedOnly, _, err := mustPlanHeaders(t,
		[]byte("X-Test: previous\r\n\r\nbody\r\n"),
		[]byte("X-Test: current\r\n\r\nbody\r\n"),
		AllowLiterals, selectiveHeaderRelevance{excluded: testExcludedHeaderName}, GenerationLimits{})
	if err != nil || !excludedOnly.Valid() || excludedOnly.Changed() {
		t.Fatalf("excluded-only result: valid=%t changed=%t code=%s", excludedOnly.Valid(), excludedOnly.Changed(), recipeTestErrorCode(err))
	}
}

// TestPlanHeadersEnforcesPerNameBytes verifies the longest canonical key boundary.
func TestPlanHeadersEnforcesPerNameBytes(t *testing.T) {
	previous := []byte("AA: old\r\n\r\nbody\r\n")
	current := []byte("aa: new\r\n\r\nbody\r\n")
	for _, test := range []struct {
		name    string
		limit   int
		wantErr bool
	}{{name: testExactBoundaryLabel, limit: 2}, {name: testOneUnderLabel, limit: 1, wantErr: true}} {
		t.Run(test.name, func(t *testing.T) {
			limits := GenerationLimits{RecipeLimits: DefaultLimits()}
			limits.RecipeLimits.MaxHeaderNameBytes = test.limit
			result, usage, err := mustPlanHeaders(t, previous, current, AllowLiterals, testHeaderRelevance{relevant: true}, limits)
			if test.wantErr {
				if result.Valid() || !usage.Valid() || recipeTestLimitName(err) != limitNameMaxHeaderNameBytes {
					t.Fatalf("per-name failure: valid=%t usage=%t code=%s", result.Valid(), usage.Valid(), recipeTestErrorCode(err))
				}
				return
			}
			if err != nil || !result.Valid() {
				t.Fatalf("per-name exact: valid=%t code=%s", result.Valid(), recipeTestErrorCode(err))
			}
		})
	}
}

// TestPlanHeadersRechecksAllSortedNamesIncludingExcluded verifies the complete final proof surface.
func TestPlanHeadersRechecksAllSortedNamesIncludingExcluded(t *testing.T) {
	relevance := &recordingHeaderRelevance{excluded: testExcludedHeaderName}
	result, _, err := mustPlanHeaders(t,
		[]byte("Z: old\r\nX-Test: old\r\nA: old\r\n\r\nbody\r\n"),
		[]byte("A: new\r\nX-Test: new\r\nZ: new\r\n\r\nbody\r\n"),
		AllowLiterals, relevance, GenerationLimits{})
	if err != nil || !result.Valid() {
		t.Fatalf("full relevance proof: valid=%t code=%s", result.Valid(), recipeTestErrorCode(err))
	}
	if !equalHeaderPlanNames(relevance.calls, []string{"a", testExcludedHeaderName, "z", "a", testExcludedHeaderName, "z"}) {
		t.Fatalf("relevance call count=%d", len(relevance.calls))
	}

	failing := &recordingHeaderRelevance{excluded: testExcludedHeaderName, errorName: testExcludedHeaderName, errorOnCall: 2}
	failed, usage, err := mustPlanHeaders(t,
		[]byte("X-Test: old\r\nA: old\r\n\r\nbody\r\n"),
		[]byte("A: new\r\nX-Test: new\r\n\r\nbody\r\n"),
		AllowLiterals, failing, GenerationLimits{})
	if failed.Valid() || !usage.Valid() {
		t.Fatalf("excluded callback failure: valid=%t usage=%t", failed.Valid(), usage.Valid())
	}
	assertClosedSafeGenerationError(t, err, ErrorCodeHeaderRelevance, ErrorClassInvariant, "protected-callback-marker")
}

// TestPlanHeadersCopyOnlyMixedPlanUsesNoLiterals verifies successful disclosure-free planning.
func TestPlanHeadersCopyOnlyMixedPlanUsesNoLiterals(t *testing.T) {
	previous := []byte("A: three\r\nA: one\r\n\r\nbody\r\n")
	current := []byte("A: three\r\nA: two\r\nA: one\r\n\r\nbody\r\n")
	result, usage, err := mustPlanHeaders(t, previous, current, CopyOnly, testHeaderRelevance{relevant: true}, GenerationLimits{})
	if err != nil || !result.Valid() || !result.Changed() {
		t.Fatalf("copy-only mixed result: valid=%t changed=%t code=%s", result.Valid(), result.Changed(), recipeTestErrorCode(err))
	}
	if usage.LiteralBytes() != 0 {
		t.Fatalf("copy-only literal bytes=%d", usage.LiteralBytes())
	}
	assertHeaderSteps(t, result.headerPlans()[0].stepsCopy(), []StepKind{StepKindCopy, StepKindCopy}, [][2]int{{1, 1}, {3, 3}}, nil)
}

// TestPlanHeadersDoesNotCopyBackwardAcrossInterleaving verifies monotone source ordering.
func TestPlanHeadersDoesNotCopyBackwardAcrossInterleaving(t *testing.T) {
	previous := []byte("A: y\r\nA: z\r\n\r\nbody\r\n")
	current := []byte("A: z\r\nA: y\r\nA: x\r\n\r\nbody\r\n")
	result, _, err := mustPlanHeaders(t, previous, current, AllowLiterals, testHeaderRelevance{relevant: true}, GenerationLimits{})
	if err != nil {
		t.Fatalf("literal interleaving code=%s", recipeTestErrorCode(err))
	}
	assertHeaderSteps(t, result.headerPlans()[0].stepsCopy(), []StepKind{StepKindCopy, StepKindData}, [][2]int{{3, 3}}, []string{" y"})
	failed, usage, err := mustPlanHeaders(t, previous, current, CopyOnly, testHeaderRelevance{relevant: true}, GenerationLimits{})
	if failed.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeHeaderUnrepresentable) {
		t.Fatalf("copy-only backward match: valid=%t usage=%t code=%s", failed.Valid(), usage.Valid(), recipeTestErrorCode(err))
	}
}

// TestPlanHeadersEnforcesLiteralDisclosureAndPrivacy verifies copy-only and bounded literal behavior.
func TestPlanHeadersEnforcesLiteralDisclosureAndPrivacy(t *testing.T) {
	const protected = "prior-secret-marker"
	previous := []byte("A: " + protected + "\r\n\r\nbody\r\n")
	current := []byte("A: current\r\n\r\nbody\r\n")
	failed, usage, err := mustPlanHeaders(t, previous, current, CopyOnly, testHeaderRelevance{relevant: true}, GenerationLimits{})
	if failed.Valid() || !usage.Valid() {
		t.Fatalf("copy-only failure atomicity: valid=%t usage=%t", failed.Valid(), usage.Valid())
	}
	assertClosedSafeGenerationError(t, err, ErrorCodeHeaderUnrepresentable, ErrorClassRepresentation, protected)

	limits := DefaultGenerationLimits()
	limits.RecipeLimits.MaxDataStringBytes = len(" "+protected) - 1
	limits.RecipeLimits.MaxTotalLiteralBytes = limits.RecipeLimits.MaxDataStringBytes
	failed, usage, err = mustPlanHeaders(t, previous, current, AllowLiterals, testHeaderRelevance{relevant: true}, limits)
	if failed.Valid() || !usage.Valid() {
		t.Fatalf("literal limit failure atomicity: valid=%t usage=%t", failed.Valid(), usage.Valid())
	}
	assertClosedSafeGenerationError(t, err, ErrorCodeLimitExceeded, ErrorClassLimit, protected)
}

// TestPlanHeadersCopiesOverlongFoldedValuesOrFailsClosed verifies reachable representation limits.
func TestPlanHeadersCopiesOverlongFoldedValuesOrFailsClosed(t *testing.T) {
	overlong := strings.Repeat("a", 700) + "\r\n " + strings.Repeat("b", 400)
	previous := []byte("Long: " + overlong + "\r\n\r\nbody\r\n")
	currentCopy := []byte("Long: " + overlong + "\r\nLong: other\r\n\r\nbody\r\n")
	result, _, err := mustPlanHeaders(t, previous, currentCopy, CopyOnly, testHeaderRelevance{relevant: true}, GenerationLimits{})
	if err != nil {
		t.Fatalf("copyable overlong code=%s", recipeTestErrorCode(err))
	}
	steps := result.headerPlans()[0].stepsCopy()
	assertHeaderSteps(t, steps, []StepKind{StepKindCopy}, [][2]int{{2, 2}}, nil)

	currentMissing := []byte("Long: other\r\n\r\nbody\r\n")
	failed, _, err := mustPlanHeaders(t, previous, currentMissing, AllowLiterals, testHeaderRelevance{relevant: true}, GenerationLimits{})
	if failed.Valid() {
		t.Fatal("overlong literal returned a partial plan")
	}
	assertClosedSafeGenerationError(t, err, ErrorCodeHeaderUnrepresentable, ErrorClassRepresentation, "aaaa")
}

// TestPlanHeadersReclassifiesEveryNameBeforeSuccess verifies final invariant classification.
func TestPlanHeadersReclassifiesEveryNameBeforeSuccess(t *testing.T) {
	for _, test := range []struct {
		name      string
		relevance HeaderRelevance
		toxic     string
	}{
		{name: "phase disagreement", relevance: &flippingHeaderRelevance{flipAfter: 2}, toxic: "previous"},
		{name: "final callback error", relevance: &flippingHeaderRelevance{flipAfter: 100, errorAfter: 2}, toxic: "protected-callback-marker"},
	} {
		t.Run(test.name, func(t *testing.T) {
			failed, usage, err := mustPlanHeaders(t,
				[]byte("B: previous\r\nA: previous\r\n\r\nbody\r\n"),
				[]byte("A: current\r\nB: current\r\n\r\nbody\r\n"),
				AllowLiterals, test.relevance, GenerationLimits{})
			if failed.Valid() || !usage.Valid() {
				t.Fatalf("reclassification failure atomicity: valid=%t usage=%t", failed.Valid(), usage.Valid())
			}
			assertClosedSafeGenerationError(t, err, ErrorCodeHeaderRelevance, ErrorClassInvariant, test.toxic)
		})
	}
}

// TestPlanHeadersEnforcesCandidateAndComparisonLimits verifies bounded adversarial duplicates.
func TestPlanHeadersEnforcesCandidateAndComparisonLimits(t *testing.T) {
	previous := []byte("A: duplicate\r\nA: duplicate\r\n\r\nbody\r\n")
	current := []byte("A: duplicate\r\nA: middle\r\nA: duplicate\r\n\r\nbody\r\n")

	for _, test := range []struct {
		name      string
		configure func(*GenerationLimits)
		limitName string
	}{
		{name: "candidate entries", configure: func(l *GenerationLimits) { l.MaxCandidateEntries = 2 }, limitName: limitNameMaxCandidateEntries},
		{name: testCandidateKeyBytesLabel, configure: func(l *GenerationLimits) { l.MaxCandidateKeyBytes = 16 }, limitName: limitNameMaxCandidateKeyBytes},
		{name: testComparisonsLabel, configure: func(l *GenerationLimits) { l.MaxComparisons = 2 }, limitName: limitNameMaxComparisons},
	} {
		t.Run(test.name, func(t *testing.T) {
			limits := DefaultGenerationLimits()
			test.configure(&limits)
			failed, usage, err := mustPlanHeaders(t, previous, current, AllowLiterals, testHeaderRelevance{relevant: true}, limits)
			if failed.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) {
				t.Fatalf("limit failure shape: valid=%t usage=%t code=%s", failed.Valid(), usage.Valid(), recipeTestErrorCode(err))
			}
			var typed *Error
			if !errors.As(err, &typed) || typed.LimitName() != test.limitName {
				t.Fatalf("limit name mismatch: code=%s", recipeTestErrorCode(err))
			}
		})
	}
}

// TestHeaderCandidateIndexChargesBeforeRetainingKeys verifies protected key ownership accounting.
func TestHeaderCandidateIndexChargesBeforeRetainingKeys(t *testing.T) {
	limits := DefaultGenerationLimits()
	limits.MaxCandidateKeyBytes = len(" protected") - 1
	normalized, err := limits.normalized()
	if err != nil {
		t.Fatalf("normalized limits code=%s", recipeTestErrorCode(err))
	}
	counter := newGenerationCounter(normalized)
	index := newExactCandidateIndex()
	if err := index.add([]byte(" protected"), 1, &counter, DimensionHeader); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("unaccounted key code=%s", recipeTestErrorCode(err))
	}
	if len(index.buckets) != 0 || counter.usage().Candidates() != 0 || counter.usage().CandidateKeyBytes() != 0 {
		t.Fatalf("failed key retained: buckets=%d candidates=%d bytes=%d", len(index.buckets), counter.usage().Candidates(), counter.usage().CandidateKeyBytes())
	}

	counter = newGenerationCounter(DefaultGenerationLimits())
	index = newExactCandidateIndex()
	if err := index.add([]byte(" duplicate"), 1, &counter, DimensionHeader); err != nil {
		t.Fatalf("first candidate code=%s", recipeTestErrorCode(err))
	}
	if err := index.add([]byte(" duplicate"), 2, &counter, DimensionHeader); err != nil {
		t.Fatalf("duplicate candidate code=%s", recipeTestErrorCode(err))
	}
	usage := counter.usage()
	if usage.Candidates() != 2 || usage.CandidateKeyBytes() != len(" duplicate") || len(index.buckets) != 1 {
		t.Fatalf("duplicate ownership: candidates=%d bytes=%d buckets=%d", usage.Candidates(), usage.CandidateKeyBytes(), len(index.buckets))
	}
}

// TestExactCandidateIndexChecksDigestCollisions verifies digest buckets never replace exact matching.
func TestExactCandidateIndexChecksDigestCollisions(t *testing.T) {
	limits := DefaultGenerationLimits()
	counter := newGenerationCounter(limits)
	wanted := []byte(" wanted")
	digest := sha256.Sum256(wanted)
	wrong := &exactCandidate{key: []byte(" different"), positions: []int{1}}
	right := &exactCandidate{key: bytes.Clone(wanted), positions: []int{2}}
	index := exactCandidateIndex{buckets: map[[sha256.Size]byte][]*exactCandidate{digest: {wrong, right}}}
	candidate, err := index.lookup(wanted, &counter, DimensionHeader)
	if err != nil || candidate != right {
		t.Fatalf("collision lookup matched wrong key: found=%t code=%s", candidate != nil, recipeTestErrorCode(err))
	}
	missing, err := index.lookup([]byte(" absent"), &counter, DimensionHeader)
	if err != nil || missing != nil {
		t.Fatalf("collision lookup fabricated match: found=%t code=%s", missing != nil, recipeTestErrorCode(err))
	}
}

// TestPlanHeadersReportsExactSuccessfulUsage locks the charged header planning model.
func TestPlanHeadersReportsExactSuccessfulUsage(t *testing.T) {
	result, usage, err := mustPlanHeaders(t,
		[]byte("A: old\r\n\r\nbody\r\n"), []byte("A: new\r\n\r\nbody\r\n"),
		AllowLiterals, testHeaderRelevance{relevant: true}, GenerationLimits{})
	if err != nil || !result.Valid() {
		t.Fatalf("usage vector result: valid=%t code=%s", result.Valid(), recipeTestErrorCode(err))
	}
	plans := result.headerPlans()
	if len(plans) != 1 || plans[0].name != "a" || plans[0].canonicalName != "a" {
		t.Fatalf("lowercase plan shape: plans=%d", len(plans))
	}
	if usage.InputBytes() != 16 || usage.InputItems() != 2 || usage.Candidates() != 1 ||
		usage.CandidateKeyBytes() != 4 || usage.Comparisons() != 1 || usage.GeneratedSteps() != 1 ||
		usage.GeneratedLiterals() != 1 || usage.LiteralBytes() != 4 || usage.WorkUnits() != 145 {
		t.Fatalf("usage vector: input=%d/%d candidates=%d keys=%d comparisons=%d steps=%d literals=%d/%d work=%d",
			usage.InputBytes(), usage.InputItems(), usage.Candidates(), usage.CandidateKeyBytes(), usage.Comparisons(),
			usage.GeneratedSteps(), usage.GeneratedLiterals(), usage.LiteralBytes(), usage.WorkUnits())
	}
}

// TestPlanHeadersEnforcesExactOperationWork verifies success at exact work and failure one under.
func TestPlanHeadersEnforcesExactOperationWork(t *testing.T) {
	previous := []byte("A: old\r\n\r\nbody\r\n")
	current := []byte("A: new\r\n\r\nbody\r\n")
	for _, test := range []struct {
		name           string
		limit          int
		wantErr        bool
		wantFailedWork int
	}{{name: testExactBoundaryLabel, limit: 145}, {name: "one under final validation", limit: 144, wantErr: true, wantFailedWork: 135}} {
		t.Run(test.name, func(t *testing.T) {
			limits := compactHeaderWorkLimits(test.limit)
			result, usage, err := mustPlanHeaders(t, previous, current, AllowLiterals, testHeaderRelevance{relevant: true}, limits)
			if test.wantErr {
				if result.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != limitNameMaxGenerationWorkUnits {
					t.Fatalf("work failure: valid=%t usage=%t code=%s", result.Valid(), usage.Valid(), recipeTestErrorCode(err))
				}
				if usage.WorkUnits() != test.wantFailedWork {
					t.Fatalf("work failure accounting=%d want=%d", usage.WorkUnits(), test.wantFailedWork)
				}
				return
			}
			if err != nil || !result.Valid() || usage.WorkUnits() != test.limit {
				t.Fatalf("exact work: valid=%t work=%d code=%s", result.Valid(), usage.WorkUnits(), recipeTestErrorCode(err))
			}
		})
	}
}

// TestPlanHeadersChargesUnchangedEqualityWork verifies equality scans fail before excess work.
func TestPlanHeadersChargesUnchangedEqualityWork(t *testing.T) {
	message := []byte("A: old\r\n\r\nbody\r\n")
	for _, test := range []struct {
		name           string
		limit          int
		wantErr        bool
		wantFailedWork int
	}{{name: testExactBoundaryLabel, limit: 87}, {name: testOneUnderLabel, limit: 86, wantErr: true, wantFailedWork: 84}} {
		t.Run(test.name, func(t *testing.T) {
			limits := compactHeaderWorkLimits(test.limit)
			result, usage, err := mustPlanHeaders(t, message, message, AllowLiterals, testHeaderRelevance{relevant: true}, limits)
			if test.wantErr {
				if result.Valid() || !usage.Valid() || recipeTestLimitName(err) != limitNameMaxGenerationWorkUnits || usage.WorkUnits() != test.wantFailedWork {
					t.Fatalf("unchanged work failure: valid=%t work=%d code=%s", result.Valid(), usage.WorkUnits(), recipeTestErrorCode(err))
				}
				return
			}
			if err != nil || !result.Valid() || result.Changed() || usage.WorkUnits() != test.limit {
				t.Fatalf("unchanged exact: valid=%t changed=%t work=%d code=%s", result.Valid(), result.Changed(), usage.WorkUnits(), recipeTestErrorCode(err))
			}
		})
	}
}

// TestPlanHeadersChargesByteAwareLongNameSortWork verifies adversarial prefix sorting bounds.
func TestPlanHeadersChargesByteAwareLongNameSortWork(t *testing.T) {
	prefix := strings.Repeat("a", 200)
	message := []byte(prefix + "b: x\r\n" + prefix + "a: y\r\n\r\nbody\r\n")
	limits := func(work int) GenerationLimits {
		recipeLimits := DefaultLimits()
		recipeLimits.MaxDecodedRecipeBytes = 1
		recipeLimits.MaxDataStringBytes = 1
		recipeLimits.MaxTotalLiteralBytes = 1
		recipeLimits.MaxOperationWorkUnits = 1
		return GenerationLimits{
			RecipeLimits: recipeLimits, MaxInputBytes: 824, MaxInputItems: 4,
			MaxCandidateEntries: 2, MaxCandidateKeyBytes: 1, MaxComparisons: 1,
			MaxGenerationWorkUnits: work,
		}
	}
	assertAdversarialHeaderWorkBoundary(t, message, message, CopyOnly, 8553, limits)
}

// TestPlanHeadersChargesSingleLongNameHashingWork isolates repeated map and classifier scans.
func TestPlanHeadersChargesSingleLongNameHashingWork(t *testing.T) {
	name := strings.Repeat("a", 900)
	previous := []byte(name + ": old\r\n\r\nbody\r\n")
	current := []byte(name + ": new\r\n\r\nbody\r\n")
	limits := func(work int) GenerationLimits {
		recipeLimits := DefaultLimits()
		recipeLimits.MaxDecodedRecipeBytes = 4
		recipeLimits.MaxDataStringBytes = 4
		recipeLimits.MaxTotalLiteralBytes = 4
		recipeLimits.MaxOperationWorkUnits = 1
		return GenerationLimits{
			RecipeLimits: recipeLimits, MaxInputBytes: 1814, MaxInputItems: 2,
			MaxCandidateEntries: 1, MaxCandidateKeyBytes: 4, MaxComparisons: 1,
			MaxGenerationWorkUnits: work,
		}
	}
	assertAdversarialHeaderWorkBoundary(t, previous, current, AllowLiterals, 19923, limits)
}

// TestPlanHeadersChargesLongLiteralValidationAndOwnershipWork verifies repeated scans and one clone.
func TestPlanHeadersChargesLongLiteralValidationAndOwnershipWork(t *testing.T) {
	previous := []byte("A: " + strings.Repeat("x", 500) + "\r\n\r\nbody\r\n")
	current := []byte("A: new\r\n\r\nbody\r\n")
	limits := func(work int) GenerationLimits {
		recipeLimits := DefaultLimits()
		recipeLimits.MaxDecodedRecipeBytes = 501
		recipeLimits.MaxDataStringBytes = 501
		recipeLimits.MaxTotalLiteralBytes = 501
		recipeLimits.MaxOperationWorkUnits = 1
		return GenerationLimits{
			RecipeLimits: recipeLimits, MaxInputBytes: 513, MaxInputItems: 2,
			MaxCandidateEntries: 1, MaxCandidateKeyBytes: 4, MaxComparisons: 1,
			MaxGenerationWorkUnits: work,
		}
	}
	assertAdversarialHeaderWorkBoundary(t, previous, current, AllowLiterals, 6109, limits)
}

// assertAdversarialHeaderWorkBoundary locks one exact vector and rejects one-under work.
func assertAdversarialHeaderWorkBoundary(t *testing.T, previous, current []byte, policy LiteralDisclosurePolicy, expectedWork int, limits func(int) GenerationLimits) {
	t.Helper()
	result, usage, err := mustPlanHeaders(t, previous, current, policy, testHeaderRelevance{relevant: true}, GenerationLimits{})
	if err != nil || !result.Valid() {
		t.Fatalf("baseline work vector: valid=%t code=%s", result.Valid(), recipeTestErrorCode(err))
	}
	if usage.WorkUnits() != expectedWork {
		t.Fatalf("baseline work=%d want=%d", usage.WorkUnits(), expectedWork)
	}
	result, usage, err = mustPlanHeaders(t, previous, current, policy, testHeaderRelevance{relevant: true}, limits(expectedWork))
	if err != nil || !result.Valid() || usage.WorkUnits() != expectedWork {
		t.Fatalf("exact adversarial work: valid=%t work=%d code=%s", result.Valid(), usage.WorkUnits(), recipeTestErrorCode(err))
	}
	failed, failedUsage, err := mustPlanHeaders(t, previous, current, policy, testHeaderRelevance{relevant: true}, limits(expectedWork-1))
	if failed.Valid() || !failedUsage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != limitNameMaxGenerationWorkUnits {
		t.Fatalf("one-under adversarial work: valid=%t work=%d code=%s", failed.Valid(), failedUsage.WorkUnits(), recipeTestErrorCode(err))
	}
}

// TestPlanHeadersEnforcesInheritedPlanLimitsAtExactBoundaries verifies M8 plan ceilings.
func TestPlanHeadersEnforcesInheritedPlanLimitsAtExactBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		previous  []byte
		current   []byte
		exact     int
		limitName string
		configure func(*Limits, int)
	}{
		{
			name: testStepsPerHeaderLabel, previous: []byte("A: new\r\nA: one\r\n\r\nbody\r\n"),
			current: []byte("A: two\r\nA: one\r\n\r\nbody\r\n"), exact: 2, limitName: limitNameMaxStepsPerHeader,
			configure: func(l *Limits, n int) { l.MaxStepsPerHeader = n },
		},
		{
			name: testTotalStepsLabel, previous: []byte("A: old\r\nB: old\r\n\r\nbody\r\n"),
			current: []byte("A: new\r\nB: new\r\n\r\nbody\r\n"), exact: 2, limitName: limitNameMaxTotalSteps,
			configure: func(l *Limits, n int) { l.MaxStepsPerHeader, l.MaxBodySteps, l.MaxTotalSteps = n, n, n },
		},
		{
			name: testCopyRangesLabel, previous: []byte("A: duplicate\r\nA: duplicate\r\n\r\nbody\r\n"),
			current: []byte("A: duplicate\r\nA: middle\r\nA: duplicate\r\n\r\nbody\r\n"), exact: 2, limitName: limitNameMaxCopyRanges,
			configure: func(l *Limits, n int) { l.MaxCopyRanges = n },
		},
		{
			name: testCopiedItemsPerRangeLabel, previous: []byte("A: two\r\nA: one\r\n\r\nbody\r\n"),
			current: []byte("A: spare\r\nA: two\r\nA: one\r\n\r\nbody\r\n"), exact: 2, limitName: limitNameMaxCopiedItemsPerRange,
			configure: func(l *Limits, n int) { l.MaxCopiedItemsPerRange = n },
		},
		{
			name: testTotalCopiedItemsLabel, previous: []byte("A: duplicate\r\nA: duplicate\r\n\r\nbody\r\n"),
			current: []byte("A: duplicate\r\nA: middle\r\nA: duplicate\r\n\r\nbody\r\n"), exact: 2, limitName: limitNameMaxTotalCopiedItems,
			configure: func(l *Limits, n int) { l.MaxCopiedItemsPerRange, l.MaxTotalCopiedItems = 1, n },
		},
		{
			name: testDataStringsLabel, previous: []byte("A: yy\r\nA: x\r\n\r\nbody\r\n"),
			current: []byte("B: retained\r\n\r\nbody\r\n"), exact: 2, limitName: limitNameMaxDataStrings,
			configure: func(l *Limits, n int) { l.MaxDataStrings = n },
		},
		{
			name: testDataStringBytesLabel, previous: []byte("A: long\r\n\r\nbody\r\n"),
			current: []byte("B: retained\r\n\r\nbody\r\n"), exact: 5, limitName: limitNameMaxDataStringBytes,
			configure: func(l *Limits, n int) { l.MaxDataStringBytes = n },
		},
		{
			name: "total literal bytes", previous: []byte("A: yy\r\nA: x\r\n\r\nbody\r\n"),
			current: []byte("B: retained\r\n\r\nbody\r\n"), exact: 5, limitName: limitNameMaxTotalLiteralBytes,
			configure: func(l *Limits, n int) { l.MaxDataStringBytes, l.MaxTotalLiteralBytes = n, n },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, boundary := range []struct {
				name    string
				limit   int
				wantErr bool
			}{{name: testExactBoundaryLabel, limit: test.exact}, {name: testOneUnderLabel, limit: test.exact - 1, wantErr: true}} {
				t.Run(boundary.name, func(t *testing.T) {
					limits := GenerationLimits{RecipeLimits: DefaultLimits()}
					test.configure(&limits.RecipeLimits, boundary.limit)
					result, usage, err := mustPlanHeaders(t, test.previous, test.current, AllowLiterals, testHeaderRelevance{relevant: true}, limits)
					if boundary.wantErr {
						if result.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != test.limitName {
							t.Fatalf("one-under result: valid=%t usage=%t code=%s limit=%s", result.Valid(), usage.Valid(), recipeTestErrorCode(err), recipeTestLimitName(err))
						}
						return
					}
					if err != nil || !result.Valid() {
						t.Fatalf("exact result: valid=%t code=%s", result.Valid(), recipeTestErrorCode(err))
					}
				})
			}
		})
	}
}

// TestPlanHeadersHonorsPreloadedOperationTotals verifies cross-dimension recipe-wide ceilings.
func TestPlanHeadersHonorsPreloadedOperationTotals(t *testing.T) {
	literalPrevious := []byte("A: old\r\n\r\nbody\r\n")
	literalCurrent := []byte("A: new\r\n\r\nbody\r\n")
	copyPrevious := []byte("A: keep\r\n\r\nbody\r\n")
	copyCurrent := []byte("A: extra\r\nA: keep\r\n\r\nbody\r\n")
	tests := []struct {
		name      string
		previous  []byte
		current   []byte
		limitName string
		preload   func(*generationCounter, bool)
	}{
		{name: testTotalStepsLabel, previous: literalPrevious, current: literalCurrent, limitName: limitNameMaxTotalSteps, preload: func(c *generationCounter, exact bool) {
			c.generatedSteps = c.limits.RecipeLimits.MaxTotalSteps - 1
			if !exact {
				c.generatedSteps++
			}
		}},
		{name: testCopyRangesLabel, previous: copyPrevious, current: copyCurrent, limitName: limitNameMaxCopyRanges, preload: func(c *generationCounter, exact bool) {
			c.copyRanges = c.limits.RecipeLimits.MaxCopyRanges - 1
			if !exact {
				c.copyRanges++
			}
		}},
		{name: testTotalCopiedItemsLabel, previous: copyPrevious, current: copyCurrent, limitName: limitNameMaxTotalCopiedItems, preload: func(c *generationCounter, exact bool) {
			c.copiedItems = c.limits.RecipeLimits.MaxTotalCopiedItems - 1
			if !exact {
				c.copiedItems++
			}
		}},
		{name: testDataStringsLabel, previous: literalPrevious, current: literalCurrent, limitName: limitNameMaxDataStrings, preload: func(c *generationCounter, exact bool) {
			c.generatedLiterals = c.limits.RecipeLimits.MaxDataStrings - 1
			if !exact {
				c.generatedLiterals++
			}
		}},
		{name: testLiteralBytesLabel, previous: literalPrevious, current: literalCurrent, limitName: limitNameMaxTotalLiteralBytes, preload: func(c *generationCounter, exact bool) {
			c.literalBytes = c.limits.RecipeLimits.MaxTotalLiteralBytes - len(" old")
			if !exact {
				c.literalBytes++
			}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, _, err := mustPlanHeadersWithPreload(t, test.previous, test.current, AllowLiterals, testHeaderRelevance{relevant: true}, test.preload, true)
			if err != nil || !result.Valid() {
				t.Fatalf("preloaded exact: valid=%t code=%s", result.Valid(), recipeTestErrorCode(err))
			}
			failed, usage, err := mustPlanHeadersWithPreload(t, test.previous, test.current, AllowLiterals, testHeaderRelevance{relevant: true}, test.preload, false)
			if failed.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) || recipeTestLimitName(err) != test.limitName {
				t.Fatalf("preloaded overflow: valid=%t usage=%t code=%s limit=%s", failed.Valid(), usage.Valid(), recipeTestErrorCode(err), recipeTestLimitName(err))
			}
		})
	}
}

// compactHeaderWorkLimits creates coherent narrow limits for one exact operation vector.
func compactHeaderWorkLimits(work int) GenerationLimits {
	recipeLimits := DefaultLimits()
	recipeLimits.MaxDecodedRecipeBytes = 4
	recipeLimits.MaxDataStringBytes = 4
	recipeLimits.MaxTotalLiteralBytes = 4
	recipeLimits.MaxOperationWorkUnits = 1
	return GenerationLimits{
		RecipeLimits: recipeLimits, MaxInputBytes: 16, MaxInputItems: 2,
		MaxCandidateEntries: 1, MaxCandidateKeyBytes: 4, MaxComparisons: 1,
		MaxGenerationWorkUnits: work,
	}
}

// TestPlanHeadersBoundsLargeDuplicateInterleaving verifies near-linear adversarial behavior.
func TestPlanHeadersBoundsLargeDuplicateInterleaving(t *testing.T) {
	var previous, current strings.Builder
	for range 200 {
		previous.WriteString("A: duplicate\r\n")
		current.WriteString("A: middle\r\nA: duplicate\r\n")
	}
	previous.WriteString("\r\nbody\r\n")
	current.WriteString("\r\nbody\r\n")

	result, usage, err := mustPlanHeaders(t, []byte(previous.String()), []byte(current.String()), CopyOnly, testHeaderRelevance{relevant: true}, GenerationLimits{})
	if err != nil || !result.Valid() || len(result.headerPlans()) != 1 {
		t.Fatalf("duplicate bomb result: valid=%t plans=%d code=%s", result.Valid(), len(result.headerPlans()), recipeTestErrorCode(err))
	}
	if got := len(result.headerPlans()[0].stepsCopy()); got != 200 {
		t.Fatalf("duplicate bomb steps=%d", got)
	}
	if usage.Candidates() != 400 || usage.CandidateKeyBytes() != len(" duplicate")+len(" middle") || usage.Comparisons() > usage.InputItems() {
		t.Fatalf("duplicate bomb usage: candidates=%d keys=%d comparisons=%d input_items=%d", usage.Candidates(), usage.CandidateKeyBytes(), usage.Comparisons(), usage.InputItems())
	}
}

// TestPlanHeadersEnforcesInputAndStateLimitsAtExactBoundaries verifies inherited and generation counters.
func TestPlanHeadersEnforcesInputAndStateLimitsAtExactBoundaries(t *testing.T) {
	previous := []byte("B: old\r\nA: old\r\n\r\nbody\r\n")
	current := []byte("A: new\r\nB: new\r\n\r\nbody\r\n")
	headerBytes := len("B: old\r\nA: old\r\n")
	inputHeaderBytes := headerBytes + len("A: new\r\nB: new\r\n")

	tests := []struct {
		name      string
		exact     int
		configure func(*GenerationLimits, int)
		limitName string
	}{
		{name: testHeaderNamesLabel, exact: 2, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxHeaderNames = n }, limitName: limitNameMaxHeaderNames},
		{name: testHeaderNameBytesLabel, exact: 2, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxTotalHeaderNameBytes = n }, limitName: limitNameMaxTotalHeaderNameBytes},
		{name: "header fields", exact: 2, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxHeaderFields = n }, limitName: limitNameMaxHeaderFields},
		{name: "header bytes", exact: headerBytes, configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxHeaderBytes = n }, limitName: limitNameMaxHeaderBytes},
		{name: testStateBytesLabel, exact: len(previous), configure: func(l *GenerationLimits, n int) { l.RecipeLimits.MaxStateBytes = n }, limitName: limitNameMaxStateBytes},
		{name: testInputBytesLabel, exact: inputHeaderBytes, configure: func(l *GenerationLimits, n int) { l.MaxInputBytes = n }, limitName: limitNameMaxInputBytes},
		{name: testInputItemsLabel, exact: 4, configure: func(l *GenerationLimits, n int) { l.MaxInputItems = n; l.MaxComparisons = n }, limitName: limitNameMaxInputItems},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exact := GenerationLimits{RecipeLimits: DefaultLimits()}
			test.configure(&exact, test.exact)
			if result, _, err := mustPlanHeaders(t, previous, current, AllowLiterals, testHeaderRelevance{relevant: true}, exact); err != nil || !result.Valid() {
				t.Fatalf("exact limit rejected: valid=%t code=%s", result.Valid(), recipeTestErrorCode(err))
			}

			over := GenerationLimits{RecipeLimits: DefaultLimits()}
			test.configure(&over, test.exact-1)
			failed, usage, err := mustPlanHeaders(t, previous, current, AllowLiterals, testHeaderRelevance{relevant: true}, over)
			if failed.Valid() || !usage.Valid() || !IsErrorCode(err, ErrorCodeLimitExceeded) {
				t.Fatalf("one-over limit shape: valid=%t usage=%t code=%s", failed.Valid(), usage.Valid(), recipeTestErrorCode(err))
			}
			var typed *Error
			if !errors.As(err, &typed) || typed.LimitName() != test.limitName {
				t.Fatalf("one-over limit name: code=%s", recipeTestErrorCode(err))
			}
		})
	}
}

// TestRawMessageBoundaryRejectsImpossibleHeaderValues verifies generation consumes validated evidence only.
func TestRawMessageBoundaryRejectsImpossibleHeaderValues(t *testing.T) {
	for _, value := range [][]byte{{0xff}, []byte("bad\rvalue"), []byte("bad\nvalue")} {
		original := append([]byte("A:"), value...)
		original = append(original, '\r', '\n')
		if _, err := rawmsg.NewHeaderField(0, []byte("A"), value, value, original); err == nil {
			t.Fatalf("rawmsg accepted impossible unfolded value: bytes=%d", len(value))
		}
	}
}

// TestPlanHeadersDoesNotAliasInputOrOutput verifies immutable state and plan accessors.
func TestPlanHeadersDoesNotAliasInputOrOutput(t *testing.T) {
	previousBytes := []byte("A: previous\r\n\r\nbody\r\n")
	currentBytes := []byte("A: current\r\n\r\nbody\r\n")
	result, _, err := mustPlanHeaders(t, previousBytes, currentBytes, AllowLiterals, testHeaderRelevance{relevant: true}, GenerationLimits{})
	if err != nil {
		t.Fatalf("planHeaders() code=%s", recipeTestErrorCode(err))
	}
	previousBytes[0], currentBytes[0] = 'X', 'Y'
	plans := result.headerPlans()
	data := plans[0].stepsCopy()[0].dataValues()
	data[0][0] = 'Z'
	if got := result.headerPlans()[0].stepsCopy()[0].dataValues()[0]; !bytes.Equal(got, []byte(" previous")) {
		t.Fatalf("planned literal mutated: bytes=%d", len(got))
	}
}

// mustPlanHeaders constructs validated states and invokes only the package-internal header seam.
func mustPlanHeaders(t *testing.T, previous, current []byte, policy LiteralDisclosurePolicy, relevance HeaderRelevance, limits GenerationLimits) (headerPlanningResult, GenerationUsage, error) {
	t.Helper()
	return mustPlanHeadersWithPreload(t, previous, current, policy, relevance, func(*generationCounter, bool) {}, true, limits)
}

// mustPlanHeadersWithPreload constructs one operation budget with optional prior-dimension totals.
func mustPlanHeadersWithPreload(t *testing.T, previous, current []byte, policy LiteralDisclosurePolicy, relevance HeaderRelevance, preload func(*generationCounter, bool), exact bool, optionalLimits ...GenerationLimits) (headerPlanningResult, GenerationUsage, error) {
	t.Helper()
	var limits GenerationLimits
	if len(optionalLimits) > 0 {
		limits = optionalLimits[0]
	}
	previousState := mustGenerationState(t, previous)
	currentState := mustGenerationState(t, current)
	request, err := NewGenerationRequest(previousState, currentState, RejectUnavailableBody, policy)
	if err != nil {
		t.Fatalf("NewGenerationRequest() code=%s", recipeTestErrorCode(err))
	}
	generator, err := NewGenerator(limits, relevance)
	if err != nil {
		t.Fatalf("NewGenerator() code=%s", recipeTestErrorCode(err))
	}
	counter := newGenerationCounter(generator.limits)
	preload(&counter, exact)
	budget, err := newGenerationPlanBudget(&counter)
	if err != nil {
		t.Fatalf("newGenerationPlanBudget() code=%s", recipeTestErrorCode(err))
	}
	result, err := generator.planHeaders(request, budget)
	return result, counter.usage(), err
}

// headerPlanNames returns deterministic canonical names without protected values.
func headerPlanNames(plans []headerPlan) []string {
	names := make([]string, len(plans))
	for index, plan := range plans {
		names[index] = plan.canonicalName
	}
	return names
}

// assertHeaderSteps compares closed operation shapes and expected static fixture values.
func assertHeaderSteps(t *testing.T, steps []step, wantKinds []StepKind, wantCopies [][2]int, wantData []string) {
	t.Helper()
	if len(steps) != len(wantKinds) {
		t.Fatalf("step count = %d, want %d", len(steps), len(wantKinds))
	}
	copyIndex, dataIndex := 0, 0
	for index, instruction := range steps {
		if instruction.kind != wantKinds[index] {
			t.Fatalf("step %d kind=%s want=%s", index, instruction.kind, wantKinds[index])
		}
		if start, end, ok := instruction.copyRange(); ok {
			if copyIndex >= len(wantCopies) || [2]int{start, end} != wantCopies[copyIndex] {
				t.Fatalf("copy step %d range=%d:%d", index, start, end)
			}
			copyIndex++
			continue
		}
		for _, value := range instruction.dataValues() {
			if dataIndex >= len(wantData) || string(value) != wantData[dataIndex] {
				t.Fatalf("data step %d value mismatch: bytes=%d", index, len(value))
			}
			dataIndex++
		}
	}
	if copyIndex != len(wantCopies) || dataIndex != len(wantData) {
		t.Fatalf("step payload counts: copies=%d/%d data=%d/%d", copyIndex, len(wantCopies), dataIndex, len(wantData))
	}
}

// equalHeaderPlanNames compares deterministic name lists without nil/empty ambiguity.
func equalHeaderPlanNames(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// recipeTestErrorClass returns the closed class without formatting raw errors.
func recipeTestErrorClass(err error) ErrorClass {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Class()
	}
	return ""
}
