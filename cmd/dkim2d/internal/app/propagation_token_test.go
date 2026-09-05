package app

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/propagationtest"
)

// propagationKey derives the propagation coordinate key of one corpus case
// through the real verifier and deriver, so ledger tests bind tokens to keys
// the coordinator would issue.
func (f *propagationFixture) propagationKey(t *testing.T, name string) dkim2.ReplayKey {
	t.Helper()
	testCase := f.corpus.Case(t, name)
	assessment, err := f.verifier.Assess(context.Background(), dkim2.NewVerifyRequest(
		testCase.RawMessage(t), []byte("<>"), [][]byte{testCase.ForwardPath(t)},
	))
	if err != nil {
		t.Fatalf("assess %s: %v", name, err)
	}
	verification, ok := assessment.Verification()
	if !ok {
		t.Fatalf("case %s carries no verification", name)
	}
	identities, err := dkim2.ReplayIdentities(verification)
	if err != nil || identities.Len() != 1 {
		t.Fatalf("identities of %s: %v", name, err)
	}
	identity, err := identities.Identity(0)
	if err != nil {
		t.Fatal(err)
	}
	key, err := f.deriver.DerivePropagation(context.Background(), identity)
	if err != nil || !key.Valid() {
		t.Fatalf("derive %s: %v", name, err)
	}
	return key
}

// reserve reserves one coordinate in the fixture's memory store.
func (f *propagationFixture) reserve(t *testing.T, key dkim2.ReplayKey) {
	t.Helper()
	retention, err := dkim2.NewReplayRetention(propagationTestRetention)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := dkim2.NewReplayLease(propagationTestLease)
	if err != nil {
		t.Fatal(err)
	}
	if reservation, err := f.store.ReservePropagation(context.Background(), key, retention, lease); err != nil ||
		reservation != dkim2.ReplayPropagationReserved {
		t.Fatalf("reserve: %s error=%v", reservation, err)
	}
}

// TestPropagationTokenLedgerBindsEveryTokenToItsCoordinate proves that two
// tokens issued for one coordinate are distinct, that each resolves to the
// key of that coordinate, and that the key resolved from the superseded
// token commits the reservation of the later attempt.
func TestPropagationTokenLedgerBindsEveryTokenToItsCoordinate(t *testing.T) {
	fixture := newPropagationFixture(t)
	key := fixture.propagationKey(t, propagationtest.CaseRunOfOne)
	ledger, err := newPropagationTokenLedger(time.Now, time.Hour, nil)
	if err != nil {
		t.Fatalf("construct ledger: %v", err)
	}
	first, err := ledger.Issue(key)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	second, err := ledger.Issue(fixture.propagationKey(t, propagationtest.CaseRunOfOne))
	if err != nil {
		t.Fatalf("reissue: %v", err)
	}
	if first == second || !ValidPropagationCommitToken(first) || !ValidPropagationCommitToken(second) {
		t.Fatalf("tokens %q and %q are not two distinct contract tokens", first, second)
	}
	fixture.reserve(t, key)
	resolved, detached, ok := ledger.Resolve(first)
	if !ok || detached || !resolved.Valid() {
		t.Fatal("the superseded token did not resolve to its coordinate")
	}
	if commit, err := fixture.store.CommitPropagation(context.Background(), resolved); err != nil ||
		commit != dkim2.ReplayPropagationCommitted {
		t.Fatalf("superseded token commit = %s error=%v", commit, err)
	}
	resolved, _, ok = ledger.Resolve(second)
	if !ok {
		t.Fatal("the later token did not resolve")
	}
	if commit, err := fixture.store.CommitPropagation(context.Background(), resolved); err != nil ||
		commit != dkim2.ReplayPropagationCommitted {
		t.Fatalf("later token commit = %s error=%v", commit, err)
	}
}

// TestPropagationTokenLedgerSeparatesCoordinates proves a token of one
// coordinate never commits another coordinate.
func TestPropagationTokenLedgerSeparatesCoordinates(t *testing.T) {
	fixture := newPropagationFixture(t)
	one := fixture.propagationKey(t, propagationtest.CaseRunOfOne)
	two := fixture.propagationKey(t, propagationtest.CaseNextDomainRun)
	ledger, err := newPropagationTokenLedger(time.Now, time.Hour, nil)
	if err != nil {
		t.Fatalf("construct ledger: %v", err)
	}
	first, err := ledger.Issue(one)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	second, err := ledger.Issue(two)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if first == second {
		t.Fatal("two coordinates shared one token")
	}
	fixture.reserve(t, one)
	resolved, _, ok := ledger.Resolve(second)
	if !ok {
		t.Fatal("the second token did not resolve")
	}
	if commit, err := fixture.store.CommitPropagation(context.Background(), resolved); err != nil ||
		commit != dkim2.ReplayPropagationCommitUnresolved {
		t.Fatalf("foreign coordinate commit = %s error=%v", commit, err)
	}
}

// TestPropagationTokenLedgerRejectsUnknownAndMalformedTokens proves the
// grammar gate and that unknown well-formed tokens never resolve.
func TestPropagationTokenLedgerRejectsUnknownAndMalformedTokens(t *testing.T) {
	t.Parallel()

	ledger, err := newPropagationTokenLedger(time.Now, time.Hour, nil)
	if err != nil {
		t.Fatalf("construct ledger: %v", err)
	}
	oversized := make([]byte, 600)
	for index := range oversized {
		oversized[index] = 'a'
	}
	for _, token := range []string{"", "short", "not+base64url/value", string(oversized)} {
		if _, _, ok := ledger.Resolve(token); ok {
			t.Fatalf("token %q resolved", token)
		}
	}
	if _, _, ok := ledger.Resolve("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); ok {
		t.Fatal("an unknown well-formed token resolved")
	}
}

// TestPropagationTokenLedgerExpiresEntriesAtRetention proves tokens stop
// resolving at the retention boundary and are dropped from memory.
func TestPropagationTokenLedgerExpiresEntriesAtRetention(t *testing.T) {
	fixture := newPropagationFixture(t)
	now := time.Unix(1700000000, 0).UTC()
	ledger, err := newPropagationTokenLedger(func() time.Time { return now }, time.Minute, nil)
	if err != nil {
		t.Fatalf("construct ledger: %v", err)
	}
	token, err := ledger.Issue(fixture.propagationKey(t, propagationtest.CaseRunOfOne))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	now = now.Add(time.Minute)
	if _, _, ok := ledger.Resolve(token); ok {
		t.Fatal("an expired token still resolved")
	}
	if ledger.size() != 0 {
		t.Fatal("the ledger retained an expired entry")
	}
}

// TestPropagationTokenLedgerIsBounded proves the ledger never exceeds its
// entry bound under a stream of issues.
func TestPropagationTokenLedgerIsBounded(t *testing.T) {
	fixture := newPropagationFixture(t)
	key := fixture.propagationKey(t, propagationtest.CaseRunOfOne)
	ledger, err := newPropagationTokenLedger(time.Now, time.Hour, nil)
	if err != nil {
		t.Fatalf("construct ledger: %v", err)
	}
	for range propagationTokenLedgerEntries + 64 {
		if _, err := ledger.Issue(key); err != nil {
			t.Fatalf("issue: %v", err)
		}
	}
	if size := ledger.size(); size > propagationTokenLedgerEntries {
		t.Fatalf("ledger holds %d entries", size)
	}
}

// TestPropagationTokenLedgerRejectsInvalidConstructionAndKeys proves the
// constructor and Issue refuse every invalid input.
func TestPropagationTokenLedgerRejectsInvalidConstructionAndKeys(t *testing.T) {
	t.Parallel()

	if _, err := newPropagationTokenLedger(nil, time.Hour, nil); err == nil {
		t.Fatal("nil clock was accepted")
	}
	if _, err := newPropagationTokenLedger(time.Now, 0, nil); err == nil {
		t.Fatal("zero retention was accepted")
	}
	ledger, err := newPropagationTokenLedger(time.Now, time.Hour, nil)
	if err != nil {
		t.Fatalf("construct ledger: %v", err)
	}
	if _, err := ledger.Issue(dkim2.ReplayKey{}); err == nil {
		t.Fatal("an invalid replay key was accepted")
	}
	var nilLedger *propagationTokenLedger
	if _, err := nilLedger.IssueDetached(); err == nil {
		t.Fatal("a nil ledger issued a token")
	}
}

// TestPropagationCommitTokenGrammar freezes the bounded base64url grammar.
func TestPropagationCommitTokenGrammar(t *testing.T) {
	t.Parallel()

	valid := []string{
		"0123456789abcdef",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"aA0-_aA0-_aA0-_a",
	}
	for _, token := range valid {
		if !ValidPropagationCommitToken(token) {
			t.Fatalf("token %q was refused", token)
		}
	}
	invalid := []string{"", "0123456789abcde", "0123456789abcde=", "0123456789abcde+", "0123456789abcde/"}
	for _, token := range invalid {
		if ValidPropagationCommitToken(token) {
			t.Fatalf("token %q was accepted", token)
		}
	}
}

// TestPropagationTokenLedgerDiagnosticsAreContentFree proves the ledger's
// diagnostics never render tokens or keys.
func TestPropagationTokenLedgerDiagnosticsAreContentFree(t *testing.T) {
	t.Parallel()

	ledger, err := newPropagationTokenLedger(time.Now, time.Hour, nil)
	if err != nil {
		t.Fatalf("construct ledger: %v", err)
	}
	token, err := ledger.IssueDetached()
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	for _, rendered := range []string{ledger.String(), ledger.GoString()} {
		if rendered != propagationRedacted {
			t.Fatalf("diagnostic %q is not content free", rendered)
		}
	}
	if token == "" {
		t.Fatal("no token was issued")
	}
}

// TestPropagationTokenLedgerEvictsTheEarliestExpiryOnly is the reproducer for
// the overflow defect: with an arbitrary eviction order a live in-flight
// token is dropped when the bound is reached, its commit answers 409, the
// adapter defers, and the same notification propagates again after the lease
// expires. The ledger must fill past its bound without ever evicting an entry
// whose expiry is later than a retained one, so the earlier live token still
// commits its coordinate.
func TestPropagationTokenLedgerEvictsTheEarliestExpiryOnly(t *testing.T) {
	fixture := newPropagationFixture(t)
	key := fixture.propagationKey(t, propagationtest.CaseRunOfOne)
	now := time.Unix(1700000000, 0).UTC()
	retention := propagationTokenRetention(propagationTestLease)
	ledger, err := newPropagationTokenLedger(func() time.Time { return now }, retention, nil)
	if err != nil {
		t.Fatalf("construct ledger: %v", err)
	}
	for range propagationTokenLedgerEntries - 1 {
		if _, err := ledger.Issue(key); err != nil {
			t.Fatalf("fill: %v", err)
		}
	}
	now = now.Add(time.Second)
	live, err := ledger.Issue(key)
	if err != nil {
		t.Fatalf("issue live token: %v", err)
	}
	for range propagationTokenLedgerEntries {
		if _, err := ledger.Issue(key); err != nil {
			t.Fatalf("overflow: %v", err)
		}
	}
	if size := ledger.size(); size > propagationTokenLedgerEntries {
		t.Fatalf("ledger holds %d entries", size)
	}
	resolved, detached, ok := ledger.Resolve(live)
	if !ok || detached || !resolved.Valid() {
		t.Fatal("overflow evicted a live in-flight token, which manufactures a duplicate propagation")
	}
	fixture.reserve(t, key)
	if commit, err := fixture.store.CommitPropagation(context.Background(), resolved); err != nil ||
		commit != dkim2.ReplayPropagationCommitted {
		t.Fatalf("live token commit = %s error=%v", commit, err)
	}
	now = now.Add(retention)
	if _, _, ok := ledger.Resolve(live); ok {
		t.Fatal("a token outlived its retention")
	}
	if ledger.size() != 0 {
		t.Fatalf("the ledger retained %d expired entries", ledger.size())
	}
}

// TestPropagationTokenRetentionFollowsThePendingLease proves the commit token
// outlives the pending lease by exactly the fixed slack. Binding it to the
// replay retention instead would keep dead tokens for the whole replay
// window and force the bounded ledger to evict live ones.
func TestPropagationTokenRetentionFollowsThePendingLease(t *testing.T) {
	t.Parallel()

	for lease, want := range map[time.Duration]time.Duration{
		120 * time.Second: 120*time.Second + propagationTokenRetentionSlack,
		time.Second:       time.Second + propagationTokenRetentionSlack,
		0:                 propagationTokenRetentionSlack,
		-time.Second:      propagationTokenRetentionSlack,
	} {
		if got := propagationTokenRetention(lease); got != want {
			t.Fatalf("retention for lease %s = %s, want %s", lease, got, want)
		}
	}
	if propagationTokenRetention(120*time.Second) >= dkim2.DefaultReplayRetention().Duration() {
		t.Fatal("the token retention still spans the replay retention window")
	}
}
