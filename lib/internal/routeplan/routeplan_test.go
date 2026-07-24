package routeplan

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/croessner/dkim2/internal/provider"
)

// TestPathComparisonKeyUsesGrammarOwnedDomainNormalization verifies route identity fidelity.
func TestPathComparisonKeyUsesGrammarOwnedDomainNormalization(t *testing.T) {
	for _, pair := range [][2][]byte{
		{[]byte("<@ROUTE.TEST:Local@EXAMPLE.TEST>"), []byte("<@route.test:Local@example.test>")},
		{[]byte("<Local@[TAG:A@B]>"), []byte("<Local@[tag:a@b]>")},
		{[]byte(`<"LoC@al"@EXAMPLE.TEST>`), []byte(`<"LoC@al"@example.test>`)},
	} {
		left, leftOK := pathComparisonKey(pair[0])
		right, rightOK := pathComparisonKey(pair[1])
		if !leftOK || !rightOK || left != right {
			t.Fatalf("pathComparisonKey(%q/%q) = %q/%q, %t/%t", pair[0], pair[1], left, right, leftOK, rightOK)
		}
	}
	upperLocal, upperOK := pathComparisonKey([]byte("<Local@example.test>"))
	lowerLocal, lowerOK := pathComparisonKey([]byte("<local@example.test>"))
	if !upperOK || !lowerOK || upperLocal == lowerLocal {
		t.Fatal("path comparison normalized local-part case")
	}
	if key, ok := pathComparisonKey([]byte("Local@example.test")); ok || key != "" {
		t.Fatalf("invalid path produced comparison key %q", key)
	}
}

const (
	testMethodFinalize = "finalize"
	testRecipientZero  = "<user0@example.test>"
)

// TestFinalizeEnforcesCoupledExactAndOneOverFanout proves one 128 copy/ticket bound.
func TestFinalizeEnforcesCoupledExactAndOneOverFanout(t *testing.T) {
	source := mustSource(t, []byte("Subject: exact\r\n\r\nbody\r\n"))
	entries := make([]Entry, hardCopies)
	for index := range entries {
		entries[index] = mustEntry(t, source, index)
	}
	authority := &countingAuthority{RouteFanoutAuthority: NewMemoryAuthority()}
	coordinator := mustCoordinator(t, authority, Limits{})
	parent, tickets, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, entries))
	if err != nil || !parent.Valid() || parent.CopyCount() != hardCopies || len(tickets) != hardCopies ||
		parent.Usage().Copies != parent.Usage().Tickets || authority.finalizeCalls.Load() != 1 {
		t.Fatalf("exact fanout = parent=%t copies=%d tickets=%d calls=%d error=%v",
			parent.Valid(), parent.CopyCount(), len(tickets), authority.finalizeCalls.Load(), err)
	}

	over := append(entries, mustEntry(t, source, hardCopies))
	if request, requestErr := NewPlanRequest(over); !IsErrorCode(requestErr, ErrorLimitExceeded) || request.Count() != 0 || authority.finalizeCalls.Load() != 1 {
		t.Fatalf("one-over = count=%d calls=%d error=%v", request.Count(), authority.finalizeCalls.Load(), requestErr)
	}
}

// TestFinalizeChargesExplicitSourceIdentity proves dedup never uses equal bytes.
func TestFinalizeChargesExplicitSourceIdentity(t *testing.T) {
	raw := []byte("Subject: source\r\n\r\nbody\r\n")
	shared := mustSource(t, raw)
	limit := len(raw)
	limits := Limits{MaxUniqueSourceBytes: limit}
	sharedEntries := []Entry{mustEntry(t, shared, 0), mustEntry(t, shared, 1)}
	coordinator := mustCoordinator(t, NewMemoryAuthority(), limits)
	parent, _, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, sharedEntries))
	if err != nil || parent.Usage().UniqueSourceBytes != limit {
		t.Fatalf("shared source usage=%d error=%v", parent.Usage().UniqueSourceBytes, err)
	}

	equalIndependent := []Entry{mustEntry(t, mustSource(t, raw), 0), mustEntry(t, mustSource(t, raw), 1)}
	if parent, _, err = coordinator.Finalize(context.Background(), mustPlanRequest(t, equalIndependent)); !IsErrorCode(err, ErrorLimitExceeded) || parent.Valid() {
		t.Fatalf("equal independent source accepted: parent=%t error=%v", parent.Valid(), err)
	}
}

// TestFinalizeDescriptorAndWorkExactOneOver proves measured local limits preflight authority.
func TestFinalizeDescriptorAndWorkExactOneOver(t *testing.T) {
	entry := mustEntry(t, mustSource(t, []byte("Subject: limits\r\n\r\nbody\r\n")), 0)
	baselineAuthority := &countingAuthority{RouteFanoutAuthority: NewMemoryAuthority()}
	baseline := mustCoordinator(t, baselineAuthority, Limits{})
	parent, _, err := baseline.Finalize(context.Background(), mustPlanRequest(t, []Entry{entry}))
	if err != nil {
		t.Fatalf("baseline Finalize() error = %v", err)
	}
	usage := parent.Usage()
	for _, test := range []struct {
		name  string
		limit Limits
	}{
		{name: "descriptor exact", limit: Limits{MaxDescriptorBytes: usage.DescriptorBytes}},
		{name: "work exact", limit: Limits{MaxWorkUnits: usage.WorkUnits}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := &countingAuthority{RouteFanoutAuthority: NewMemoryAuthority()}
			coordinator := mustCoordinator(t, authority, test.limit)
			if _, _, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{entry})); err != nil || authority.finalizeCalls.Load() != 1 {
				t.Fatalf("exact limit error=%v calls=%d", err, authority.finalizeCalls.Load())
			}
		})
	}
	for _, test := range []struct {
		name  string
		limit Limits
	}{
		{name: "descriptor one over", limit: Limits{MaxDescriptorBytes: usage.DescriptorBytes - 1}},
		{name: "work one over", limit: Limits{MaxWorkUnits: usage.WorkUnits - 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := &countingAuthority{RouteFanoutAuthority: NewMemoryAuthority()}
			coordinator := mustCoordinator(t, authority, test.limit)
			if _, _, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{entry})); !IsErrorCode(err, ErrorLimitExceeded) || authority.finalizeCalls.Load() != 0 {
				t.Fatalf("one-over error=%v calls=%d", err, authority.finalizeCalls.Load())
			}
		})
	}
}

// TestHardSourceAndDescriptorLimitsRejectOneOverBeforeAuthority proves hard ceilings cannot be widened or bypassed.
func TestHardSourceAndDescriptorLimitsRejectOneOverBeforeAuthority(t *testing.T) {
	exactRaw := make([]byte, hardPerSource)
	exactRaw[0] = 'X'
	exact := mustSource(t, exactRaw)
	runtime.GC()
	authority := &countingAuthority{RouteFanoutAuthority: NewMemoryAuthority()}
	coordinator := mustCoordinator(t, authority, Limits{})
	if _, _, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{mustEntry(t, exact, 0)})); err != nil || authority.finalizeCalls.Load() != 1 {
		t.Fatalf("exact hard source error=%v calls=%d", err, authority.finalizeCalls.Load())
	}
	if source, err := NewImmutableSource(make([]byte, hardPerSource+1)); !IsErrorCode(err, ErrorInvalidRequest) || source.Valid() {
		t.Fatalf("one-over hard source valid=%t error=%v", source.Valid(), err)
	}
	small := mustSource(t, []byte("Subject: descriptor\r\n\r\nbody\r\n"))
	exactRoute := exactDescriptorRoute(t, small)
	exactEntry, err := NewEntry(small, PurposeOrigin, []byte("<sender@example.test>"),
		[][]byte{[]byte("<recipient@example.test>")}, DisclosureSingle, exactRoute, nil)
	if err != nil {
		t.Fatalf("exact hard descriptor constructor error = %v", err)
	}
	descriptorAuthority := &countingAuthority{RouteFanoutAuthority: NewMemoryAuthority()}
	descriptorCoordinator := mustCoordinator(t, descriptorAuthority, Limits{})
	parent, _, err := descriptorCoordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{exactEntry}))
	if err != nil || parent.Usage().DescriptorBytes != hardDescriptors || descriptorAuthority.finalizeCalls.Load() != 1 {
		t.Fatalf("exact hard descriptor bytes=%d calls=%d error=%v", parent.Usage().DescriptorBytes, descriptorAuthority.finalizeCalls.Load(), err)
	}
	if entry, err := NewEntry(small, PurposeOrigin, []byte("<sender@example.test>"),
		[][]byte{[]byte("<recipient@example.test>")}, DisclosureSingle, append(exactRoute, 'X'), nil); !IsErrorCode(err, ErrorInvalidRequest) || entry.valid() {
		t.Fatalf("one-over hard descriptor valid=%t error=%v", entry.valid(), err)
	}
	if authority.finalizeCalls.Load() != 1 {
		t.Fatalf("hard preflight failures reached authority: calls=%d", authority.finalizeCalls.Load())
	}
}

// TestRouteKnownSigningLimitsRejectBeforeAuthority proves exact per-copy source and envelope preflight.
func TestRouteKnownSigningLimitsRejectBeforeAuthority(t *testing.T) {
	source := mustSource(t, []byte("Subject: route-known limits\r\n\r\nbody\r\n"))
	reverse := []byte("<sender@example.test>")
	first := []byte("<first@example.test>")
	second := []byte("<second@example.test>")
	entry, err := NewEntry(
		source, PurposeOrigin, reverse, [][]byte{first, second},
		DisclosureAuthorizedGroup, []byte("route-known"), nil,
	)
	if err != nil {
		t.Fatalf("NewEntry() error = %v", err)
	}
	envelopeBytes := len(reverse) + len(first) + len(second)
	for _, test := range []struct {
		name  string
		exact Limits
		over  Limits
	}{
		{
			name:  "source bytes",
			exact: Limits{MaxSourceBytes: len(source.raw)},
			over:  Limits{MaxSourceBytes: len(source.raw) - 1},
		},
		{
			name:  "recipients",
			exact: Limits{MaxRecipientsPerCopy: 2},
			over:  Limits{MaxRecipientsPerCopy: 1},
		},
		{
			name:  "envelope bytes",
			exact: Limits{MaxEnvelopePathBytes: envelopeBytes},
			over:  Limits{MaxEnvelopePathBytes: envelopeBytes - 1},
		},
	} {
		t.Run(test.name+" exact", func(t *testing.T) {
			authority := &countingAuthority{RouteFanoutAuthority: NewMemoryAuthority()}
			coordinator := mustCoordinator(t, authority, test.exact)
			if _, _, err := coordinator.Finalize(
				context.Background(), mustPlanRequest(t, []Entry{entry}),
			); err != nil || authority.finalizeCalls.Load() != 1 {
				t.Fatalf("exact Finalize() error=%v calls=%d", err, authority.finalizeCalls.Load())
			}
		})
		t.Run(test.name+" one over", func(t *testing.T) {
			authority := &countingAuthority{RouteFanoutAuthority: NewMemoryAuthority()}
			coordinator := mustCoordinator(t, authority, test.over)
			if plan, tickets, err := coordinator.Finalize(
				context.Background(), mustPlanRequest(t, []Entry{entry}),
			); !IsErrorCode(err, ErrorLimitExceeded) || plan.Valid() || tickets != nil ||
				authority.finalizeCalls.Load() != 0 {
				t.Fatalf("one-over plan=%t tickets=%d error=%v calls=%d",
					plan.Valid(), len(tickets), err, authority.finalizeCalls.Load())
			}
		})
	}
}

// exactDescriptorRoute computes route bytes that make the one-copy descriptor exactly hard-sized.
func exactDescriptorRoute(t *testing.T, source ImmutableSource) []byte {
	t.Helper()
	length := hardDescriptors
	for range 8 {
		route := make([]byte, length)
		size := descriptorSize(routeBinding{
			sourceDigest: digestSource(source.raw), purpose: PurposeOrigin,
			reversePath: []byte("<sender@example.test>"), forwardPaths: [][]byte{[]byte("<recipient@example.test>")},
			disclosure: DisclosureSingle, routeClass: RouteExternal, route: route, total: 1,
		})
		if size == hardDescriptors {
			return route
		}
		length += hardDescriptors - size
		if length <= 0 {
			break
		}
	}
	t.Fatal("could not construct exact hard descriptor fixture")
	return nil
}

// TestSameRecipientAcrossDistinctCopiesCountsEveryCopy proves recipient equality never deduplicates fanout.
func TestSameRecipientAcrossDistinctCopiesCountsEveryCopy(t *testing.T) {
	source := mustSource(t, []byte("Subject: duplicate recipient\r\n\r\nbody\r\n"))
	entries := make([]Entry, hardCopies)
	for index := range entries {
		entry, err := NewEntry(source, PurposeOrigin, []byte("<sender@example.test>"),
			[][]byte{[]byte("<same@example.test>")}, DisclosureSingle, []byte(fmt.Sprintf("route-%d", index)), nil)
		if err != nil {
			t.Fatalf("NewEntry(%d) error = %v", index, err)
		}
		entries[index] = entry
	}
	coordinator := mustCoordinator(t, NewMemoryAuthority(), Limits{})
	parent, tickets, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, entries))
	if err != nil || parent.CopyCount() != hardCopies || len(tickets) != hardCopies {
		t.Fatalf("same-recipient fanout copies=%d tickets=%d error=%v", parent.CopyCount(), len(tickets), err)
	}
}

// TestPlanRequestSnapshotsEntryOrderAndSupportsConcurrentReuse proves immutable planning input.
func TestPlanRequestSnapshotsEntryOrderAndSupportsConcurrentReuse(t *testing.T) {
	source := mustSource(t, []byte("Subject: request snapshot\r\n\r\nbody\r\n"))
	first := mustEntry(t, source, 0)
	second := mustEntry(t, source, 1)
	entries := []Entry{first, second}
	request := mustPlanRequest(t, entries)
	entries[0], entries[1] = entries[1], entries[0]
	if request.Count() != 2 || string(request.entries[0].forwardPaths[0]) != testRecipientZero ||
		string(request.entries[0].routeBinding) != "route-0" {
		t.Fatal("plan request retained caller aliases or reorder")
	}
	coordinator := mustCoordinator(t, NewMemoryAuthority(), Limits{})
	const workers = 8
	var wait sync.WaitGroup
	var failures atomic.Int32
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			parent, tickets, err := coordinator.Finalize(context.Background(), request)
			if err != nil || parent.CopyCount() != 2 || len(tickets) != 2 ||
				string(tickets[0].DisclosureRecipients()[0]) != testRecipientZero {
				failures.Add(1)
			}
		}()
	}
	wait.Wait()
	if failures.Load() != 0 {
		t.Fatalf("concurrent immutable request failures = %d", failures.Load())
	}
}

// TestTicketLifecycleIsAtomicAndRequiresReplacementAfterBoundary proves retry semantics.
func TestTicketLifecycleIsAtomicAndRequiresReplacementAfterBoundary(t *testing.T) {
	authority := NewMemoryAuthority()
	coordinator := mustCoordinator(t, authority, Limits{})
	_, tickets, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{
		mustClassifiedEntry(t, mustSource(t, []byte("Subject: state\r\n\r\nbody\r\n")), 0, RouteInControl, nil),
	}))
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	ticket := tickets[0]
	const racers = 16
	var won atomic.Int32
	var wait sync.WaitGroup
	start := make(chan struct{})
	winners := make(chan Reservation, racers)
	for range racers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			if reservation, reserveErr := coordinator.Reserve(context.Background(), ticket); reserveErr == nil {
				won.Add(1)
				winners <- reservation
			}
		}()
	}
	close(start)
	wait.Wait()
	close(winners)
	if won.Load() != 1 {
		t.Fatalf("concurrent reserve winners = %d, want 1", won.Load())
	}
	winner := <-winners
	if err := winner.ReleaseBeforeBoundary(context.Background()); err != nil {
		t.Fatalf("winner release error = %v", err)
	}

	first, err := coordinator.Reserve(context.Background(), ticket)
	if err != nil {
		t.Fatalf("first Reserve() error = %v", err)
	}
	if _, err := coordinator.Reserve(context.Background(), ticket); !IsErrorCode(err, ErrorDenied) {
		t.Fatalf("concurrent Reserve() error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := first.PrepareExternalBoundary(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-boundary cancellation error = %v", err)
	}
	retry, err := coordinator.Reserve(context.Background(), ticket)
	if err != nil {
		t.Fatalf("released ticket Reserve() error = %v", err)
	}
	if err := retry.PrepareExternalBoundary(context.Background()); err != nil {
		t.Fatalf("PrepareExternalBoundary() error = %v", err)
	}
	if _, err := coordinator.Reserve(context.Background(), ticket); !IsErrorCode(err, ErrorDenied) {
		t.Fatalf("burned ticket Reserve() error = %v", err)
	}
	replacement, err := retry.Replacement(context.Background())
	if err != nil || !replacement.Valid() {
		t.Fatalf("Replacement() valid=%t error=%v", replacement.Valid(), err)
	}
	if repeated, err := retry.Replacement(context.Background()); !IsErrorCode(err, ErrorState) || repeated.Valid() {
		t.Fatalf("repeated replacement valid=%t error=%v", repeated.Valid(), err)
	}
	if err := retry.ConsumeRestrictedRelease(context.Background(), RestrictedReleaseProof{}); !IsErrorCode(err, ErrorState) {
		t.Fatalf("replaced predecessor consumed: %v", err)
	}
	replacementReservation, err := coordinator.Reserve(context.Background(), replacement)
	if err != nil {
		t.Fatalf("replacement Reserve() error = %v", err)
	}
	if err := replacementReservation.PrepareExternalBoundary(context.Background()); err != nil {
		t.Fatalf("replacement burn error = %v", err)
	}
	proof, err := NewLocalReleaseProof(replacement, replacement.binding.route)
	if err != nil {
		t.Fatalf("NewLocalReleaseProof() error = %v", err)
	}
	if err := replacementReservation.CommitSuccessfulSigning(ReleaseLocalOnly); err != nil {
		t.Fatalf("CommitSuccessfulSigning(local-only) error = %v", err)
	}
	if err := replacementReservation.ConsumeRestrictedRelease(context.Background(), proof); err != nil {
		t.Fatalf("ConsumeRestrictedRelease() error = %v", err)
	}
	if err := replacementReservation.ConsumeRestrictedRelease(context.Background(), proof); !IsErrorCode(err, ErrorState) {
		t.Fatalf("double consume error = %v", err)
	}
}

// TestSuccessfulSigningCommitClosesReplacementAndSeparatesRestrictedRelease proves the final success states.
func TestSuccessfulSigningCommitClosesReplacementAndSeparatesRestrictedRelease(t *testing.T) {
	for _, test := range []struct {
		name        string
		requirement ReleaseRequirement
	}{
		{name: "unrestricted", requirement: ReleaseUnrestricted},
		{name: "local only", requirement: ReleaseLocalOnly},
	} {
		t.Run(test.name, func(t *testing.T) {
			coordinator := mustCoordinator(t, NewMemoryAuthority(), Limits{})
			routeClass := RouteExternal
			if test.requirement == ReleaseLocalOnly {
				routeClass = RouteInControl
			}
			_, tickets, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{
				mustClassifiedEntry(
					t, mustSource(t, []byte("Subject: success\r\n\r\nbody\r\n")),
					0, routeClass, nil,
				),
			}))
			if err != nil {
				t.Fatalf("Finalize() error = %v", err)
			}
			reservation, err := coordinator.Reserve(context.Background(), tickets[0])
			if err != nil || reservation.PrepareExternalBoundary(context.Background()) != nil {
				t.Fatalf("burned reservation error = %v", err)
			}
			if err := reservation.CommitSuccessfulSigning(test.requirement); err != nil {
				t.Fatalf("CommitSuccessfulSigning(%s) error = %v", test.requirement, err)
			}
			restricted := test.requirement.Restricted()
			if reservation.ReplacementRequired() ||
				reservation.RestrictedReleaseRequired() != restricted {
				t.Fatalf("success state replacement=%t restricted=%t",
					reservation.ReplacementRequired(), reservation.RestrictedReleaseRequired())
			}
			if replacement, replaceErr := reservation.Replacement(context.Background()); replacement.Valid() ||
				!IsErrorCode(replaceErr, ErrorState) {
				t.Fatalf("successful reservation replaced: valid=%t error=%v", replacement.Valid(), replaceErr)
			}
			if commitErr := reservation.CommitSuccessfulSigning(test.requirement); !IsErrorCode(commitErr, ErrorState) {
				t.Fatalf("double success commit error = %v", commitErr)
			}
			proof := RestrictedReleaseProof{}
			if restricted {
				proof, err = NewLocalReleaseProof(tickets[0], tickets[0].binding.route)
				if err != nil {
					t.Fatalf("NewLocalReleaseProof() error = %v", err)
				}
			}
			releaseErr := reservation.ConsumeRestrictedRelease(context.Background(), proof)
			if restricted && releaseErr != nil {
				t.Fatalf("restricted release error = %v", releaseErr)
			}
			if !restricted && !IsErrorCode(releaseErr, ErrorState) {
				t.Fatalf("unrestricted result acquired restricted release: %v", releaseErr)
			}
		})
	}
}

// TestAuthorityCallBudgetCannotStrandRequiredRecovery proves narrowing preserves release/retry operations.
func TestAuthorityCallBudgetCannotStrandRequiredRecovery(t *testing.T) {
	for _, calls := range []int{1, 2} {
		if coordinator, err := NewCoordinator(NewMemoryAuthority(), Limits{MaxAuthorityCalls: calls}); !IsErrorCode(err, ErrorInvalidOptions) || coordinator.authority != nil {
			t.Fatalf("unsafe call budget %d accepted: coordinator=%v error=%v", calls, coordinator, err)
		}
	}
	coordinator := mustCoordinator(t, NewMemoryAuthority(), Limits{MaxAuthorityCalls: 3})
	source := mustSource(t, []byte("Subject: budget\r\n\r\nbody\r\n"))
	request := mustPlanRequest(t, []Entry{mustEntry(t, source, 0), mustEntry(t, source, 1)})
	_, tickets, err := coordinator.Finalize(context.Background(), request)
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	released, err := coordinator.Reserve(context.Background(), tickets[0])
	if err != nil || released.ReleaseBeforeBoundary(context.Background()) != nil {
		t.Fatalf("three-call release path error = %v", err)
	}
	burned, err := coordinator.Reserve(context.Background(), tickets[1])
	if err != nil || burned.PrepareExternalBoundary(context.Background()) != nil {
		t.Fatalf("three-call burn path error = %v", err)
	}
	if replacement, err := burned.Replacement(context.Background()); err != nil || !replacement.Valid() {
		t.Fatalf("three-call replacement valid=%t error=%v", replacement.Valid(), err)
	}
}

// TestMemoryAuthorityReleaseDistinguishesFreshFromReleased proves exact reservation lifecycle ownership.
func TestMemoryAuthorityReleaseDistinguishesFreshFromReleased(t *testing.T) {
	authority := NewMemoryAuthority()
	coordinator := mustCoordinator(t, authority, Limits{})
	_, tickets, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{
		mustEntry(t, mustSource(t, []byte("Subject: release-state\r\n\r\nbody\r\n")), 0),
	}))
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	query := tickets[0].query()
	if result, err := authority.ReleaseReservation(context.Background(), query); err != nil ||
		result.Status() != AuthorityDenied {
		t.Fatalf("never-reserved release result=%v error=%v", result, err)
	}
	reservation, err := coordinator.Reserve(context.Background(), tickets[0])
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	if err := reservation.ReleaseBeforeBoundary(context.Background()); err != nil {
		t.Fatalf("ReleaseBeforeBoundary() error = %v", err)
	}
	if result, err := authority.ReleaseReservation(context.Background(), query); err != nil ||
		result.Status() != AuthorityReleased {
		t.Fatalf("idempotent released retry result=%v error=%v", result, err)
	}
	retry, err := coordinator.Reserve(context.Background(), tickets[0])
	if err != nil {
		t.Fatalf("Reserve() after released retry error = %v", err)
	}
	if err := retry.ReleaseBeforeBoundary(context.Background()); err != nil {
		t.Fatalf("second ReleaseBeforeBoundary() error = %v", err)
	}
}

// TestCanceledReserveCleanupFailuresReturnRecoveryCapability proves cleanup failures remain recoverable.
func TestCanceledReserveCleanupFailuresReturnRecoveryCapability(t *testing.T) {
	tests := []struct {
		name string
		mode cleanupFailureMode
		code ErrorCode
	}{
		{name: "temporary", mode: cleanupTemporary, code: ErrorTemporary},
		{name: "permanent", mode: cleanupPermanent, code: ErrorPermanent},
		{name: "denied", mode: cleanupDenied, code: ErrorDenied},
		{name: "malformed committed acknowledgement", mode: cleanupMalformedCommitted, code: ErrorContract},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := NewMemoryAuthority()
			var cancel context.CancelFunc
			authority := &cancelReserveCleanupAuthority{
				RouteFanoutAuthority: base, mode: test.mode, cancel: func() { cancel() },
			}
			coordinator := mustCoordinator(t, authority, Limits{MaxAuthorityCalls: 3})
			_, tickets, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{
				mustEntry(t, mustSource(t, []byte("Subject: cleanup\r\n\r\nbody\r\n")), 0),
			}))
			if err != nil {
				t.Fatalf("Finalize() error = %v", err)
			}
			ctx, cancelCall := context.WithCancel(context.Background())
			cancel = cancelCall
			recovery, err := coordinator.Reserve(ctx, tickets[0])
			if !IsErrorCode(err, test.code) || !recovery.RecoveryRequired() {
				t.Fatalf("cleanup failure recovery=%t error=%v, want %q", recovery.RecoveryRequired(), err, test.code)
			}
			if err := recovery.PrepareExternalBoundary(context.Background()); !IsErrorCode(err, ErrorState) {
				t.Fatalf("recovery capability crossed boundary: %v", err)
			}
			authority.mode = cleanupNone
			if err := recovery.ReleaseBeforeBoundary(context.Background()); err != nil {
				t.Fatalf("recovery ReleaseBeforeBoundary() error = %v", err)
			}
			if recovery.RecoveryRequired() {
				t.Fatal("released recovery capability remained marked")
			}
		})
	}
}

type cleanupFailureMode string

const (
	cleanupNone               cleanupFailureMode = ""
	cleanupTemporary          cleanupFailureMode = "temporary"
	cleanupPermanent          cleanupFailureMode = "permanent"
	cleanupDenied             cleanupFailureMode = "denied"
	cleanupMalformedCommitted cleanupFailureMode = "malformed_committed"
)

type cancelReserveCleanupAuthority struct {
	RouteFanoutAuthority
	mode   cleanupFailureMode
	cancel func()
}

// Reserve cancels the caller after the delegated reservation commits.
func (a *cancelReserveCleanupAuthority) Reserve(ctx context.Context, query TicketQuery) (AuthorityResult, error) {
	result, err := a.RouteFanoutAuthority.Reserve(ctx, query)
	if err == nil {
		a.cancel()
	}
	return result, err
}

// ReleaseReservation injects one selected cleanup outcome.
func (a *cancelReserveCleanupAuthority) ReleaseReservation(ctx context.Context, query TicketQuery) (AuthorityResult, error) {
	switch a.mode {
	case cleanupTemporary:
		return AuthorityResult{}, provider.NewFailure(provider.FailureTemporary)
	case cleanupPermanent:
		return AuthorityResult{}, provider.NewFailure(provider.FailurePermanent)
	case cleanupDenied:
		return NewAuthorityResult(AuthorityDenied, [32]byte{}, nil), nil
	case cleanupMalformedCommitted:
		if _, err := a.RouteFanoutAuthority.ReleaseReservation(ctx, query); err != nil {
			return AuthorityResult{}, err
		}
		return AuthorityResult{}, nil
	default:
		return a.RouteFanoutAuthority.ReleaseReservation(ctx, query)
	}
}

// TestAuthorityResultMatrixRejectsIllegalPairs proves shared typed failure classification.
func TestAuthorityResultMatrixRejectsIllegalPairs(t *testing.T) {
	wrongStatus := validFinalizeTestResult(1)
	wrongStatus.status = AuthorityReserved
	resultPlusError := validFinalizeTestResult(1)
	underreported := validFinalizeTestResult(1)
	overreported := validFinalizeTestResult(2)
	parentAlias := validFinalizeTestResult(1)
	parentAlias.ticketIDs[0] = parentAlias.parentID
	duplicateTicket := validFinalizeTestResult(2)
	duplicateTicket.ticketIDs[1] = duplicateTicket.ticketIDs[0]
	zeroParentSeal := validFinalizeTestResult(1)
	zeroParentSeal.parentSeal = [32]byte{}
	zeroTicketSeal := validFinalizeTestResult(1)
	zeroTicketSeal.ticketSeals[0] = [32]byte{}
	missingTicketSeal := validFinalizeTestResult(1)
	missingTicketSeal.ticketSeals = nil
	missingBinding := validFinalizeTestResult(1)
	missingBinding.bindingIDs = nil
	tests := []struct {
		name   string
		result AuthorityResult
		err    error
		count  int
		code   ErrorCode
	}{
		{name: "zero plus nil", count: 1, code: ErrorContract},
		{name: "wrong status", result: wrongStatus, count: 1, code: ErrorContract},
		{name: "result plus error", result: resultPlusError, err: provider.NewFailure(provider.FailureTemporary), count: 1, code: ErrorContract},
		{name: "raw error", err: errors.New("temporary SECRET"), count: 1, code: ErrorContract},
		{name: "typed temporary", err: provider.NewFailure(provider.FailureTemporary), count: 1, code: ErrorTemporary},
		{name: "typed permanent", err: provider.NewFailure(provider.FailurePermanent), count: 1, code: ErrorPermanent},
		{name: "underreported ticket count", result: underreported, count: 2, code: ErrorContract},
		{name: "overreported ticket count", result: overreported, count: 1, code: ErrorContract},
		{name: "parent ticket alias", result: parentAlias, count: 1, code: ErrorContract},
		{name: "duplicate ticket identity", result: duplicateTicket, count: 2, code: ErrorContract},
		{name: "zero parent seal", result: zeroParentSeal, count: 1, code: ErrorContract},
		{name: "zero ticket seal", result: zeroTicketSeal, count: 1, code: ErrorContract},
		{name: "missing ticket seal", result: missingTicketSeal, count: 1, code: ErrorContract},
		{name: "missing binding acknowledgement", result: missingBinding, count: 1, code: ErrorContract},
		{name: "typed nil error", err: (*typedNilRouteError)(nil), count: 1, code: ErrorContract},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateAuthorityResult(test.result, test.err, AuthorityIssued, test.count)
			if !IsErrorCode(err, test.code) {
				t.Fatalf("matrix error = %v, want %q", err, test.code)
			}
		})
	}
}

// validFinalizeTestResult returns a complete authority-issued result fixture.
func validFinalizeTestResult(count int) AuthorityResult {
	result := AuthorityResult{
		status: AuthorityIssued, parentID: testAuthorityIdentity(1), parentSeal: testAuthorityIdentity(2),
		ticketIDs: make([][32]byte, count), ticketSeals: make([][32]byte, count),
		bindingIDs: make([][32]byte, count),
	}
	for index := range count {
		result.ticketIDs[index] = testAuthorityIdentity(byte(index + 3))
		result.ticketSeals[index] = testAuthorityIdentity(byte(index + 67))
		result.bindingIDs[index] = testAuthorityIdentity(byte(index + 131))
	}
	return result
}

// TestMemoryAuthorityRejectsIdentityReuse proves authority-owned cross-finalize uniqueness.
func TestMemoryAuthorityRejectsIdentityReuse(t *testing.T) {
	parentOne := testAuthorityIdentity(1)
	ticketOne := testAuthorityIdentity(2)
	parentTwo := testAuthorityIdentity(3)
	ticketTwo := testAuthorityIdentity(4)
	sealKey := testAuthorityIdentity(9)
	tests := []struct {
		name string
		ids  [][32]byte
	}{
		{name: "parent reuse", ids: [][32]byte{parentOne, ticketOne, parentOne, ticketTwo}},
		{name: "ticket reuse", ids: [][32]byte{parentOne, ticketOne, parentTwo, ticketOne}},
		{name: "cross namespace reuse", ids: [][32]byte{parentOne, ticketOne, ticketOne, ticketTwo}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := newMemoryAuthorityWithEntropy(
				sequenceAuthorityIDs(test.ids...),
				func() ([32]byte, bool) { return sealKey, true },
			)
			coordinator := mustCoordinator(t, authority, Limits{})
			request := mustPlanRequest(t, []Entry{
				mustEntry(t, mustSource(t, []byte("Subject: reuse\r\n\r\nbody\r\n")), 0),
			})
			if _, _, err := coordinator.Finalize(context.Background(), request); err != nil {
				t.Fatalf("first Finalize() error = %v", err)
			}
			if _, _, err := coordinator.Finalize(context.Background(), request); !IsErrorCode(err, ErrorContract) {
				t.Fatalf("reused identity error = %v", err)
			}
			if len(authority.parents) != 1 || len(authority.tickets) != 1 {
				t.Fatalf("reuse partially committed parents=%d tickets=%d", len(authority.parents), len(authority.tickets))
			}
		})
	}
}

// TestMemoryAuthorityRejectsConcurrentIdentityReuse proves uniqueness checks and issuance are atomic.
func TestMemoryAuthorityRejectsConcurrentIdentityReuse(t *testing.T) {
	authority := newMemoryAuthorityWithEntropy(
		sequenceAuthorityIDs(
			testAuthorityIdentity(1), testAuthorityIdentity(2),
			testAuthorityIdentity(1), testAuthorityIdentity(3),
		),
		func() ([32]byte, bool) { return testAuthorityIdentity(9), true },
	)
	coordinator := mustCoordinator(t, authority, Limits{})
	request := mustPlanRequest(t, []Entry{
		mustEntry(t, mustSource(t, []byte("Subject: concurrent-reuse\r\n\r\nbody\r\n")), 0),
	})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, _, err := coordinator.Finalize(context.Background(), request)
			results <- err
		}()
	}
	workers.Wait()
	close(results)
	var succeeded, rejected int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case IsErrorCode(err, ErrorContract):
			rejected++
		default:
			t.Fatalf("concurrent Finalize() unexpected error = %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 || len(authority.parents) != 1 || len(authority.tickets) != 1 {
		t.Fatalf(
			"concurrent reuse succeeded=%d rejected=%d parents=%d tickets=%d",
			succeeded, rejected, len(authority.parents), len(authority.tickets),
		)
	}
}

// TestMemoryAuthorityClassifiesMissingSealEntropy proves partial secret entropy is discarded and fails closed.
func TestMemoryAuthorityClassifiesMissingSealEntropy(t *testing.T) {
	authority := newMemoryAuthorityWithEntropy(randomID, func() ([32]byte, bool) {
		return testAuthorityIdentity(9), false
	})
	if authority.sealKey != [32]byte{} {
		t.Fatal("partial secret entropy retained")
	}
	coordinator := mustCoordinator(t, authority, Limits{})
	_, _, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{
		mustEntry(t, mustSource(t, []byte("Subject: entropy\r\n\r\nbody\r\n")), 0),
	}))
	if !IsErrorCode(err, ErrorPermanent) {
		t.Fatalf("zero seal-key entropy error = %v", err)
	}
}

// testAuthorityIdentity returns one deterministic nonzero opaque identity.
func testAuthorityIdentity(value byte) [32]byte {
	var id [32]byte
	id[0] = value
	return id
}

// sequenceAuthorityIDs returns a deterministic authority identity generator.
func sequenceAuthorityIDs(ids ...[32]byte) authorityIDGenerator {
	index := 0
	return func() ([32]byte, bool) {
		if index >= len(ids) {
			return [32]byte{}, false
		}
		id := ids[index]
		index++
		return id, id != [32]byte{}
	}
}

type typedNilRouteError struct{}

// Error exists only to construct a typed-nil route authority error.
func (*typedNilRouteError) Error() string { return "SECRET typed nil" }

type nilRouteAuthority struct{}

// Finalize exists only to construct a typed-nil route authority.
func (*nilRouteAuthority) Finalize(context.Context, FinalizeQuery) (AuthorityResult, error) {
	return AuthorityResult{}, nil
}

// Reserve exists only to construct a typed-nil route authority.
func (*nilRouteAuthority) Reserve(context.Context, TicketQuery) (AuthorityResult, error) {
	return AuthorityResult{}, nil
}

// ReleaseReservation exists only to construct a typed-nil route authority.
func (*nilRouteAuthority) ReleaseReservation(context.Context, TicketQuery) (AuthorityResult, error) {
	return AuthorityResult{}, nil
}

// Burn exists only to construct a typed-nil route authority.
func (*nilRouteAuthority) Burn(context.Context, TicketQuery) (AuthorityResult, error) {
	return AuthorityResult{}, nil
}

// Replace exists only to construct a typed-nil route authority.
func (*nilRouteAuthority) Replace(context.Context, TicketQuery) (AuthorityResult, error) {
	return AuthorityResult{}, nil
}

// ConsumeRelease exists only to construct a typed-nil route authority.
func (*nilRouteAuthority) ConsumeRelease(context.Context, TicketQuery) (AuthorityResult, error) {
	return AuthorityResult{}, nil
}

// TestCoordinatorRejectsTypedNilAuthorityAndForgedTickets proves authority-owned seal validation fails closed.
func TestCoordinatorRejectsTypedNilAuthorityAndForgedTickets(t *testing.T) {
	var nilAuthority *nilRouteAuthority
	if coordinator, err := NewCoordinator(nilAuthority, Limits{}); !IsErrorCode(err, ErrorInvalidOptions) || coordinator.authority != nil {
		t.Fatalf("typed-nil authority accepted: coordinator=%v error=%v", coordinator, err)
	}
	first := mustCoordinator(t, NewMemoryAuthority(), Limits{})
	_, tickets, err := first.Finalize(context.Background(), mustPlanRequest(t, []Entry{
		mustEntry(t, mustSource(t, []byte("Subject: seal\r\n\r\nbody\r\n")), 0),
	}))
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	ticket := tickets[0]
	forged := ticket
	forged.seal[0] ^= 1
	if reservation, err := first.Reserve(context.Background(), forged); !IsErrorCode(err, ErrorDenied) ||
		reservation.coordinator != nil {
		t.Fatalf("bit-flipped ticket accepted: %v", err)
	}
	second := mustCoordinator(t, NewMemoryAuthority(), Limits{})
	if reservation, err := second.Reserve(context.Background(), ticket); !IsErrorCode(err, ErrorDenied) ||
		reservation.coordinator != nil {
		t.Fatalf("cross-issuer ticket accepted: %v", err)
	}
	mixed := ticket
	mixed.binding.route = []byte("stale-route")
	if _, err := first.Reserve(context.Background(), mixed); !IsErrorCode(err, ErrorInvalidRequest) {
		t.Fatalf("stale mixed ticket accepted: %v", err)
	}
	mixed = ticket
	mixed.parentID[0] ^= 1
	if reservation, err := first.Reserve(context.Background(), mixed); !IsErrorCode(err, ErrorDenied) ||
		reservation.coordinator != nil {
		t.Fatalf("cross-parent mixed ticket accepted: %v", err)
	}
	mixed = ticket
	mixed.ticketID[0] ^= 1
	if reservation, err := first.Reserve(context.Background(), mixed); !IsErrorCode(err, ErrorDenied) ||
		reservation.coordinator != nil {
		t.Fatalf("cross-copy mixed ticket accepted: %v", err)
	}
	reservation, err := first.Reserve(context.Background(), ticket)
	if err != nil || reservation.coordinator == nil {
		t.Fatalf("exact authority-issued ticket rejected after forgeries: reservation=%v error=%v", reservation, err)
	}
	if err := reservation.ReleaseBeforeBoundary(context.Background()); err != nil {
		t.Fatalf("release after forgery attempts error = %v", err)
	}
}

// TestMalformedAuthorityPairsRemainContractErrorsAfterCancellation proves context cannot mask callback defects.
func TestMalformedAuthorityPairsRemainContractErrorsAfterCancellation(t *testing.T) {
	base := NewMemoryAuthority()
	authority := &cancelMalformedAuthority{RouteFanoutAuthority: base}
	coordinator := mustCoordinator(t, authority, Limits{})
	source := mustSource(t, []byte("Subject: malformed cancel\r\n\r\nbody\r\n"))
	entry := mustEntry(t, source, 0)

	finalizeCtx, cancelFinalize := context.WithCancel(context.Background())
	authority.method = testMethodFinalize
	authority.cancel = cancelFinalize
	if _, _, err := coordinator.Finalize(finalizeCtx, mustPlanRequest(t, []Entry{entry})); !IsErrorCode(err, ErrorContract) {
		t.Fatalf("malformed finalize cancellation error = %v", err)
	}

	authority.method = ""
	_, tickets, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{entry}))
	if err != nil {
		t.Fatalf("valid Finalize() error = %v", err)
	}
	reserveCtx, cancelReserve := context.WithCancel(context.Background())
	authority.method = methodReserve
	authority.cancel = cancelReserve
	if _, err := coordinator.Reserve(reserveCtx, tickets[0]); !IsErrorCode(err, ErrorContract) {
		t.Fatalf("malformed reserve cancellation error = %v", err)
	}
}

// TestAuthorityAcknowledgementsRejectReorderedFinalizeAndMismatchedTransition proves exact query ownership.
func TestAuthorityAcknowledgementsRejectReorderedFinalizeAndMismatchedTransition(t *testing.T) {
	base := NewMemoryAuthority()
	authority := &badAcknowledgementAuthority{RouteFanoutAuthority: base, method: testMethodFinalize}
	coordinator := mustCoordinator(t, authority, Limits{})
	source := mustSource(t, []byte("Subject: acknowledgements\r\n\r\nbody\r\n"))
	request := mustPlanRequest(t, []Entry{mustEntry(t, source, 0), mustEntry(t, source, 1)})
	if _, _, err := coordinator.Finalize(context.Background(), request); !IsErrorCode(err, ErrorContract) {
		t.Fatalf("reordered finalize acknowledgement error = %v", err)
	}
	authority.method = ""
	_, tickets, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{mustEntry(t, source, 2)}))
	if err != nil {
		t.Fatalf("valid Finalize() error = %v", err)
	}
	authority.method = "reserve_ack"
	if _, err := coordinator.Reserve(context.Background(), tickets[0]); !IsErrorCode(err, ErrorContract) {
		t.Fatalf("mismatched transition acknowledgement error = %v", err)
	}
}

type badAcknowledgementAuthority struct {
	RouteFanoutAuthority
	method string
}

// Finalize reorders exact binding acknowledgements when selected.
func (a *badAcknowledgementAuthority) Finalize(ctx context.Context, query FinalizeQuery) (AuthorityResult, error) {
	result, err := a.RouteFanoutAuthority.Finalize(ctx, query)
	if a.method == testMethodFinalize && err == nil && len(result.bindingIDs) == 2 {
		result.bindingIDs[0], result.bindingIDs[1] = result.bindingIDs[1], result.bindingIDs[0]
	}
	return result, err
}

// Reserve returns one success acknowledgement bound to a sibling ticket when selected.
func (a *badAcknowledgementAuthority) Reserve(ctx context.Context, query TicketQuery) (AuthorityResult, error) {
	if a.method == "reserve_ack" {
		wrong := query
		wrong.binding[0] ^= 1
		return NewTransitionAuthorityResult(AuthorityReserved, wrong, nil, nil), nil
	}
	return a.RouteFanoutAuthority.Reserve(ctx, query)
}

type cancelMalformedAuthority struct {
	RouteFanoutAuthority
	method authorityMethod
	cancel context.CancelFunc
}

// Finalize returns a malformed zero-plus-nil pair after cancellation when selected.
func (a *cancelMalformedAuthority) Finalize(ctx context.Context, query FinalizeQuery) (AuthorityResult, error) {
	if a.method == testMethodFinalize {
		a.cancel()
		return AuthorityResult{}, nil
	}
	return a.RouteFanoutAuthority.Finalize(ctx, query)
}

// Reserve returns a malformed zero-plus-nil pair after cancellation when selected.
func (a *cancelMalformedAuthority) Reserve(ctx context.Context, query TicketQuery) (AuthorityResult, error) {
	if a.method == methodReserve {
		a.cancel()
		return AuthorityResult{}, nil
	}
	return a.RouteFanoutAuthority.Reserve(ctx, query)
}

// TestReplacementRejectsPredecessorIdentityReplay proves same-ticket reminting cannot revive a burn.
func TestReplacementRejectsPredecessorIdentityReplay(t *testing.T) {
	base := NewMemoryAuthority()
	authority := &replacementReplayAuthority{RouteFanoutAuthority: base}
	coordinator := mustCoordinator(t, authority, Limits{})
	_, tickets, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{
		mustEntry(t, mustSource(t, []byte("Subject: replay\r\n\r\nbody\r\n")), 0),
	}))
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	reservation, err := coordinator.Reserve(context.Background(), tickets[0])
	if err != nil || reservation.PrepareExternalBoundary(context.Background()) != nil {
		t.Fatalf("burn setup error = %v", err)
	}
	if replacement, err := reservation.Replacement(context.Background()); !IsErrorCode(err, ErrorContract) || replacement.Valid() {
		t.Fatalf("replayed replacement valid=%t error=%v", replacement.Valid(), err)
	}
	if _, err := coordinator.Reserve(context.Background(), tickets[0]); !IsErrorCode(err, ErrorDenied) {
		t.Fatalf("original ticket revived: %v", err)
	}
}

type replacementReplayAuthority struct{ RouteFanoutAuthority }

// Replace maliciously returns the predecessor ticket identity.
func (a *replacementReplayAuthority) Replace(_ context.Context, query TicketQuery) (AuthorityResult, error) {
	var seal [32]byte
	seal[0] = 1
	return NewTransitionAuthorityResult(
		AuthorityReplacementIssued, query, [][32]byte{query.TicketIdentity()}, [][32]byte{seal},
	), nil
}

// TestPostCallCancellationRetainsOnlyValidatedCommittedTransitions proves reconciliation.
func TestPostCallCancellationRetainsOnlyValidatedCommittedTransitions(t *testing.T) {
	base := NewMemoryAuthority()
	var cancel context.CancelFunc
	authority := &cancelAfterAuthority{RouteFanoutAuthority: base, cancel: func() {
		if cancel != nil {
			cancel()
		}
	}}
	coordinator := mustCoordinator(t, authority, Limits{})
	_, tickets, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{
		mustClassifiedEntry(t, mustSource(t, []byte("Subject: cancel\r\n\r\nbody\r\n")), 0, RouteInControl, nil),
	}))
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}

	ctx, cancelCall := context.WithCancel(context.Background())
	cancel = cancelCall
	authority.method = methodReserve
	if _, err := coordinator.Reserve(ctx, tickets[0]); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-reserve cancellation error=%v", err)
	}
	reservation, err := coordinator.Reserve(context.Background(), tickets[0])
	if err != nil {
		t.Fatalf("Reserve() after canceled reserve cleanup error = %v", err)
	}
	ctx, cancelCall = context.WithCancel(context.Background())
	cancel = cancelCall
	authority.method = methodRelease
	if err := reservation.ReleaseBeforeBoundary(ctx); !errors.Is(err, context.Canceled) || reservation.state != reservationReleased {
		t.Fatalf("post-release cancellation state=%q error=%v", reservation.state, err)
	}

	reservation, err = coordinator.Reserve(context.Background(), tickets[0])
	if err != nil {
		t.Fatalf("retry Reserve() error = %v", err)
	}
	ctx, cancelCall = context.WithCancel(context.Background())
	cancel = cancelCall
	authority.method = methodBurn
	if err := reservation.PrepareExternalBoundary(ctx); !errors.Is(err, context.Canceled) || reservation.state != reservationBurned {
		t.Fatalf("post-burn cancellation state=%q error=%v", reservation.state, err)
	}

	ctx, cancelCall = context.WithCancel(context.Background())
	cancel = cancelCall
	authority.method = methodReplace
	if replacement, err := reservation.Replacement(ctx); !errors.Is(err, context.Canceled) || replacement.Valid() {
		t.Fatalf("post-replace cancellation valid=%t error=%v", replacement.Valid(), err)
	}
	replacement, err := reservation.RecoverReplacement()
	if err != nil || !replacement.Valid() {
		t.Fatalf("RecoverReplacement() valid=%t error=%v", replacement.Valid(), err)
	}
	replacementReservation, err := coordinator.Reserve(context.Background(), replacement)
	if err != nil || replacementReservation.PrepareExternalBoundary(context.Background()) != nil {
		t.Fatalf("replacement burn setup error=%v", err)
	}
	proof, err := NewLocalReleaseProof(replacement, replacement.binding.route)
	if err != nil {
		t.Fatalf("NewLocalReleaseProof() error = %v", err)
	}
	if err := replacementReservation.CommitSuccessfulSigning(ReleaseLocalOnly); err != nil {
		t.Fatalf("CommitSuccessfulSigning(local-only) error = %v", err)
	}
	ctx, cancelCall = context.WithCancel(context.Background())
	cancel = cancelCall
	authority.method = methodConsume
	if err := replacementReservation.ConsumeRestrictedRelease(ctx, proof); !errors.Is(err, context.Canceled) ||
		replacementReservation.state != reservationConsumed {
		t.Fatalf("post-consume cancellation state=%q error=%v", replacementReservation.state, err)
	}
}

type cancelAfterAuthority struct {
	RouteFanoutAuthority
	method authorityMethod
	cancel func()
}

// Reserve cancels only after a successful delegated reservation.
func (a *cancelAfterAuthority) Reserve(ctx context.Context, query TicketQuery) (AuthorityResult, error) {
	result, err := a.RouteFanoutAuthority.Reserve(ctx, query)
	if a.method == methodReserve && err == nil {
		a.cancel()
	}
	return result, err
}

// ReleaseReservation cancels only after a successful delegated release.
func (a *cancelAfterAuthority) ReleaseReservation(ctx context.Context, query TicketQuery) (AuthorityResult, error) {
	result, err := a.RouteFanoutAuthority.ReleaseReservation(ctx, query)
	if a.method == methodRelease && err == nil {
		a.cancel()
	}
	return result, err
}

// Burn cancels only after a successful delegated burn.
func (a *cancelAfterAuthority) Burn(ctx context.Context, query TicketQuery) (AuthorityResult, error) {
	result, err := a.RouteFanoutAuthority.Burn(ctx, query)
	if a.method == methodBurn && err == nil {
		a.cancel()
	}
	return result, err
}

// Replace cancels only after a successful delegated replacement.
func (a *cancelAfterAuthority) Replace(ctx context.Context, query TicketQuery) (AuthorityResult, error) {
	result, err := a.RouteFanoutAuthority.Replace(ctx, query)
	if a.method == methodReplace && err == nil {
		a.cancel()
	}
	return result, err
}

// ConsumeRelease cancels only after a successful delegated consume.
func (a *cancelAfterAuthority) ConsumeRelease(ctx context.Context, query TicketQuery) (AuthorityResult, error) {
	result, err := a.RouteFanoutAuthority.ConsumeRelease(ctx, query)
	if a.method == methodConsume && err == nil {
		a.cancel()
	}
	return result, err
}

// TestTypedTransitionFailureDoesNotClaimStateChange proves availability errors are non-committing.
func TestTypedTransitionFailureDoesNotClaimStateChange(t *testing.T) {
	base := NewMemoryAuthority()
	authority := &failingTransitionAuthority{RouteFanoutAuthority: base, fail: methodBurn}
	coordinator := mustCoordinator(t, authority, Limits{MaxAuthorityCalls: 3})
	_, tickets, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{
		mustEntry(t, mustSource(t, []byte("Subject: failure\r\n\r\nbody\r\n")), 0),
	}))
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	reservation, err := coordinator.Reserve(context.Background(), tickets[0])
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	if err := reservation.PrepareExternalBoundary(context.Background()); !IsErrorCode(err, ErrorTemporary) ||
		reservation.state != reservationReserved {
		t.Fatalf("typed burn failure state=%q error=%v", reservation.state, err)
	}
	if err := reservation.PrepareExternalBoundary(context.Background()); !IsErrorCode(err, ErrorLimitExceeded) ||
		authority.burnCalls != 1 {
		t.Fatalf("repeated burn failure calls=%d error=%v", authority.burnCalls, err)
	}
	if err := reservation.ReleaseBeforeBoundary(context.Background()); err != nil {
		t.Fatalf("release after noncommitting failure error=%v", err)
	}
}

type failingTransitionAuthority struct {
	RouteFanoutAuthority
	fail      authorityMethod
	burnCalls int
}

// Burn returns a legal zero-result typed temporary failure when selected.
func (a *failingTransitionAuthority) Burn(ctx context.Context, query TicketQuery) (AuthorityResult, error) {
	a.burnCalls++
	if a.fail == methodBurn {
		return AuthorityResult{}, provider.NewFailure(provider.FailureTemporary)
	}
	return a.RouteFanoutAuthority.Burn(ctx, query)
}

// TestRouteValuesAreImmutableBoundAndRedacted proves message/purpose privacy.
func TestRouteValuesAreImmutableBoundAndRedacted(t *testing.T) {
	raw := []byte("Subject: SECRET-BODY\r\n\r\nSECRET-BODY\r\n")
	source := mustSource(t, raw)
	entry := mustEntry(t, source, 0)
	raw[0] ^= 0xff
	authority := NewMemoryAuthority()
	coordinator := mustCoordinator(t, authority, Limits{})
	parent, tickets, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{entry}))
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	ticket := tickets[0]
	if !ticket.MatchesSource(source.raw) || ticket.MatchesSource([]byte("wrong")) {
		t.Fatal("ticket exact source binding failed")
	}
	recipients := ticket.DisclosureRecipients()
	recipients[0][1] = 'X'
	if string(ticket.DisclosureRecipients()[0]) != testRecipientZero {
		t.Fatal("recipient accessor retained caller alias")
	}
	reservation, err := coordinator.Reserve(context.Background(), ticket)
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	for _, value := range []any{
		source, entry, mustPlanRequest(t, []Entry{entry}), parent, ticket,
		coordinator, reservation, authority,
	} {
		formatted := fmt.Sprintf("%v %+v %#v", value, value, value)
		if strings.Contains(formatted, "SECRET") || strings.Contains(formatted, "example.test") || !strings.Contains(formatted, "redacted") {
			t.Fatalf("unsafe formatting %q", formatted)
		}
	}
}

type countingAuthority struct {
	RouteFanoutAuthority
	finalizeCalls atomic.Int32
}

// Finalize counts authority calls before delegating.
func (a *countingAuthority) Finalize(ctx context.Context, query FinalizeQuery) (AuthorityResult, error) {
	a.finalizeCalls.Add(1)
	return a.RouteFanoutAuthority.Finalize(ctx, query)
}

// mustSource constructs an immutable source fixture.
func mustSource(t *testing.T, raw []byte) ImmutableSource {
	t.Helper()
	source, err := NewImmutableSource(raw)
	if err != nil {
		t.Fatalf("NewImmutableSource() error = %v", err)
	}
	return source
}

// mustEntry constructs one single-recipient route fixture.
func mustEntry(t *testing.T, source ImmutableSource, index int) Entry {
	t.Helper()
	entry, err := NewEntry(source, PurposeOrigin, []byte("<sender@example.test>"),
		[][]byte{[]byte(fmt.Sprintf("<user%d@example.test>", index))}, DisclosureSingle,
		[]byte(fmt.Sprintf("route-%d", index)), nil)
	if err != nil {
		t.Fatalf("NewEntry() error = %v", err)
	}
	return entry
}

// mustClassifiedEntry constructs one classified single-recipient route fixture.
func mustClassifiedEntry(
	t *testing.T,
	source ImmutableSource,
	index int,
	routeClass RouteClass,
	receiver []byte,
) Entry {
	t.Helper()
	purpose := PurposeOrigin
	var revision []byte
	if routeClass == RouteInControl || routeClass == RouteExternal && len(receiver) > 0 {
		purpose = PurposeRevision
		revision = make([]byte, sha256.Size)
		revision[0] = 1
	}
	if routeClass == RouteOutOfBand {
		purpose = PurposeNextDomain
		revision = make([]byte, sha256.Size)
		revision[0] = 1
	}
	entry, err := NewClassifiedEntry(
		source, purpose, []byte("<sender@example.test>"),
		[][]byte{[]byte(fmt.Sprintf("<user%d@example.test>", index))},
		DisclosureSingle, routeClass, []byte(fmt.Sprintf("route-%d", index)),
		receiver, revision,
	)
	if err != nil {
		t.Fatalf("NewClassifiedEntry() error = %v", err)
	}
	return entry
}

// mustCoordinator constructs one route coordinator fixture.
func mustCoordinator(t *testing.T, authority RouteFanoutAuthority, limits Limits) Coordinator {
	t.Helper()
	coordinator, err := NewCoordinator(authority, limits)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}
	return coordinator
}

// mustPlanRequest constructs one immutable planning request fixture.
func mustPlanRequest(t *testing.T, entries []Entry) PlanRequest {
	t.Helper()
	request, err := NewPlanRequest(entries)
	if err != nil {
		t.Fatalf("NewPlanRequest() error = %v", err)
	}
	return request
}
