package routeplan

import (
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// TestRestrictedReleaseProofsRequireExactSealedRouteClass proves local and OOB directionality.
func TestRestrictedReleaseProofsRequireExactSealedRouteClass(t *testing.T) {
	source := mustSource(t, []byte("Subject: restricted release\r\n\r\nbody\r\n"))
	tests := []struct {
		name        string
		routeClass  RouteClass
		receiver    []byte
		requirement ReleaseRequirement
		proof       func(CopyTicket) (RestrictedReleaseProof, error)
	}{
		{
			name: "local", routeClass: RouteInControl, requirement: ReleaseLocalOnly,
			proof: func(ticket CopyTicket) (RestrictedReleaseProof, error) {
				return NewLocalReleaseProof(ticket, []byte("route-0"))
			},
		},
		{
			name: "out of band", routeClass: RouteOutOfBand,
			receiver: []byte("receiver-transaction"), requirement: ReleaseOutOfBand,
			proof: func(ticket CopyTicket) (RestrictedReleaseProof, error) {
				return NewOutOfBandReleaseProof(
					ticket, []byte("<sender@example.test>"),
					[][]byte{[]byte("<user0@example.test>")},
					[]byte("receiver-transaction"), []byte("route-0"),
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator := mustCoordinator(t, NewMemoryAuthority(), Limits{})
			_, tickets, err := coordinator.Finalize(
				context.Background(),
				mustPlanRequest(t, []Entry{
					mustClassifiedEntry(t, source, 0, test.routeClass, test.receiver),
				}),
			)
			if err != nil {
				t.Fatalf("Finalize() error = %v", err)
			}
			reservation := mustBurnedReservation(t, coordinator, tickets[0])
			proof, err := test.proof(tickets[0])
			if err != nil || !proof.Valid() || proof.Requirement() != test.requirement {
				t.Fatalf("proof valid=%t requirement=%q error=%v", proof.Valid(), proof.Requirement(), err)
			}
			if err := reservation.CommitSuccessfulSigning(test.requirement); err != nil {
				t.Fatalf("CommitSuccessfulSigning() error = %v", err)
			}
			if err := reservation.ConsumeRestrictedRelease(context.Background(), proof); err != nil {
				t.Fatalf("ConsumeRestrictedRelease() error = %v", err)
			}
			if err := reservation.ConsumeRestrictedRelease(context.Background(), proof); !IsErrorCode(err, ErrorState) {
				t.Fatalf("replayed proof error = %v", err)
			}
		})
	}
}

// TestRestrictedReleaseRejectsWrongExternalCrossTicketAndModeWithoutConsumption proves local failures are noncommitting.
func TestRestrictedReleaseRejectsWrongExternalCrossTicketAndModeWithoutConsumption(t *testing.T) {
	source := mustSource(t, []byte("Subject: restricted negatives\r\n\r\nbody\r\n"))
	coordinator := mustCoordinator(t, NewMemoryAuthority(), Limits{})
	_, tickets, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{
		mustClassifiedEntry(t, source, 0, RouteInControl, nil),
		mustClassifiedEntry(t, source, 1, RouteInControl, nil),
		mustClassifiedEntry(t, source, 2, RouteExternal, nil),
	}))
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	if proof, proofErr := NewLocalReleaseProof(tickets[0], []byte("wrong-route")); proof.Valid() ||
		!IsErrorCode(proofErr, ErrorInvalidRequest) {
		t.Fatalf("wrong route proof valid=%t error=%v", proof.Valid(), proofErr)
	}
	if proof, proofErr := NewLocalReleaseProof(tickets[2], []byte("route-2")); proof.Valid() ||
		!IsErrorCode(proofErr, ErrorInvalidRequest) {
		t.Fatalf("external route proof valid=%t error=%v", proof.Valid(), proofErr)
	}
	firstProof, err := NewLocalReleaseProof(tickets[0], []byte("route-0"))
	if err != nil {
		t.Fatalf("first proof error = %v", err)
	}
	secondProof, err := NewLocalReleaseProof(tickets[1], []byte("route-1"))
	if err != nil {
		t.Fatalf("second proof error = %v", err)
	}
	reservation := mustBurnedReservation(t, coordinator, tickets[0])
	if err := reservation.CommitSuccessfulSigning(ReleaseLocalOnly); err != nil {
		t.Fatalf("CommitSuccessfulSigning() error = %v", err)
	}
	if err := reservation.ConsumeRestrictedRelease(context.Background(), secondProof); !IsErrorCode(err, ErrorState) {
		t.Fatalf("cross-ticket proof error = %v", err)
	}
	oobProof := firstProof
	oobProof.requirement = ReleaseOutOfBand
	if err := reservation.ConsumeRestrictedRelease(context.Background(), oobProof); !IsErrorCode(err, ErrorState) {
		t.Fatalf("wrong-mode proof error = %v", err)
	}
	if err := reservation.ConsumeRestrictedRelease(context.Background(), firstProof); err != nil {
		t.Fatalf("valid proof after failures error = %v", err)
	}
}

// TestSuccessfulSigningRejectsRouteRequirementMismatch proves no unreleasable result can commit.
func TestSuccessfulSigningRejectsRouteRequirementMismatch(t *testing.T) {
	source := mustSource(t, []byte("Subject: requirement mismatch\r\n\r\nbody\r\n"))
	for _, test := range []struct {
		name        string
		routeClass  RouteClass
		receiver    []byte
		requirement ReleaseRequirement
	}{
		{name: "external local-only", routeClass: RouteExternal, requirement: ReleaseLocalOnly},
		{name: "external OOB", routeClass: RouteExternal, requirement: ReleaseOutOfBand},
		{name: "in-control OOB", routeClass: RouteInControl, requirement: ReleaseOutOfBand},
		{name: "OOB local-only", routeClass: RouteOutOfBand, receiver: []byte("receiver"), requirement: ReleaseLocalOnly},
	} {
		t.Run(test.name, func(t *testing.T) {
			coordinator := mustCoordinator(t, NewMemoryAuthority(), Limits{})
			_, tickets, err := coordinator.Finalize(
				context.Background(),
				mustPlanRequest(t, []Entry{
					mustClassifiedEntry(t, source, 0, test.routeClass, test.receiver),
				}),
			)
			if err != nil {
				t.Fatalf("Finalize() error = %v", err)
			}
			reservation := mustBurnedReservation(t, coordinator, tickets[0])
			if err := reservation.CommitSuccessfulSigning(test.requirement); !IsErrorCode(err, ErrorInvalidRequest) {
				t.Fatalf("mismatch commit error = %v", err)
			}
			if !reservation.ReplacementRequired() || reservation.RestrictedReleaseRequired() {
				t.Fatalf("mismatch changed route state: replacement=%t release=%t",
					reservation.ReplacementRequired(), reservation.RestrictedReleaseRequired())
			}
		})
	}
}

// TestReceiverEvidenceIsOrthogonalToOutboundRelease proves nd completion route combinations.
func TestReceiverEvidenceIsOrthogonalToOutboundRelease(t *testing.T) {
	source := mustSource(t, []byte("Subject: nd completion route\r\n\r\nbody\r\n"))
	for _, test := range []struct {
		name        string
		routeClass  RouteClass
		requirement ReleaseRequirement
	}{
		{name: "external unrestricted", routeClass: RouteExternal, requirement: ReleaseUnrestricted},
		{name: "in-control unrestricted", routeClass: RouteInControl, requirement: ReleaseUnrestricted},
		{name: "in-control local-only", routeClass: RouteInControl, requirement: ReleaseLocalOnly},
	} {
		t.Run(test.name, func(t *testing.T) {
			coordinator := mustCoordinator(t, NewMemoryAuthority(), Limits{})
			_, tickets, err := coordinator.Finalize(
				context.Background(),
				mustPlanRequest(t, []Entry{
					mustClassifiedEntry(t, source, 0, test.routeClass, []byte("receiver")),
				}),
			)
			if err != nil {
				t.Fatalf("Finalize() error = %v", err)
			}
			if string(tickets[0].InboundReceiverBinding()) != "receiver" {
				t.Fatal("sealed receiver evidence missing from completion ticket")
			}
			reservation := mustBurnedReservation(t, coordinator, tickets[0])
			if err := reservation.CommitSuccessfulSigning(test.requirement); err != nil {
				t.Fatalf("CommitSuccessfulSigning() error = %v", err)
			}
			if test.requirement == ReleaseLocalOnly {
				proof, proofErr := NewLocalReleaseProof(tickets[0], []byte("route-0"))
				if proofErr != nil {
					t.Fatalf("NewLocalReleaseProof() error = %v", proofErr)
				}
				if err := reservation.ConsumeRestrictedRelease(context.Background(), proof); err != nil {
					t.Fatalf("ConsumeRestrictedRelease() error = %v", err)
				}
			} else if reservation.RestrictedReleaseRequired() {
				t.Fatal("unrestricted completion retained release phase")
			}
		})
	}
}

// TestOutOfBandReleaseProofRequiresExactReceiverEnvelopeAndRoute proves every OOB binding dimension.
func TestOutOfBandReleaseProofRequiresExactReceiverEnvelopeAndRoute(t *testing.T) {
	source := mustSource(t, []byte("Subject: OOB exactness\r\n\r\nbody\r\n"))
	coordinator := mustCoordinator(t, NewMemoryAuthority(), Limits{})
	_, tickets, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{
		mustClassifiedEntry(t, source, 0, RouteOutOfBand, []byte("receiver")),
	}))
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	ticket := tickets[0]
	reverse := []byte("<sender@example.test>")
	forward := [][]byte{[]byte("<user0@example.test>")}
	for _, test := range []struct {
		name     string
		reverse  []byte
		forward  [][]byte
		receiver []byte
		route    []byte
	}{
		{name: "wrong reverse", reverse: []byte("<other@example.test>"), forward: forward, receiver: []byte("receiver"), route: []byte("route-0")},
		{name: "wrong forward", reverse: reverse, forward: [][]byte{[]byte("<other@example.test>")}, receiver: []byte("receiver"), route: []byte("route-0")},
		{name: "wrong receiver", reverse: reverse, forward: forward, receiver: []byte("other"), route: []byte("route-0")},
		{name: "wrong route", reverse: reverse, forward: forward, receiver: []byte("receiver"), route: []byte("other")},
	} {
		t.Run(test.name, func(t *testing.T) {
			proof, proofErr := NewOutOfBandReleaseProof(
				ticket, test.reverse, test.forward, test.receiver, test.route,
			)
			if proof.Valid() || !IsErrorCode(proofErr, ErrorInvalidRequest) {
				t.Fatalf("proof valid=%t error=%v", proof.Valid(), proofErr)
			}
		})
	}
	if proof, proofErr := NewLocalReleaseProof(ticket, []byte("route-0")); proof.Valid() ||
		!IsErrorCode(proofErr, ErrorInvalidRequest) {
		t.Fatalf("OOB ticket became local proof: valid=%t error=%v", proof.Valid(), proofErr)
	}
}

// TestRestrictedReleaseConcurrentConsumptionHasOneWinner proves one atomic release phase.
func TestRestrictedReleaseConcurrentConsumptionHasOneWinner(t *testing.T) {
	source := mustSource(t, []byte("Subject: concurrent release\r\n\r\nbody\r\n"))
	coordinator := mustCoordinator(t, NewMemoryAuthority(), Limits{})
	_, tickets, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{
		mustClassifiedEntry(t, source, 0, RouteInControl, nil),
	}))
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	proof, err := NewLocalReleaseProof(tickets[0], []byte("route-0"))
	if err != nil {
		t.Fatalf("NewLocalReleaseProof() error = %v", err)
	}
	reservation := mustBurnedReservation(t, coordinator, tickets[0])
	if err := reservation.CommitSuccessfulSigning(ReleaseLocalOnly); err != nil {
		t.Fatalf("CommitSuccessfulSigning() error = %v", err)
	}
	const workers = 16
	var successes atomic.Int32
	var failures atomic.Int32
	var wait sync.WaitGroup
	start := make(chan struct{})
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			err := reservation.ConsumeRestrictedRelease(context.Background(), proof)
			if err == nil {
				successes.Add(1)
			} else if IsErrorCode(err, ErrorState) {
				failures.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if successes.Load() != 1 || failures.Load() != workers-1 {
		t.Fatalf("successes=%d failures=%d", successes.Load(), failures.Load())
	}
}

// TestDualReceiverEdgesAreSealedDistinctAndAliasSafe proves both trust edges are authoritative.
func TestDualReceiverEdgesAreSealedDistinctAndAliasSafe(t *testing.T) {
	source := mustSource(t, []byte("Subject: sealed dimensions\r\n\r\nbody\r\n"))
	inbound := []byte("inbound-receiver")
	outbound := []byte("outbound-receiver")
	entry := mustDualReceiverEntry(t, source, inbound, outbound)
	inbound[0] = 'X'
	outbound[0] = 'X'
	coordinator := mustCoordinator(t, NewMemoryAuthority(), Limits{})
	_, oobTickets, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{entry}))
	if err != nil {
		t.Fatalf("Finalize(OOB) error = %v", err)
	}
	_, localTickets, err := coordinator.Finalize(context.Background(), mustPlanRequest(t, []Entry{
		mustClassifiedEntry(t, source, 0, RouteInControl, nil),
	}))
	if err != nil {
		t.Fatalf("Finalize(local) error = %v", err)
	}
	variants := []Entry{
		mustDualReceiverEntry(t, source, []byte("other-inbound"), []byte("outbound-receiver")),
		mustDualReceiverEntry(t, source, []byte("inbound-receiver"), []byte("other-outbound")),
		mustDualReceiverEntry(t, source, []byte("outbound-receiver"), []byte("inbound-receiver")),
	}
	identities := make([][32]byte, 0, len(variants))
	for _, variant := range variants {
		_, tickets, finalizeErr := coordinator.Finalize(
			context.Background(), mustPlanRequest(t, []Entry{variant}),
		)
		if finalizeErr != nil {
			t.Fatalf("Finalize(receiver variant) error = %v", finalizeErr)
		}
		identities = append(identities, tickets[0].BindingIdentity())
	}
	baseIdentity := oobTickets[0].BindingIdentity()
	if baseIdentity == localTickets[0].BindingIdentity() {
		t.Fatal("route class missing from exact binding identity")
	}
	for index, identity := range identities {
		if baseIdentity == identity {
			t.Fatalf("receiver edge variant %d missing from exact binding identity", index)
		}
	}
	if _, err := NewOutOfBandReleaseProof(
		oobTickets[0], []byte("<sender@example.test>"),
		[][]byte{[]byte("<user0@example.test>")},
		[]byte("outbound-receiver"), []byte("route-0"),
	); err != nil {
		t.Fatalf("owned receiver alias changed: %v", err)
	}
	routeCopy := oobTickets[0].RouteScope()
	inboundCopy := oobTickets[0].InboundReceiverBinding()
	outboundCopy := oobTickets[0].OutboundReceiverBinding()
	routeCopy[0] = 'X'
	inboundCopy[0] = 'X'
	outboundCopy[0] = 'X'
	if _, err := NewOutOfBandReleaseProof(
		oobTickets[0], []byte("<sender@example.test>"),
		[][]byte{[]byte("<user0@example.test>")},
		[]byte("outbound-receiver"), []byte("route-0"),
	); err != nil {
		t.Fatalf("trusted accessor aliases escaped: %v", err)
	}
}

// TestOOBDescriptorAccountingIncludesBothReceiverEdges proves exact and one-over budgets.
func TestOOBDescriptorAccountingIncludesBothReceiverEdges(t *testing.T) {
	source := mustSource(t, []byte("Subject: OOB accounting\r\n\r\nbody\r\n"))
	entry := mustDualReceiverEntry(
		t, source, []byte("inbound-receiver"), []byte("outbound-receiver"),
	)
	binding := routeBinding{
		sourceDigest: digestSource(source.raw), purpose: PurposeNextDomain,
		reversePath:  []byte("<sender@example.test>"),
		forwardPaths: [][]byte{[]byte("<user0@example.test>")},
		disclosure:   DisclosureSingle, routeClass: RouteOutOfBand,
		route: []byte("route-0"), inboundReceiver: []byte("inbound-receiver"),
		outboundReceiver: []byte("outbound-receiver"),
		revision: func() []byte {
			value := make([]byte, sha256.Size)
			value[0] = 1
			return value
		}(), total: 1,
	}
	exact := descriptorSize(binding)
	authority := &countingAuthority{RouteFanoutAuthority: NewMemoryAuthority()}
	coordinator := mustCoordinator(t, authority, Limits{MaxDescriptorBytes: exact})
	if _, tickets, err := coordinator.Finalize(
		context.Background(), mustPlanRequest(t, []Entry{entry}),
	); err != nil || len(tickets) != 1 || authority.finalizeCalls.Load() != 1 {
		t.Fatalf("exact descriptor tickets=%d error=%v calls=%d",
			len(tickets), err, authority.finalizeCalls.Load())
	}
	authority = &countingAuthority{RouteFanoutAuthority: NewMemoryAuthority()}
	coordinator = mustCoordinator(t, authority, Limits{MaxDescriptorBytes: exact - 1})
	if plan, tickets, err := coordinator.Finalize(
		context.Background(), mustPlanRequest(t, []Entry{entry}),
	); !IsErrorCode(err, ErrorLimitExceeded) || plan.Valid() || tickets != nil ||
		authority.finalizeCalls.Load() != 0 {
		t.Fatalf("one-over plan=%t tickets=%d error=%v calls=%d",
			plan.Valid(), len(tickets), err, authority.finalizeCalls.Load())
	}
	const exactWork = 1 + 4 + 1 + 2 // unique source, fixed work, recipient, two receiver edges.
	authority = &countingAuthority{RouteFanoutAuthority: NewMemoryAuthority()}
	coordinator = mustCoordinator(t, authority, Limits{MaxWorkUnits: exactWork})
	if _, tickets, err := coordinator.Finalize(
		context.Background(), mustPlanRequest(t, []Entry{entry}),
	); err != nil || len(tickets) != 1 || authority.finalizeCalls.Load() != 1 {
		t.Fatalf("exact work tickets=%d error=%v calls=%d",
			len(tickets), err, authority.finalizeCalls.Load())
	}
	authority = &countingAuthority{RouteFanoutAuthority: NewMemoryAuthority()}
	coordinator = mustCoordinator(t, authority, Limits{MaxWorkUnits: exactWork - 1})
	if plan, tickets, err := coordinator.Finalize(
		context.Background(), mustPlanRequest(t, []Entry{entry}),
	); !IsErrorCode(err, ErrorLimitExceeded) || plan.Valid() || tickets != nil ||
		authority.finalizeCalls.Load() != 0 {
		t.Fatalf("one-over work plan=%t tickets=%d error=%v calls=%d",
			plan.Valid(), len(tickets), err, authority.finalizeCalls.Load())
	}
}

// mustDualReceiverEntry constructs one next-domain route with two distinct OOB trust edges.
func mustDualReceiverEntry(
	t *testing.T,
	source ImmutableSource,
	inboundReceiver, outboundReceiver []byte,
) Entry {
	t.Helper()
	revision := make([]byte, sha256.Size)
	revision[0] = 1
	entry, err := NewDualReceiverClassifiedEntry(
		source, PurposeNextDomain, []byte("<sender@example.test>"),
		[][]byte{[]byte("<user0@example.test>")}, DisclosureSingle,
		RouteOutOfBand, []byte("route-0"), inboundReceiver, outboundReceiver, revision,
	)
	if err != nil {
		t.Fatalf("NewDualReceiverClassifiedEntry() error = %v", err)
	}
	return entry
}

// TestRestrictedReleaseTypesAreRedactedAndHaveNoGenericSerialization proves proof privacy.
func TestRestrictedReleaseTypesAreRedactedAndHaveNoGenericSerialization(t *testing.T) {
	proofType := reflect.TypeOf(RestrictedReleaseProof{})
	for _, method := range []string{"Bytes", "Marshal", "MarshalBinary", "MarshalText", "AppendText"} {
		if _, ok := proofType.MethodByName(method); ok {
			t.Fatalf("RestrictedReleaseProof exposes %s", method)
		}
	}
	proof := RestrictedReleaseProof{
		requirement: ReleaseLocalOnly,
		query: TicketQuery{
			parentID: filledDigest(1), ticketID: filledDigest(2),
			binding: filledDigest(3), seal: filledDigest(4),
		},
	}
	formatted := fmt.Sprintf("%v %+v %#v %s", proof, proof, proof, proof)
	if strings.Contains(formatted, "local_only") || !strings.Contains(formatted, "redacted") {
		t.Fatalf("unsafe proof formatting %q", formatted)
	}
}

// mustBurnedReservation reserves and burns one exact ticket fixture.
func mustBurnedReservation(t *testing.T, coordinator Coordinator, ticket CopyTicket) *Reservation {
	t.Helper()
	reservation, err := coordinator.Reserve(context.Background(), ticket)
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	if err := reservation.PrepareExternalBoundary(context.Background()); err != nil {
		t.Fatalf("PrepareExternalBoundary() error = %v", err)
	}
	return &reservation
}

// filledDigest constructs one nonzero opaque digest fixture.
func filledDigest(value byte) [32]byte {
	var digest [32]byte
	for index := range digest {
		digest[index] = value
	}
	return digest
}
