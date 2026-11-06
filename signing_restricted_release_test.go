package dkim2

import (
	"context"
	"sync"
	"testing"
)

type nextDomainReleaseScenario struct {
	fixture        *nextDomainRegressionFixture
	result         SigningResult
	capability     VerifiedRevisionInput
	raw            []byte
	ticket         RouteCopyTicket
	reversePath    []byte
	forwardPaths   [][]byte
	routeScope     []byte
	receiver       []byte
	releaseVariant OutOfBandAcceptanceSignedMessage
}

// prepareNextDomainReleaseScenario creates one unreleased OOB-restricted public result.
func prepareNextDomainReleaseScenario(t *testing.T) nextDomainReleaseScenario {
	t.Helper()
	fixture := newNextDomainRegressionFixture(t)
	raw := []byte("From: alice@example.test\r\nSubject: OOB release\r\n\r\nbody\r\n")
	origin := fixture.signOrigin(t, raw, []byte("<bob@example.net>"), nil)
	capability := fixture.verifyRevision(
		t, origin, []byte("<alice@example.test>"),
		[][]byte{[]byte("<bob@example.net>")}, RevisionVerificationVerified,
	)
	reversePath := []byte("<relay@example.net>")
	forwardPaths := [][]byte{[]byte("<receiver@next.example.test>")}
	routeScope := []byte("release-route")
	receiver := []byte("release-receiver")
	ticket := fixture.nextDomainTicket(
		t, capability, origin, reversePath, forwardPaths,
		string(routeScope), string(receiver),
	)
	result, recovery, err := fixture.signNextDomain(
		t, capability, origin, reversePath, forwardPaths, ticket,
		fixture.profile(t, "example.net", "release"), "next.example.test",
		fixture.publication(t, "next.example.test", "release-next"), RecipeCopyOnly,
	)
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf("SignNextDomain(release) valid=%t recovery=%t error=%v",
			result.Valid(), recovery.Valid(), err)
	}
	restricted, ok := result.OutOfBandAcceptance()
	if !ok || !restricted.Valid() {
		t.Fatal("SignNextDomain(release) did not return an OOB-restricted variant")
	}
	return nextDomainReleaseScenario{
		fixture: fixture, result: result, capability: capability, raw: origin,
		ticket: ticket, reversePath: reversePath, forwardPaths: forwardPaths,
		routeScope: routeScope, receiver: receiver, releaseVariant: restricted,
	}
}

// TestPublicOutOfBandReleaseIsExactAtomicAndNilOnDenial proves every public
// OOB release denial preserves authority state and returns no message bytes.
func TestPublicOutOfBandReleaseIsExactAtomicAndNilOnDenial(t *testing.T) {
	t.Run("wrong cross replay and cancellation", func(t *testing.T) {
		scenario := prepareNextDomainReleaseScenario(t)
		otherTicket := scenario.fixture.nextDomainTicket(
			t, scenario.capability, scenario.raw, scenario.reversePath, scenario.forwardPaths,
			"other-route", "other-receiver",
		)
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		for _, testCase := range []struct {
			name         string
			ctx          context.Context
			ticket       RouteCopyTicket
			reversePath  []byte
			forwardPaths [][]byte
			receiver     []byte
			routeScope   []byte
		}{
			{
				name: "wrong reverse", ctx: context.Background(), ticket: scenario.ticket,
				reversePath: []byte("<wrong@example.net>"), forwardPaths: scenario.forwardPaths,
				receiver: scenario.receiver, routeScope: scenario.routeScope,
			},
			{
				name: "wrong recipients", ctx: context.Background(), ticket: scenario.ticket,
				reversePath:  scenario.reversePath,
				forwardPaths: [][]byte{[]byte("<wrong@next.example.test>")},
				receiver:     scenario.receiver, routeScope: scenario.routeScope,
			},
			{
				name: "wrong receiver", ctx: context.Background(), ticket: scenario.ticket,
				reversePath: scenario.reversePath, forwardPaths: scenario.forwardPaths,
				receiver: []byte("wrong-receiver"), routeScope: scenario.routeScope,
			},
			{
				name: "wrong route", ctx: context.Background(), ticket: scenario.ticket,
				reversePath: scenario.reversePath, forwardPaths: scenario.forwardPaths,
				receiver: scenario.receiver, routeScope: []byte("wrong-route"),
			},
			{
				name: "cross ticket", ctx: context.Background(), ticket: otherTicket,
				reversePath: scenario.reversePath, forwardPaths: scenario.forwardPaths,
				receiver: scenario.receiver, routeScope: scenario.routeScope,
			},
			{
				name: "cancelled", ctx: cancelled, ticket: scenario.ticket,
				reversePath: scenario.reversePath, forwardPaths: scenario.forwardPaths,
				receiver: scenario.receiver, routeScope: scenario.routeScope,
			},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				output, err := scenario.releaseVariant.ReleaseForOutOfBandAcceptance(
					testCase.ctx, testCase.ticket, testCase.reversePath,
					testCase.forwardPaths, testCase.receiver, testCase.routeScope,
				)
				if err == nil || output != nil {
					t.Fatalf("denied release bytes=%d error=%v", len(output), err)
				}
			})
		}
		output, err := scenario.releaseVariant.ReleaseForOutOfBandAcceptance(
			context.Background(), scenario.ticket, scenario.reversePath,
			scenario.forwardPaths, scenario.receiver, scenario.routeScope,
		)
		if err != nil || len(output) == 0 {
			t.Fatalf("valid release after denials bytes=%d error=%v", len(output), err)
		}
		replay, replayErr := scenario.releaseVariant.ReleaseForOutOfBandAcceptance(
			context.Background(), scenario.ticket, scenario.reversePath,
			scenario.forwardPaths, scenario.receiver, scenario.routeScope,
		)
		if replayErr == nil || replay != nil {
			t.Fatalf("replayed release bytes=%d error=%v", len(replay), replayErr)
		}
	})

	t.Run("concurrent one winner", func(t *testing.T) {
		scenario := prepareNextDomainReleaseScenario(t)
		type outcome struct {
			output []byte
			err    error
		}
		start := make(chan struct{})
		results := make(chan outcome, 2)
		var workers sync.WaitGroup
		for range 2 {
			workers.Go(func() {
				<-start
				output, err := scenario.releaseVariant.ReleaseForOutOfBandAcceptance(
					context.Background(), scenario.ticket, scenario.reversePath,
					scenario.forwardPaths, scenario.receiver, scenario.routeScope,
				)
				results <- outcome{output: output, err: err}
			})
		}
		close(start)
		workers.Wait()
		close(results)
		succeeded, denied := 0, 0
		for result := range results {
			if result.err == nil && len(result.output) > 0 {
				succeeded++
				continue
			}
			if result.err != nil && result.output == nil {
				denied++
				continue
			}
			t.Fatalf("unexpected concurrent release bytes=%d error=%v", len(result.output), result.err)
		}
		if succeeded != 1 || denied != 1 {
			t.Fatalf("concurrent release succeeded=%d denied=%d", succeeded, denied)
		}
	})
}
