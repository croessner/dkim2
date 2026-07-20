package signing

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/verify"
)

// requireCanceledSigningReplacement proves cancellation exposes no partial field and preserves route lineage.
func requireCanceledSigningReplacement(
	ctx context.Context,
	t *testing.T,
	coordinator Coordinator,
	request SignFieldRequest,
) {
	t.Helper()

	completed, recovery, err := coordinator.CompleteField(ctx, request)
	if !errors.Is(err, context.Canceled) || completed.Valid() || completed.field.Valid() ||
		completed.reservation != nil || completed.initialized || !recovery.Valid() ||
		!recovery.ReplacementReady() || recovery.RecoveryPending() {
		t.Fatalf(
			"canceled signing completed=%t field=%t reservation=%t initialized=%t recovery=%t/%t/%t error=%v",
			completed.Valid(), completed.field.Valid(), completed.reservation != nil, completed.initialized,
			recovery.Valid(), recovery.ReplacementReady(), recovery.RecoveryPending(), err,
		)
	}
	replacement, recoverErr := recovery.Recover(context.Background())
	if recoverErr != nil || !replacement.Valid() ||
		replacement.ParentIdentity() != request.Ticket.ParentIdentity() ||
		replacement.TicketIdentity() == request.Ticket.TicketIdentity() {
		t.Fatalf(
			"replacement valid=%t same_parent=%t distinct_ticket=%t error=%v",
			replacement.Valid(), replacement.ParentIdentity() == request.Ticket.ParentIdentity(),
			replacement.TicketIdentity() != request.Ticket.TicketIdentity(), recoverErr,
		)
	}
}

// TestSigningPostCallbackCancellationReturnsReplacement covers every context-ignoring external callback boundary.
func TestSigningPostCallbackCancellationReturnsReplacement(t *testing.T) {
	t.Run("inherited revision provider", func(t *testing.T) {
		harness := newExistingSignerHarness(t, AlgorithmEd25519SHA256)
		ctx, cancel := context.WithCancel(context.Background())
		harness.inherited.after = cancel
		authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
			harness.events.add("authorize:" + string(query.Purpose()))
			return NewAuthorizationResult(query, AuthorizationAuthorized), nil
		})
		coordinator := harness.newCoordinatorWithAuthorizer(t, authorizer, harness.defaultSigner(t), Limits{})

		requireCanceledSigningReplacement(ctx, t, coordinator, harness.request)

		want := []string{
			eventRouteReserve, eventRouteBurn, eventInheritedEd25519, eventRouteReplace,
		}
		if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("inherited cancellation order = %v, want %v", got, want)
		}
	})

	t.Run("publication", func(t *testing.T) {
		harness := newSignerHarness(t, AlgorithmEd25519SHA256)
		delegate := harness.publication.provider
		ctx, cancel := context.WithCancel(context.Background())
		harness.publication.provider = publicationProviderFunc(func(callCtx context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
			result, err := delegate.LookupKey(callCtx, query)
			cancel()
			return result, err
		})
		coordinator := harness.newCoordinator(t, harness.defaultSigner(t), Limits{})

		requireCanceledSigningReplacement(ctx, t, coordinator, harness.request)

		want := []string{
			eventRouteReserve, eventRouteBurn, eventPublishEd25519, eventRouteReplace,
		}
		if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("publication cancellation order = %v, want %v", got, want)
		}
	})

	for _, test := range []struct {
		name    string
		purpose AuthorizationPurpose
		want    []string
	}{
		{
			name: signerTestPolicyLabel, purpose: AuthorizationPolicy,
			want: []string{
				eventRouteReserve, eventRouteBurn, eventInheritedEd25519,
				eventPublishEd25519, eventAuthorizePolicy, eventRouteReplace,
			},
		},
		{
			name: signerTestFeedbackFlag, purpose: AuthorizationFeedbackRelay,
			want: []string{
				eventRouteReserve, eventRouteBurn, eventInheritedEd25519,
				eventPublishEd25519, eventAuthorizePolicy, eventAuthorizeFeedbackRelay, eventRouteReplace,
			},
		},
		{
			name: "disclosure", purpose: AuthorizationDisclosure,
			want: []string{
				eventRouteReserve, eventRouteBurn, eventInheritedEd25519,
				eventPublishEd25519, eventAuthorizePolicy, eventAuthorizeFeedbackRelay,
				eventAuthorizeRecipientDisclosure, eventRouteReplace,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newExistingSignerHarness(t, AlgorithmEd25519SHA256)
			ctx, cancel := context.WithCancel(context.Background())
			authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
				harness.events.add("authorize:" + string(query.Purpose()))
				result := NewAuthorizationResult(query, AuthorizationAuthorized)
				if query.Purpose() == test.purpose {
					cancel()
				}
				return result, nil
			})
			coordinator := harness.newCoordinatorWithAuthorizer(t, authorizer, harness.defaultSigner(t), Limits{})

			requireCanceledSigningReplacement(ctx, t, coordinator, harness.request)

			if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(test.want) {
				t.Fatalf("%s cancellation order = %v, want %v", test.name, got, test.want)
			}
		})
	}

	for _, test := range []struct {
		name      string
		algorithm Algorithm
		event     string
	}{
		{name: "RSA", algorithm: AlgorithmRSASHA256, event: "rsa-sha256"},
		{name: "Ed25519", algorithm: AlgorithmEd25519SHA256, event: string(AlgorithmEd25519SHA256)},
	} {
		t.Run(test.name+" signer", func(t *testing.T) {
			harness := newSignerHarness(t, test.algorithm)
			delegate := harness.defaultSigner(t)
			ctx, cancel := context.WithCancel(context.Background())
			signer := privateSignerFunc(func(callCtx context.Context, handle PrivateKeyHandle, request PrivateKeySignRequest) (PrivateKeySignResult, error) {
				result, err := delegate.SignDigest(callCtx, handle, request)
				cancel()
				return result, err
			})
			coordinator := harness.newCoordinator(t, signer, Limits{})

			requireCanceledSigningReplacement(ctx, t, coordinator, harness.request)

			want := []string{
				eventRouteReserve, eventRouteBurn, "publish:" + test.event,
				"sign:" + test.event, eventRouteReplace,
			}
			if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("%s signer cancellation order = %v, want %v", test.name, got, want)
			}
		})
	}

	t.Run("dual stops between RSA and Ed25519", func(t *testing.T) {
		harness := newSignerHarness(t, AlgorithmEd25519SHA256, AlgorithmRSASHA256)
		delegate := harness.defaultSigner(t)
		ctx, cancel := context.WithCancel(context.Background())
		signer := privateSignerFunc(func(callCtx context.Context, handle PrivateKeyHandle, request PrivateKeySignRequest) (PrivateKeySignResult, error) {
			result, err := delegate.SignDigest(callCtx, handle, request)
			if request.Algorithm() == AlgorithmRSASHA256 {
				cancel()
			}
			return result, err
		})
		coordinator := harness.newCoordinator(t, signer, Limits{})

		requireCanceledSigningReplacement(ctx, t, coordinator, harness.request)

		want := []string{
			eventRouteReserve, eventRouteBurn, eventPublishRSA, eventPublishEd25519,
			eventSignRSA, eventRouteReplace,
		}
		if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("dual cancellation order = %v, want %v", got, want)
		}
	})

	t.Run("deadline-ignoring signer", func(t *testing.T) {
		harness := newSignerHarness(t, AlgorithmEd25519SHA256)
		delegate := harness.defaultSigner(t)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		signer := privateSignerFunc(func(callCtx context.Context, handle PrivateKeyHandle, request PrivateKeySignRequest) (PrivateKeySignResult, error) {
			<-callCtx.Done()
			return delegate.SignDigest(context.Background(), handle, request)
		})
		coordinator := harness.newCoordinator(t, signer, Limits{})

		completed, recovery, err := coordinator.CompleteField(ctx, harness.request)
		if !errors.Is(err, context.DeadlineExceeded) || completed.Valid() || !recovery.Valid() ||
			!recovery.ReplacementReady() {
			t.Fatalf("deadline completed=%t recovery=%t/%t error=%v",
				completed.Valid(), recovery.Valid(), recovery.ReplacementReady(), err)
		}
		want := []string{
			eventRouteReserve, eventRouteBurn, eventPublishEd25519,
			eventSignEd25519, eventRouteReplace,
		}
		if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("deadline-ignoring signer order = %v, want %v", got, want)
		}
	})
}

// TestSigningRouteBoundaryCancellationReleasesOrReplacesAccordingToCommitState proves authority ownership.
func TestSigningRouteBoundaryCancellationReleasesOrReplacesAccordingToCommitState(t *testing.T) {
	t.Run("reserve committed", func(t *testing.T) {
		harness := newSignerHarness(t, AlgorithmEd25519SHA256)
		ctx, cancel := context.WithCancel(context.Background())
		harness.authority.reserved = cancel
		coordinator := harness.newCoordinator(t, harness.defaultSigner(t), Limits{})

		completed, recovery, err := coordinator.CompleteField(ctx, harness.request)
		if !errors.Is(err, context.Canceled) || completed.Valid() || completed.field.Valid() ||
			recovery.Valid() || recovery.RecoveryPending() || recovery.ReplacementReady() {
			t.Fatalf("reserve cancel completed=%t recovery=%t/%t/%t error=%v",
				completed.Valid(), recovery.Valid(), recovery.RecoveryPending(), recovery.ReplacementReady(), err)
		}
		want := []string{eventRouteReserve, "route:release"}
		if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("reserve cancellation order = %v, want %v", got, want)
		}
	})

	t.Run("burn committed", func(t *testing.T) {
		harness := newSignerHarness(t, AlgorithmEd25519SHA256)
		ctx, cancel := context.WithCancel(context.Background())
		harness.authority.burned = cancel
		coordinator := harness.newCoordinator(t, harness.defaultSigner(t), Limits{})

		requireCanceledSigningReplacement(ctx, t, coordinator, harness.request)

		want := []string{eventRouteReserve, eventRouteBurn, eventRouteReplace}
		if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("burn cancellation order = %v, want %v", got, want)
		}
	})
}

// TestSigningConcurrentSameTicketCancellationHasOneBoundaryWinner proves overlapping reuse cannot duplicate signing.
func TestSigningConcurrentSameTicketCancellationHasOneBoundaryWinner(t *testing.T) {
	harness := newSignerHarness(t, AlgorithmEd25519SHA256)
	delegate := harness.defaultSigner(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseSigner := func() {
		releaseOnce.Do(func() {
			close(release)
		})
	}
	t.Cleanup(releaseSigner)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	signer := privateSignerFunc(func(callCtx context.Context, handle PrivateKeyHandle, request PrivateKeySignRequest) (PrivateKeySignResult, error) {
		close(entered)
		<-release
		result, err := delegate.SignDigest(callCtx, handle, request)
		cancel()
		return result, err
	})
	coordinator := harness.newCoordinator(t, signer, Limits{})
	type callResult struct {
		completed CompletedSigningField
		recovery  Recovery
		err       error
	}
	firstResult := make(chan callResult, 1)
	go func() {
		completed, recovery, err := coordinator.CompleteField(ctx, harness.request)
		firstResult <- callResult{completed: completed, recovery: recovery, err: err}
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first same-ticket operation did not reach the signing boundary")
	}

	secondResult := make(chan callResult, 1)
	go func() {
		completed, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
		secondResult <- callResult{completed: completed, recovery: recovery, err: err}
	}()
	select {
	case result := <-secondResult:
		if result.err == nil || result.completed.Valid() || result.completed.field.Valid() || result.recovery.Valid() {
			t.Fatalf(
				"concurrent reuse completed=%t field=%t recovery=%t error=%v",
				result.completed.Valid(), result.completed.field.Valid(), result.recovery.Valid(), result.err,
			)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent same-ticket reuse did not fail while the winner held the boundary")
	}

	releaseSigner()
	var winner callResult
	select {
	case winner = <-firstResult:
	case <-time.After(5 * time.Second):
		t.Fatal("boundary winner did not finish after release")
	}
	if !errors.Is(winner.err, context.Canceled) || winner.completed.Valid() ||
		!winner.recovery.Valid() || !winner.recovery.ReplacementReady() {
		t.Fatalf(
			"boundary winner completed=%t recovery=%t/%t error=%v",
			winner.completed.Valid(), winner.recovery.Valid(), winner.recovery.ReplacementReady(), winner.err,
		)
	}
	replacement, err := winner.recovery.Recover(context.Background())
	if err != nil || !replacement.Valid() {
		t.Fatalf("boundary winner replacement valid=%t error=%v", replacement.Valid(), err)
	}

	want := []string{
		eventRouteReserve, eventRouteBurn, eventPublishEd25519,
		eventRouteReserve, eventSignEd25519, eventRouteReplace,
	}
	if got := harness.events.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("same-ticket cancellation order = %v, want %v", got, want)
	}
}
