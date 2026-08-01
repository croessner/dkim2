package dkim2

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type observationCollector struct {
	mu     sync.Mutex
	events []ObservationEvent
}

// Observe retains one immutable event for test assertions.
func (c *observationCollector) Observe(_ context.Context, event ObservationEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, event)
}

// snapshot returns an isolated event sequence.
func (c *observationCollector) snapshot() []ObservationEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]ObservationEvent(nil), c.events...)
}

// TestVerifierObservationBridgeEmitsDNSAndVerify proves injected nonnormative coverage.
func TestVerifierObservationBridgeEmitsDNSAndVerify(t *testing.T) {
	raw, publicKey := publicEd25519Fixture(t)
	collector := &observationCollector{}
	verifier, err := NewVerifier(
		publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
			providerResult := withKeyPolicyMetadata(
				FoundEd25519PublicKey(publicKey),
				newKeyPolicyMetadata(true, true),
			)
			publicKey[0] ^= 0xff
			return providerResult, nil
		}),
		WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }),
		WithObservationSink(collector),
	)
	if err != nil {
		t.Fatal("verifier construction failed")
	}
	result, err := verifier.Verify(
		context.Background(),
		NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}),
	)
	if err != nil || result.State() != ResultStatePASS {
		t.Fatalf("observation changed verification behavior: state=%q err=%v", result.State(), err)
	}
	events := collector.snapshot()
	if len(events) != 2 ||
		events[0].Kind() != ObservationDNSLookupCompleted ||
		events[1].Kind() != ObservationVerifyCompleted ||
		events[0].Result() != ObservationResultSuccess ||
		events[1].Result() != ObservationResultSuccess {
		t.Fatal("closed observation sequence changed")
	}
}

// TestVerifierAssessmentObservesOnlyApplicableVerification proves applicability
// classification does not erase completed verification telemetry or invent work.
func TestVerifierAssessmentObservesOnlyApplicableVerification(t *testing.T) {
	raw, publicKey := publicEd25519Fixture(t)
	collector := &observationCollector{}
	verifier, err := NewVerifier(
		publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
			return FoundEd25519PublicKey(publicKey), nil
		}),
		WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }),
		WithObservationSink(collector),
	)
	if err != nil {
		t.Fatal("verifier construction failed")
	}
	assessment, err := verifier.Assess(
		context.Background(),
		NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}),
	)
	if err != nil || !assessment.Applicable() {
		t.Fatalf("applicable assessment=%t error=%v", assessment.Applicable(), err)
	}
	events := collector.snapshot()
	if len(events) != 2 || events[0].Kind() != ObservationDNSLookupCompleted ||
		events[1].Kind() != ObservationVerifyCompleted {
		t.Fatalf("applicable assessment observations=%#v", events)
	}
	assessment, err = verifier.Assess(
		context.Background(),
		NewVerifyRequest(
			[]byte("From: sender@example.test\r\nSubject: unsigned\r\n\r\nbody\r\n"),
			[]byte("<sender@example.test>"),
			[][]byte{[]byte("<recipient@example.test>")},
		),
	)
	if err != nil || assessment.Applicable() || len(collector.snapshot()) != len(events) {
		t.Fatalf("non-applicable assessment=%t observations=%d error=%v", assessment.Applicable(), len(collector.snapshot()), err)
	}
}

// TestVerifierAssessmentObservesInterruptedApplicableVerification proves
// cancellation and deadline exits retain the already-known applicability.
func TestVerifierAssessmentObservesInterruptedApplicableVerification(t *testing.T) {
	raw, _ := publicEd25519Fixture(t)
	for _, testCase := range []struct {
		name       string
		newContext func() (context.Context, func(), func())
		wantErr    error
		wantClass  ObservationErrorClass
	}{
		{
			name: "canceled",
			newContext: func() (context.Context, func(), func()) {
				ctx, cancel := context.WithCancel(context.Background())
				return ctx, cancel, func() {}
			},
			wantErr: context.Canceled, wantClass: ObservationErrorCanceled,
		},
		{
			name: "deadline",
			newContext: func() (context.Context, func(), func()) {
				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
				return ctx, func() { <-ctx.Done() }, cancel
			},
			wantErr: context.DeadlineExceeded, wantClass: ObservationErrorDeadline,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, interrupt, cleanup := testCase.newContext()
			defer cleanup()
			collector := &observationCollector{}
			verifier, err := NewVerifier(
				publicProviderFunc(func(providerContext context.Context, _ PublicKeyQuery) (PublicKeyResult, error) {
					interrupt()
					return PublicKeyResult{}, providerContext.Err()
				}),
				WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }),
				WithObservationSink(collector),
			)
			if err != nil {
				t.Fatal("verifier construction failed")
			}
			assessment, assessErr := verifier.Assess(
				ctx,
				NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}),
			)
			if !errors.Is(assessErr, testCase.wantErr) || assessment.Valid() {
				t.Fatalf("assessment valid=%t error=%v", assessment.Valid(), assessErr)
			}
			events := collector.snapshot()
			verifyEvents := 0
			for _, event := range events {
				if event.Kind() != ObservationVerifyCompleted {
					continue
				}
				verifyEvents++
				if event.Result() != ObservationResultTemporary ||
					event.Reason() != ObservationReasonUnavailable ||
					event.ErrorClass() != testCase.wantClass {
					t.Fatalf("verification observation=%#v", event)
				}
			}
			if verifyEvents != 1 {
				t.Fatalf("verification observations=%d events=%#v", verifyEvents, events)
			}
		})
	}
}

// TestVerifierAssessmentLeavesUnsignedInputUnobserved proves applicability
// classification alone does not fabricate completed verification telemetry.
func TestVerifierAssessmentLeavesUnsignedInputUnobserved(t *testing.T) {
	collector := &observationCollector{}
	verifier, err := NewVerifier(
		publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
			t.Fatal("unsigned assessment reached the public-key provider")
			return PublicKeyResult{}, nil
		}),
		WithObservationSink(collector),
	)
	if err != nil {
		t.Fatal("verifier construction failed")
	}
	assessment, err := verifier.Assess(
		context.Background(),
		NewVerifyRequest(
			[]byte("From: sender@example.test\r\nSubject: unsigned\r\n\r\nbody\r\n"),
			[]byte("<sender@example.test>"),
			[][]byte{[]byte("<recipient@example.test>")},
		),
	)
	if err != nil || !assessment.Valid() || assessment.Applicable() {
		t.Fatalf("assessment valid=%t applicable=%t error=%v", assessment.Valid(), assessment.Applicable(), err)
	}
	if events := collector.snapshot(); len(events) != 0 {
		t.Fatalf("unsigned assessment observations=%#v", events)
	}
}
