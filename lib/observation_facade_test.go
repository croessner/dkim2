package dkim2

import (
	"context"
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
