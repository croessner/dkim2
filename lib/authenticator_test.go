package dkim2

import (
	"context"
	"errors"
	"testing"
	"time"
)

// indeterminateAuthenticationStore simulates one ambiguous replay mutation.
type indeterminateAuthenticationStore struct{}

// CheckAndRemember reports a content-free ambiguous store failure.
func (indeterminateAuthenticationStore) CheckAndRemember(context.Context, ReplayKey, ReplayRetention) (ReplayCheck, error) {
	return ReplayCheck(0), errors.New("ambiguous replay mutation")
}

// TestAuthenticatorOwnsFirstSeenAndDuplicateState proves replay changes the final result only.
func TestAuthenticatorOwnsFirstSeenAndDuplicateState(t *testing.T) {
	const timestamp = int64(1700000000)
	raw, key := signedPublicReplayMessage(t, timestamp, [][]byte{[]byte("<rcpt@example.test>")})
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return FoundRSAPublicKey(key), nil
	}), WithVerificationClock(func() time.Time { return time.Unix(timestamp, 0) }))
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewReplayMemoryStore(ReplayMemoryConfig{Clock: ReplayClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	deriver, err := NewReplayDeriver(syntheticReplaySecret(), 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = deriver.Close(context.Background()) })
	authenticator, err := NewAuthenticator(verifier, store, deriver, DefaultReplayRetention())
	if err != nil {
		t.Fatal(err)
	}
	request := NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")})
	first, err := authenticator.Authenticate(context.Background(), request)
	if err != nil || !first.Valid() || first.State() != ResultStatePASS || first.ReplayClass() != AuthenticationReplayFirstSeen {
		t.Fatalf("first result state=%q replay=%q valid=%t error=%v", first.State(), first.ReplayClass(), first.Valid(), err)
	}
	duplicate, err := authenticator.Authenticate(context.Background(), request)
	if err != nil || !duplicate.Valid() || duplicate.State() != ResultStateFAIL ||
		duplicate.PrimaryReason() != AuthenticationReasonDuplicateMessageWithoutExploded ||
		duplicate.ReplayClass() != AuthenticationReplayReplayed || duplicate.Verification().State() != ResultStatePASS {
		t.Fatalf("duplicate state=%q reason=%q replay=%q verification=%q error=%v", duplicate.State(), duplicate.PrimaryReason(), duplicate.ReplayClass(), duplicate.Verification().State(), err)
	}
	assertFinalAuthenticationPolicy(t, duplicate, PolicyVerdictReject)
	evidenceUnavailable := newAuthenticationResult(
		first.Verification(), ResultStateTEMPERROR,
		AuthenticationReasonReplayEvidenceUnavailable, AuthenticationReplayIndeterminate,
	)
	assertFinalAuthenticationPolicy(t, evidenceUnavailable, PolicyVerdictTempfail)
}

// TestAuthenticatorFailsClosedOnAmbiguousReplayStore proves storage uncertainty is final TEMPERROR.
func TestAuthenticatorFailsClosedOnAmbiguousReplayStore(t *testing.T) {
	const timestamp = int64(1700000000)
	raw, key := signedPublicReplayMessage(t, timestamp, [][]byte{[]byte("<rcpt@example.test>")})
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return FoundRSAPublicKey(key), nil
	}), WithVerificationClock(func() time.Time { return time.Unix(timestamp, 0) }))
	if err != nil {
		t.Fatal(err)
	}
	deriver, err := NewReplayDeriver(syntheticReplaySecret(), 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = deriver.Close(context.Background()) })
	authenticator, err := NewAuthenticator(verifier, indeterminateAuthenticationStore{}, deriver, DefaultReplayRetention())
	if err != nil {
		t.Fatal(err)
	}
	result, err := authenticator.Authenticate(context.Background(), NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil || !result.Valid() || result.State() != ResultStateTEMPERROR ||
		result.PrimaryReason() != AuthenticationReasonReplayIndeterminate ||
		result.ReplayClass() != AuthenticationReplayIndeterminate {
		t.Fatalf("result state=%q reason=%q replay=%q valid=%t error=%v", result.State(), result.PrimaryReason(), result.ReplayClass(), result.Valid(), err)
	}
	assertFinalAuthenticationPolicy(t, result, PolicyVerdictTempfail)
}

// assertFinalAuthenticationPolicy proves replay-owned final states cannot be weakened by mode.
func assertFinalAuthenticationPolicy(t *testing.T, result AuthenticationResult, want PolicyVerdict) {
	t.Helper()
	for _, mode := range []PolicyMode{PolicyModeStrict, PolicyModePermissive, PolicyModeTesting} {
		decision, err := EvaluateAuthenticationPolicy(result, WithPolicyMode(mode))
		if err != nil || !decision.Valid() || decision.VerificationState() != result.State() || decision.Verdict() != want {
			t.Fatalf("mode=%q state=%q verdict=%q want=%q valid=%t error=%v", mode, decision.VerificationState(), decision.Verdict(), want, decision.Valid(), err)
		}
	}
}
