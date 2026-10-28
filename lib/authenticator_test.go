package dkim2

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
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
	raw, key := signedForwardedReplayMessage(t, timestamp, "")
	authenticator := newTestAuthenticator(t, key, timestamp, newTestReplayMemoryStore(t))
	request := forwardedReplayRequest(raw)
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
	raw, key := signedForwardedReplayMessage(t, timestamp, "")
	authenticator := newTestAuthenticator(t, key, timestamp, indeterminateAuthenticationStore{})
	result, err := authenticator.Authenticate(context.Background(), forwardedReplayRequest(raw))
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

// signedForwardedReplayMessage creates one passing two-hop synthetic fixture:
// the originator's i=1 signature and an i=2 forwarder signature over the same
// m=1 instance, so the message is replay-eligible under Draft-08 Section 15.1.
func signedForwardedReplayMessage(t testing.TB, timestamp int64, flags string) ([]byte, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	base, err := rawmsg.Parse([]byte("From: sender@example.test\r\nSubject: replay facade\r\n\r\nbody line\r\n"))
	if err != nil {
		t.Fatalf("rawmsg.Parse(base) error = %v", err)
	}
	headerHash, _ := canonicalizer.HeaderHashFromMessage(base)
	bodyHash, _ := canonicalizer.BodyHashFromMessage(base)
	headerDigest, _ := headerHash.Digest()
	bodyDigest, _ := bodyHash.Digest()
	stamp := strconv.FormatInt(timestamp, 10)
	encode := func(path string) string { return base64.StdEncoding.EncodeToString([]byte(path)) }
	fields := []string{
		"From: sender@example.test\r\n",
		"Subject: replay facade\r\n",
		"Message-Instance: m=1; h=sha256:" + headerDigest.Base64() + ":" + bodyDigest.Base64() + ";\r\n",
	}
	values := []string{
		"i=1; m=1; t=" + stamp + "; mf=" + encode("<sender@example.test>") + "; rt=" + encode("<rcpt@example.test>") + "; d=example.test; s=selector.test:rsa-sha256:",
		"i=2; m=1; t=" + stamp + "; mf=" + encode("<rcpt@example.test>") + "; rt=" + encode("<final@example.test>") + flags + "; d=example.test; s=selector.test:rsa-sha256:",
	}
	placeholder := base64.StdEncoding.EncodeToString(make([]byte, 128))
	for index, value := range values {
		unsigned, err := rawmsg.Parse([]byte(strings.Join(fields, "") + "DKIM2-Signature: " + value + placeholder + ";\r\n\r\nbody line\r\n"))
		if err != nil {
			t.Fatalf("rawmsg.Parse(unsigned) error = %v", err)
		}
		input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{Headers: unsigned.Headers(), TargetSequence: uint64(index + 1)})
		if err != nil {
			t.Fatalf("SignatureInput() error = %v", err)
		}
		digest := sha256.Sum256(input.Bytes())
		sealed, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
		}
		fields = append(fields, "DKIM2-Signature: "+value+base64.StdEncoding.EncodeToString(sealed)+";\r\n")
	}
	return []byte(strings.Join(fields, "") + "\r\nbody line\r\n"), &key.PublicKey
}

// forwardedReplayRequest is the current SMTP envelope of the i=2 forwarder hop.
func forwardedReplayRequest(raw []byte) VerifyRequest {
	return NewVerifyRequest(raw, []byte("<rcpt@example.test>"), [][]byte{[]byte("<final@example.test>")})
}

// newTestAuthenticator constructs one enabled authenticator over a fixed clock and store.
func newTestAuthenticator(t *testing.T, key *rsa.PublicKey, timestamp int64, store ReplayStore, options ...AuthenticatorOption) *Authenticator {
	t.Helper()
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
	authenticator, err := NewAuthenticator(verifier, store, deriver, DefaultReplayRetention(), options...)
	if err != nil {
		t.Fatal(err)
	}
	return authenticator
}

// newTestReplayMemoryStore constructs one closed-on-cleanup in-memory replay store.
func newTestReplayMemoryStore(t *testing.T) *ReplayMemoryStore {
	t.Helper()
	store, err := NewReplayMemoryStore(ReplayMemoryConfig{Clock: ReplayClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	return store
}

// TestAuthenticatorDoesNotCountDirectDeliveries reproduces Draft-08 Section
// 15.1: a message carrying only the originator's i=1 signature was not re-sent
// by an intermediary, so repeated direct (bulk) deliveries are not replays and
// never touch the store, while verification still reports PASS.
func TestAuthenticatorDoesNotCountDirectDeliveries(t *testing.T) {
	const timestamp = int64(1700000000)
	raw, key := signedPublicReplayMessage(t, timestamp, [][]byte{[]byte("<rcpt@example.test>")})
	authenticator := newTestAuthenticator(t, key, timestamp, indeterminateAuthenticationStore{})
	request := NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")})
	for range 2 {
		result, err := authenticator.Authenticate(context.Background(), request)
		if err != nil || !result.Valid() || result.State() != ResultStatePASS || result.ReplayClass() != AuthenticationReplayNotEligible {
			t.Fatalf("direct delivery state=%q replay=%q error=%v", result.State(), result.ReplayClass(), err)
		}
	}
}

// TestAuthenticatorCountsDirectDeliveriesWhenLocalPolicyRequestsIt proves
// the opt-in local replay policy counts i=1-only messages: the first delivery
// is first_seen and an identical second delivery is a replay.
func TestAuthenticatorCountsDirectDeliveriesWhenLocalPolicyRequestsIt(t *testing.T) {
	const timestamp = int64(1700000000)
	raw, key := signedPublicReplayMessage(t, timestamp, [][]byte{[]byte("<rcpt@example.test>")})
	authenticator := newTestAuthenticator(t, key, timestamp, newTestReplayMemoryStore(t), WithDirectDeliveryReplayCounting())
	request := NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")})
	first, err := authenticator.Authenticate(context.Background(), request)
	if err != nil || first.State() != ResultStatePASS || first.ReplayClass() != AuthenticationReplayFirstSeen {
		t.Fatalf("first direct delivery state=%q replay=%q error=%v", first.State(), first.ReplayClass(), err)
	}
	second, err := authenticator.Authenticate(context.Background(), request)
	if err != nil || second.State() != ResultStateFAIL || second.ReplayClass() != AuthenticationReplayReplayed {
		t.Fatalf("second direct delivery state=%q replay=%q error=%v", second.State(), second.ReplayClass(), err)
	}
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return FoundRSAPublicKey(key), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDisabledAuthenticator(verifier, WithDirectDeliveryReplayCounting()); err == nil {
		t.Fatal("direct-delivery counting accepted without a replay store")
	}
	if DirectDeliveryReplayCountingPolicy().Counts(ReplayIdentitySet{}) || (ReplayCountingPolicy{}).Counts(ReplayIdentitySet{}) {
		t.Fatal("an invalid identity set was counted")
	}
	if _, err := NewAuthenticator(verifier, newTestReplayMemoryStore(t), nil, DefaultReplayRetention(), nil); err == nil {
		t.Fatal("nil authenticator option accepted")
	}
}

// TestAuthenticatorExplodedForwardIsNotAReplay proves an authenticated
// exploded flag on the intermediary signature permits repeated copies.
func TestAuthenticatorExplodedForwardIsNotAReplay(t *testing.T) {
	const timestamp = int64(1700000000)
	raw, key := signedForwardedReplayMessage(t, timestamp, "; f=exploded")
	authenticator := newTestAuthenticator(t, key, timestamp, newTestReplayMemoryStore(t))
	for range 2 {
		result, err := authenticator.Authenticate(context.Background(), forwardedReplayRequest(raw))
		if err != nil || !result.Valid() || result.State() != ResultStatePASS || result.ReplayClass() != AuthenticationReplayExploded {
			t.Fatalf("exploded copy state=%q reason=%q replay=%q error=%v", result.State(), result.PrimaryReason(), result.ReplayClass(), err)
		}
	}
}
