package service

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/policy"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/verify"
)

// TestServiceUsesCurrentOnlyVerification proves post-current history cancellation is not service state.
func TestServiceUsesCurrentOnlyVerification(t *testing.T) {
	const timestamp = uint64(1700000000)
	raw, key := signedMalformedHistoryMessage(t, timestamp)
	config := DefaultConfig()
	config.Clock = func() time.Time { return time.Unix(int64(timestamp), 0) }
	coordinator, err := NewVerifier(passingPolicyProvider{key: key}, config)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	message, err := rawmsg.Parse(raw)
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}
	coreRequest := verify.Request{
		Message:         message,
		Envelope:        verify.NewEnvelope([]byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}),
		RequireEnvelope: true,
	}
	counting := &serviceCancellationContext{cancelAt: int(^uint(0) >> 1)}
	if result, currentErr := coordinator.core.VerifyCurrent(counting, coreRequest); currentErr != nil || result.Status() != verify.TargetStatusPass {
		t.Fatalf("core VerifyCurrent() status=%q error=%v", result.Status(), currentErr)
	}
	if counting.calls == 0 {
		t.Fatal("core current verification made no context checks")
	}

	// Service owns one check before and one after core verification. Cancellation
	// on the next check is therefore reachable only through history descent.
	ctx := &serviceCancellationContext{cancelAt: counting.calls + 3}
	result, err := coordinator.Verify(ctx, NewRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil || result.State() != StatePASS {
		t.Fatalf("service Verify() state=%q error=%v", result.State(), err)
	}
	projection := result.PolicyProjection()
	if result.Scope() != ScopeCurrent ||
		result.HistoricalContent() != HistoricalNotEvaluated ||
		result.HistoricalSignatures() != HistoricalNotEvaluated ||
		!projection.Valid() || projection.HistoryCoverage() != policy.HistoryNotEvaluated {
		t.Fatal("service result did not preserve the current-only historical projection")
	}
}

// signedMalformedHistoryMessage creates a current-PASS m=2 request with invalid recipe JSON.
func signedMalformedHistoryMessage(t *testing.T, timestamp uint64) ([]byte, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	base, err := rawmsg.Parse([]byte("From: sender@example.test\r\nSubject: current-only service\r\n\r\nbody line\r\n"))
	if err != nil {
		t.Fatalf("rawmsg.Parse(base) error = %v", err)
	}
	headerHash, err := canonicalizer.HeaderHashFromMessage(base)
	if err != nil {
		t.Fatalf("HeaderHashFromMessage() error = %v", err)
	}
	bodyHash, err := canonicalizer.BodyHashFromMessage(base)
	if err != nil {
		t.Fatalf("BodyHashFromMessage() error = %v", err)
	}
	headerDigest, headerOK := headerHash.Digest()
	bodyDigest, bodyOK := bodyHash.Digest()
	if !headerOK || !bodyOK {
		t.Fatal("current-only service fixture omitted a digest")
	}
	build := func(signature string) string {
		hashSet := "sha256:" + headerDigest.Base64() + ":" + bodyDigest.Base64()
		return "From: sender@example.test\r\nSubject: current-only service\r\n" +
			"Message-Instance: m=1; h=" + hashSet + ";\r\n" +
			"Message-Instance: m=2; h=" + hashSet + "; r=" + base64.StdEncoding.EncodeToString([]byte("{")) + ";\r\n" +
			"DKIM2-Signature: i=1; m=2; t=" + strconv.FormatUint(timestamp, 10) +
			"; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; d=example.test; s=selector1.test:rsa-sha256:" +
			signature + ";\r\n\r\nbody line\r\n"
	}
	placeholder := base64.StdEncoding.EncodeToString(make([]byte, 128))
	unsigned, err := rawmsg.Parse([]byte(build(placeholder)))
	if err != nil {
		t.Fatalf("rawmsg.Parse(unsigned) error = %v", err)
	}
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{
		Headers:        unsigned.Headers(),
		TargetSequence: 1,
	})
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}
	digest := sha256.Sum256(input.Bytes())
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}
	return []byte(build(base64.StdEncoding.EncodeToString(signature))), &key.PublicKey
}

type serviceCancellationContext struct {
	calls    int
	cancelAt int
}

// Deadline reports no deadline for deterministic boundary cancellation.
func (*serviceCancellationContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done returns nil because the service consults Err at owned boundaries.
func (*serviceCancellationContext) Done() <-chan struct{} { return nil }

// Err returns cancellation at the configured deterministic check.
func (c *serviceCancellationContext) Err() error {
	c.calls++
	if c.calls >= c.cancelAt {
		return context.Canceled
	}
	return nil
}

// Value returns no context values.
func (*serviceCancellationContext) Value(any) any { return nil }
