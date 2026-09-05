package dsn

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/dsn/dsntest"
	"github.com/croessner/dkim2/internal/verify"
)

// FuzzReceivedDSN proves the received-DSN parser path never panics, never
// returns an invalid evaluation, never leaks the outer recipient into
// diagnostics, and keeps context errors as Go errors under hostile input.
func FuzzReceivedDSN(f *testing.F) {
	keys := receivedKeys()
	staticKeys := make([]verify.StaticKey, 0, len(keys))
	for domain, key := range keys {
		staticKeys = append(staticKeys, verify.StaticKey{Domain: domain, Selector: key.Selector, Algorithm: verify.AlgorithmEd25519SHA256, Material: key.Public()})
	}
	provider, err := verify.NewStaticKeyProvider(staticKeys)
	if err != nil {
		f.Fatal(err)
	}
	verifier, err := verify.NewVerifier(provider, verify.WithClock(receivedFuzzClock))
	if err != nil {
		f.Fatal(err)
	}
	evaluator, err := NewReceivedEvaluator(verifier, ReceivedEvaluatorConfig{Parser: Options{MaxMessageBytes: 1 << 20, MaxPartBytes: 1 << 19, MaxBoundaryBytes: 70}})
	if err != nil {
		f.Fatal(err)
	}
	valid := receivedFuzzReport(f)
	f.Add(valid, []byte(receivedLocalMailFrom))
	f.Add(bytes.Replace(valid, []byte("Action: failed"), []byte("Action: delayed"), 1), []byte(receivedLocalMailFrom))
	f.Add(bytes.Replace(valid, []byte("Content-Type: message/rfc822"), []byte("Content-Type: text/rfc822-headers"), 1), []byte(receivedLocalMailFrom))
	f.Add(bytes.Replace(valid, []byte("Status: 5.1.1"), []byte("Status: 5.1"), 1), []byte(receivedLocalMailFrom))
	f.Add(bytes.Replace(valid, []byte("--dsn-boundary--"), []byte("--dsn-boundary"), 1), []byte(receivedLocalMailFrom))
	f.Add([]byte("From: a@b.example\r\n\r\nbody\r\n"), []byte("<a@b.example>"))
	f.Add(valid, []byte("<other@local.example>"))
	f.Add(valid, []byte("not-a-path"))
	f.Add([]byte(""), []byte(receivedLocalMailFrom))
	errorShape := regexp.MustCompile(`^dsn received evaluation error: stage=[a-z_]+ code=[a-z_]+$`)
	f.Fuzz(func(t *testing.T, raw []byte, recipient []byte) {
		authority := newReceivedAuthority(receivedLocalDomain)
		evaluation, err := evaluator.Evaluate(context.Background(), ReceivedRequest{Raw: raw, OuterRecipient: recipient, Authority: authority})
		if err != nil {
			if !IsReceivedErrorCode(err, ReceivedErrorInvalidRequest) {
				t.Fatalf("unexpected error class: %v", err)
			}
			if !errorShape.MatchString(err.Error()) {
				t.Fatalf("error carries content beyond the closed shape: %v", err)
			}
			return
		}
		if !evaluation.Valid() {
			t.Fatalf("invalid evaluation %+v", evaluation.Propagation())
		}
		if evaluation.Structure() != StructureValid && evaluation.Embedded() != EmbeddedNotEvaluated {
			t.Fatal("embedded evaluated without valid structure")
		}
		if evaluation.Structure() == StructureValid && evaluation.Embedded() == EmbeddedNotEvaluated {
			t.Fatal("embedded left unevaluated after a valid structure")
		}
		if evaluation.Propagation() == PropagationEligible && evaluation.LocalHop() != LocalHopLocal {
			t.Fatal("eligible without local hop")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, cancelErr := evaluator.Evaluate(ctx, ReceivedRequest{Raw: raw, OuterRecipient: recipient, Authority: authority}); cancelErr != nil &&
			!errors.Is(cancelErr, context.Canceled) && !IsReceivedErrorCode(cancelErr, ReceivedErrorInvalidRequest) {
			t.Fatalf("canceled evaluation returned %v", cancelErr)
		}
	})
}

// receivedFuzzReport renders the eligible seed report.
func receivedFuzzReport(f *testing.F) []byte {
	f.Helper()
	original, err := (dsntest.Original{Headers: "From: sender@remote.example\r\nSubject: original\r\n", Body: "body\r\n", Hops: defaultReceivedHops()}).Build()
	if err != nil {
		f.Fatal(err)
	}
	signer := receivedHop(receivedDestinationDomain, "<>", receivedLocalMailFrom)
	raw, err := (dsntest.Report{
		OuterHeaders:        "From: MAILER-DAEMON@destination.example\r\nSubject: Undelivered Mail\r\n",
		Human:               "delivery failed",
		DeliveryStatus:      dsntest.FailedDeliveryStatus(receivedDestinationDomain, receivedDestinationRaw, "5.1.1"),
		OriginalContentType: string(ContentTypeRFC822),
		Original:            original,
		Signer:              &signer,
	}).Build()
	if err != nil {
		f.Fatal(err)
	}
	return raw
}

// receivedFuzzClock fixes the verification time just after the fixture timestamp.
func receivedFuzzClock() time.Time {
	return time.Unix(int64(dsntest.DefaultTimestamp), 0).Add(time.Minute)
}
