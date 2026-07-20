package dkim2

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/routeplan"
	"github.com/croessner/dkim2/internal/signature"
)

// FuzzSigningFacade exercises the public route-plan and originator-signing boundary.
func FuzzSigningFacade(f *testing.F) {
	rsaKey, profile := newPublicFuzzProfile(f)
	f.Add([]byte("body"), false)
	f.Add([]byte("marker-private-selector-secret"), true)
	f.Add(bytes.Repeat([]byte{'x'}, 4096), false)

	f.Fuzz(func(t *testing.T, bodySeed []byte, invalidTransport bool) {
		signer := newPublicFuzzSigner(t, rsaKey)
		if len(bodySeed) > 4096 {
			bodySeed = bodySeed[:4096]
		}
		body := fuzzSigningASCII(bodySeed)
		raw := append([]byte("From: alice@example.test\r\nTo: bob@example.net\r\nSubject: fuzz facade\r\n\r\n"), body...)
		raw = append(raw, '\r', '\n')
		source, err := NewSigningSource(raw)
		if err != nil {
			t.Fatalf("NewSigningSource() error = %v", err)
		}
		entry, err := NewOriginatorRouteEntry(
			source, []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")},
			RouteDisclosureSingle, []byte("fuzz-local-route"),
		)
		if err != nil {
			t.Fatalf("NewOriginatorRouteEntry() error = %v", err)
		}
		fanout, err := NewRouteFanoutRequest([]RouteEntry{entry})
		if err != nil {
			t.Fatalf("NewRouteFanoutRequest() error = %v", err)
		}
		plan, tickets, err := signer.PlanRouteFanout(context.Background(), fanout)
		if err != nil || !plan.Valid() || len(tickets) != 1 {
			t.Fatalf("PlanRouteFanout() valid=%t tickets=%d error=%v", plan.Valid(), len(tickets), err)
		}
		transport := SigningTransportFinalNetworkPreDotStuffing
		if invalidTransport {
			transport = SigningTransportForm("post_dot_stuffing")
		}
		result, recovery, err := signer.SignOriginator(context.Background(), NewOriginatorSigningRequest(
			raw, []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")},
			tickets[0], profile, SigningMetadata{}, transport,
		))
		if invalidTransport {
			if err == nil || result.Valid() || recovery.Valid() {
				t.Fatalf("invalid transport result=%t recovery=%t error=%v", result.Valid(), recovery.Valid(), err)
			}
			return
		}
		if err != nil || recovery.Valid() || !result.Valid() {
			t.Fatalf("SignOriginator() result=%t recovery=%t error=%v", result.Valid(), recovery.Valid(), err)
		}
		unrestricted, ok := result.Unrestricted()
		if !ok || !unrestricted.Valid() {
			t.Fatal("public signing result was not unrestricted and valid")
		}
		signed, parseErr := rawmsg.Parse(unrestricted.Bytes())
		original, originalErr := rawmsg.Parse(raw)
		if parseErr != nil || originalErr != nil ||
			signed.Framing() != original.Framing() ||
			!bytes.Equal(signed.Body().Bytes(), original.Body().Bytes()) ||
			len(signed.Headers().FieldsByName(instance.HeaderName)) != 1 ||
			len(signed.Headers().FieldsByName(signature.HeaderName)) != 1 {
			t.Fatalf("signed parse=%v original parse=%v framing/body/protocol cardinality mismatch", parseErr, originalErr)
		}
		originalFields := original.Headers().Fields()
		signedFields := signed.Headers().Fields()
		if len(signedFields) != len(originalFields)+2 {
			t.Fatalf("signed header count=%d, want %d", len(signedFields), len(originalFields)+2)
		}
		for index := range originalFields {
			if !bytes.Equal(originalFields[index].OriginalBytes(), signedFields[index].OriginalBytes()) {
				t.Fatalf("inherited header %d changed", index)
			}
		}
	})
}

// newPublicFuzzProfile constructs one reusable RSA key and public profile.
func newPublicFuzzProfile(f *testing.F) (*rsa.PrivateKey, SigningProfile) {
	f.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		f.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	handle, err := NewPrivateKeyHandle([]byte("fuzz-rsa"))
	if err != nil {
		f.Fatalf("NewPrivateKeyHandle() error = %v", err)
	}
	credential, err := NewRSASigningCredential("rsa", &rsaKey.PublicKey, handle)
	if err != nil {
		f.Fatalf("NewRSASigningCredential() error = %v", err)
	}
	profile, err := NewRSASigningProfile("example.test", credential)
	if err != nil {
		f.Fatalf("NewRSASigningProfile() error = %v", err)
	}
	return rsaKey, profile
}

// newPublicFuzzSigner creates a fresh bounded route authority for one fuzz case.
func newPublicFuzzSigner(t testing.TB, rsaKey *rsa.PrivateKey) *Signer {
	t.Helper()
	provider := &publicSigningProvider{rsaKey: rsaKey}
	signer, err := NewSigner(
		provider, publicRouteMemoryAuthority{value: routeplan.NewMemoryAuthority()},
		&authorizeOrdinary{}, provider,
		WithSigningClock(func() time.Time { return time.Unix(1_700_000_000, 0) }),
	)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	return signer
}

// fuzzSigningASCII maps arbitrary input to bounded RFC 5322 body-safe bytes.
func fuzzSigningASCII(seed []byte) []byte {
	output := make([]byte, 0, len(seed)+len(seed)/72*2)
	for index, value := range seed {
		if index > 0 && index%72 == 0 {
			output = append(output, '\r', '\n')
		}
		output = append(output, 0x20+value%0x5f)
	}
	return output
}
