package dkim2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/routeplan"
)

// TestSigningLimitsRejectEveryWideningAndAcceptZeroDefaults proves the public narrow-only contract.
func TestSigningLimitsRejectEveryWideningAndAcceptZeroDefaults(t *testing.T) {
	if err := (SigningLimits{}).Validate(); err != nil {
		t.Fatalf("zero default Validate() error = %v", err)
	}
	defaults := DefaultSigningLimits()
	if err := defaults.Validate(); err != nil {
		t.Fatalf("DefaultSigningLimits().Validate() error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*SigningLimits)
	}{
		{"message", func(l *SigningLimits) { l.MaxMessageBytes++ }},
		{"header", func(l *SigningLimits) { l.MaxHeaderBytes++ }},
		{"header fields", func(l *SigningLimits) { l.MaxHeaderFields++ }},
		{"field", func(l *SigningLimits) { l.MaxFieldBytes++ }},
		{"line", func(l *SigningLimits) { l.MaxLineBytes++ }},
		{"instances", func(l *SigningLimits) { l.MaxInstances++ }},
		{"signatures", func(l *SigningLimits) { l.MaxSignatures++ }},
		{"protocol fields", func(l *SigningLimits) { l.MaxProtocolFields++ }},
		{testNameHashSets, func(l *SigningLimits) { l.MaxHashSetsPerInstance++ }},
		{"sets per field", func(l *SigningLimits) { l.MaxSignatureSetsPerField++ }},
		{"total sets", func(l *SigningLimits) { l.MaxTotalSignatureSets++ }},
		{"lookups", func(l *SigningLimits) { l.MaxPublicKeyLookups++ }},
		{"signature input", func(l *SigningLimits) { l.MaxSignatureInputBytes++ }},
		{"canonical work", func(l *SigningLimits) { l.MaxCanonicalWorkBytes++ }},
		{testNameRecipients, func(l *SigningLimits) { l.MaxGeneratedRecipients++ }},
		{"parent copies", func(l *SigningLimits) { l.MaxParentOutputCopiesAndTickets++ }},
		{"envelope paths", func(l *SigningLimits) { l.MaxEnvelopePathBytes++ }},
		{"recipe", func(l *SigningLimits) { l.MaxDecodedRecipeBytes++ }},
		{"generated sets", func(l *SigningLimits) { l.MaxGeneratedSignatureSets++ }},
		{"authorization", func(l *SigningLimits) { l.MaxAuthorizationCalls++ }},
		{"private signing", func(l *SigningLimits) { l.MaxPrivateSigningCalls++ }},
		{"nonce", func(l *SigningLimits) { l.MaxNonceBytes++ }},
		{"rsa minimum", func(l *SigningLimits) { l.MinRSABits-- }},
		{"rsa maximum", func(l *SigningLimits) { l.MaxRSABits++ }},
		{"private signature", func(l *SigningLimits) { l.MaxPrivateSignatureBytes++ }},
		{"route descriptor", func(l *SigningLimits) { l.MaxRouteDescriptorBytes++ }},
		{"route work", func(l *SigningLimits) { l.MaxRouteWorkUnits++ }},
		{"source bytes", func(l *SigningLimits) { l.MaxUniquePreSignSourceBytes++ }},
		{"route calls", func(l *SigningLimits) { l.MaxRouteAuthorityCalls++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := defaults
			test.mutate(&candidate)
			var typed *SigningError
			if err := candidate.Validate(); !errors.As(err, &typed) ||
				typed.Code() != SigningErrorInvalidOptions {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

// TestPublicSigningMessageLimitExactAndOneOver proves completed output
// accounting rejects one byte over before reservation or provider callbacks.
func TestPublicSigningMessageLimitExactAndOneOver(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	raw := []byte("From: alice@example.test\r\nSubject: exact output\r\n\r\nbody\r\n")
	baseline := fixture.signOrigin(t, raw, RouteDisclosureSingle)
	headerEnd := bytes.Index(baseline, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		t.Fatal("baseline output has no header/body separator")
	}
	headerBytes := headerEnd + len("\r\n")

	run := func(t *testing.T, maximum int, wantSuccess bool) {
		t.Helper()
		limits := DefaultSigningLimits()
		limits.MaxMessageBytes = maximum
		limits.MaxHeaderBytes = min(headerBytes, maximum)
		limits.MaxFieldBytes = min(limits.MaxFieldBytes, limits.MaxHeaderBytes)
		limits.MaxLineBytes = min(limits.MaxLineBytes, limits.MaxFieldBytes)
		limits.MaxDecodedRecipeBytes = min(limits.MaxDecodedRecipeBytes, 64)
		var authorityCalls atomic.Int64
		authority := publicRouteMemoryAuthority{
			value: routeplan.NewMemoryAuthority(), calls: &authorityCalls,
		}
		facade, err := NewSigner(
			fixture.provider, authority, fixture.authorizer, fixture.provider,
			WithSigningClock(func() time.Time { return time.Unix(1_700_000_000, 0) }),
			WithSigningLimits(limits),
		)
		if err != nil {
			t.Fatalf("NewSigner() error = %v", err)
		}
		bounded := fixture
		bounded.facade = facade
		ticket := bounded.originTicket(t, raw, RouteDisclosureSingle)
		beforeAuthority := authorityCalls.Load()
		beforeLookups := fixture.provider.lookups.Load()
		beforeSigns := fixture.provider.signs.Load()
		result, recovery, signErr := facade.SignOriginator(
			context.Background(), NewOriginatorSigningRequest(
				raw, []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")},
				ticket, fixture.profile, SigningMetadata{},
				SigningTransportFinalNetworkPreDotStuffing,
			),
		)
		if wantSuccess {
			signed, ok := result.Unrestricted()
			if signErr != nil || recovery.Valid() || !ok || len(signed.Bytes()) != maximum {
				t.Fatalf("exact result=%v recovery=%v bytes=%d error=%v",
					result.Valid(), recovery.Valid(), len(signed.Bytes()), signErr)
			}
			return
		}
		if signErr == nil || result.Valid() || recovery.Valid() {
			t.Fatalf("one-over result=%v recovery=%v error=%v", result.Valid(), recovery.Valid(), signErr)
		}
		if authorityCalls.Load() != beforeAuthority ||
			fixture.provider.lookups.Load() != beforeLookups ||
			fixture.provider.signs.Load() != beforeSigns {
			t.Fatal("one-over output crossed authority or provider boundary")
		}
	}

	t.Run("exact", func(t *testing.T) { run(t, len(baseline), true) })
	t.Run("one over", func(t *testing.T) { run(t, len(baseline)-1, false) })
}

// TestWithSigningLimitsWiresTheSharedParentCardinalityToFanout proves cross-owner coherence.
func TestWithSigningLimitsWiresTheSharedParentCardinalityToFanout(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	provider := &publicSigningProvider{edKey: privateKey}
	facade, err := NewSigner(
		provider, publicRouteMemoryAuthority{value: routeplan.NewMemoryAuthority()},
		&authorizeOrdinary{}, provider,
		WithSigningLimits(SigningLimits{MaxParentOutputCopiesAndTickets: 1}),
	)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	source, err := NewSigningSource([]byte("Subject: bounded fanout\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatalf("NewSigningSource() error = %v", err)
	}
	entries := make([]RouteEntry, 2)
	for index := range entries {
		entries[index], err = NewOriginatorRouteEntry(
			source, []byte("<sender@example.test>"),
			[][]byte{[]byte("<recipient@example.test>")}, RouteDisclosureSingle,
			[]byte{byte('a' + index)},
		)
		if err != nil {
			t.Fatalf("NewOriginatorRouteEntry(%d) error = %v", index, err)
		}
	}
	request, err := NewRouteFanoutRequest(entries)
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest() error = %v", err)
	}
	plan, tickets, err := facade.PlanRouteFanout(context.Background(), request)
	var typed *SigningError
	if plan.Valid() || tickets != nil || !errors.As(err, &typed) ||
		typed.Code() != SigningErrorLimitExceeded {
		t.Fatalf("PlanRouteFanout() plan=%t tickets=%d error=%v", plan.Valid(), len(tickets), err)
	}
}
