package dkim2

import (
	"bytes"
	"context"
	"testing"
)

// traceFieldsOf splits a CRLF header block into complete fields, keeping each
// field's continuation lines and terminal CRLF attached.
func traceFieldsOf(t *testing.T, raw []byte) (fields [][]byte, rest []byte) {
	t.Helper()
	end := bytes.Index(raw, []byte("\r\n\r\n"))
	if end < 0 {
		t.Fatal("fixture lacks a header/body separator")
	}
	block := raw[:end+2]
	rest = raw[end+2:]
	for len(block) > 0 {
		lineEnd := bytes.Index(block, []byte("\r\n")) + 2
		if lineEnd < 2 {
			t.Fatal("fixture header line lacks CRLF")
		}
		if block[0] == ' ' || block[0] == '\t' {
			if len(fields) == 0 {
				t.Fatal("fixture starts with a continuation line")
			}
			fields[len(fields)-1] = append(fields[len(fields)-1], block[:lineEnd]...)
		} else {
			fields = append(fields, append([]byte(nil), block[:lineEnd]...))
		}
		block = block[lineEnd:]
	}
	return fields, rest
}

// moveLatestHopToTop models an adapter that prepends this hop's trace fields:
// the library appends the hop's count generated fields at the end of the header
// block, and this helper moves exactly those fields, in their emitted order,
// above the given prefix fields and the previous top field.
func moveLatestHopToTop(t *testing.T, raw []byte, count int, prefix ...string) []byte {
	t.Helper()
	fields, rest := traceFieldsOf(t, raw)
	if count < 0 || count > len(fields) {
		t.Fatal("fixture has fewer fields than the hop emitted")
	}
	hop := fields[len(fields)-count:]
	for _, field := range hop {
		if !bytes.HasPrefix(field, []byte("Message-Instance:")) && !bytes.HasPrefix(field, []byte("DKIM2-Signature:")) {
			t.Fatal("latest hop fields are not protocol fields")
		}
	}
	output := make([]byte, 0, len(raw)+64)
	for _, field := range hop {
		output = append(output, field...)
	}
	for _, field := range prefix {
		output = append(output, field...)
	}
	for _, field := range fields[:len(fields)-count] {
		output = append(output, field...)
	}
	return append(output, rest...)
}

// TestVerificationIsIndependentOfTraceFieldPlacement proves Draft-08 Sections
// 9 and 10 trace placement is presentation only: the verifier authenticates
// a chain whose hops were bottom-placed, top-placed, or mixed, and a Reviser
// signs over a top-placed predecessor. Section 6.2 orders the header hash by
// field name, so physical placement across names is outside the signed input.
func TestVerificationIsIndependentOfTraceFieldPlacement(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	origin := fixture.signOrigin(t, []byte(
		"From: alice@example.test\r\nTo: bob@example.net\r\nSubject: before\r\n\r\nbody\r\n",
	), RouteDisclosureSingle)
	originReverse := []byte("<alice@example.test>")
	originForward := [][]byte{[]byte("<bob@example.net>")}
	topOrigin := moveLatestHopToTop(t, origin, 2, "Received: from origin.example.test by relay.example.net; Tue, 14 Nov 2023 22:13:20 +0000\r\n")
	if !bytes.HasPrefix(topOrigin, []byte("Message-Instance:")) {
		t.Fatal("top-placed origin does not start with its Message-Instance")
	}
	for name, raw := range map[string][]byte{"bottom": origin, "top": topOrigin} {
		t.Run("origin_"+name, func(t *testing.T) {
			fixture.assertPublicChainPass(t, raw, originReverse, originForward, 1)
		})
	}

	verification, capability, err := fixture.facade.VerifyForRevision(
		context.Background(), NewVerifyRequest(topOrigin, originReverse, originForward),
	)
	if err != nil || verification.Status() != RevisionVerificationVerified || !capability.Valid() {
		t.Fatalf("VerifyForRevision(top) status=%q capability=%v error=%v", verification.Status(), capability.Valid(), err)
	}
	revised := bytes.Replace(topOrigin, []byte("Subject: before\r\n"), []byte("Subject: after\r\n"), 1)
	nextReverse := []byte("<relay@example.net>")
	nextForward := [][]byte{[]byte("<carol@next.test>")}
	result, recovery, err := fixture.facade.SignExisting(context.Background(), NewExistingSigningRequest(
		capability, revised, nextReverse, nextForward,
		fixture.existingTicketFor(t, capability, revised, nextReverse, nextForward, RouteDisclosureSingle),
		fixture.existingProfile, SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
		RejectUnavailableBody, RecipeAllowLiterals,
	))
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf("SignExisting(top predecessor) valid=%v recovery=%v error=%v", result.Valid(), recovery.Valid(), err)
	}
	reviser, ok := result.Unrestricted()
	if !ok || reviser.Facts().NewInstanceNumber() != 2 {
		t.Fatal("revision over a top-placed predecessor did not add instance 2")
	}
	mixed := reviser.Bytes()
	allTop := moveLatestHopToTop(t, mixed, 2, "Received: from relay.example.net by mx.next.test; Tue, 14 Nov 2023 22:13:21 +0000\r\n")
	if !bytes.HasPrefix(allTop, []byte("Message-Instance:")) {
		t.Fatal("top-placed revision does not start with its Message-Instance")
	}
	for name, raw := range map[string][]byte{"mixed": mixed, "top": allTop} {
		t.Run("revision_"+name, func(t *testing.T) {
			fixture.assertPublicChainPass(t, raw, nextReverse, nextForward, 2)
		})
	}
}
