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

// requireLatestHopOnTop asserts the library placed this hop's count generated
// protocol fields as the leading block of the header, Message-Instance first.
func requireLatestHopOnTop(t *testing.T, raw []byte, count int) {
	t.Helper()
	fields, _ := traceFieldsOf(t, raw)
	if count < 1 || count > len(fields) {
		t.Fatal("fixture has fewer fields than the hop emitted")
	}
	for index, field := range fields[:count] {
		name := []byte("DKIM2-Signature:")
		if index == 0 && count == 2 {
			name = []byte("Message-Instance:")
		}
		if !bytes.HasPrefix(field, name) {
			t.Fatalf("library output field %d is not the expected top-of-header trace field", index)
		}
	}
}

// insertBelowLatestHop models an MTA trace field that sits directly below the
// hop block, such as the Received field an adapter keeps under its insert.
func insertBelowLatestHop(t *testing.T, raw []byte, count int, field string) []byte {
	t.Helper()
	fields, rest := traceFieldsOf(t, raw)
	output := make([]byte, 0, len(raw)+len(field))
	for _, current := range fields[:count] {
		output = append(output, current...)
	}
	output = append(output, field...)
	for _, current := range fields[count:] {
		output = append(output, current...)
	}
	return append(output, rest...)
}

// moveLatestHopToBottom models a legacy appender: it moves exactly the hop's
// count leading generated fields, in their emitted order, to the end of the
// header block.
func moveLatestHopToBottom(t *testing.T, raw []byte, count int) []byte {
	t.Helper()
	requireLatestHopOnTop(t, raw, count)
	fields, rest := traceFieldsOf(t, raw)
	output := make([]byte, 0, len(raw))
	for _, field := range fields[count:] {
		output = append(output, field...)
	}
	for _, field := range fields[:count] {
		output = append(output, field...)
	}
	return append(output, rest...)
}

// TestVerificationIsIndependentOfTraceFieldPlacement proves Draft-08 Sections
// 9 and 10 trace placement is presentation only: the library prepends each
// hop's block, and the verifier authenticates a chain whose hops were
// top-placed, bottom-placed, or mixed, and a Reviser signs over both a
// top-placed and a bottom-placed predecessor. Section 6.2 orders the header
// hash by field name, so physical placement across names is outside the
// signed input.
func TestVerificationIsIndependentOfTraceFieldPlacement(t *testing.T) {
	const (
		libraryPlacement = "library"
		topPlacement     = "top"
		bottomPlacement  = "bottom"
	)
	fixture := newPublicSigningFixture(t)
	origin := fixture.signOrigin(t, []byte(
		"From: alice@example.test\r\nTo: bob@example.net\r\nSubject: before\r\n\r\nbody\r\n",
	), RouteDisclosureSingle)
	requireLatestHopOnTop(t, origin, 2)
	originReverse := []byte("<alice@example.test>")
	originForward := [][]byte{[]byte("<bob@example.net>")}
	topOrigin := insertBelowLatestHop(t, origin, 2, "Received: from origin.example.test by relay.example.net; Tue, 14 Nov 2023 22:13:20 +0000\r\n")
	bottomOrigin := moveLatestHopToBottom(t, origin, 2)
	for name, raw := range map[string][]byte{libraryPlacement: origin, topPlacement: topOrigin, bottomPlacement: bottomOrigin} {
		t.Run("origin_"+name, func(t *testing.T) {
			fixture.assertPublicChainPass(t, raw, originReverse, originForward, 1)
		})
	}

	for name, predecessor := range map[string][]byte{topPlacement: topOrigin, bottomPlacement: bottomOrigin} {
		t.Run("revision_over_"+name, func(t *testing.T) {
			verification, capability, err := fixture.facade.VerifyForRevision(
				context.Background(), NewVerifyRequest(predecessor, originReverse, originForward),
			)
			if err != nil || verification.Status() != RevisionVerificationVerified || !capability.Valid() {
				t.Fatalf("VerifyForRevision() status=%q capability=%v error=%v", verification.Status(), capability.Valid(), err)
			}
			revised := bytes.Replace(predecessor, []byte("Subject: before\r\n"), []byte("Subject: after\r\n"), 1)
			nextReverse := []byte("<relay@example.net>")
			nextForward := [][]byte{[]byte("<carol@next.test>")}
			result, recovery, err := fixture.facade.SignExisting(context.Background(), NewExistingSigningRequest(
				capability, revised, nextReverse, nextForward,
				fixture.existingTicketFor(t, capability, revised, nextReverse, nextForward, RouteDisclosureSingle),
				fixture.existingProfile, SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
				RejectUnavailableBody, RecipeAllowLiterals,
			))
			if err != nil || recovery.Valid() || !result.Valid() {
				t.Fatalf("SignExisting() valid=%v recovery=%v error=%v", result.Valid(), recovery.Valid(), err)
			}
			reviser, ok := result.Unrestricted()
			if !ok || reviser.Facts().NewInstanceNumber() != 2 {
				t.Fatal("revision did not add instance 2")
			}
			signed := reviser.Bytes()
			requireLatestHopOnTop(t, signed, 2)
			for variant, raw := range map[string][]byte{
				libraryPlacement: signed,
				bottomPlacement:  moveLatestHopToBottom(t, signed, 2),
			} {
				t.Run(variant, func(t *testing.T) {
					fixture.assertPublicChainPass(t, raw, nextReverse, nextForward, 2)
				})
			}
		})
	}
}
