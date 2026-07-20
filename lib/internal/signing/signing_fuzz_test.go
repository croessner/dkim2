package signing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"slices"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/routeplan"
	"github.com/croessner/dkim2/internal/signature"
)

// FuzzSigningRequest exercises closed request construction, immutability, and redaction.
func FuzzSigningRequest(f *testing.F) {
	f.Add(false, []byte("handle"), []byte("nonce"), byte(0), []byte("signature"))
	f.Add(true, bytes.Repeat([]byte{0xff}, 257), bytes.Repeat([]byte{'n'}, 65), byte(7), []byte{})

	f.Fuzz(func(t *testing.T, ed25519Algorithm bool, handleSeed, nonceSeed []byte, flagBits byte, signatureSeed []byte) {
		if len(handleSeed) > maxPrivateKeyHandleIdentityBytes+1 {
			handleSeed = handleSeed[:maxPrivateKeyHandleIdentityBytes+1]
		}
		if len(nonceSeed) > DefaultLimits().MaxNonceBytes+1 {
			nonceSeed = nonceSeed[:DefaultLimits().MaxNonceBytes+1]
		}
		if len(signatureSeed) > DefaultLimits().MaxPrivateSignatureBytes+1 {
			signatureSeed = signatureSeed[:DefaultLimits().MaxPrivateSignatureBytes+1]
		}
		algorithm := AlgorithmRSASHA256
		if ed25519Algorithm {
			algorithm = AlgorithmEd25519SHA256
		}
		digest := sha256.Sum256(append(bytes.Clone(handleSeed), nonceSeed...))
		request, err := NewPrivateKeySignRequest(algorithm, digest)
		if err != nil || !request.Valid() || request.Algorithm() != algorithm || request.Digest() != digest {
			t.Fatalf("NewPrivateKeySignRequest() valid=%t algorithm=%q error=%v", request.Valid(), request.Algorithm(), err)
		}

		handleInput := bytes.Clone(handleSeed)
		handle, handleErr := NewPrivateKeyHandle(handleInput)
		if len(handleInput) == 0 || len(handleInput) > maxPrivateKeyHandleIdentityBytes {
			if handleErr == nil || handle.Valid() {
				t.Fatal("invalid handle input unexpectedly succeeded")
			}
		} else {
			if handleErr != nil || !handle.Valid() {
				t.Fatalf("valid handle rejected: %v", handleErr)
			}
			handleInput[0] ^= 0xff
			if !handle.Valid() {
				t.Fatal("caller mutation invalidated opaque handle")
			}
		}

		flags := make([]string, 0, 3)
		if flagBits&1 != 0 {
			flags = append(flags, signature.FlagDoNotModify)
		}
		if flagBits&2 != 0 {
			flags = append(flags, signature.FlagDoNotExplode)
		}
		if flagBits&4 != 0 {
			flags = append(flags, signature.FlagFeedback)
		}
		nonce := bytes.Clone(nonceSeed)
		if len(nonce) > DefaultLimits().MaxNonceBytes {
			nonce = nonce[:DefaultLimits().MaxNonceBytes]
		}
		const nonceAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
		for index := range nonce {
			nonce[index] = nonceAlphabet[int(nonce[index])%len(nonceAlphabet)]
		}
		metadata, metadataErr := NewSigningMetadata(nonce, nonce != nil, flags)
		if metadataErr != nil || !metadata.Valid() {
			t.Fatalf("NewSigningMetadata() error = %v", metadataErr)
		}
		gotNonce, present := metadata.Nonce()
		if present != (nonce != nil) || !bytes.Equal(gotNonce, nonce) ||
			!slices.Equal(metadata.RequestedFlags(), flags) {
			t.Fatal("metadata did not preserve the exact bounded request")
		}

		signatureInput := bytes.Clone(signatureSeed)
		result := NewPrivateKeySignResult(signatureInput)
		before := bytes.Clone(result.signature)
		if len(signatureInput) > 0 {
			signatureInput[0] ^= 0xff
		}
		if !bytes.Equal(before, result.signature) {
			t.Fatal("private result retained caller-owned signature storage")
		}
	})
}

// FuzzHashGate exercises originator protocol-field rejection and exact hash planning.
//
//nolint:gocyclo // The branches intentionally cover every closed hash-gate role and tamper state.
func FuzzHashGate(f *testing.F) {
	f.Add([]byte("unchanged"), byte(0))
	f.Add([]byte("changed"), byte(1))
	f.Add([]byte("tampered"), byte(2))
	f.Add(bytes.Repeat([]byte{'x'}, 4096), byte(1))

	f.Fuzz(func(t *testing.T, contentSeed []byte, mode byte) {
		if len(contentSeed) > 4096 {
			contentSeed = contentSeed[:4096]
		}
		fixture := newRevisionTestFixture(t, nil, false)
		coordinator, verifier := newTestHashPlanCoordinator(t, fixture)
		outcome, capability, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{
			Message: fixture.message, Envelope: fixture.envelope,
		})
		if err != nil || outcome.Status() != RevisionVerificationVerified || !capability.Valid() {
			t.Fatalf("VerifyForRevision() status=%q valid=%t error=%v", outcome.Status(), capability.Valid(), err)
		}
		message := fixture.message
		switch mode % 3 {
		case 1:
			body := append([]byte("fuzz-changed:"), fuzzSigningPlanASCII(contentSeed)...)
			raw := bytes.Replace(
				fixture.message.RawBytes(), []byte("current body\r\n"),
				append(body, '\r', '\n'), 1,
			)
			message = mustParseRevisionMessage(t, raw)
		case 2:
			base := fixture.message.RawBytes()
			duplicate := fixture.message.Headers().FieldsByName(instance.HeaderName)[0].OriginalBytes()
			headerBytes := fixture.message.Metadata().HeaderBytes
			raw := make([]byte, 0, len(base)+len(duplicate))
			raw = append(raw, base[:headerBytes]...)
			raw = append(raw, duplicate...)
			raw = append(raw, base[headerBytes:]...)
			message = mustParseRevisionMessage(t, raw)
		}
		ticket := testPlanTicket(t, message.RawBytes(), routeplan.PurposeRevision, capability)
		first, firstErr := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
			Capability: capability, Message: message, Ticket: ticket,
			LiteralPolicy: recipe.AllowLiterals,
		})
		if mode%3 == 2 {
			if firstErr == nil || first.Valid() {
				t.Fatal("tampered existing message unexpectedly produced a plan")
			}
			return
		}
		if firstErr != nil || !first.Valid() {
			t.Fatalf("PlanExisting() valid=%t error=%v", first.Valid(), firstErr)
		}
		if mode%3 == 0 {
			if first.Role() != RoleHashUnchangedForwarder || first.HasNewInstance() ||
				first.NewInstanceNumber() != 0 {
				t.Fatal("hash-equal gate did not select the no-instance forwarder role")
			}
		} else if first.Role() != RoleReviser || !first.HasNewInstance() ||
			first.NewInstanceNumber() != 2 || first.GenerationFacts().Outcome() != recipe.GenerationOutcomeRecipe {
			t.Fatal("hash-different gate did not select one recipe-backed revision instance")
		}

		canonicalizer, canonicalErr := canonical.NewCanonicalizer()
		headerResult, headerErr := canonicalizer.HeaderHashFromMessage(message)
		bodyResult, bodyErr := canonicalizer.BodyHashFromMessage(message)
		headerDigest, headerOK := headerResult.Digest()
		bodyDigest, bodyOK := bodyResult.Digest()
		hashes := first.CurrentHashes()
		plannedHeader := hashes.Header()
		plannedBody := hashes.Body()
		if canonicalErr != nil || headerErr != nil || bodyErr != nil || !headerOK || !bodyOK ||
			!bytes.Equal(plannedHeader[:], headerDigest.Bytes()) ||
			!bytes.Equal(plannedBody[:], bodyDigest.Bytes()) {
			t.Fatal("hash plan differs from independent canonical SHA-256 results")
		}
		if first.HasNewInstance() {
			rendered, parseErr := rawmsg.Parse(first.RenderedInstance())
			if parseErr != nil || rendered.Headers().Len() != 1 {
				t.Fatalf("rendered instance parse error = %v", parseErr)
			}
			parsed, parseErr := instance.Parse(rendered.Headers().Fields()[0])
			set, status := parsed.SHA256HashSet()
			headerHash, headerPresent := set.HeaderHash()
			bodyHash, bodyPresent := set.BodyHash()
			if parseErr != nil || status != instance.HashSelectionStatusSelected ||
				!headerPresent || !bodyPresent ||
				!bytes.Equal(headerHash.Decoded(), headerDigest.Bytes()) ||
				!bytes.Equal(bodyHash.Decoded(), bodyDigest.Bytes()) {
				t.Fatal("rendered revision instance differs from planned exact digests")
			}
		}
		second, secondErr := coordinator.PlanExisting(context.Background(), ExistingPlanRequest{
			Capability: capability, Message: message, Ticket: ticket,
			LiteralPolicy: recipe.AllowLiterals,
		})
		if secondErr != nil || !second.Valid() ||
			first.CurrentHashes() != second.CurrentHashes() ||
			!bytes.Equal(first.RenderedInstance(), second.RenderedInstance()) {
			t.Fatalf("repeated pure hash plan differs: error=%v", secondErr)
		}
	})
}

// fuzzSigningPlanASCII maps arbitrary input to nonempty RFC 5322 body-safe bytes.
func fuzzSigningPlanASCII(seed []byte) []byte {
	if len(seed) == 0 {
		return []byte("changed")
	}
	output := make([]byte, 0, len(seed)+len(seed)/72*2)
	for index, value := range seed {
		if index > 0 && index%72 == 0 {
			output = append(output, '\r', '\n')
		}
		output = append(output, 0x20+value%0x5f)
	}
	return output
}
