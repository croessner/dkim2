package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"sort"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/replay"
	"github.com/croessner/dkim2/internal/signature"
)

const (
	recipientScopeLabel          = "dkim2-replay-recipient-v1"
	recipientScopeRedactedText   = "verify.recipientScope{redacted}"
	replayProjectionRedactedText = "verify.ReplayProjection{redacted}"
)

// ReplayProjection carries sealed aggregate-current-PASS replay facts.
type ReplayProjection struct {
	draft                   string
	messageDigest           [32]byte
	signatureInputDigest    [32]byte
	recipientDigests        [][32]byte
	hasMessageDigest        bool
	hasSignatureInputDigest bool
	exploded                bool
	sealed                  bool
}

type recipientScope struct {
	canonical string
	digest    [32]byte
	valid     bool
}

// String returns a constant representation without recipient or digest bytes.
func (recipientScope) String() string { return recipientScopeRedactedText }

// GoString returns a constant representation without recipient or digest bytes.
func (recipientScope) GoString() string { return recipientScopeRedactedText }

// Format prevents formatting from traversing recipient or digest bytes.
func (recipientScope) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, recipientScopeRedactedText)
}

// Valid reports whether the projection contains complete baseline facts.
func (p ReplayProjection) Valid() bool {
	if !p.sealed || p.draft != replay.DraftIdentifier || !p.hasMessageDigest ||
		!p.hasSignatureInputDigest || len(p.recipientDigests) == 0 {
		return false
	}
	for index, digest := range p.recipientDigests {
		if index > 0 && bytes.Compare(p.recipientDigests[index-1][:], digest[:]) >= 0 {
			return false
		}
	}
	return true
}

// Draft returns the exact bounded behavior baseline.
func (p ReplayProjection) Draft() string {
	if !p.Valid() {
		return ""
	}
	return p.draft
}

// MessageDigest returns the locally computed canonical SHA-256 header digest by value.
func (p ReplayProjection) MessageDigest() ([32]byte, bool) {
	return p.messageDigest, p.Valid() && p.hasMessageDigest
}

// SignatureInputDigest returns the highest canonical signature-input digest by value.
func (p ReplayProjection) SignatureInputDigest() ([32]byte, bool) {
	return p.signatureInputDigest, p.Valid() && p.hasSignatureInputDigest
}

// RecipientCount returns the complete unique current-recipient count.
func (p ReplayProjection) RecipientCount() int {
	if !p.Valid() {
		return 0
	}
	return len(p.recipientDigests)
}

// RecipientDigest returns one sorted recipient-scope digest by value.
func (p ReplayProjection) RecipientDigest(index int) ([32]byte, bool) {
	if !p.Valid() || index < 0 || index >= len(p.recipientDigests) {
		return [32]byte{}, false
	}
	return p.recipientDigests[index], true
}

// Exploded returns the authenticated complete-current-chain OR fact.
func (p ReplayProjection) Exploded() bool { return p.Valid() && p.exploded }

// String returns a constant representation without authenticated digest bytes.
func (ReplayProjection) String() string { return replayProjectionRedactedText }

// GoString returns a constant representation without authenticated digest bytes.
func (ReplayProjection) GoString() string { return replayProjectionRedactedText }

// Format prevents every formatting verb from exposing authenticated digest bytes.
func (ReplayProjection) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, replayProjectionRedactedText)
}

// clone returns an independent trusted-boundary projection.
func (p ReplayProjection) clone() ReplayProjection {
	p.recipientDigests = slices.Clone(p.recipientDigests)
	return p
}

// buildReplayProjection seals exact intermediates only after aggregate current PASS.
func buildReplayProjection(
	input verificationInput,
	targetSignature signature.Signature,
	targetInstance instance.MessageInstance,
	hashes hashCheckResults,
	signatureDigest []byte,
	result Result,
) (ReplayProjection, bool) {
	target := result.Target()
	if !aggregateCurrentPass(result) || target.Sequence != highestSignatureSequence(input.signatures) ||
		target.InstanceNumber != highestInstanceNumber(input.instances) ||
		targetSignature.Sequence() != target.Sequence ||
		targetSignature.InstanceNumber() != target.InstanceNumber ||
		targetInstance.Number() != target.InstanceNumber ||
		!hashes.hasLocalHeaderSHA256 || len(signatureDigest) != sha256.Size ||
		!resultHasEnvelopePass(result) || resultHasTestingOnlyPass(result) ||
		len(input.signatures) != int(target.Sequence) {
		return ReplayProjection{}, false
	}

	scopes := make(map[string]recipientScope, input.request.Envelope.RecipientCount())
	for _, path := range input.request.Envelope.ForwardPaths() {
		if !signature.ValidEnvelopePath(path, false) {
			return ReplayProjection{}, false
		}
		scope, err := recipientScopeFromValidatedPath(path)
		if err != nil || !scope.valid {
			return ReplayProjection{}, false
		}
		scopes[scope.canonical] = scope
	}
	if len(scopes) == 0 {
		return ReplayProjection{}, false
	}

	recipients := make([][32]byte, 0, len(scopes))
	for _, scope := range scopes {
		recipients = append(recipients, scope.digest)
	}
	sort.Slice(recipients, func(left int, right int) bool {
		return bytes.Compare(recipients[left][:], recipients[right][:]) < 0
	})
	for index := 1; index < len(recipients); index++ {
		if recipients[index-1] == recipients[index] {
			return ReplayProjection{}, false
		}
	}

	var canonicalSignatureDigest [32]byte
	copy(canonicalSignatureDigest[:], signatureDigest)
	exploded, complete := authenticatedExploded(input.signatures, target.Sequence)
	if !complete {
		return ReplayProjection{}, false
	}
	return ReplayProjection{
		draft:                   replay.DraftIdentifier,
		messageDigest:           hashes.localHeaderSHA256,
		signatureInputDigest:    canonicalSignatureDigest,
		recipientDigests:        recipients,
		hasMessageDigest:        true,
		hasSignatureInputDigest: true,
		exploded:                exploded,
		sealed:                  true,
	}, true
}

// recipientScopeFromValidatedPath canonicalizes one already-owner-validated bracketed path.
func recipientScopeFromValidatedPath(path []byte) (recipientScope, error) {
	canonicalPath, valid := signature.CanonicalEnvelopePath(path, false)
	if !valid {
		return recipientScope{}, malformedStateError(CheckKindEnvelope, Target{}, nil)
	}
	canonical := canonicalPath[1 : len(canonicalPath)-1]

	frame := make([]byte, 0, len(recipientScopeLabel)+1+4+len(canonical))
	frame = append(frame, recipientScopeLabel...)
	frame = append(frame, 0)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(canonical)))
	frame = append(frame, length[:]...)
	frame = append(frame, canonical...)
	return recipientScope{
		canonical: string(canonical),
		digest:    sha256.Sum256(frame),
		valid:     true,
	}, nil
}

// resultHasEnvelopePass proves the exact current SMTP envelope check succeeded.
func resultHasEnvelopePass(result Result) bool {
	count := 0
	for _, check := range result.checks {
		if check.Kind != CheckKindEnvelope {
			continue
		}
		count++
		if check.Status != CheckStatusPass || check.EnvelopeStatus != EnvelopeStatusPass {
			return false
		}
	}
	return count == 1
}

// resultHasTestingOnlyPass reports whether every authoritative passing set is testing-declared.
func resultHasTestingOnlyPass(result Result) bool {
	passing := 0
	for _, set := range result.signatureSets {
		if set.Status != SignatureSetStatusPass {
			continue
		}
		passing++
		if !set.KeyPolicy.TestingDeclared {
			return false
		}
	}
	return passing > 0
}

// authenticatedExploded ORs the complete current signature chain covered by the highest input.
func authenticatedExploded(signatures []signature.Signature, highest uint64) (bool, bool) {
	if highest == 0 || len(signatures) != int(highest) ||
		signature.ValidateSequence(signatures) != nil {
		return false, false
	}
	exploded := false
	for _, parsed := range signatures {
		if parsed.Sequence() == 0 || parsed.Sequence() > highest {
			return false, false
		}
		if parsed.Flags().HasKnown(signature.FlagExploded) {
			exploded = true
		}
	}
	return exploded, true
}
