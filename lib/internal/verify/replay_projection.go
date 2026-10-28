package verify

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/replay"
	"github.com/croessner/dkim2/internal/signature"
)

const (
	originReplayDomainLabel      = "dkim2-replay-origin-declaration-v1"
	originReplayAlgorithm        = "dkim2-replay-origin-declaration-sha256-v1"
	replayProjectionRedactedText = "verify.ReplayProjection{redacted}"
)

// ReplayProjection carries sealed aggregate-chain-PASS replay facts. The origin
// digest is the m=1 hash declaration identity: SHA-256 is preferred, so a
// SHA-512-only origin never groups with a mixed-algorithm origin.
type ReplayProjection struct {
	draft           string
	originDigest    [32]byte
	hasOriginDigest bool
	exploded        bool
	eligible        bool
	sealed          bool
}

// Valid reports whether the projection contains complete baseline facts.
func (p ReplayProjection) Valid() bool {
	return p.sealed && p.draft == replay.DraftIdentifier && p.hasOriginDigest
}

// Draft returns the exact bounded behavior baseline.
func (p ReplayProjection) Draft() string {
	if !p.Valid() {
		return ""
	}
	return p.draft
}

// OriginReplayDigest returns the locally computed message-wide origin digest by value.
func (p ReplayProjection) OriginReplayDigest() ([32]byte, bool) {
	return p.originDigest, p.Valid() && p.hasOriginDigest
}

// OriginReplayAlgorithm returns the frozen local equality algorithm.
func (p ReplayProjection) OriginReplayAlgorithm() string {
	if !p.Valid() {
		return ""
	}
	return originReplayAlgorithm
}

// Exploded returns the authenticated complete-chain OR fact.
func (p ReplayProjection) Exploded() bool { return p.Valid() && p.exploded }

// ReplayEligible reports whether local replay policy applies. Draft-08
// Section 15.1 concerns copies re-sent by an intermediary, so a message that
// carries only the originator's i=1 signature is not counted; the identity
// itself stays available for DSN propagation.
func (p ReplayProjection) ReplayEligible() bool { return p.Valid() && p.eligible }

// String returns a constant representation without authenticated digest bytes.
func (ReplayProjection) String() string { return replayProjectionRedactedText }

// GoString returns a constant representation without authenticated digest bytes.
func (ReplayProjection) GoString() string { return replayProjectionRedactedText }

// Format prevents every formatting verb from exposing authenticated digest bytes.
func (ReplayProjection) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, replayProjectionRedactedText)
}

// clone returns an independent trusted-boundary projection.
func (p ReplayProjection) clone() ReplayProjection { return p }

// buildReplayProjection seals exact origin intermediates only after aggregate current PASS.
func buildReplayProjection(input verificationInput, targetSignature signature.Signature, targetInstance instance.MessageInstance, result Result) (ReplayProjection, bool) {
	target := result.Target()
	if !aggregateCurrentPass(result) || target.Sequence != highestSignatureSequence(input.signatures) ||
		target.InstanceNumber != highestInstanceNumber(input.instances) || targetSignature.Sequence() != target.Sequence ||
		targetSignature.InstanceNumber() != target.InstanceNumber || targetInstance.Number() != target.InstanceNumber ||
		!resultHasEnvelopePass(result) || len(input.signatures) != int(target.Sequence) {
		return ReplayProjection{}, false
	}
	exploded, complete := authenticatedExploded(input.signatures, target.Sequence)
	if !complete {
		return ReplayProjection{}, false
	}
	// A current projection is authoritative for replay only when it is already m=1.
	if target.InstanceNumber != 1 {
		return ReplayProjection{}, false
	}
	digest, ok := originReplayDigest(targetInstance)
	if !ok {
		return ReplayProjection{}, false
	}
	return newReplayProjection(digest, exploded, len(input.signatures) > 1), true
}

// newReplayProjection seals a verifier-computed fixed-size origin fact.
// eligible is true only when more than one DKIM2-Signature authenticated the
// message, that is, when at least one intermediary handled it.
func newReplayProjection(digest [32]byte, exploded, eligible bool) ReplayProjection {
	return ReplayProjection{draft: replay.DraftIdentifier, originDigest: digest, hasOriginDigest: true, exploded: exploded, eligible: eligible, sealed: true}
}

// originReplayDigest derives the message-wide replay identity from the hash
// declarations of the authenticated m=1 Message-Instance. Every copy of one
// original carries byte-identical m=1 declarations, so equality needs neither
// the reconstructed origin bytes nor an available body (a "b":null Recipe).
// SHA-256 is preferred and SHA-512 is used only when no SHA-256 tuple exists,
// so a SHA-512-only origin never groups with a mixed-algorithm origin. The
// caller must pass the m=1 instance proven by verification.
func originReplayDigest(origin instance.MessageInstance) ([32]byte, bool) {
	if origin.Number() != 1 {
		return [32]byte{}, false
	}
	hashSets, status := origin.SupportedHashSets()
	if status != instance.HashSelectionStatusSelected {
		return [32]byte{}, false
	}
	selected, found := preferredReplayHashSet(hashSets)
	if !found {
		return [32]byte{}, false
	}
	header, headerOK := selected.HeaderHash()
	body, bodyOK := selected.BodyHash()
	if !headerOK || !bodyOK || header.DecodedLen() == 0 || body.DecodedLen() == 0 {
		return [32]byte{}, false
	}
	// Decoded digests make the identity independent of base64 folding whitespace.
	return sha256.Sum256(originReplayFrame(selected.Name(), header.Decoded(), body.Decoded())), true
}

// preferredReplayHashSet selects the SHA-256 tuple, else the SHA-512 tuple.
func preferredReplayHashSet(hashSets []instance.HashSet) (instance.HashSet, bool) {
	for _, preferred := range []string{instance.HashAlgorithmSHA256, instance.HashAlgorithmSHA512} {
		for _, candidate := range hashSets {
			if candidate.Name() == preferred {
				return candidate, true
			}
		}
	}
	return instance.HashSet{}, false
}

// originReplayFrame builds the frozen length-delimited declaration input.
func originReplayFrame(algorithm string, header, body []byte) []byte {
	frame := make([]byte, 0, len(originReplayDomainLabel)+64+len(algorithm)+len(header)+len(body))
	frame = append(frame, originReplayDomainLabel...)
	frame = append(frame, 0, 1, 1)
	frame = appendUint32ReplayField(frame, []byte(replay.DraftIdentifier))
	frame = append(frame, 2)
	frame = appendUint32ReplayField(frame, []byte(algorithm))
	frame = append(frame, 3)
	frame = appendUint32ReplayField(frame, header)
	frame = append(frame, 4)
	return appendUint32ReplayField(frame, body)
}

// appendUint32ReplayField appends a network-order 32-bit byte length and value.
func appendUint32ReplayField(output, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	output = append(output, length[:]...)
	return append(output, value...)
}

// resultHasEnvelopePass proves the exact current SMTP envelope check succeeded.
func resultHasEnvelopePass(result Result) bool {
	count := 0
	for _, check := range result.checks {
		if check.Kind == CheckKindEnvelope {
			count++
			if check.Status != CheckStatusPass || check.EnvelopeStatus != EnvelopeStatusPass {
				return false
			}
		}
	}
	return count == 1
}

// authenticatedExploded ORs the complete signature chain covered by the highest input.
func authenticatedExploded(signatures []signature.Signature, highest uint64) (bool, bool) {
	if highest == 0 || len(signatures) != int(highest) || signature.ValidateSequence(signatures) != nil {
		return false, false
	}
	exploded := false
	for _, parsed := range signatures {
		if parsed.Sequence() == 0 || parsed.Sequence() > highest {
			return false, false
		}
		exploded = exploded || parsed.Flags().HasKnown(signature.FlagExploded)
	}
	return exploded, true
}
