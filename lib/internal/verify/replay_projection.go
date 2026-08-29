package verify

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/replay"
	"github.com/croessner/dkim2/internal/signature"
)

const (
	originReplayDomainLabel      = "dkim2-replay-origin-v1"
	originReplayAlgorithm        = "dkim2-replay-origin-sha256-v1"
	replayProjectionRedactedText = "verify.ReplayProjection{redacted}"
)

// ReplayProjection carries sealed aggregate-chain-PASS replay facts.
type ReplayProjection struct {
	draft           string
	originDigest    [32]byte
	hasOriginDigest bool
	exploded        bool
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
func buildReplayProjection(input verificationInput, targetSignature signature.Signature, targetInstance instance.MessageInstance, hashes hashCheckResults, signatureDigest []byte, result Result) (ReplayProjection, bool) {
	target := result.Target()
	if !aggregateCurrentPass(result) || target.Sequence != highestSignatureSequence(input.signatures) ||
		target.InstanceNumber != highestInstanceNumber(input.instances) || targetSignature.Sequence() != target.Sequence ||
		targetSignature.InstanceNumber() != target.InstanceNumber || targetInstance.Number() != target.InstanceNumber ||
		!hashes.hasLocalHeaderSHA256 || !hashes.hasLocalBodySHA256 || len(signatureDigest) != sha256.Size ||
		!resultHasEnvelopePass(result) || resultHasTestingOnlyPass(result) || len(input.signatures) != int(target.Sequence) {
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
	digest, ok := originReplayDigest(input.request.Message)
	if !ok {
		return ReplayProjection{}, false
	}
	return newReplayProjection(digest, exploded), true
}

// newReplayProjection seals a verifier-computed fixed-size origin fact.
func newReplayProjection(digest [32]byte, exploded bool) ReplayProjection {
	return ReplayProjection{draft: replay.DraftIdentifier, originDigest: digest, hasOriginDigest: true, exploded: exploded, sealed: true}
}

// originReplayDigest hashes the exact Draft-06 origin header and body hash inputs.
func originReplayDigest(message rawmsg.Message) ([32]byte, bool) {
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		return [32]byte{}, false
	}
	header, err := canonicalizer.HeaderHashInputFromMessage(message)
	if err != nil {
		return [32]byte{}, false
	}
	body, err := canonicalizer.BodyHashInputFromMessage(message)
	if err != nil {
		return [32]byte{}, false
	}
	frame := originReplayFrame(header.Bytes(), body.Bytes())
	return sha256.Sum256(frame), true
}

// originReplayFrame builds the frozen length-delimited origin input.
func originReplayFrame(header, body []byte) []byte {
	frame := make([]byte, 0, len(originReplayDomainLabel)+64+len(header)+len(body))
	frame = append(frame, originReplayDomainLabel...)
	frame = append(frame, 0, 1, 1)
	frame = appendUint32ReplayField(frame, []byte(replay.DraftIdentifier))
	frame = append(frame, 2)
	frame = appendUint64ReplayField(frame, header)
	frame = append(frame, 3)
	return appendUint64ReplayField(frame, body)
}

// appendUint32ReplayField appends a network-order 32-bit byte length and value.
func appendUint32ReplayField(output, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	output = append(output, length[:]...)
	return append(output, value...)
}

// appendUint64ReplayField appends a network-order 64-bit byte length and value.
func appendUint64ReplayField(output, value []byte) []byte {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
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

// resultHasTestingOnlyPass reports whether every authoritative passing set is testing-declared.
func resultHasTestingOnlyPass(result Result) bool {
	passing := 0
	for _, set := range result.signatureSets {
		if set.Status == SignatureSetStatusPass {
			passing++
			if !set.KeyPolicy.TestingDeclared {
				return false
			}
		}
	}
	return passing > 0
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
