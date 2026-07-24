package service

import (
	"bytes"
	"fmt"
	"io"
	"slices"

	"github.com/croessner/dkim2/internal/replay"
	"github.com/croessner/dkim2/internal/verify"
)

const serviceReplayProjectionRedactedText = "service.ReplayProjection{redacted}"

// ReplayProjection carries sealed replay facts across the trusted root boundary.
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

// MessageDigest returns the selected matched Message-Instance header hash by value.
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
func (ReplayProjection) String() string { return serviceReplayProjectionRedactedText }

// GoString returns a constant representation without authenticated digest bytes.
func (ReplayProjection) GoString() string { return serviceReplayProjectionRedactedText }

// Format prevents every formatting verb from exposing authenticated digest bytes.
func (ReplayProjection) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, serviceReplayProjectionRedactedText)
}

// clone returns an independent trusted-boundary projection.
func (p ReplayProjection) clone() ReplayProjection {
	p.recipientDigests = slices.Clone(p.recipientDigests)
	return p
}

// mapReplayProjection clones only one complete verify-owned sealed projection.
func mapReplayProjection(source verify.ReplayProjection) (ReplayProjection, bool) {
	if !source.Valid() || source.Draft() != replay.DraftIdentifier ||
		source.RecipientCount() <= 0 {
		return ReplayProjection{}, false
	}
	message, messagePresent := source.MessageDigest()
	signatureInput, signaturePresent := source.SignatureInputDigest()
	if !messagePresent || !signaturePresent {
		return ReplayProjection{}, false
	}
	recipients := make([][32]byte, source.RecipientCount())
	for index := range recipients {
		digest, present := source.RecipientDigest(index)
		if !present {
			return ReplayProjection{}, false
		}
		recipients[index] = digest
	}
	projection := ReplayProjection{
		draft:                   replay.DraftIdentifier,
		messageDigest:           message,
		signatureInputDigest:    signatureInput,
		recipientDigests:        recipients,
		hasMessageDigest:        true,
		hasSignatureInputDigest: true,
		exploded:                source.Exploded(),
		sealed:                  true,
	}
	return projection, projection.Valid()
}
