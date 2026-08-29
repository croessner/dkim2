package service

import (
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/replay"
	"github.com/croessner/dkim2/internal/verify"
)

const serviceReplayProjectionRedactedText = "service.ReplayProjection{redacted}"

// ReplayProjection carries sealed replay facts across the trusted root boundary.
type ReplayProjection struct{ state *replayProjectionState }

// replayProjectionState owns one fixed-size message-wide identity fact.
type replayProjectionState struct {
	draft           string
	originDigest    [32]byte
	hasOriginDigest bool
	exploded        bool
	sealed          bool
}

// Valid reports whether the projection contains complete baseline facts.
func (p ReplayProjection) Valid() bool {
	return p.state != nil && p.state.sealed && p.state.draft == replay.DraftIdentifier && p.state.hasOriginDigest
}

// Draft returns the exact bounded behavior baseline.
func (p ReplayProjection) Draft() string {
	if !p.Valid() {
		return ""
	}
	return p.state.draft
}

// OriginReplayDigest returns the message-wide origin digest by value.
func (p ReplayProjection) OriginReplayDigest() ([32]byte, bool) {
	if !p.Valid() {
		return [32]byte{}, false
	}
	return p.state.originDigest, true
}

// Exploded returns the authenticated complete-chain OR fact.
func (p ReplayProjection) Exploded() bool { return p.Valid() && p.state.exploded }

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
	if p.state == nil {
		return ReplayProjection{}
	}
	state := *p.state
	return ReplayProjection{state: &state}
}

// mapReplayProjection clones only one complete verify-owned sealed projection.
func mapReplayProjection(source verify.ReplayProjection) (ReplayProjection, bool) {
	if !source.Valid() || source.Draft() != replay.DraftIdentifier {
		return ReplayProjection{}, false
	}
	digest, present := source.OriginReplayDigest()
	if !present {
		return ReplayProjection{}, false
	}
	projection := ReplayProjection{state: &replayProjectionState{draft: replay.DraftIdentifier, originDigest: digest, hasOriginDigest: true, exploded: source.Exploded(), sealed: true}}
	return projection, projection.Valid()
}
