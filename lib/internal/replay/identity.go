package replay

import (
	"crypto/sha256"
	"fmt"
	"io"
)

const (
	// DraftIdentifier is the exact behavior baseline bound into replay identities.
	DraftIdentifier         = "draft-ietf-dkim-dkim2-spec-06"
	identityRedactedText    = "replay_identity"
	identitySetRedactedText = "replay_identity_set"
)

// IdentitySource exposes only sealed fixed replay facts at the trusted root bridge.
type IdentitySource interface {
	Valid() bool
	Draft() string
}

type originIdentitySource interface {
	OriginReplayDigest() ([32]byte, bool)
	Exploded() bool
}

type legacyIdentitySource interface {
	MessageDigest() ([32]byte, bool)
	SignatureInputDigest() ([32]byte, bool)
	RecipientCount() int
	RecipientDigest(int) ([32]byte, bool)
	Exploded() bool
}

// Identity is one immutable message-wide authenticated replay identity.
type Identity struct{ state *identityState }

// identityState owns immutable authenticated origin material.
type identityState struct {
	originDigest    [32]byte
	hasOriginDigest bool
	recipientDigest [32]byte
	draft           uint8
}

// Valid reports whether the identity contains complete sealed baseline facts.
func (i Identity) Valid() bool {
	return i.state != nil && i.state.draft == 2 && i.state.hasOriginDigest
}

// String returns a constant representation without authenticated digest bytes.
func (Identity) String() string { return identityRedactedText }

// GoString returns a constant representation without authenticated digest bytes.
func (Identity) GoString() string { return identityRedactedText }

// Format prevents every formatting verb from exposing authenticated digest bytes.
func (Identity) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, identityRedactedText) }

// IdentitySet is an immutable compatibility wrapper around the single message identity.
//
// Deprecated: Draft-06 replay equality is message-wide. New code should use Identity.
type IdentitySet struct{ state *identitySetState }

// identitySetState owns one immutable message-wide identity and authenticated flag.
type identitySetState struct {
	identity   Identity
	identities []Identity
	exploded   bool
	valid      bool
}

// NewIdentitySet constructs one identity from a sealed trusted-boundary source.
func NewIdentitySet(source IdentitySource) (set IdentitySet, resultErr error) {
	defer func() {
		if recover() != nil {
			set = IdentitySet{}
			resultErr = NewError(ErrorCodeInternalInvariant)
		}
	}()
	if nilIdentitySource(source) || !source.Valid() || source.Draft() != DraftIdentifier {
		return IdentitySet{}, NewError(ErrorCodeInvalidRequest)
	}
	if origin, ok := source.(originIdentitySource); ok {
		digest, present := origin.OriginReplayDigest()
		if !present {
			return IdentitySet{}, NewError(ErrorCodeInvalidRequest)
		}
		identity := Identity{state: &identityState{originDigest: digest, hasOriginDigest: true, draft: 2}}
		return IdentitySet{state: &identitySetState{identity: identity, identities: []Identity{identity}, exploded: origin.Exploded(), valid: true}}, nil
	}
	legacy, ok := source.(legacyIdentitySource)
	if !ok {
		return IdentitySet{}, NewError(ErrorCodeInvalidRequest)
	}
	message, messageOK := legacy.MessageDigest()
	signature, signatureOK := legacy.SignatureInputDigest()
	if !messageOK || !signatureOK || legacy.RecipientCount() <= 0 {
		return IdentitySet{}, NewError(ErrorCodeInvalidRequest)
	}
	identities := make([]Identity, legacy.RecipientCount())
	var previous [32]byte
	for index := range identities {
		recipient, present := legacy.RecipientDigest(index)
		if !present || index > 0 && string(previous[:]) >= string(recipient[:]) {
			return IdentitySet{}, NewError(ErrorCodeInvalidRequest)
		}
		frame := make([]byte, 0, 96)
		frame = append(frame, message[:]...)
		frame = append(frame, signature[:]...)
		frame = append(frame, recipient[:]...)
		digest := sha256.Sum256(frame)
		identities[index] = Identity{state: &identityState{originDigest: digest, hasOriginDigest: true, recipientDigest: recipient, draft: 2}}
		previous = recipient
	}
	return IdentitySet{state: &identitySetState{identity: identities[0], identities: identities, exploded: legacy.Exploded(), valid: true}}, nil
}

// Valid reports whether the set contains the single message-wide identity.
func (s IdentitySet) Valid() bool {
	if s.state == nil || !s.state.valid || len(s.state.identities) == 0 {
		return false
	}
	for _, identity := range s.state.identities {
		if !identity.Valid() {
			return false
		}
	}
	return true
}

// Len returns one for a valid Draft-06 message identity.
func (s IdentitySet) Len() int {
	if !s.Valid() {
		return 0
	}
	return len(s.state.identities)
}

// Identity returns the immutable message-wide identity at index zero.
func (s IdentitySet) Identity(index int) (Identity, error) {
	if !s.Valid() || index < 0 || index >= len(s.state.identities) {
		return Identity{}, NewError(ErrorCodeInvalidRequest)
	}
	state := *s.state.identities[index].state
	return Identity{state: &state}, nil
}

// Exploded returns the authenticated complete-chain OR fact for a valid set.
func (s IdentitySet) Exploded() bool { return s.Valid() && s.state.exploded }

// String returns a constant representation without authenticated digest bytes.
func (IdentitySet) String() string { return identitySetRedactedText }

// GoString returns a constant representation without authenticated digest bytes.
func (IdentitySet) GoString() string { return identitySetRedactedText }

// Format prevents every formatting verb from exposing authenticated digest bytes.
func (IdentitySet) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, identitySetRedactedText)
}

// nilIdentitySource reports nil and typed-nil trusted projection sources.
func nilIdentitySource(source IdentitySource) bool { return nilInterface(source) }
