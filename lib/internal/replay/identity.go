package replay

import (
	"bytes"
	"fmt"
	"io"
)

const (
	// DraftIdentifier is the exact behavior baseline bound into replay identities.
	DraftIdentifier = "draft-ietf-dkim-dkim2-spec-04"
	// maxIdentityRecipients mirrors the authoritative signature parser hard limit.
	// Replay cannot import the protocol parser without reversing the package graph.
	maxIdentityRecipients = 2_000
)

const (
	identityRedactedText    = "replay_identity"
	identitySetRedactedText = "replay_identity_set"
)

// IdentitySource exposes only sealed fixed replay facts at the trusted root bridge.
type IdentitySource interface {
	Valid() bool
	Draft() string
	MessageDigest() ([32]byte, bool)
	SignatureInputDigest() ([32]byte, bool)
	RecipientCount() int
	RecipientDigest(int) ([32]byte, bool)
	Exploded() bool
}

// Identity is one immutable recipient-scoped authenticated replay identity.
type Identity struct {
	messageDigest           [32]byte
	signatureInputDigest    [32]byte
	recipientDigest         [32]byte
	hasMessageDigest        bool
	hasSignatureInputDigest bool
	hasRecipientDigest      bool
	draft                   uint8
}

// Valid reports whether the identity contains complete sealed baseline facts.
func (i Identity) Valid() bool {
	return i.draft == 1 && i.hasMessageDigest && i.hasSignatureInputDigest && i.hasRecipientDigest
}

// String returns a constant representation without authenticated digest bytes.
func (Identity) String() string { return identityRedactedText }

// GoString returns a constant representation without authenticated digest bytes.
func (Identity) GoString() string { return identityRedactedText }

// Format prevents every formatting verb from exposing authenticated digest bytes.
func (Identity) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, identityRedactedText)
}

// IdentitySet is an immutable sorted complete set of recipient-scoped identities.
type IdentitySet struct {
	identities []Identity
	exploded   bool
	valid      bool
}

// NewIdentitySet constructs identities from one sealed trusted-boundary source.
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
	message, messagePresent := source.MessageDigest()
	signatureInput, signaturePresent := source.SignatureInputDigest()
	count := source.RecipientCount()
	if !messagePresent || !signaturePresent || count <= 0 || count > maxIdentityRecipients {
		return IdentitySet{}, NewError(ErrorCodeInvalidRequest)
	}

	identities := make([]Identity, count)
	var previous [32]byte
	for index := range count {
		recipient, present := source.RecipientDigest(index)
		if !present {
			return IdentitySet{}, NewError(ErrorCodeInvalidRequest)
		}
		if index > 0 && bytes.Compare(previous[:], recipient[:]) >= 0 {
			return IdentitySet{}, NewError(ErrorCodeInvalidRequest)
		}
		identities[index] = Identity{
			messageDigest: message, signatureInputDigest: signatureInput,
			recipientDigest: recipient, hasMessageDigest: true,
			hasSignatureInputDigest: true, hasRecipientDigest: true, draft: 1,
		}
		previous = recipient
	}

	return IdentitySet{
		identities: identities,
		exploded:   source.Exploded(),
		valid:      true,
	}, nil
}

// Valid reports whether the set contains a complete sorted identity collection.
func (s IdentitySet) Valid() bool {
	if !s.valid || len(s.identities) == 0 || len(s.identities) > maxIdentityRecipients {
		return false
	}
	for index, identity := range s.identities {
		if !identity.Valid() {
			return false
		}
		if index > 0 && bytes.Compare(s.identities[index-1].recipientDigest[:], identity.recipientDigest[:]) >= 0 {
			return false
		}
	}
	return true
}

// Len returns the number of recipient-scoped identities in a valid set.
func (s IdentitySet) Len() int {
	if !s.Valid() {
		return 0
	}
	return len(s.identities)
}

// Identity returns one immutable identity by value.
func (s IdentitySet) Identity(index int) (Identity, error) {
	if !s.Valid() || index < 0 || index >= len(s.identities) {
		return Identity{}, NewError(ErrorCodeInvalidRequest)
	}
	return s.identities[index], nil
}

// Exploded returns the authenticated complete-chain OR fact for a valid set.
func (s IdentitySet) Exploded() bool { return s.Valid() && s.exploded }

// String returns a constant representation without authenticated digest bytes.
func (IdentitySet) String() string { return identitySetRedactedText }

// GoString returns a constant representation without authenticated digest bytes.
func (IdentitySet) GoString() string { return identitySetRedactedText }

// Format prevents every formatting verb from exposing authenticated digest bytes.
func (IdentitySet) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, identitySetRedactedText)
}

// nilIdentitySource reports nil and typed-nil trusted projection sources.
func nilIdentitySource(source IdentitySource) bool {
	return nilInterface(source)
}
