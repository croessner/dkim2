package dkim2

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/provider"
	"github.com/croessner/dkim2/internal/signing"
)

// SigningAuthorizationPurpose identifies one closed authorization decision.
type SigningAuthorizationPurpose string

const (
	// SigningAuthorizationPolicy authorizes exact modification and route facts.
	SigningAuthorizationPolicy SigningAuthorizationPurpose = "policy"
	// SigningAuthorizationFeedbackRelay authorizes inherited feedback relay.
	SigningAuthorizationFeedbackRelay SigningAuthorizationPurpose = "feedback_relay"
	// SigningAuthorizationRecipientDisclosure authorizes exact multi-recipient disclosure.
	SigningAuthorizationRecipientDisclosure SigningAuthorizationPurpose = "recipient_disclosure"
	// SigningAuthorizationReceiveNextDomain authorizes receipt from one inherited nd= hop.
	SigningAuthorizationReceiveNextDomain SigningAuthorizationPurpose = "receive_terminal_next_domain"
	// SigningAuthorizationSendNextDomain authorizes one exact terminal nd= route.
	SigningAuthorizationSendNextDomain SigningAuthorizationPurpose = "send_terminal_next_domain"
)

// Known reports whether the purpose belongs to the closed signing vocabulary.
func (p SigningAuthorizationPurpose) Known() bool {
	return p == SigningAuthorizationPolicy ||
		p == SigningAuthorizationFeedbackRelay ||
		p == SigningAuthorizationRecipientDisclosure ||
		p == SigningAuthorizationReceiveNextDomain ||
		p == SigningAuthorizationSendNextDomain
}

// SigningAuthorizationStatus identifies one closed declared authorization result.
type SigningAuthorizationStatus string

const (
	// SigningAuthorizationAuthorized approves the exact supplied query.
	SigningAuthorizationAuthorized SigningAuthorizationStatus = "authorized"
	// SigningAuthorizationDenied denies the exact supplied query.
	SigningAuthorizationDenied SigningAuthorizationStatus = "denied"
)

// Known reports whether status belongs to the closed authorization vocabulary.
func (s SigningAuthorizationStatus) Known() bool {
	return s == SigningAuthorizationAuthorized || s == SigningAuthorizationDenied
}

// SigningRestriction identifies one closed signing output restriction.
type SigningRestriction string

const (
	// SigningRestrictionUnrestricted permits ordinary message release.
	SigningRestrictionUnrestricted SigningRestriction = "unrestricted"
	// SigningRestrictionLocalOnly prevents generic message-byte release.
	SigningRestrictionLocalOnly SigningRestriction = "local_only"
	// SigningRestrictionOutOfBandAcceptance requires exact OOB-bound release.
	SigningRestrictionOutOfBandAcceptance SigningRestriction = "requires_out_of_band_acceptance"
)

// Known reports whether restriction belongs to the closed signing vocabulary.
func (r SigningRestriction) Known() bool {
	return r == SigningRestrictionUnrestricted || r == SigningRestrictionLocalOnly ||
		r == SigningRestrictionOutOfBandAcceptance
}

// SigningOutOfBandFacts exposes exact values only across the trusted authorizer boundary.
type SigningOutOfBandFacts struct {
	value signing.OutOfBandFacts
	valid bool
}

// SigningPredecessorKind identifies the authenticated predecessor envelope form.
type SigningPredecessorKind string

const (
	// SigningPredecessorOrdinary identifies an ordinary mf=/rt= predecessor.
	SigningPredecessorOrdinary SigningPredecessorKind = "ordinary"
	// SigningPredecessorNextDomain identifies a terminal nd= predecessor.
	SigningPredecessorNextDomain SigningPredecessorKind = "next_domain"
)

// Known reports whether the predecessor kind belongs to the closed signing vocabulary.
func (k SigningPredecessorKind) Known() bool {
	return k == SigningPredecessorOrdinary || k == SigningPredecessorNextDomain
}

// Valid reports whether the facts form one exact receive or send authorization.
func (f SigningOutOfBandFacts) Valid() bool { return f.valid && f.value.Valid() }

// PredecessorKind returns the authenticated predecessor envelope form.
func (f SigningOutOfBandFacts) PredecessorKind() SigningPredecessorKind {
	if !f.Valid() {
		return ""
	}
	return SigningPredecessorKind(f.value.PredecessorKind())
}

// PredecessorDomain returns the authenticated canonical predecessor domain.
func (f SigningOutOfBandFacts) PredecessorDomain() string {
	if !f.Valid() {
		return ""
	}
	return f.value.PredecessorDomain()
}

// ProfileDomain returns the exact canonical signing domain.
func (f SigningOutOfBandFacts) ProfileDomain() string {
	if !f.Valid() {
		return ""
	}
	return f.value.ProfileDomain()
}

// ProposedNextDomain returns the terminal nd= value or empty for receive authorization.
func (f SigningOutOfBandFacts) ProposedNextDomain() string {
	if !f.Valid() {
		return ""
	}
	return f.value.ProposedNextDomain()
}

// ReversePath returns detached purpose-bound exact SMTP reverse-path evidence.
func (f SigningOutOfBandFacts) ReversePath() []byte {
	if !f.Valid() {
		return nil
	}
	return f.value.ReversePath()
}

// ForwardPaths returns detached purpose-bound exact SMTP recipient evidence.
func (f SigningOutOfBandFacts) ForwardPaths() [][]byte {
	if !f.Valid() {
		return nil
	}
	return f.value.ForwardPaths()
}

// RouteScope returns the detached exact trusted route-scope handle.
func (f SigningOutOfBandFacts) RouteScope() []byte {
	if !f.Valid() {
		return nil
	}
	return f.value.Route()
}

// ReceiverBinding returns the detached exact receiver-transaction evidence.
func (f SigningOutOfBandFacts) ReceiverBinding() []byte {
	if !f.Valid() {
		return nil
	}
	return f.value.ReceiverBinding()
}

// String returns a constant secret-safe OOB facts summary.
func (f SigningOutOfBandFacts) String() string { return "dkim2.SigningOutOfBandFacts{redacted}" }

// GoString returns the constant secret-safe OOB facts Go representation.
func (f SigningOutOfBandFacts) GoString() string { return f.String() }

// Format routes every OOB facts formatting form through the redacted summary.
func (f SigningOutOfBandFacts) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, f.String())
}

// SigningModificationFacts contains only bounded authenticated modification facts.
type SigningModificationFacts struct {
	bodyChanged            bool
	existingHeadersChanged bool
	valid                  bool
}

// BodyChanged reports whether the authoritative body hash changed.
func (f SigningModificationFacts) BodyChanged() bool { return f.valid && f.bodyChanged }

// ExistingHeadersChanged reports whether inherited non-protocol headers changed.
func (f SigningModificationFacts) ExistingHeadersChanged() bool {
	return f.valid && f.existingHeadersChanged
}

// Valid reports whether the facts came from a sealed signing query.
func (f SigningModificationFacts) Valid() bool { return f.valid }

// String returns a constant secret-safe facts summary.
func (f SigningModificationFacts) String() string {
	return "dkim2.SigningModificationFacts{redacted}"
}

// GoString returns the constant secret-safe facts Go representation.
func (f SigningModificationFacts) GoString() string { return f.String() }

// Format routes every facts formatting form through the redacted summary.
func (f SigningModificationFacts) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, f.String())
}

// SigningAuthorizationQuery carries exact bounded authorization evidence.
type SigningAuthorizationQuery struct{ value signing.AuthorizationQuery }

// Valid reports whether the query contains one coherent sealed purpose.
func (q SigningAuthorizationQuery) Valid() bool { return q.value.Valid() }

// Purpose returns the closed authorization purpose.
func (q SigningAuthorizationQuery) Purpose() SigningAuthorizationPurpose {
	return SigningAuthorizationPurpose(q.value.Purpose())
}

// Binding returns the opaque exact-operation authorization binding.
func (q SigningAuthorizationQuery) Binding() [sha256.Size]byte { return q.value.Binding() }

// Recipients returns detached exact envelope recipients only across this trusted boundary.
func (q SigningAuthorizationQuery) Recipients() [][]byte { return q.value.Recipients() }

// PolicyFacts returns bounded policy facts and the inherited restriction.
func (q SigningAuthorizationQuery) PolicyFacts() (SigningModificationFacts, SigningRestriction, bool) {
	facts, restriction, ok := q.value.PolicyFacts()
	if !ok {
		return SigningModificationFacts{}, "", false
	}
	return SigningModificationFacts{
		bodyChanged: facts.BodyChanged(), existingHeadersChanged: facts.ExistingHeadersChanged(), valid: true,
	}, SigningRestriction(restriction), true
}

// OutOfBandFacts returns exact trusted-boundary evidence for receive/send purposes.
func (q SigningAuthorizationQuery) OutOfBandFacts() (SigningOutOfBandFacts, bool) {
	facts, ok := q.value.OutOfBandFacts()
	if !ok {
		return SigningOutOfBandFacts{}, false
	}
	return SigningOutOfBandFacts{value: facts, valid: true}, true
}

// String returns a constant secret-safe query summary.
func (q SigningAuthorizationQuery) String() string {
	return "dkim2.SigningAuthorizationQuery{redacted}"
}

// GoString returns the constant secret-safe query Go representation.
func (q SigningAuthorizationQuery) GoString() string { return q.String() }

// Format routes every query formatting form through the redacted summary.
func (q SigningAuthorizationQuery) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, q.String())
}

// SigningAuthorizationResult is a closed query-bound authorization result.
type SigningAuthorizationResult struct{ value signing.AuthorizationResult }

// AuthorizeSigning constructs an approval for the exact supplied query.
func AuthorizeSigning(query SigningAuthorizationQuery) SigningAuthorizationResult {
	return SigningAuthorizationResult{value: signing.NewAuthorizationResult(
		query.value, signing.AuthorizationAuthorized,
	)}
}

// DenySigning constructs a denial for the exact supplied query.
func DenySigning(query SigningAuthorizationQuery) SigningAuthorizationResult {
	return SigningAuthorizationResult{value: signing.NewAuthorizationResult(
		query.value, signing.AuthorizationDenied,
	)}
}

// IsZero reports whether no declared authorization result is present.
func (r SigningAuthorizationResult) IsZero() bool { return r.value.Status() == "" }

// String returns a constant secret-safe result summary.
func (r SigningAuthorizationResult) String() string {
	return "dkim2.SigningAuthorizationResult{redacted}"
}

// GoString returns the constant secret-safe result Go representation.
func (r SigningAuthorizationResult) GoString() string { return r.String() }

// Format routes every result formatting form through the redacted summary.
func (r SigningAuthorizationResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// SigningAuthorizer decides exact policy, OOB, feedback, and disclosure queries.
type SigningAuthorizer interface {
	Authorize(context.Context, SigningAuthorizationQuery) (SigningAuthorizationResult, error)
}

type signingAuthorizerBridge struct{ authorizer SigningAuthorizer }

// Authorize adapts the public closed authorization matrix into the protocol core.
func (b signingAuthorizerBridge) Authorize(ctx context.Context, query signing.AuthorizationQuery) (signing.AuthorizationResult, error) {
	if !query.Valid() || nilSigningCallback(b.authorizer) {
		return signing.AuthorizationResult{}, provider.NewFailure(provider.FailureContract)
	}
	result, err := b.authorizer.Authorize(ctx, SigningAuthorizationQuery{value: query})
	if err != nil {
		if !result.IsZero() {
			return signing.AuthorizationResult{}, provider.NewFailure(provider.FailureContract)
		}
		return signing.AuthorizationResult{}, bridgeProviderError(ctx, err)
	}
	return result.value, nil
}
