package verify

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/signature"
)

// HistoricalTargetOutcome is the closed result of verifying one historical
// DKIM2-Signature over a reconstructed state.
type HistoricalTargetOutcome string

const (
	// HistoricalTargetVerified reports hash, signature, timestamp, and alignment success.
	HistoricalTargetVerified HistoricalTargetOutcome = "verified"
	// HistoricalTargetHashMismatch reports a state whose digests differ from the target instance.
	HistoricalTargetHashMismatch HistoricalTargetOutcome = "hash_mismatch"
	// HistoricalTargetSignatureUnverified reports a permanent signature or key failure.
	HistoricalTargetSignatureUnverified HistoricalTargetOutcome = "signature_unverified"
	// HistoricalTargetTimestampRejected reports a t= outside the window at the reference instant.
	HistoricalTargetTimestampRejected HistoricalTargetOutcome = "timestamp_rejected"
	// HistoricalTargetAlignmentRejected reports a failed Section 11.4 d=/mf= match of the target itself.
	HistoricalTargetAlignmentRejected HistoricalTargetOutcome = "alignment_rejected"
	// HistoricalTargetCustodyRejected reports a broken custody link in the chain below and including the target.
	HistoricalTargetCustodyRejected HistoricalTargetOutcome = "custody_rejected"
	// HistoricalTargetNullSender reports a target whose mf= is the null reverse path.
	HistoricalTargetNullSender HistoricalTargetOutcome = "null_sender"
	// HistoricalTargetTemporary reports a typed temporary key-provider failure.
	HistoricalTargetTemporary HistoricalTargetOutcome = "temporary"
)

// Known reports whether the outcome belongs to the closed vocabulary.
func (o HistoricalTargetOutcome) Known() bool {
	switch o {
	case HistoricalTargetVerified, HistoricalTargetHashMismatch, HistoricalTargetSignatureUnverified,
		HistoricalTargetTimestampRejected, HistoricalTargetAlignmentRejected, HistoricalTargetCustodyRejected,
		HistoricalTargetNullSender, HistoricalTargetTemporary:
		return true
	default:
		return false
	}
}

// HistoricalTargetRequest binds one reconstructed state to the historical
// signature that must verify over it.
type HistoricalTargetRequest struct {
	// State is the proven reconstruction at the instance referenced by the target.
	State recipe.State
	// Sequence selects the non-highest DKIM2-Signature i= to verify.
	Sequence uint64
	// ReferenceTime is the instant at which the Section 8.4 window is evaluated.
	ReferenceTime time.Time
	// MaxTimestamp is the t= the target must not exceed, the completion instant.
	MaxTimestamp uint64
}

// String returns a constant secret-safe request summary.
func (HistoricalTargetRequest) String() string { return "verify.HistoricalTargetRequest{redacted}" }

// GoString returns the constant secret-safe request Go representation.
func (r HistoricalTargetRequest) GoString() string { return r.String() }

// Format routes every request formatting form through the redacted summary.
func (r HistoricalTargetRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// valid reports whether the request carries a coherent state, sequence, and instant.
func (r HistoricalTargetRequest) valid() bool {
	return r.State.Valid() && r.Sequence > 0 && !r.ReferenceTime.IsZero() && r.MaxTimestamp > 0 &&
		r.ReferenceTime.Unix() >= 0 && uint64(r.ReferenceTime.Unix()) <= maxRepresentableUnixSeconds/2
}

// VerifyHistoricalTarget verifies the non-highest DKIM2-Signature selected by
// request.Sequence over the reconstructed state at its instance. It re-proves
// the state's header hash, and its body hash when known, against that
// instance, computes the Section 9.6 input over the state's header block,
// evaluates the signature sets with the current-target crypto and key
// provider, evaluates the Section 8.4 window at the request reference instant
// with the additional bound that t= must not exceed MaxTimestamp, and applies
// the Section 11.4 relaxed d=/mf= match through the shared custody rules of
// the chain as it existed when the target signed. Custody is validated over
// the whole chain below and including the target, exactly as the
// current-target verifier validates the chain below its target; a broken
// link there is the distinct custody_rejected outcome, while a failed d=/mf=
// match of the target itself is alignment_rejected. A null mf= is reported as
// its own outcome so the caller can forbid propagation. An nd= target is not
// a supported historical target and is a request error.
func (v Verifier) VerifyHistoricalTarget(ctx context.Context, embedded EmbeddedInput, request HistoricalTargetRequest) (HistoricalTargetOutcome, error) {
	if ctx == nil || !v.valid() || !embedded.Valid() || !request.valid() {
		return "", newError(ErrorCodeInvalidRequest, ErrorLocation{}, ErrorDetails{Class: ErrorClassRequest}, nil)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	ordered, err := signature.OrderBySequence(embedded.input.signatures)
	if err != nil || request.Sequence >= uint64(len(ordered)) {
		return "", newError(ErrorCodeInvalidRequest, ErrorLocation{}, ErrorDetails{Class: ErrorClassRequest}, err)
	}
	parsed := ordered[request.Sequence-1]
	if parsed.Sequence() != request.Sequence || parsed.HasNextDomain() {
		return "", newError(ErrorCodeInvalidRequest, ErrorLocation{}, ErrorDetails{Class: ErrorClassRequest}, nil)
	}
	targetInstance, err := instanceByNumber(embedded.input.instances, parsed.InstanceNumber())
	if err != nil {
		return "", err
	}
	target := Target{Sequence: parsed.Sequence(), InstanceNumber: parsed.InstanceNumber()}
	matched, supported, _, err := v.history.initialStateMatches(request.State, targetInstance, v.options.RevisionLimits.MaxCanonicalWorkBytes)
	if err != nil {
		if IsErrorCode(err, ErrorCodeHistoryLimitExceeded) {
			return "", err
		}
		return "", newError(ErrorCodeInternalMisuse, ErrorLocation{Check: CheckKindHeaderHash, TargetSequence: target.Sequence, InstanceNumber: target.InstanceNumber}, ErrorDetails{Class: ErrorClassInternal}, err)
	}
	if !supported || !matched {
		return HistoricalTargetHashMismatch, nil
	}
	custody, err := validateCustodyChain(ordered[:request.Sequence], request.Sequence)
	if err != nil {
		return HistoricalTargetCustodyRejected, nil
	}
	switch custody.DirectAlignment(request.Sequence) {
	case signature.CustodyDirectAlignmentPass:
	case signature.CustodyDirectAlignmentNotApplicableNull:
		return HistoricalTargetNullSender, nil
	default:
		return HistoricalTargetAlignmentRejected, nil
	}
	if parsed.TimestampSeconds() > request.MaxTimestamp {
		return HistoricalTargetTimestampRejected, nil
	}
	switch timestampStatusAt(request.ReferenceTime, parsed.TimestampSeconds(), v.options.TimestampPolicy) {
	case TimestampStatusPass, TimestampStatusNoMaxAge:
	default:
		return HistoricalTargetTimestampRejected, nil
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		return "", malformedStateError(CheckKindSignature, target, err)
	}
	signatureInput, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{Headers: request.State.Headers(), TargetSequence: target.Sequence})
	if err != nil {
		return HistoricalTargetSignatureUnverified, nil
	}
	digest, err := canonicalizer.SHA256Digest(signatureInput)
	if err != nil {
		return "", malformedStateError(CheckKindSignature, target, err)
	}
	plan, outcome := v.prepareRevisionSignatureSets(parsed)
	if outcome != "" {
		return HistoricalTargetSignatureUnverified, nil
	}
	evaluation := v.evaluateRevisionSignatureSets(ctx, parsed, digest.Bytes(), target, plan)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	switch revisionSignatureOutcome(evaluation) {
	case RevisionProofVerified:
		return HistoricalTargetVerified, nil
	case RevisionProofProviderTemporary:
		return HistoricalTargetTemporary, nil
	default:
		return HistoricalTargetSignatureUnverified, nil
	}
}
