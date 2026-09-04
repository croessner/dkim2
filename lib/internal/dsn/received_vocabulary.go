package dsn

// StructureResult is the closed outcome of the RFC 6522 and RFC 3464 structure stage.
type StructureResult string

const (
	// StructureValid reports exact three-part framing and a strict generic RFC 3464 body.
	StructureValid StructureResult = "valid"
	// StructureMalformed reports framing or delivery-status syntax outside the closed profile.
	StructureMalformed StructureResult = "malformed"
	// StructureLimitExceeded reports a configured DSN parser resource limit violation.
	StructureLimitExceeded StructureResult = "limit_exceeded"
)

// Known reports whether the value belongs to the closed vocabulary.
func (r StructureResult) Known() bool {
	return r == StructureValid || r == StructureMalformed || r == StructureLimitExceeded
}

// EmbeddedResult is the closed outcome of the embedded-original verification stage.
type EmbeddedResult string

const (
	// EmbeddedVerified reports a complete message/rfc822 original whose highest signature and instance verify.
	EmbeddedVerified EmbeddedResult = "verified"
	// EmbeddedVerifiedHeadersOnly reports a text/rfc822-headers original whose header evidence verifies.
	EmbeddedVerifiedHeadersOnly EmbeddedResult = "verified_headers_only"
	// EmbeddedUnverified reports permanent embedded verification failure.
	EmbeddedUnverified EmbeddedResult = "unverified"
	// EmbeddedTemporaryError reports a temporary DNS or key failure during embedded verification.
	EmbeddedTemporaryError EmbeddedResult = "temperror"
	// EmbeddedAbsent reports an embedded original that carries no DKIM2-Signature at all.
	EmbeddedAbsent EmbeddedResult = "absent"
)

// Known reports whether the value belongs to the closed vocabulary.
func (r EmbeddedResult) Known() bool {
	switch r {
	case EmbeddedVerified, EmbeddedVerifiedHeadersOnly, EmbeddedUnverified, EmbeddedTemporaryError, EmbeddedAbsent:
		return true
	default:
		return false
	}
}

// LocalHopResult is the closed outcome of the Section 12.1.2 item 2 identity stage.
type LocalHopResult string

const (
	// LocalHopLocal reports a verified, datasource-local completion signature bound to the outer recipient.
	LocalHopLocal LocalHopResult = "local"
	// LocalHopNotLocal reports a completion signature under a domain the tenant does not control.
	LocalHopNotLocal LocalHopResult = "not_local"
	// LocalHopMismatch reports a local domain whose mf= does not bind to the outer recipient or its d=.
	LocalHopMismatch LocalHopResult = "mismatch"
	// LocalHopTemporaryError reports a temporary datasource failure during locality resolution.
	LocalHopTemporaryError LocalHopResult = "temperror"
	// LocalHopNotEvaluated reports that an earlier stage stopped or that no tenant was available.
	LocalHopNotEvaluated LocalHopResult = "not_evaluated"
)

// Known reports whether the value belongs to the closed vocabulary.
func (r LocalHopResult) Known() bool {
	switch r {
	case LocalHopLocal, LocalHopNotLocal, LocalHopMismatch, LocalHopTemporaryError, LocalHopNotEvaluated:
		return true
	default:
		return false
	}
}

// OuterAlignmentResult is the closed outcome of the Section 12.1.2 item 1 alignment stage.
type OuterAlignmentResult string

const (
	// OuterAlignmentAligned reports that the outer signer relaxed-matches a completion rt= domain.
	OuterAlignmentAligned OuterAlignmentResult = "aligned"
	// OuterAlignmentMisaligned reports that no completion rt= domain relaxed-matches the outer signer.
	OuterAlignmentMisaligned OuterAlignmentResult = "misaligned"
	// OuterAlignmentNotEvaluated reports that an earlier stage stopped the evaluation.
	OuterAlignmentNotEvaluated OuterAlignmentResult = "not_evaluated"
)

// Known reports whether the value belongs to the closed vocabulary.
func (r OuterAlignmentResult) Known() bool {
	return r == OuterAlignmentAligned || r == OuterAlignmentMisaligned || r == OuterAlignmentNotEvaluated
}

// RecipientLinkageResult is the closed outcome of the RFC 3464 recipient linkage stage.
type RecipientLinkageResult string

const (
	// RecipientLinkageLinked reports at least one recipient group naming an authenticated rt= path.
	RecipientLinkageLinked RecipientLinkageResult = "linked"
	// RecipientLinkageUnlinked reports that no recipient group names an authenticated rt= path.
	RecipientLinkageUnlinked RecipientLinkageResult = "unlinked"
	// RecipientLinkageNotEvaluated reports that an earlier stage stopped the evaluation.
	RecipientLinkageNotEvaluated RecipientLinkageResult = "not_evaluated"
)

// Known reports whether the value belongs to the closed vocabulary.
func (r RecipientLinkageResult) Known() bool {
	return r == RecipientLinkageLinked || r == RecipientLinkageUnlinked || r == RecipientLinkageNotEvaluated
}

// PropagationResult is the closed informational propagation projection.
type PropagationResult string

const (
	// PropagationNotApplicable reports an embedded original without DKIM2 signatures.
	PropagationNotApplicable PropagationResult = "not_applicable"
	// PropagationEligible reports that a rebuild toward the previous hop can be attempted.
	PropagationEligible PropagationResult = "eligible"
	// PropagationTerminalOrigin reports that this system originated the message.
	PropagationTerminalOrigin PropagationResult = "terminal_origin"
	// PropagationNotFailure reports that no linked group carries Action: failed.
	PropagationNotFailure PropagationResult = "not_failure"
	// PropagationForbiddenNullPreviousSender reports a previous hop with mf=<>.
	PropagationForbiddenNullPreviousSender PropagationResult = "forbidden_null_previous_sender"
	// PropagationUnsupportedChain reports a custody chain this system does not
	// qualify for reconstruction: an nd= previous hop, a run member that does
	// not verify, a run whose detection exceeded the bounded authority lookup
	// limit, or a run whose custody structure is malformed. All four fail
	// closed into the same value so that the projection never distinguishes
	// a forged local signature from a merely unsupported one.
	PropagationUnsupportedChain PropagationResult = "unsupported_chain"
	// PropagationNotReconstructable reports a condition visible without a rebuild that prevents reconstruction.
	PropagationNotReconstructable PropagationResult = "not_reconstructable"
	// PropagationNotEvaluated reports that an earlier stage stopped or that no tenant was available.
	PropagationNotEvaluated PropagationResult = "not_evaluated"
)

// Known reports whether the value belongs to the closed vocabulary.
func (r PropagationResult) Known() bool {
	switch r {
	case PropagationNotApplicable, PropagationEligible, PropagationTerminalOrigin, PropagationNotFailure,
		PropagationForbiddenNullPreviousSender, PropagationUnsupportedChain, PropagationNotReconstructable,
		PropagationNotEvaluated:
		return true
	default:
		return false
	}
}

// ReceivedStage identifies one closed received-DSN evaluation stage.
type ReceivedStage string

const (
	// ReceivedStagePreflight identifies request or evaluator validation before parsing.
	ReceivedStagePreflight ReceivedStage = "preflight"
	// ReceivedStageStructure identifies RFC 6522 and RFC 3464 structure evaluation.
	ReceivedStageStructure ReceivedStage = "structure"
	// ReceivedStageEmbeddedVerification identifies embedded-original verification.
	ReceivedStageEmbeddedVerification ReceivedStage = "embedded_verification"
	// ReceivedStageLocalHop identifies local-hop identity and run detection.
	ReceivedStageLocalHop ReceivedStage = "local_hop"
	// ReceivedStageOuterAlignment identifies outer signer alignment.
	ReceivedStageOuterAlignment ReceivedStage = "outer_alignment"
	// ReceivedStageRecipientLinkage identifies RFC 3464 recipient linkage.
	ReceivedStageRecipientLinkage ReceivedStage = "recipient_linkage"
	// ReceivedStageFailureClass identifies propagation-group selection.
	ReceivedStageFailureClass ReceivedStage = "failure_class"
	// ReceivedStagePreviousHop identifies previous-hop classification.
	ReceivedStagePreviousHop ReceivedStage = "previous_hop"
)

// Known reports whether the stage belongs to the closed vocabulary.
func (s ReceivedStage) Known() bool {
	switch s {
	case ReceivedStagePreflight, ReceivedStageStructure, ReceivedStageEmbeddedVerification, ReceivedStageLocalHop,
		ReceivedStageOuterAlignment, ReceivedStageRecipientLinkage, ReceivedStageFailureClass, ReceivedStagePreviousHop:
		return true
	default:
		return false
	}
}

// ReceivedErrorCode identifies one closed received-DSN evaluation failure class.
type ReceivedErrorCode string

const (
	// ReceivedErrorInvalidRequest reports an unusable evaluator, request, or outer report.
	ReceivedErrorInvalidRequest ReceivedErrorCode = "invalid_request"
	// ReceivedErrorCanceled reports caller context cancellation or deadline expiry.
	ReceivedErrorCanceled ReceivedErrorCode = "canceled"
	// ReceivedErrorInternal reports an impossible internal state.
	ReceivedErrorInternal ReceivedErrorCode = "internal"
)

// Known reports whether the code belongs to the closed vocabulary.
func (c ReceivedErrorCode) Known() bool {
	return c == ReceivedErrorInvalidRequest || c == ReceivedErrorCanceled || c == ReceivedErrorInternal
}
