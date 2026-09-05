package dkim2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/dsn"
	"github.com/croessner/dkim2/internal/niliface"
	"github.com/croessner/dkim2/internal/policy"
	"github.com/croessner/dkim2/internal/verify"
)

const (
	receivedDSNRequestRedactedText    = "dkim2.ReceivedDSNRequest{redacted}"
	receivedDSNEvaluationRedactedText = "dkim2.ReceivedDSNEvaluation{redacted}"
)

// ReceivedDSNStructure is the closed structure member of the delivery_status projection.
type ReceivedDSNStructure string

const (
	// ReceivedDSNStructureValid reports exact RFC 6522 framing and a strict generic RFC 3464 body.
	ReceivedDSNStructureValid ReceivedDSNStructure = "valid"
	// ReceivedDSNStructureMalformed reports framing or delivery-status syntax outside the closed profile.
	ReceivedDSNStructureMalformed ReceivedDSNStructure = "malformed"
	// ReceivedDSNStructureLimitExceeded reports a DSN parser resource limit violation.
	ReceivedDSNStructureLimitExceeded ReceivedDSNStructure = "limit_exceeded"
)

// Known reports whether the value belongs to the closed vocabulary.
func (s ReceivedDSNStructure) Known() bool { return dsn.StructureResult(s).Known() }

// ReceivedDSNEmbedded is the closed embedded member of the delivery_status projection.
type ReceivedDSNEmbedded string

const (
	// ReceivedDSNEmbeddedVerified reports a verified complete embedded original.
	ReceivedDSNEmbeddedVerified ReceivedDSNEmbedded = "verified"
	// ReceivedDSNEmbeddedVerifiedHeadersOnly reports verified header-only embedded evidence.
	ReceivedDSNEmbeddedVerifiedHeadersOnly ReceivedDSNEmbedded = "verified_headers_only"
	// ReceivedDSNEmbeddedUnverified reports permanent embedded verification failure.
	ReceivedDSNEmbeddedUnverified ReceivedDSNEmbedded = "unverified"
	// ReceivedDSNEmbeddedTemperror reports a temporary DNS or key failure.
	ReceivedDSNEmbeddedTemperror ReceivedDSNEmbedded = "temperror"
	// ReceivedDSNEmbeddedAbsent reports an embedded original without any DKIM2-Signature.
	ReceivedDSNEmbeddedAbsent ReceivedDSNEmbedded = "absent"
	// ReceivedDSNEmbeddedNotEvaluated reports that the structure stage stopped
	// the evaluation before any embedded evidence could be assessed.
	ReceivedDSNEmbeddedNotEvaluated ReceivedDSNEmbedded = "not_evaluated"
)

// Known reports whether the value belongs to the closed vocabulary.
func (s ReceivedDSNEmbedded) Known() bool { return dsn.EmbeddedResult(s).Known() }

// ReceivedDSNLocalHop is the closed local_hop member of the delivery_status projection.
type ReceivedDSNLocalHop string

const (
	// ReceivedDSNLocalHopLocal reports a verified, datasource-local completion signature bound to the outer recipient.
	ReceivedDSNLocalHopLocal ReceivedDSNLocalHop = "local"
	// ReceivedDSNLocalHopNotLocal reports a completion signature under a domain the tenant does not control.
	ReceivedDSNLocalHopNotLocal ReceivedDSNLocalHop = "not_local"
	// ReceivedDSNLocalHopMismatch reports a local domain whose mf= does not bind to the outer recipient or its d=.
	ReceivedDSNLocalHopMismatch ReceivedDSNLocalHop = "mismatch"
	// ReceivedDSNLocalHopTemperror reports a temporary datasource failure.
	ReceivedDSNLocalHopTemperror ReceivedDSNLocalHop = "temperror"
	// ReceivedDSNLocalHopNotEvaluated reports an earlier stop or the absence of a tenant.
	ReceivedDSNLocalHopNotEvaluated ReceivedDSNLocalHop = "not_evaluated"
)

// Known reports whether the value belongs to the closed vocabulary.
func (s ReceivedDSNLocalHop) Known() bool { return dsn.LocalHopResult(s).Known() }

// ReceivedDSNOuterAlignment is the closed outer_alignment member of the delivery_status projection.
type ReceivedDSNOuterAlignment string

const (
	// ReceivedDSNOuterAlignmentAligned reports that the outer signer relaxed-matches a completion rt= domain.
	ReceivedDSNOuterAlignmentAligned ReceivedDSNOuterAlignment = "aligned"
	// ReceivedDSNOuterAlignmentMisaligned reports that no completion rt= domain relaxed-matches the outer signer.
	ReceivedDSNOuterAlignmentMisaligned ReceivedDSNOuterAlignment = "misaligned"
	// ReceivedDSNOuterAlignmentNotEvaluated reports an earlier stop.
	ReceivedDSNOuterAlignmentNotEvaluated ReceivedDSNOuterAlignment = "not_evaluated"
)

// Known reports whether the value belongs to the closed vocabulary.
func (s ReceivedDSNOuterAlignment) Known() bool { return dsn.OuterAlignmentResult(s).Known() }

// ReceivedDSNRecipientLinkage is the closed recipient_linkage member of the delivery_status projection.
type ReceivedDSNRecipientLinkage string

const (
	// ReceivedDSNRecipientLinkageLinked reports at least one recipient group naming an authenticated rt= path.
	ReceivedDSNRecipientLinkageLinked ReceivedDSNRecipientLinkage = "linked"
	// ReceivedDSNRecipientLinkageUnlinked reports that no recipient group names an authenticated rt= path.
	ReceivedDSNRecipientLinkageUnlinked ReceivedDSNRecipientLinkage = "unlinked"
	// ReceivedDSNRecipientLinkageNotEvaluated reports an earlier stop.
	ReceivedDSNRecipientLinkageNotEvaluated ReceivedDSNRecipientLinkage = "not_evaluated"
)

// Known reports whether the value belongs to the closed vocabulary.
func (s ReceivedDSNRecipientLinkage) Known() bool { return dsn.RecipientLinkageResult(s).Known() }

// ReceivedDSNPropagation is the closed informational propagation member of the delivery_status projection.
type ReceivedDSNPropagation string

const (
	// ReceivedDSNPropagationNotApplicable reports an embedded original without DKIM2 signatures.
	ReceivedDSNPropagationNotApplicable ReceivedDSNPropagation = "not_applicable"
	// ReceivedDSNPropagationEligible reports that a rebuild toward the previous hop can be attempted.
	ReceivedDSNPropagationEligible ReceivedDSNPropagation = "eligible"
	// ReceivedDSNPropagationTerminalOrigin reports that this system originated the message.
	ReceivedDSNPropagationTerminalOrigin ReceivedDSNPropagation = "terminal_origin"
	// ReceivedDSNPropagationNotFailure reports that no linked group carries Action: failed.
	ReceivedDSNPropagationNotFailure ReceivedDSNPropagation = "not_failure"
	// ReceivedDSNPropagationForbiddenNullPreviousSender reports a previous hop with mf=<>.
	ReceivedDSNPropagationForbiddenNullPreviousSender ReceivedDSNPropagation = "forbidden_null_previous_sender"
	// ReceivedDSNPropagationUnsupportedChain reports an nd= previous hop or a non-verifying run member.
	ReceivedDSNPropagationUnsupportedChain ReceivedDSNPropagation = "unsupported_chain"
	// ReceivedDSNPropagationNotReconstructable reports a rebuild-preventing condition visible without a rebuild.
	ReceivedDSNPropagationNotReconstructable ReceivedDSNPropagation = "not_reconstructable"
	// ReceivedDSNPropagationNotEvaluated reports an earlier stop or the absence of a tenant.
	ReceivedDSNPropagationNotEvaluated ReceivedDSNPropagation = "not_evaluated"
)

// Known reports whether the value belongs to the closed vocabulary.
func (s ReceivedDSNPropagation) Known() bool { return dsn.PropagationResult(s).Known() }

// ReceivedDSNOriginalForm identifies the embedded original representation.
type ReceivedDSNOriginalForm string

const (
	// ReceivedDSNOriginalComplete identifies a message/rfc822 embedded original.
	ReceivedDSNOriginalComplete ReceivedDSNOriginalForm = "complete"
	// ReceivedDSNOriginalHeadersOnly identifies a text/rfc822-headers embedded original.
	ReceivedDSNOriginalHeadersOnly ReceivedDSNOriginalForm = "headers_only"
)

// Known reports whether the form belongs to the closed vocabulary.
func (f ReceivedDSNOriginalForm) Known() bool {
	return f == ReceivedDSNOriginalComplete || f == ReceivedDSNOriginalHeadersOnly
}

// LocalAuthorityStatus is the closed answer of one local-authority lookup.
type LocalAuthorityStatus string

const (
	// LocalAuthorityLocal reports that the bound tenant holds an active signing profile of any use for the domain.
	LocalAuthorityLocal LocalAuthorityStatus = "local"
	// LocalAuthorityNotLocal reports that the domain is not a local authority domain for the bound tenant.
	LocalAuthorityNotLocal LocalAuthorityStatus = "not_local"
)

// Known reports whether the status belongs to the closed vocabulary.
func (s LocalAuthorityStatus) Known() bool { return verify.LocalAuthorityStatus(s).Known() }

// LocalAuthority answers whether a canonical DNS domain is a local authority
// domain. It carries no tenant value: the daemon binds the tenant when it
// constructs the implementation. The library validates domain syntax before
// every call and never passes a malformed d=. Any returned error is treated
// as a temporary datasource failure, never as not_local; a status outside the
// closed vocabulary is a contract violation and is also temporary.
type LocalAuthority interface {
	LookupLocalAuthority(ctx context.Context, domain string) (LocalAuthorityStatus, error)
}

// localAuthorityBridge adapts the public authority contract to the protocol-core seam.
type localAuthorityBridge struct{ authority LocalAuthority }

// LookupLocalAuthority delegates and fails closed on contract violations.
func (b localAuthorityBridge) LookupLocalAuthority(ctx context.Context, domain string) (verify.LocalAuthorityStatus, error) {
	if niliface.IsNil(b.authority) {
		return "", newAPIError(APIErrorCodeInvalidRequest)
	}
	status, err := b.authority.LookupLocalAuthority(ctx, domain)
	if err != nil {
		return "", err
	}
	if !status.Known() {
		return "", newAPIError(APIErrorCodeInvalidRequest)
	}
	return verify.LocalAuthorityStatus(status), nil
}

// ReceivedDSNStage identifies one closed received-DSN evaluation stage.
type ReceivedDSNStage string

const (
	// ReceivedDSNStagePreflight identifies request or evaluator validation.
	ReceivedDSNStagePreflight ReceivedDSNStage = "preflight"
	// ReceivedDSNStageStructure identifies RFC 6522 and RFC 3464 structure evaluation.
	ReceivedDSNStageStructure ReceivedDSNStage = "structure"
	// ReceivedDSNStageEmbeddedVerification identifies embedded-original verification.
	ReceivedDSNStageEmbeddedVerification ReceivedDSNStage = "embedded_verification"
	// ReceivedDSNStageLocalHop identifies local-hop identity and run detection.
	ReceivedDSNStageLocalHop ReceivedDSNStage = "local_hop"
	// ReceivedDSNStageOuterAlignment identifies outer signer alignment.
	ReceivedDSNStageOuterAlignment ReceivedDSNStage = "outer_alignment"
	// ReceivedDSNStageRecipientLinkage identifies RFC 3464 recipient linkage.
	ReceivedDSNStageRecipientLinkage ReceivedDSNStage = "recipient_linkage"
	// ReceivedDSNStageFailureClass identifies propagation-group selection.
	ReceivedDSNStageFailureClass ReceivedDSNStage = "failure_class"
	// ReceivedDSNStagePreviousHop identifies previous-hop classification.
	ReceivedDSNStagePreviousHop ReceivedDSNStage = "previous_hop"
)

// Known reports whether the stage belongs to the closed vocabulary.
func (s ReceivedDSNStage) Known() bool { return dsn.ReceivedStage(s).Known() }

// ReceivedDSNError preserves only a closed failure stage while exposing the
// caller context error or the public API error through errors.Unwrap.
type ReceivedDSNError struct {
	stage ReceivedDSNStage
	cause error
}

// Error returns a bounded diagnostic without message, envelope, or identity data.
func (e *ReceivedDSNError) Error() string {
	if e == nil || !e.stage.Known() {
		return "dkim2 received dsn error"
	}
	return "dkim2 received dsn error: stage=" + string(e.stage)
}

// Unwrap preserves context and API error classification.
func (e *ReceivedDSNError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Stage returns the closed failure stage or the zero value.
func (e *ReceivedDSNError) Stage() ReceivedDSNStage {
	if e == nil || !e.stage.Known() {
		return ""
	}
	return e.stage
}

// Format routes every formatting verb through the bounded diagnostic.
func (e *ReceivedDSNError) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, e.Error()) }

// ReceivedDSNStageOf returns the closed stage only for a typed received-DSN failure.
func ReceivedDSNStageOf(err error) ReceivedDSNStage {
	var typed *ReceivedDSNError
	if errors.As(err, &typed) {
		return typed.Stage()
	}
	return ""
}

// newReceivedDSNError binds a closed stage to an existing bounded cause.
func newReceivedDSNError(stage ReceivedDSNStage, cause error) error {
	if !stage.Known() || cause == nil {
		return newAPIError(APIErrorCodeInvalidRequest)
	}
	return &ReceivedDSNError{stage: stage, cause: cause}
}

// mapReceivedError converts the protocol-core staged error into the public vocabulary.
func mapReceivedError(ctx context.Context, err error) error {
	stage := ReceivedDSNStage(dsn.ReceivedStageOf(err))
	if !stage.Known() {
		stage = ReceivedDSNStagePreflight
	}
	if ctx != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return newReceivedDSNError(stage, ctxErr)
		}
	}
	return newReceivedDSNError(stage, newAPIError(APIErrorCodeInvalidRequest))
}

// ReceivedDSNRequest carries cloned outer DSN bytes, the observed null
// reverse path and single forward path, and the tenant-bound local authority.
type ReceivedDSNRequest struct {
	state *receivedDSNRequestState
}

// receivedDSNRequestState stores the immutable private request values.
type receivedDSNRequestState struct {
	raw          []byte
	reversePath  []byte
	forwardPaths [][]byte
	authority    LocalAuthority
}

// NewReceivedDSNRequest snapshots one received-DSN evaluation request. A nil
// authority means no tenant is available; locality is then not evaluated.
func NewReceivedDSNRequest(raw, reversePath []byte, forwardPaths [][]byte, authority LocalAuthority) ReceivedDSNRequest {
	state := &receivedDSNRequestState{raw: bytes.Clone(raw), reversePath: bytes.Clone(reversePath), forwardPaths: cloneByteSlices(forwardPaths)}
	if !niliface.IsNil(authority) {
		state.authority = authority
	}
	return ReceivedDSNRequest{state: state}
}

// String prevents raw DSN or envelope content from reaching diagnostics.
func (ReceivedDSNRequest) String() string { return receivedDSNRequestRedactedText }

// GoString returns the constant secret-safe request representation.
func (r ReceivedDSNRequest) GoString() string { return r.String() }

// Format routes every request formatting form through the redacted representation.
func (r ReceivedDSNRequest) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// MarshalJSON rejects serialization of message or envelope bytes.
func (ReceivedDSNRequest) MarshalJSON() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// MarshalText rejects diagnostic serialization of message or envelope bytes.
func (ReceivedDSNRequest) MarshalText() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// ReceivedDSNEvaluation is the immutable read-only outcome of one received-DSN
// evaluation. It exposes only the closed projection and bounded sequence
// facts; it can never authorize signing and is never an input to a signing route.
type ReceivedDSNEvaluation struct {
	state *receivedDSNEvaluationState
}

// receivedDSNEvaluationState stores the sealed protocol-core evaluation.
type receivedDSNEvaluationState struct {
	inner dsn.ReceivedEvaluation
}

// Valid reports whether the evaluation was issued by Verifier.EvaluateReceivedDSN and is coherent.
func (e ReceivedDSNEvaluation) Valid() bool {
	return e.state != nil && e.state.inner.Valid() &&
		e.Structure().Known() && e.LocalHop().Known() && e.OuterAlignment().Known() &&
		e.RecipientLinkage().Known() && e.Propagation().Known() && e.Embedded().Known()
}

// Structure returns the closed structure member.
func (e ReceivedDSNEvaluation) Structure() ReceivedDSNStructure {
	if e.state == nil {
		return ""
	}
	return ReceivedDSNStructure(e.state.inner.Structure())
}

// Embedded returns the closed embedded member, which is
// ReceivedDSNEmbeddedNotEvaluated when the structure stage stopped the
// evaluation.
func (e ReceivedDSNEvaluation) Embedded() ReceivedDSNEmbedded {
	if e.state == nil {
		return ""
	}
	return ReceivedDSNEmbedded(e.state.inner.Embedded())
}

// LocalHop returns the closed local_hop member.
func (e ReceivedDSNEvaluation) LocalHop() ReceivedDSNLocalHop {
	if e.state == nil {
		return ""
	}
	return ReceivedDSNLocalHop(e.state.inner.LocalHop())
}

// OuterAlignment returns the closed outer_alignment member.
func (e ReceivedDSNEvaluation) OuterAlignment() ReceivedDSNOuterAlignment {
	if e.state == nil {
		return ""
	}
	return ReceivedDSNOuterAlignment(e.state.inner.OuterAlignment())
}

// RecipientLinkage returns the closed recipient_linkage member.
func (e ReceivedDSNEvaluation) RecipientLinkage() ReceivedDSNRecipientLinkage {
	if e.state == nil {
		return ""
	}
	return ReceivedDSNRecipientLinkage(e.state.inner.RecipientLinkage())
}

// Propagation returns the closed informational propagation member.
func (e ReceivedDSNEvaluation) Propagation() ReceivedDSNPropagation {
	if e.state == nil {
		return ""
	}
	return ReceivedDSNPropagation(e.state.inner.Propagation())
}

// OriginalForm returns the embedded original representation once structure passed.
func (e ReceivedDSNEvaluation) OriginalForm() ReceivedDSNOriginalForm {
	if e.state == nil || e.state.inner.Structure() != dsn.StructureValid {
		return ""
	}
	return ReceivedDSNOriginalForm(e.state.inner.Form())
}

// CompletionSequence returns the i= of the verified completion signature or zero.
func (e ReceivedDSNEvaluation) CompletionSequence() uint64 {
	if e.state == nil {
		return 0
	}
	return e.state.inner.CompletionSequence()
}

// LocalHopRunLength returns the number of local run members when the local hop was proven, otherwise zero.
func (e ReceivedDSNEvaluation) LocalHopRunLength() int {
	if e.state == nil {
		return 0
	}
	run, ok := e.state.inner.Run()
	if !ok {
		return 0
	}
	return len(run.Members())
}

// String returns a constant representation without sealed evaluation facts.
func (ReceivedDSNEvaluation) String() string { return receivedDSNEvaluationRedactedText }

// GoString returns the constant secret-safe evaluation representation.
func (e ReceivedDSNEvaluation) GoString() string { return e.String() }

// Format routes every evaluation formatting form through the redacted representation.
func (e ReceivedDSNEvaluation) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, e.String())
}

// MarshalJSON rejects direct serialization outside generated response DTOs.
func (ReceivedDSNEvaluation) MarshalJSON() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// MarshalText rejects diagnostic serialization of sealed evaluation state.
func (ReceivedDSNEvaluation) MarshalText() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// policyFacts projects the closed stage members into the internal policy
// contract for the received-DSN mapping table. Propagation is informational
// and never a policy input. A valid evaluation whose members are not stage
// coherent is an internal contract violation.
func (e ReceivedDSNEvaluation) policyFacts() (policy.ReceivedDSNFacts, error) {
	if !e.Valid() {
		return policy.ReceivedDSNFacts{}, newPolicyError(PolicyErrorInvalidInput)
	}
	facts, err := policy.NewReceivedDSNFacts(
		policy.ReceivedDSNStructure(e.Structure()), policy.ReceivedDSNEmbedded(e.Embedded()),
		policy.ReceivedDSNLocalHop(e.LocalHop()), policy.ReceivedDSNOuterAlignment(e.OuterAlignment()),
		policy.ReceivedDSNRecipientLinkage(e.RecipientLinkage()),
	)
	if err != nil {
		return policy.ReceivedDSNFacts{}, newPolicyError(PolicyErrorInternalContract)
	}
	return facts, nil
}

// newReceivedDSNEvaluator binds the protocol-core received-DSN evaluator to
// the verifier's retained core and narrows the RFC 6522 parser to the public
// raw-message limit.
func newReceivedDSNEvaluator(core verify.Verifier, limits VerificationLimits) (dsn.ReceivedEvaluator, error) {
	parser := dsn.DefaultOptions()
	parser.MaxMessageBytes = min(parser.MaxMessageBytes, limits.MaxRawMessageBytes())
	parser.MaxPartBytes = min(parser.MaxPartBytes, parser.MaxMessageBytes)
	return dsn.NewReceivedEvaluator(core, dsn.ReceivedEvaluatorConfig{Parser: parser})
}

// EvaluateReceivedDSN evaluates one inbound DKIM2-signed delivery-status
// notification under Draft-06 Section 12.1.2 after the caller verified the
// outer message as an ordinary message with this verifier. It shares the
// verifier's key provider, limits, clock, and observation sink and adds the
// tenant-bound local authority carried by the request. The request must carry
// the observed null reverse path and exactly one forward path. Protocol
// outcomes are returned in the evaluation; only invalid requests,
// cancellation, and internal contract violations return a Go error.
func (v *Verifier) EvaluateReceivedDSN(ctx context.Context, request ReceivedDSNRequest) (ReceivedDSNEvaluation, error) {
	if v == nil || v.state == nil || !v.state.initialized || ctx == nil || request.state == nil ||
		!bytes.Equal(request.state.reversePath, []byte("<>")) || len(request.state.forwardPaths) != 1 || len(request.state.raw) == 0 {
		return ReceivedDSNEvaluation{}, newReceivedDSNError(ReceivedDSNStagePreflight, newAPIError(APIErrorCodeInvalidRequest))
	}
	if err := ctx.Err(); err != nil {
		return ReceivedDSNEvaluation{}, newReceivedDSNError(ReceivedDSNStagePreflight, err)
	}
	internal := dsn.ReceivedRequest{Raw: request.state.raw, OuterRecipient: request.state.forwardPaths[0]}
	if request.state.authority != nil {
		internal.Authority = localAuthorityBridge{authority: request.state.authority}
	}
	evaluation, err := v.state.receivedDSN.Evaluate(ctx, internal)
	if err != nil {
		return ReceivedDSNEvaluation{}, mapReceivedError(ctx, err)
	}
	public := ReceivedDSNEvaluation{state: &receivedDSNEvaluationState{inner: evaluation}}
	if !public.Valid() {
		return ReceivedDSNEvaluation{}, newReceivedDSNError(ReceivedDSNStagePreflight, newAPIError(APIErrorCodeInvalidRequest))
	}
	return public, nil
}
