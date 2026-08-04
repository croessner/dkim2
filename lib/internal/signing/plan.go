package signing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/routeplan"
	"github.com/croessner/dkim2/internal/signature"
	"github.com/croessner/dkim2/internal/verify"
)

// DerivedRole identifies the role selected by the exact Section 9.1 hash gate.
type DerivedRole string

const (
	// RoleOriginator identifies a message without inherited DKIM2 protocol fields.
	RoleOriginator DerivedRole = "originator"
	// RoleHashUnchangedForwarder identifies an existing message whose exact SHA-256 tuple is unchanged.
	RoleHashUnchangedForwarder DerivedRole = "hash_unchanged_forwarder"
	// RoleReviser identifies an existing message whose header or body SHA-256 digest changed.
	RoleReviser DerivedRole = "reviser"
)

// Known reports whether the role belongs to the closed signing vocabulary.
func (r DerivedRole) Known() bool {
	return r == RoleOriginator || r == RoleHashUnchangedForwarder || r == RoleReviser
}

// HashTuple stores one immutable exact SHA-256 header/body digest pair.
type HashTuple struct {
	header, body [sha256.Size]byte
	initialized  bool
}

// Header returns the exact header digest.
func (h HashTuple) Header() [sha256.Size]byte { return h.header }

// Body returns the exact body digest.
func (h HashTuple) Body() [sha256.Size]byte { return h.body }

// Valid reports whether the tuple was derived from canonical SHA-256 results.
func (h HashTuple) Valid() bool { return h.initialized }

// String returns a constant secret-safe tuple summary.
func (h HashTuple) String() string { return "signing.HashTuple{redacted}" }

// GoString returns a constant secret-safe tuple Go representation.
func (h HashTuple) GoString() string { return h.String() }

// Format routes every tuple formatting form through the redacted summary.
func (h HashTuple) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, h.String()) }

// PlanGenerationFacts records the bounded inverse-recipe result used by a plan.
type PlanGenerationFacts struct {
	outcome                recipe.GenerationOutcome
	bodyOutcome            recipe.BodyGenerationOutcome
	unavailable            recipe.BodyUnavailableReason
	bodyPolicy             recipe.BodyUnavailablePolicy
	literalPolicy          recipe.LiteralDisclosurePolicy
	decoded, canonical     int
	currentCanonical       int
	usage                  recipe.GenerationUsage
	parseUsage, applyUsage recipe.Usage
	initialized            bool
}

// Valid reports whether recipe outcome, policy, proof usage, and canonical work agree.
func (f PlanGenerationFacts) Valid() bool {
	if !f.initialized || !f.outcome.Known() || !f.bodyOutcome.Known() ||
		!f.bodyPolicy.Known() || !f.literalPolicy.Known() || f.canonical <= 0 ||
		f.currentCanonical <= 0 || f.currentCanonical > f.canonical || f.decoded < 0 {
		return false
	}
	if f.outcome == recipe.GenerationOutcomeUnchanged {
		return f.bodyOutcome == recipe.BodyGenerationUnchanged && !f.unavailable.Known() &&
			f.decoded == 0 && !f.usage.Valid() && !f.parseUsage.Valid() && !f.applyUsage.Valid()
	}
	if f.decoded == 0 || !f.usage.Valid() || !f.parseUsage.Valid() || !f.applyUsage.Valid() {
		return false
	}
	if f.bodyOutcome == recipe.BodyGenerationUnavailable {
		return f.bodyPolicy == recipe.AllowUnavailableBody && f.unavailable.Known()
	}
	return !f.unavailable.Known()
}

// Outcome returns the closed recipe-generation outcome.
func (f PlanGenerationFacts) Outcome() recipe.GenerationOutcome {
	if !f.initialized {
		return ""
	}
	return f.outcome
}

// BodyOutcome returns the closed body-generation outcome.
func (f PlanGenerationFacts) BodyOutcome() recipe.BodyGenerationOutcome {
	if !f.initialized {
		return ""
	}
	return f.bodyOutcome
}

// BodyUnavailableReason returns the explicit unavailable-body reason when present.
func (f PlanGenerationFacts) BodyUnavailableReason() recipe.BodyUnavailableReason {
	if !f.initialized {
		return ""
	}
	return f.unavailable
}

// BodyUnavailablePolicy returns the closed recipe body-unavailable policy.
func (f PlanGenerationFacts) BodyUnavailablePolicy() recipe.BodyUnavailablePolicy {
	if !f.Valid() {
		return recipe.BodyUnavailablePolicy(255)
	}
	return f.bodyPolicy
}

// LiteralPolicy returns the closed recipe literal-disclosure policy.
func (f PlanGenerationFacts) LiteralPolicy() recipe.LiteralDisclosurePolicy {
	if !f.Valid() {
		return recipe.LiteralDisclosurePolicy(255)
	}
	return f.literalPolicy
}

// DecodedBytes returns the exact decoded JSON byte count.
func (f PlanGenerationFacts) DecodedBytes() int {
	if !f.initialized {
		return 0
	}
	return f.decoded
}

// CanonicalWorkBytes returns aggregate sealed and local canonical hash work.
func (f PlanGenerationFacts) CanonicalWorkBytes() int {
	if !f.initialized {
		return 0
	}
	return f.canonical
}

// CurrentHashCanonicalWorkBytes returns exact final header/body hash work reserved for completion.
func (f PlanGenerationFacts) CurrentHashCanonicalWorkBytes() int {
	if !f.Valid() {
		return 0
	}
	return f.currentCanonical
}

// Usage returns immutable recipe-generation accounting.
func (f PlanGenerationFacts) Usage() recipe.GenerationUsage { return f.usage }

// ParseUsage returns the strict independent recipe-parse proof accounting.
func (f PlanGenerationFacts) ParseUsage() recipe.Usage { return f.parseUsage }

// ApplyUsage returns the strict independent recipe-application proof accounting.
func (f PlanGenerationFacts) ApplyUsage() recipe.Usage { return f.applyUsage }

// String returns a constant secret-safe generation summary.
func (f PlanGenerationFacts) String() string { return "signing.PlanGenerationFacts{redacted}" }

// GoString returns a constant secret-safe generation Go representation.
func (f PlanGenerationFacts) GoString() string { return f.String() }

// Format routes every generation-facts formatting form through the redacted summary.
func (f PlanGenerationFacts) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, f.String())
}

// PlanSizeFacts stores exact known sizes and reserved protocol cardinality.
type PlanSizeFacts struct {
	instanceFieldBytes, signatureFieldBytes int
	headerBytes, messageBytes               int
	protocolFields, signatureFields         int
	finalHeaderFields                       int
	signatureLimit                          LimitName
	initialized                             bool
}

// InstanceFieldBytes returns the exact new Message-Instance field size.
func (f PlanSizeFacts) InstanceFieldBytes() int { return f.instanceFieldBytes }

// SignatureFieldAllowanceBytes returns the exact bounded allowance remaining for the future field.
func (f PlanSizeFacts) SignatureFieldAllowanceBytes() int { return f.signatureFieldBytes }

// SignatureFieldLimitName returns the dimension that bounded the future field allowance.
func (f PlanSizeFacts) SignatureFieldLimitName() LimitName { return f.signatureLimit }

// signatureAllowanceFailure projects one field size into its sealed limiting dimension.
func (f PlanSizeFacts) signatureAllowanceFailure(fieldBytes int) (LimitName, int, int, bool) {
	if !f.Valid() || fieldBytes <= f.signatureFieldBytes {
		return "", 0, 0, false
	}
	switch f.signatureLimit {
	case LimitNameMaxFieldBytes:
		return f.signatureLimit, f.signatureFieldBytes, fieldBytes, true
	case LimitNameMaxHeaderBytes:
		base := f.headerBytes - f.signatureFieldBytes
		actual, ok := checkedAdd(base, fieldBytes)
		return f.signatureLimit, f.headerBytes, actual, ok
	case LimitNameMaxMessageBytes:
		base := f.messageBytes - f.signatureFieldBytes
		actual, ok := checkedAdd(base, fieldBytes)
		return f.signatureLimit, f.messageBytes, actual, ok
	default:
		return "", 0, 0, false
	}
}

// HeaderBytes returns the worst-case complete header bytes after both planned field insertions.
func (f PlanSizeFacts) HeaderBytes() int { return f.headerBytes }

// MessageBytes returns the worst-case complete message bytes after both planned field insertions.
func (f PlanSizeFacts) MessageBytes() int { return f.messageBytes }

// ProtocolFields returns the count after reserving the required future signature.
func (f PlanSizeFacts) ProtocolFields() int { return f.protocolFields }

// SignatureFields returns the count after reserving the required future signature.
func (f PlanSizeFacts) SignatureFields() int { return f.signatureFields }

// FinalHeaderFields returns the exact raw header occurrence count after insertion.
func (f PlanSizeFacts) FinalHeaderFields() int { return f.finalHeaderFields }

// Valid reports whether all exact sizes and reserved counts are initialized.
func (f PlanSizeFacts) Valid() bool {
	return f.initialized && f.instanceFieldBytes >= 0 && f.signatureFieldBytes > 0 &&
		validSignatureAllowanceLimit(f.signatureLimit) &&
		f.headerBytes >= f.instanceFieldBytes+f.signatureFieldBytes &&
		f.messageBytes >= f.headerBytes && f.protocolFields > 0 && f.signatureFields > 0 &&
		f.finalHeaderFields >= f.protocolFields
}

// validSignatureAllowanceLimit restricts the planner seal to the three size dimensions.
func validSignatureAllowanceLimit(name LimitName) bool {
	return name == LimitNameMaxFieldBytes || name == LimitNameMaxHeaderBytes ||
		name == LimitNameMaxMessageBytes
}

// OriginatorPlanRequest carries one exact source-bound origin plan request.
type OriginatorPlanRequest struct {
	Message rawmsg.Message
	Ticket  routeplan.CopyTicket
}

// String returns a constant secret-safe originator request summary.
func (r OriginatorPlanRequest) String() string { return "signing.OriginatorPlanRequest{redacted}" }

// GoString returns a constant secret-safe originator request Go representation.
func (r OriginatorPlanRequest) GoString() string { return r.String() }

// Format routes every originator request formatting form through the redacted summary.
func (r OriginatorPlanRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// ExistingPlanRequest carries one exact capability- and source-bound existing-message plan request.
type ExistingPlanRequest struct {
	Capability    VerifiedRevisionInput
	Message       rawmsg.Message
	Ticket        routeplan.CopyTicket
	BodyPolicy    recipe.BodyUnavailablePolicy
	LiteralPolicy recipe.LiteralDisclosurePolicy
}

// String returns a constant secret-safe existing-message request summary.
func (r ExistingPlanRequest) String() string { return "signing.ExistingPlanRequest{redacted}" }

// GoString returns a constant secret-safe existing-message request Go representation.
func (r ExistingPlanRequest) GoString() string { return r.String() }

// Format routes every existing-message request formatting form through the redacted summary.
func (r ExistingPlanRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// UnsignedOperationPlan is an immutable pure hash-gate and instance plan.
type UnsignedOperationPlan struct {
	role                                       DerivedRole
	highestInstance, newInstance, nextSequence uint64
	signatureInstance                          uint64
	hashes                                     HashTuple
	generation                                 PlanGenerationFacts
	modifications                              ModificationFacts
	instance                                   instance.MessageInstance
	renderedInstance                           []byte
	sizes                                      PlanSizeFacts
	binding                                    operationPlanBinding
	instant                                    verify.RevisionInstant
	initialized                                bool
}

// operationPlanBinding seals the exact source, ticket, and optional revision capability used by planning.
type operationPlanBinding struct {
	sourceDigest                      [sha256.Size]byte
	parentID, ticketID, ticketBinding [sha256.Size]byte
	capabilitySeal                    [sha256.Size]byte
	purpose                           routeplan.Purpose
	hasCapability, initialized        bool
}

// valid reports whether every exact plan binding component has an initialized shape.
func (b operationPlanBinding) valid() bool {
	if !b.initialized || b.sourceDigest == [sha256.Size]byte{} || b.parentID == [sha256.Size]byte{} ||
		b.ticketID == [sha256.Size]byte{} || b.ticketBinding == [sha256.Size]byte{} || !b.purpose.Known() {
		return false
	}
	return b.hasCapability == (b.capabilitySeal != [sha256.Size]byte{})
}

// Valid reports whether the plan is a coherent unsigned operation.
func (p UnsignedOperationPlan) Valid() bool {
	if !p.initialized || !p.role.Known() || !p.hashes.Valid() || !p.generation.Valid() || !p.sizes.Valid() ||
		!p.binding.valid() || !p.instant.Valid() ||
		p.nextSequence == 0 || p.signatureInstance == 0 ||
		p.sizes.signatureFields != int(p.nextSequence) ||
		len(p.renderedInstance) != p.sizes.instanceFieldBytes {
		return false
	}
	switch p.role {
	case RoleOriginator:
		return p.validOriginator()
	case RoleHashUnchangedForwarder:
		return p.validHashUnchangedForwarder()
	case RoleReviser:
		return p.validReviser()
	default:
		return false
	}
}

// validOriginator verifies origin-only progression, generation, and size invariants.
func (p UnsignedOperationPlan) validOriginator() bool {
	return p.highestInstance == 0 && p.newInstance == 1 && p.signatureInstance == 1 &&
		(p.binding.purpose == routeplan.PurposeOrigin || p.binding.purpose == routeplan.PurposeDeliveryStatus) &&
		!p.binding.hasCapability &&
		p.nextSequence == 1 && p.instance.Number() == 1 && len(p.renderedInstance) > 0 &&
		p.generation.outcome == recipe.GenerationOutcomeUnchanged &&
		p.generation.bodyOutcome == recipe.BodyGenerationUnchanged && p.generation.canonical > 0 &&
		!p.modifications.initialized && p.sizes.protocolFields == 2
}

// validHashUnchangedForwarder verifies no-instance forwarding invariants.
func (p UnsignedOperationPlan) validHashUnchangedForwarder() bool {
	return p.highestInstance > 0 && p.newInstance == 0 && p.signatureInstance == p.highestInstance &&
		(p.binding.purpose == routeplan.PurposeRevision || p.binding.purpose == routeplan.PurposeNextDomain) &&
		p.binding.hasCapability &&
		p.nextSequence > 1 && p.instance.Number() == 0 && len(p.renderedInstance) == 0 &&
		p.generation.outcome == recipe.GenerationOutcomeUnchanged &&
		p.generation.bodyOutcome == recipe.BodyGenerationUnchanged && p.generation.canonical > 0 &&
		p.modifications.initialized && p.sizes.protocolFields > p.sizes.signatureFields
}

// validReviser verifies one-instance inverse-recipe progression invariants.
func (p UnsignedOperationPlan) validReviser() bool {
	return p.highestInstance > 0 && p.newInstance == p.highestInstance+1 &&
		(p.binding.purpose == routeplan.PurposeRevision || p.binding.purpose == routeplan.PurposeNextDomain) &&
		p.binding.hasCapability &&
		p.signatureInstance == p.newInstance && p.nextSequence > 1 &&
		p.instance.Number() == p.newInstance && len(p.renderedInstance) > 0 &&
		p.generation.outcome == recipe.GenerationOutcomeRecipe &&
		p.generation.bodyOutcome.Known() && p.generation.decoded > 0 && p.generation.canonical > 0 &&
		p.modifications.initialized && p.sizes.protocolFields > p.sizes.signatureFields
}

// Role returns the exact hash-derived role.
func (p UnsignedOperationPlan) Role() DerivedRole { return p.role }

// HighestInstance returns the highest inherited instance number.
func (p UnsignedOperationPlan) HighestInstance() uint64 { return p.highestInstance }

// NewInstanceNumber returns the generated instance number or zero.
func (p UnsignedOperationPlan) NewInstanceNumber() uint64 { return p.newInstance }

// HasNewInstance reports whether the plan emits one Message-Instance field.
func (p UnsignedOperationPlan) HasNewInstance() bool { return p.newInstance != 0 }

// NextSequence returns the exactly reserved new signature sequence.
func (p UnsignedOperationPlan) NextSequence() uint64 { return p.nextSequence }

// SignatureInstance returns the instance referenced by the future signature.
func (p UnsignedOperationPlan) SignatureInstance() uint64 { return p.signatureInstance }

// CurrentHashes returns the exact current canonical digest tuple.
func (p UnsignedOperationPlan) CurrentHashes() HashTuple { return p.hashes }

// GenerationFacts returns bounded inverse-generation facts.
func (p UnsignedOperationPlan) GenerationFacts() PlanGenerationFacts { return p.generation }

// ModificationFacts returns exact sealed policy-comparison facts.
func (p UnsignedOperationPlan) ModificationFacts() ModificationFacts { return p.modifications }

// MessageInstance returns the immutable generated instance model when present.
func (p UnsignedOperationPlan) MessageInstance() (instance.MessageInstance, bool) {
	return p.instance, p.HasNewInstance() && p.Valid()
}

// RenderedInstance returns detached exact Message-Instance field bytes.
func (p UnsignedOperationPlan) RenderedInstance() []byte { return bytes.Clone(p.renderedInstance) }

// SizeFacts returns exact known pre-sign sizes and reserved counts.
func (p UnsignedOperationPlan) SizeFacts() PlanSizeFacts { return p.sizes }

// operationTimestamp returns the one verifier-owned timestamp bound to the plan.
func (p UnsignedOperationPlan) operationTimestamp() uint64 { return p.instant.UnixSeconds() }

// operationInstant returns the verifier-owned instant bound to this plan.
func (p UnsignedOperationPlan) operationInstant() verify.RevisionInstant { return p.instant }

// matchesOperation rebinds an unsigned plan to exact source, ticket, and capability state.
func (p UnsignedOperationPlan) matchesOperation(message rawmsg.Message, ticket routeplan.CopyTicket, capability VerifiedRevisionInput) bool {
	if !p.Valid() || !message.Initialized() || !ticket.Valid() || ticket.Purpose() != p.binding.purpose {
		return false
	}
	raw := message.RawBytes()
	hasCapability := capability.Valid()
	if !p.binding.hasCapability && !capability.IsZero() {
		return false
	}
	if p.binding.hasCapability && !hasCapability {
		return false
	}
	seal := [sha256.Size]byte{}
	if hasCapability {
		seal = capability.seal
	}
	capabilityMatches := !hasCapability ||
		subtle.ConstantTimeCompare(seal[:], p.binding.capabilitySeal[:]) == 1
	return sha256.Sum256(raw) == p.binding.sourceDigest &&
		ticket.ParentIdentity() == p.binding.parentID &&
		ticket.TicketIdentity() == p.binding.ticketID &&
		ticket.BindingIdentity() == p.binding.ticketBinding &&
		hasCapability == p.binding.hasCapability && capabilityMatches &&
		ticket.MatchesSource(raw)
}

// newOperationPlanBinding captures exact immutable operation identities.
func newOperationPlanBinding(message rawmsg.Message, ticket routeplan.CopyTicket, capability VerifiedRevisionInput) operationPlanBinding {
	raw := message.RawBytes()
	binding := operationPlanBinding{
		sourceDigest: sha256.Sum256(raw), parentID: ticket.ParentIdentity(),
		ticketID: ticket.TicketIdentity(), ticketBinding: ticket.BindingIdentity(),
		purpose: ticket.Purpose(), initialized: true,
	}
	if capability.Valid() {
		binding.capabilitySeal = capability.seal
		binding.hasCapability = true
	}
	return binding
}

// String returns a constant secret-safe plan summary.
func (p UnsignedOperationPlan) String() string { return "signing.UnsignedOperationPlan{redacted}" }

// GoString returns a constant secret-safe plan Go representation.
func (p UnsignedOperationPlan) GoString() string { return p.String() }

// Format routes every plan formatting form through the redacted summary.
func (p UnsignedOperationPlan) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, p.String())
}

// HashPlanCoordinator owns pure Section 9.1 planning dependencies.
type HashPlanCoordinator struct {
	revision      RevisionVerifier
	generator     recipe.Generator
	parser        recipe.Parser
	applier       recipe.Applier
	canonicalizer canonical.Canonicalizer
	limits        Limits
	initialized   bool
}

// NewHashPlanCoordinator constructs one immutable pure hash-plan coordinator.
func NewHashPlanCoordinator(revision RevisionVerifier, generationLimits recipe.GenerationLimits, limits Limits) (HashPlanCoordinator, error) {
	resolved, err := limits.normalized()
	if err != nil || !revision.valid() {
		return HashPlanCoordinator{}, newError(ErrorCodeInvalidOptions, ErrorLocation{Phase: PhaseOptions}, ErrorDetails{})
	}
	generator, err := recipe.NewGenerator(generationLimits, canonical.NewHeaderRelevance())
	if err != nil || generator.Limits().RecipeLimits.MaxDecodedRecipeBytes < resolved.MaxDecodedRecipeBytes {
		return HashPlanCoordinator{}, newError(ErrorCodeInvalidOptions, ErrorLocation{Phase: PhaseOptions}, ErrorDetails{})
	}
	canonicalLimits := canonical.DefaultLimits()
	canonicalLimits.MaxBodyInputBytes = resolved.MaxMessageBytes
	canonicalLimits.MaxHeaderInputBytes = min(resolved.MaxHeaderBytes, canonicalLimits.MaxHeaderInputBytes)
	canonicalizer, err := canonical.NewCanonicalizer(canonical.WithLimits(canonicalLimits))
	if err != nil {
		return HashPlanCoordinator{}, newError(ErrorCodeInvalidOptions, ErrorLocation{Phase: PhaseOptions}, ErrorDetails{})
	}
	parser, err := recipe.NewParser(generator.Limits().RecipeLimits)
	if err != nil {
		return HashPlanCoordinator{}, newError(ErrorCodeInvalidOptions, ErrorLocation{Phase: PhaseOptions}, ErrorDetails{})
	}
	applier, err := recipe.NewApplier(generator.Limits().RecipeLimits)
	if err != nil {
		return HashPlanCoordinator{}, newError(ErrorCodeInvalidOptions, ErrorLocation{Phase: PhaseOptions}, ErrorDetails{})
	}
	return HashPlanCoordinator{
		revision: revision, generator: generator, parser: parser, applier: applier, canonicalizer: canonicalizer,
		limits: resolved, initialized: true,
	}, nil
}

// String returns a constant secret-safe coordinator summary.
func (c HashPlanCoordinator) String() string { return "signing.HashPlanCoordinator{redacted}" }

// GoString returns a constant secret-safe coordinator Go representation.
func (c HashPlanCoordinator) GoString() string { return c.String() }

// Format routes every coordinator formatting form through the redacted summary.
func (c HashPlanCoordinator) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, c.String())
}

// PlanOriginator derives the sole legal origin plan without invoking external services.
func (c HashPlanCoordinator) PlanOriginator(ctx context.Context, request OriginatorPlanRequest) (UnsignedOperationPlan, error) {
	return c.planInitial(ctx, request, routeplan.PurposeOrigin)
}

// PlanDeliveryStatus derives an initial DSN plan after a dedicated evidence
// boundary has authorized its otherwise null reverse-path envelope.
func (c HashPlanCoordinator) PlanDeliveryStatus(ctx context.Context, request OriginatorPlanRequest) (UnsignedOperationPlan, error) {
	return c.planInitial(ctx, request, routeplan.PurposeDeliveryStatus)
}

// planInitial derives one initial instance under the exact route purpose that
// has already authorized the otherwise identical hash and signature plan.
func (c HashPlanCoordinator) planInitial(
	ctx context.Context,
	request OriginatorPlanRequest,
	purpose routeplan.Purpose,
) (UnsignedOperationPlan, error) {
	if err := c.validateBase(ctx, request.Message, request.Ticket, purpose); err != nil {
		return UnsignedOperationPlan{}, err
	}
	if len(revisionProtocolFields(request.Message)) != 0 {
		return UnsignedOperationPlan{}, newError(ErrorCodeProtocolTampering, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	hashes, canonicalWork, err := c.currentHashes(ctx, request.Message)
	if err != nil {
		return UnsignedOperationPlan{}, err
	}
	if canonicalWork > c.limits.MaxCanonicalWorkBytes {
		return UnsignedOperationPlan{}, limitError(LimitNameMaxCanonicalWorkBytes, c.limits.MaxCanonicalWorkBytes, canonicalWork)
	}
	model, rendered, sizes, err := c.buildInstanceAndSizes(request.Message, 1, hashes, nil, 1, 1)
	if err != nil {
		return UnsignedOperationPlan{}, err
	}
	if err := ctx.Err(); err != nil {
		return UnsignedOperationPlan{}, err
	}
	instant, err := c.revision.CaptureOperationInstant()
	if err != nil {
		return UnsignedOperationPlan{}, err
	}
	if err := ctx.Err(); err != nil {
		return UnsignedOperationPlan{}, err
	}
	return UnsignedOperationPlan{
		role: RoleOriginator, newInstance: 1, nextSequence: 1, signatureInstance: 1,
		hashes: hashes, generation: unchangedPlanGenerationFacts(
			canonicalWork, canonicalWork, recipe.RejectUnavailableBody, recipe.CopyOnly,
		), instance: model, renderedInstance: rendered, sizes: sizes,
		binding: newOperationPlanBinding(request.Message, request.Ticket, VerifiedRevisionInput{}),
		instant: instant, initialized: true,
	}, nil
}

// PlanExisting derives forwarding or revision solely from the exact SHA-256 tuple.
func (c HashPlanCoordinator) PlanExisting(ctx context.Context, request ExistingPlanRequest) (UnsignedOperationPlan, error) {
	return c.planExisting(ctx, request, routeplan.PurposeRevision)
}

// PlanNextDomain derives the same exact hash gate for one terminal next-domain operation.
func (c HashPlanCoordinator) PlanNextDomain(ctx context.Context, request ExistingPlanRequest) (UnsignedOperationPlan, error) {
	return c.planExisting(ctx, request, routeplan.PurposeNextDomain)
}

type preparedExistingPlan struct {
	facts         verify.RevisionFacts
	bodyPolicy    recipe.BodyUnavailablePolicy
	literalPolicy recipe.LiteralDisclosurePolicy
	instant       verify.RevisionInstant
	nextSequence  uint64
}

// planExisting applies the shared hash and recipe plan under one closed route purpose.
func (c HashPlanCoordinator) planExisting(ctx context.Context, request ExistingPlanRequest, purpose routeplan.Purpose) (UnsignedOperationPlan, error) {
	prepared, err := c.prepareExistingPlan(ctx, request, purpose)
	if err != nil {
		return UnsignedOperationPlan{}, err
	}
	facts := prepared.facts
	bodyPolicy := prepared.bodyPolicy
	literalPolicy := prepared.literalPolicy
	instant := prepared.instant
	nextSequence := prepared.nextSequence
	hashes, currentCanonicalWork, err := c.currentHashes(ctx, request.Message)
	if err != nil {
		return UnsignedOperationPlan{}, err
	}
	previousHashes := facts.Hashes()
	if !previousHashes.Valid() || previousHashes.Instance() != facts.HighestInstance() {
		return UnsignedOperationPlan{}, newError(ErrorCodeHashStateAmbiguity, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	modifications, err := c.modificationFacts(ctx, request.Capability, request.Ticket, request.Message, hashes)
	if err != nil {
		return UnsignedOperationPlan{}, err
	}
	canonicalWork, ok := checkedAdd(facts.Usage().CanonicalBytes(), currentCanonicalWork)
	if !ok || canonicalWork > c.limits.MaxCanonicalWorkBytes {
		return UnsignedOperationPlan{}, limitError(LimitNameMaxCanonicalWorkBytes, c.limits.MaxCanonicalWorkBytes, canonicalWork)
	}
	if hashes.header == previousHashes.HeaderDigest() && hashes.body == previousHashes.BodyDigest() {
		sizes, sizeErr := c.preflightSizes(request.Message, 0, facts.InstanceCount(), facts.SignatureCount()+1)
		if sizeErr != nil {
			return UnsignedOperationPlan{}, sizeErr
		}
		return UnsignedOperationPlan{
			role: RoleHashUnchangedForwarder, highestInstance: facts.HighestInstance(),
			nextSequence: nextSequence, signatureInstance: facts.HighestInstance(), hashes: hashes,
			generation:    unchangedPlanGenerationFacts(canonicalWork, currentCanonicalWork, bodyPolicy, literalPolicy),
			modifications: modifications,
			sizes:         sizes,
			binding:       newOperationPlanBinding(request.Message, request.Ticket, request.Capability),
			instant:       instant, initialized: true,
		}, nil
	}
	plan, err := c.planRevision(
		ctx, request, facts, hashes, modifications, canonicalWork, currentCanonicalWork, bodyPolicy, literalPolicy,
	)
	if err != nil {
		return UnsignedOperationPlan{}, err
	}
	plan.binding = newOperationPlanBinding(request.Message, request.Ticket, request.Capability)
	plan.instant = instant
	return plan, nil
}

// prepareExistingPlan validates and consumes the shared sealed predecessor state.
func (c HashPlanCoordinator) prepareExistingPlan(
	ctx context.Context,
	request ExistingPlanRequest,
	purpose routeplan.Purpose,
) (preparedExistingPlan, error) {
	if purpose != routeplan.PurposeRevision && purpose != routeplan.PurposeNextDomain {
		return preparedExistingPlan{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if err := c.validateBase(ctx, request.Message, request.Ticket, purpose); err != nil {
		return preparedExistingPlan{}, err
	}
	if !request.Capability.Valid() || !request.Ticket.MatchesRevisionBinding(request.Capability.seal[:]) {
		return preparedExistingPlan{}, newError(ErrorCodeCapabilityMismatch, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	state := request.Capability.proof.State()
	if state != verify.RevisionProofVerified && state != verify.RevisionProofTerminalNextDomainAuthorizationRequired {
		return preparedExistingPlan{}, newError(ErrorCodeAuthorizationDenied, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	bodyPolicy := request.BodyPolicy
	literalPolicy := request.LiteralPolicy
	if !bodyPolicy.Known() || !literalPolicy.Known() {
		return preparedExistingPlan{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	instant, instantErr := c.revision.CaptureOperationInstant()
	if instantErr != nil {
		return preparedExistingPlan{}, instantErr
	}
	if err := c.revision.ConsumeVerifiedRevisionInputAt(ctx, request.Capability, request.Message, instant); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return preparedExistingPlan{}, contextErr
		}
		var signingErr *Error
		if errors.As(err, &signingErr) {
			return preparedExistingPlan{}, signingErr
		}
		return preparedExistingPlan{}, boundedPlanError(err, ErrorCodeCapabilityMismatch)
	}
	if err := ctx.Err(); err != nil {
		return preparedExistingPlan{}, err
	}
	facts := request.Capability.proof.Facts()
	if !facts.Valid() || facts.HighestInstance() == 0 || facts.HighestSequence() == 0 {
		return preparedExistingPlan{}, newError(ErrorCodeSequenceFailure, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if facts.InstanceCount() > c.limits.MaxInstances {
		return preparedExistingPlan{}, limitError(LimitNameMaxInstances, c.limits.MaxInstances, facts.InstanceCount())
	}
	if facts.SignatureCount() >= c.limits.MaxSignatures {
		return preparedExistingPlan{}, limitError(LimitNameMaxSignatures, c.limits.MaxSignatures, facts.SignatureCount()+1)
	}
	_, nextSequence, err := nextProgression(facts.HighestInstance(), facts.HighestSequence(), false)
	if err != nil {
		return preparedExistingPlan{}, err
	}
	return preparedExistingPlan{
		facts: facts, bodyPolicy: bodyPolicy, literalPolicy: literalPolicy,
		instant: instant, nextSequence: nextSequence,
	}, nil
}

// planRevision builds the sole one-instance inverse-recipe branch after the exact tuple mismatch.
func (c HashPlanCoordinator) planRevision(ctx context.Context, request ExistingPlanRequest, facts verify.RevisionFacts, hashes HashTuple, modifications ModificationFacts, canonicalWork, currentCanonicalWork int, bodyPolicy recipe.BodyUnavailablePolicy, literalPolicy recipe.LiteralDisclosurePolicy) (UnsignedOperationPlan, error) {
	newInstance, nextSequence, err := nextProgression(facts.HighestInstance(), facts.HighestSequence(), true)
	if err != nil || facts.InstanceCount() >= c.limits.MaxInstances {
		if err != nil {
			return UnsignedOperationPlan{}, err
		}
		return UnsignedOperationPlan{}, limitError(LimitNameMaxInstances, c.limits.MaxInstances, facts.InstanceCount()+1)
	}
	previousMessage, err := rawmsg.Parse(request.Capability.raw)
	if err != nil {
		return UnsignedOperationPlan{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	previousState, err := recipe.NewState(previousMessage)
	if err != nil {
		return UnsignedOperationPlan{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	currentState, err := recipe.NewState(request.Message)
	if err != nil {
		return UnsignedOperationPlan{}, newError(ErrorCodeMalformedInput, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	generationRequest, err := recipe.NewGenerationRequest(previousState, currentState, bodyPolicy, literalPolicy)
	if err != nil {
		return UnsignedOperationPlan{}, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	generation, usage, err := c.generator.Generate(generationRequest)
	if err != nil {
		return UnsignedOperationPlan{}, mapRecipePlanError(err)
	}
	if err := ctx.Err(); err != nil {
		return UnsignedOperationPlan{}, err
	}
	if !generation.Valid() || generation.Outcome() != recipe.GenerationOutcomeRecipe {
		return UnsignedOperationPlan{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	decoded := generation.DecodedJSON()
	if len(decoded) > c.limits.MaxDecodedRecipeBytes {
		return UnsignedOperationPlan{}, limitError(LimitNameMaxDecodedRecipeBytes, c.limits.MaxDecodedRecipeBytes, len(decoded))
	}
	previousHashes := facts.Hashes()
	proof, err := c.proveGeneratedRecipe(
		ctx, currentState, generation, previousHashes.HeaderDigest(), previousHashes.BodyDigest(), bodyPolicy,
	)
	if err != nil {
		return UnsignedOperationPlan{}, err
	}
	canonicalWork, ok := checkedAdd(canonicalWork, proof.canonicalWork)
	if !ok || canonicalWork > c.limits.MaxCanonicalWorkBytes {
		return UnsignedOperationPlan{}, limitError(LimitNameMaxCanonicalWorkBytes, c.limits.MaxCanonicalWorkBytes, canonicalWork)
	}
	model, rendered, sizes, err := c.buildInstanceAndSizes(
		request.Message, newInstance, hashes, decoded, facts.InstanceCount()+1, facts.SignatureCount()+1,
	)
	if err != nil {
		return UnsignedOperationPlan{}, err
	}
	if err := ctx.Err(); err != nil {
		return UnsignedOperationPlan{}, err
	}
	return UnsignedOperationPlan{
		role: RoleReviser, highestInstance: facts.HighestInstance(), newInstance: newInstance,
		nextSequence: nextSequence, signatureInstance: newInstance, hashes: hashes,
		generation:    planGenerationFacts(generation, usage, proof, canonicalWork, currentCanonicalWork, bodyPolicy, literalPolicy),
		modifications: modifications, instance: model, renderedInstance: rendered,
		sizes: sizes, initialized: true,
	}, nil
}

// validateBase enforces exact source, purpose, bounds, and cancellation before planning.
func (c HashPlanCoordinator) validateBase(ctx context.Context, message rawmsg.Message, ticket routeplan.CopyTicket, purpose routeplan.Purpose) error {
	if ctx == nil || !c.valid() || !message.Initialized() || !ticket.Valid() || ticket.Purpose() != purpose {
		return newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !ticket.MatchesSource(message.RawBytes()) {
		return newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	metadata := message.Metadata()
	if metadata.HeaderBytes > c.limits.MaxHeaderBytes {
		return limitError(LimitNameMaxHeaderBytes, c.limits.MaxHeaderBytes, metadata.HeaderBytes)
	}
	if metadata.StoredBytes > c.limits.MaxMessageBytes {
		return limitError(LimitNameMaxMessageBytes, c.limits.MaxMessageBytes, metadata.StoredBytes)
	}
	generatedFields := 1
	if purpose == routeplan.PurposeOrigin || purpose == routeplan.PurposeDeliveryStatus {
		generatedFields = 2
	}
	finalHeaderFields, ok := checkedAdd(metadata.HeaderFields, generatedFields)
	if !ok || finalHeaderFields > c.limits.MaxHeaderFields {
		return limitError(LimitNameMaxHeaderFields, c.limits.MaxHeaderFields, finalHeaderFields)
	}
	headers := message.Headers()
	if signatures := len(headers.FieldsByName(signature.HeaderName)); signatures >= c.limits.MaxSignatures {
		return limitError(LimitNameMaxSignatures, c.limits.MaxSignatures, signatures+1)
	}
	protocolFields := len(revisionProtocolFields(message))
	finalProtocolFields, ok := checkedAdd(protocolFields, generatedFields)
	if !ok || finalProtocolFields > c.limits.MaxProtocolFields {
		return limitError(LimitNameMaxProtocolFields, c.limits.MaxProtocolFields, finalProtocolFields)
	}
	return nil
}

// currentHashes computes the sole authoritative exact SHA-256 tuple.
func (c HashPlanCoordinator) currentHashes(ctx context.Context, message rawmsg.Message) (HashTuple, int, error) {
	if err := ctx.Err(); err != nil {
		return HashTuple{}, 0, err
	}
	headerResult, err := c.canonicalizer.HeaderHashFromMessage(message)
	if err != nil {
		return HashTuple{}, 0, newError(ErrorCodeMalformedInput, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if err := ctx.Err(); err != nil {
		return HashTuple{}, 0, err
	}
	bodyResult, err := c.canonicalizer.BodyHashFromMessage(message)
	if err != nil {
		return HashTuple{}, 0, newError(ErrorCodeMalformedInput, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if err := ctx.Err(); err != nil {
		return HashTuple{}, 0, err
	}
	header, headerOK := headerResult.Digest()
	body, bodyOK := bodyResult.Digest()
	if !headerOK || !bodyOK || header.Len() != sha256.Size || body.Len() != sha256.Size {
		return HashTuple{}, 0, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	var tuple HashTuple
	copy(tuple.header[:], header.Bytes())
	copy(tuple.body[:], body.Bytes())
	tuple.initialized = true
	work, ok := checkedAdd(headerResult.CanonicalBytes().Len(), bodyResult.CanonicalBytes().Len())
	if !ok {
		return HashTuple{}, 0, limitError(LimitNameMaxCanonicalWorkBytes, c.limits.MaxCanonicalWorkBytes, math.MaxInt)
	}
	return tuple, work, nil
}

// modificationFacts derives donotmodify evidence independently from the hash gate.
func (c HashPlanCoordinator) modificationFacts(ctx context.Context, capability VerifiedRevisionInput, ticket routeplan.CopyTicket, current rawmsg.Message, hashes HashTuple) (ModificationFacts, error) {
	if err := ctx.Err(); err != nil {
		return ModificationFacts{}, err
	}
	previous, err := rawmsg.Parse(capability.raw)
	if err != nil {
		return ModificationFacts{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	existingChanged := !previousHeadersRemain(previous.Headers(), current.Headers())
	if err := ctx.Err(); err != nil {
		return ModificationFacts{}, err
	}
	previousBody := capability.proof.Facts().Hashes().BodyDigest()
	return ModificationFacts{
		bodyChanged: hashes.body != previousBody, existingHeadersChanged: existingChanged,
		initialized: true, capabilitySeal: capability.seal, parentID: ticket.ParentIdentity(),
		ticketID: ticket.TicketIdentity(), ticketBinding: ticket.BindingIdentity(),
	}, nil
}

// previousHeadersRemain reports exact prior-field subsequence preservation with additions allowed.
func previousHeadersRemain(previous, current rawmsg.HeaderBlock) bool {
	priorFields := previous.Fields()
	currentFields := current.Fields()
	next := 0
	for _, candidate := range currentFields {
		if next < len(priorFields) && bytes.Equal(priorFields[next].OriginalBytes(), candidate.OriginalBytes()) {
			next++
		}
	}
	return next == len(priorFields)
}

// buildInstanceAndSizes constructs and renders through instance ownership after exact preflight.
func (c HashPlanCoordinator) buildInstanceAndSizes(message rawmsg.Message, number uint64, hashes HashTuple, decoded []byte, instances, signatures int) (instance.MessageInstance, []byte, PlanSizeFacts, error) {
	recipePresent := len(decoded) > 0
	fieldBytes, err := PreflightMessageInstanceField(number, len(decoded), recipePresent, c.limits)
	if err != nil {
		return instance.MessageInstance{}, nil, PlanSizeFacts{}, err
	}
	sizes, err := c.preflightSizes(message, fieldBytes, instances, signatures)
	if err != nil {
		return instance.MessageInstance{}, nil, PlanSizeFacts{}, err
	}
	model, err := instance.NewForSigning(instance.SigningRequest{
		Number: number, HeaderHash: hashes.header[:], BodyHash: hashes.body[:],
		Recipe: decoded, RecipePresent: recipePresent,
	})
	if err != nil {
		return instance.MessageInstance{}, nil, PlanSizeFacts{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	rendered, err := model.Render(instance.RenderLimits{
		MaxFieldBytes: c.limits.MaxFieldBytes, MaxLineBytes: c.limits.MaxLineBytes,
		MaxRecipeBytes: c.limits.MaxDecodedRecipeBytes,
	})
	if err != nil || len(rendered) != fieldBytes {
		return instance.MessageInstance{}, nil, PlanSizeFacts{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	return model, rendered, sizes, nil
}

// preflightSizes checks exact known bytes and reserves the mandatory signature cardinality.
func (c HashPlanCoordinator) preflightSizes(message rawmsg.Message, instanceBytes, instances, signatures int) (PlanSizeFacts, error) {
	if instances < 0 || signatures <= 0 || instanceBytes < 0 {
		return PlanSizeFacts{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if instances > c.limits.MaxInstances {
		return PlanSizeFacts{}, limitError(LimitNameMaxInstances, c.limits.MaxInstances, instances)
	}
	if signatures > c.limits.MaxSignatures {
		return PlanSizeFacts{}, limitError(LimitNameMaxSignatures, c.limits.MaxSignatures, signatures)
	}
	protocolFields, ok := checkedAdd(instances, signatures)
	if !ok || protocolFields > c.limits.MaxProtocolFields {
		return PlanSizeFacts{}, limitError(LimitNameMaxProtocolFields, c.limits.MaxProtocolFields, protocolFields)
	}
	generatedFields := 1
	if instanceBytes > 0 {
		generatedFields++
	}
	finalHeaderFields, ok := checkedAdd(message.Metadata().HeaderFields, generatedFields)
	if !ok || finalHeaderFields > c.limits.MaxHeaderFields {
		return PlanSizeFacts{}, limitError(LimitNameMaxHeaderFields, c.limits.MaxHeaderFields, finalHeaderFields)
	}
	baseHeaderBytes, ok := checkedAdd(message.Metadata().HeaderBytes, instanceBytes)
	if !ok || baseHeaderBytes >= c.limits.MaxHeaderBytes {
		return PlanSizeFacts{}, limitError(LimitNameMaxHeaderBytes, c.limits.MaxHeaderBytes, baseHeaderBytes)
	}
	baseMessageBytes, ok := checkedAdd(message.Metadata().StoredBytes, instanceBytes)
	if !ok || baseMessageBytes >= c.limits.MaxMessageBytes {
		return PlanSizeFacts{}, limitError(LimitNameMaxMessageBytes, c.limits.MaxMessageBytes, baseMessageBytes)
	}
	signatureAllowance, signatureLimit := signatureFieldAllowance(
		c.limits.MaxFieldBytes,
		c.limits.MaxHeaderBytes-baseHeaderBytes,
		c.limits.MaxMessageBytes-baseMessageBytes,
	)
	if signatureAllowance <= 0 {
		return PlanSizeFacts{}, limitError(LimitNameMaxFieldBytes, c.limits.MaxFieldBytes, 0)
	}
	return PlanSizeFacts{
		instanceFieldBytes: instanceBytes, signatureFieldBytes: signatureAllowance,
		headerBytes: baseHeaderBytes + signatureAllowance, messageBytes: baseMessageBytes + signatureAllowance,
		protocolFields: protocolFields, signatureFields: signatures,
		finalHeaderFields: finalHeaderFields,
		signatureLimit:    signatureLimit, initialized: true,
	}, nil
}

// signatureFieldAllowance selects the narrowest dimension with deterministic field-header-message ties.
func signatureFieldAllowance(field, header, message int) (int, LimitName) {
	allowance, name := field, LimitNameMaxFieldBytes
	if header < allowance {
		allowance, name = header, LimitNameMaxHeaderBytes
	}
	if message < allowance {
		allowance, name = message, LimitNameMaxMessageBytes
	}
	return allowance, name
}

type generatedRecipeProof struct {
	canonicalWork    int
	parseUsage       recipe.Usage
	applicationUsage recipe.Usage
}

// proveGeneratedRecipe independently reparses, reapplies, and rehashes the exact generated JSON.
func (c HashPlanCoordinator) proveGeneratedRecipe(ctx context.Context, current recipe.State, generation recipe.Generation, previousHeader, previousBody [sha256.Size]byte, bodyPolicy recipe.BodyUnavailablePolicy) (generatedRecipeProof, error) {
	if err := ctx.Err(); err != nil {
		return generatedRecipeProof{}, err
	}
	decoded := generation.DecodedJSON()
	parsed, parseUsage, err := c.parser.Parse(decoded)
	if err != nil || !parsed.Valid() {
		return generatedRecipeProof{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if err := ctx.Err(); err != nil {
		return generatedRecipeProof{}, err
	}
	reconstructed, applyUsage, err := c.applier.Apply(current, parsed)
	if err != nil || !reconstructed.Valid() {
		return generatedRecipeProof{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	if err := ctx.Err(); err != nil {
		return generatedRecipeProof{}, err
	}
	headerResult, err := c.canonicalizer.HeaderHash(reconstructed.Headers())
	if err != nil {
		return generatedRecipeProof{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	headerDigest, ok := headerResult.Digest()
	if !ok || headerDigest.Len() != sha256.Size || !bytes.Equal(headerDigest.Bytes(), previousHeader[:]) {
		return generatedRecipeProof{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	canonicalWork := headerResult.CanonicalBytes().Len()
	if generation.BodyOutcome() == recipe.BodyGenerationUnavailable {
		if bodyPolicy != recipe.AllowUnavailableBody || reconstructed.BodyState() != recipe.BodyAvailabilityUnavailable {
			return generatedRecipeProof{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
		}
		return generatedRecipeProof{
			canonicalWork: canonicalWork, parseUsage: parseUsage, applicationUsage: applyUsage,
		}, ctx.Err()
	}
	body, ok := reconstructed.Body()
	if !ok {
		return generatedRecipeProof{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	bodyResult, err := c.canonicalizer.BodyHash(body)
	if err != nil {
		return generatedRecipeProof{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	bodyDigest, ok := bodyResult.Digest()
	if !ok || bodyDigest.Len() != sha256.Size || !bytes.Equal(bodyDigest.Bytes(), previousBody[:]) {
		return generatedRecipeProof{}, newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	canonicalWork, ok = checkedAdd(canonicalWork, bodyResult.CanonicalBytes().Len())
	if !ok {
		return generatedRecipeProof{}, limitError(LimitNameMaxCanonicalWorkBytes, c.limits.MaxCanonicalWorkBytes, math.MaxInt)
	}
	return generatedRecipeProof{
		canonicalWork: canonicalWork, parseUsage: parseUsage, applicationUsage: applyUsage,
	}, ctx.Err()
}

// nextProgression computes bounded m/i progression without attacker-controlled iteration.
func nextProgression(highestInstance, highestSequence uint64, newInstance bool) (uint64, uint64, error) {
	if highestSequence == 0 || highestSequence == math.MaxUint64 ||
		newInstance && (highestInstance == 0 || highestInstance == math.MaxUint64) {
		return 0, 0, newError(ErrorCodeSequenceFailure, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	nextInstance := uint64(0)
	if newInstance {
		nextInstance = highestInstance + 1
	}
	return nextInstance, highestSequence + 1, nil
}

// unchangedPlanGenerationFacts constructs explicit no-recipe facts.
func unchangedPlanGenerationFacts(canonicalWork, currentCanonicalWork int, bodyPolicy recipe.BodyUnavailablePolicy, literalPolicy recipe.LiteralDisclosurePolicy) PlanGenerationFacts {
	return PlanGenerationFacts{
		outcome: recipe.GenerationOutcomeUnchanged, bodyOutcome: recipe.BodyGenerationUnchanged,
		bodyPolicy: bodyPolicy, literalPolicy: literalPolicy,
		canonical: canonicalWork, currentCanonical: currentCanonicalWork,
		initialized: canonicalWork > 0 && currentCanonicalWork > 0,
	}
}

// planGenerationFacts projects one proved recipe result into bounded plan facts.
func planGenerationFacts(generation recipe.Generation, usage recipe.GenerationUsage, proof generatedRecipeProof, canonicalWork, currentCanonicalWork int, bodyPolicy recipe.BodyUnavailablePolicy, literalPolicy recipe.LiteralDisclosurePolicy) PlanGenerationFacts {
	return PlanGenerationFacts{
		outcome: generation.Outcome(), bodyOutcome: generation.BodyOutcome(),
		unavailable: generation.BodyUnavailableReason(), decoded: len(generation.DecodedJSON()),
		bodyPolicy: bodyPolicy, literalPolicy: literalPolicy,
		canonical: canonicalWork, currentCanonical: currentCanonicalWork,
		usage: usage, parseUsage: proof.parseUsage,
		applyUsage: proof.applicationUsage,
		initialized: generation.Valid() && usage.Valid() && proof.parseUsage.Valid() &&
			proof.applicationUsage.Valid() && canonicalWork > 0,
	}
}

// mapRecipePlanError preserves bounded recipe failure classes without retaining protected causes.
func mapRecipePlanError(err error) error {
	switch {
	case recipe.IsErrorCode(err, recipe.ErrorCodeLimitExceeded):
		return newError(ErrorCodeLimitExceeded, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	case recipe.IsErrorCode(err, recipe.ErrorCodeInvalidPolicy),
		recipe.IsErrorCode(err, recipe.ErrorCodeHeaderUnrepresentable),
		recipe.IsErrorCode(err, recipe.ErrorCodeBodyUnrepresentable):
		return newError(ErrorCodePolicyRestriction, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	case recipe.IsErrorCode(err, recipe.ErrorCodeInvalidGenerator),
		recipe.IsErrorCode(err, recipe.ErrorCodeInvalidState),
		recipe.IsErrorCode(err, recipe.ErrorCodeSerializationFailure),
		recipe.IsErrorCode(err, recipe.ErrorCodeGeneratedOutputInvariant),
		recipe.IsErrorCode(err, recipe.ErrorCodeReconstructionMismatch),
		recipe.IsErrorCode(err, recipe.ErrorCodeHeaderRelevance):
		return newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	default:
		return newError(ErrorCodeMalformedInput, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
}

// boundedPlanError removes component causes and protected values from signing diagnostics.
func boundedPlanError(err error, fallback ErrorCode) error {
	if err == nil {
		return nil
	}
	return newError(fallback, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
}

// valid reports whether the coordinator retains coherent immutable dependencies.
func (c HashPlanCoordinator) valid() bool {
	return c.initialized && c.revision.valid() && c.generator.Valid() &&
		c.parser.Valid() && c.applier.Valid() && c.canonicalizer.Options().Validate() == nil &&
		c.limits.Validate() == nil
}
