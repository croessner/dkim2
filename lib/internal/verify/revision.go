package verify

import (
	"context"
	"fmt"
	"io"
	"math"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/signature"
)

// RevisionProofOutcome identifies a closed all-hop verification result.
type RevisionProofOutcome string

const (
	// RevisionProofVerified reports complete ordinary all-hop proof.
	RevisionProofVerified RevisionProofOutcome = "verified"
	// RevisionProofTerminalNextDomainAuthorizationRequired reports clean proof ending in terminal nd=.
	RevisionProofTerminalNextDomainAuthorizationRequired RevisionProofOutcome = "terminal_next_domain_authorization_required"
	// RevisionProofProtocolRejected reports malformed, mismatched, expired, or otherwise failed protocol evidence.
	RevisionProofProtocolRejected RevisionProofOutcome = "protocol_rejected"
	// RevisionProofInvalidRecipeJSON reports malformed authenticated r= JSON.
	RevisionProofInvalidRecipeJSON RevisionProofOutcome = "invalid_recipe_json"
	// RevisionProofHashMismatch reports a supported current or historical hash mismatch.
	RevisionProofHashMismatch RevisionProofOutcome = "hash_mismatch"
	// RevisionProofSignatureMismatch reports a supported inherited signature mismatch.
	RevisionProofSignatureMismatch RevisionProofOutcome = "signature_mismatch"
	// RevisionProofUnsupported reports an unsupported-only inherited signature field or hash tuple.
	RevisionProofUnsupported RevisionProofOutcome = "unsupported"
	// RevisionProofProviderTemporary reports retryable public-key provider failure.
	RevisionProofProviderTemporary RevisionProofOutcome = "provider_temporary"
	// RevisionProofProviderRejected reports permanent public-key provider or key rejection.
	RevisionProofProviderRejected RevisionProofOutcome = "provider_rejected"
	// RevisionProofProviderContract reports an inconsistent provider result/error pair.
	RevisionProofProviderContract RevisionProofOutcome = "provider_contract"
	// RevisionProofLimitExceeded reports bounded all-hop work exhaustion.
	RevisionProofLimitExceeded RevisionProofOutcome = "limit_exceeded"
)

// Known reports whether outcome belongs to the closed revision proof vocabulary.
func (o RevisionProofOutcome) Known() bool {
	switch o {
	case RevisionProofVerified, RevisionProofTerminalNextDomainAuthorizationRequired,
		RevisionProofProtocolRejected, RevisionProofInvalidRecipeJSON, RevisionProofHashMismatch, RevisionProofSignatureMismatch,
		RevisionProofUnsupported, RevisionProofProviderTemporary,
		RevisionProofProviderRejected, RevisionProofProviderContract, RevisionProofLimitExceeded:
		return true
	default:
		return false
	}
}

// RevisionProofRevalidation identifies timestamp-only capability revalidation.
type RevisionProofRevalidation string

const (
	// RevisionProofRevalidated reports that every inherited timestamp remains valid.
	RevisionProofRevalidated RevisionProofRevalidation = "revalidated"
	// RevisionProofTimestampInvalid reports that at least one inherited timestamp is no longer valid.
	RevisionProofTimestampInvalid RevisionProofRevalidation = "timestamp_invalid"
)

// Known reports whether status belongs to the closed revalidation vocabulary.
func (s RevisionProofRevalidation) Known() bool {
	return s == RevisionProofRevalidated || s == RevisionProofTimestampInvalid
}

// RevisionFlagFacts stores bounded authenticated policy facts for one inherited signature.
type RevisionFlagFacts struct {
	doNotModify  bool
	doNotExplode bool
	feedback     bool
	feedHere     bool
	exploded     bool
}

// DoNotModify reports authenticated donotmodify presence.
func (f RevisionFlagFacts) DoNotModify() bool { return f.doNotModify }

// DoNotExplode reports authenticated donotexplode presence.
func (f RevisionFlagFacts) DoNotExplode() bool { return f.doNotExplode }

// Feedback reports authenticated feedback presence.
func (f RevisionFlagFacts) Feedback() bool { return f.feedback }

// FeedHere reports authenticated feedhere presence.
func (f RevisionFlagFacts) FeedHere() bool { return f.feedHere }

// Exploded reports authenticated exploded presence.
func (f RevisionFlagFacts) Exploded() bool { return f.exploded }

// RevisionFacts stores immutable bounded all-hop facts without content or identities.
type RevisionFacts struct {
	highestSequence, highestInstance uint64
	instanceCount, signatureCount    int
	signatures                       []RevisionSignatureFact
	hashes                           RevisionHashFacts
	envelope                         RevisionEnvelopeState
	custody                          RevisionCustodyFacts
	history                          RevisionHistoryFacts
	usage                            RevisionUsage
	initialized                      bool
}

// String returns a constant secret-safe facts summary.
func (f RevisionFacts) String() string { return "verify.RevisionFacts{redacted}" }

// GoString returns a constant secret-safe facts Go representation.
func (f RevisionFacts) GoString() string { return f.String() }

// Format routes every facts format through the redacted summary.
func (f RevisionFacts) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, f.String()) }

// Valid reports whether facts are complete and internally coherent.
func (f RevisionFacts) Valid() bool {
	if !f.initialized || f.highestSequence == 0 || f.highestInstance == 0 ||
		f.instanceCount <= 0 || f.signatureCount <= 0 ||
		f.highestSequence != uint64(f.signatureCount) || f.highestInstance != uint64(f.instanceCount) ||
		len(f.signatures) != f.signatureCount || !f.hashes.Valid() || f.hashes.instance != f.highestInstance ||
		!f.envelope.Known() || !f.custody.Valid() || len(f.custody.hops) != f.signatureCount || !f.history.Valid() || f.history.target != f.highestInstance || !f.usage.Valid() {
		return false
	}
	totalSets, supported := 0, 0
	previousInstance := uint64(0)
	for index, fact := range f.signatures {
		if !fact.Valid() || fact.sequence != uint64(index+1) || fact.instance > f.highestInstance || fact.instance < previousInstance {
			return false
		}
		previousInstance = fact.instance
		totalSets += len(fact.sets)
		for _, set := range fact.sets {
			if set.state == RevisionSetSupportedPass {
				supported++
			}
		}
	}
	terminal := f.custody.status == signature.CustodyStatusTerminalNextDomain
	return (f.envelope == RevisionEnvelopeTerminalNextDomainNotApplicable) == terminal && previousInstance == f.highestInstance && f.usage.protocolFields == f.instanceCount+f.signatureCount && f.usage.signatureSets == totalSets &&
		f.usage.keyLookups == supported && f.usage.providerCalls == supported && f.usage.history == f.history.usage
}

// HighestSequence returns the highest inherited i= value.
func (f RevisionFacts) HighestSequence() uint64 { return f.highestSequence }

// HighestInstance returns the highest inherited m= value.
func (f RevisionFacts) HighestInstance() uint64 { return f.highestInstance }

// InstanceCount returns the contiguous inherited instance count.
func (f RevisionFacts) InstanceCount() int { return f.instanceCount }

// SignatureCount returns the contiguous inherited signature count.
func (f RevisionFacts) SignatureCount() int { return f.signatureCount }

// Timestamps returns detached inherited t= values in semantic sequence order.
func (f RevisionFacts) Timestamps() []uint64 {
	result := make([]uint64, len(f.signatures))
	for index, fact := range f.signatures {
		result[index] = fact.timestamp
	}
	return result
}

// Flags returns detached authenticated flag facts in semantic sequence order.
func (f RevisionFacts) Flags() []RevisionFlagFacts {
	result := make([]RevisionFlagFacts, len(f.signatures))
	for index, fact := range f.signatures {
		result[index] = fact.flags
	}
	return result
}

// Signatures returns detached per-signature proof facts.
func (f RevisionFacts) Signatures() []RevisionSignatureFact {
	result := slices.Clone(f.signatures)
	for index := range result {
		result[index].sets = slices.Clone(result[index].sets)
	}
	return result
}

// Hashes returns locally computed canonical SHA-256 facts after current hash verification passes.
func (f RevisionFacts) Hashes() RevisionHashFacts { return f.hashes }

// Envelope returns the authenticated current-envelope result.
func (f RevisionFacts) Envelope() RevisionEnvelopeState { return f.envelope }

// Custody returns detached complete custody facts.
func (f RevisionFacts) Custody() RevisionCustodyFacts {
	result := f.custody
	result.hops = slices.Clone(result.hops)
	return result
}

// History returns detached authenticated history facts.
func (f RevisionFacts) History() RevisionHistoryFacts {
	result := f.history
	result.transitions = slices.Clone(result.transitions)
	return result
}

// Usage returns aggregate all-hop proof work.
func (f RevisionFacts) Usage() RevisionUsage { return f.usage }

// HistoryHasUnavailableBody reports whether explicit b:null created a historical proof gap.
func (f RevisionFacts) HistoryHasUnavailableBody() bool { return f.history.gap }

// clone returns detached immutable fact slices.
func (f RevisionFacts) clone() RevisionFacts {
	f.signatures = f.Signatures()
	f.custody.hops = slices.Clone(f.custody.hops)
	f.history.transitions = slices.Clone(f.history.transitions)
	return f
}

// RevisionProof is an opaque verify-owned capability input for signing-owned sealing.
type RevisionProof struct {
	state       RevisionProofOutcome
	draft       string
	facts       RevisionFacts
	replay      ReplayProjection
	verifier    VerifierProjection
	policy      TimestampPolicy
	initialized bool
}

// RevisionInstant is one opaque, verifier-captured operation time.
//
// Callers may copy this value between verification stages, but cannot
// initialize or alter its timestamp or policy binding.
type RevisionInstant struct {
	now         time.Time
	policy      TimestampPolicy
	owner       *revisionInstantOwner
	initialized bool
}

// Valid reports whether the instant was captured under the fixed revision policy.
func (i RevisionInstant) Valid() bool {
	return i.initialized && i.owner != nil && revisionTimestampPolicySafe(i.policy) && revisionClockInstantSafe(i.now)
}

// UnixSeconds returns the exact nonnegative operation timestamp.
func (i RevisionInstant) UnixSeconds() uint64 {
	if !i.Valid() {
		return 0
	}
	return uint64(i.now.Unix())
}

// Time returns the exact immutable captured instant to trusted internal consumers.
func (i RevisionInstant) Time() time.Time {
	if !i.Valid() {
		return time.Time{}
	}
	return i.now
}

// IsZero reports whether proof is the exact uninitialized zero value.
func (p RevisionProof) IsZero() bool { return reflect.ValueOf(p).IsZero() }

// Valid reports whether proof is one of the two clean all-hop states.
func (p RevisionProof) Valid() bool {
	if !p.initialized || (p.state != RevisionProofVerified && p.state != RevisionProofTerminalNextDomainAuthorizationRequired) ||
		p.draft != DraftBaseline || !p.facts.Valid() || !revisionTimestampPolicySafe(p.policy) {
		return false
	}
	terminal := p.state == RevisionProofTerminalNextDomainAuthorizationRequired
	return terminal == (p.facts.custody.status == signature.CustodyStatusTerminalNextDomain) &&
		(terminal && !p.verifier.Valid() || !terminal && p.verifier.Valid())
}

// ReplayProjection returns the sealed message-wide origin facts from complete proof.
func (p RevisionProof) ReplayProjection() (ReplayProjection, bool) {
	if !p.Valid() {
		return ReplayProjection{}, false
	}
	return p.replay.clone(), true
}

// VerifierProjection returns sealed transport-neutral evidence only for ordinary complete proof.
func (p RevisionProof) VerifierProjection() (VerifierProjection, bool) {
	if !p.Valid() || p.state != RevisionProofVerified || !p.verifier.Valid() {
		return VerifierProjection{}, false
	}
	return p.verifier.clone(), true
}

// State returns the clean proof state or zero for invalid proof.
func (p RevisionProof) State() RevisionProofOutcome {
	if !p.Valid() {
		return ""
	}
	return p.state
}

// Draft returns the bound protocol draft or an empty string for invalid proof.
func (p RevisionProof) Draft() string {
	if !p.Valid() {
		return ""
	}
	return p.draft
}

// Facts returns detached bounded all-hop facts.
func (p RevisionProof) Facts() RevisionFacts {
	if !p.Valid() {
		return RevisionFacts{}
	}
	return p.facts.clone()
}

// String returns a constant secret-safe proof summary.
func (p RevisionProof) String() string { return "verify.RevisionProof{redacted}" }

// GoString returns a constant secret-safe proof Go representation.
func (p RevisionProof) GoString() string { return p.String() }

// Format routes every proof formatting form through the redacted summary.
func (p RevisionProof) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, p.String()) }

// VerifyRevisionProof verifies every inherited signature and all authenticated history without using Result.
func (v Verifier) VerifyRevisionProof(ctx context.Context, request Request) (RevisionProofOutcome, RevisionProof, error) {
	if ctx == nil || !request.Message.Initialized() || request.TargetSequence != 0 || request.SkipEnvelopeForNonCurrentTarget || !v.valid() || !revisionTimestampPolicySafe(v.options.TimestampPolicy) {
		return "", RevisionProof{}, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	if err := ctx.Err(); err != nil {
		return "", RevisionProof{}, err
	}
	instant, err := v.CaptureRevisionInstant()
	if err != nil {
		return "", RevisionProof{}, err
	}
	return v.VerifyRevisionProofAt(ctx, request, instant)
}

// VerifyRevisionProofAfterCurrent completes all-hop proof without repeating the already verified current key lookup.
func (v Verifier) VerifyRevisionProofAfterCurrent(ctx context.Context, request Request, current Result) (RevisionProofOutcome, RevisionProof, error) {
	if !aggregateCurrentPass(current) {
		return "", RevisionProof{}, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	instant, err := v.CaptureRevisionInstant()
	if err != nil {
		return "", RevisionProof{}, err
	}
	outcome, prepared, err := v.PrepareRevisionProofAt(ctx, request, instant)
	if err != nil || outcome != "" {
		return outcome, RevisionProof{}, err
	}
	return v.executePreparedRevisionProof(ctx, prepared, &current)
}

// CaptureRevisionInstant captures one representable nonnegative operation time.
func (v Verifier) CaptureRevisionInstant() (RevisionInstant, error) {
	if !v.valid() || !revisionTimestampPolicySafe(v.options.TimestampPolicy) {
		return RevisionInstant{}, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	now, err := captureRevisionClock(v.options.Clock)
	if err != nil {
		return RevisionInstant{}, err
	}
	return RevisionInstant{now: now, policy: v.options.TimestampPolicy, owner: v.revisionOwner, initialized: true}, nil
}

// VerifyRevisionProofAt verifies inherited proof at one verifier-owned instant.
func (v Verifier) VerifyRevisionProofAt(ctx context.Context, request Request, instant RevisionInstant) (RevisionProofOutcome, RevisionProof, error) {
	outcome, prepared, err := v.PrepareRevisionProofAt(ctx, request, instant)
	if err != nil || outcome != "" {
		return outcome, RevisionProof{}, err
	}
	return v.ExecutePreparedRevisionProof(ctx, prepared)
}

// PrepareRevisionProofAt performs all provider-free revision work at one operation instant.
func (v Verifier) PrepareRevisionProofAt(ctx context.Context, request Request, instant RevisionInstant) (RevisionProofOutcome, PreparedRevisionProof, error) {
	if ctx == nil || !request.Message.Initialized() || request.TargetSequence != 0 || request.SkipEnvelopeForNonCurrentTarget || !v.valid() ||
		!instant.Valid() || instant.policy != v.options.TimestampPolicy || instant.owner != v.revisionOwner {
		return "", PreparedRevisionProof{}, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	if err := ctx.Err(); err != nil {
		return "", PreparedRevisionProof{}, err
	}
	input, err := v.extractVerificationInput(request, v.options.RevisionLimits.MaxDecodedRecipeBytes)
	if err != nil {
		return revisionOutcomeFromError(err), PreparedRevisionProof{}, nil
	}
	orderedSignatures, orderErr := signature.OrderBySequence(input.signatures)
	if orderErr != nil {
		return revisionOutcomeFromError(orderErr), PreparedRevisionProof{}, nil
	}
	input.signatures = orderedSignatures
	base, outcome, err := v.verifyRevisionBase(ctx, input)
	if err != nil || outcome != "" {
		return outcome, PreparedRevisionProof{}, err
	}
	signatures, prepared, outcome, err := v.preflightRevisionSignatures(ctx, input, instant.now, base.canonicalWork)
	if err != nil || outcome != "" {
		return outcome, PreparedRevisionProof{}, err
	}
	result := PreparedRevisionProof{
		input: input, base: base, signatures: signatures, prepared: prepared,
		instant: instant, owner: v.revisionOwner, execution: &preparedRevisionExecution{}, initialized: true,
	}
	if !result.Valid() {
		return "", PreparedRevisionProof{}, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	return "", result, nil
}

// ExecutePreparedRevisionProof performs only fixed-order provider lookup and signature verification.
func (v Verifier) ExecutePreparedRevisionProof(ctx context.Context, prepared PreparedRevisionProof) (RevisionProofOutcome, RevisionProof, error) {
	return v.executePreparedRevisionProof(ctx, prepared, nil)
}

func (v Verifier) executePreparedRevisionProof(ctx context.Context, prepared PreparedRevisionProof, current *Result) (RevisionProofOutcome, RevisionProof, error) {
	if ctx == nil || !v.valid() || !prepared.Valid() || prepared.owner != v.revisionOwner {
		return "", RevisionProof{}, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	if err := ctx.Err(); err != nil {
		return "", RevisionProof{}, err
	}
	prepared.execution.mu.Lock()
	if prepared.execution.consumed {
		prepared.execution.mu.Unlock()
		return "", RevisionProof{}, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	prepared.execution.consumed = true
	prepared.execution.mu.Unlock()
	signatures := prepared.signatures
	signatures.facts = slices.Clone(prepared.signatures.facts)
	for _, candidate := range prepared.prepared {
		if err := ctx.Err(); err != nil {
			return "", RevisionProof{}, err
		}
		if current != nil && candidate.fact.sequence == current.Target().Sequence {
			sets, ok := revisionSetsFromCurrent(*current, len(candidate.parsed.SignatureSets()))
			if !ok || candidate.fact.instance != current.Target().InstanceNumber {
				return "", RevisionProof{}, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
			}
			candidate.fact.sets = sets
			signatures.facts[candidate.fact.sequence-1] = candidate.fact
			continue
		}
		evaluation := v.evaluateRevisionSignatureSets(ctx, candidate.parsed, candidate.digest, Target{
			Sequence: candidate.fact.sequence, InstanceNumber: candidate.fact.instance,
		}, candidate.plan)
		if err := ctx.Err(); err != nil {
			return "", RevisionProof{}, err
		}
		outcome := revisionSignatureOutcome(evaluation)
		if outcome != RevisionProofVerified {
			return outcome, RevisionProof{}, nil
		}
		setFacts := make([]RevisionSetFact, len(evaluation.sets))
		for setIndex, set := range evaluation.sets {
			if set.Status == SignatureSetStatusPass {
				setFacts[setIndex] = RevisionSetFact{index: setIndex, algorithm: set.Algorithm, state: RevisionSetSupportedPass}
			} else {
				setFacts[setIndex] = RevisionSetFact{index: setIndex, algorithm: AlgorithmUnknown, state: RevisionSetIgnoredUnknown}
			}
		}
		candidate.fact.sets = setFacts
		signatures.facts[candidate.fact.sequence-1] = candidate.fact
	}
	return v.completePreparedRevisionProof(prepared.input, prepared.base, signatures)
}

func revisionSetsFromCurrent(current Result, count int) ([]RevisionSetFact, bool) {
	sets := current.SignatureSets()
	if len(sets) != count {
		return nil, false
	}
	result := make([]RevisionSetFact, len(sets))
	passes := 0
	for index, set := range sets {
		if set.Index != index {
			return nil, false
		}
		switch set.Status {
		case SignatureSetStatusPass:
			result[index] = RevisionSetFact{index: index, algorithm: set.Algorithm, state: RevisionSetSupportedPass}
			passes++
		case SignatureSetStatusUnsupportedAlgorithm:
			result[index] = RevisionSetFact{index: index, algorithm: AlgorithmUnknown, state: RevisionSetIgnoredUnknown}
		default:
			return nil, false
		}
	}
	return result, passes > 0
}

// revisionTimestampPolicySafe enforces exact 14-day age and non-widened future tolerance.
func revisionTimestampPolicySafe(policy TimestampPolicy) bool {
	return policy.Validate() == nil && policy == DefaultTimestampPolicy()
}

// RevalidateRevisionProof rechecks every inherited timestamp against one newly captured clock.
func (v Verifier) RevalidateRevisionProof(ctx context.Context, proof RevisionProof) (RevisionProofRevalidation, error) {
	if ctx == nil || !v.valid() || !proof.Valid() || proof.policy != v.options.TimestampPolicy {
		return "", newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	instant, err := v.CaptureRevisionInstant()
	if err != nil {
		return "", err
	}
	return v.RevalidateRevisionProofAt(ctx, proof, instant)
}

// RevalidateRevisionProofAt rechecks inherited timestamps at one verifier-owned instant.
func (v Verifier) RevalidateRevisionProofAt(ctx context.Context, proof RevisionProof, instant RevisionInstant) (RevisionProofRevalidation, error) {
	if ctx == nil || !v.valid() || !proof.Valid() || proof.policy != v.options.TimestampPolicy ||
		!instant.Valid() || instant.policy != v.options.TimestampPolicy || instant.owner != v.revisionOwner {
		return "", newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	for _, fact := range proof.facts.signatures {
		if timestampStatusAt(instant.now, fact.timestamp, proof.policy) != TimestampStatusPass {
			return RevisionProofTimestampInvalid, nil
		}
	}
	return RevisionProofRevalidated, nil
}

// valid reports whether the verifier owns coherent immutable dependencies.
func (v Verifier) valid() bool {
	return !nilKeyProvider(v.keyProvider) && v.options.Validate() == nil &&
		v.history.initialized && v.revisionHistory.initialized && v.revisionOwner != nil
}

// Valid reports whether the verifier owns coherent immutable dependencies.
func (v Verifier) Valid() bool { return v.valid() }

// revisionBaseProof stores current-message, custody, and history proof state.
type revisionBaseProof struct {
	highestSignature     signature.Signature
	highestInstance      instance.MessageInstance
	custody              signature.CustodyResult
	history              HistoryWalk
	canonicalWork        int
	currentCanonicalWork int
	hashes               RevisionHashFacts
	originDigest         [32]byte
	hasOriginDigest      bool
}

// revisionSignatureProof stores detached inherited-signature proof state.
type revisionSignatureProof struct {
	facts                  []RevisionSignatureFact
	totalSets              int
	lookups                int
	canonicalWork          int
	signatureCanonicalWork int
}

type revisionPreparedSignature struct {
	parsed signature.Signature
	digest []byte
	fact   RevisionSignatureFact
	plan   revisionSignatureSetPlan
}

type revisionSignatureSetPlan struct {
	results []SignatureSetResult
	order   []int
}

// PreparedRevisionProof is an opaque provider-free all-hop verification plan.
type PreparedRevisionProof struct {
	input       verificationInput
	base        revisionBaseProof
	signatures  revisionSignatureProof
	prepared    []revisionPreparedSignature
	instant     RevisionInstant
	owner       *revisionInstantOwner
	execution   *preparedRevisionExecution
	initialized bool
}

// preparedRevisionExecution makes copied prepared values one shared single-use capability.
type preparedRevisionExecution struct {
	mu       sync.Mutex
	consumed bool
}

// Valid reports whether the prepared proof belongs to one initialized verifier operation.
func (p PreparedRevisionProof) Valid() bool {
	return p.initialized && p.owner != nil && p.execution != nil && p.instant.Valid() && p.instant.owner == p.owner &&
		p.input.request.Message.Initialized() && len(p.prepared) == len(p.input.signatures)
}

// Usage returns exact provider-free work and future callback counts.
func (p PreparedRevisionProof) Usage() RevisionUsage {
	if !p.Valid() {
		return RevisionUsage{}
	}
	return RevisionUsage{
		protocolFields: len(p.input.instances) + len(p.input.signatures),
		signatureSets:  p.signatures.totalSets, keyLookups: p.signatures.lookups,
		providerCalls: p.signatures.lookups, canonicalBytes: p.signatures.canonicalWork,
		currentCanonicalBytes:   p.base.currentCanonicalWork,
		signatureCanonicalBytes: p.signatures.signatureCanonicalWork, history: p.base.history.Usage(),
	}
}

// String returns a constant secret-safe prepared-proof summary.
func (p PreparedRevisionProof) String() string { return "verify.PreparedRevisionProof{redacted}" }

// GoString returns the constant secret-safe prepared-proof Go representation.
func (p PreparedRevisionProof) GoString() string { return p.String() }

// Format routes every prepared-proof formatting form through the redacted summary.
func (p PreparedRevisionProof) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, p.String())
}

// completePreparedRevisionProof builds immutable facts after every provider-backed signature passes.
func (v Verifier) completePreparedRevisionProof(input verificationInput, base revisionBaseProof, signatures revisionSignatureProof) (RevisionProofOutcome, RevisionProof, error) {
	if !base.hashes.Valid() {
		return "", RevisionProof{}, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	custodyFacts := revisionCustodyFacts(base.custody, input.signatures)
	historyFacts := revisionHistoryFacts(base.history)

	proofState := RevisionProofVerified
	if base.highestSignature.HasNextDomain() {
		proofState = RevisionProofTerminalNextDomainAuthorizationRequired
	}
	facts := RevisionFacts{
		highestSequence: base.highestSignature.Sequence(), highestInstance: base.highestInstance.Number(),
		instanceCount: len(input.instances), signatureCount: len(input.signatures),
		signatures: signatures.facts, hashes: base.hashes, envelope: revisionEnvelopeFact(base.highestSignature), custody: custodyFacts, history: historyFacts,
		usage: RevisionUsage{protocolFields: len(input.instances) + len(input.signatures), signatureSets: signatures.totalSets, keyLookups: signatures.lookups, providerCalls: signatures.lookups,
			canonicalBytes: signatures.canonicalWork, currentCanonicalBytes: base.currentCanonicalWork, signatureCanonicalBytes: signatures.signatureCanonicalWork, history: base.history.Usage()}, initialized: true,
	}
	exploded := false
	for _, fact := range signatures.facts {
		exploded = exploded || fact.flags.exploded
	}
	var replayProjection ReplayProjection
	if base.hasOriginDigest {
		replayProjection = newReplayProjection(base.originDigest, exploded)
	}
	verifierProjection, hasVerifierProjection := v.buildVerifierProjection(input, base, signatures)
	if proofState == RevisionProofVerified && !hasVerifierProjection {
		return "", RevisionProof{}, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	if proofState != RevisionProofVerified {
		verifierProjection = VerifierProjection{}
	}
	proof := RevisionProof{state: proofState, draft: DraftBaseline, facts: facts, replay: replayProjection, verifier: verifierProjection, policy: v.options.TimestampPolicy, initialized: true}
	if !proof.Valid() {
		return "", RevisionProof{}, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	return proofState, proof, nil
}

// verifyRevisionBase proves the current tuple, custody, and complete bounded history.
func (v Verifier) verifyRevisionBase(ctx context.Context, input verificationInput) (revisionBaseProof, RevisionProofOutcome, error) {
	highestSignature, highestInstance, custody, target, err := selectVerificationTarget(input)
	if err != nil {
		return revisionBaseProof{}, revisionOutcomeFromError(err), nil
	}
	limits := v.options.RevisionLimits
	if len(input.instances)+len(input.signatures) > limits.MaxProtocolFields {
		return revisionBaseProof{}, RevisionProofLimitExceeded, nil
	}
	if input.request.Envelope.RecipientCount() > v.options.Limits.MaxEnvelopeRecipients {
		return revisionBaseProof{}, RevisionProofLimitExceeded, nil
	}
	if !revisionEnvelopeShapeValid(input.request.Envelope, highestSignature.HasNextDomain()) {
		return revisionBaseProof{}, RevisionProofHashMismatch, nil
	}
	if !custody.Evaluated() {
		return revisionBaseProof{}, RevisionProofProtocolRejected, nil
	}
	if !highestSignature.HasNextDomain() && compareCurrentEnvelope(input.request.Envelope, highestSignature) != EnvelopeStatusPass {
		return revisionBaseProof{}, RevisionProofProtocolRejected, nil
	}
	if !custody.AllDirectAligned() {
		return revisionBaseProof{}, RevisionProofProtocolRejected, nil
	}

	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		return revisionBaseProof{}, "", newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	hashes, err := compareTargetHashes(canonicalizer, input.request.Message, highestInstance, target)
	if err != nil {
		return revisionBaseProof{}, RevisionProofProtocolRejected, nil
	}
	if !hashes.pass {
		if hashes.body.HashStatus == HashStatusUnsupported || hashes.header.HashStatus == HashStatusUnsupported {
			return revisionBaseProof{}, RevisionProofUnsupported, nil
		}
		return revisionBaseProof{}, RevisionProofProtocolRejected, nil
	}
	if !hashes.hasLocalHeaderSHA256 || !hashes.hasLocalBodySHA256 {
		return revisionBaseProof{}, RevisionProofProtocolRejected, nil
	}
	hashFacts := RevisionHashFacts{instance: highestInstance.Number(), header: hashes.localHeaderSHA256, body: hashes.localBodySHA256}

	currentCanonicalWork := hashes.canonicalWork
	canonicalWork := currentCanonicalWork
	if canonicalWork <= 0 || canonicalWork > limits.MaxCanonicalWorkBytes {
		return revisionBaseProof{}, RevisionProofLimitExceeded, nil
	}
	collection, err := instance.NewCollection(input.instances)
	if err != nil {
		return revisionBaseProof{}, RevisionProofProtocolRejected, nil
	}
	state, err := recipe.NewState(input.request.Message)
	if err != nil {
		return revisionBaseProof{}, RevisionProofProtocolRejected, nil
	}
	walk, err := v.revisionHistory.walkAuthenticatedWithin(ctx, target.InstanceNumber, collection, state, limits.MaxCanonicalWorkBytes-canonicalWork, true)
	if err != nil {
		if ctx.Err() != nil {
			return revisionBaseProof{}, "", ctx.Err()
		}
		return revisionBaseProof{}, "", newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	if outcome := rejectedRevisionHistoryOutcome(walk); outcome != "" {
		return revisionBaseProof{}, outcome, nil
	}
	if walk.Usage().CanonicalBytes() > limits.MaxCanonicalWorkBytes-canonicalWork {
		return revisionBaseProof{}, RevisionProofLimitExceeded, nil
	}
	canonicalWork += walk.Usage().CanonicalBytes()
	originMessage := input.request.Message
	if target.InstanceNumber > 1 {
		transitions := walk.Transitions()
		if len(transitions) != int(target.InstanceNumber-1) {
			return revisionBaseProof{highestSignature: highestSignature, highestInstance: highestInstance, custody: custody, history: walk, canonicalWork: canonicalWork, currentCanonicalWork: currentCanonicalWork, hashes: hashFacts}, "", nil
		}
		state, ok := transitions[len(transitions)-1].ReconstructedState()
		if !ok {
			return revisionBaseProof{highestSignature: highestSignature, highestInstance: highestInstance, custody: custody, history: walk, canonicalWork: canonicalWork, currentCanonicalWork: currentCanonicalWork, hashes: hashFacts}, "", nil
		}
		originMessage, err = state.Materialize()
		if err != nil {
			return revisionBaseProof{highestSignature: highestSignature, highestInstance: highestInstance, custody: custody, history: walk, canonicalWork: canonicalWork, currentCanonicalWork: currentCanonicalWork, hashes: hashFacts}, "", nil
		}
	}
	originDigest, ok := originReplayDigest(originMessage)
	if !ok {
		return revisionBaseProof{highestSignature: highestSignature, highestInstance: highestInstance, custody: custody, history: walk, canonicalWork: canonicalWork, currentCanonicalWork: currentCanonicalWork, hashes: hashFacts}, "", nil
	}
	return revisionBaseProof{highestSignature: highestSignature, highestInstance: highestInstance, custody: custody, history: walk, canonicalWork: canonicalWork, currentCanonicalWork: currentCanonicalWork, hashes: hashFacts, originDigest: originDigest, hasOriginDigest: true}, "", nil
}

// rejectedRevisionHistoryOutcome maps every incomplete authenticated walk to one closed result.
func rejectedRevisionHistoryOutcome(walk HistoryWalk) RevisionProofOutcome {
	if revisionHistoryAccepted(walk) {
		return ""
	}
	if !walk.Valid() {
		return RevisionProofProtocolRejected
	}
	switch walk.StopReason() {
	case HistoryStopRecipeInvalid:
		return RevisionProofInvalidRecipeJSON
	case HistoryStopLimitExceeded:
		return RevisionProofLimitExceeded
	case HistoryStopHashUnsupported:
		return RevisionProofUnsupported
	case HistoryStopHashMismatch:
		return RevisionProofHashMismatch
	case HistoryStopOriginReached:
		if walk.ReachedInstance() == 1 && len(walk.Transitions()) != int(walk.TargetInstance()-1) {
			return RevisionProofLimitExceeded
		}
	}
	return RevisionProofProtocolRejected
}

// preflightRevisionSignatures proves every local all-hop timestamp, limit, and canonical-input invariant before provider callbacks.
func (v Verifier) preflightRevisionSignatures(ctx context.Context, input verificationInput, now time.Time, canonicalWork int) (revisionSignatureProof, []revisionPreparedSignature, RevisionProofOutcome, error) {
	limits := v.options.RevisionLimits
	proof := revisionSignatureProof{facts: make([]RevisionSignatureFact, len(input.signatures)), canonicalWork: canonicalWork}
	prepared := make([]revisionPreparedSignature, 0, len(input.signatures))
	totalSets, lookups := 0, 0
	for _, parsed := range input.signatures {
		if err := ctx.Err(); err != nil {
			return revisionSignatureProof{}, nil, "", err
		}
		sequence := parsed.Sequence()
		if sequence == 0 || sequence > uint64(len(input.signatures)) {
			return revisionSignatureProof{}, nil, RevisionProofProtocolRejected, nil
		}
		timestamp := parsed.TimestampSeconds()
		if timestampStatusAt(now, timestamp, v.options.TimestampPolicy) != TimestampStatusPass {
			return revisionSignatureProof{}, nil, RevisionProofProtocolRejected, nil
		}
		parsedFlags := parsed.Flags()
		flagFacts := RevisionFlagFacts{
			doNotModify:  parsedFlags.HasKnown(signature.FlagDoNotModify),
			doNotExplode: parsedFlags.HasKnown(signature.FlagDoNotExplode),
			feedback:     parsedFlags.HasKnown(signature.FlagFeedback),
			feedHere:     parsedFlags.HasKnown(signature.FlagFeedHere),
			exploded:     parsedFlags.HasKnown(signature.FlagExploded),
		}
		sets := parsed.SignatureSets()
		if len(sets) > math.MaxInt-totalSets {
			return revisionSignatureProof{}, nil, RevisionProofLimitExceeded, nil
		}
		totalSets += len(sets)
		if totalSets > limits.MaxTotalSignatureSets {
			return revisionSignatureProof{}, nil, RevisionProofLimitExceeded, nil
		}
		for _, set := range sets {
			if set.KnownAlgorithm() {
				if lookups == math.MaxInt {
					return revisionSignatureProof{}, nil, RevisionProofLimitExceeded, nil
				}
				lookups++
			}
		}
		if lookups > limits.MaxPublicKeyLookups {
			return revisionSignatureProof{}, nil, RevisionProofLimitExceeded, nil
		}

		remaining := limits.MaxCanonicalWorkBytes - proof.canonicalWork
		if remaining <= 0 {
			return revisionSignatureProof{}, nil, RevisionProofLimitExceeded, nil
		}
		digest, work, digestErr := revisionSignatureInputDigest(input.request.Message, Target{Sequence: sequence, InstanceNumber: parsed.InstanceNumber()}, min(remaining, limits.MaxSignatureInputBytes))
		if canonical.IsErrorCode(digestErr, canonical.ErrorCodeLimitExceeded) || work > math.MaxInt-proof.canonicalWork {
			return revisionSignatureProof{}, nil, RevisionProofLimitExceeded, nil
		}
		if digestErr != nil {
			return revisionSignatureProof{}, nil, RevisionProofProtocolRejected, nil
		}
		proof.canonicalWork += work
		proof.signatureCanonicalWork += work
		if proof.canonicalWork > limits.MaxCanonicalWorkBytes {
			return revisionSignatureProof{}, nil, RevisionProofLimitExceeded, nil
		}
		plan, planOutcome := v.prepareRevisionSignatureSets(parsed)
		if planOutcome != "" {
			return revisionSignatureProof{}, nil, planOutcome, nil
		}
		prepared = append(prepared, revisionPreparedSignature{
			parsed: parsed, digest: digest,
			fact: RevisionSignatureFact{sequence: sequence, instance: parsed.InstanceNumber(), timestamp: timestamp, flags: flagFacts},
			plan: plan,
		})
	}
	proof.totalSets = totalSets
	proof.lookups = lookups
	return proof, prepared, "", nil
}

// prepareRevisionSignatureSets classifies every set locally and builds fixed callback order before any provider call.
func (v Verifier) prepareRevisionSignatureSets(parsed signature.Signature) (revisionSignatureSetPlan, RevisionProofOutcome) {
	sets := parsed.SignatureSets()
	if len(sets) > v.options.Limits.MaxSignatureSets {
		return revisionSignatureSetPlan{}, RevisionProofLimitExceeded
	}

	plan := revisionSignatureSetPlan{
		results: make([]SignatureSetResult, len(sets)),
		order:   make([]int, 0, len(sets)),
	}
	enabled := make([]bool, len(sets))
	locallyRejected := false
	for index, set := range sets {
		algorithm := Algorithm(set.Algorithm())
		switch status := v.options.AlgorithmPolicy.ClassifyAlgorithm(algorithm); status {
		case KeyStatusFound:
			enabled[index] = true
			plan.results[index] = SignatureSetResult{
				Index: index, Algorithm: algorithm, Status: SignatureSetStatusNotChecked, KeyStatus: KeyStatusNotChecked,
			}
		case KeyStatusUnsupportedAlgorithm:
			plan.results[index] = SignatureSetResult{
				Index: index, Algorithm: algorithm, Status: SignatureSetStatusUnsupportedAlgorithm, KeyStatus: status,
			}
		default:
			plan.results[index] = SignatureSetResult{
				Index: index, Algorithm: algorithm, Status: SignatureSetStatusDisabledAlgorithm, KeyStatus: status,
			}
			locallyRejected = true
		}
	}

	for _, algorithm := range [...]Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256} {
		for index, set := range sets {
			if enabled[index] && Algorithm(set.Algorithm()) == algorithm {
				plan.order = append(plan.order, index)
			}
		}
	}
	if locallyRejected {
		return revisionSignatureSetPlan{}, RevisionProofProtocolRejected
	}
	if len(plan.order) == 0 {
		return revisionSignatureSetPlan{}, RevisionProofUnsupported
	}
	return plan, ""
}

// evaluateRevisionSignatureSets executes one preflighted plan and summarizes results in source order.
func (v Verifier) evaluateRevisionSignatureSets(ctx context.Context, parsed signature.Signature, digest []byte, target Target, plan revisionSignatureSetPlan) signatureEvaluation {
	sets := parsed.SignatureSets()
	evaluation := signatureEvaluation{
		checks: make([]CheckResult, 0, len(sets)),
		sets:   append([]SignatureSetResult(nil), plan.results...),
	}
	for _, index := range plan.order {
		if ctx == nil || ctx.Err() != nil {
			return evaluation
		}
		evaluation.sets[index] = v.evaluateSignatureSet(ctx, parsed, sets[index], index, digest, target)
		if ctx.Err() != nil {
			return evaluation
		}
	}
	for _, setResult := range evaluation.sets {
		evaluation.checks = append(evaluation.checks, signatureCheckResult(setResult, target))
		evaluation.account(setResult)
	}
	return evaluation
}

// revisionEnvelopeFact projects the already-passing current-envelope branch.
func revisionEnvelopeFact(highest signature.Signature) RevisionEnvelopeState {
	if highest.HasNextDomain() {
		return RevisionEnvelopeTerminalNextDomainNotApplicable
	}
	return RevisionEnvelopeOrdinaryPass
}

// revisionEnvelopeShapeValid applies the signature owner's exact SMTP path contract.
func revisionEnvelopeShapeValid(envelope Envelope, terminalNextDomain bool) bool {
	if envelope.IsZero() {
		return terminalNextDomain
	}
	if !signature.ValidEnvelopePath(envelope.ReversePath(), true) || envelope.RecipientCount() == 0 {
		return false
	}
	for _, path := range envelope.ForwardPaths() {
		if !signature.ValidEnvelopePath(path, false) {
			return false
		}
	}
	return true
}

// revisionSignatureInputDigest returns a digest plus exact canonical work bytes.
func revisionSignatureInputDigest(message rawmsg.Message, target Target, remaining int) ([]byte, int, error) {
	limits := canonical.DefaultLimits()
	if remaining < limits.MaxSignatureInputBytes {
		limits.MaxSignatureInputBytes = remaining
	}
	canonicalizer, err := canonical.NewCanonicalizer(canonical.WithLimits(limits))
	if err != nil {
		return nil, 0, err
	}
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{Headers: message.Headers(), TargetSequence: target.Sequence})
	if err != nil {
		return nil, 0, err
	}
	digest, err := canonicalizer.SHA256Digest(input)
	if err != nil {
		return nil, 0, err
	}
	return digest.Bytes(), canonicalWorkBytes(input), nil
}

// revisionSignatureOutcome folds one inherited field without accepting mixed known failures.
func revisionSignatureOutcome(evaluation signatureEvaluation) RevisionProofOutcome {
	hasTemporary, hasPermanent, hasMismatch := false, false, false
	for _, set := range evaluation.sets {
		switch set.Status {
		case SignatureSetStatusPass, SignatureSetStatusUnsupportedAlgorithm:
		case SignatureSetStatusProviderContract, SignatureSetStatusProviderError:
			return RevisionProofProviderContract
		case SignatureSetStatusProviderTemporary:
			hasTemporary = true
		case SignatureSetStatusFail:
			hasMismatch = true
		case SignatureSetStatusProviderPermanent, SignatureSetStatusMissingKey, SignatureSetStatusInvalidKey,
			SignatureSetStatusAmbiguousKey, SignatureSetStatusRevokedKey, SignatureSetStatusUnsupportedKeyType,
			SignatureSetStatusKeyAlgorithmMismatch, SignatureSetStatusWrongKeyType, SignatureSetStatusKeyPolicyRejected,
			SignatureSetStatusDisabledAlgorithm:
			hasPermanent = true
		default:
			return RevisionProofProtocolRejected
		}
	}
	if hasPermanent {
		return RevisionProofProviderRejected
	}
	if hasTemporary {
		return RevisionProofProviderTemporary
	}
	if hasMismatch {
		return RevisionProofSignatureMismatch
	}
	if evaluation.pass == 0 {
		return RevisionProofUnsupported
	}
	if evaluation.fail != 0 || evaluation.other != 0 || evaluation.temporary != 0 {
		return RevisionProofProtocolRejected
	}
	return RevisionProofVerified
}

// revisionHistoryAccepted permits complete proof or only explicit b:null body unavailability through m=1.
func revisionHistoryAccepted(walk HistoryWalk) bool {
	return walk.Valid() && walk.StopReason() == HistoryStopOriginReached && walk.ReachedInstance() == 1 &&
		len(walk.Transitions()) == int(walk.TargetInstance()-1) &&
		(walk.Coverage() == HistoryCoverageComplete || walk.Coverage() == HistoryCoveragePartial && walk.hadUnavailable)
}

// revisionCustodyFacts projects the already evaluated shared state machine once.
func revisionCustodyFacts(custody signature.CustodyResult, signatures []signature.Signature) RevisionCustodyFacts {
	hops := make([]RevisionCustodyHopFact, len(signatures))
	for index, parsed := range signatures {
		link := RevisionCustodyOrigin
		if index > 0 {
			link = RevisionCustodyOrdinaryToOrdinaryPass
			if parsed.HasNextDomain() {
				link = RevisionCustodyOrdinaryToNextDomainPass
			}
			if signatures[index-1].HasNextDomain() {
				link = RevisionCustodyNextDomainToSignaturePass
			}
		}
		hops[index] = RevisionCustodyHopFact{sequence: parsed.Sequence(), direct: custody.DirectAlignment(parsed.Sequence()), link: link}
	}
	return RevisionCustodyFacts{status: custody.Status(), hadND: custody.HadNextDomain(), hops: hops}
}

// revisionHistoryFacts removes reconstructed content while retaining every bounded proof transition.
func revisionHistoryFacts(walk HistoryWalk) RevisionHistoryFacts {
	transitions := walk.Transitions()
	projected := make([]RevisionHistoryTransitionFact, len(transitions))
	for index, transition := range transitions {
		projected[index] = RevisionHistoryTransitionFact{from: transition.FromInstance(), to: transition.ToInstance(), mode: transition.RecipeMode(), header: transition.HeaderState(), body: transition.BodyState()}
	}
	return RevisionHistoryFacts{coverage: walk.Coverage(), stop: walk.StopReason(), target: walk.TargetInstance(), reached: walk.ReachedInstance(), gap: walk.hadUnavailable, transitions: projected, usage: walk.Usage()}
}

// revisionOutcomeFromError maps bounded protocol extraction failures without retaining their details.
func revisionOutcomeFromError(err error) RevisionProofOutcome {
	if IsErrorCode(err, ErrorCodeLimitExceeded) || IsErrorCode(err, ErrorCodeHistoryLimitExceeded) {
		return RevisionProofLimitExceeded
	}
	return RevisionProofProtocolRejected
}

// captureRevisionClock obtains one representable nonnegative clock instant without propagating panics.
func captureRevisionClock(clock Clock) (now time.Time, err error) {
	defer func() {
		if recover() != nil {
			now = time.Time{}
			err = newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
		}
	}()
	if clock == nil {
		return time.Time{}, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	now = clock.Now()
	seconds := now.Unix()
	if seconds < 0 || !time.Unix(seconds, int64(now.Nanosecond())).Equal(now) {
		return time.Time{}, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	if _, ok := safeAddDuration(now, defaultFutureTolerance); !ok {
		return time.Time{}, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	return now, nil
}

// revisionClockInstantSafe reports whether a captured instant remains exactly representable.
func revisionClockInstantSafe(now time.Time) bool {
	seconds := now.Unix()
	if seconds < 0 || !time.Unix(seconds, int64(now.Nanosecond())).Equal(now) {
		return false
	}
	_, ok := safeAddDuration(now, defaultFutureTolerance)
	return ok
}
