package policy

// ReceivedDSNStructure mirrors the closed structure member of a received-DSN evaluation.
type ReceivedDSNStructure string

const (
	// ReceivedDSNStructureValid reports exact RFC 6522 framing and a strict RFC 3464 body.
	ReceivedDSNStructureValid ReceivedDSNStructure = "valid"
	// ReceivedDSNStructureMalformed reports framing or delivery-status syntax outside the profile.
	ReceivedDSNStructureMalformed ReceivedDSNStructure = "malformed"
	// ReceivedDSNStructureLimitExceeded reports a DSN parser resource limit violation.
	ReceivedDSNStructureLimitExceeded ReceivedDSNStructure = "limit_exceeded"
)

// Known reports whether the value belongs to the closed vocabulary.
func (s ReceivedDSNStructure) Known() bool {
	return s == ReceivedDSNStructureValid || s == ReceivedDSNStructureMalformed || s == ReceivedDSNStructureLimitExceeded
}

// ReceivedDSNEmbedded mirrors the closed embedded member of a received-DSN evaluation.
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
)

// Known reports whether the value belongs to the closed vocabulary.
func (e ReceivedDSNEmbedded) Known() bool {
	switch e {
	case ReceivedDSNEmbeddedVerified, ReceivedDSNEmbeddedVerifiedHeadersOnly, ReceivedDSNEmbeddedUnverified,
		ReceivedDSNEmbeddedTemperror, ReceivedDSNEmbeddedAbsent:
		return true
	default:
		return false
	}
}

// verified reports whether the embedded original passed either verification form.
func (e ReceivedDSNEmbedded) verified() bool {
	return e == ReceivedDSNEmbeddedVerified || e == ReceivedDSNEmbeddedVerifiedHeadersOnly
}

// ReceivedDSNLocalHop mirrors the closed local_hop member of a received-DSN evaluation.
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
	// ReceivedDSNLocalHopNotEvaluated reports that an earlier stage stopped or that no tenant was available.
	ReceivedDSNLocalHopNotEvaluated ReceivedDSNLocalHop = "not_evaluated"
)

// Known reports whether the value belongs to the closed vocabulary.
func (l ReceivedDSNLocalHop) Known() bool {
	switch l {
	case ReceivedDSNLocalHopLocal, ReceivedDSNLocalHopNotLocal, ReceivedDSNLocalHopMismatch,
		ReceivedDSNLocalHopTemperror, ReceivedDSNLocalHopNotEvaluated:
		return true
	default:
		return false
	}
}

// ReceivedDSNOuterAlignment mirrors the closed outer_alignment member of a received-DSN evaluation.
type ReceivedDSNOuterAlignment string

const (
	// ReceivedDSNOuterAlignmentAligned reports that the outer signer relaxed-matches a completion rt= domain.
	ReceivedDSNOuterAlignmentAligned ReceivedDSNOuterAlignment = "aligned"
	// ReceivedDSNOuterAlignmentMisaligned reports that no completion rt= domain relaxed-matches the outer signer.
	ReceivedDSNOuterAlignmentMisaligned ReceivedDSNOuterAlignment = "misaligned"
	// ReceivedDSNOuterAlignmentNotEvaluated reports that an earlier stage stopped the evaluation.
	ReceivedDSNOuterAlignmentNotEvaluated ReceivedDSNOuterAlignment = "not_evaluated"
)

// Known reports whether the value belongs to the closed vocabulary.
func (a ReceivedDSNOuterAlignment) Known() bool {
	return a == ReceivedDSNOuterAlignmentAligned || a == ReceivedDSNOuterAlignmentMisaligned || a == ReceivedDSNOuterAlignmentNotEvaluated
}

// ReceivedDSNRecipientLinkage mirrors the closed recipient_linkage member of a received-DSN evaluation.
type ReceivedDSNRecipientLinkage string

const (
	// ReceivedDSNRecipientLinkageLinked reports at least one recipient group naming an authenticated completion rt= path.
	ReceivedDSNRecipientLinkageLinked ReceivedDSNRecipientLinkage = "linked"
	// ReceivedDSNRecipientLinkageUnlinked reports that no recipient group names an authenticated completion rt= path.
	ReceivedDSNRecipientLinkageUnlinked ReceivedDSNRecipientLinkage = "unlinked"
	// ReceivedDSNRecipientLinkageNotEvaluated reports that an earlier stage stopped the evaluation.
	ReceivedDSNRecipientLinkageNotEvaluated ReceivedDSNRecipientLinkage = "not_evaluated"
)

// Known reports whether the value belongs to the closed vocabulary.
func (l ReceivedDSNRecipientLinkage) Known() bool {
	return l == ReceivedDSNRecipientLinkageLinked || l == ReceivedDSNRecipientLinkageUnlinked || l == ReceivedDSNRecipientLinkageNotEvaluated
}

// ReceivedDSNFacts is the immutable, content-free projection of one received-DSN
// evaluation that the policy engine maps through the received-DSN row table.
// It carries only the closed stage members; propagation is informational and
// never a policy input.
type ReceivedDSNFacts struct {
	structure ReceivedDSNStructure
	embedded  ReceivedDSNEmbedded
	localHop  ReceivedDSNLocalHop
	alignment ReceivedDSNOuterAlignment
	linkage   ReceivedDSNRecipientLinkage
}

// NewReceivedDSNFacts seals one stage-coherent received-DSN projection.
func NewReceivedDSNFacts(structure ReceivedDSNStructure, embedded ReceivedDSNEmbedded, localHop ReceivedDSNLocalHop, alignment ReceivedDSNOuterAlignment, linkage ReceivedDSNRecipientLinkage) (ReceivedDSNFacts, error) {
	facts := ReceivedDSNFacts{structure: structure, embedded: embedded, localHop: localHop, alignment: alignment, linkage: linkage}
	if !facts.Valid() {
		return ReceivedDSNFacts{}, newError(ErrorInvalidInput)
	}
	return facts, nil
}

// Valid reports whether the members are known and coherent with the
// stop-at-first-failure stage order of the evaluation.
func (f ReceivedDSNFacts) Valid() bool {
	if !f.structure.Known() || !f.localHop.Known() || !f.alignment.Known() || !f.linkage.Known() {
		return false
	}
	laterNotEvaluated := f.localHop == ReceivedDSNLocalHopNotEvaluated && f.alignment == ReceivedDSNOuterAlignmentNotEvaluated && f.linkage == ReceivedDSNRecipientLinkageNotEvaluated
	if f.structure != ReceivedDSNStructureValid {
		return f.embedded == "" && laterNotEvaluated
	}
	if !f.embedded.Known() {
		return false
	}
	if !f.embedded.verified() {
		return laterNotEvaluated
	}
	if f.localHop != ReceivedDSNLocalHopLocal {
		return f.alignment == ReceivedDSNOuterAlignmentNotEvaluated && f.linkage == ReceivedDSNRecipientLinkageNotEvaluated
	}
	if f.alignment != ReceivedDSNOuterAlignmentAligned {
		return f.linkage == ReceivedDSNRecipientLinkageNotEvaluated
	}
	return f.linkage != ReceivedDSNRecipientLinkageNotEvaluated
}

// Structure returns the closed structure member.
func (f ReceivedDSNFacts) Structure() ReceivedDSNStructure { return f.structure }

// Embedded returns the closed embedded member or the empty value before that stage.
func (f ReceivedDSNFacts) Embedded() ReceivedDSNEmbedded { return f.embedded }

// LocalHop returns the closed local_hop member.
func (f ReceivedDSNFacts) LocalHop() ReceivedDSNLocalHop { return f.localHop }

// OuterAlignment returns the closed outer_alignment member.
func (f ReceivedDSNFacts) OuterAlignment() ReceivedDSNOuterAlignment { return f.alignment }

// RecipientLinkage returns the closed recipient_linkage member.
func (f ReceivedDSNFacts) RecipientLinkage() ReceivedDSNRecipientLinkage { return f.linkage }

// receivedDSNRowReason selects the first matching received-DSN row in stage
// order for an outer verification of the given protocol class. The rows are
// local policy; only the reject rows for an unverified embedded original and
// an identity mismatch restate the Draft-06 Section 12.1.2 SHOULD.
func receivedDSNRowReason(protocol ProtocolClass, facts ReceivedDSNFacts) PolicyReason {
	switch {
	case protocol != ProtocolPASS:
		return ReasonReceivedDSNOuterPolicy
	case facts.structure != ReceivedDSNStructureValid:
		return ReasonReceivedDSNStructureInvalid
	case facts.embedded == ReceivedDSNEmbeddedUnverified:
		return ReasonReceivedDSNEmbeddedUnverified
	case facts.embedded == ReceivedDSNEmbeddedAbsent:
		return ReasonReceivedDSNEmbeddedAbsent
	case facts.embedded == ReceivedDSNEmbeddedTemperror || facts.localHop == ReceivedDSNLocalHopTemperror:
		return ReasonReceivedDSNTemporaryFailure
	case facts.localHop == ReceivedDSNLocalHopNotEvaluated:
		return ReasonReceivedDSNTenantUnavailable
	case facts.localHop == ReceivedDSNLocalHopMismatch || facts.alignment == ReceivedDSNOuterAlignmentMisaligned:
		return ReasonReceivedDSNIdentityMismatch
	case facts.localHop == ReceivedDSNLocalHopNotLocal:
		return ReasonReceivedDSNNotLocal
	case facts.linkage == ReceivedDSNRecipientLinkageUnlinked:
		return ReasonReceivedDSNRecipientUnlinked
	default:
		return ReasonReceivedDSNLinked
	}
}

// receivedDSNRowVerdict returns the verdict a received-DSN row imposes in the
// given mode and whether it replaces the outer verdict. Accept rows keep the
// outer verdict so that a DSN fact never upgrades a restrictive or
// non-terminal outer decision.
func receivedDSNRowVerdict(mode Mode, reason PolicyReason) (Verdict, bool) {
	switch reason {
	case ReasonReceivedDSNStructureInvalid, ReasonReceivedDSNEmbeddedUnverified,
		ReasonReceivedDSNIdentityMismatch, ReasonReceivedDSNRecipientUnlinked:
		if mode == ModeStrict {
			return VerdictReject, true
		}
		return VerdictContinue, true
	case ReasonReceivedDSNTemporaryFailure:
		if mode == ModeTesting {
			return VerdictContinue, true
		}
		return VerdictTempfail, true
	default:
		return "", false
	}
}

// receivedDSNFindingReason returns the single received-DSN finding reason when present.
func receivedDSNFindingReason(findings []Finding) (PolicyReason, bool) {
	for _, finding := range findings {
		if complianceFindingClass(finding.reason) == receivedDSNFindingClass {
			return finding.reason, true
		}
	}
	return "", false
}

// receivedDSNFindingCount counts received-DSN findings, of which at most one is coherent.
func receivedDSNFindingCount(findings []Finding) int {
	count := 0
	for _, finding := range findings {
		if complianceFindingClass(finding.reason) == receivedDSNFindingClass {
			count++
		}
	}
	return count
}

// receivedDSNDecisionCoherent binds the received-DSN finding to the protocol
// class and returns the verdict override it imposes, if any.
func receivedDSNDecisionCoherent(protocol ProtocolClass, mode Mode, findings []Finding) (Verdict, PolicyReason, bool, bool) {
	if receivedDSNFindingCount(findings) > 1 {
		return "", "", false, false
	}
	reason, present := receivedDSNFindingReason(findings)
	if !present {
		return "", "", false, true
	}
	if (reason == ReasonReceivedDSNOuterPolicy) != (protocol != ProtocolPASS) {
		return "", "", false, false
	}
	verdict, replace := receivedDSNRowVerdict(mode, reason)
	return verdict, reason, replace, true
}
