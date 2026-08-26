package verify

import (
	"fmt"
	"io"
	"slices"

	"github.com/croessner/dkim2/internal/signature"
)

// writeRevisionFactSummary writes one constant secret-safe fact representation.
func writeRevisionFactSummary(state fmt.State, name string) {
	_, _ = io.WriteString(state, "verify."+name+"{redacted}")
}

// RevisionSetState identifies one inherited set's accepted proof role.
type RevisionSetState string

const (
	// RevisionSetSupportedPass reports one known supported passing set.
	RevisionSetSupportedPass RevisionSetState = "supported_pass"
	// RevisionSetIgnoredUnknown reports one unknown extension ignored beside a pass.
	RevisionSetIgnoredUnknown RevisionSetState = "ignored_unknown"
)

// Known reports whether state belongs to the closed accepted-set vocabulary.
func (s RevisionSetState) Known() bool {
	return s == RevisionSetSupportedPass || s == RevisionSetIgnoredUnknown
}

// RevisionSetFact stores one source-indexed accepted signature-set fact.
type RevisionSetFact struct {
	index     int
	algorithm Algorithm
	state     RevisionSetState
}

// String returns a constant secret-safe set fact summary.
func (f RevisionSetFact) String() string { return "verify.RevisionSetFact{redacted}" }

// GoString returns a constant secret-safe set fact Go representation.
func (f RevisionSetFact) GoString() string { return f.String() }

// Format routes every set fact format through the redacted summary.
func (f RevisionSetFact) Format(state fmt.State, _ rune) {
	writeRevisionFactSummary(state, "RevisionSetFact")
}

// Index returns source order within the inherited field.
func (f RevisionSetFact) Index() int { return f.index }

// Algorithm returns a known algorithm or the bounded unknown token.
func (f RevisionSetFact) Algorithm() Algorithm { return f.algorithm }

// State returns the accepted set role.
func (f RevisionSetFact) State() RevisionSetState { return f.state }

// Valid reports whether the set fact is closed and coherent.
func (f RevisionSetFact) Valid() bool {
	return f.index >= 0 && (f.state == RevisionSetSupportedPass && knownAlgorithm(f.algorithm) || f.state == RevisionSetIgnoredUnknown && f.algorithm == AlgorithmUnknown)
}

// RevisionSignatureFact stores one complete inherited signature proof projection.
type RevisionSignatureFact struct {
	sequence, instance, timestamp uint64
	flags                         RevisionFlagFacts
	sets                          []RevisionSetFact
}

// String returns a constant secret-safe signature fact summary.
func (f RevisionSignatureFact) String() string { return "verify.RevisionSignatureFact{redacted}" }

// GoString returns a constant secret-safe signature fact Go representation.
func (f RevisionSignatureFact) GoString() string { return f.String() }

// Format routes every signature fact format through the redacted summary.
func (f RevisionSignatureFact) Format(state fmt.State, _ rune) {
	writeRevisionFactSummary(state, "RevisionSignatureFact")
}

// Sequence returns the inherited i= value.
func (f RevisionSignatureFact) Sequence() uint64 { return f.sequence }

// Instance returns the inherited m= reference.
func (f RevisionSignatureFact) Instance() uint64 { return f.instance }

// Timestamp returns the inherited t= seconds.
func (f RevisionSignatureFact) Timestamp() uint64 { return f.timestamp }

// Flags returns bounded authenticated policy flags.
func (f RevisionSignatureFact) Flags() RevisionFlagFacts { return f.flags }

// Sets returns detached source-ordered set facts.
func (f RevisionSignatureFact) Sets() []RevisionSetFact { return slices.Clone(f.sets) }

// Valid reports whether the signature fact has a supported pass and complete indexes.
func (f RevisionSignatureFact) Valid() bool {
	if f.sequence == 0 || f.instance == 0 || len(f.sets) == 0 {
		return false
	}
	passes := 0
	for index, set := range f.sets {
		if !set.Valid() || set.index != index {
			return false
		}
		if set.state == RevisionSetSupportedPass {
			passes++
		}
	}
	return passes > 0
}

// RevisionHashFacts stores the verifier-local canonical SHA-256 projection.
type RevisionHashFacts struct {
	instance     uint64
	header, body [sha256DigestLength]byte
}

// String returns a constant secret-safe hash fact summary.
func (f RevisionHashFacts) String() string { return "verify.RevisionHashFacts{redacted}" }

// GoString returns a constant secret-safe hash fact Go representation.
func (f RevisionHashFacts) GoString() string { return f.String() }

// Format routes every hash fact format through the redacted summary.
func (f RevisionHashFacts) Format(state fmt.State, _ rune) {
	writeRevisionFactSummary(state, "RevisionHashFacts")
}

// Instance returns the selected current m= value.
func (f RevisionHashFacts) Instance() uint64 { return f.instance }

// HeaderDigest returns the locally computed canonical SHA-256 header digest.
func (f RevisionHashFacts) HeaderDigest() [sha256DigestLength]byte { return f.header }

// BodyDigest returns the locally computed canonical SHA-256 body digest.
func (f RevisionHashFacts) BodyDigest() [sha256DigestLength]byte { return f.body }

// Valid reports whether fixed SHA-256 pass facts name a current instance.
func (f RevisionHashFacts) Valid() bool { return f.instance > 0 }

// RevisionEnvelopeState identifies the already-proved current-envelope result.
type RevisionEnvelopeState string

const (
	// RevisionEnvelopeOrdinaryPass reports passing current mf=/rt= comparison.
	RevisionEnvelopeOrdinaryPass RevisionEnvelopeState = "ordinary_pass"
	// RevisionEnvelopeTerminalNextDomainNotApplicable reports the terminal nd= exception.
	RevisionEnvelopeTerminalNextDomainNotApplicable RevisionEnvelopeState = "terminal_next_domain_not_applicable"
)

// Known reports whether state belongs to the closed revision-envelope vocabulary.
func (s RevisionEnvelopeState) Known() bool {
	return s == RevisionEnvelopeOrdinaryPass || s == RevisionEnvelopeTerminalNextDomainNotApplicable
}

// RevisionCustodyLinkStatus identifies one already-passing custody link kind.
type RevisionCustodyLinkStatus string

const (
	// RevisionCustodyOrigin reports the first signature without a predecessor.
	RevisionCustodyOrigin RevisionCustodyLinkStatus = "origin"
	// RevisionCustodyOrdinaryToOrdinaryPass reports a passing Section 9.4 link.
	RevisionCustodyOrdinaryToOrdinaryPass RevisionCustodyLinkStatus = "ordinary_to_ordinary_pass"
	// RevisionCustodyOrdinaryToNextDomainPass reports a passing Section 9.3 authorization link.
	RevisionCustodyOrdinaryToNextDomainPass RevisionCustodyLinkStatus = "ordinary_to_next_domain_pass"
	// RevisionCustodyNextDomainToSignaturePass reports a passing nd= to d= link.
	RevisionCustodyNextDomainToSignaturePass RevisionCustodyLinkStatus = "next_domain_to_signature_pass"
)

// Known reports whether status belongs to the closed passing-link vocabulary.
func (s RevisionCustodyLinkStatus) Known() bool {
	return s == RevisionCustodyOrigin || s == RevisionCustodyOrdinaryToOrdinaryPass ||
		s == RevisionCustodyOrdinaryToNextDomainPass || s == RevisionCustodyNextDomainToSignaturePass
}

// RevisionCustodyHopFact stores one bounded passing direct/link projection.
type RevisionCustodyHopFact struct {
	sequence uint64
	direct   signature.CustodyDirectAlignmentStatus
	link     RevisionCustodyLinkStatus
}

// Sequence returns the inherited i= value.
func (f RevisionCustodyHopFact) Sequence() uint64 { return f.sequence }

// Direct returns the shared d=/mf= status.
func (f RevisionCustodyHopFact) Direct() signature.CustodyDirectAlignmentStatus { return f.direct }

// Link returns the passing predecessor-link kind.
func (f RevisionCustodyHopFact) Link() RevisionCustodyLinkStatus { return f.link }

// RevisionCustodyFacts stores the complete shared custody projection.
type RevisionCustodyFacts struct {
	status signature.CustodyStatus
	hadND  bool
	hops   []RevisionCustodyHopFact
}

// String returns a constant secret-safe custody fact summary.
func (f RevisionCustodyFacts) String() string { return "verify.RevisionCustodyFacts{redacted}" }

// GoString returns a constant secret-safe custody fact Go representation.
func (f RevisionCustodyFacts) GoString() string { return f.String() }

// Format routes every custody fact format through the redacted summary.
func (f RevisionCustodyFacts) Format(state fmt.State, _ rune) {
	writeRevisionFactSummary(state, "RevisionCustodyFacts")
}

// Status returns the shared terminal custody status.
func (f RevisionCustodyFacts) Status() signature.CustodyStatus { return f.status }

// HadNextDomain reports whether any inherited hop used nd=.
func (f RevisionCustodyFacts) HadNextDomain() bool { return f.hadND }

// Hops returns detached complete per-hop facts.
func (f RevisionCustodyFacts) Hops() []RevisionCustodyHopFact { return slices.Clone(f.hops) }

// Valid reports whether custody facts are complete, contiguous, and passing.
func (f RevisionCustodyFacts) Valid() bool {
	if !f.status.Known() || len(f.hops) == 0 {
		return false
	}
	derivedND := false
	for index, hop := range f.hops {
		if hop.sequence != uint64(index+1) || !hop.direct.Known() || !hop.link.Known() || index == 0 && hop.link != RevisionCustodyOrigin || index > 0 && hop.link == RevisionCustodyOrigin {
			return false
		}
		if hop.direct == signature.CustodyDirectAlignmentMismatch || hop.direct == signature.CustodyDirectAlignmentInvalid {
			return false
		}
		derivedND = derivedND || hop.direct == signature.CustodyDirectAlignmentNotApplicableNextDomain
		if index > 0 {
			previousND := f.hops[index-1].direct == signature.CustodyDirectAlignmentNotApplicableNextDomain
			currentND := hop.direct == signature.CustodyDirectAlignmentNotApplicableNextDomain
			expected := RevisionCustodyOrdinaryToOrdinaryPass
			if previousND {
				expected = RevisionCustodyNextDomainToSignaturePass
			} else if currentND {
				expected = RevisionCustodyOrdinaryToNextDomainPass
			}
			if hop.link != expected {
				return false
			}
		}
	}
	terminalND := f.hops[len(f.hops)-1].direct == signature.CustodyDirectAlignmentNotApplicableNextDomain
	return derivedND == f.hadND && (f.status == signature.CustodyStatusTerminalNextDomain) == terminalND
}

// RevisionHistoryTransitionFact stores one redacted adjacent proof.
type RevisionHistoryTransitionFact struct {
	from, to     uint64
	mode         HistoryRecipeMode
	header, body HistoryDimensionState
}

// From returns the recipe-owning m= value.
func (f RevisionHistoryTransitionFact) From() uint64 { return f.from }

// To returns the reconstructed adjacent m= value.
func (f RevisionHistoryTransitionFact) To() uint64 { return f.to }

// Mode returns the applied recipe mode.
func (f RevisionHistoryTransitionFact) Mode() HistoryRecipeMode { return f.mode }

// Header returns the authenticated header state.
func (f RevisionHistoryTransitionFact) Header() HistoryDimensionState { return f.header }

// Body returns the authenticated body state.
func (f RevisionHistoryTransitionFact) Body() HistoryDimensionState { return f.body }

// Valid reports whether the transition contains only accepted proof states.
func (f RevisionHistoryTransitionFact) Valid() bool {
	return f.from > 1 && f.to+1 == f.from && f.mode.Known() && f.header == HistoryDimensionMatched &&
		(f.body == HistoryDimensionMatched || f.body == HistoryDimensionUnavailable)
}

// RevisionHistoryFacts stores accepted history without reconstructed state.
type RevisionHistoryFacts struct {
	coverage        HistoryCoverage
	stop            HistoryStopReason
	target, reached uint64
	gap             bool
	transitions     []RevisionHistoryTransitionFact
	usage           HistoryUsage
}

// String returns a constant secret-safe history fact summary.
func (f RevisionHistoryFacts) String() string { return "verify.RevisionHistoryFacts{redacted}" }

// GoString returns a constant secret-safe history fact Go representation.
func (f RevisionHistoryFacts) GoString() string { return f.String() }

// Format routes every history fact format through the redacted summary.
func (f RevisionHistoryFacts) Format(state fmt.State, _ rune) {
	writeRevisionFactSummary(state, "RevisionHistoryFacts")
}

// Coverage returns accepted historical coverage.
func (f RevisionHistoryFacts) Coverage() HistoryCoverage { return f.coverage }

// Stop returns the origin stop reason.
func (f RevisionHistoryFacts) Stop() HistoryStopReason { return f.stop }

// Target returns the highest historical m= value.
func (f RevisionHistoryFacts) Target() uint64 { return f.target }

// Reached returns the earliest proved m= value.
func (f RevisionHistoryFacts) Reached() uint64 { return f.reached }

// HasUnavailableBody reports the persistent explicit b:null gap.
func (f RevisionHistoryFacts) HasUnavailableBody() bool { return f.gap }

// Transitions returns detached redacted adjacent facts.
func (f RevisionHistoryFacts) Transitions() []RevisionHistoryTransitionFact {
	return slices.Clone(f.transitions)
}

// Usage returns bounded authenticated history work.
func (f RevisionHistoryFacts) Usage() HistoryUsage { return f.usage }

// Valid reports whether every retained transition reached origin cleanly.
func (f RevisionHistoryFacts) Valid() bool {
	if f.stop != HistoryStopOriginReached || f.target == 0 || f.reached != 1 || !f.usage.Valid() || len(f.transitions) != int(f.target-1) {
		return false
	}
	if f.coverage != HistoryCoverageComplete || f.gap {
		if f.coverage != HistoryCoveragePartial || !f.gap {
			return false
		}
	}
	derivedGap := false
	for index, transition := range f.transitions {
		if !transition.Valid() || transition.from != f.target-uint64(index) {
			return false
		}
		derivedGap = derivedGap || transition.body == HistoryDimensionUnavailable
	}
	return derivedGap == f.gap
}

// RevisionUsage stores aggregate all-hop proof work.
type RevisionUsage struct {
	protocolFields, signatureSets, keyLookups, providerCalls       int
	canonicalBytes, currentCanonicalBytes, signatureCanonicalBytes int
	history                                                        HistoryUsage
}

// String returns a constant secret-safe usage summary.
func (u RevisionUsage) String() string { return "verify.RevisionUsage{redacted}" }

// GoString returns a constant secret-safe usage Go representation.
func (u RevisionUsage) GoString() string { return u.String() }

// Format routes every usage format through the redacted summary.
func (u RevisionUsage) Format(state fmt.State, _ rune) {
	writeRevisionFactSummary(state, "RevisionUsage")
}

// ProtocolFields returns inherited protocol field count.
func (u RevisionUsage) ProtocolFields() int { return u.protocolFields }

// SignatureSets returns inherited set count.
func (u RevisionUsage) SignatureSets() int { return u.signatureSets }

// KeyLookups returns supported-set lookup count.
func (u RevisionUsage) KeyLookups() int { return u.keyLookups }

// ProviderCalls returns actual provider callback count.
func (u RevisionUsage) ProviderCalls() int { return u.providerCalls }

// CanonicalBytes returns aggregate Section 6 and Section 9.6 input bytes.
func (u RevisionUsage) CanonicalBytes() int { return u.canonicalBytes }

// CurrentCanonicalBytes returns current Section 6 hash input work.
func (u RevisionUsage) CurrentCanonicalBytes() int { return u.currentCanonicalBytes }

// SignatureCanonicalBytes returns aggregate Section 9.6 input work.
func (u RevisionUsage) SignatureCanonicalBytes() int { return u.signatureCanonicalBytes }

// History returns bounded recipe/history usage.
func (u RevisionUsage) History() HistoryUsage { return u.history }

// Valid reports whether aggregate counts are nonnegative and callback-exact.
func (u RevisionUsage) Valid() bool {
	return u.protocolFields > 0 && u.signatureSets > 0 && u.keyLookups > 0 && u.providerCalls == u.keyLookups &&
		u.currentCanonicalBytes > 0 && u.signatureCanonicalBytes > 0 && u.history.Valid() &&
		u.canonicalBytes == u.currentCanonicalBytes+u.signatureCanonicalBytes+u.history.CanonicalBytes()
}
