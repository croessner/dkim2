package verify

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"slices"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/recipe"
)

const (
	// VerifierProjectionSchema identifies the stable transport-neutral projection shape.
	VerifierProjectionSchema = "dkim2.verifier-projection.v1"
	verifierProjectionDomain = "dkim2-verifier-projection-binding-v1"
	verifierHopDomain        = "dkim2-verifier-hop-binding-v1"
	verifierProjectionText   = "verify.VerifierProjection{redacted}"
)

// VerifierCustodyTransition identifies one authenticated hop's chain role.
type VerifierCustodyTransition string

const (
	// VerifierCustodyOrigin identifies the first authenticated signature.
	VerifierCustodyOrigin VerifierCustodyTransition = "origin"
	// VerifierCustodyOrdinary identifies an ordinary adjacent custody link.
	VerifierCustodyOrdinary VerifierCustodyTransition = "ordinary"
	// VerifierCustodyNextDomain identifies a link involving authenticated nd= custody.
	VerifierCustodyNextDomain VerifierCustodyTransition = "next_domain"
	// VerifierCustodyTerminalNextDomain identifies an unresolved terminal nd= claim.
	VerifierCustodyTerminalNextDomain VerifierCustodyTransition = "terminal_next_domain"
)

// Known reports whether the transition belongs to the closed projection vocabulary.
func (t VerifierCustodyTransition) Known() bool {
	return t == VerifierCustodyOrigin || t == VerifierCustodyOrdinary ||
		t == VerifierCustodyNextDomain || t == VerifierCustodyTerminalNextDomain
}

// VerifierRecipeMode identifies whether one authenticated transition used a Recipe.
type VerifierRecipeMode string

const (
	// VerifierRecipeUnchanged reports an absent Recipe and unchanged state.
	VerifierRecipeUnchanged VerifierRecipeMode = "unchanged"
	// VerifierRecipeApplied reports a parsed and authenticated Recipe transition.
	VerifierRecipeApplied VerifierRecipeMode = "applied"
)

// Known reports whether the mode belongs to the closed projection vocabulary.
func (m VerifierRecipeMode) Known() bool {
	return m == VerifierRecipeUnchanged || m == VerifierRecipeApplied
}

// VerifierHop stores one immutable authenticated chain record.
type VerifierHop struct {
	domain        string
	algorithms    []Algorithm
	recipe        recipe.Descriptor
	binding       [sha256.Size]byte
	sequence      uint64
	instance      uint64
	custody       VerifierCustodyTransition
	recipeMode    VerifierRecipeMode
	headerState   HistoryDimensionState
	bodyState     HistoryDimensionState
	bodyAvailable recipe.BodyAvailability
	flags         RevisionFlagFacts
	sealed        bool
}

// Valid reports whether the hop is complete, bounded, and binding-coherent.
func (h VerifierHop) Valid() bool {
	return verifierHopShapeValid(h) && h.binding != ([sha256.Size]byte{})
}

// verifierHopShapeValid validates closed hop content independently of its projection binding.
func verifierHopShapeValid(h VerifierHop) bool {
	if !h.sealed || h.sequence == 0 || h.instance == 0 || h.domain == "" || len(h.domain) > 253 ||
		len(h.algorithms) == 0 || len(h.algorithms) > 4 || !h.custody.Known() ||
		!h.recipeMode.Known() || !h.recipe.Valid() || !h.headerState.Known() ||
		!h.bodyState.Known() || !h.bodyAvailable.Known() {
		return false
	}
	for index, algorithm := range h.algorithms {
		if !knownAlgorithm(algorithm) || index > 0 && h.algorithms[index-1] >= algorithm {
			return false
		}
	}
	return true
}

// Sequence returns the authenticated signature sequence.
func (h VerifierHop) Sequence() uint64 { return h.sequence }

// MessageInstance returns the authenticated Message-Instance number.
func (h VerifierHop) MessageInstance() uint64 { return h.instance }

// SignerDomain returns the canonical verified signing domain.
func (h VerifierHop) SignerDomain() string {
	if !h.Valid() {
		return ""
	}
	return h.domain
}

// SignatureAlgorithms returns sorted unique successfully verified algorithms.
func (h VerifierHop) SignatureAlgorithms() []Algorithm {
	if !h.Valid() {
		return nil
	}
	return slices.Clone(h.algorithms)
}

// CustodyTransition returns the authenticated closed custody role.
func (h VerifierHop) CustodyTransition() VerifierCustodyTransition { return h.custody }

// Flags returns authenticated policy flags by value.
func (h VerifierHop) Flags() RevisionFlagFacts { return h.flags }

// RecipeMode returns whether the transition used a Recipe.
func (h VerifierHop) RecipeMode() VerifierRecipeMode { return h.recipeMode }

// Recipe returns the immutable privacy-minimized Recipe descriptor.
func (h VerifierHop) Recipe() recipe.Descriptor { return h.recipe }

// HistoryHeaderState returns authenticated historical header comparison state.
func (h VerifierHop) HistoryHeaderState() HistoryDimensionState { return h.headerState }

// HistoryBodyState returns authenticated historical body comparison state.
func (h VerifierHop) HistoryBodyState() HistoryDimensionState { return h.bodyState }

// BodyAvailability returns whether authenticated historical body bytes were available.
func (h VerifierHop) BodyAvailability() recipe.BodyAvailability { return h.bodyAvailable }

// HopBinding returns the deterministic SHA-256 binding for this record.
func (h VerifierHop) HopBinding() [sha256.Size]byte {
	if !h.Valid() {
		return [sha256.Size]byte{}
	}
	return h.binding
}

// String returns a constant representation without message-derived facts.
func (VerifierHop) String() string { return "verify.VerifierHop{redacted}" }

// GoString returns a constant representation without message-derived facts.
func (VerifierHop) GoString() string { return "verify.VerifierHop{redacted}" }

// Format prevents formatting verbs from exposing message-derived facts.
func (VerifierHop) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "verify.VerifierHop{redacted}")
}

// clone returns an independently owned hop.
func (h VerifierHop) clone() VerifierHop {
	h.algorithms = slices.Clone(h.algorithms)
	return h
}

// VerifierProjection stores one sealed complete-chain policy evidence projection.
type VerifierProjection struct {
	hops    []VerifierHop
	binding [sha256.Size]byte
	draft   string
	schema  string
	sealed  bool
}

// Valid reports whether the projection is complete, contiguous, and binding-coherent.
func (p VerifierProjection) Valid() bool {
	if !p.sealed || p.schema != VerifierProjectionSchema || p.draft != DraftBaseline || len(p.hops) == 0 || len(p.hops) > 128 {
		return false
	}
	for index, hop := range p.hops {
		if !hop.Valid() || hop.sequence != uint64(index+1) ||
			hop.binding != verifierBoundHopBinding(p.binding, hop) {
			return false
		}
	}
	return p.binding == verifierProjectionBinding(p.hops)
}

// Schema returns the exact stable projection identity.
func (p VerifierProjection) Schema() string {
	if !p.Valid() {
		return ""
	}
	return p.schema
}

// Draft returns the exact protocol baseline.
func (p VerifierProjection) Draft() string {
	if !p.Valid() {
		return ""
	}
	return p.draft
}

// Binding returns the complete projection SHA-256 binding.
func (p VerifierProjection) Binding() [sha256.Size]byte {
	if !p.Valid() {
		return [sha256.Size]byte{}
	}
	return p.binding
}

// Hops returns detached ordered chain records.
func (p VerifierProjection) Hops() []VerifierHop {
	if !p.Valid() {
		return nil
	}
	return cloneVerifierHops(p.hops)
}

// String returns a constant representation without message-derived facts.
func (VerifierProjection) String() string { return verifierProjectionText }

// GoString returns a constant representation without message-derived facts.
func (VerifierProjection) GoString() string { return verifierProjectionText }

// Format prevents formatting verbs from exposing message-derived facts.
func (VerifierProjection) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, verifierProjectionText)
}

// clone returns an independently owned projection.
func (p VerifierProjection) clone() VerifierProjection {
	p.hops = cloneVerifierHops(p.hops)
	return p
}

// buildVerifierProjection seals already-authenticated revision proof facts.
func (v Verifier) buildVerifierProjection(input verificationInput, base revisionBaseProof, signatures revisionSignatureProof) (VerifierProjection, bool) {
	if len(input.signatures) == 0 || len(input.signatures) != len(signatures.facts) || !base.history.Valid() || base.history.Coverage() == HistoryCoverageFailed {
		return VerifierProjection{}, false
	}
	instances := make(map[uint64]instance.MessageInstance, len(input.instances))
	for _, messageInstance := range input.instances {
		instances[messageInstance.Number()] = messageInstance
	}
	transitions := make(map[uint64]HistoryTransition, len(base.history.Transitions()))
	for _, transition := range base.history.Transitions() {
		transitions[transition.FromInstance()] = transition
	}
	hops := make([]VerifierHop, len(input.signatures))
	custodyFacts := revisionCustodyFacts(base.custody, input.signatures)
	if !custodyFacts.Valid() || len(custodyFacts.hops) != len(input.signatures) {
		return VerifierProjection{}, false
	}
	for index, parsed := range input.signatures {
		fact := signatures.facts[index]
		messageInstance, ok := instances[parsed.InstanceNumber()]
		if !ok || fact.sequence != parsed.Sequence() || fact.instance != parsed.InstanceNumber() {
			return VerifierProjection{}, false
		}
		descriptor := recipe.UnchangedDescriptor()
		mode := VerifierRecipeUnchanged
		headerState, bodyState := HistoryDimensionMatched, HistoryDimensionMatched
		bodyAvailability := recipe.BodyAvailabilityKnown
		if parsed.InstanceNumber() > 1 {
			transition, present := transitions[parsed.InstanceNumber()]
			if !present || !transition.Valid() {
				return VerifierProjection{}, false
			}
			headerState, bodyState = transition.HeaderState(), transition.BodyState()
			if bodyState == HistoryDimensionUnavailable {
				bodyAvailability = recipe.BodyAvailabilityUnavailable
			}
			if encoded, hasRecipe := messageInstance.Recipe(); hasRecipe {
				plan, _, parseErr := v.revisionHistory.parser.Parse(encoded.Decoded())
				if parseErr != nil {
					return VerifierProjection{}, false
				}
				descriptor = plan.Descriptor()
				mode = VerifierRecipeApplied
			}
		}
		algorithms := verifiedRevisionAlgorithms(fact)
		hop := VerifierHop{
			domain: parsed.Domain(), algorithms: algorithms, recipe: descriptor,
			sequence: parsed.Sequence(), instance: parsed.InstanceNumber(),
			custody:    verifierCustodyTransition(custodyFacts.hops[index]),
			recipeMode: mode, headerState: headerState, bodyState: bodyState,
			bodyAvailable: bodyAvailability, flags: fact.flags, sealed: true,
		}
		if !verifierHopShapeValid(hop) {
			return VerifierProjection{}, false
		}
		hops[index] = hop
	}
	projection := VerifierProjection{hops: hops, draft: DraftBaseline, schema: VerifierProjectionSchema, sealed: true}
	projection.binding = verifierProjectionBinding(hops)
	for index := range projection.hops {
		projection.hops[index].binding = verifierBoundHopBinding(projection.binding, projection.hops[index])
	}
	return projection, projection.Valid()
}

// verifiedRevisionAlgorithms returns sorted unique supported passing algorithm families.
func verifiedRevisionAlgorithms(fact RevisionSignatureFact) []Algorithm {
	algorithms := make([]Algorithm, 0, len(fact.sets))
	for _, set := range fact.sets {
		if set.state == RevisionSetSupportedPass && !slices.Contains(algorithms, set.algorithm) {
			algorithms = append(algorithms, set.algorithm)
		}
	}
	slices.Sort(algorithms)
	return algorithms
}

// verifierCustodyTransition maps authenticated chain position and nd= presence to the closed role.
func verifierCustodyTransition(fact RevisionCustodyHopFact) VerifierCustodyTransition {
	if fact.link == RevisionCustodyOrigin {
		return VerifierCustodyOrigin
	}
	if fact.link == RevisionCustodyOrdinaryToNextDomainPass || fact.link == RevisionCustodyNextDomainToSignaturePass {
		return VerifierCustodyNextDomain
	}
	return VerifierCustodyOrdinary
}

// cloneVerifierHops returns deep-cloned ordered records.
func cloneVerifierHops(input []VerifierHop) []VerifierHop {
	result := make([]VerifierHop, len(input))
	for index, hop := range input {
		result[index] = hop.clone()
	}
	return result
}

// verifierHopContentDigest hashes one exact deterministic length-prefixed record without bindings.
func verifierHopContentDigest(hop VerifierHop) [sha256.Size]byte {
	frame := appendVerifierField(nil, []byte(verifierHopDomain))
	frame = appendVerifierUint64(frame, hop.sequence)
	frame = appendVerifierUint64(frame, hop.instance)
	frame = appendVerifierField(frame, []byte(hop.domain))
	frame = appendVerifierStrings(frame, algorithmsAsStrings(hop.algorithms))
	frame = appendVerifierField(frame, []byte("pass"))
	frame = appendVerifierField(frame, []byte(hop.custody))
	frame = appendVerifierFlags(frame, hop.flags)
	frame = appendVerifierField(frame, []byte(hop.recipeMode))
	frame = appendVerifierBoolean(frame, hop.recipe.HasHeaderChanges())
	frame = appendVerifierField(frame, []byte(hop.recipe.BodyMode()))
	recipeDigest := hop.recipe.Digest()
	frame = appendVerifierField(frame, recipeDigest[:])
	changeClasses := hop.recipe.ChangeClasses()
	changeClassStrings := make([]string, len(changeClasses))
	for index, class := range changeClasses {
		changeClassStrings[index] = string(class)
	}
	frame = appendVerifierStrings(frame, changeClassStrings)
	frame = appendVerifierStrings(frame, hop.recipe.AffectedHeaders())
	frame = appendVerifierUint64(frame, uint64(hop.recipe.ChangeCount()))
	frame = appendVerifierUint64(frame, uint64(hop.recipe.AffectedHeaderCount()))
	frame = appendVerifierField(frame, []byte(hop.headerState))
	frame = appendVerifierField(frame, []byte(hop.bodyState))
	frame = appendVerifierField(frame, []byte(hop.bodyAvailable))
	return sha256.Sum256(frame)
}

// appendVerifierBoolean appends one canonical raw boolean byte.
func appendVerifierBoolean(output []byte, value bool) []byte {
	if value {
		return append(output, 1)
	}
	return append(output, 0)
}

// verifierProjectionBinding hashes the ordered set of base hop content digests.
func verifierProjectionBinding(hops []VerifierHop) [sha256.Size]byte {
	frame := appendVerifierField(nil, []byte(verifierProjectionDomain))
	frame = appendVerifierField(frame, []byte(VerifierProjectionSchema))
	frame = appendVerifierField(frame, []byte(DraftBaseline))
	frame = appendVerifierUint64(frame, uint64(len(hops)))
	for _, hop := range hops {
		contentDigest := verifierHopContentDigest(hop)
		frame = appendVerifierField(frame, contentDigest[:])
	}
	return sha256.Sum256(frame)
}

// verifierBoundHopBinding binds one base hop digest to the exact complete projection.
func verifierBoundHopBinding(projectionBinding [sha256.Size]byte, hop VerifierHop) [sha256.Size]byte {
	contentDigest := verifierHopContentDigest(hop)
	frame := appendVerifierField(nil, []byte("dkim2-verifier-bound-hop-v1"))
	frame = appendVerifierField(frame, projectionBinding[:])
	frame = appendVerifierUint64(frame, hop.sequence)
	frame = appendVerifierField(frame, contentDigest[:])
	return sha256.Sum256(frame)
}

// algorithmsAsStrings projects a closed algorithm list for canonical framing.
func algorithmsAsStrings(algorithms []Algorithm) []string {
	result := make([]string, len(algorithms))
	for index, algorithm := range algorithms {
		result[index] = string(algorithm)
	}
	return result
}

// appendVerifierFlags appends authenticated booleans in fixed schema order.
func appendVerifierFlags(output []byte, flags RevisionFlagFacts) []byte {
	for _, value := range []bool{flags.doNotModify, flags.doNotExplode, flags.feedback, flags.feedHere, flags.exploded} {
		if value {
			output = append(output, 1)
		} else {
			output = append(output, 0)
		}
	}
	return output
}

// appendVerifierStrings appends a length-prefixed ordered string collection.
func appendVerifierStrings(output []byte, values []string) []byte {
	output = appendVerifierUint64(output, uint64(len(values)))
	for _, value := range values {
		output = appendVerifierField(output, []byte(value))
	}
	return output
}

// appendVerifierField appends one network-order length-prefixed byte value.
func appendVerifierField(output, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	output = append(output, length[:]...)
	return append(output, value...)
}

// appendVerifierUint64 appends one fixed-width network-order integer.
func appendVerifierUint64(output []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(output, encoded[:]...)
}
