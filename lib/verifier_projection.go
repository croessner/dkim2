package dkim2

import (
	"fmt"
	"io"
	"slices"

	"github.com/croessner/dkim2/internal/service"
)

// VerifierProjectionSchema identifies the stable transport-neutral verifier projection.
const VerifierProjectionSchema = "dkim2.verifier-projection.v1"

// VerifierRecipeDescriptor is a privacy-minimized authenticated Recipe summary.
type VerifierRecipeDescriptor struct {
	state *verifierRecipeDescriptorState
}

type verifierRecipeDescriptorState struct {
	affectedHeaders []string
	changeClasses   []string
	digest          [32]byte
	bodyMode        string
}

// Valid reports whether the descriptor is a closed bounded projection.
func (d VerifierRecipeDescriptor) Valid() bool {
	return d.state != nil && d.state.digest != ([32]byte{}) &&
		(d.state.bodyMode == "absent" || d.state.bodyMode == "steps" || d.state.bodyMode == "unavailable") &&
		len(d.state.affectedHeaders) <= 128 && len(d.state.changeClasses) <= 2
}

// HasHeaderChanges reports whether any authenticated header dimension is present.
func (d VerifierRecipeDescriptor) HasHeaderChanges() bool {
	return d.Valid() && len(d.state.affectedHeaders) > 0
}

// AffectedHeaders returns sorted unique lower-case header names without values.
func (d VerifierRecipeDescriptor) AffectedHeaders() []string {
	if !d.Valid() {
		return nil
	}
	return slices.Clone(d.state.affectedHeaders)
}

// ChangeClasses returns sorted unique conservative change classes.
func (d VerifierRecipeDescriptor) ChangeClasses() []string {
	if !d.Valid() {
		return nil
	}
	return slices.Clone(d.state.changeClasses)
}

// Digest returns the verifier-owned normalized descriptor binding.
func (d VerifierRecipeDescriptor) Digest() [32]byte {
	if !d.Valid() {
		return [32]byte{}
	}
	return d.state.digest
}

// BodyMode returns absent, steps, or unavailable.
func (d VerifierRecipeDescriptor) BodyMode() string {
	if !d.Valid() {
		return ""
	}
	return d.state.bodyMode
}

// ChangeCount returns the number of normalized change dimensions.
func (d VerifierRecipeDescriptor) ChangeCount() int {
	if !d.Valid() {
		return 0
	}
	return len(d.state.changeClasses)
}

// AffectedHeaderCount returns the coherence count for AffectedHeaders.
func (d VerifierRecipeDescriptor) AffectedHeaderCount() int {
	if !d.Valid() {
		return 0
	}
	return len(d.state.affectedHeaders)
}

// String returns a constant representation without message-derived facts.
func (VerifierRecipeDescriptor) String() string { return "dkim2.VerifierRecipeDescriptor{redacted}" }

// GoString returns a constant representation without message-derived facts.
func (VerifierRecipeDescriptor) GoString() string { return "dkim2.VerifierRecipeDescriptor{redacted}" }

// Format prevents formatting verbs from exposing message-derived facts.
func (VerifierRecipeDescriptor) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "dkim2.VerifierRecipeDescriptor{redacted}")
}

// VerifierHop is one immutable authenticated chain record.
type VerifierHop struct{ state *verifierHopState }

type verifierHopState struct {
	domain, custody, recipeMode, headerState, bodyState, bodyAvailability string
	algorithms                                                            []string
	recipe                                                                VerifierRecipeDescriptor
	binding                                                               [32]byte
	sequence, instance                                                    uint64
	doNotModify, doNotExplode, feedback, feedHere, exploded               bool
}

// Valid reports whether the hop owns complete cloned evidence.
func (h VerifierHop) Valid() bool {
	return h.state != nil && h.state.sequence > 0 && h.state.instance > 0 && h.state.domain != "" && len(h.state.algorithms) > 0 && h.state.recipe.Valid() && h.state.binding != ([32]byte{})
}

// Sequence returns the authenticated signature sequence.
func (h VerifierHop) Sequence() uint64 {
	if !h.Valid() {
		return 0
	}
	return h.state.sequence
}

// MessageInstance returns the authenticated Message-Instance number.
func (h VerifierHop) MessageInstance() uint64 {
	if !h.Valid() {
		return 0
	}
	return h.state.instance
}

// SignerDomain returns the canonical verified signer domain.
func (h VerifierHop) SignerDomain() string {
	if !h.Valid() {
		return ""
	}
	return h.state.domain
}

// SignatureAlgorithms returns sorted unique successfully verified algorithms.
func (h VerifierHop) SignatureAlgorithms() []string {
	if !h.Valid() {
		return nil
	}
	return slices.Clone(h.state.algorithms)
}

// CustodyTransition returns origin, ordinary, next_domain, or terminal_next_domain.
func (h VerifierHop) CustodyTransition() string {
	if !h.Valid() {
		return ""
	}
	return h.state.custody
}

// RecipeMode returns unchanged or applied.
func (h VerifierHop) RecipeMode() string {
	if !h.Valid() {
		return ""
	}
	return h.state.recipeMode
}

// Recipe returns the immutable Recipe descriptor.
func (h VerifierHop) Recipe() VerifierRecipeDescriptor {
	if !h.Valid() {
		return VerifierRecipeDescriptor{}
	}
	return clonePublicRecipe(h.state.recipe)
}

// HistoryHeaderState returns the authenticated historical header state.
func (h VerifierHop) HistoryHeaderState() string {
	if !h.Valid() {
		return ""
	}
	return h.state.headerState
}

// HistoryBodyState returns the authenticated historical body state.
func (h VerifierHop) HistoryBodyState() string {
	if !h.Valid() {
		return ""
	}
	return h.state.bodyState
}

// BodyAvailability returns known or unavailable.
func (h VerifierHop) BodyAvailability() string {
	if !h.Valid() {
		return ""
	}
	return h.state.bodyAvailability
}

// HopBinding returns the verifier-owned record binding.
func (h VerifierHop) HopBinding() [32]byte {
	if !h.Valid() {
		return [32]byte{}
	}
	return h.state.binding
}

// DoNotModify reports authenticated donotmodify presence.
func (h VerifierHop) DoNotModify() bool { return h.Valid() && h.state.doNotModify }

// DoNotExplode reports authenticated donotexplode presence.
func (h VerifierHop) DoNotExplode() bool { return h.Valid() && h.state.doNotExplode }

// Feedback reports authenticated feedback presence.
func (h VerifierHop) Feedback() bool { return h.Valid() && h.state.feedback }

// FeedHere reports authenticated feedhere presence.
func (h VerifierHop) FeedHere() bool { return h.Valid() && h.state.feedHere }

// Exploded reports authenticated exploded presence.
func (h VerifierHop) Exploded() bool { return h.Valid() && h.state.exploded }

// String returns a constant representation without message-derived facts.
func (VerifierHop) String() string { return "dkim2.VerifierHop{redacted}" }

// GoString returns a constant representation without message-derived facts.
func (VerifierHop) GoString() string { return "dkim2.VerifierHop{redacted}" }

// Format prevents formatting verbs from exposing message-derived facts.
func (VerifierHop) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "dkim2.VerifierHop{redacted}")
}

// VerifierProjection is sealed complete-chain verifier evidence for policy consumers.
type VerifierProjection struct{ state *verifierProjectionState }

type verifierProjectionState struct {
	hops          []VerifierHop
	binding       [32]byte
	draft, schema string
}

// Valid reports whether the projection is complete and bounded.
func (p VerifierProjection) Valid() bool {
	return p.state != nil && p.state.schema == VerifierProjectionSchema && p.state.draft == DraftIdentifier && len(p.state.hops) > 0 && len(p.state.hops) <= 128 && p.state.binding != ([32]byte{})
}

// Schema returns the stable projection identity.
func (p VerifierProjection) Schema() string {
	if !p.Valid() {
		return ""
	}
	return p.state.schema
}

// Draft returns the exact verifier baseline.
func (p VerifierProjection) Draft() string {
	if !p.Valid() {
		return ""
	}
	return p.state.draft
}

// Binding returns the verifier-owned complete projection binding.
func (p VerifierProjection) Binding() [32]byte {
	if !p.Valid() {
		return [32]byte{}
	}
	return p.state.binding
}

// Hops returns detached ordered chain records.
func (p VerifierProjection) Hops() []VerifierHop {
	if !p.Valid() {
		return nil
	}
	return clonePublicHops(p.state.hops)
}

// String returns a constant representation without message-derived facts.
func (VerifierProjection) String() string { return "dkim2.VerifierProjection{redacted}" }

// GoString returns a constant representation without message-derived facts.
func (VerifierProjection) GoString() string { return "dkim2.VerifierProjection{redacted}" }

// Format prevents formatting verbs from exposing message-derived facts.
func (VerifierProjection) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "dkim2.VerifierProjection{redacted}")
}

// adaptVerifierProjection clones the service-owned sealed projection.
func adaptVerifierProjection(source service.VerifierProjection) (VerifierProjection, bool) {
	if !source.Valid() || source.Schema() != VerifierProjectionSchema || source.Draft() != DraftIdentifier {
		return VerifierProjection{}, false
	}
	sourceHops := source.Hops()
	hops := make([]VerifierHop, len(sourceHops))
	for index, sourceHop := range sourceHops {
		descriptor := sourceHop.Recipe
		publicDescriptor := VerifierRecipeDescriptor{state: &verifierRecipeDescriptorState{affectedHeaders: slices.Clone(descriptor.AffectedHeaders), changeClasses: slices.Clone(descriptor.ChangeClasses), digest: descriptor.Digest, bodyMode: descriptor.BodyMode}}
		hops[index] = VerifierHop{state: &verifierHopState{domain: sourceHop.SignerDomain, algorithms: slices.Clone(sourceHop.Algorithms), custody: sourceHop.CustodyTransition, recipeMode: sourceHop.RecipeMode, headerState: sourceHop.HistoryHeaderState, bodyState: sourceHop.HistoryBodyState, bodyAvailability: sourceHop.BodyAvailability, recipe: publicDescriptor, binding: sourceHop.Binding, sequence: sourceHop.Sequence, instance: sourceHop.MessageInstance, doNotModify: sourceHop.DoNotModify, doNotExplode: sourceHop.DoNotExplode, feedback: sourceHop.Feedback, feedHere: sourceHop.FeedHere, exploded: sourceHop.Exploded}}
		if !hops[index].Valid() {
			return VerifierProjection{}, false
		}
	}
	projection := VerifierProjection{state: &verifierProjectionState{hops: hops, binding: source.Binding(), draft: source.Draft(), schema: source.Schema()}}
	return projection, projection.Valid()
}

// clonePublicRecipe returns an independently owned descriptor.
func clonePublicRecipe(input VerifierRecipeDescriptor) VerifierRecipeDescriptor {
	if input.state == nil {
		return VerifierRecipeDescriptor{}
	}
	state := *input.state
	state.affectedHeaders = slices.Clone(input.state.affectedHeaders)
	state.changeClasses = slices.Clone(input.state.changeClasses)
	return VerifierRecipeDescriptor{state: &state}
}

// clonePublicHops returns deep-cloned ordered hop values.
func clonePublicHops(input []VerifierHop) []VerifierHop {
	result := make([]VerifierHop, len(input))
	for index, hop := range input {
		if hop.state != nil {
			state := *hop.state
			state.algorithms = slices.Clone(hop.state.algorithms)
			state.recipe = clonePublicRecipe(hop.state.recipe)
			result[index] = VerifierHop{state: &state}
		}
	}
	return result
}

// clone returns a detached public projection.
func (p VerifierProjection) clone() VerifierProjection {
	if p.state == nil {
		return VerifierProjection{}
	}
	state := *p.state
	state.hops = clonePublicHops(p.state.hops)
	return VerifierProjection{state: &state}
}
