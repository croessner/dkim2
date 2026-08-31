package service

import (
	"fmt"
	"io"
	"slices"

	"github.com/croessner/dkim2/internal/verify"
)

const serviceVerifierProjectionText = "service.VerifierProjection{redacted}"

// VerifierRecipeDescriptor stores one cloned privacy-minimized Recipe descriptor.
type VerifierRecipeDescriptor struct {
	AffectedHeaders []string
	ChangeClasses   []string
	Digest          [32]byte
	BodyMode        string
}

// clone returns detached descriptor collections.
func (d VerifierRecipeDescriptor) clone() VerifierRecipeDescriptor {
	d.AffectedHeaders = slices.Clone(d.AffectedHeaders)
	d.ChangeClasses = slices.Clone(d.ChangeClasses)
	return d
}

// VerifierHopFact stores one cloned authenticated chain record.
type VerifierHopFact struct {
	SignerDomain       string
	Algorithms         []string
	CustodyTransition  string
	RecipeMode         string
	HistoryHeaderState string
	HistoryBodyState   string
	BodyAvailability   string
	Recipe             VerifierRecipeDescriptor
	Binding            [32]byte
	Sequence           uint64
	MessageInstance    uint64
	DoNotModify        bool
	DoNotExplode       bool
	Feedback           bool
	FeedHere           bool
	Exploded           bool
}

// clone returns detached hop collections.
func (h VerifierHopFact) clone() VerifierHopFact {
	h.Algorithms = slices.Clone(h.Algorithms)
	h.Recipe = h.Recipe.clone()
	return h
}

// VerifierProjection carries cloned sealed verifier evidence across the facade boundary.
type VerifierProjection struct {
	hops    []VerifierHopFact
	binding [32]byte
	draft   string
	schema  string
	valid   bool
}

// Valid reports whether the projection was mapped from one sealed verifier-owned source.
func (p VerifierProjection) Valid() bool {
	return p.valid && p.schema == verify.VerifierProjectionSchema && p.draft == DraftIdentifier &&
		len(p.hops) > 0 && len(p.hops) <= 128 && p.binding != ([32]byte{})
}

// Schema returns the exact projection identity.
func (p VerifierProjection) Schema() string {
	if !p.Valid() {
		return ""
	}
	return p.schema
}

// Draft returns the exact verifier baseline.
func (p VerifierProjection) Draft() string {
	if !p.Valid() {
		return ""
	}
	return p.draft
}

// Binding returns the verifier-owned complete projection binding.
func (p VerifierProjection) Binding() [32]byte {
	if !p.Valid() {
		return [32]byte{}
	}
	return p.binding
}

// Hops returns detached ordered chain facts.
func (p VerifierProjection) Hops() []VerifierHopFact {
	if !p.Valid() {
		return nil
	}
	return cloneServiceVerifierHops(p.hops)
}

// String returns a constant representation without message-derived facts.
func (VerifierProjection) String() string { return serviceVerifierProjectionText }

// GoString returns a constant representation without message-derived facts.
func (VerifierProjection) GoString() string { return serviceVerifierProjectionText }

// Format prevents formatting verbs from exposing message-derived facts.
func (VerifierProjection) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, serviceVerifierProjectionText)
}

// clone returns an independently owned projection.
func (p VerifierProjection) clone() VerifierProjection {
	p.hops = cloneServiceVerifierHops(p.hops)
	return p
}

// mapVerifierProjection clones only a complete verifier-owned sealed projection.
func mapVerifierProjection(source verify.VerifierProjection) (VerifierProjection, bool) {
	if !source.Valid() || source.Schema() != verify.VerifierProjectionSchema || source.Draft() != verify.DraftBaseline {
		return VerifierProjection{}, false
	}
	sourceHops := source.Hops()
	hops := make([]VerifierHopFact, len(sourceHops))
	for index, sourceHop := range sourceHops {
		if !sourceHop.Valid() || sourceHop.Sequence() != uint64(index+1) {
			return VerifierProjection{}, false
		}
		algorithms := sourceHop.SignatureAlgorithms()
		mappedAlgorithms := make([]string, len(algorithms))
		for algorithmIndex, algorithm := range algorithms {
			mappedAlgorithms[algorithmIndex] = string(algorithm)
		}
		descriptor := sourceHop.Recipe()
		classes := descriptor.ChangeClasses()
		mappedClasses := make([]string, len(classes))
		for classIndex, class := range classes {
			mappedClasses[classIndex] = string(class)
		}
		flags := sourceHop.Flags()
		hops[index] = VerifierHopFact{
			SignerDomain: sourceHop.SignerDomain(), Algorithms: mappedAlgorithms,
			CustodyTransition: string(sourceHop.CustodyTransition()), RecipeMode: string(sourceHop.RecipeMode()),
			HistoryHeaderState: string(sourceHop.HistoryHeaderState()), HistoryBodyState: string(sourceHop.HistoryBodyState()),
			BodyAvailability: string(sourceHop.BodyAvailability()), Binding: sourceHop.HopBinding(),
			Sequence: sourceHop.Sequence(), MessageInstance: sourceHop.MessageInstance(),
			DoNotModify: flags.DoNotModify(), DoNotExplode: flags.DoNotExplode(), Feedback: flags.Feedback(), FeedHere: flags.FeedHere(), Exploded: flags.Exploded(),
			Recipe: VerifierRecipeDescriptor{AffectedHeaders: descriptor.AffectedHeaders(), ChangeClasses: mappedClasses, Digest: descriptor.Digest(), BodyMode: string(descriptor.BodyMode())},
		}
	}
	projection := VerifierProjection{hops: hops, binding: source.Binding(), draft: source.Draft(), schema: source.Schema(), valid: true}
	return projection, projection.Valid()
}

// cloneServiceVerifierHops returns deep-cloned service facts.
func cloneServiceVerifierHops(input []VerifierHopFact) []VerifierHopFact {
	result := make([]VerifierHopFact, len(input))
	for index, hop := range input {
		result[index] = hop.clone()
	}
	return result
}
