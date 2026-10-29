package dkim2

import (
	"fmt"
	"io"
	"slices"

	"github.com/croessner/dkim2/internal/verify"
)

const recordedHopRedactedText = "dkim2.RecordedHop{redacted}"

// RecordedHop is one DKIM2 hop as the message's header fields record it: who signed, which
// Message-Instance it signed and what its Recipe says it changed. It is NOT verified. A mail
// client or other consumer may present it only for a message that a verifier it trusts (for
// example its own receiving server, through its Authentication-Results) reported as PASS;
// such a PASS covers the complete chain and therefore every recorded field.
type RecordedHop struct{ state *recordedHopState }

type recordedHopState struct {
	domain             string
	recipeMode         string
	recipe             VerifierRecipeDescriptor
	sequence, instance uint64
	introducesInstance bool
}

// Valid reports whether the hop carries coherent recorded facts.
func (h RecordedHop) Valid() bool {
	return h.state != nil && h.state.sequence > 0 && h.state.instance > 0 && h.state.domain != "" &&
		(h.state.recipeMode == string(verify.VerifierRecipeUnchanged) || h.state.recipeMode == string(verify.VerifierRecipeApplied)) &&
		h.state.recipe.Valid()
}

// Sequence returns the recorded signature sequence (i=).
func (h RecordedHop) Sequence() uint64 {
	if !h.Valid() {
		return 0
	}
	return h.state.sequence
}

// MessageInstance returns the recorded Message-Instance number (m=) the hop signed.
func (h RecordedHop) MessageInstance() uint64 {
	if !h.Valid() {
		return 0
	}
	return h.state.instance
}

// SignerDomain returns the recorded canonical signer domain (d=), in its A-label form.
func (h RecordedHop) SignerDomain() string {
	if !h.Valid() {
		return ""
	}
	return h.state.domain
}

// IntroducesInstance reports whether this hop produced its Message-Instance; a later hop
// signing the same instance only relayed the message unchanged.
func (h RecordedHop) IntroducesInstance() bool { return h.Valid() && h.state.introducesInstance }

// RecipeMode returns applied when the hop recorded a Recipe for its revision, else unchanged.
func (h RecordedHop) RecipeMode() string {
	if !h.Valid() {
		return ""
	}
	return h.state.recipeMode
}

// Recipe returns the privacy-minimized descriptor of the recorded Recipe: affected header
// names, change classes and the body mode, never header values or body content.
func (h RecordedHop) Recipe() VerifierRecipeDescriptor {
	if !h.Valid() {
		return VerifierRecipeDescriptor{}
	}
	return clonePublicRecipe(h.state.recipe)
}

// String returns a constant representation without message-derived facts.
func (RecordedHop) String() string { return recordedHopRedactedText }

// GoString returns a constant representation without message-derived facts.
func (RecordedHop) GoString() string { return recordedHopRedactedText }

// Format prevents formatting verbs from exposing message-derived facts.
func (RecordedHop) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, recordedHopRedactedText)
}

// DescribeRecordedChain returns the DKIM2 hops recorded in rawMessage, ordered by sequence,
// or none for a message without DKIM2 fields. rawMessage must keep its CRLF line endings; only
// the header section is parsed (the body is neither needed nor copied), with the verifier's
// extraction and collection rules under the default limits. No key is looked up and nothing is
// verified, so the result is a description, not evidence. Malformed, over-limit or otherwise
// unusable input yields an invalid_request error instead of a partial chain.
func DescribeRecordedChain(rawMessage []byte) ([]RecordedHop, error) {
	if len(rawMessage) > HardMaxRawMessageBytes {
		return nil, newAPIError(APIErrorCodeInvalidRequest)
	}
	message, err := parseHeaderSection(rawMessage)
	if err != nil {
		return nil, newAPIError(APIErrorCodeInvalidRequest)
	}
	if !hasProtocolFields(message.Headers()) {
		return nil, nil
	}
	recorded, err := verify.DescribeRecordedChain(message)
	if err != nil {
		return nil, newAPIError(APIErrorCodeInvalidRequest)
	}
	hops := make([]RecordedHop, len(recorded))
	for index, source := range recorded {
		descriptor := source.Recipe()
		classes := make([]string, 0, descriptor.ChangeCount())
		for _, class := range descriptor.ChangeClasses() {
			classes = append(classes, string(class))
		}
		hops[index] = RecordedHop{state: &recordedHopState{
			domain: source.SignerDomain(), recipeMode: string(source.RecipeMode()),
			recipe: VerifierRecipeDescriptor{state: &verifierRecipeDescriptorState{
				affectedHeaders: descriptor.AffectedHeaders(), changeClasses: classes,
				digest: descriptor.Digest(), bodyMode: string(descriptor.BodyMode()),
			}},
			sequence: source.Sequence(), instance: source.MessageInstance(), introducesInstance: source.IntroducesInstance(),
		}}
		if !hops[index].Valid() {
			return nil, newAPIError(APIErrorCodeInvalidRequest)
		}
	}
	return slices.Clip(hops), nil
}
