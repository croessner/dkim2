package verify

import (
	"fmt"
	"io"
	"slices"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/signature"
)

const recordedHopText = "verify.RecordedHop{redacted}"

// RecordedHop is one DKIM2 hop exactly as the message's header fields record it. Nothing in
// it is cryptographically verified: it is meaningful only for a message a trusted verifier
// already reported as PASS, whose chain result then covers every recorded field.
type RecordedHop struct {
	domain             string
	recipe             recipe.Descriptor
	recipeMode         VerifierRecipeMode
	sequence, instance uint64
	introducesInstance bool
}

// Valid reports whether the hop carries coherent recorded facts.
func (h RecordedHop) Valid() bool {
	return h.sequence > 0 && h.instance > 0 && h.domain != "" && h.recipeMode.Known() && h.recipe.Valid() &&
		(h.recipeMode == VerifierRecipeUnchanged) == (h.recipe.ChangeCount() == 0) &&
		(h.recipeMode == VerifierRecipeUnchanged || h.introducesInstance)
}

// Sequence returns the recorded signature sequence (i=).
func (h RecordedHop) Sequence() uint64 { return h.sequence }

// MessageInstance returns the recorded Message-Instance number (m=) the hop signed.
func (h RecordedHop) MessageInstance() uint64 { return h.instance }

// SignerDomain returns the recorded canonical signer domain (d=).
func (h RecordedHop) SignerDomain() string { return h.domain }

// IntroducesInstance reports whether this hop is the first signer of its Message-Instance,
// that is the hop that produced the revision; later signers of the same instance relayed it.
func (h RecordedHop) IntroducesInstance() bool { return h.introducesInstance }

// RecipeMode returns applied when this hop recorded a Recipe for its revision, else unchanged.
func (h RecordedHop) RecipeMode() VerifierRecipeMode { return h.recipeMode }

// Recipe returns the privacy-minimized descriptor of the recorded Recipe.
func (h RecordedHop) Recipe() recipe.Descriptor { return h.recipe }

// String returns a constant representation without message-derived facts.
func (RecordedHop) String() string { return recordedHopText }

// GoString returns a constant representation without message-derived facts.
func (RecordedHop) GoString() string { return recordedHopText }

// Format prevents formatting verbs from exposing message-derived facts.
func (RecordedHop) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, recordedHopText) }

// DescribeRecordedChain summarizes every DKIM2 hop recorded in message, ordered by sequence.
// It parses DKIM2-Signature, Message-Instance and Recipe fields with the verifier's extraction
// and collection rules under the default limits (a verifier configured with larger limits may
// pass a message this rejects), consults no key provider and verifies nothing. A Recipe is
// attributed only to the hop that introduced its Message-Instance, never to later relays; the
// VerifierProjection instead marks every signer of a Recipe-carrying instance as applied.
func DescribeRecordedChain(message rawmsg.Message) ([]RecordedHop, error) {
	if !message.Initialized() {
		return nil, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	options := DefaultOptions()
	input, err := extractVerificationInputWithin(Request{Message: message}, options.Limits, options.RevisionLimits.MaxDecodedRecipeBytes)
	if err != nil {
		return nil, err
	}
	// The same collection rules as the verifier's target selection: contiguous unique numbers,
	// no exploded origin, nondecreasing m= and the highest instance signed by the highest hop.
	if err := validateInstanceCollection(input.instances); err != nil {
		return nil, err
	}
	if err := validateSignatureCollection(input.signatures); err != nil {
		return nil, err
	}
	if err := validateReferencedInstances(input.instances, input.signatures); err != nil {
		return nil, err
	}
	if len(input.instances)+len(input.signatures) > options.RevisionLimits.MaxProtocolFields {
		return nil, newError(ErrorCodeLimitExceeded, ErrorLocation{Check: CheckKindSignature}, ErrorDetails{Class: ErrorClassLimit}, nil)
	}
	ordered, err := signature.OrderBySequence(input.signatures)
	if err != nil {
		return nil, newError(ErrorCodeSequenceInvalid, ErrorLocation{Check: CheckKindSignature}, ErrorDetails{Class: ErrorClassMalformed}, nil)
	}
	parser, err := newRevisionRecipeParser(options.RevisionLimits)
	if err != nil {
		return nil, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	recipes := make(map[uint64]recipe.Descriptor, len(input.instances))
	for _, messageInstance := range input.instances {
		encoded, hasRecipe := messageInstance.Recipe()
		if messageInstance.Number() == 1 || !hasRecipe {
			continue
		}
		plan, _, parseErr := parser.Parse(encoded.Decoded())
		if parseErr != nil {
			return nil, newError(ErrorCodeMalformedState, ErrorLocation{Check: CheckKindSignature}, ErrorDetails{Class: ErrorClassMalformed}, nil)
		}
		recipes[messageInstance.Number()] = plan.Descriptor()
	}
	hops := make([]RecordedHop, 0, len(ordered))
	signed := make(map[uint64]bool, len(ordered))
	for _, parsed := range ordered {
		number := parsed.InstanceNumber()
		hop := RecordedHop{
			domain: parsed.Domain(), sequence: parsed.Sequence(), instance: number,
			recipe: recipe.UnchangedDescriptor(), recipeMode: VerifierRecipeUnchanged, introducesInstance: !signed[number],
		}
		signed[number] = true
		if descriptor, present := recipes[number]; present && hop.introducesInstance {
			hop.recipe, hop.recipeMode = descriptor, VerifierRecipeApplied
		}
		if !hop.Valid() {
			return nil, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
		}
		hops = append(hops, hop)
	}
	return slices.Clip(hops), nil
}
