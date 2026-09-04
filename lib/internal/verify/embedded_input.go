package verify

import (
	"slices"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
)

// EmbeddedInput is the one-time, verifier-bounded extraction of an embedded
// original's Message-Instance and DKIM2-Signature fields. It lets callers
// that already verified the highest target reuse the parsed fields for run
// detection, run-member verification, and historical hash-tuple checks
// without re-parsing under different limits.
type EmbeddedInput struct {
	input       verificationInput
	initialized bool
}

// ExtractEmbeddedInput parses the protocol fields of an embedded original
// once under the verifier's own instance, signature, and recipe limits.
func (v Verifier) ExtractEmbeddedInput(message rawmsg.Message) (EmbeddedInput, error) {
	if !v.valid() || !message.Initialized() {
		return EmbeddedInput{}, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	input, err := v.extractVerificationInput(Request{Message: message}, v.options.RevisionLimits.MaxDecodedRecipeBytes)
	if err != nil {
		return EmbeddedInput{}, err
	}
	return EmbeddedInput{input: input, initialized: true}, nil
}

// Valid reports whether the input was produced by ExtractEmbeddedInput.
func (i EmbeddedInput) Valid() bool { return i.initialized && i.input.request.Message.Initialized() }

// Signatures returns an independent copy of the parsed DKIM2-Signature fields in field order.
func (i EmbeddedInput) Signatures() []signature.Signature { return slices.Clone(i.input.signatures) }

// Instances returns an independent copy of the parsed Message-Instance fields.
func (i EmbeddedInput) Instances() []instance.MessageInstance { return slices.Clone(i.input.instances) }
