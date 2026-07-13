package recipe

import "github.com/croessner/dkim2/internal/rawmsg"

const (
	hardMaxDecodedRecipeBytes   = 49_152
	hardMaxJSONDepth            = 16
	hardMaxJSONMembers          = 2_048
	hardMaxJSONTokens           = 8_192
	hardMaxHeaderNames          = 256
	hardMaxTotalHeaderNameBytes = 16_384
	hardMaxStepsPerHeader       = 256
	hardMaxBodySteps            = 2_048
	hardMaxTotalSteps           = 4_096
	hardMaxCopyRanges           = 2_048
	hardMaxCopiedItemsPerRange  = 2_000
	hardMaxTotalCopiedItems     = 8_192
	hardMaxDataStrings          = 4_096
	hardMaxDataStringBytes      = 16_384
	hardMaxTotalLiteralBytes    = 32_768
	hardMaxBodyLines            = 65_536
	hardMaxOperationWorkUnits   = 4_194_304
)

// Limits bounds one recipe parse or apply operation.
type Limits struct {
	// MaxDecodedRecipeBytes bounds one decoded r= JSON payload.
	MaxDecodedRecipeBytes int
	// MaxJSONDepth bounds nested unknown extension traversal.
	MaxJSONDepth int
	// MaxJSONMembers bounds all object members scanned.
	MaxJSONMembers int
	// MaxJSONTokens bounds total JSON tokenization work.
	MaxJSONTokens int
	// MaxHeaderNames bounds distinct recipe and state header groups.
	MaxHeaderNames int
	// MaxHeaderNameBytes bounds one RFC 5322 header field name.
	MaxHeaderNameBytes int
	// MaxTotalHeaderNameBytes bounds retained recipe-key storage.
	MaxTotalHeaderNameBytes int
	// MaxStepsPerHeader bounds one header-name instruction array.
	MaxStepsPerHeader int
	// MaxBodySteps bounds the body instruction array.
	MaxBodySteps int
	// MaxTotalSteps bounds all retained recipe steps.
	MaxTotalSteps int
	// MaxCopyRanges bounds copy-range metadata.
	MaxCopyRanges int
	// MaxCopiedItemsPerRange bounds one inclusive copy expansion.
	MaxCopiedItemsPerRange int
	// MaxTotalCopiedItems bounds all copied fields or lines per apply.
	MaxTotalCopiedItems int
	// MaxDataStrings bounds retained literal strings.
	MaxDataStrings int
	// MaxDataStringBytes bounds one decoded literal before dimension checks.
	MaxDataStringBytes int
	// MaxTotalLiteralBytes bounds all retained decoded literal bytes.
	MaxTotalLiteralBytes int
	// MaxHeaderFields bounds reconstructed header occurrence count.
	MaxHeaderFields int
	// MaxHeaderFieldBytes bounds one reconstructed logical field.
	MaxHeaderFieldBytes int
	// MaxHeaderLineBytes bounds one reconstructed physical header line.
	MaxHeaderLineBytes int
	// MaxHeaderBytes bounds the reconstructed header block.
	MaxHeaderBytes int
	// MaxBodyLines bounds reconstructed body line indexing.
	MaxBodyLines int
	// MaxBodyLineBytes bounds one reconstructed body line.
	MaxBodyLineBytes int
	// MaxStateBytes bounds one reconstructed raw message state.
	MaxStateBytes int
	// MaxOperationWorkUnits bounds aggregate parsing or application work.
	MaxOperationWorkUnits int
}

// DefaultLimits returns the closed hard ceilings for one recipe operation.
func DefaultLimits() Limits {
	rawLimits := rawmsg.DefaultParserOptions()
	return Limits{
		MaxDecodedRecipeBytes: hardMaxDecodedRecipeBytes, MaxJSONDepth: hardMaxJSONDepth,
		MaxJSONMembers: hardMaxJSONMembers, MaxJSONTokens: hardMaxJSONTokens,
		MaxHeaderNames: hardMaxHeaderNames, MaxHeaderNameBytes: rawLimits.MaxHeaderLineBytes,
		MaxTotalHeaderNameBytes: hardMaxTotalHeaderNameBytes, MaxStepsPerHeader: hardMaxStepsPerHeader,
		MaxBodySteps: hardMaxBodySteps, MaxTotalSteps: hardMaxTotalSteps,
		MaxCopyRanges: hardMaxCopyRanges, MaxCopiedItemsPerRange: hardMaxCopiedItemsPerRange,
		MaxTotalCopiedItems: hardMaxTotalCopiedItems, MaxDataStrings: hardMaxDataStrings,
		MaxDataStringBytes: hardMaxDataStringBytes, MaxTotalLiteralBytes: hardMaxTotalLiteralBytes,
		MaxHeaderFields: rawLimits.MaxHeaderFields, MaxHeaderFieldBytes: rawLimits.MaxHeaderFieldBytes,
		MaxHeaderLineBytes: rawLimits.MaxHeaderLineBytes, MaxHeaderBytes: rawLimits.MaxHeaderBytes,
		MaxBodyLines: hardMaxBodyLines, MaxBodyLineBytes: rawLimits.MaxBodyLineBytes,
		MaxStateBytes: rawLimits.MaxMessageBytes, MaxOperationWorkUnits: hardMaxOperationWorkUnits,
	}
}

// Validate rejects negative, widening, or incoherent recipe limits.
func (l Limits) Validate() error {
	_, err := l.normalized()
	return err
}

// normalized fills zero-valued limits and validates the resolved configuration.
func (l Limits) normalized() (Limits, error) {
	defaults := DefaultLimits()
	values := []*int{
		&l.MaxDecodedRecipeBytes, &l.MaxJSONDepth, &l.MaxJSONMembers, &l.MaxJSONTokens,
		&l.MaxHeaderNames, &l.MaxHeaderNameBytes, &l.MaxTotalHeaderNameBytes,
		&l.MaxStepsPerHeader, &l.MaxBodySteps, &l.MaxTotalSteps, &l.MaxCopyRanges,
		&l.MaxCopiedItemsPerRange, &l.MaxTotalCopiedItems, &l.MaxDataStrings,
		&l.MaxDataStringBytes, &l.MaxTotalLiteralBytes, &l.MaxHeaderFields,
		&l.MaxHeaderFieldBytes, &l.MaxHeaderLineBytes, &l.MaxHeaderBytes,
		&l.MaxBodyLines, &l.MaxBodyLineBytes, &l.MaxStateBytes, &l.MaxOperationWorkUnits,
	}
	defaultValues := []int{
		defaults.MaxDecodedRecipeBytes, defaults.MaxJSONDepth, defaults.MaxJSONMembers, defaults.MaxJSONTokens,
		defaults.MaxHeaderNames, defaults.MaxHeaderNameBytes, defaults.MaxTotalHeaderNameBytes,
		defaults.MaxStepsPerHeader, defaults.MaxBodySteps, defaults.MaxTotalSteps, defaults.MaxCopyRanges,
		defaults.MaxCopiedItemsPerRange, defaults.MaxTotalCopiedItems, defaults.MaxDataStrings,
		defaults.MaxDataStringBytes, defaults.MaxTotalLiteralBytes, defaults.MaxHeaderFields,
		defaults.MaxHeaderFieldBytes, defaults.MaxHeaderLineBytes, defaults.MaxHeaderBytes,
		defaults.MaxBodyLines, defaults.MaxBodyLineBytes, defaults.MaxStateBytes, defaults.MaxOperationWorkUnits,
	}
	names := []string{
		limitNameMaxDecodedRecipeBytes, limitNameMaxJSONDepth, limitNameMaxJSONMembers, limitNameMaxJSONTokens,
		limitNameMaxHeaderNames, limitNameMaxHeaderNameBytes, limitNameMaxTotalHeaderNameBytes,
		limitNameMaxStepsPerHeader, limitNameMaxBodySteps, limitNameMaxTotalSteps, limitNameMaxCopyRanges,
		limitNameMaxCopiedItemsPerRange, limitNameMaxTotalCopiedItems, limitNameMaxDataStrings,
		limitNameMaxDataStringBytes, limitNameMaxTotalLiteralBytes, limitNameMaxHeaderFields,
		limitNameMaxHeaderFieldBytes, limitNameMaxHeaderLineBytes, limitNameMaxHeaderBytes,
		limitNameMaxBodyLines, limitNameMaxBodyLineBytes, limitNameMaxStateBytes, limitNameMaxOperationWorkUnits,
	}
	for index, value := range values {
		if *value < 0 || *value > defaultValues[index] {
			return Limits{}, invalidOptionsError(names[index])
		}
		if *value == 0 {
			*value = defaultValues[index]
		}
	}
	if l.MaxDataStringBytes > l.MaxTotalLiteralBytes ||
		l.MaxTotalLiteralBytes > l.MaxDecodedRecipeBytes {
		return Limits{}, invalidOptionsError("literal_limit_coherence")
	}
	if l.MaxStepsPerHeader > l.MaxTotalSteps || l.MaxBodySteps > l.MaxTotalSteps {
		return Limits{}, invalidOptionsError("step_limit_coherence")
	}
	if l.MaxCopiedItemsPerRange > l.MaxTotalCopiedItems {
		return Limits{}, invalidOptionsError("copy_limit_coherence")
	}

	return l, nil
}

// invalidOptionsError returns the closed recipe configuration failure.
func invalidOptionsError(limitName string) *Error {
	return newError(ErrorCodeInvalidOptions, ErrorLocation{}, ErrorDetails{Class: ErrorClassOptions, LimitName: limitName}, nil)
}
