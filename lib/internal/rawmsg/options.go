package rawmsg

const (
	defaultMaxMessageBytes     = 32 * 1024 * 1024
	defaultMaxHeaderBytes      = 1024 * 1024
	defaultMaxHeaderFields     = 2000
	defaultMaxHeaderFieldBytes = 64 * 1024
	defaultMaxHeaderLineBytes  = 998
	defaultMaxBodyLineBytes    = 998
	defaultMaxBodyLines        = HardMaxBodyLines
)

// HardMaxBodyLines is the closed ceiling for parser-owned body-line metadata.
const HardMaxBodyLines = 65_536

// LineEndingPolicy identifies the parser's line-ending handling mode.
type LineEndingPolicy string

const (
	// LineEndingPolicyStrictCRLF accepts only CRLF-delimited protocol input.
	LineEndingPolicyStrictCRLF LineEndingPolicy = "strict-crlf"
	// LineEndingPolicyNormalizeLF is reserved and rejected until normalization is implemented.
	LineEndingPolicyNormalizeLF LineEndingPolicy = "normalize-lf"
)

// ParserOptions contains fail-closed parser resource and policy settings.
type ParserOptions struct {
	// MaxMessageBytes bounds the full raw message accepted by the parser.
	MaxMessageBytes int
	// MaxHeaderBytes bounds the raw header block accepted by the parser.
	MaxHeaderBytes int
	// MaxHeaderFields bounds the number of parsed header occurrences.
	MaxHeaderFields int
	// MaxHeaderFieldBytes bounds one header field including continuations.
	MaxHeaderFieldBytes int
	// MaxHeaderLineBytes bounds one physical header line excluding CRLF.
	MaxHeaderLineBytes int
	// MaxBodyLineBytes bounds the body line size recorded for indexing.
	MaxBodyLineBytes int
	// MaxBodyLines bounds the number of body lines recorded for indexing.
	MaxBodyLines int
	// LineEndingPolicy controls strict CRLF handling; compatibility modes are reserved.
	LineEndingPolicy LineEndingPolicy
	// RecordNormalizedInput is reserved and rejected until normalization is implemented.
	RecordNormalizedInput bool
}

// DefaultParserOptions returns the restrictive raw-message parser defaults.
func DefaultParserOptions() ParserOptions {
	return ParserOptions{
		MaxMessageBytes:       defaultMaxMessageBytes,
		MaxHeaderBytes:        defaultMaxHeaderBytes,
		MaxHeaderFields:       defaultMaxHeaderFields,
		MaxHeaderFieldBytes:   defaultMaxHeaderFieldBytes,
		MaxHeaderLineBytes:    defaultMaxHeaderLineBytes,
		MaxBodyLineBytes:      defaultMaxBodyLineBytes,
		MaxBodyLines:          defaultMaxBodyLines,
		LineEndingPolicy:      LineEndingPolicyStrictCRLF,
		RecordNormalizedInput: false,
	}
}

// Validate rejects unsafe parser option values before parsing begins.
func (o ParserOptions) Validate() error {
	if o.MaxMessageBytes <= 0 {
		return limitOptionError("max_message_bytes", o.MaxMessageBytes)
	}
	if o.MaxHeaderBytes <= 0 {
		return limitOptionError("max_header_bytes", o.MaxHeaderBytes)
	}
	if o.MaxHeaderFields <= 0 {
		return limitOptionError("max_header_fields", o.MaxHeaderFields)
	}
	if o.MaxHeaderFieldBytes <= 0 {
		return limitOptionError("max_header_field_bytes", o.MaxHeaderFieldBytes)
	}
	if o.MaxHeaderLineBytes <= 0 {
		return limitOptionError(limitNameMaxHeaderLineBytes, o.MaxHeaderLineBytes)
	}
	if o.MaxHeaderLineBytes > defaultMaxHeaderLineBytes {
		return limitOptionError(limitNameMaxHeaderLineBytes, defaultMaxHeaderLineBytes)
	}
	if o.MaxBodyLineBytes <= 0 {
		return limitOptionError("max_body_line_bytes", o.MaxBodyLineBytes)
	}
	if o.MaxBodyLineBytes > defaultMaxBodyLineBytes {
		return limitOptionError(limitNameMaxBodyLineBytes, defaultMaxBodyLineBytes)
	}
	if o.MaxBodyLines <= 0 {
		return limitOptionError(limitNameMaxBodyLines, o.MaxBodyLines)
	}
	if o.MaxBodyLines > HardMaxBodyLines {
		return limitOptionError(limitNameMaxBodyLines, HardMaxBodyLines)
	}
	if o.LineEndingPolicy != LineEndingPolicyStrictCRLF {
		return unsupportedPolicyError(string(o.LineEndingPolicy))
	}
	if o.RecordNormalizedInput {
		return unsupportedPolicyError("record-normalized-input")
	}

	return nil
}

// ParserMetadata records bounded facts about parser-owned message bytes.
type ParserMetadata struct {
	// LineEndingPolicy records the policy used for parser-owned bytes.
	LineEndingPolicy LineEndingPolicy
	// NormalizedInput records whether explicit compatibility normalization occurred.
	NormalizedInput bool
	// OriginalBytes records the caller input size before normalization.
	OriginalBytes int
	// StoredBytes records the parser-owned raw message size.
	StoredBytes int
	// HeaderBytes records the parser-owned header block size.
	HeaderBytes int
	// HeaderFields records the number of parsed header occurrences.
	HeaderFields int
	// BodyBytes records the parser-owned body size.
	BodyBytes int
}

// NewParserMetadata constructs bounded parser metadata from byte counts.
func NewParserMetadata(policy LineEndingPolicy, normalized bool, originalBytes int, storedBytes int, headerBytes int, headerFields int, bodyBytes int) ParserMetadata {
	return ParserMetadata{
		LineEndingPolicy: policy,
		NormalizedInput:  normalized,
		OriginalBytes:    nonNegative(originalBytes),
		StoredBytes:      nonNegative(storedBytes),
		HeaderBytes:      nonNegative(headerBytes),
		HeaderFields:     nonNegative(headerFields),
		BodyBytes:        nonNegative(bodyBytes),
	}
}

// limitOptionError reports a parser option resource-limit failure.
func limitOptionError(limitName string, limit int) *ParserError {
	return NewParserError(ErrorCodeLimitExceeded, ErrorLocation{}, ParserErrorDetails{
		Reason:    ErrorReasonLimit,
		LimitName: limitName,
		Limit:     limit,
	})
}

// unsupportedPolicyError reports an unavailable parser compatibility policy.
func unsupportedPolicyError(policyName string) *ParserError {
	return NewParserError(ErrorCodeUnsupportedPolicy, ErrorLocation{}, ParserErrorDetails{
		Reason:     ErrorReasonPolicy,
		PolicyName: policyName,
	})
}

// nonNegative clamps metadata counters to their safe lower bound.
func nonNegative(value int) int {
	if value < 0 {
		return 0
	}

	return value
}
