package rawmsg

// NewReconstructedHeaderBlock validates detached logical header-field bytes for recipe output.
func NewReconstructedHeaderBlock(fieldBytes [][]byte, options ParserOptions) (HeaderBlock, error) {
	if err := options.Validate(); err != nil {
		return HeaderBlock{}, err
	}
	if len(fieldBytes) > options.MaxHeaderFields {
		return HeaderBlock{}, reconstructionLimitError("max_header_fields", options.MaxHeaderFields)
	}
	if len(fieldBytes) == 0 {
		return NewHeaderBlock(nil, nil)
	}

	total := 0
	for _, encoded := range fieldBytes {
		if len(encoded) == 0 || len(encoded) > options.MaxHeaderFieldBytes {
			return HeaderBlock{}, reconstructionLimitError("max_header_field_bytes", options.MaxHeaderFieldBytes)
		}
		parsed, err := parseHeaderBlock(encoded, options)
		if err != nil {
			return HeaderBlock{}, err
		}
		if parsed.Len() != 1 {
			return HeaderBlock{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{Reason: ErrorReasonInvariant})
		}
		if total > options.MaxHeaderBytes-len(encoded) {
			return HeaderBlock{}, reconstructionLimitError("max_header_bytes", options.MaxHeaderBytes)
		}
		total += len(encoded)
	}

	joined := make([]byte, 0, total)
	for _, encoded := range fieldBytes {
		joined = append(joined, encoded...)
	}

	return parseHeaderBlock(joined, options)
}

// NewReconstructedBody validates detached body bytes and rebuilds their line index.
func NewReconstructedBody(data []byte, options ParserOptions) (Body, error) {
	if err := options.Validate(); err != nil {
		return Body{}, err
	}
	if len(data) > options.MaxMessageBytes {
		return Body{}, reconstructionLimitError("max_message_bytes", options.MaxMessageBytes)
	}

	return buildBody(data, options, 0)
}

// NewReconstructedMessage materializes validated reconstructed components with an RFC 5322 separator.
func NewReconstructedMessage(headers HeaderBlock, body Body, options ParserOptions) (Message, error) {
	return NewReconstructedMessageWithFraming(headers, body, options, MessageFramingDelimited)
}

// NewReconstructedMessageWithFraming materializes components under explicit validated framing.
func NewReconstructedMessageWithFraming(headers HeaderBlock, body Body, options ParserOptions, framing MessageFraming) (Message, error) {
	if err := options.Validate(); err != nil {
		return Message{}, err
	}
	if !headers.Initialized() || !body.Initialized() || !framing.Known() {
		return Message{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{Reason: ErrorReasonInvariant})
	}
	fieldBytes := make([][]byte, 0, headers.Len())
	for _, field := range headers.Fields() {
		fieldBytes = append(fieldBytes, field.OriginalBytes())
	}
	validatedHeaders, err := NewReconstructedHeaderBlock(fieldBytes, options)
	if err != nil {
		return Message{}, err
	}
	validatedBody, err := NewReconstructedBody(body.Bytes(), options)
	if err != nil {
		return Message{}, err
	}
	headerBytes := validatedHeaders.OriginalBytes()
	bodyBytes := validatedBody.Bytes()
	separatorBytes := len(crlf)
	if framing == MessageFramingHeaderOnly {
		if validatedHeaders.Len() == 0 || len(bodyBytes) != 0 {
			return Message{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{Reason: ErrorReasonInvariant})
		}
		separatorBytes = 0
	}
	if len(headerBytes) > options.MaxMessageBytes-separatorBytes || len(bodyBytes) > options.MaxMessageBytes-len(headerBytes)-separatorBytes {
		return Message{}, reconstructionLimitError("max_message_bytes", options.MaxMessageBytes)
	}

	raw := make([]byte, 0, len(headerBytes)+separatorBytes+len(bodyBytes))
	raw = append(raw, headerBytes...)
	if separatorBytes != 0 {
		raw = append(raw, crlf...)
	}
	raw = append(raw, bodyBytes...)
	metadata := NewParserMetadata(
		LineEndingPolicyStrictCRLF, false, len(raw), len(raw), len(headerBytes), headers.Len(), len(bodyBytes),
	)

	return NewMessage(raw, validatedHeaders, validatedBody, metadata)
}

// reconstructionLimitError reports a bounded reconstructed-state limit failure.
func reconstructionLimitError(limitName string, limit int) *ParserError {
	return NewParserError(ErrorCodeLimitExceeded, ErrorLocation{}, ParserErrorDetails{
		Reason: ErrorReasonLimit, LimitName: limitName, Limit: limit,
	})
}
