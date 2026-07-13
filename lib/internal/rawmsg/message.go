package rawmsg

import "bytes"

// MessageFraming identifies whether an empty body used an explicit header/body separator.
type MessageFraming string

const (
	// MessageFramingHeaderOnly identifies header bytes without a separator or body.
	MessageFramingHeaderOnly MessageFraming = "header_only"
	// MessageFramingDelimited identifies an explicit CRLF header/body separator.
	MessageFramingDelimited MessageFraming = "delimited"
)

// Known reports whether framing belongs to the closed raw-message vocabulary.
func (f MessageFraming) Known() bool {
	return f == MessageFramingHeaderOnly || f == MessageFramingDelimited
}

// Message stores immutable raw RFC 5322 message bytes and controlled views.
type Message struct {
	rawBytes []byte
	headers  HeaderBlock
	body     Body
	metadata ParserMetadata
}

// NewMessage constructs an immutable message from parser-owned components.
func NewMessage(rawBytes []byte, headers HeaderBlock, body Body, metadata ParserMetadata) (Message, error) {
	if len(rawBytes) == 0 {
		return Message{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
			Reason: ErrorReasonInvariant,
		})
	}
	if !headers.Initialized() || !body.Initialized() {
		return Message{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
			Reason: ErrorReasonInvariant,
		})
	}
	validatedHeaders, err := NewHeaderBlock(headers.fields, headers.originalBytes)
	if err != nil {
		return Message{}, err
	}
	validatedBody, err := NewBody(body.bytes, body.lines)
	if err != nil {
		return Message{}, err
	}
	if !matchesMessageComponents(rawBytes, validatedHeaders.originalBytes, validatedBody.bytes) {
		return Message{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
			Reason: ErrorReasonInvariant,
		})
	}
	if metadata.LineEndingPolicy != LineEndingPolicyStrictCRLF || metadata.NormalizedInput || metadata.OriginalBytes != len(rawBytes) || metadata.StoredBytes != len(rawBytes) || metadata.HeaderBytes != len(validatedHeaders.originalBytes) || metadata.HeaderFields != validatedHeaders.Len() || metadata.BodyBytes != validatedBody.Len() {
		return Message{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
			Reason: ErrorReasonInvariant,
		})
	}

	return Message{
		rawBytes: bytes.Clone(rawBytes),
		headers:  validatedHeaders,
		body:     validatedBody,
		metadata: metadata,
	}, nil
}

// Initialized reports whether the message was constructed through rawmsg validation.
func (m Message) Initialized() bool {
	return len(m.rawBytes) > 0 && m.headers.Initialized() && m.body.Initialized()
}

// Framing returns the validated raw message's header/body separator form.
func (m Message) Framing() MessageFraming {
	if !m.Initialized() {
		return ""
	}
	if len(m.body.bytes) == 0 && bytes.Equal(m.rawBytes, m.headers.originalBytes) {
		return MessageFramingHeaderOnly
	}
	return MessageFramingDelimited
}

// matchesMessageComponents verifies header-only or delimiter-separated body framing.
func matchesMessageComponents(rawBytes []byte, headerBytes []byte, bodyBytes []byte) bool {
	if len(bodyBytes) == 0 && bytes.Equal(rawBytes, headerBytes) {
		return true
	}
	expectedLength := len(headerBytes) + len(crlf) + len(bodyBytes)
	if len(rawBytes) != expectedLength || !bytes.Equal(rawBytes[:len(headerBytes)], headerBytes) {
		return false
	}
	delimiterEnd := len(headerBytes) + len(crlf)

	return bytes.Equal(rawBytes[len(headerBytes):delimiterEnd], crlf) && bytes.Equal(rawBytes[delimiterEnd:], bodyBytes)
}

// RawBytes returns the parser-owned full message bytes.
func (m Message) RawBytes() []byte {
	return bytes.Clone(m.rawBytes)
}

// Headers returns the immutable header block.
func (m Message) Headers() HeaderBlock {
	return m.headers.clone()
}

// Body returns the immutable message body.
func (m Message) Body() Body {
	return m.body.clone()
}

// Metadata returns bounded parser metadata for the message.
func (m Message) Metadata() ParserMetadata {
	return m.metadata
}
