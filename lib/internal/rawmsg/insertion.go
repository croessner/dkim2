package rawmsg

import (
	"bytes"
	"fmt"
	"io"
)

// TransportForm identifies the caller-declared transport state of signable bytes.
type TransportForm string

const (
	// TransportFormFinalNetworkPreDotStuffing declares final network bytes before SMTP dot-stuffing.
	TransportFormFinalNetworkPreDotStuffing TransportForm = "final_network_form_pre_dot_stuffing"
)

// Known reports whether the form is the sole signable transport declaration.
func (f TransportForm) Known() bool {
	return f == TransportFormFinalNetworkPreDotStuffing
}

// InsertionRequest carries ordered complete fields and exact validated source bytes.
type InsertionRequest struct {
	// Message is the immutable authoritative RFC 5322 source.
	Message Message
	// TransportForm declares that all local transformations except dot-stuffing are complete.
	TransportForm TransportForm
	// Fields contains one or more ordered, complete RFC 5322 header fields.
	Fields [][]byte
	// Options narrows parser and output limits without widening hard defaults.
	Options ParserOptions
}

// String returns a constant secret-safe insertion-request summary.
func (r InsertionRequest) String() string { return "rawmsg.InsertionRequest{redacted}" }

// GoString returns the constant secret-safe insertion-request Go representation.
func (r InsertionRequest) GoString() string { return r.String() }

// Format routes every insertion-request formatting form through the redacted summary.
func (r InsertionRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// InsertValidatedFields inserts ordered complete fields without rewriting inherited bytes.
func InsertValidatedFields(request InsertionRequest) (Message, error) {
	if !request.TransportForm.Known() {
		return Message{}, invalidTransportFormError()
	}
	if !request.Message.Initialized() || len(request.Fields) == 0 {
		return Message{}, insertionInvariantError()
	}
	if err := request.Options.Validate(); err != nil {
		return Message{}, err
	}
	if err := validateInsertionOptions(request.Options); err != nil {
		return Message{}, err
	}

	sourceBytes := request.Message.RawBytes()
	source, err := ParseWithOptions(sourceBytes, request.Options)
	if err != nil {
		return Message{}, err
	}
	if source.Framing() != request.Message.Framing() {
		return Message{}, insertionInvariantError()
	}

	addedBytes, err := validateInsertionFields(request.Fields, source.Metadata(), request.Options)
	if err != nil {
		return Message{}, err
	}
	headerBytes := source.Metadata().HeaderBytes
	if addedBytes > request.Options.MaxHeaderBytes-headerBytes {
		return Message{}, reconstructionLimitError("max_header_bytes", request.Options.MaxHeaderBytes)
	}
	if addedBytes > request.Options.MaxMessageBytes-len(sourceBytes) {
		return Message{}, reconstructionLimitError("max_message_bytes", request.Options.MaxMessageBytes)
	}

	output := make([]byte, 0, len(sourceBytes)+addedBytes)
	output = append(output, sourceBytes[:headerBytes]...)
	for _, field := range request.Fields {
		output = append(output, field...)
	}
	output = append(output, sourceBytes[headerBytes:]...)

	inserted, err := ParseWithOptions(output, request.Options)
	if err != nil {
		return Message{}, err
	}
	if !insertionPreservedSource(source, inserted, request.Fields) {
		return Message{}, insertionInvariantError()
	}
	return inserted, nil
}

// validateInsertionOptions keeps insertion limits narrowable below raw-message hard defaults.
func validateInsertionOptions(options ParserOptions) error {
	hard := DefaultParserOptions()
	limits := []struct {
		name  string
		value int
		max   int
	}{
		{name: limitNameMaxMessageBytes, value: options.MaxMessageBytes, max: hard.MaxMessageBytes},
		{name: limitNameMaxHeaderBytes, value: options.MaxHeaderBytes, max: hard.MaxHeaderBytes},
		{name: limitNameMaxHeaderFields, value: options.MaxHeaderFields, max: hard.MaxHeaderFields},
		{name: limitNameMaxHeaderFieldBytes, value: options.MaxHeaderFieldBytes, max: hard.MaxHeaderFieldBytes},
	}
	for _, limit := range limits {
		if limit.value > limit.max {
			return reconstructionLimitError(limit.name, limit.max)
		}
	}
	return nil
}

// validateInsertionFields proves each payload is exactly one complete field and accounts for limits.
func validateInsertionFields(fields [][]byte, metadata ParserMetadata, options ParserOptions) (int, error) {
	if len(fields) > options.MaxHeaderFields-metadata.HeaderFields {
		return 0, reconstructionLimitError(limitNameMaxHeaderFields, options.MaxHeaderFields)
	}
	total := 0
	for _, field := range fields {
		if len(field) == 0 {
			return 0, insertionInvariantError()
		}
		if err := enforceStrictCRLF(field, options); err != nil {
			return 0, err
		}
		parsed, err := NewReconstructedHeaderBlock([][]byte{field}, options)
		if err != nil {
			return 0, err
		}
		if parsed.Len() != 1 || !bytes.Equal(parsed.OriginalBytes(), field) {
			return 0, insertionInvariantError()
		}
		if len(field) > options.MaxHeaderBytes-total {
			return 0, reconstructionLimitError(limitNameMaxHeaderBytes, options.MaxHeaderBytes)
		}
		total += len(field)
	}
	return total, nil
}

// insertionPreservedSource proves framing, inherited fields, and body remained byte-identical.
func insertionPreservedSource(source Message, inserted Message, fields [][]byte) bool {
	if !source.Initialized() || !inserted.Initialized() || source.Framing() != inserted.Framing() ||
		!bytes.Equal(source.Body().Bytes(), inserted.Body().Bytes()) {
		return false
	}
	sourceFields := source.Headers().Fields()
	insertedFields := inserted.Headers().Fields()
	if len(insertedFields) != len(sourceFields)+len(fields) {
		return false
	}
	for index := range sourceFields {
		if !bytes.Equal(sourceFields[index].OriginalBytes(), insertedFields[index].OriginalBytes()) {
			return false
		}
	}
	for index := range fields {
		if !bytes.Equal(fields[index], insertedFields[len(sourceFields)+index].OriginalBytes()) {
			return false
		}
	}
	return true
}

// invalidTransportFormError reports missing or unsupported transport metadata.
func invalidTransportFormError() *ParserError {
	return NewParserError(ErrorCodeInvalidTransportForm, ErrorLocation{}, ParserErrorDetails{
		Reason: ErrorReasonPolicy,
	})
}

// insertionInvariantError reports malformed caller-owned insertion state without content.
func insertionInvariantError() *ParserError {
	return NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
		Reason: ErrorReasonInvariant,
	})
}
