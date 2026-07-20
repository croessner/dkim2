package rawmsg

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// TestInsertValidatedFieldsPreservesNormalMessageBytes verifies insertion occurs before the existing separator.
func TestInsertValidatedFieldsPreservesNormalMessageBytes(t *testing.T) {
	source := mustParseInsertionMessage(t, []byte("From: sender@example.test\r\nSubject: original\r\n\r\n..legitimate\r\nbody\r\n"))
	instanceField := []byte("Message-Instance: m=2;\r\n")
	signatureField := []byte("DKIM2-Signature: i=2;\r\n")

	inserted, err := InsertValidatedFields(InsertionRequest{
		Message:       source,
		TransportForm: TransportFormFinalNetworkPreDotStuffing,
		Fields:        [][]byte{instanceField, signatureField},
		Options:       DefaultParserOptions(),
	})
	if err != nil {
		t.Fatalf("InsertValidatedFields() error = %v", err)
	}
	want := []byte("From: sender@example.test\r\nSubject: original\r\nMessage-Instance: m=2;\r\nDKIM2-Signature: i=2;\r\n\r\n..legitimate\r\nbody\r\n")
	if got := inserted.RawBytes(); !bytes.Equal(got, want) {
		t.Fatalf("inserted message bytes differ")
	}
	if inserted.Framing() != MessageFramingDelimited {
		t.Fatalf("Framing() = %q, want %q", inserted.Framing(), MessageFramingDelimited)
	}
	if got := inserted.Body().Bytes(); !bytes.Equal(got, source.Body().Bytes()) {
		t.Fatal("insertion changed body bytes")
	}
}

// TestInsertValidatedFieldsPreservesHeaderOnlyFraming verifies insertion does not invent a separator.
func TestInsertValidatedFieldsPreservesHeaderOnlyFraming(t *testing.T) {
	source := mustParseInsertionMessage(t, []byte("From: sender@example.test\r\n"))

	inserted, err := InsertValidatedFields(InsertionRequest{
		Message:       source,
		TransportForm: TransportFormFinalNetworkPreDotStuffing,
		Fields:        [][]byte{[]byte("DKIM2-Signature: i=1;\r\n")},
		Options:       DefaultParserOptions(),
	})
	if err != nil {
		t.Fatalf("InsertValidatedFields() error = %v", err)
	}
	want := []byte("From: sender@example.test\r\nDKIM2-Signature: i=1;\r\n")
	if got := inserted.RawBytes(); !bytes.Equal(got, want) {
		t.Fatal("header-only insertion changed framing")
	}
	if inserted.Framing() != MessageFramingHeaderOnly || inserted.Body().Len() != 0 {
		t.Fatalf("inserted framing/body = %q/%d", inserted.Framing(), inserted.Body().Len())
	}
}

// TestInsertValidatedFieldsPreservesFoldedInternationalizedHeaders verifies inherited valid RFC 6532 bytes are untouched.
func TestInsertValidatedFieldsPreservesFoldedInternationalizedHeaders(t *testing.T) {
	inherited := []byte("Subject: Gr\xc3\xbc\xc3\x9fe\r\n\tund Faltung\r\nX-Duplicate: one\r\nX-Duplicate: two\r\n")
	sourceBytes := append(bytes.Clone(inherited), []byte("\r\nbody")...)
	source := mustParseInsertionMessage(t, sourceBytes)

	inserted, err := InsertValidatedFields(InsertionRequest{
		Message:       source,
		TransportForm: TransportFormFinalNetworkPreDotStuffing,
		Fields:        [][]byte{[]byte("DKIM2-Signature: i=2;\r\n")},
		Options:       DefaultParserOptions(),
	})
	if err != nil {
		t.Fatalf("InsertValidatedFields() error = %v", err)
	}
	if got := inserted.RawBytes(); !bytes.HasPrefix(got, inherited) {
		t.Fatal("insertion changed folded or internationalized inherited header bytes")
	}
	for index, field := range source.Headers().Fields() {
		if got := inserted.Headers().Fields()[index].OriginalBytes(); !bytes.Equal(got, field.OriginalBytes()) {
			t.Fatalf("inherited header occurrence %d changed", index)
		}
	}
}

// TestInsertValidatedFieldsRejectsTransportAndFieldAmbiguity verifies closed metadata and one-field payloads.
func TestInsertValidatedFieldsRejectsTransportAndFieldAmbiguity(t *testing.T) {
	source := mustParseInsertionMessage(t, []byte("A: b\r\n"))
	tests := []struct {
		name   string
		form   TransportForm
		fields [][]byte
		code   ErrorCode
	}{
		{name: "zero transport", fields: [][]byte{[]byte("X: y\r\n")}, code: ErrorCodeInvalidTransportForm},
		{name: "wrong transport", form: TransportForm("post_dot_stuffing"), fields: [][]byte{[]byte("X: y\r\n")}, code: ErrorCodeInvalidTransportForm},
		{name: "zero fields", form: TransportFormFinalNetworkPreDotStuffing, code: ErrorCodeInvalidInvariant},
		{name: "empty field", form: TransportFormFinalNetworkPreDotStuffing, fields: [][]byte{nil}, code: ErrorCodeInvalidInvariant},
		{name: "double field", form: TransportFormFinalNetworkPreDotStuffing, fields: [][]byte{[]byte("X: y\r\nY: z\r\n")}, code: ErrorCodeInvalidInvariant},
		{name: "separator payload", form: TransportFormFinalNetworkPreDotStuffing, fields: [][]byte{[]byte("X: y\r\n\r\n")}, code: ErrorCodeMalformedHeader},
		{name: "bare LF", form: TransportFormFinalNetworkPreDotStuffing, fields: [][]byte{[]byte("X: y\n")}, code: ErrorCodeBareLF},
		{name: "bare CR", form: TransportFormFinalNetworkPreDotStuffing, fields: [][]byte{[]byte("X: y\r")}, code: ErrorCodeBareCR},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := InsertValidatedFields(InsertionRequest{
				Message: source, TransportForm: test.form, Fields: test.fields, Options: DefaultParserOptions(),
			})
			if result.Initialized() || !IsParserErrorCode(err, test.code) {
				t.Fatalf("result initialized=%t error=%v, want %q", result.Initialized(), err, test.code)
			}
		})
	}
}

// TestInsertValidatedFieldsRejectsInvalidSourceAndOptions verifies invalid state never yields partial output.
func TestInsertValidatedFieldsRejectsInvalidSourceAndOptions(t *testing.T) {
	valid := mustParseInsertionMessage(t, []byte("A: b\r\n"))
	tests := []struct {
		name    string
		message Message
		options ParserOptions
		code    ErrorCode
	}{
		{name: "zero message", options: DefaultParserOptions(), code: ErrorCodeInvalidInvariant},
		{name: "zero options", message: valid, code: ErrorCodeLimitExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := InsertValidatedFields(InsertionRequest{
				Message: test.message, TransportForm: TransportFormFinalNetworkPreDotStuffing,
				Fields: [][]byte{[]byte("X: y\r\n")}, Options: test.options,
			})
			if result.Initialized() || !IsParserErrorCode(err, test.code) {
				t.Fatalf("result initialized=%t error=%v, want %q", result.Initialized(), err, test.code)
			}
		})
	}
}

// TestInsertValidatedFieldsRejectsWidenedHardLimits verifies insertion options only narrow defaults.
func TestInsertValidatedFieldsRejectsWidenedHardLimits(t *testing.T) {
	source := mustParseInsertionMessage(t, []byte("A: b\r\n"))
	tests := []struct {
		name   string
		mutate func(*ParserOptions)
		limit  string
	}{
		{name: "message", mutate: func(options *ParserOptions) { options.MaxMessageBytes++ }, limit: limitNameMaxMessageBytes},
		{name: "header", mutate: func(options *ParserOptions) { options.MaxHeaderBytes++ }, limit: limitNameMaxHeaderBytes},
		{name: "count", mutate: func(options *ParserOptions) { options.MaxHeaderFields++ }, limit: limitNameMaxHeaderFields},
		{name: "field", mutate: func(options *ParserOptions) { options.MaxHeaderFieldBytes++ }, limit: limitNameMaxHeaderFieldBytes},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := DefaultParserOptions()
			test.mutate(&options)
			result, err := InsertValidatedFields(InsertionRequest{
				Message: source, TransportForm: TransportFormFinalNetworkPreDotStuffing,
				Fields: [][]byte{[]byte("X: y\r\n")}, Options: options,
			})
			var parserErr *ParserError
			if result.Initialized() || !errors.As(err, &parserErr) ||
				parserErr.Code() != ErrorCodeLimitExceeded || parserErr.LimitName() != test.limit {
				t.Fatalf("result initialized=%t error=%v, want hard %q limit", result.Initialized(), err, test.limit)
			}
		})
	}
}

// TestInsertValidatedFieldsEnforcesExactNarrowedLimits verifies count and byte ceilings before allocation.
func TestInsertValidatedFieldsEnforcesExactNarrowedLimits(t *testing.T) {
	source := mustParseInsertionMessage(t, []byte("A: b\r\n\r\nbody\r\n"))
	field := []byte("X: y\r\n")
	exactHeaderBytes := source.Metadata().HeaderBytes + len(field)
	exactMessageBytes := source.Metadata().StoredBytes + len(field)

	tests := []struct {
		name      string
		exact     func(*ParserOptions)
		oneOver   func(*ParserOptions)
		wantLimit string
	}{
		{
			name: "field count",
			exact: func(options *ParserOptions) {
				options.MaxHeaderFields = source.Metadata().HeaderFields + 1
			},
			oneOver: func(options *ParserOptions) {
				options.MaxHeaderFields = source.Metadata().HeaderFields
			},
			wantLimit: "max_header_fields",
		},
		{
			name: "field bytes",
			exact: func(options *ParserOptions) {
				options.MaxHeaderFieldBytes = len(field)
			},
			oneOver: func(options *ParserOptions) {
				options.MaxHeaderFieldBytes = len(field) - 1
			},
			wantLimit: "max_header_field_bytes",
		},
		{
			name: testNameHeaderBytes,
			exact: func(options *ParserOptions) {
				options.MaxHeaderBytes = exactHeaderBytes
			},
			oneOver: func(options *ParserOptions) {
				options.MaxHeaderBytes = exactHeaderBytes - 1
			},
			wantLimit: "max_header_bytes",
		},
		{
			name: "message bytes",
			exact: func(options *ParserOptions) {
				options.MaxMessageBytes = exactMessageBytes
			},
			oneOver: func(options *ParserOptions) {
				options.MaxMessageBytes = exactMessageBytes - 1
			},
			wantLimit: "max_message_bytes",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exact := DefaultParserOptions()
			test.exact(&exact)
			result, err := InsertValidatedFields(InsertionRequest{
				Message: source, TransportForm: TransportFormFinalNetworkPreDotStuffing,
				Fields: [][]byte{field}, Options: exact,
			})
			if err != nil || !result.Initialized() {
				t.Fatalf("exact limit result initialized=%t error=%v", result.Initialized(), err)
			}

			oneOver := DefaultParserOptions()
			test.oneOver(&oneOver)
			result, err = InsertValidatedFields(InsertionRequest{
				Message: source, TransportForm: TransportFormFinalNetworkPreDotStuffing,
				Fields: [][]byte{field}, Options: oneOver,
			})
			var parserErr *ParserError
			if result.Initialized() || !IsParserErrorCode(err, ErrorCodeLimitExceeded) ||
				!errors.As(err, &parserErr) || parserErr.LimitName() != test.wantLimit {
				t.Fatalf("one-over result initialized=%t error=%v limit=%q, want %q",
					result.Initialized(), err, parserErrorLimitName(parserErr), test.wantLimit)
			}
		})
	}
}

// TestInsertValidatedFieldsDetachesAllByteOwnership verifies requests and accessors cannot mutate output.
func TestInsertValidatedFieldsDetachesAllByteOwnership(t *testing.T) {
	sourceBytes := []byte("A: b\r\n\r\nbody\r\n")
	source := mustParseInsertionMessage(t, sourceBytes)
	field := []byte("X: y\r\n")
	request := InsertionRequest{
		Message: source, TransportForm: TransportFormFinalNetworkPreDotStuffing,
		Fields: [][]byte{field}, Options: DefaultParserOptions(),
	}
	inserted, err := InsertValidatedFields(request)
	if err != nil {
		t.Fatal(err)
	}
	field[0] = 'Z'
	request.Fields[0][1] = 'Z'
	sourceBytes[0] = 'Z'
	accessor := inserted.RawBytes()
	accessor[0] = 'Z'

	want := []byte("A: b\r\nX: y\r\n\r\nbody\r\n")
	if got := inserted.RawBytes(); !bytes.Equal(got, want) {
		t.Fatal("inserted message retained a mutable alias")
	}
	for _, formatted := range []string{
		fmt.Sprintf("%v", request),
		fmt.Sprintf("%+v", request),
		fmt.Sprintf("%#v", request),
	} {
		if formatted != "rawmsg.InsertionRequest{redacted}" {
			t.Fatalf("request formatting leaked data: %q", formatted)
		}
	}
}

// mustParseInsertionMessage parses one trusted fixture for insertion tests.
func mustParseInsertionMessage(t *testing.T, data []byte) Message {
	t.Helper()
	message, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return message
}

// parserErrorLimitName returns a zero-safe limit name for test diagnostics.
func parserErrorLimitName(err *ParserError) string {
	if err == nil {
		return ""
	}
	return err.LimitName()
}
