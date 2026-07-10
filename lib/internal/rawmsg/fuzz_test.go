package rawmsg

import (
	"bytes"
	"errors"
	"testing"
)

// FuzzParseSmallInputs exercises the strict parser with bounded synthetic bytes.
func FuzzParseSmallInputs(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("A: b\r\n\r\nbody"),
		[]byte("A: b\r\nB: c\r\n\r\nbody\r\n"),
		[]byte("A: b\n\nbody"),
		[]byte(" continuation\r\nA: b\r\n\r\nbody"),
		[]byte("A b\r\n\r\nbody"),
		[]byte("A: b\r\n\r\n"),
		[]byte{},
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		options := smallFuzzParserOptions()
		original := bytes.Clone(data)

		msg, err := ParseWithOptions(data, options)
		if !bytes.Equal(data, original) {
			t.Fatalf("ParseWithOptions mutated caller input: before length %d after length %d", len(original), len(data))
		}
		if err != nil {
			assertFuzzParserErrorDeterministic(t, data, options, err)
			return
		}

		assertFuzzMessageImmutable(t, msg, data)
	})
}

// smallFuzzParserOptions returns deterministic limits for local fuzz smoke tests.
func smallFuzzParserOptions() ParserOptions {
	options := DefaultParserOptions()
	options.MaxMessageBytes = 512
	options.MaxHeaderBytes = 256
	options.MaxHeaderFields = 16
	options.MaxHeaderFieldBytes = 128
	options.MaxBodyLineBytes = 128

	return options
}

// assertFuzzParserErrorDeterministic verifies fuzz errors stay typed and stable.
func assertFuzzParserErrorDeterministic(t *testing.T, data []byte, options ParserOptions, err error) {
	t.Helper()

	var parserErr *ParserError
	if !errors.As(err, &parserErr) {
		t.Fatalf("ParseWithOptions error = %T, want ParserError", err)
	}

	_, repeatErr := ParseWithOptions(bytes.Clone(data), options)
	var repeatParserErr *ParserError
	if !errors.As(repeatErr, &repeatParserErr) {
		t.Fatalf("repeat ParseWithOptions error = %T, want ParserError", repeatErr)
	}
	if repeatParserErr.Code() != parserErr.Code() {
		t.Fatalf("error code changed across parses: first=%s repeat=%s", parserErr.Code(), repeatParserErr.Code())
	}
	if repeatParserErr.ReasonClass() != parserErr.ReasonClass() {
		t.Fatalf("reason class changed across parses: first=%s repeat=%s", parserErr.ReasonClass(), repeatParserErr.ReasonClass())
	}
}

// assertFuzzMessageImmutable verifies successful parses copy input and accessors.
func assertFuzzMessageImmutable(t *testing.T, msg Message, data []byte) {
	t.Helper()

	if !bytes.Equal(msg.RawBytes(), data) {
		t.Fatalf("RawBytes mismatch after successful fuzz parse: got length %d want %d", len(msg.RawBytes()), len(data))
	}

	originalRaw := msg.RawBytes()
	for i := range data {
		data[i] ^= 0xff
	}
	if !bytes.Equal(msg.RawBytes(), originalRaw) {
		t.Fatal("message raw bytes changed after caller input mutation")
	}

	rawView := msg.RawBytes()
	if len(rawView) > 0 {
		rawView[0] ^= 0xff
	}
	if !bytes.Equal(msg.RawBytes(), originalRaw) {
		t.Fatal("message raw bytes changed after accessor mutation")
	}

	bodyView := msg.Body().Bytes()
	originalBody := msg.Body().Bytes()
	if len(bodyView) > 0 {
		bodyView[0] ^= 0xff
	}
	if !bytes.Equal(msg.Body().Bytes(), originalBody) {
		t.Fatal("message body changed after accessor mutation")
	}
}
