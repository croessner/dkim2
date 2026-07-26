package rawmsg

import (
	"bytes"
	"testing"
)

// TestReconstructedHeaderBlockSupportsInitializedEmptyState verifies zero fields differ from a zero value.
func TestReconstructedHeaderBlockSupportsInitializedEmptyState(t *testing.T) {
	headers, err := NewReconstructedHeaderBlock(nil, DefaultParserOptions())
	if err != nil {
		t.Fatalf("NewReconstructedHeaderBlock() error = %v", err)
	}
	if !headers.Initialized() || headers.Len() != 0 || len(headers.OriginalBytes()) != 0 {
		t.Fatalf("headers = %#v", headers)
	}
	if (HeaderBlock{}).Initialized() {
		t.Fatal("zero HeaderBlock unexpectedly initialized")
	}
}

// TestReconstructedComponentsValidateCloneAndMaterialize verifies narrow synthetic seams preserve ownership.
func TestReconstructedComponentsValidateCloneAndMaterialize(t *testing.T) {
	field := []byte("Subject: folded\r\n value\r\n")
	headers, err := NewReconstructedHeaderBlock([][]byte{field}, DefaultParserOptions())
	if err != nil {
		t.Fatalf("NewReconstructedHeaderBlock() error = %v", err)
	}
	field[0] = 'X'
	bodyInput := []byte("body\r\n")
	body, err := NewReconstructedBody(bodyInput, DefaultParserOptions())
	if err != nil {
		t.Fatalf("NewReconstructedBody() error = %v", err)
	}
	bodyInput[0] = 'X'
	message, err := NewReconstructedMessage(headers, body, DefaultParserOptions())
	if err != nil {
		t.Fatalf("NewReconstructedMessage() error = %v", err)
	}
	want := []byte("Subject: folded\r\n value\r\n\r\nbody\r\n")
	if got := message.RawBytes(); !bytes.Equal(got, want) {
		t.Fatalf("message = %q, want %q", got, want)
	}
	if got := headers.Fields()[0].OriginalBytes(); !bytes.Equal(got, []byte("Subject: folded\r\n value\r\n")) {
		t.Fatalf("header aliased caller: %q", got)
	}
	if got := body.Bytes(); !bytes.Equal(got, []byte("body\r\n")) {
		t.Fatalf("body aliased caller: %q", got)
	}
}

// TestReconstructedComponentsRejectZeroAndLimits verifies injected states cannot bypass parser ceilings.
func TestReconstructedComponentsRejectZeroAndLimits(t *testing.T) {
	if _, err := NewReconstructedMessage(HeaderBlock{}, Body{}, DefaultParserOptions()); !IsParserErrorCode(err, ErrorCodeInvalidInvariant) {
		t.Fatalf("zero component error = %v", err)
	}
	options := DefaultParserOptions()
	options.MaxHeaderFields = 1
	if _, err := NewReconstructedHeaderBlock([][]byte{[]byte("A: 1\r\n"), []byte("B: 2\r\n")}, options); !IsParserErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("header count error = %v", err)
	}
	options = DefaultParserOptions()
	options.MaxBodyLineBytes = 3
	if _, err := NewReconstructedBody([]byte("four\r\n"), options); !IsParserErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("body line error = %v", err)
	}
	options = DefaultParserOptions()
	options.MaxBodyLines = 1
	if _, err := NewReconstructedBody([]byte("\r\n\r\n"), options); !IsParserErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("body line-count error = %v", err)
	}
}

// TestReconstructedEmptyStatesMaterializeWithExplicitDelimiter verifies valid empty output is not a zero Message.
func TestReconstructedEmptyStatesMaterializeWithExplicitDelimiter(t *testing.T) {
	headers, err := NewReconstructedHeaderBlock(nil, DefaultParserOptions())
	if err != nil {
		t.Fatal(err)
	}
	body, err := NewReconstructedBody(nil, DefaultParserOptions())
	if err != nil {
		t.Fatal(err)
	}
	message, err := NewReconstructedMessage(headers, body, DefaultParserOptions())
	if err != nil {
		t.Fatalf("NewReconstructedMessage() error = %v", err)
	}
	if !message.Initialized() || !bytes.Equal(message.RawBytes(), []byte("\r\n")) {
		t.Fatalf("empty message = %#v %q", message, message.RawBytes())
	}
	body, err = NewReconstructedBody([]byte("body\r\n"), DefaultParserOptions())
	if err != nil {
		t.Fatal(err)
	}
	message, err = NewReconstructedMessage(headers, body, DefaultParserOptions())
	if err != nil {
		t.Fatal(err)
	}
	if got := message.RawBytes(); !bytes.Equal(got, []byte("\r\nbody\r\n")) {
		t.Fatalf("body-only message = %q", got)
	}
}

// TestReconstructedMessageRevalidatesNarrowerOptions verifies detached components cannot bypass caller ceilings.
func TestReconstructedMessageRevalidatesNarrowerOptions(t *testing.T) {
	headers, err := NewReconstructedHeaderBlock([][]byte{[]byte("A: four\r\n")}, DefaultParserOptions())
	if err != nil {
		t.Fatal(err)
	}
	body, err := NewReconstructedBody([]byte("four\r\n"), DefaultParserOptions())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*ParserOptions)
	}{
		{"header field", func(o *ParserOptions) { o.MaxHeaderFieldBytes = len("A: four\r\n") - 1 }},
		{"header line", func(o *ParserOptions) { o.MaxHeaderLineBytes = len("A: four") - 1 }},
		{testNameHeaderBytes, func(o *ParserOptions) { o.MaxHeaderBytes = len("A: four\r\n") - 1 }},
		{"body line", func(o *ParserOptions) { o.MaxBodyLineBytes = len("four") - 1 }},
		{"message", func(o *ParserOptions) { o.MaxMessageBytes = len("A: four\r\n\r\nfour\r\n") - 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := DefaultParserOptions()
			test.mutate(&options)
			if _, err := NewReconstructedMessage(headers, body, options); !IsParserErrorCode(err, ErrorCodeLimitExceeded) {
				t.Fatalf("error = %v, want limit", err)
			}
		})
	}
}

// TestReconstructedHeaderBlockRejectsMalformedDetachedFields verifies field boundaries cannot inject extra state.
func TestReconstructedHeaderBlockRejectsMalformedDetachedFields(t *testing.T) {
	for _, encoded := range [][]byte{
		[]byte("Bad Name: value\r\n"), []byte("A: one\r\nB: two\r\n"),
		[]byte("A: bare\n"), []byte("A: missing terminator"),
	} {
		if _, err := NewReconstructedHeaderBlock([][]byte{encoded}, DefaultParserOptions()); err == nil {
			t.Fatalf("NewReconstructedHeaderBlock(%q) unexpectedly passed", encoded)
		}
	}
	if _, err := NewReconstructedHeaderBlock(nil, ParserOptions{}); err == nil {
		t.Fatal("invalid zero ParserOptions unexpectedly passed")
	}
}

// TestReconstructedMessagePreservesRequestedFraming verifies header-only and delimited empty bodies remain distinct.
func TestReconstructedMessagePreservesRequestedFraming(t *testing.T) {
	parsedHeaderOnly, err := Parse([]byte("A: b\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	parsedDelimited, err := Parse([]byte("A: b\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		message Message
		framing MessageFraming
		want    []byte
	}{
		{parsedHeaderOnly, MessageFramingHeaderOnly, []byte("A: b\r\n")},
		{parsedDelimited, MessageFramingDelimited, []byte("A: b\r\n\r\n")},
	} {
		got, err := NewReconstructedMessageWithFraming(test.message.Headers(), test.message.Body(), DefaultParserOptions(), test.framing)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.RawBytes(), test.want) || got.Framing() != test.framing {
			t.Fatalf("got %q/%q", got.RawBytes(), got.Framing())
		}
	}
}
