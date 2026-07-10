package rawmsg

import (
	"bytes"
	"testing"
)

// TestHeaderFieldAccessorsReturnCopies verifies header byte views are immutable.
func TestHeaderFieldAccessorsReturnCopies(t *testing.T) {
	field, err := NewHeaderField(
		0,
		[]byte("Subject"),
		[]byte(" hello"),
		[]byte(" hello"),
		[]byte("Subject: hello\r\n"),
	)
	if err != nil {
		t.Fatalf("NewHeaderField returned error: %v", err)
	}

	rawName := field.RawName()
	rawName[0] = 'X'
	rawValue := field.RawValue()
	rawValue[1] = 'X'
	unfolded := field.UnfoldedValue()
	unfolded[0] = 'X'
	original := field.OriginalBytes()
	original[0] = 'X'

	if got := field.RawName(); !bytes.Equal(got, []byte("Subject")) {
		t.Fatalf("RawName mutated stored state: %q", got)
	}
	if got := field.RawValue(); !bytes.Equal(got, []byte(" hello")) {
		t.Fatalf("RawValue mutated stored state: %q", got)
	}
	if got := field.UnfoldedValue(); !bytes.Equal(got, []byte(" hello")) {
		t.Fatalf("UnfoldedValue mutated stored state: %q", got)
	}
	if got := field.OriginalBytes(); !bytes.Equal(got, []byte("Subject: hello\r\n")) {
		t.Fatalf("OriginalBytes mutated stored state: %q", got)
	}
	if field.NameLower() != "subject" {
		t.Fatalf("NameLower = %q, want subject", field.NameLower())
	}
}

// TestMessageAccessorsPreserveImmutability verifies nested byte views are immutable.
func TestMessageAccessorsPreserveImmutability(t *testing.T) {
	field, err := NewHeaderField(0, []byte("From"), []byte(" sender@example.test"), []byte(" sender@example.test"), []byte("From: sender@example.test\r\n"))
	if err != nil {
		t.Fatalf("NewHeaderField returned error: %v", err)
	}
	headers, err := NewHeaderBlock([]HeaderField{field}, []byte("From: sender@example.test\r\n"))
	if err != nil {
		t.Fatalf("NewHeaderBlock returned error: %v", err)
	}
	line, err := NewBodyLine(0, 0, 5, 2)
	if err != nil {
		t.Fatalf("NewBodyLine returned error: %v", err)
	}
	lines, err := NewBodyLineIndex([]BodyLine{line})
	if err != nil {
		t.Fatalf("NewBodyLineIndex returned error: %v", err)
	}
	body, err := NewBody([]byte("hello\r\n"), lines)
	if err != nil {
		t.Fatalf("NewBody returned error: %v", err)
	}
	msg, err := NewMessage([]byte("From: sender@example.test\r\n\r\nhello\r\n"), headers, body, ParserMetadata{
		LineEndingPolicy: LineEndingPolicyStrictCRLF,
		OriginalBytes:    len("From: sender@example.test\r\n\r\nhello\r\n"),
		StoredBytes:      len("From: sender@example.test\r\n\r\nhello\r\n"),
		HeaderBytes:      len("From: sender@example.test\r\n"),
		HeaderFields:     1,
		BodyBytes:        len("hello\r\n"),
	})
	if err != nil {
		t.Fatalf("NewMessage returned error: %v", err)
	}

	raw := msg.RawBytes()
	raw[0] = 'X'
	fields := msg.Headers().Fields()
	fields[0], err = NewHeaderField(0, []byte("X-Test"), []byte(" value"), []byte(" value"), []byte("X-Test: value\r\n"))
	if err != nil {
		t.Fatalf("NewHeaderField returned error: %v", err)
	}
	bodyBytes := msg.Body().Bytes()
	bodyBytes[0] = 'X'
	indexLines := msg.Body().Lines().Lines()
	indexLines[0], err = NewBodyLine(0, 2, 4, 0)
	if err != nil {
		t.Fatalf("NewBodyLine returned error: %v", err)
	}

	if got := msg.RawBytes(); !bytes.Equal(got, []byte("From: sender@example.test\r\n\r\nhello\r\n")) {
		t.Fatalf("RawBytes mutated stored state: %q", got)
	}
	if got := msg.Headers().Fields()[0].RawName(); !bytes.Equal(got, []byte("From")) {
		t.Fatalf("Headers mutated stored field: %q", got)
	}
	if got := msg.Body().Bytes(); !bytes.Equal(got, []byte("hello\r\n")) {
		t.Fatalf("Body mutated stored state: %q", got)
	}
	if got := msg.Body().Lines().Lines()[0].StartOffset(); got != 0 {
		t.Fatalf("Body line index mutated stored state: %d", got)
	}
}

// TestTypeConstructorsEnforceInvariants verifies invalid domain states are rejected.
func TestTypeConstructorsEnforceInvariants(t *testing.T) {
	if _, err := NewHeaderField(-1, []byte("Subject"), []byte(" value"), []byte(" value"), []byte("Subject: value\r\n")); !IsParserErrorCode(err, ErrorCodeInvalidInvariant) {
		t.Fatalf("NewHeaderField negative index error = %v", err)
	}
	if _, err := NewHeaderField(0, []byte("Bad Name"), []byte(" value"), []byte(" value"), []byte("Bad Name: value\r\n")); !IsParserErrorCode(err, ErrorCodeMalformedHeader) {
		t.Fatalf("NewHeaderField invalid name error = %v", err)
	}
	if _, err := NewHeaderBlock([]HeaderField{}, []byte{}); !IsParserErrorCode(err, ErrorCodeInvalidInvariant) {
		t.Fatalf("NewHeaderBlock empty field error = %v", err)
	}
	line, err := NewBodyLine(0, 2, 1, 0)
	if !IsParserErrorCode(err, ErrorCodeInvalidInvariant) {
		t.Fatalf("NewBodyLine invalid offsets line=%#v error=%v", line, err)
	}
	if _, err := NewBodyLineIndex([]BodyLine{{}}); !IsParserErrorCode(err, ErrorCodeInvalidInvariant) {
		t.Fatalf("NewBodyLineIndex direct zero line error = %v", err)
	}
}

// TestHeaderConstructorsRejectSplitBrainViews verifies derived field and block bytes agree.
func TestHeaderConstructorsRejectSplitBrainViews(t *testing.T) {
	tests := []struct {
		name      string
		rawName   []byte
		rawValue  []byte
		unfolded  []byte
		original  []byte
		errorCode ErrorCode
	}{
		{
			name:      "name differs from original",
			rawName:   []byte("Subject"),
			rawValue:  []byte(" value"),
			unfolded:  []byte(" value"),
			original:  []byte("X-Test: value\r\n"),
			errorCode: ErrorCodeInvalidInvariant,
		},
		{
			name:      "value differs from original",
			rawName:   []byte("Subject"),
			rawValue:  []byte(" other"),
			unfolded:  []byte(" other"),
			original:  []byte("Subject: value\r\n"),
			errorCode: ErrorCodeInvalidInvariant,
		},
		{
			name:      "unfolded view differs",
			rawName:   []byte("Subject"),
			rawValue:  []byte(" folded\r\n value"),
			unfolded:  []byte(" foldedvalue"),
			original:  []byte("Subject: folded\r\n value\r\n"),
			errorCode: ErrorCodeInvalidInvariant,
		},
		{
			name:      "invalid utf8 field body",
			rawName:   []byte("Subject"),
			rawValue:  []byte(" \xff\xfe"),
			unfolded:  []byte(" \xff\xfe"),
			original:  []byte("Subject: \xff\xfe\r\n"),
			errorCode: ErrorCodeMalformedHeader,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewHeaderField(0, test.rawName, test.rawValue, test.unfolded, test.original)
			if !IsParserErrorCode(err, test.errorCode) {
				t.Fatalf("NewHeaderField error = %v, want %q", err, test.errorCode)
			}
		})
	}

	field, err := NewHeaderField(0, []byte("Subject"), []byte(" value"), []byte(" value"), []byte("Subject: value\r\n"))
	if err != nil {
		t.Fatalf("NewHeaderField returned error: %v", err)
	}
	if _, err := NewHeaderBlock([]HeaderField{field}, []byte("Subject: other\r\n")); !IsParserErrorCode(err, ErrorCodeInvalidInvariant) {
		t.Fatalf("NewHeaderBlock error = %v, want invalid invariant", err)
	}
}

// TestNewMessageRejectsSplitBrainComponents verifies raw bytes and metadata are derived consistently.
func TestNewMessageRejectsSplitBrainComponents(t *testing.T) {
	message, err := Parse([]byte("Subject: value\r\n\r\nbody"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if _, err := NewMessage([]byte("Subject: other\r\n\r\nbody"), message.Headers(), message.Body(), message.Metadata()); !IsParserErrorCode(err, ErrorCodeInvalidInvariant) {
		t.Fatalf("NewMessage raw mismatch error = %v", err)
	}

	metadata := message.Metadata()
	metadata.BodyBytes++
	if _, err := NewMessage(message.RawBytes(), message.Headers(), message.Body(), metadata); !IsParserErrorCode(err, ErrorCodeInvalidInvariant) {
		t.Fatalf("NewMessage metadata mismatch error = %v", err)
	}
}
