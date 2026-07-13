package rawmsg

import (
	"bytes"
	"errors"
	"testing"
)

// TestBodyLineViewTraversesWithoutExposingStorage verifies top-down immutable views.
func TestBodyLineViewTraversesWithoutExposingStorage(t *testing.T) {
	zero := BodyLineView{}
	if zero.EncodedLen() != 0 || zero.ContentLen() != 0 || zero.Terminated() || zero.EncodedCopy() != nil {
		t.Fatal("zero body line view exposed storage")
	}
	message, err := Parse([]byte("A:x\r\n\r\none\r\ntwo"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	var encoded [][]byte
	err = message.Body().VisitLines(func(view BodyLineView) error {
		line := view.EncodedCopy()
		if len(line) != view.EncodedLen() || view.ContentLen() <= 0 {
			return errors.New("invalid body view")
		}
		encoded = append(encoded, line)
		return nil
	})
	if err != nil || len(encoded) != 2 || !bytes.Equal(encoded[0], []byte("one\r\n")) || !bytes.Equal(encoded[1], []byte("two")) {
		t.Fatalf("body views: count=%d error=%v", len(encoded), err)
	}
	if !bytes.Equal(message.Body().Bytes(), []byte("one\r\ntwo")) {
		t.Fatal("view copy mutated body storage")
	}
	if err := message.Body().VisitLines(nil); err == nil {
		t.Fatal("nil visitor accepted")
	}
	toxic := errors.New("stop")
	calls := 0
	err = message.Body().VisitLines(func(BodyLineView) error { calls++; return toxic })
	if !errors.Is(err, toxic) || calls != 1 {
		t.Fatalf("early visitor stop: calls=%d error=%v", calls, err)
	}
}

// TestBodyEmptyAfterDelimiterIsValid verifies empty strict bodies have no synthetic line.
func TestBodyEmptyAfterDelimiterIsValid(t *testing.T) {
	msg, err := Parse([]byte("A: b\r\n\r\n"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	body := msg.Body()
	if body.Len() != 0 {
		t.Fatalf("body length = %d, want 0", body.Len())
	}
	if len(body.Bytes()) != 0 {
		t.Fatalf("body bytes length = %d, want 0", len(body.Bytes()))
	}
	if body.Lines().Len() != 0 {
		t.Fatalf("body line count = %d, want 0", body.Lines().Len())
	}
	if msg.Metadata().BodyBytes != 0 {
		t.Fatalf("metadata body bytes = %d, want 0", msg.Metadata().BodyBytes)
	}
}

// TestBodyLineIndexRecordsParserOwnedOffsets verifies line spans match stored bytes.
func TestBodyLineIndexRecordsParserOwnedOffsets(t *testing.T) {
	tests := []struct {
		name  string
		body  []byte
		lines []bodyLineExpectation
	}{
		{
			name: "multiple lines with final unterminated line",
			body: []byte("alpha\r\nbeta"),
			lines: []bodyLineExpectation{
				{index: 0, start: 0, end: 5, ending: 2},
				{index: 1, start: 7, end: 11, ending: 0},
			},
		},
		{
			name: "multiple lines with terminal crlf",
			body: []byte("alpha\r\nbeta\r\n"),
			lines: []bodyLineExpectation{
				{index: 0, start: 0, end: 5, ending: 2},
				{index: 1, start: 7, end: 11, ending: 2},
			},
		},
		{
			name: "terminal empty line",
			body: []byte("alpha\r\n\r\n"),
			lines: []bodyLineExpectation{
				{index: 0, start: 0, end: 5, ending: 2},
				{index: 1, start: 7, end: 7, ending: 2},
			},
		},
		{
			name: "single empty crlf line",
			body: []byte("\r\n"),
			lines: []bodyLineExpectation{
				{index: 0, start: 0, end: 0, ending: 2},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := append([]byte("A: b\r\n\r\n"), tt.body...)

			msg, err := Parse(raw)
			if err != nil {
				t.Fatalf("Parse returned error: %v", err)
			}

			if got := msg.Body().Bytes(); !bytes.Equal(got, tt.body) {
				t.Fatalf("body byte preservation failed: got length %d want %d", len(got), len(tt.body))
			}
			assertBodyLines(t, msg.Body().Lines(), tt.lines)
		})
	}
}

// TestImmutableBodyAccessorsResistMutation verifies body views cannot mutate stored state.
func TestImmutableBodyAccessorsResistMutation(t *testing.T) {
	msg, err := Parse([]byte("A: b\r\n\r\nalpha\r\nbeta\r\n"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	body := msg.Body()
	bodyBytes := body.Bytes()
	bodyBytes[0] = 'X'

	lines := body.Lines().Lines()
	mutatedLine, err := NewBodyLine(0, 2, 4, 0)
	if err != nil {
		t.Fatalf("NewBodyLine returned error: %v", err)
	}
	lines[0] = mutatedLine

	if got := msg.Body().Bytes(); !bytes.Equal(got, []byte("alpha\r\nbeta\r\n")) {
		t.Fatalf("body bytes were mutated: got length %d", len(got))
	}
	assertBodyLines(t, msg.Body().Lines(), []bodyLineExpectation{
		{index: 0, start: 0, end: 5, ending: 2},
		{index: 1, start: 7, end: 11, ending: 2},
	})
}

// TestLimitBodyLineBytesIsEnforced verifies oversized indexed lines fail closed.
func TestLimitBodyLineBytesIsEnforced(t *testing.T) {
	options := DefaultParserOptions()
	options.MaxBodyLineBytes = 3

	_, err := ParseWithOptions([]byte("A: b\r\n\r\nabcd\r\n"), options)
	if !IsParserErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("Parse error = %v, want body line limit", err)
	}

	var parserErr *ParserError
	if !errors.As(err, &parserErr) {
		t.Fatalf("Parse error %v did not expose ParserError", err)
	}
	if parserErr.LimitName() != limitNameMaxBodyLineBytes {
		t.Fatalf("LimitName = %q, want max_body_line_bytes", parserErr.LimitName())
	}
}

// TestLimitRawMessageBytesIsEnforced verifies full-message limits are enforced.
func TestLimitRawMessageBytesIsEnforced(t *testing.T) {
	options := DefaultParserOptions()
	options.MaxMessageBytes = len("A: b\r\n\r\n") - 1

	_, err := ParseWithOptions([]byte("A: b\r\n\r\n"), options)
	if !IsParserErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("Parse error = %v, want message size limit", err)
	}
}

// TestBodyConstructorsRejectNonContiguousIndexes verifies body invariants fail closed.
func TestBodyConstructorsRejectNonContiguousIndexes(t *testing.T) {
	line, err := NewBodyLine(0, 1, 3, 0)
	if err != nil {
		t.Fatalf("NewBodyLine returned error: %v", err)
	}
	if _, err := NewBodyLineIndex([]BodyLine{line}); !IsParserErrorCode(err, ErrorCodeInvalidInvariant) {
		t.Fatalf("NewBodyLineIndex gap error = %v", err)
	}

	line, err = NewBodyLine(0, 0, 3, 0)
	if err != nil {
		t.Fatalf("NewBodyLine returned error: %v", err)
	}
	index, err := NewBodyLineIndex([]BodyLine{line})
	if err != nil {
		t.Fatalf("NewBodyLineIndex returned error: %v", err)
	}
	if _, err := NewBody([]byte("abcdef"), index); !IsParserErrorCode(err, ErrorCodeInvalidInvariant) {
		t.Fatalf("NewBody partial index error = %v", err)
	}
}

// TestBodyConstructorsRejectSplitBrainLineEndings verifies indexes match body bytes.
func TestBodyConstructorsRejectSplitBrainLineEndings(t *testing.T) {
	if _, err := NewBodyLine(0, 0, 3, 1); !IsParserErrorCode(err, ErrorCodeInvalidInvariant) {
		t.Fatalf("NewBodyLine width-one error = %v", err)
	}

	line, err := NewBodyLine(0, 0, 3, 2)
	if err != nil {
		t.Fatalf("NewBodyLine returned error: %v", err)
	}
	index, err := NewBodyLineIndex([]BodyLine{line})
	if err != nil {
		t.Fatalf("NewBodyLineIndex returned error: %v", err)
	}
	if _, err := NewBody([]byte("abcXX"), index); !IsParserErrorCode(err, ErrorCodeInvalidInvariant) {
		t.Fatalf("NewBody non-CRLF declaration error = %v", err)
	}

	line, err = NewBodyLine(0, 0, 4, 0)
	if err != nil {
		t.Fatalf("NewBodyLine returned error: %v", err)
	}
	index, err = NewBodyLineIndex([]BodyLine{line})
	if err != nil {
		t.Fatalf("NewBodyLineIndex returned error: %v", err)
	}
	if _, err := NewBody([]byte("a\r\nb"), index); !IsParserErrorCode(err, ErrorCodeInvalidInvariant) {
		t.Fatalf("NewBody hidden line-ending error = %v", err)
	}
}

type bodyLineExpectation struct {
	index  int
	start  int
	end    int
	ending int
}

// assertBodyLines compares body line indexes without exposing body content.
func assertBodyLines(t *testing.T, index BodyLineIndex, want []bodyLineExpectation) {
	t.Helper()

	if index.Len() != len(want) {
		t.Fatalf("body line count = %d, want %d", index.Len(), len(want))
	}
	lines := index.Lines()
	for i, wantLine := range want {
		got := lines[i]
		if got.Index() != wantLine.index || got.StartOffset() != wantLine.start || got.EndOffset() != wantLine.end || got.LineEndingWidth() != wantLine.ending {
			t.Fatalf("line %d = index:%d start:%d end:%d ending:%d, want index:%d start:%d end:%d ending:%d",
				i,
				got.Index(), got.StartOffset(), got.EndOffset(), got.LineEndingWidth(),
				wantLine.index, wantLine.start, wantLine.end, wantLine.ending,
			)
		}
	}
}
