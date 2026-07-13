package rawmsg

import "bytes"

const limitNameMaxBodyLineBytes = "max_body_line_bytes"

// Body stores immutable parser-owned body bytes and their line index.
type Body struct {
	bytes       []byte
	lines       BodyLineIndex
	initialized bool
}

// BodyLineView provides read-only bounded traversal without cloning body storage.
type BodyLineView struct {
	body *Body
	line BodyLine
}

// NewBody constructs an immutable body from bytes and a validated line index.
func NewBody(data []byte, lines BodyLineIndex) (Body, error) {
	nextOffset := 0
	for lineIndex, line := range lines.lines {
		lineEnd := line.endOffset + line.lineEndingWidth
		if line.startOffset != nextOffset || lineEnd > len(data) {
			return Body{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
				Reason: ErrorReasonInvariant,
			})
		}
		if bytes.ContainsAny(data[line.startOffset:line.endOffset], "\r\n") {
			return Body{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
				Reason: ErrorReasonInvariant,
			})
		}
		switch line.lineEndingWidth {
		case 0:
			if lineIndex != len(lines.lines)-1 || line.endOffset != len(data) {
				return Body{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
					Reason: ErrorReasonInvariant,
				})
			}
		case len(crlf):
			if !bytes.Equal(data[line.endOffset:lineEnd], crlf) {
				return Body{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
					Reason: ErrorReasonInvariant,
				})
			}
		default:
			return Body{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
				Reason: ErrorReasonInvariant,
			})
		}
		nextOffset = lineEnd
	}
	if len(data) > 0 && nextOffset != len(data) {
		return Body{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
			Reason: ErrorReasonInvariant,
		})
	}

	return Body{
		bytes:       bytes.Clone(data),
		lines:       lines.clone(),
		initialized: true,
	}, nil
}

// Initialized reports whether the body was constructed through rawmsg validation.
func (b Body) Initialized() bool {
	return b.initialized
}

// Bytes returns the parser-owned body bytes.
func (b Body) Bytes() []byte {
	return bytes.Clone(b.bytes)
}

// Lines returns the immutable body line index.
func (b Body) Lines() BodyLineIndex {
	return b.lines.clone()
}

// Len returns the number of parser-owned body bytes.
func (b Body) Len() int {
	return len(b.bytes)
}

// LineCount returns the validated body-line count without cloning the index.
func (b Body) LineCount() int {
	return len(b.lines.lines)
}

// Equal reports exact body-byte equality without exposing or cloning storage.
func (b Body) Equal(other Body) bool {
	return b.Initialized() && other.Initialized() && bytes.Equal(b.bytes, other.bytes)
}

// VisitLines visits immutable line views in top-down message order.
func (b Body) VisitLines(visit func(BodyLineView) error) error {
	if !b.Initialized() || visit == nil {
		return NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{Reason: ErrorReasonInvariant})
	}
	for _, line := range b.lines.lines {
		if err := visit(BodyLineView{body: &b, line: line}); err != nil {
			return err
		}
	}
	return nil
}

// EncodedLen returns content plus the validated original terminator width.
func (v BodyLineView) EncodedLen() int {
	if v.body == nil || !v.line.valid {
		return 0
	}
	return v.line.endOffset - v.line.startOffset + v.line.lineEndingWidth
}

// ContentLen returns line bytes excluding the validated original terminator.
func (v BodyLineView) ContentLen() int {
	if v.body == nil || !v.line.valid {
		return 0
	}
	return v.line.endOffset - v.line.startOffset
}

// Terminated reports whether the line ended with CRLF in the parsed body.
func (v BodyLineView) Terminated() bool {
	return v.body != nil && v.line.valid && v.line.lineEndingWidth == len(crlf)
}

// EncodedCopy returns detached exact content and terminator bytes.
func (v BodyLineView) EncodedCopy() []byte {
	if v.body == nil || !v.line.valid {
		return nil
	}
	end := v.line.endOffset + v.line.lineEndingWidth
	return bytes.Clone(v.body.bytes[v.line.startOffset:end])
}

// LineBytes returns one detached encoded line including its original terminator.
func (b Body) LineBytes(index int) ([]byte, bool) {
	if index < 0 || index >= len(b.lines.lines) {
		return nil, false
	}
	line := b.lines.lines[index]
	end := line.endOffset + line.lineEndingWidth
	return bytes.Clone(b.bytes[line.startOffset:end]), true
}

// LineEncodedLen returns one line's byte size including its original terminator.
func (b Body) LineEncodedLen(index int) (int, bool) {
	if index < 0 || index >= len(b.lines.lines) {
		return 0, false
	}
	line := b.lines.lines[index]
	return line.endOffset - line.startOffset + line.lineEndingWidth, true
}

// clone returns a deep copy of the body.
func (b Body) clone() Body {
	return Body{
		bytes:       bytes.Clone(b.bytes),
		lines:       b.lines.clone(),
		initialized: b.initialized,
	}
}

// buildBody constructs parser-owned body bytes and their stable line index.
func buildBody(data []byte, options ParserOptions, bodyOffset int) (Body, error) {
	lines, err := indexBodyLines(data, options, bodyOffset)
	if err != nil {
		return Body{}, err
	}

	index, err := NewBodyLineIndex(lines)
	if err != nil {
		return Body{}, err
	}

	return NewBody(data, index)
}

// indexBodyLines records body line spans without rewriting body bytes.
func indexBodyLines(data []byte, options ParserOptions, bodyOffset int) ([]BodyLine, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var lines []BodyLine
	lineStart := 0
	for lineIndex := 0; lineStart < len(data); lineIndex++ {
		lineEndRel := bytes.Index(data[lineStart:], crlf)
		lineEnd := len(data)
		lineEndingWidth := 0
		if lineEndRel >= 0 {
			lineEnd = lineStart + lineEndRel
			lineEndingWidth = len(crlf)
		}

		if lineEnd-lineStart > options.MaxBodyLineBytes {
			return nil, NewParserError(ErrorCodeLimitExceeded, ErrorLocation{Offset: bodyOffset + lineStart}, ParserErrorDetails{
				Reason:    ErrorReasonLimit,
				LimitName: limitNameMaxBodyLineBytes,
				Limit:     options.MaxBodyLineBytes,
			})
		}

		line, err := NewBodyLine(lineIndex, lineStart, lineEnd, lineEndingWidth)
		if err != nil {
			return nil, err
		}
		lines = append(lines, line)

		lineStart = lineEnd + lineEndingWidth
		if lineEndingWidth == 0 {
			break
		}
	}

	return lines, nil
}

// BodyLineIndex stores immutable body line spans in byte order.
type BodyLineIndex struct {
	lines []BodyLine
}

// NewBodyLineIndex constructs an immutable body line index.
func NewBodyLineIndex(lines []BodyLine) (BodyLineIndex, error) {
	if len(lines) == 0 {
		return BodyLineIndex{}, nil
	}

	copiedLines := make([]BodyLine, len(lines))
	previousEnd := 0
	for i, line := range lines {
		if !line.valid || line.index != i || line.startOffset != previousEnd || i < len(lines)-1 && line.lineEndingWidth == 0 {
			return BodyLineIndex{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
				Reason: ErrorReasonInvariant,
			})
		}
		previousEnd = line.endOffset + line.lineEndingWidth
		copiedLines[i] = line
	}

	return BodyLineIndex{lines: copiedLines}, nil
}

// Len returns the number of indexed body lines.
func (i BodyLineIndex) Len() int {
	return len(i.lines)
}

// Lines returns copies of all indexed body line spans.
func (i BodyLineIndex) Lines() []BodyLine {
	if len(i.lines) == 0 {
		return nil
	}

	lines := make([]BodyLine, len(i.lines))
	copy(lines, i.lines)

	return lines
}

// Line returns an indexed body line by zero-based index.
func (i BodyLineIndex) Line(index int) (BodyLine, bool) {
	if index < 0 || index >= len(i.lines) {
		return BodyLine{}, false
	}

	return i.lines[index], true
}

// clone returns a copy of the line index.
func (i BodyLineIndex) clone() BodyLineIndex {
	return BodyLineIndex{lines: i.Lines()}
}

// BodyLine describes one body line span without rewriting body bytes.
type BodyLine struct {
	index           int
	startOffset     int
	endOffset       int
	lineEndingWidth int
	valid           bool
}

// NewBodyLine constructs an immutable body line span.
func NewBodyLine(index int, startOffset int, endOffset int, lineEndingWidth int) (BodyLine, error) {
	if index < 0 || startOffset < 0 || endOffset < startOffset {
		return BodyLine{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
			Reason: ErrorReasonInvariant,
		})
	}
	if lineEndingWidth != 0 && lineEndingWidth != len(crlf) {
		return BodyLine{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
			Reason: ErrorReasonInvariant,
		})
	}

	return BodyLine{
		index:           index,
		startOffset:     startOffset,
		endOffset:       endOffset,
		lineEndingWidth: lineEndingWidth,
		valid:           true,
	}, nil
}

// Index returns the zero-based body line index.
func (l BodyLine) Index() int {
	return l.index
}

// StartOffset returns the inclusive body byte offset where the line begins.
func (l BodyLine) StartOffset() int {
	return l.startOffset
}

// EndOffset returns the exclusive body byte offset before the line ending.
func (l BodyLine) EndOffset() int {
	return l.endOffset
}

// LineEndingWidth returns the byte width of the line ending after the line.
func (l BodyLine) LineEndingWidth() int {
	return l.lineEndingWidth
}
