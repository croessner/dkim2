package rawmsg

import (
	"bytes"
	"unicode/utf8"
)

// HeaderBlock stores immutable header fields in RFC 5322 occurrence order.
type HeaderBlock struct {
	fields        []HeaderField
	originalBytes []byte
}

// NewHeaderBlock constructs an immutable header block from validated fields.
func NewHeaderBlock(fields []HeaderField, originalBytes []byte) (HeaderBlock, error) {
	if len(fields) == 0 {
		return HeaderBlock{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
			Reason: ErrorReasonInvariant,
		})
	}

	copiedFields := make([]HeaderField, len(fields))
	originalOffset := 0
	for i, field := range fields {
		if !field.valid || field.index != i {
			return HeaderBlock{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
				Reason: ErrorReasonInvariant,
			})
		}
		if !bytes.HasPrefix(originalBytes[originalOffset:], field.originalBytes) {
			return HeaderBlock{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
				Reason: ErrorReasonInvariant,
			})
		}
		originalOffset += len(field.originalBytes)
		copiedFields[i] = field.clone()
	}
	if originalOffset != len(originalBytes) {
		return HeaderBlock{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
			Reason: ErrorReasonInvariant,
		})
	}

	return HeaderBlock{
		fields:        copiedFields,
		originalBytes: bytes.Clone(originalBytes),
	}, nil
}

// Len returns the number of header fields in occurrence order.
func (h HeaderBlock) Len() int {
	return len(h.fields)
}

// Fields returns immutable copies of the header field sequence.
func (h HeaderBlock) Fields() []HeaderField {
	return cloneHeaderFields(h.fields)
}

// Field returns the header field at index when it exists.
func (h HeaderBlock) Field(index int) (HeaderField, bool) {
	if index < 0 || index >= len(h.fields) {
		return HeaderField{}, false
	}

	return h.fields[index].clone(), true
}

// FieldsByName returns header occurrences matching a lowercase ASCII name.
func (h HeaderBlock) FieldsByName(name string) []HeaderField {
	nameLower, ok := canonicalHeaderLookupName(name)
	if !ok {
		return nil
	}

	var fields []HeaderField
	for _, field := range h.fields {
		if field.nameLower == nameLower {
			fields = append(fields, field.clone())
		}
	}

	return fields
}

// LastFieldByName returns the last matching header occurrence.
func (h HeaderBlock) LastFieldByName(name string) (HeaderField, bool) {
	nameLower, ok := canonicalHeaderLookupName(name)
	if !ok {
		return HeaderField{}, false
	}

	for i := len(h.fields) - 1; i >= 0; i-- {
		if h.fields[i].nameLower == nameLower {
			return h.fields[i].clone(), true
		}
	}

	return HeaderField{}, false
}

// OriginalBytes returns the parser-owned raw header bytes.
func (h HeaderBlock) OriginalBytes() []byte {
	return bytes.Clone(h.originalBytes)
}

// clone returns a deep copy of the header block.
func (h HeaderBlock) clone() HeaderBlock {
	return HeaderBlock{
		fields:        cloneHeaderFields(h.fields),
		originalBytes: bytes.Clone(h.originalBytes),
	}
}

// HeaderField stores one immutable RFC 5322 header occurrence.
type HeaderField struct {
	index         int
	rawName       []byte
	nameLower     string
	rawValue      []byte
	unfoldedValue []byte
	originalBytes []byte
	valid         bool
}

// NewHeaderField constructs an immutable header field and canonical name view.
func NewHeaderField(index int, rawName []byte, rawValue []byte, unfoldedValue []byte, originalBytes []byte) (HeaderField, error) {
	if index < 0 {
		return HeaderField{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
			Reason: ErrorReasonInvariant,
		})
	}
	if !validHeaderFieldName(rawName) {
		return HeaderField{}, NewParserError(ErrorCodeMalformedHeader, ErrorLocation{}, ParserErrorDetails{
			Reason: ErrorReasonMalformed,
		})
	}
	if !validHeaderFieldValue(rawValue) {
		return HeaderField{}, NewParserError(ErrorCodeMalformedHeader, ErrorLocation{}, ParserErrorDetails{
			Reason: ErrorReasonMalformed,
		})
	}
	expectedLength := len(rawName) + 1 + len(rawValue) + len(crlf)
	if len(originalBytes) != expectedLength || !bytes.Equal(originalBytes[:len(rawName)], rawName) || originalBytes[len(rawName)] != ':' || !bytes.Equal(originalBytes[len(rawName)+1:len(originalBytes)-len(crlf)], rawValue) || !bytes.HasSuffix(originalBytes, crlf) {
		return HeaderField{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
			Reason: ErrorReasonInvariant,
		})
	}
	if !bytes.Equal(unfoldedValue, unfoldHeaderValue(rawValue)) {
		return HeaderField{}, NewParserError(ErrorCodeInvalidInvariant, ErrorLocation{}, ParserErrorDetails{
			Reason: ErrorReasonInvariant,
		})
	}

	return HeaderField{
		index:         index,
		rawName:       bytes.Clone(rawName),
		nameLower:     lowerASCII(rawName),
		rawValue:      bytes.Clone(rawValue),
		unfoldedValue: bytes.Clone(unfoldedValue),
		originalBytes: bytes.Clone(originalBytes),
		valid:         true,
	}, nil
}

// Index returns the zero-based header occurrence index.
func (f HeaderField) Index() int {
	return f.index
}

// RawName returns the field name bytes exactly as captured by the parser.
func (f HeaderField) RawName() []byte {
	return bytes.Clone(f.rawName)
}

// NameLower returns the lowercase ASCII field name for matching.
func (f HeaderField) NameLower() string {
	return f.nameLower
}

// RawValue returns the field value bytes without the field name or line ending.
func (f HeaderField) RawValue() []byte {
	return bytes.Clone(f.rawValue)
}

// UnfoldedValue returns a parser-owned unfolded value copy.
func (f HeaderField) UnfoldedValue() []byte {
	return bytes.Clone(f.unfoldedValue)
}

// OriginalBytes returns the original field bytes including its line ending.
func (f HeaderField) OriginalBytes() []byte {
	return bytes.Clone(f.originalBytes)
}

// clone returns a deep copy of the header field.
func (f HeaderField) clone() HeaderField {
	return HeaderField{
		index:         f.index,
		rawName:       bytes.Clone(f.rawName),
		nameLower:     f.nameLower,
		rawValue:      bytes.Clone(f.rawValue),
		unfoldedValue: bytes.Clone(f.unfoldedValue),
		originalBytes: bytes.Clone(f.originalBytes),
		valid:         f.valid,
	}
}

// cloneHeaderFields returns deep copies of header fields.
func cloneHeaderFields(fields []HeaderField) []HeaderField {
	if len(fields) == 0 {
		return nil
	}

	cloned := make([]HeaderField, len(fields))
	for i, field := range fields {
		cloned[i] = field.clone()
	}

	return cloned
}

// validHeaderFieldName reports whether name is an ASCII RFC 5322 field token.
func validHeaderFieldName(name []byte) bool {
	return invalidHeaderFieldNameOffset(name) < 0
}

// lowerASCII lowercases an already validated ASCII header field name.
func lowerASCII(input []byte) string {
	output := make([]byte, len(input))
	for i, b := range input {
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		output[i] = b
	}

	return string(output)
}

// canonicalHeaderLookupName validates and lowercases accessor lookup names.
func canonicalHeaderLookupName(name string) (string, bool) {
	if !validHeaderFieldName([]byte(name)) {
		return "", false
	}

	return lowerASCII([]byte(name)), true
}

// invalidHeaderFieldNameOffset returns the first invalid byte offset.
func invalidHeaderFieldNameOffset(name []byte) int {
	if len(name) == 0 {
		return 0
	}
	for i, b := range name {
		if b <= 32 || b >= 127 || b == ':' {
			return i
		}
	}

	return -1
}

// validHeaderFieldValue validates UTF-8 extensions and folded CRLF framing.
func validHeaderFieldValue(value []byte) bool {
	if !utf8.Valid(value) {
		return false
	}
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '\r':
			if index+2 >= len(value) || value[index+1] != '\n' || value[index+2] != ' ' && value[index+2] != '\t' {
				return false
			}
			index++
		case '\n':
			return false
		}
	}

	return true
}
