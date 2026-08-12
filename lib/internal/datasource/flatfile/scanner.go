package flatfile

import (
	"bytes"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/croessner/dkim2/internal/datasource"
)

const maxSchemaObjectMembers = 8

// scanner performs strict RFC 8259 lexical and structural validation.
type scanner struct {
	data        []byte
	position    int
	depth       int
	stringBytes int
	arrayItems  int
	limits      datasource.Limits
	charge      bool
}

// scanDocument validates one complete JSON value and returns string accounting.
func scanDocument(data []byte, limits datasource.Limits) (int, error) {
	target := scanner{data: data, limits: limits, charge: true}
	target.skipWhitespace()
	if err := target.scanValue(); err != nil {
		return 0, err
	}
	target.skipWhitespace()
	if target.position != len(target.data) {
		return 0, malformed()
	}
	return target.stringBytes, nil
}

// scanValue validates one JSON value without constructing a generic model.
func (s *scanner) scanValue() error {
	s.skipWhitespace()
	if s.position >= len(s.data) {
		return malformed()
	}
	switch s.data[s.position] {
	case '{':
		return s.scanObject()
	case '[':
		return s.scanArray()
	case '"':
		_, err := s.readString()
		return err
	case 't':
		return s.scanLiteral("true")
	case 'f':
		return s.scanLiteral("false")
	case 'n':
		return s.scanLiteral("null")
	default:
		return s.scanNumber()
	}
}

// scanObject validates one object and rejects decoded-equivalent member names.
func (s *scanner) scanObject() error {
	if err := s.enter('{'); err != nil {
		return err
	}
	seen := make(map[string]struct{})
	s.skipWhitespace()
	if s.consume('}') {
		s.leave()
		return nil
	}
	for {
		s.skipWhitespace()
		name, err := s.readString()
		if err != nil {
			return err
		}
		if _, duplicate := seen[name]; duplicate {
			return malformed()
		}
		if len(seen) >= maxSchemaObjectMembers {
			return malformed()
		}
		seen[name] = struct{}{}
		s.skipWhitespace()
		if !s.consume(':') {
			return malformed()
		}
		if err := s.scanValue(); err != nil {
			return err
		}
		s.skipWhitespace()
		if s.consume('}') {
			s.leave()
			return nil
		}
		if !s.consume(',') {
			return malformed()
		}
	}
}

// scanArray validates one bounded-depth JSON array.
func (s *scanner) scanArray() error {
	if err := s.enter('['); err != nil {
		return err
	}
	items := 0
	s.skipWhitespace()
	if s.consume(']') {
		s.leave()
		return nil
	}
	for {
		if items >= s.maxArrayItems() || s.arrayItems >= s.limits.MaxRecords {
			return limitExceeded()
		}
		items++
		s.arrayItems++
		if err := s.scanValue(); err != nil {
			return err
		}
		s.skipWhitespace()
		if s.consume(']') {
			s.leave()
			return nil
		}
		if !s.consume(',') {
			return malformed()
		}
	}
}

// maxArrayItems returns the largest configured valid schema collection.
func (s *scanner) maxArrayItems() int {
	maximum := s.limits.MaxProfiles
	for _, candidate := range []int{
		s.limits.MaxCredentialsPerProfile,
		s.limits.MaxHandles,
		s.limits.MaxPolicies,
	} {
		if candidate > maximum {
			maximum = candidate
		}
	}
	return maximum
}

// scanLiteral consumes one exact JSON literal.
func (s *scanner) scanLiteral(literal string) error {
	if !bytes.HasPrefix(s.data[s.position:], []byte(literal)) {
		return malformed()
	}
	s.position += len(literal)
	return nil
}

// scanNumber validates the RFC 8259 JSON number grammar.
func (s *scanner) scanNumber() error {
	start := s.position
	s.consume('-')
	if s.consume('0') {
		if s.position < len(s.data) && isDigit(s.data[s.position]) {
			return malformed()
		}
	} else {
		if s.position >= len(s.data) || !isNonzeroDigit(s.data[s.position]) {
			return malformed()
		}
		for s.position < len(s.data) && isDigit(s.data[s.position]) {
			s.position++
		}
	}
	if s.consume('.') {
		if s.position >= len(s.data) || !isDigit(s.data[s.position]) {
			return malformed()
		}
		for s.position < len(s.data) && isDigit(s.data[s.position]) {
			s.position++
		}
	}
	if s.position < len(s.data) && (s.data[s.position] == 'e' || s.data[s.position] == 'E') {
		s.position++
		if s.position < len(s.data) && (s.data[s.position] == '+' || s.data[s.position] == '-') {
			s.position++
		}
		if s.position >= len(s.data) || !isDigit(s.data[s.position]) {
			return malformed()
		}
		for s.position < len(s.data) && isDigit(s.data[s.position]) {
			s.position++
		}
	}
	if s.position == start {
		return malformed()
	}
	return nil
}

// readString decodes one strict JSON string and applies configured accounting.
func (s *scanner) readString() (string, error) {
	if !s.consume('"') {
		return "", malformed()
	}
	var decoded strings.Builder
	for s.position < len(s.data) {
		value := s.data[s.position]
		switch {
		case value == '"':
			s.position++
			result := decoded.String()
			if len(result) > s.limits.MaxJSONStringBytes {
				return "", limitExceeded()
			}
			if s.charge {
				if len(result) > s.limits.MaxDecodedStringBytes-s.stringBytes {
					return "", limitExceeded()
				}
				s.stringBytes += len(result)
			}
			return result, nil
		case value == '\\':
			s.position++
			if err := s.readEscape(&decoded); err != nil {
				return "", err
			}
		case value < 0x20:
			return "", malformed()
		case value < utf8.RuneSelf:
			decoded.WriteByte(value)
			s.position++
		default:
			r, size := utf8.DecodeRune(s.data[s.position:])
			if r == utf8.RuneError && size == 1 {
				return "", malformed()
			}
			decoded.WriteRune(r)
			s.position += size
		}
		if decoded.Len() > s.limits.MaxJSONStringBytes {
			return "", limitExceeded()
		}
	}
	return "", malformed()
}

// readEscape decodes one JSON escape and rejects invalid UTF-16 sequences.
func (s *scanner) readEscape(output *strings.Builder) error {
	if s.position >= len(s.data) {
		return malformed()
	}
	escape := s.data[s.position]
	s.position++
	switch escape {
	case '"', '\\', '/':
		output.WriteByte(escape)
	case 'b':
		output.WriteByte('\b')
	case 'f':
		output.WriteByte('\f')
	case 'n':
		output.WriteByte('\n')
	case 'r':
		output.WriteByte('\r')
	case 't':
		output.WriteByte('\t')
	case 'u':
		return s.readUnicodeEscape(output)
	default:
		return malformed()
	}
	return nil
}

// readUnicodeEscape decodes one scalar from canonical JSON UTF-16 escapes.
func (s *scanner) readUnicodeEscape(output *strings.Builder) error {
	first, ok := s.readHexQuad()
	if !ok {
		return malformed()
	}
	firstRune := rune(first)
	if firstRune >= 0xDC00 && firstRune <= 0xDFFF {
		return malformed()
	}
	if firstRune < 0xD800 || firstRune > 0xDBFF {
		output.WriteRune(firstRune)
		return nil
	}
	if s.position+2 > len(s.data) || s.data[s.position] != '\\' ||
		s.data[s.position+1] != 'u' {
		return malformed()
	}
	s.position += 2
	second, ok := s.readHexQuad()
	if !ok || second < 0xDC00 || second > 0xDFFF {
		return malformed()
	}
	decoded := utf16.DecodeRune(firstRune, rune(second))
	if decoded == utf8.RuneError {
		return malformed()
	}
	output.WriteRune(decoded)
	return nil
}

// readHexQuad consumes exactly four hexadecimal digits.
func (s *scanner) readHexQuad() (uint16, bool) {
	if s.position+4 > len(s.data) {
		return 0, false
	}
	var value uint16
	for range 4 {
		digit, ok := hexValue(s.data[s.position])
		if !ok {
			return 0, false
		}
		value = value<<4 | uint16(digit)
		s.position++
	}
	return value, true
}

// enter consumes one container opener and enforces nesting depth before descent.
func (s *scanner) enter(open byte) error {
	if !s.consume(open) {
		return malformed()
	}
	if s.depth >= s.limits.MaxJSONDepth {
		return limitExceeded()
	}
	s.depth++
	return nil
}

// leave records one completed container.
func (s *scanner) leave() { s.depth-- }

// skipWhitespace consumes the four RFC 8259 whitespace bytes.
func (s *scanner) skipWhitespace() {
	for s.position < len(s.data) {
		switch s.data[s.position] {
		case ' ', '\t', '\n', '\r':
			s.position++
		default:
			return
		}
	}
}

// consume advances past one expected byte when present.
func (s *scanner) consume(expected byte) bool {
	if s.position >= len(s.data) || s.data[s.position] != expected {
		return false
	}
	s.position++
	return true
}

// isDigit reports whether one byte is an ASCII decimal digit.
func isDigit(value byte) bool { return value >= '0' && value <= '9' }

// isNonzeroDigit reports whether one byte is an ASCII nonzero decimal digit.
func isNonzeroDigit(value byte) bool { return value >= '1' && value <= '9' }

// hexValue decodes one ASCII hexadecimal digit.
func hexValue(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}
