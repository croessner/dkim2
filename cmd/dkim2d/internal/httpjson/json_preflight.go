package httpjson

import (
	"unicode/utf16"
	"unicode/utf8"
)

const (
	maxJSONDepth           = 32
	maxJSONTokens          = 8_192
	maxJSONMemberNameBytes = 64
	maxAPIVersionBytes     = 16
	maxDraftVersionBytes   = 128

	supportedAPIVersion   = "v1"
	supportedDraftVersion = "draft-ietf-dkim-dkim2-spec-04"
	jsonDraftMember       = "draft"

	jsonPreflightErrorDescription = "http-json lexical preflight failure"
)

type jsonPreflightErrorCode uint8

const (
	jsonPreflightInvalidJSON jsonPreflightErrorCode = iota + 1
	jsonPreflightRequestTooLarge
	jsonPreflightInvalidContract
	jsonPreflightUnsupportedVersion
	jsonPreflightUnsupportedDraft
)

type jsonPreflightError struct {
	code jsonPreflightErrorCode
}

// Error returns one constant diagnostic that never retains request bytes.
func (*jsonPreflightError) Error() string {
	return jsonPreflightErrorDescription
}

// Code returns the closed lexical-preflight failure class.
func (e *jsonPreflightError) Code() jsonPreflightErrorCode {
	if e == nil {
		return 0
	}

	return e.code
}

type jsonConstants struct {
	apiVersion string
	draft      string
	rawMessage jsonRawMessageToken
	known      jsonKnownFieldFacts
}

type jsonRawMessageToken struct {
	present     bool
	stringValue bool
	start       int
	end         int
	escaped     bool
	decodedSize int
}

type jsonObjectScope uint8

const (
	jsonObjectGeneric jsonObjectScope = iota
	jsonObjectRoot
	jsonObjectMessage
	jsonObjectSMTP
)

type jsonConstantState struct {
	apiVersionSeen   bool
	apiVersionString bool
	apiVersionLarge  bool
	apiVersion       string
	draftSeen        bool
	draftString      bool
	draftLarge       bool
	draft            string
	rawMessage       jsonRawMessageToken
	known            jsonKnownFieldFacts
}

type jsonStringFact struct {
	present     bool
	stringValue bool
	decodedSize int
}

type jsonRecipientFacts struct {
	present       bool
	arrayValue    bool
	allStrings    bool
	count         int
	decodedBytes  int
	maxStringSize int
}

type jsonKnownFieldFacts struct {
	smtpObject bool
	mailFrom   jsonStringFact
	recipients jsonRecipientFacts
}

type jsonScanner struct {
	input     []byte
	offset    int
	tokens    int
	depth     int
	constants jsonConstantState

	lastStringEscaped bool
	lastStringBytes   int
	deferStringLimit  bool
}

// preflightJSON validates one bounded RFC 8259 text and extracts its root constants.
func preflightJSON(input []byte) (jsonConstants, error) {
	scanner := jsonScanner{input: input}
	return scanner.scanDocument()
}

// scanDocument validates one complete JSON text and classifies its root constants.
func (s *jsonScanner) scanDocument() (jsonConstants, error) {
	s.skipWhitespace()
	if s.offset == len(s.input) {
		return jsonConstants{}, newJSONPreflightError(jsonPreflightInvalidJSON)
	}

	rootObject := s.input[s.offset] == '{'
	scope := jsonObjectGeneric
	if rootObject {
		scope = jsonObjectRoot
	}
	if err := s.scanValue(scope, false, 0); err != nil {
		return jsonConstants{}, err
	}
	s.skipWhitespace()
	if s.offset != len(s.input) {
		return jsonConstants{}, newJSONPreflightError(jsonPreflightInvalidJSON)
	}
	if !rootObject || !s.constants.apiVersionSeen || !s.constants.apiVersionString {
		return jsonConstants{}, newJSONPreflightError(jsonPreflightInvalidContract)
	}
	if s.constants.apiVersionLarge {
		return jsonConstants{}, newJSONPreflightError(jsonPreflightRequestTooLarge)
	}
	if s.constants.apiVersion != supportedAPIVersion {
		return jsonConstants{}, newJSONPreflightError(jsonPreflightUnsupportedVersion)
	}
	if !s.constants.draftSeen || !s.constants.draftString {
		return jsonConstants{}, newJSONPreflightError(jsonPreflightInvalidContract)
	}
	if s.constants.draftLarge {
		return jsonConstants{}, newJSONPreflightError(jsonPreflightRequestTooLarge)
	}
	if s.constants.draft != supportedDraftVersion {
		return jsonConstants{}, newJSONPreflightError(jsonPreflightUnsupportedDraft)
	}

	return jsonConstants{
		apiVersion: supportedAPIVersion,
		draft:      supportedDraftVersion,
		rawMessage: s.constants.rawMessage,
		known:      s.constants.known,
	}, nil
}

// scanValue validates one JSON value and optionally captures a bounded string value.
func (s *jsonScanner) scanValue(scope jsonObjectScope, captureString bool, stringLimit int) error {
	s.skipWhitespace()
	if s.offset == len(s.input) {
		return newJSONPreflightError(jsonPreflightInvalidJSON)
	}

	switch s.input[s.offset] {
	case '{':
		return s.scanObject(scope)
	case '[':
		return s.scanArray()
	case '"':
		_, err := s.scanString(captureString, stringLimit)
		return err
	case 'f':
		return s.scanLiteral("false")
	case 'n':
		return s.scanLiteral("null")
	case 't':
		return s.scanLiteral("true")
	case '-':
		return s.scanNumber()
	default:
		if isJSONDigit(s.input[s.offset]) {
			return s.scanNumber()
		}

		return newJSONPreflightError(jsonPreflightInvalidJSON)
	}
}

// scanObject validates one object and detects duplicate decoded member names.
func (s *jsonScanner) scanObject(scope jsonObjectScope) error {
	if err := s.openContainer('{'); err != nil {
		return err
	}
	defer func() {
		s.depth--
	}()

	members := make(map[string]struct{})
	s.skipWhitespace()
	if s.hasByte('}') {
		return s.acceptStructural('}')
	}

	for {
		s.skipWhitespace()
		if !s.hasByte('"') {
			return newJSONPreflightError(jsonPreflightInvalidJSON)
		}
		name, err := s.scanString(true, maxJSONMemberNameBytes)
		if err != nil {
			return err
		}
		if _, exists := members[name]; exists {
			return newJSONPreflightError(jsonPreflightInvalidJSON)
		}
		members[name] = struct{}{}

		s.skipWhitespace()
		if err := s.acceptStructural(':'); err != nil {
			return err
		}

		if err := s.scanObjectMember(scope, name); err != nil {
			return err
		}

		s.skipWhitespace()
		switch {
		case s.hasByte('}'):
			return s.acceptStructural('}')
		case s.hasByte(','):
			if err := s.acceptStructural(','); err != nil {
				return err
			}
		default:
			return newJSONPreflightError(jsonPreflightInvalidJSON)
		}
	}
}

// scanObjectMember dispatches one decoded member through its owning object scope.
func (s *jsonScanner) scanObjectMember(scope jsonObjectScope, name string) error {
	switch scope {
	case jsonObjectRoot:
		return s.scanRootMember(name)
	case jsonObjectMessage:
		if name == "raw_rfc5322_base64" {
			return s.scanRawMessageValue()
		}
	case jsonObjectSMTP:
		return s.scanSMTPMember(name)
	}
	return s.scanValue(jsonObjectGeneric, false, 0)
}

// scanRootMember captures bounded root constants and delegates structured values.
func (s *jsonScanner) scanRootMember(name string) error {
	switch name {
	case "api_version":
		s.constants.apiVersionSeen = true
		value, isString, tooLarge, err := s.scanConstantStringValue(maxAPIVersionBytes)
		if err != nil {
			return err
		}
		s.constants.apiVersionString = isString
		s.constants.apiVersionLarge = tooLarge
		s.constants.apiVersion = value
		return nil
	case jsonDraftMember:
		s.constants.draftSeen = true
		value, isString, tooLarge, err := s.scanConstantStringValue(maxDraftVersionBytes)
		if err != nil {
			return err
		}
		s.constants.draftString = isString
		s.constants.draftLarge = tooLarge
		s.constants.draft = value
		return nil
	case "message":
		return s.scanMessageValue()
	case "smtp":
		return s.scanSMTPValue()
	default:
		return s.scanValue(jsonObjectGeneric, false, 0)
	}
}

// scanSMTPMember captures bounded SMTP fields and ignores unknown members structurally.
func (s *jsonScanner) scanSMTPMember(name string) error {
	switch name {
	case "mail_from":
		return s.scanSMTPPathValue()
	case "rcpt_to":
		return s.scanRecipientValues()
	default:
		return s.scanValue(jsonObjectGeneric, false, 0)
	}
}

// scanArray validates one array without retaining any element value.
func (s *jsonScanner) scanArray() error {
	if err := s.openContainer('['); err != nil {
		return err
	}
	defer func() {
		s.depth--
	}()

	s.skipWhitespace()
	if s.hasByte(']') {
		return s.acceptStructural(']')
	}

	for {
		if err := s.scanValue(jsonObjectGeneric, false, 0); err != nil {
			return err
		}
		s.skipWhitespace()
		switch {
		case s.hasByte(']'):
			return s.acceptStructural(']')
		case s.hasByte(','):
			if err := s.acceptStructural(','); err != nil {
				return err
			}
		default:
			return newJSONPreflightError(jsonPreflightInvalidJSON)
		}
	}
}

// scanMessageValue recognizes only the root message object without retaining its values.
func (s *jsonScanner) scanMessageValue() error {
	s.skipWhitespace()
	if s.hasByte('{') {
		return s.scanObject(jsonObjectMessage)
	}

	return s.scanValue(jsonObjectGeneric, false, 0)
}

// scanSMTPValue recognizes only the exact root smtp object.
func (s *jsonScanner) scanSMTPValue() error {
	s.skipWhitespace()
	if s.hasByte('{') {
		s.constants.known.smtpObject = true
		return s.scanObject(jsonObjectSMTP)
	}
	s.constants.known.smtpObject = false
	return s.scanValue(jsonObjectGeneric, false, 0)
}

// scanSMTPPathValue records only the decoded byte size of exact mail_from.
func (s *jsonScanner) scanSMTPPathValue() error {
	fact := &s.constants.known.mailFrom
	fact.present = true
	s.skipWhitespace()
	if !s.hasByte('"') {
		fact.stringValue = false
		return s.scanValue(jsonObjectGeneric, false, 0)
	}
	fact.stringValue = true
	if _, err := s.scanString(false, 0); err != nil {
		return err
	}
	fact.decodedSize = s.lastStringBytes
	return nil
}

// scanRecipientValues records exact rcpt_to count and decoded string sizes.
func (s *jsonScanner) scanRecipientValues() error {
	facts := &s.constants.known.recipients
	facts.present = true
	facts.allStrings = true
	s.skipWhitespace()
	if !s.hasByte('[') {
		facts.arrayValue = false
		return s.scanValue(jsonObjectGeneric, false, 0)
	}
	facts.arrayValue = true
	if err := s.openContainer('['); err != nil {
		return err
	}
	defer func() { s.depth-- }()
	s.skipWhitespace()
	if s.hasByte(']') {
		return s.acceptStructural(']')
	}
	for {
		facts.count++
		s.skipWhitespace()
		if s.hasByte('"') {
			if _, err := s.scanString(false, 0); err != nil {
				return err
			}
			facts.decodedBytes += s.lastStringBytes
			facts.maxStringSize = max(facts.maxStringSize, s.lastStringBytes)
		} else {
			facts.allStrings = false
			if err := s.scanValue(jsonObjectGeneric, false, 0); err != nil {
				return err
			}
		}
		s.skipWhitespace()
		switch {
		case s.hasByte(']'):
			return s.acceptStructural(']')
		case s.hasByte(','):
			if err := s.acceptStructural(','); err != nil {
				return err
			}
		default:
			return newJSONPreflightError(jsonPreflightInvalidJSON)
		}
	}
}

// scanRawMessageValue records input-relative bounds only for one string token.
func (s *jsonScanner) scanRawMessageValue() error {
	s.constants.rawMessage.present = true
	s.skipWhitespace()
	if !s.hasByte('"') {
		s.constants.rawMessage.stringValue = false
		return s.scanValue(jsonObjectGeneric, false, 0)
	}

	s.constants.rawMessage.stringValue = true
	s.constants.rawMessage.start = s.offset + 1
	if _, err := s.scanString(false, 0); err != nil {
		return err
	}
	s.constants.rawMessage.end = s.offset - 1
	s.constants.rawMessage.escaped = s.lastStringEscaped
	s.constants.rawMessage.decodedSize = s.lastStringBytes

	return nil
}

// scanConstantStringValue defers its size outcome until ordered constant classification.
func (s *jsonScanner) scanConstantStringValue(limit int) (string, bool, bool, error) {
	s.skipWhitespace()
	if !s.hasByte('"') {
		if err := s.scanValue(jsonObjectGeneric, false, 0); err != nil {
			return "", false, false, err
		}
		return "", false, false, nil
	}
	s.deferStringLimit = true
	value, err := s.scanString(true, limit)
	s.deferStringLimit = false
	if err != nil {
		return "", false, false, err
	}
	return value, true, s.lastStringBytes > limit, nil
}

// scanString validates one JSON string and retains decoded bytes only when requested.
func (s *jsonScanner) scanString(capture bool, limit int) (string, error) {
	if err := s.chargeToken(); err != nil {
		return "", err
	}
	if !s.hasByte('"') {
		return "", newJSONPreflightError(jsonPreflightInvalidJSON)
	}
	s.offset++
	s.lastStringEscaped = false
	s.lastStringBytes = 0

	var decoded []byte
	if capture {
		decoded = make([]byte, 0, min(limit, 16))
	}

	for s.offset < len(s.input) {
		current := s.input[s.offset]
		switch {
		case current == '"':
			s.offset++
			return string(decoded), nil
		case current == '\\':
			s.lastStringEscaped = true
			s.offset++
			escaped, width, err := s.scanEscape()
			if err != nil {
				return "", err
			}
			if capture {
				decoded, err = s.appendCapturedString(decoded, escaped[:width], limit)
				if err != nil {
					return "", err
				}
			}
			s.lastStringBytes += width
		case current < 0x20:
			return "", newJSONPreflightError(jsonPreflightInvalidJSON)
		default:
			r, width := utf8.DecodeRune(s.input[s.offset:])
			if r == utf8.RuneError && width == 1 {
				return "", newJSONPreflightError(jsonPreflightInvalidJSON)
			}
			if capture {
				var err error
				decoded, err = s.appendCapturedString(decoded, s.input[s.offset:s.offset+width], limit)
				if err != nil {
					return "", err
				}
			}
			s.lastStringBytes += width
			s.offset += width
		}
	}

	return "", newJSONPreflightError(jsonPreflightInvalidJSON)
}

// appendCapturedString bounds retained bytes or defers one constant-size outcome.
func (s *jsonScanner) appendCapturedString(
	destination []byte,
	source []byte,
	limit int,
) ([]byte, error) {
	if len(destination) > limit-len(source) {
		if s.deferStringLimit {
			return destination, nil
		}
		return nil, newJSONPreflightError(jsonPreflightRequestTooLarge)
	}
	return append(destination, source...), nil
}

// scanEscape validates one JSON escape and returns its exact decoded UTF-8 bytes.
func (s *jsonScanner) scanEscape() ([utf8.UTFMax]byte, int, error) {
	var encoded [utf8.UTFMax]byte
	if s.offset == len(s.input) {
		return encoded, 0, newJSONPreflightError(jsonPreflightInvalidJSON)
	}

	current := s.input[s.offset]
	s.offset++
	switch current {
	case '"', '\\', '/':
		encoded[0] = current
		return encoded, 1, nil
	case 'b':
		encoded[0] = '\b'
		return encoded, 1, nil
	case 'f':
		encoded[0] = '\f'
		return encoded, 1, nil
	case 'n':
		encoded[0] = '\n'
		return encoded, 1, nil
	case 'r':
		encoded[0] = '\r'
		return encoded, 1, nil
	case 't':
		encoded[0] = '\t'
		return encoded, 1, nil
	case 'u':
		first, err := s.scanHexRune()
		if err != nil {
			return encoded, 0, err
		}
		if first >= 0xdc00 && first <= 0xdfff {
			return encoded, 0, newJSONPreflightError(jsonPreflightInvalidJSON)
		}
		if first >= 0xd800 && first <= 0xdbff {
			if s.offset+2 > len(s.input) || s.input[s.offset] != '\\' || s.input[s.offset+1] != 'u' {
				return encoded, 0, newJSONPreflightError(jsonPreflightInvalidJSON)
			}
			s.offset += 2
			second, secondErr := s.scanHexRune()
			if secondErr != nil || second < 0xdc00 || second > 0xdfff {
				return encoded, 0, newJSONPreflightError(jsonPreflightInvalidJSON)
			}
			first = utf16.DecodeRune(first, second)
		}

		width := utf8.EncodeRune(encoded[:], first)
		return encoded, width, nil
	default:
		return encoded, 0, newJSONPreflightError(jsonPreflightInvalidJSON)
	}
}

// scanHexRune decodes exactly four hexadecimal digits from a Unicode escape.
func (s *jsonScanner) scanHexRune() (rune, error) {
	if s.offset+4 > len(s.input) {
		return 0, newJSONPreflightError(jsonPreflightInvalidJSON)
	}

	var value rune
	for _, current := range s.input[s.offset : s.offset+4] {
		value <<= 4
		switch {
		case current >= '0' && current <= '9':
			value += rune(current - '0')
		case current >= 'a' && current <= 'f':
			value += rune(current-'a') + 10
		case current >= 'A' && current <= 'F':
			value += rune(current-'A') + 10
		default:
			return 0, newJSONPreflightError(jsonPreflightInvalidJSON)
		}
	}
	s.offset += 4

	return value, nil
}

// scanLiteral validates and consumes one RFC 8259 literal token.
func (s *jsonScanner) scanLiteral(literal string) error {
	if err := s.chargeToken(); err != nil {
		return err
	}
	if len(s.input)-s.offset < len(literal) {
		return newJSONPreflightError(jsonPreflightInvalidJSON)
	}
	for index := range len(literal) {
		if s.input[s.offset+index] != literal[index] {
			return newJSONPreflightError(jsonPreflightInvalidJSON)
		}
	}
	s.offset += len(literal)

	return nil
}

// scanNumber validates and consumes one RFC 8259 number token.
func (s *jsonScanner) scanNumber() error {
	if err := s.chargeToken(); err != nil {
		return err
	}

	if s.hasByte('-') {
		s.offset++
		if s.offset == len(s.input) {
			return newJSONPreflightError(jsonPreflightInvalidJSON)
		}
	}

	switch {
	case s.hasByte('0'):
		s.offset++
		if s.offset < len(s.input) && isJSONDigit(s.input[s.offset]) {
			return newJSONPreflightError(jsonPreflightInvalidJSON)
		}
	case s.offset < len(s.input) && s.input[s.offset] >= '1' && s.input[s.offset] <= '9':
		for s.offset < len(s.input) && isJSONDigit(s.input[s.offset]) {
			s.offset++
		}
	default:
		return newJSONPreflightError(jsonPreflightInvalidJSON)
	}

	if s.hasByte('.') {
		s.offset++
		if s.offset == len(s.input) || !isJSONDigit(s.input[s.offset]) {
			return newJSONPreflightError(jsonPreflightInvalidJSON)
		}
		for s.offset < len(s.input) && isJSONDigit(s.input[s.offset]) {
			s.offset++
		}
	}

	if s.hasByte('e') || s.hasByte('E') {
		s.offset++
		if s.hasByte('+') || s.hasByte('-') {
			s.offset++
		}
		if s.offset == len(s.input) || !isJSONDigit(s.input[s.offset]) {
			return newJSONPreflightError(jsonPreflightInvalidJSON)
		}
		for s.offset < len(s.input) && isJSONDigit(s.input[s.offset]) {
			s.offset++
		}
	}

	return nil
}

// openContainer accepts one opening structural token and enforces maximum depth.
func (s *jsonScanner) openContainer(want byte) error {
	if err := s.acceptStructural(want); err != nil {
		return err
	}
	s.depth++
	if s.depth > maxJSONDepth {
		return newJSONPreflightError(jsonPreflightRequestTooLarge)
	}

	return nil
}

// acceptStructural charges and consumes one exact JSON structural token.
func (s *jsonScanner) acceptStructural(want byte) error {
	if !s.hasByte(want) {
		return newJSONPreflightError(jsonPreflightInvalidJSON)
	}
	if err := s.chargeToken(); err != nil {
		return err
	}
	s.offset++

	return nil
}

// chargeToken reserves one token before accepting it.
func (s *jsonScanner) chargeToken() error {
	if s.tokens == maxJSONTokens {
		return newJSONPreflightError(jsonPreflightRequestTooLarge)
	}
	s.tokens++

	return nil
}

// skipWhitespace consumes insignificant RFC 8259 whitespace.
func (s *jsonScanner) skipWhitespace() {
	for s.offset < len(s.input) {
		switch s.input[s.offset] {
		case ' ', '\t', '\n', '\r':
			s.offset++
		default:
			return
		}
	}
}

// hasByte reports whether the current input byte equals want.
func (s *jsonScanner) hasByte(want byte) bool {
	return s.offset < len(s.input) && s.input[s.offset] == want
}

// isJSONDigit reports whether one byte belongs to the decimal digit grammar.
func isJSONDigit(value byte) bool {
	return value >= '0' && value <= '9'
}

// newJSONPreflightError constructs one content-free lexical-preflight error.
func newJSONPreflightError(code jsonPreflightErrorCode) *jsonPreflightError {
	return &jsonPreflightError{code: code}
}

var _ error = (*jsonPreflightError)(nil)
