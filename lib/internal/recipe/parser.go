package recipe

import (
	"bytes"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// Parser converts decoded Draft-06 recipe JSON into immutable plans.
type Parser struct {
	limits      Limits
	initialized bool
}

// NewParser constructs a strict recipe parser with resolved restrictive limits.
func NewParser(limits Limits) (Parser, error) {
	resolved, err := limits.normalized()
	if err != nil {
		return Parser{}, err
	}
	return Parser{limits: resolved, initialized: true}, nil
}

// Valid reports whether the parser owns coherent resolved limits.
func (p Parser) Valid() bool {
	return p.initialized && p.limits.Validate() == nil
}

// Parse parses one complete decoded RFC 8259 recipe object.
func (p Parser) Parse(input []byte) (Recipe, Usage, error) {
	counter, counterErr := newUsageCounter(p.limits)
	if counterErr != nil || !p.initialized {
		if counter == nil {
			counter, _ = newUsageCounter(DefaultLimits())
		}
		return Recipe{}, counter.usage(), invalidStateError()
	}
	if err := counter.chargeDecoded(len(input)); err != nil {
		return Recipe{}, counter.usage(), err
	}
	ownedInput := bytes.Clone(input)
	scanner := jsonScanner{input: ownedInput, limits: p.limits, usage: counter}
	root, err := scanner.parseDocument()
	if err != nil {
		return Recipe{}, counter.usage(), err
	}
	semantic := recipeDecoder{limits: p.limits, usage: counter}
	parsed, err := semantic.decodeRoot(root)
	if err != nil {
		return Recipe{}, counter.usage(), err
	}
	return parsed, counter.usage(), nil
}

type jsonKind uint8

const (
	jsonInvalid jsonKind = iota
	jsonObject
	jsonArray
	jsonString
	jsonNumber
	jsonNull
	jsonBoolean
)

type jsonMember struct {
	name   string
	value  jsonValue
	offset int
}

type jsonValue struct {
	kind    jsonKind
	offset  int
	text    []byte
	members []jsonMember
	items   []jsonValue
}

type jsonScanner struct {
	input           []byte
	offset          int
	depth           int
	tokens          int
	members         int
	stringValues    int
	stringBytes     int
	headerNameBytes int
	limits          Limits
	usage           *usageCounter
}

// parseDocument parses exactly one JSON value with surrounding RFC 8259 whitespace.
func (s *jsonScanner) parseDocument() (jsonValue, error) {
	s.skipWhitespace()
	if s.offset >= len(s.input) {
		return jsonValue{}, s.syntaxError()
	}
	value, err := s.parseValue()
	if err != nil {
		return jsonValue{}, err
	}
	s.skipWhitespace()
	if s.offset != len(s.input) {
		return jsonValue{}, s.syntaxError()
	}
	return value, nil
}

// parseValue dispatches one bounded JSON value.
func (s *jsonScanner) parseValue() (jsonValue, error) {
	s.skipWhitespace()
	if s.offset >= len(s.input) {
		return jsonValue{}, s.syntaxError()
	}
	switch s.input[s.offset] {
	case '{':
		return s.parseObject(false)
	case '[':
		return s.parseArray()
	case '"':
		start := s.offset
		if err := s.beginStringValue(start); err != nil {
			return jsonValue{}, err
		}
		value, err := s.parseStringToken(s.stringValueLimit(), s.stringValueLimitName())
		if err == nil {
			s.stringBytes += len(value)
		}
		return jsonValue{kind: jsonString, offset: start, text: value}, err
	case 'n':
		return s.parseLiteral("null", jsonNull)
	case 't':
		return s.parseLiteral("true", jsonBoolean)
	case 'f':
		return s.parseLiteral("false", jsonBoolean)
	default:
		if s.input[s.offset] == '-' || isDigit(s.input[s.offset]) {
			return s.parseNumber()
		}
		return jsonValue{}, s.syntaxError()
	}
}

// parseObject parses one duplicate-aware JSON object.
func (s *jsonScanner) parseObject(headerNames bool) (jsonValue, error) {
	start := s.offset
	if err := s.enterContainer(); err != nil {
		return jsonValue{}, err
	}
	defer s.leaveContainer()
	if err := s.consumeToken('{'); err != nil {
		return jsonValue{}, err
	}
	s.skipWhitespace()
	if s.peek('}') {
		if err := s.consumeToken('}'); err != nil {
			return jsonValue{}, err
		}
		return jsonValue{kind: jsonObject, offset: start}, nil
	}
	seen := make(map[string]struct{})
	members := make([]jsonMember, 0)
	for {
		s.skipWhitespace()
		memberOffset := s.offset
		nameLimit, nameLimitName := s.memberNameLimit(headerNames)
		nameBytes, err := s.parseStringToken(nameLimit, nameLimitName)
		if err != nil {
			return jsonValue{}, err
		}
		if headerNames {
			s.headerNameBytes += len(nameBytes)
		}
		name := string(nameBytes)
		if err := s.chargeMember(); err != nil {
			return jsonValue{}, err
		}
		if _, duplicate := seen[name]; duplicate {
			return jsonValue{}, newError(ErrorCodeDuplicateMember, ErrorLocation{Offset: memberOffset, MemberIndex: len(members)}, ErrorDetails{Class: ErrorClassSyntax}, nil)
		}
		seen[name] = struct{}{}
		s.skipWhitespace()
		if err := s.consumeToken(':'); err != nil {
			return jsonValue{}, err
		}
		var value jsonValue
		if s.depth == 1 && name == "h" {
			s.skipWhitespace()
			if s.peek('{') {
				value, err = s.parseObject(true)
			} else {
				value, err = s.parseValue()
			}
		} else {
			value, err = s.parseValue()
		}
		if err != nil {
			return jsonValue{}, err
		}
		members = append(members, jsonMember{name: name, value: value, offset: memberOffset})
		s.skipWhitespace()
		if s.peek('}') {
			if err := s.consumeToken('}'); err != nil {
				return jsonValue{}, err
			}
			break
		}
		if err := s.consumeToken(','); err != nil {
			return jsonValue{}, err
		}
	}
	return jsonValue{kind: jsonObject, offset: start, members: members}, nil
}

// memberNameLimit selects incremental limits only for dynamic h member names.
func (s *jsonScanner) memberNameLimit(headerNames bool) (int, string) {
	if !headerNames {
		return s.limits.MaxDecodedRecipeBytes, limitNameMaxDecodedRecipeBytes
	}
	remaining := s.limits.MaxTotalHeaderNameBytes - s.headerNameBytes
	if remaining < s.limits.MaxHeaderNameBytes {
		return remaining, limitNameMaxTotalHeaderNameBytes
	}
	return s.limits.MaxHeaderNameBytes, limitNameMaxHeaderNameBytes
}

// beginStringValue charges one recognized or ignored decoded string before scanning it.
func (s *jsonScanner) beginStringValue(offset int) error {
	s.stringValues++
	if err := s.usage.chargeItems(1); err != nil {
		return err
	}
	if s.stringValues > s.limits.MaxDataStrings {
		return parserLimitError(limitNameMaxDataStrings, s.limits.MaxDataStrings, s.stringValues, offset)
	}
	return nil
}

// stringValueLimit returns the remaining smallest decoded string ceiling.
func (s *jsonScanner) stringValueLimit() int {
	remaining := s.limits.MaxTotalLiteralBytes - s.stringBytes
	if remaining < s.limits.MaxDataStringBytes {
		return remaining
	}
	return s.limits.MaxDataStringBytes
}

// stringValueLimitName identifies the ceiling selected by stringValueLimit.
func (s *jsonScanner) stringValueLimitName() string {
	if s.limits.MaxTotalLiteralBytes-s.stringBytes < s.limits.MaxDataStringBytes {
		return limitNameMaxTotalLiteralBytes
	}
	return limitNameMaxDataStringBytes
}

// parseArray parses one ordered JSON array.
func (s *jsonScanner) parseArray() (jsonValue, error) {
	start := s.offset
	if err := s.enterContainer(); err != nil {
		return jsonValue{}, err
	}
	defer s.leaveContainer()
	if err := s.consumeToken('['); err != nil {
		return jsonValue{}, err
	}
	s.skipWhitespace()
	if s.peek(']') {
		if err := s.consumeToken(']'); err != nil {
			return jsonValue{}, err
		}
		return jsonValue{kind: jsonArray, offset: start}, nil
	}
	items := make([]jsonValue, 0)
	for {
		value, err := s.parseValue()
		if err != nil {
			return jsonValue{}, err
		}
		items = append(items, value)
		s.skipWhitespace()
		if s.peek(']') {
			if err := s.consumeToken(']'); err != nil {
				return jsonValue{}, err
			}
			break
		}
		if err := s.consumeToken(','); err != nil {
			return jsonValue{}, err
		}
	}
	return jsonValue{kind: jsonArray, offset: start, items: items}, nil
}

// parseStringToken decodes one strict RFC 8259 string without replacement runes.
func (s *jsonScanner) parseStringToken(maxDecoded int, limitName string) ([]byte, error) {
	if s.offset >= len(s.input) || s.input[s.offset] != '"' {
		return nil, s.syntaxError()
	}
	if err := s.chargeToken(); err != nil {
		return nil, err
	}
	s.offset++
	decoded := make([]byte, 0)
	for s.offset < len(s.input) {
		current := s.input[s.offset]
		if current == '"' {
			s.offset++
			if !utf8.Valid(decoded) {
				return nil, s.syntaxError()
			}
			return decoded, nil
		}
		if current < 0x20 {
			return nil, s.syntaxError()
		}
		if current != '\\' {
			var err error
			decoded, err = appendBoundedByte(decoded, current, maxDecoded, limitName, s.offset)
			if err != nil {
				return nil, err
			}
			s.offset++
			continue
		}
		var err error
		decoded, err = s.parseStringEscape(decoded, maxDecoded, limitName)
		if err != nil {
			return nil, err
		}
	}
	return nil, s.syntaxError()
}

// parseStringEscape decodes one RFC 8259 escape sequence.
func (s *jsonScanner) parseStringEscape(output []byte, limit int, limitName string) ([]byte, error) {
	s.offset++
	if s.offset >= len(s.input) {
		return nil, s.syntaxError()
	}
	escape := s.input[s.offset]
	s.offset++
	switch escape {
	case '"', '\\', '/':
		return appendBoundedByte(output, escape, limit, limitName, s.offset)
	case 'b':
		return appendBoundedByte(output, '\b', limit, limitName, s.offset)
	case 'f':
		return appendBoundedByte(output, '\f', limit, limitName, s.offset)
	case 'n':
		return appendBoundedByte(output, '\n', limit, limitName, s.offset)
	case 'r':
		return appendBoundedByte(output, '\r', limit, limitName, s.offset)
	case 't':
		return appendBoundedByte(output, '\t', limit, limitName, s.offset)
	case 'u':
		return s.parseUnicodeEscape(output, limit, limitName)
	default:
		return nil, s.syntaxError()
	}
}

// parseUnicodeEscape decodes one scalar or a required surrogate pair.
func (s *jsonScanner) parseUnicodeEscape(output []byte, limit int, limitName string) ([]byte, error) {
	first, err := s.parseHexRune()
	if err != nil {
		return nil, err
	}
	if first >= 0xdc00 && first <= 0xdfff {
		return nil, s.syntaxError()
	}
	if first < 0xd800 || first > 0xdbff {
		return appendBoundedRune(output, rune(first), limit, limitName, s.offset)
	}
	if s.offset+2 > len(s.input) || s.input[s.offset] != '\\' || s.input[s.offset+1] != 'u' {
		return nil, s.syntaxError()
	}
	s.offset += 2
	second, err := s.parseHexRune()
	if err != nil || second < 0xdc00 || second > 0xdfff {
		return nil, s.syntaxError()
	}
	return appendBoundedRune(output, utf16.DecodeRune(rune(first), rune(second)), limit, limitName, s.offset)
}

// appendBoundedByte appends one decoded byte without exceeding its selected ceiling.
func appendBoundedByte(output []byte, value byte, limit int, limitName string, offset int) ([]byte, error) {
	if len(output) >= limit {
		return nil, parserLimitError(limitName, limit, len(output)+1, offset)
	}
	return append(output, value), nil
}

// parseHexRune parses exactly four hexadecimal digits after a unicode escape.
func (s *jsonScanner) parseHexRune() (uint16, error) {
	if s.offset+4 > len(s.input) {
		return 0, s.syntaxError()
	}
	var value uint16
	for index := range 4 {
		digit, ok := hexValue(s.input[s.offset+index])
		if !ok {
			return 0, s.syntaxError()
		}
		value = value*16 + uint16(digit)
	}
	s.offset += 4
	return value, nil
}

// appendBoundedRune appends one decoded rune without exceeding its selected ceiling.
func appendBoundedRune(output []byte, value rune, limit int, limitName string, offset int) ([]byte, error) {
	width := utf8.RuneLen(value)
	if width < 0 || len(output) > limit-width {
		return nil, parserLimitError(limitName, limit, len(output)+maxInt(width, 0), offset)
	}
	return utf8.AppendRune(output, value), nil
}

// maxInt returns the larger integer.
func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

// parseNumber scans one syntactically valid JSON number lexeme.
func (s *jsonScanner) parseNumber() (jsonValue, error) {
	start := s.offset
	if err := s.chargeToken(); err != nil {
		return jsonValue{}, err
	}
	if s.peek('-') {
		s.offset++
	}
	if s.offset >= len(s.input) {
		return jsonValue{}, s.syntaxError()
	}
	if s.input[s.offset] == '0' {
		s.offset++
	} else if s.input[s.offset] >= '1' && s.input[s.offset] <= '9' {
		for s.offset < len(s.input) && isDigit(s.input[s.offset]) {
			s.offset++
		}
	} else {
		return jsonValue{}, s.syntaxError()
	}
	if s.peek('.') {
		s.offset++
		fractionStart := s.offset
		for s.offset < len(s.input) && isDigit(s.input[s.offset]) {
			s.offset++
		}
		if fractionStart == s.offset {
			return jsonValue{}, s.syntaxError()
		}
	}
	if s.peek('e') || s.peek('E') {
		s.offset++
		if s.peek('+') || s.peek('-') {
			s.offset++
		}
		exponentStart := s.offset
		for s.offset < len(s.input) && isDigit(s.input[s.offset]) {
			s.offset++
		}
		if exponentStart == s.offset {
			return jsonValue{}, s.syntaxError()
		}
	}
	return jsonValue{kind: jsonNumber, offset: start, text: append([]byte(nil), s.input[start:s.offset]...)}, nil
}

// parseLiteral parses one fixed JSON keyword.
func (s *jsonScanner) parseLiteral(literal string, kind jsonKind) (jsonValue, error) {
	start := s.offset
	if err := s.chargeToken(); err != nil {
		return jsonValue{}, err
	}
	if !bytes.HasPrefix(s.input[s.offset:], []byte(literal)) {
		return jsonValue{}, s.syntaxError()
	}
	s.offset += len(literal)
	return jsonValue{kind: kind, offset: start}, nil
}

// enterContainer enforces maximum JSON nesting before allocation.
func (s *jsonScanner) enterContainer() error {
	s.depth++
	if s.depth > s.limits.MaxJSONDepth {
		return parserLimitError(limitNameMaxJSONDepth, s.limits.MaxJSONDepth, s.depth, s.offset)
	}
	return nil
}

// leaveContainer releases one scanner nesting level.
func (s *jsonScanner) leaveContainer() { s.depth-- }

// chargeToken accounts one JSON lexical token before applying its count bound.
func (s *jsonScanner) chargeToken() error {
	if err := s.usage.chargeWork(1); err != nil {
		return err
	}
	s.tokens++
	if s.tokens > s.limits.MaxJSONTokens {
		return parserLimitError(limitNameMaxJSONTokens, s.limits.MaxJSONTokens, s.tokens, s.offset)
	}
	return nil
}

// chargeMember accounts one decoded object member before duplicate checks.
func (s *jsonScanner) chargeMember() error {
	if err := s.usage.chargeItems(1); err != nil {
		return err
	}
	s.members++
	if s.members > s.limits.MaxJSONMembers {
		return parserLimitError(limitNameMaxJSONMembers, s.limits.MaxJSONMembers, s.members, s.offset)
	}
	return nil
}

// consumeToken consumes one exact punctuation token.
func (s *jsonScanner) consumeToken(expected byte) error {
	if s.offset >= len(s.input) || s.input[s.offset] != expected {
		return s.syntaxError()
	}
	if err := s.chargeToken(); err != nil {
		return err
	}
	s.offset++
	return nil
}

// skipWhitespace consumes only RFC 8259 whitespace bytes.
func (s *jsonScanner) skipWhitespace() {
	for s.offset < len(s.input) {
		switch s.input[s.offset] {
		case ' ', '\t', '\r', '\n':
			s.offset++
		default:
			return
		}
	}
}

// peek reports whether the next byte equals expected.
func (s *jsonScanner) peek(expected byte) bool {
	return s.offset < len(s.input) && s.input[s.offset] == expected
}

// syntaxError returns a bounded JSON syntax failure.
func (s *jsonScanner) syntaxError() *Error {
	return newError(ErrorCodeInvalidJSON, ErrorLocation{Offset: s.offset}, ErrorDetails{Class: ErrorClassSyntax}, nil)
}

type recipeDecoder struct {
	limits           Limits
	usage            *usageCounter
	headerNames      int
	totalHeaderBytes int
	totalSteps       int
	copyRanges       int
	totalCopiedItems int
}

// decodeRoot validates the recipe-v1 root and constructs the immutable model.
func (d *recipeDecoder) decodeRoot(root jsonValue) (Recipe, error) {
	if root.kind != jsonObject {
		return Recipe{}, newError(ErrorCodeInvalidTopLevel, ErrorLocation{Offset: root.offset}, ErrorDetails{Class: ErrorClassSchema}, nil)
	}
	var headers []headerPlan
	hasHeaders := false
	bodyMode := BodyModeAbsent
	var bodySteps []step
	for _, member := range root.members {
		switch member.name {
		case "h":
			hasHeaders = true
			parsed, err := d.decodeHeaders(member.value)
			if err != nil {
				return Recipe{}, err
			}
			headers = parsed
		case "b":
			mode, parsed, err := d.decodeBody(member.value)
			if err != nil {
				return Recipe{}, err
			}
			bodyMode, bodySteps = mode, parsed
		}
	}
	if !hasHeaders && bodyMode == BodyModeAbsent {
		return Recipe{}, newError(ErrorCodeMissingRecipeDimension, ErrorLocation{Offset: root.offset}, ErrorDetails{Class: ErrorClassSchema}, nil)
	}
	return newRecipe(headers, hasHeaders, bodyMode, bodySteps)
}

// decodeHeaders parses the dynamic h object under case-folded uniqueness rules.
func (d *recipeDecoder) decodeHeaders(value jsonValue) ([]headerPlan, error) {
	if value.kind != jsonObject || len(value.members) == 0 {
		return nil, newError(ErrorCodeInvalidHeaderRecipe, ErrorLocation{Offset: value.offset}, ErrorDetails{Dimension: DimensionHeader}, nil)
	}
	plans := make([]headerPlan, 0, len(value.members))
	seen := make(map[string]struct{}, len(value.members))
	canonicalNames := make([]string, len(value.members))
	for ordinal, member := range value.members {
		canonicalName, ok := rawmsg.CanonicalHeaderName(member.name)
		if !ok {
			return nil, newError(ErrorCodeInvalidHeaderName, ErrorLocation{Offset: member.offset, HeaderOrdinal: ordinal}, ErrorDetails{Dimension: DimensionHeader}, nil)
		}
		if _, exists := seen[canonicalName]; exists {
			return nil, newError(ErrorCodeHeaderNameCollision, ErrorLocation{Offset: member.offset, HeaderOrdinal: ordinal}, ErrorDetails{Dimension: DimensionHeader}, nil)
		}
		seen[canonicalName] = struct{}{}
		canonicalNames[ordinal] = canonicalName
	}
	for ordinal, member := range value.members {
		canonicalName := canonicalNames[ordinal]
		if member.name != canonicalName {
			return nil, newError(ErrorCodeNonLowercaseHeaderName, ErrorLocation{Offset: member.offset, HeaderOrdinal: ordinal}, ErrorDetails{Dimension: DimensionHeader}, nil)
		}
		d.headerNames++
		if d.headerNames > d.limits.MaxHeaderNames {
			return nil, parserLimitError(limitNameMaxHeaderNames, d.limits.MaxHeaderNames, d.headerNames, member.offset)
		}
		if len(member.name) > d.limits.MaxHeaderNameBytes {
			return nil, parserLimitError(limitNameMaxHeaderNameBytes, d.limits.MaxHeaderNameBytes, len(member.name), member.offset)
		}
		totalNameBytes, totalOK := checkedAdd(d.totalHeaderBytes, len(member.name))
		if !totalOK || totalNameBytes > d.limits.MaxTotalHeaderNameBytes {
			return nil, parserLimitError(limitNameMaxTotalHeaderNameBytes, d.limits.MaxTotalHeaderNameBytes, totalNameBytes, member.offset)
		}
		d.totalHeaderBytes = totalNameBytes
		steps, err := d.decodeSteps(member.value, DimensionHeader, member.name, d.limits.MaxStepsPerHeader, limitNameMaxStepsPerHeader)
		if err != nil {
			return nil, err
		}
		plan, err := newHeaderPlan(member.name, canonicalName, steps)
		if err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}
	if err := d.sortHeaderPlans(plans); err != nil {
		return nil, err
	}
	return plans, nil
}

// sortHeaderPlans orders deterministic metadata while charging every comparison.
func (d *recipeDecoder) sortHeaderPlans(plans []headerPlan) error {
	for index := 1; index < len(plans); index++ {
		for position := index; position > 0; position-- {
			if err := d.usage.chargeWork(1); err != nil {
				return err
			}
			if plans[position-1].canonicalName <= plans[position].canonicalName {
				break
			}
			plans[position-1], plans[position] = plans[position], plans[position-1]
		}
	}
	return nil
}

// decodeBody parses absent-independent body steps or the unavailable marker.
func (d *recipeDecoder) decodeBody(value jsonValue) (BodyMode, []step, error) {
	if value.kind == jsonNull {
		return BodyModeUnavailable, nil, nil
	}
	steps, err := d.decodeSteps(value, DimensionBody, "", d.limits.MaxBodySteps, limitNameMaxBodySteps)
	if err != nil {
		return "", nil, err
	}
	return BodyModeSteps, steps, nil
}

// decodeSteps parses one ordered array of exact c or d objects.
func (d *recipeDecoder) decodeSteps(value jsonValue, dimension Dimension, headerName string, maximum int, limitName string) ([]step, error) {
	if value.kind != jsonArray {
		code := ErrorCodeInvalidHeaderRecipe
		if dimension == DimensionBody {
			code = ErrorCodeInvalidBodyRecipe
		}
		return nil, newError(code, ErrorLocation{Offset: value.offset}, ErrorDetails{Dimension: dimension}, nil)
	}
	if len(value.items) > maximum {
		for range value.items {
			if err := d.usage.chargeItems(1); err != nil {
				return nil, err
			}
		}
		return nil, parserLimitError(limitName, maximum, len(value.items), value.offset)
	}
	steps := make([]step, 0, len(value.items))
	previousEnd := 0
	for index, item := range value.items {
		d.totalSteps++
		if err := d.usage.chargeItems(1); err != nil {
			return nil, err
		}
		if d.totalSteps > d.limits.MaxTotalSteps {
			return nil, parserLimitError(limitNameMaxTotalSteps, d.limits.MaxTotalSteps, d.totalSteps, item.offset)
		}
		if item.kind != jsonObject || len(item.members) != 1 {
			return nil, newError(ErrorCodeInvalidStep, ErrorLocation{Offset: item.offset, StepIndex: index}, ErrorDetails{Dimension: dimension}, nil)
		}
		member := item.members[0]
		var parsed step
		var err error
		switch member.name {
		case "c":
			parsed, err = d.decodeCopy(member.value, dimension, index, previousEnd)
			if err == nil {
				_, previousEnd, _ = parsed.copyRange()
			}
		case "d":
			parsed, err = d.decodeData(member.value, dimension, headerName, index)
		default:
			err = newError(ErrorCodeInvalidStep, ErrorLocation{Offset: member.offset, StepIndex: index}, ErrorDetails{Dimension: dimension}, nil)
		}
		if err != nil {
			return nil, err
		}
		steps = append(steps, parsed)
	}
	return steps, nil
}

// decodeCopy validates exact mathematical integer endpoints and range budgets.
func (d *recipeDecoder) decodeCopy(value jsonValue, dimension Dimension, stepIndex, previousEnd int) (step, error) {
	if value.kind != jsonArray || len(value.items) != 2 || value.items[0].kind != jsonNumber || value.items[1].kind != jsonNumber {
		return step{}, newError(ErrorCodeInvalidCopyRange, ErrorLocation{Offset: value.offset, StepIndex: stepIndex}, ErrorDetails{Dimension: dimension, StepKind: StepKindCopy}, nil)
	}
	start, ok := exactPositiveInt(string(value.items[0].text))
	if !ok {
		return step{}, newError(ErrorCodeInvalidCopyRange, ErrorLocation{Offset: value.items[0].offset, StepIndex: stepIndex}, ErrorDetails{Dimension: dimension, StepKind: StepKindCopy}, nil)
	}
	end, ok := exactPositiveInt(string(value.items[1].text))
	if !ok || end < start {
		return step{}, newError(ErrorCodeInvalidCopyRange, ErrorLocation{Offset: value.items[1].offset, StepIndex: stepIndex}, ErrorDetails{Dimension: dimension, StepKind: StepKindCopy}, nil)
	}
	if previousEnd != 0 && start <= previousEnd {
		return step{}, newError(ErrorCodeCopyRangeOrder, ErrorLocation{Offset: value.offset, StepIndex: stepIndex}, ErrorDetails{Dimension: dimension, StepKind: StepKindCopy}, nil)
	}
	d.copyRanges++
	if err := d.usage.chargeItems(1); err != nil {
		return step{}, err
	}
	if d.copyRanges > d.limits.MaxCopyRanges {
		return step{}, parserLimitError(limitNameMaxCopyRanges, d.limits.MaxCopyRanges, d.copyRanges, value.offset)
	}
	width := end - start + 1
	if width > d.limits.MaxCopiedItemsPerRange {
		return step{}, parserLimitError(limitNameMaxCopiedItemsPerRange, d.limits.MaxCopiedItemsPerRange, width, value.offset)
	}
	total, valid := checkedAdd(d.totalCopiedItems, width)
	if !valid || total > d.limits.MaxTotalCopiedItems {
		return step{}, parserLimitError(limitNameMaxTotalCopiedItems, d.limits.MaxTotalCopiedItems, total, value.offset)
	}
	d.totalCopiedItems = total
	return newCopyStep(start, end)
}

// decodeData validates nonempty immutable UTF-8 literal arrays and dimension limits.
func (d *recipeDecoder) decodeData(value jsonValue, dimension Dimension, headerName string, stepIndex int) (step, error) {
	if value.kind != jsonArray || len(value.items) == 0 {
		return step{}, newError(ErrorCodeInvalidLiteral, ErrorLocation{Offset: value.offset, StepIndex: stepIndex}, ErrorDetails{Dimension: dimension, StepKind: StepKindData}, nil)
	}
	literals := make([][]byte, 0, len(value.items))
	for _, item := range value.items {
		if item.kind != jsonString || !validDataLiteral(item.text) {
			return step{}, newError(ErrorCodeInvalidLiteral, ErrorLocation{Offset: item.offset, StepIndex: stepIndex}, ErrorDetails{Dimension: dimension, StepKind: StepKindData}, nil)
		}
		if dimension == DimensionHeader && len(headerName)+1+len(item.text) > d.limits.MaxHeaderLineBytes {
			return step{}, parserLimitError(limitNameMaxHeaderLineBytes, d.limits.MaxHeaderLineBytes, len(headerName)+1+len(item.text), item.offset)
		}
		if dimension == DimensionHeader && len(headerName)+1+len(item.text)+2 > d.limits.MaxHeaderFieldBytes {
			return step{}, parserLimitError(limitNameMaxHeaderFieldBytes, d.limits.MaxHeaderFieldBytes, len(headerName)+1+len(item.text)+2, item.offset)
		}
		if dimension == DimensionBody && len(item.text) > d.limits.MaxBodyLineBytes {
			return step{}, parserLimitError(limitNameMaxBodyLineBytes, d.limits.MaxBodyLineBytes, len(item.text), item.offset)
		}
		literals = append(literals, append([]byte(nil), item.text...))
	}
	return newDataStep(literals)
}

// exactPositiveInt converts an exact integral JSON number without float64 rounding.
func exactPositiveInt(lexeme string) (int, bool) {
	if lexeme == "" || lexeme[0] == '-' {
		return 0, false
	}
	mantissa := lexeme
	exponent := 0
	if index := strings.IndexAny(mantissa, "eE"); index >= 0 {
		exponentText := mantissa[index+1:]
		mantissa = mantissa[:index]
		exponentSign := 1
		exponentText = strings.TrimPrefix(exponentText, "+")
		if strings.HasPrefix(exponentText, "-") {
			exponentSign = -1
			exponentText = exponentText[1:]
		}
		exponentText = strings.TrimLeft(exponentText, "0")
		if exponentText == "" {
			exponent = 0
		} else if len(exponentText) > 6 {
			return 0, false
		} else {
			parsed, err := strconv.Atoi(exponentText)
			if err != nil {
				return 0, false
			}
			exponent = exponentSign * parsed
		}
	}
	fractionDigits := 0
	if index := strings.IndexByte(mantissa, '.'); index >= 0 {
		fractionDigits = len(mantissa) - index - 1
		mantissa = mantissa[:index] + mantissa[index+1:]
	}
	digits := strings.TrimLeft(mantissa, "0")
	if digits == "" {
		return 0, false
	}
	power := exponent - fractionDigits
	if power < 0 {
		remove := -power
		if remove >= len(digits) {
			return 0, false
		}
		for _, char := range digits[len(digits)-remove:] {
			if char != '0' {
				return 0, false
			}
		}
		digits = digits[:len(digits)-remove]
	} else {
		if power > 32 || len(digits)+power > 20 {
			return 0, false
		}
		digits += strings.Repeat("0", power)
	}
	value, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || value == 0 || value > uint64(^uint(0)>>1) {
		return 0, false
	}
	return int(value), true
}

// parserLimitError constructs one stable bounded parser resource failure.
func parserLimitError(name string, limit, actual, offset int) *Error {
	return newError(ErrorCodeLimitExceeded, ErrorLocation{Offset: offset}, ErrorDetails{Class: ErrorClassLimit, LimitName: name, Expected: limit, Actual: actual}, nil)
}

// isDigit reports whether one byte is an ASCII decimal digit.
func isDigit(value byte) bool { return value >= '0' && value <= '9' }

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
