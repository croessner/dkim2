package tagvalue

import (
	"bytes"
	"slices"
)

// KnownTags records validated tag names for exact case-sensitive lookup.
type KnownTags struct {
	exact map[string]struct{}
}

// NewKnownTags validates known tag names for exact scanner lookup.
func NewKnownTags(names ...string) (KnownTags, error) {
	known := KnownTags{}
	if len(names) == 0 {
		return known, nil
	}

	known.exact = make(map[string]struct{}, len(names))
	for _, name := range names {
		exact, ok := tagName([]byte(name), DefaultLimits().MaxTagNameBytes)
		if !ok {
			return KnownTags{}, NewError(ErrorCodeInvalidOptions, ErrorLocation{}, ErrorDetails{
				Class: ErrorClassInvariant,
			})
		}
		if _, duplicate := known.exact[exact]; duplicate {
			return KnownTags{}, NewError(ErrorCodeInvalidOptions, ErrorLocation{}, ErrorDetails{
				Class: ErrorClassInvariant,
			})
		}
		known.exact[exact] = struct{}{}
	}

	return known, nil
}

// MustKnownTags validates known tag names and panics on programmer error.
func MustKnownTags(names ...string) KnownTags {
	known, err := NewKnownTags(names...)
	if err != nil {
		panic(err)
	}

	return known
}

// Contains reports whether name is an exact case-sensitive known tag.
func (k KnownTags) Contains(name string) bool {
	if len(k.exact) == 0 {
		return false
	}
	_, exists := k.exact[name]

	return exists
}

// Tag stores one immutable DKIM2 tag specification.
type Tag struct {
	name  string
	value string
	known bool
}

// Name returns the exact validated tag name.
func (t Tag) Name() string {
	return t.name
}

// RawName returns the validated tag identifier with its original ASCII
// spelling, which equals Name because neither scanner mode folds names.
func (t Tag) RawName() string {
	return t.name
}

// Value returns the case-sensitive parser-owned tag value.
func (t Tag) Value() string {
	return t.value
}

// Known reports whether the tag name was present in the scanner allowlist.
func (t Tag) Known() bool {
	return t.known
}

// Field stores an immutable DKIM2 tag-list scan result.
type Field struct {
	tags  []Tag
	index map[string]int
}

// Len returns the number of scanned tag specifications.
func (f Field) Len() int {
	return len(f.tags)
}

// Tags returns the scanned tags in field order.
func (f Field) Tags() []Tag {
	return slices.Clone(f.tags)
}

// Has reports whether a tag name is present under the field's matching mode.
func (f Field) Has(name string) bool {
	_, ok := f.Get(name)

	return ok
}

// Get returns the tag with exactly the requested name.
func (f Field) Get(name string) (Tag, bool) {
	index, exists := f.index[name]
	if !exists {
		return Tag{}, false
	}

	return f.tags[index], true
}

// UnknownTags returns syntactically valid extension tags in field order.
func (f Field) UnknownTags() []Tag {
	var unknown []Tag
	for _, tag := range f.tags {
		if !tag.known {
			unknown = append(unknown, tag)
		}
	}

	return unknown
}

// scanMode selects the field-family rules applied by the shared tag-list scanner.
type scanMode uint8

const (
	// scanModeDNS applies DNS record rules: FWS unfolding and case-sensitive names.
	scanModeDNS scanMode = iota
	// scanModeHeader applies DKIM2 header rules: already-unfolded input and lowercase names.
	scanModeHeader
)

// Scan parses a DNS key-record tag list with case-sensitive names and FWS unfolding.
func Scan(input []byte, known KnownTags, limits Limits) (Field, error) {
	return scan(input, known, limits, scanModeDNS)
}

// ScanHeader parses an unfolded Message-Instance or DKIM2-Signature tag list.
// Draft-08 Section 8 makes the final semicolon optional, and Sections 9 and 10
// require every tag name, including unknown extension names, to be lowercase;
// an uppercase name is a syntax error rather than an ignored tag.
func ScanHeader(input []byte, known KnownTags, limits Limits) (Field, error) {
	return scan(input, known, limits, scanModeHeader)
}

// scan parses one Draft-08 Section 8 tag-list under the selected field-family mode.
func scan(input []byte, known KnownTags, limits Limits, mode scanMode) (Field, error) {
	limits = limits.normalize()
	if err := limits.Validate(); err != nil {
		return Field{}, err
	}
	if len(input) > limits.MaxFieldValueBytes {
		return Field{}, limitExceededError("max_field_value_bytes", limits.MaxFieldValueBytes, len(input), ErrorLocation{})
	}
	if mode == scanModeHeader {
		if offset := invalidUnfoldedLineBreak(input); offset >= 0 {
			return Field{}, NewError(ErrorCodeInvalidTagValue, ErrorLocation{Offset: offset}, ErrorDetails{})
		}
	} else {
		var err error
		input, err = unfoldDNSFWS(input)
		if err != nil {
			return Field{}, err
		}
	}

	segments := splitTagSpecs(input)
	tags := make([]Tag, 0, len(segments))
	index := make(map[string]int, len(segments))
	tagIndex := 0
	for i, segment := range segments {
		if isFinalTrailingSemicolon(segments, i, segment) {
			continue
		}

		trimmed, leading := trimWSP(segment.bytes)
		if len(trimmed) == 0 {
			return Field{}, NewError(ErrorCodeEmptyTagSpec, ErrorLocation{Offset: segment.offset + leading, TagIndex: tagIndex}, ErrorDetails{})
		}
		if tagIndex >= limits.MaxTags {
			return Field{}, limitExceededError("max_tags", limits.MaxTags, tagIndex+1, ErrorLocation{Offset: segment.offset, TagIndex: tagIndex})
		}

		tag, err := parseTagSpec(trimmed, segment.offset+leading, tagIndex, known, limits, mode)
		if err != nil {
			return Field{}, err
		}
		if _, exists := index[tag.name]; exists {
			return Field{}, duplicateTagError(tag, segment.offset+leading, tagIndex)
		}

		index[tag.name] = len(tags)
		tags = append(tags, tag)
		tagIndex++
	}
	if len(tags) == 0 {
		return Field{}, NewError(ErrorCodeEmptyTagSpec, ErrorLocation{}, ErrorDetails{})
	}

	return Field{
		tags:  tags,
		index: index,
	}, nil
}

// tagSegment records one semicolon-delimited byte segment and source offset.
type tagSegment struct {
	bytes  []byte
	offset int
}

// splitTagSpecs splits input at DKIM2 semicolon tag separators.
func splitTagSpecs(input []byte) []tagSegment {
	var segments []tagSegment
	start := 0
	for i, b := range input {
		if b != ';' {
			continue
		}
		segments = append(segments, tagSegment{bytes: input[start:i], offset: start})
		start = i + 1
	}

	return append(segments, tagSegment{bytes: input[start:], offset: start})
}

// parseTagSpec parses one non-empty DKIM2 tag specification.
func parseTagSpec(input []byte, offset int, tagIndex int, known KnownTags, limits Limits, mode scanMode) (Tag, error) {
	equals := bytes.IndexByte(input, '=')
	if equals < 0 {
		return Tag{}, NewError(ErrorCodeMissingEquals, ErrorLocation{Offset: offset, TagIndex: tagIndex}, ErrorDetails{})
	}

	rawName, nameLeading := trimWSP(input[:equals])
	rawValue, valueLeading := trimWSP(input[equals+1:])
	if len(rawName) > limits.MaxTagNameBytes {
		return Tag{}, limitExceededError("max_tag_name_bytes", limits.MaxTagNameBytes, len(rawName), ErrorLocation{Offset: offset + nameLeading, TagIndex: tagIndex})
	}
	if len(rawValue) > limits.MaxTagValueBytes {
		return Tag{}, limitExceededError("max_tag_value_bytes", limits.MaxTagValueBytes, len(rawValue), ErrorLocation{Offset: offset + equals + 1 + valueLeading, TagIndex: tagIndex})
	}

	name, ok := tagName(rawName, limits.MaxTagNameBytes)
	if !ok || mode == scanModeHeader && containsASCIIUpper(rawName) {
		return Tag{}, NewError(ErrorCodeInvalidTagName, ErrorLocation{Offset: offset + nameLeading, TagIndex: tagIndex}, ErrorDetails{})
	}
	knownTag := known.Contains(name)
	if (mode == scanModeDNS || !knownTag) && !validTagValue(rawValue) {
		return Tag{}, NewError(ErrorCodeInvalidTagValue, ErrorLocation{Offset: offset + equals + 1 + valueLeading, TagIndex: tagIndex}, ErrorDetails{})
	}

	return Tag{
		name:  name,
		value: string(rawValue),
		known: knownTag,
	}, nil
}

// duplicateTagError reports a duplicate tag without leaking extension names.
func duplicateTagError(tag Tag, offset int, tagIndex int) *Error {
	details := ErrorDetails{
		Class: ErrorClassDuplicate,
	}
	if tag.known {
		details.tagName = tag.name
	}

	return NewError(ErrorCodeDuplicateTag, ErrorLocation{Offset: offset, TagIndex: tagIndex}, details)
}

// isFinalTrailingSemicolon reports whether segment follows the optional final semicolon.
func isFinalTrailingSemicolon(segments []tagSegment, index int, segment tagSegment) bool {
	if index != len(segments)-1 {
		return false
	}

	trimmed, _ := trimWSP(segment.bytes)

	return len(trimmed) == 0 && len(segments) > 1
}

// unfoldDNSFWS removes CRLF only when followed by required DNS-02 white space.
func unfoldDNSFWS(input []byte) ([]byte, error) {
	unfolded := make([]byte, 0, len(input))
	for index := 0; index < len(input); index++ {
		switch input[index] {
		case '\r':
			if index+2 >= len(input) || input[index+1] != '\n' || !isWSP(input[index+2]) {
				return nil, NewError(ErrorCodeInvalidTagValue, ErrorLocation{Offset: index}, ErrorDetails{})
			}
			index++
		case '\n':
			return nil, NewError(ErrorCodeInvalidTagValue, ErrorLocation{Offset: index}, ErrorDetails{})
		default:
			unfolded = append(unfolded, input[index])
		}
	}

	return unfolded, nil
}

// invalidUnfoldedLineBreak returns the first CR or LF in header-mode input.
func invalidUnfoldedLineBreak(input []byte) int {
	for index, b := range input {
		if b == '\r' || b == '\n' {
			return index
		}
	}

	return -1
}

// tagName validates the Draft-08 Section 8 tag-name grammar without folding case.
func tagName(input []byte, maxNameBytes int) (string, bool) {
	if len(input) == 0 || len(input) > maxNameBytes || !isASCIILetter(input[0]) {
		return "", false
	}
	for _, b := range input {
		if !isASCIILetter(b) && !isASCIIDigit(b) && b != '_' {
			return "", false
		}
	}

	return string(input), true
}

// containsASCIIUpper reports whether input contains an ASCII uppercase letter.
func containsASCIIUpper(input []byte) bool {
	for _, b := range input {
		if b >= 'A' && b <= 'Z' {
			return true
		}
	}

	return false
}

// validTagValue enforces printable non-semicolon bytes for DNS tags and header extensions.
func validTagValue(input []byte) bool {
	for _, b := range input {
		if b == '\t' || b == ' ' || b >= '!' && b <= ':' || b >= '<' && b <= '~' {
			continue
		}

		return false
	}

	return true
}

// trimWSP removes DKIM2-permitted surrounding space and tab bytes.
func trimWSP(input []byte) ([]byte, int) {
	start := 0
	for start < len(input) && isWSP(input[start]) {
		start++
	}

	end := len(input)
	for end > start && isWSP(input[end-1]) {
		end--
	}

	return input[start:end], start
}

// isWSP reports whether b is RFC 5322 white space allowed around tags.
func isWSP(b byte) bool {
	return b == ' ' || b == '\t'
}

// isASCIILetter reports whether b is an ASCII alpha byte.
func isASCIILetter(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// isASCIIDigit reports whether b is an ASCII digit byte.
func isASCIIDigit(b byte) bool {
	return b >= '0' && b <= '9'
}
