package dsn

import (
	"bytes"
	"strings"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// Parse parses one RFC 3462 multipart/report delivery-status envelope with restrictive defaults.
func Parse(data []byte) (Report, error) {
	return ParseWithOptions(data, DefaultOptions())
}

// ParseWithOptions parses only the bounded DSN report structure and does not verify DSN or DKIM2 semantics.
func ParseWithOptions(data []byte, options Options) (Report, error) {
	if err := validateOptions(options); err != nil {
		return Report{}, err
	}
	if len(data) > options.MaxMessageBytes {
		return Report{}, newError(ErrorCodeLimitExceeded, 0, LimitNameMaxMessageBytes, options.MaxMessageBytes, len(data))
	}

	rawOptions := rawmsg.DefaultParserOptions()
	rawOptions.MaxMessageBytes = options.MaxMessageBytes
	message, err := rawmsg.ParseWithOptions(data, rawOptions)
	if err != nil {
		return Report{}, newError(ErrorCodeInvalidMessage, 0, "", 0, 0)
	}
	contentType, err := requiredContentType(message.Headers(), 0)
	if err != nil {
		return Report{}, err
	}
	if contentType.mediaType != "multipart/report" {
		return Report{}, newError(ErrorCodeInvalidContentType, 0, "", 0, 0)
	}
	reportType, present := contentType.parameter("report-type")
	if !present || !equalFoldASCII(reportType, "delivery-status") {
		return Report{}, newError(ErrorCodeInvalidReportType, 0, "", 0, 0)
	}
	boundary, present := contentType.parameter("boundary")
	if !present || !validBoundary(boundary, options.MaxBoundaryBytes) {
		return Report{}, newError(ErrorCodeInvalidBoundary, 0, LimitNameMaxBoundaryBytes, options.MaxBoundaryBytes, len(boundary))
	}

	partBytes, err := splitMultipart(message.Body().Bytes(), []byte(boundary))
	if err != nil {
		return Report{}, err
	}
	if len(partBytes) != 3 {
		return Report{}, newError(ErrorCodeInvalidPartCount, 0, "", 0, 0)
	}

	parts := make([]Part, len(partBytes))
	for index, encodedPart := range partBytes {
		partIndex := index + 1
		if len(encodedPart) > options.MaxPartBytes {
			return Report{}, newError(ErrorCodeLimitExceeded, partIndex, LimitNameMaxPartBytes, options.MaxPartBytes, len(encodedPart))
		}
		partOptions := rawmsg.DefaultParserOptions()
		partOptions.MaxMessageBytes = options.MaxPartBytes
		partMessage, parseErr := rawmsg.ParseWithOptions(encodedPart, partOptions)
		if parseErr != nil {
			return Report{}, newError(ErrorCodeInvalidPart, partIndex, "", 0, 0)
		}
		partContentType, contentTypeErr := requiredContentType(partMessage.Headers(), partIndex)
		if contentTypeErr != nil {
			return Report{}, contentTypeErr
		}
		parts[index] = Part{message: partMessage, contentType: ContentType(partContentType.mediaType)}
	}
	if parts[1].contentType != ContentTypeDeliveryStatus {
		return Report{}, newError(ErrorCodeInvalidPartContentType, 2, "", 0, 0)
	}
	if parts[2].contentType != ContentTypeRFC822 && parts[2].contentType != ContentTypeRFC822Headers {
		return Report{}, newError(ErrorCodeInvalidPartContentType, 3, "", 0, 0)
	}

	return Report{message: message, humanReadable: parts[0], deliveryStatus: parts[1], original: parts[2]}, nil
}

// validateOptions rejects values that could weaken the fixed parser ceilings.
func validateOptions(options Options) error {
	if options.MaxMessageBytes <= 0 || options.MaxMessageBytes > defaultMaxMessageBytes {
		return newError(ErrorCodeInvalidOptions, 0, LimitNameMaxMessageBytes, defaultMaxMessageBytes, options.MaxMessageBytes)
	}
	if options.MaxPartBytes <= 0 || options.MaxPartBytes > options.MaxMessageBytes {
		return newError(ErrorCodeInvalidOptions, 0, LimitNameMaxPartBytes, options.MaxMessageBytes, options.MaxPartBytes)
	}
	if options.MaxBoundaryBytes <= 0 || options.MaxBoundaryBytes > hardMaxBoundaryBytes {
		return newError(ErrorCodeInvalidOptions, 0, LimitNameMaxBoundaryBytes, hardMaxBoundaryBytes, options.MaxBoundaryBytes)
	}
	return nil
}

// requiredContentType returns exactly one syntactically valid MIME Content-Type field.
func requiredContentType(headers rawmsg.HeaderBlock, partIndex int) (parsedContentType, error) {
	fields := headers.FieldsByName("content-type")
	if len(fields) == 0 {
		return parsedContentType{}, newError(ErrorCodeMissingContentType, partIndex, "", 0, 0)
	}
	if len(fields) != 1 {
		return parsedContentType{}, newError(ErrorCodeInvalidContentType, partIndex, "", 0, 0)
	}
	contentType, err := parseContentType(fields[0].UnfoldedValue())
	if err != nil {
		return parsedContentType{}, newError(ErrorCodeInvalidContentType, partIndex, "", 0, 0)
	}
	return contentType, nil
}

// splitMultipart extracts exactly three semantic MIME parts while ignoring RFC 2046 preambles and epilogues.
func splitMultipart(body []byte, boundary []byte) ([][]byte, error) {
	_, firstEnd, closing, ok := firstDelimiter(body, boundary)
	if !ok {
		return nil, newError(ErrorCodeMalformedMultipart, 0, "", 0, 0)
	}
	if closing {
		return nil, newError(ErrorCodeInvalidPartCount, 0, "", 0, 0)
	}
	partStart := firstEnd
	parts := make([][]byte, 0, 3)
	for {
		boundaryStart, delimiterEnd, nextClosing, found := nextDelimiter(body, partStart, boundary)
		if !found {
			return nil, newError(ErrorCodeMalformedMultipart, 0, "", 0, 0)
		}
		parts = append(parts, bytes.Clone(body[partStart:boundaryStart]))
		if len(parts) > 3 {
			return nil, newError(ErrorCodeInvalidPartCount, 0, "", 0, 0)
		}
		if nextClosing {
			return parts, nil
		}
		partStart = delimiterEnd
	}
}

// firstDelimiter finds the opening boundary after an optional RFC 2046 preamble.
func firstDelimiter(body []byte, boundary []byte) (int, int, bool, bool) {
	if delimiterEnd, closing, ok := delimiterAt(body, 0, boundary); ok {
		return 0, delimiterEnd, closing, true
	}
	for offset := 0; offset+2+len(boundary) <= len(body); {
		relative := bytes.Index(body[offset:], []byte("\r\n--"))
		if relative < 0 {
			return 0, 0, false, false
		}
		lineStart := offset + relative + 2
		lineEnd, closing, ok := delimiterAt(body, lineStart, boundary)
		if ok {
			return lineStart - 2, lineEnd, closing, true
		}
		offset = lineStart + 1
	}
	return 0, 0, false, false
}

// nextDelimiter finds the next full boundary line after one MIME part.
func nextDelimiter(body []byte, start int, boundary []byte) (int, int, bool, bool) {
	for offset := start; offset+2+len(boundary) <= len(body); {
		relative := bytes.Index(body[offset:], []byte("\r\n--"))
		if relative < 0 {
			return 0, 0, false, false
		}
		lineStart := offset + relative + 2
		lineEnd, closing, ok := delimiterAt(body, lineStart, boundary)
		if ok {
			return lineStart - 2, lineEnd, closing, true
		}
		offset = lineStart + 1
	}
	return 0, 0, false, false
}

// delimiterAt recognizes one complete MIME boundary line at the supplied offset.
func delimiterAt(body []byte, offset int, boundary []byte) (int, bool, bool) {
	prefix := append([]byte("--"), boundary...)
	if offset < 0 || !bytes.HasPrefix(body[offset:], prefix) {
		return 0, false, false
	}
	position := offset + len(prefix)
	closing := false
	if bytes.HasPrefix(body[position:], []byte("--")) {
		closing = true
		position += 2
	}
	for position < len(body) && (body[position] == ' ' || body[position] == '\t') {
		position++
	}
	if position+2 > len(body) || !bytes.Equal(body[position:position+2], []byte("\r\n")) {
		return 0, false, false
	}
	return position + 2, closing, true
}

// parsedContentType retains only the normalized MIME media type and bounded parameters required for structure checks.
type parsedContentType struct {
	mediaType  string
	parameters map[string]string
}

// parameter returns one parsed parameter by lowercase ASCII name.
func (c parsedContentType) parameter(name string) (string, bool) {
	value, ok := c.parameters[name]
	return value, ok
}

// parseContentType parses one unfolded Content-Type value without generic MIME reserialization.
func parseContentType(value []byte) (parsedContentType, error) {
	parser := contentTypeParser{input: value}
	parser.skipWhitespace()
	typeToken, ok := parser.token()
	if !ok || !parser.consume('/') {
		return parsedContentType{}, errInvalidContentType
	}
	subtypeToken, ok := parser.token()
	if !ok {
		return parsedContentType{}, errInvalidContentType
	}
	contentType := parsedContentType{mediaType: lowerASCII(typeToken) + "/" + lowerASCII(subtypeToken), parameters: make(map[string]string)}
	for {
		parser.skipWhitespace()
		if parser.done() {
			return contentType, nil
		}
		if !parser.consume(';') {
			return parsedContentType{}, errInvalidContentType
		}
		parser.skipWhitespace()
		name, ok := parser.token()
		if !ok {
			return parsedContentType{}, errInvalidContentType
		}
		parser.skipWhitespace()
		if !parser.consume('=') {
			return parsedContentType{}, errInvalidContentType
		}
		parser.skipWhitespace()
		parameterValue, ok := parser.value()
		if !ok {
			return parsedContentType{}, errInvalidContentType
		}
		name = lowerASCII(name)
		if _, exists := contentType.parameters[name]; exists {
			return parsedContentType{}, errInvalidContentType
		}
		contentType.parameters[name] = parameterValue
	}
}

// contentTypeParser parses the small MIME grammar needed for DSN structural validation.
type contentTypeParser struct {
	input  []byte
	offset int
}

// done reports whether every input byte has been consumed.
func (p *contentTypeParser) done() bool {
	return p.offset == len(p.input)
}

// skipWhitespace consumes linear whitespace only after rawmsg has unfolded header folding.
func (p *contentTypeParser) skipWhitespace() {
	for p.offset < len(p.input) && (p.input[p.offset] == ' ' || p.input[p.offset] == '\t') {
		p.offset++
	}
}

// consume consumes one required ASCII punctuation byte.
func (p *contentTypeParser) consume(want byte) bool {
	if p.offset >= len(p.input) || p.input[p.offset] != want {
		return false
	}
	p.offset++
	return true
}

// token consumes an RFC 2045 token without accepting control or non-ASCII bytes.
func (p *contentTypeParser) token() (string, bool) {
	start := p.offset
	for p.offset < len(p.input) && isTokenByte(p.input[p.offset]) {
		p.offset++
	}
	return string(p.input[start:p.offset]), p.offset > start
}

// value consumes a token or a quoted MIME parameter value with quoted-pair handling.
func (p *contentTypeParser) value() (string, bool) {
	if p.offset >= len(p.input) {
		return "", false
	}
	if p.input[p.offset] != '"' {
		return p.token()
	}
	p.offset++
	output := make([]byte, 0, 16)
	for p.offset < len(p.input) {
		current := p.input[p.offset]
		p.offset++
		if current == '"' {
			return string(output), true
		}
		if current == '\\' {
			if p.offset >= len(p.input) || p.input[p.offset] < 32 || p.input[p.offset] > 126 {
				return "", false
			}
			output = append(output, p.input[p.offset])
			p.offset++
			continue
		}
		if current < 32 || current > 126 {
			return "", false
		}
		output = append(output, current)
	}
	return "", false
}

// validBoundary enforces RFC 2046's bounded ASCII delimiter vocabulary before scanning message content.
func validBoundary(boundary string, maximum int) bool {
	if len(boundary) == 0 || len(boundary) > maximum || boundary[len(boundary)-1] == ' ' {
		return false
	}
	for index := 0; index < len(boundary); index++ {
		if !isBoundaryByte(boundary[index]) {
			return false
		}
	}
	return true
}

// isBoundaryByte reports whether one byte belongs to the RFC 2046 boundary grammar.
func isBoundaryByte(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9' ||
		strings.ContainsRune("'()+_,-./:=? ", rune(value))
}

// isTokenByte reports whether one byte belongs to the RFC 2045 token grammar.
func isTokenByte(value byte) bool {
	if value <= 32 || value >= 127 {
		return false
	}
	return !strings.ContainsRune("()<>@,;:\\\"/[]?=", rune(value))
}

// lowerASCII normalizes MIME type and parameter names without Unicode interpretation.
func lowerASCII(value string) string {
	output := []byte(value)
	for index := range output {
		if output[index] >= 'A' && output[index] <= 'Z' {
			output[index] += 'a' - 'A'
		}
	}
	return string(output)
}

// equalFoldASCII compares MIME tokens without Unicode case conversion.
func equalFoldASCII(left string, right string) bool {
	return lowerASCII(left) == lowerASCII(right)
}

var errInvalidContentType = &Error{code: ErrorCodeInvalidContentType}
