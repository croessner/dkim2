package rawmsg

import "bytes"

var crlf = []byte("\r\n")
var strictHeaderBodyDelimiter = []byte("\r\n\r\n")

const limitNameMaxHeaderLineBytes = "max_header_line_bytes"

// Parse parses raw RFC 5322 bytes with restrictive default parser options.
func Parse(data []byte) (Message, error) {
	return ParseWithOptions(data, DefaultParserOptions())
}

// ParseWithOptions parses raw RFC 5322 bytes with explicit parser options.
func ParseWithOptions(data []byte, options ParserOptions) (Message, error) {
	if err := options.Validate(); err != nil {
		return Message{}, err
	}
	if options.LineEndingPolicy != LineEndingPolicyStrictCRLF {
		return Message{}, unsupportedPolicyError(string(options.LineEndingPolicy))
	}
	if len(data) > options.MaxMessageBytes {
		return Message{}, NewParserError(ErrorCodeLimitExceeded, ErrorLocation{}, ParserErrorDetails{
			Reason:    ErrorReasonLimit,
			LimitName: "max_message_bytes",
			Limit:     options.MaxMessageBytes,
		})
	}
	if err := enforceStrictCRLF(data, options); err != nil {
		return Message{}, err
	}

	delimiterOffset := bytes.Index(data, strictHeaderBodyDelimiter)
	var headerBytes []byte
	var bodyBytes []byte
	if delimiterOffset >= 0 {
		headerBytes = data[:delimiterOffset+len(crlf)]
		bodyBytes = data[delimiterOffset+len(strictHeaderBodyDelimiter):]
	} else {
		if !bytes.HasSuffix(data, crlf) {
			return Message{}, NewParserError(ErrorCodeMissingDelimiter, ErrorLocation{}, ParserErrorDetails{
				Reason:     ErrorReasonPolicy,
				PolicyName: string(options.LineEndingPolicy),
			})
		}
		headerBytes = data
	}
	if len(headerBytes) == 0 {
		return Message{}, malformedHeaderError(0, 1, 1)
	}
	if len(headerBytes) > options.MaxHeaderBytes {
		return Message{}, NewParserError(ErrorCodeLimitExceeded, ErrorLocation{}, ParserErrorDetails{
			Reason:    ErrorReasonLimit,
			LimitName: "max_header_bytes",
			Limit:     options.MaxHeaderBytes,
		})
	}

	headers, err := parseHeaderBlock(headerBytes, options)
	if err != nil {
		return Message{}, err
	}
	body, err := buildBody(bodyBytes, options, delimiterOffset+len(strictHeaderBodyDelimiter))
	if err != nil {
		return Message{}, err
	}

	metadata := NewParserMetadata(
		options.LineEndingPolicy,
		false,
		len(data),
		len(data),
		len(headerBytes),
		headers.Len(),
		len(bodyBytes),
	)

	return NewMessage(data, headers, body, metadata)
}

// enforceStrictCRLF rejects ambiguous line endings before message construction.
func enforceStrictCRLF(data []byte, options ParserOptions) error {
	var sawCRLF bool
	var sawBareLF bool
	var sawBareCR bool
	var firstBareLF ErrorLocation
	var firstBareCR ErrorLocation
	line := 1
	column := 1

	for offset := 0; offset < len(data); offset++ {
		switch data[offset] {
		case '\r':
			if offset+1 < len(data) && data[offset+1] == '\n' {
				sawCRLF = true
				offset++
				line++
				column = 1
				continue
			}
			if !sawBareCR {
				firstBareCR = ErrorLocation{Offset: offset, Line: line, Column: column}
			}
			sawBareCR = true
			column++
		case '\n':
			if !sawBareLF {
				firstBareLF = ErrorLocation{Offset: offset, Line: line, Column: column}
			}
			sawBareLF = true
			line++
			column = 1
		default:
			column++
		}
	}

	if (sawBareLF || sawBareCR) && (sawCRLF || sawBareLF && sawBareCR) {
		return NewParserError(ErrorCodeMixedLineEndings, firstLineEndingLocation(firstBareLF, firstBareCR), ParserErrorDetails{
			Reason:     ErrorReasonPolicy,
			PolicyName: string(options.LineEndingPolicy),
		})
	}
	if sawBareLF {
		return NewParserError(ErrorCodeBareLF, firstBareLF, ParserErrorDetails{
			Reason:     ErrorReasonPolicy,
			PolicyName: string(options.LineEndingPolicy),
		})
	}
	if sawBareCR {
		return NewParserError(ErrorCodeBareCR, firstBareCR, ParserErrorDetails{
			Reason:     ErrorReasonPolicy,
			PolicyName: string(options.LineEndingPolicy),
		})
	}

	return nil
}

// firstLineEndingLocation selects the earliest recorded bare line ending.
func firstLineEndingLocation(lf ErrorLocation, cr ErrorLocation) ErrorLocation {
	if lf == (ErrorLocation{}) {
		return cr
	}
	if cr == (ErrorLocation{}) {
		return lf
	}
	if lf.Offset < cr.Offset {
		return lf
	}

	return cr
}

// parseHeaderBlock parses CRLF-terminated header fields in occurrence order.
func parseHeaderBlock(headerBytes []byte, options ParserOptions) (HeaderBlock, error) {
	if len(headerBytes) == 0 {
		return HeaderBlock{}, malformedHeaderError(0, 1, 1)
	}

	var fields []HeaderField
	currentStart := -1
	currentEnd := 0
	lineStart := 0
	lineNumber := 1

	for lineStart < len(headerBytes) {
		lineEndRel := bytes.Index(headerBytes[lineStart:], crlf)
		if lineEndRel < 0 {
			return HeaderBlock{}, malformedHeaderError(lineStart, lineNumber, 1)
		}
		lineEnd := lineStart + lineEndRel
		line := headerBytes[lineStart:lineEnd]
		if len(line) > options.MaxHeaderLineBytes {
			return HeaderBlock{}, NewParserError(ErrorCodeLimitExceeded, ErrorLocation{Offset: lineStart, Line: lineNumber, Column: 1}, ParserErrorDetails{
				Reason:    ErrorReasonLimit,
				LimitName: limitNameMaxHeaderLineBytes,
				Limit:     options.MaxHeaderLineBytes,
			})
		}
		if len(line) == 0 {
			return HeaderBlock{}, malformedHeaderError(lineStart, lineNumber, 1)
		}

		if line[0] == ' ' || line[0] == '\t' {
			if currentStart < 0 {
				return HeaderBlock{}, malformedHeaderError(lineStart, lineNumber, 1)
			}
			currentEnd = lineEnd + len(crlf)
		} else {
			if currentStart >= 0 {
				field, err := buildHeaderField(len(fields), headerBytes, currentStart, currentEnd, options)
				if err != nil {
					return HeaderBlock{}, err
				}
				fields = append(fields, field)
				if len(fields) > options.MaxHeaderFields {
					return HeaderBlock{}, NewParserError(ErrorCodeLimitExceeded, ErrorLocation{Offset: lineStart, Line: lineNumber, Column: 1}, ParserErrorDetails{
						Reason:    ErrorReasonLimit,
						LimitName: "max_header_fields",
						Limit:     options.MaxHeaderFields,
					})
				}
			}
			currentStart = lineStart
			currentEnd = lineEnd + len(crlf)
		}

		lineStart = lineEnd + len(crlf)
		lineNumber++
	}

	if currentStart < 0 {
		return HeaderBlock{}, malformedHeaderError(0, 1, 1)
	}
	field, err := buildHeaderField(len(fields), headerBytes, currentStart, currentEnd, options)
	if err != nil {
		return HeaderBlock{}, err
	}
	fields = append(fields, field)
	if len(fields) > options.MaxHeaderFields {
		return HeaderBlock{}, NewParserError(ErrorCodeLimitExceeded, ErrorLocation{Offset: currentStart, Line: lineNumber, Column: 1}, ParserErrorDetails{
			Reason:    ErrorReasonLimit,
			LimitName: "max_header_fields",
			Limit:     options.MaxHeaderFields,
		})
	}

	return NewHeaderBlock(fields, headerBytes)
}

// buildHeaderField constructs one validated immutable header field.
func buildHeaderField(index int, headerBytes []byte, start int, end int, options ParserOptions) (HeaderField, error) {
	if end <= start || end-start > options.MaxHeaderFieldBytes {
		return HeaderField{}, NewParserError(ErrorCodeLimitExceeded, ErrorLocation{Offset: start}, ParserErrorDetails{
			Reason:    ErrorReasonLimit,
			LimitName: "max_header_field_bytes",
			Limit:     options.MaxHeaderFieldBytes,
		})
	}

	original := headerBytes[start:end]
	firstLineEnd := bytes.Index(original, crlf)
	if firstLineEnd < 0 {
		return HeaderField{}, malformedHeaderError(start, 0, 0)
	}
	firstLine := original[:firstLineEnd]
	colon := bytes.IndexByte(firstLine, ':')
	if colon < 0 {
		return HeaderField{}, malformedHeaderError(start, 0, 1)
	}
	rawName := firstLine[:colon]
	if invalidOffset := invalidHeaderFieldNameOffset(rawName); invalidOffset >= 0 {
		return HeaderField{}, malformedHeaderError(start+invalidOffset, 0, invalidOffset+1)
	}

	rawValue := original[colon+1 : len(original)-len(crlf)]
	unfoldedValue := unfoldHeaderValue(rawValue)

	return NewHeaderField(index, rawName, rawValue, unfoldedValue, original)
}

// unfoldHeaderValue removes RFC 5322 folding CRLF while preserving WSP bytes.
func unfoldHeaderValue(value []byte) []byte {
	if !bytes.Contains(value, crlf) {
		return bytes.Clone(value)
	}

	unfolded := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if i+2 < len(value) && value[i] == '\r' && value[i+1] == '\n' && (value[i+2] == ' ' || value[i+2] == '\t') {
			i++
			continue
		}
		unfolded = append(unfolded, value[i])
	}

	return unfolded
}

// malformedHeaderError constructs a bounded malformed-header parser error.
func malformedHeaderError(offset int, line int, column int) *ParserError {
	return NewParserError(ErrorCodeMalformedHeader, ErrorLocation{Offset: offset, Line: line, Column: column}, ParserErrorDetails{
		Reason: ErrorReasonMalformed,
	})
}
