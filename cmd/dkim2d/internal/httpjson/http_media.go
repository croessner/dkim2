package httpjson

import "strings"

// validJSONContentType accepts only the frozen application/json representation.
func validJSONContentType(values []string) bool {
	if len(values) != 1 {
		return false
	}
	value := values[0]
	position := 0
	skipOWS(value, &position)
	mediaType, ok := readToken(value, &position)
	if !ok || position >= len(value) || value[position] != '/' {
		return false
	}
	position++
	mediaSubtype, ok := readToken(value, &position)
	if !ok || !strings.EqualFold(mediaType, "application") || !strings.EqualFold(mediaSubtype, "json") {
		return false
	}
	charsetSeen := false
	for {
		skipOWS(value, &position)
		if position == len(value) {
			return true
		}
		if value[position] != ';' {
			return false
		}
		position++
		skipOWS(value, &position)
		if position == len(value) || value[position] == ';' {
			continue
		}
		name, nameOK := readToken(value, &position)
		if !nameOK || position >= len(value) || value[position] != '=' {
			return false
		}
		position++
		parameterValue, valueOK := readParameterValue(value, &position)
		if !valueOK || charsetSeen || !strings.EqualFold(name, "charset") ||
			!strings.EqualFold(parameterValue, "utf-8") {
			return false
		}
		charsetSeen = true
	}
}

// skipOWS advances across RFC optional whitespace.
func skipOWS(value string, position *int) {
	for *position < len(value) && (value[*position] == ' ' || value[*position] == '\t') {
		*position++
	}
}

// readToken consumes one nonempty RFC token.
func readToken(value string, position *int) (string, bool) {
	start := *position
	for *position < len(value) && httpTokenByte(value[*position]) {
		*position++
	}
	return value[start:*position], *position > start
}

// readParameterValue consumes one token or quoted-string with quoted-pair decoding.
func readParameterValue(value string, position *int) (string, bool) {
	if *position >= len(value) {
		return "", false
	}
	if value[*position] != '"' {
		return readToken(value, position)
	}
	*position++
	decoded := make([]byte, 0, len(value)-*position)
	for *position < len(value) {
		current := value[*position]
		*position++
		switch {
		case current == '"':
			return string(decoded), true
		case current == '\\':
			if *position >= len(value) {
				return "", false
			}
			escaped := value[*position]
			*position++
			if escaped == 0x7f || escaped < 0x20 && escaped != '\t' {
				return "", false
			}
			decoded = append(decoded, escaped)
		case current == '\r' || current == '\n' || current == 0x7f || current < 0x20 && current != '\t':
			return "", false
		default:
			decoded = append(decoded, current)
		}
	}
	return "", false
}
