package httpjson

import (
	"bytes"
	"net/http"
)

// preconditionOutcome is the closed status-route conditional result.
type preconditionOutcome uint8

const (
	preconditionProceed preconditionOutcome = iota + 1
	preconditionNotModified
	preconditionFailed
	preconditionInvalid
)

// evaluateStatusPreconditions applies If-Match then If-None-Match to a selected representation.
func evaluateStatusPreconditions(header http.Header, selectedETag string) preconditionOutcome {
	if values, present := header["If-Match"]; present {
		matched, valid := matchEntityTagList(values, selectedETag, true)
		if !valid {
			return preconditionInvalid
		}
		if !matched {
			return preconditionFailed
		}
	}
	if values, present := header["If-None-Match"]; present {
		matched, valid := matchEntityTagList(values, selectedETag, false)
		if !valid {
			return preconditionInvalid
		}
		if matched {
			return preconditionNotModified
		}
	}
	return preconditionProceed
}

// matchEntityTagList parses one combined RFC entity-tag list without retaining members.
func matchEntityTagList(values []string, selected string, strong bool) (matched bool, valid bool) {
	if len(values) == 0 {
		return false, true
	}
	combinedLength := len(values) - 1
	for _, value := range values {
		combinedLength += len(value)
	}
	combined := make([]byte, 0, combinedLength)
	for index, value := range values {
		if index > 0 {
			combined = append(combined, ',')
		}
		combined = append(combined, value...)
	}
	trimmed := bytes.Trim(combined, " \t")
	if bytes.Equal(trimmed, []byte("*")) {
		return true, true
	}
	selectedBytes := []byte(selected)
	position := 0
	for {
		skipEntityOWS(combined, &position)
		if position == len(combined) {
			break
		}
		if combined[position] == ',' {
			position++
			continue
		}
		if combined[position] == '*' {
			return false, false
		}
		weak := false
		if position+2 <= len(combined) && bytes.Equal(combined[position:position+2], []byte("W/")) {
			weak = true
			position += 2
		}
		start := position
		if position >= len(combined) || combined[position] != '"' {
			return false, false
		}
		position++
		for position < len(combined) && combined[position] != '"' {
			value := combined[position]
			if value != 0x21 && (value < 0x23 || value > 0x7e) && value < 0x80 {
				return false, false
			}
			position++
		}
		if position >= len(combined) {
			return false, false
		}
		position++
		member := combined[start:position]
		if (!strong || !weak) && entityTagEqual(member, selectedBytes) {
			matched = true
		}
		skipEntityOWS(combined, &position)
		if position == len(combined) {
			break
		}
		if combined[position] != ',' {
			return false, false
		}
		position++
	}
	return matched, true
}

// entityTagEqual compares opaque tags after removing only an exact weak prefix.
func entityTagEqual(candidate, selected []byte) bool {
	if bytes.HasPrefix(candidate, []byte("W/")) {
		candidate = candidate[2:]
	}
	if bytes.HasPrefix(selected, []byte("W/")) {
		selected = selected[2:]
	}
	return bytes.Equal(candidate, selected)
}

// skipEntityOWS advances across RFC optional whitespace.
func skipEntityOWS(value []byte, position *int) {
	for *position < len(value) && (value[*position] == ' ' || value[*position] == '\t') {
		*position++
	}
}
