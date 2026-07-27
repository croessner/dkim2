package signingstore

import (
	"strings"
	"unicode/utf8"
)

const maxChildNameBytes = 255

// validChildName accepts one portable direct-child component.
func validChildName(name string) bool {
	if len(name) == 0 || len(name) > maxChildNameBytes ||
		!utf8.ValidString(name) || name == "." || name == ".." ||
		strings.ContainsAny(name, "/\\:\x00") ||
		strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return false
	}
	for index := range len(name) {
		if name[index] < 0x20 || name[index] == 0x7f {
			return false
		}
	}
	return true
}
