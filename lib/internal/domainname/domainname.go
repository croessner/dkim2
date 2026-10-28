// Package domainname owns the Draft-08 Section 18 conversion of protocol
// domain names from U-labels to A-labels.
//
// Input is treated as a protocol label sequence, not as browser or user input:
// ASCII letters are case-folded, but no Unicode compatibility mapping, width
// folding, alternate dot separators, or transitional processing is applied.
// U-labels must already be NFC and valid under the IDNA2008 registration
// profile of golang.org/x/net/idna, including the Bidi and joiner rules;
// existing A-labels are validated by decoding. Output is a lowercase ASCII
// A-label domain. A failure never returns partial output.
//
// Plain ASCII names without an "xn--" label take an LDH fast path that keeps
// their previous handling; it does not apply the IDNA hyphen rule for
// reserved "??--" labels, which is harmless for DNS lookup and comparison.
//
// Known limitation: golang.org/x/net/idna collapses the IDNA2008 NV8 and XV8
// categories into "valid", so it is not a complete strict IDNA2008 validator.
package domainname

import (
	"strings"

	"golang.org/x/net/idna"
)

const (
	maxDomainBytes = 253
	maxLabelBytes  = 63
)

// registration is the immutable strict conversion profile. It validates
// without mapping, so uppercase non-ASCII, compatibility, and width variants
// fail instead of being folded.
var registration = idna.New(
	idna.ValidateForRegistration(),
	idna.Transitional(false),
)

// ToASCII converts one DNS domain name in U-label or A-label form to its
// lowercase A-label form. It rejects empty input, leading or trailing dots,
// empty labels, labels outside letter/digit/hyphen form after conversion, and
// names longer than 253 octets.
func ToASCII(domain []byte) (string, bool) {
	if len(domain) == 0 || domain[0] == '.' || domain[len(domain)-1] == '.' {
		return "", false
	}
	folded := make([]byte, len(domain))
	for index, b := range domain {
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		folded[index] = b
	}
	if IsASCII(folded) && !hasACEPrefix(string(folded)) {
		// Plain LDH names need no IDNA processing; this keeps every
		// previously valid ASCII domain unchanged apart from case.
		if !validASCIIDomain(string(folded)) {
			return "", false
		}
		return string(folded), true
	}
	converted, err := registration.ToASCII(string(folded))
	if err != nil || !validASCIIDomain(converted) {
		return "", false
	}
	return converted, true
}

// IsASCII reports whether domain contains only ASCII bytes, which is the form
// Draft-08 Section 18 requires for domains recorded in DKIM2 header fields.
func IsASCII(domain []byte) bool {
	for _, b := range domain {
		if b >= 0x80 {
			return false
		}
	}
	return true
}

// hasACEPrefix reports whether any label of a lowercase ASCII name is an
// A-label candidate that must be validated by IDNA decoding.
func hasACEPrefix(domain string) bool {
	for label := range strings.SplitSeq(domain, ".") {
		if strings.HasPrefix(label, "xn--") {
			return true
		}
	}
	return false
}

// validASCIIDomain checks the converted name against lowercase LDH label rules
// and DNS length bounds as a defense against unexpected profile output.
func validASCIIDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > maxDomainBytes {
		return false
	}
	labelStart := 0
	for index := 0; index <= len(domain); index++ {
		if index < len(domain) && domain[index] != '.' {
			continue
		}
		if !validLDHLabel(domain[labelStart:index]) {
			return false
		}
		labelStart = index + 1
	}
	return true
}

// validLDHLabel checks one lowercase letter/digit/hyphen label.
func validLDHLabel(label string) bool {
	if len(label) == 0 || len(label) > maxLabelBytes || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for index := 0; index < len(label); index++ {
		b := label[index]
		if b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' {
			continue
		}
		return false
	}
	return true
}
