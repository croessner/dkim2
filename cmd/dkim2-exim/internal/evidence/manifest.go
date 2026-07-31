package evidence

import (
	"encoding/base64"
	"strings"
)

const (
	publicationAttempts = 8
	nonceBytes          = 16
	nonceTextBytes      = 22
	finalSuffix         = ".ev1"
	publicationPrefix   = ".put-"
	quarantinePrefix    = ".gc-"
)

// manifestKind identifies one exact reserved direct-child grammar.
type manifestKind uint8

const (
	manifestFinal manifestKind = iota + 1
	manifestPublication
	manifestQuarantine
)

// parseChildName validates exact final, publication, or quarantine grammar.
func parseChildName(name string) (string, manifestKind, error) {
	switch {
	case len(name) == LocatorTextBytes+len(finalSuffix) &&
		strings.HasSuffix(name, finalSuffix):
		locator := name[:LocatorTextBytes]
		if validLocator(locator) {
			return locator, manifestFinal, nil
		}
	case len(name) == len(publicationPrefix)+LocatorTextBytes+1+nonceTextBytes &&
		strings.HasPrefix(name, publicationPrefix):
		return parseReservedName(name, publicationPrefix, manifestPublication)
	case len(name) == len(quarantinePrefix)+LocatorTextBytes+1+nonceTextBytes &&
		strings.HasPrefix(name, quarantinePrefix):
		return parseReservedName(name, quarantinePrefix, manifestQuarantine)
	}
	return "", 0, ErrEvidence
}

// parseReservedName validates an exact locator plus canonical 128-bit nonce.
func parseReservedName(name, prefix string, kind manifestKind) (string, manifestKind, error) {
	locatorStart := len(prefix)
	locatorEnd := locatorStart + LocatorTextBytes
	if len(name) != locatorEnd+1+nonceTextBytes || name[locatorEnd] != '-' {
		return "", 0, ErrEvidence
	}
	locator := name[locatorStart:locatorEnd]
	nonce := name[locatorEnd+1:]
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil || len(decoded) != nonceBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != nonce ||
		!validLocator(locator) {
		clear(decoded)
		return "", 0, ErrEvidence
	}
	clear(decoded)
	return locator, kind, nil
}
