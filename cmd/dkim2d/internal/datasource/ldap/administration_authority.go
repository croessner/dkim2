package ldap

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

const (
	ldapAdministrationAuthorityDomain   = "dkim2 ldap administration authority v2\x00"
	ldapAdministrationAuthorityRedacted = "ldap_administration_authority{redacted}"
	maximumAdministrationDNValueBytes   = 63
)

// AdministrationAuthority is one opaque canonical LDAP bind identity used
// only to enforce construction-time administration role separation.
type AdministrationAuthority struct {
	digest      [sha256.Size]byte
	initialized bool
}

// newAdministrationAuthority accepts only the closed canonical service-DN
// grammar before deriving its domain-separated opaque identity.
func newAdministrationAuthority(bindDN string) (AdministrationAuthority, error) {
	parsed, err := goldap.ParseDN(bindDN)
	if err != nil {
		return AdministrationAuthority{}, errors.New("ldap administration authority unavailable")
	}
	canonical, ok := canonicalAdministrationBindDN(parsed)
	if !ok || bindDN != canonical {
		return AdministrationAuthority{}, errors.New("ldap administration authority unavailable")
	}
	digest := sha256.Sum256([]byte(ldapAdministrationAuthorityDomain + canonical))
	return AdministrationAuthority{digest: digest, initialized: true}, nil
}

// canonicalAdministrationBindDN reconstructs cn, ou+, dc+ from simple RDNs
// whose values are lowercase ASCII LDH labels.
func canonicalAdministrationBindDN(parsed *goldap.DN) (string, bool) {
	if parsed == nil || len(parsed.RDNs) < 3 {
		return "", false
	}
	parts := make([]string, 0, len(parsed.RDNs))
	seenOU := false
	seenDC := false
	for index, rdn := range parsed.RDNs {
		if rdn == nil || len(rdn.Attributes) != 1 || rdn.Attributes[0] == nil {
			return "", false
		}
		attribute := rdn.Attributes[0]
		if !canonicalAdministrationDNValue(attribute.Value) {
			return "", false
		}
		switch {
		case index == 0 && attribute.Type == "cn":
		case index > 0 && attribute.Type == "ou" && !seenDC:
			seenOU = true
		case index > 0 && attribute.Type == "dc" && seenOU:
			seenDC = true
		default:
			return "", false
		}
		parts = append(parts, attribute.Type+"="+attribute.Value)
	}
	if !seenOU || !seenDC {
		return "", false
	}
	return strings.Join(parts, ","), true
}

// canonicalAdministrationDNValue accepts one 1-to-63-byte lowercase ASCII
// letter-digit-hyphen label without a leading or trailing hyphen.
func canonicalAdministrationDNValue(value string) bool {
	if len(value) == 0 || len(value) > maximumAdministrationDNValueBytes ||
		!administrationDNAlphaNumeric(value[0]) ||
		!administrationDNAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for index := 1; index < len(value)-1; index++ {
		if !administrationDNAlphaNumeric(value[index]) && value[index] != '-' {
			return false
		}
	}
	return true
}

// administrationDNAlphaNumeric reports whether one byte is a lowercase ASCII
// letter or decimal digit.
func administrationDNAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

// Valid reports whether the authority was derived from the closed canonical
// administration service-DN grammar.
func (a AdministrationAuthority) Valid() bool { return a.initialized }

// Equal reports whether two initialized authorities represent the same
// canonical service bind identity.
func (a AdministrationAuthority) Equal(other AdministrationAuthority) bool {
	return a.initialized && other.initialized &&
		subtle.ConstantTimeCompare(a.digest[:], other.digest[:]) == 1
}

// String returns a constant representation without the bind identity.
func (AdministrationAuthority) String() string { return ldapAdministrationAuthorityRedacted }

// GoString returns a constant representation without the bind identity.
func (AdministrationAuthority) GoString() string { return ldapAdministrationAuthorityRedacted }

// Format prevents formatting verbs from traversing the opaque identity.
func (AdministrationAuthority) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, ldapAdministrationAuthorityRedacted)
}

// MarshalJSON rejects generic serialization of the opaque authority.
func (AdministrationAuthority) MarshalJSON() ([]byte, error) {
	return nil, errors.New("ldap administration authority unavailable")
}
