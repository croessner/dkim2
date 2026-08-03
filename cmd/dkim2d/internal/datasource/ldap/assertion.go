package ldap

import (
	"errors"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
)

const assertionControlOID = "1.3.6.1.1.12"

type criticalAssertionControl struct{ filter *ber.Packet }

// NewCriticalAssertionControl compiles one mandatory RFC 4528 assertion filter.
func NewCriticalAssertionControl(filter string) (goldap.Control, error) {
	compiled, err := goldap.CompileFilter(filter)
	if err != nil || compiled == nil {
		return nil, errors.New("ldap assertion unavailable")
	}
	return &criticalAssertionControl{filter: compiled}, nil
}

// GetControlType returns the RFC 4528 assertion-control OID.
func (*criticalAssertionControl) GetControlType() string { return assertionControlOID }

// Encode emits one critical assertion control with compiled filter bytes.
func (c *criticalAssertionControl) Encode() *ber.Packet {
	control := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	control.AppendChild(ber.NewString(
		ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		assertionControlOID, "Control Type",
	))
	control.AppendChild(ber.NewBoolean(
		ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality",
	))
	value := ""
	if c != nil && c.filter != nil {
		value = string(c.filter.Bytes())
	}
	control.AppendChild(ber.NewString(
		ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "Control Value",
	))
	return control
}

// String returns only the closed RFC 4528 control class.
func (*criticalAssertionControl) String() string { return "critical_assertion_control" }
