package datasourceadmin

import (
	"fmt"
	"io"
)

// formatProtected writes the package's constant protected representation.
func formatProtected(state fmt.State) { _, _ = io.WriteString(state, redacted) }

// String returns a constant protected handle-row representation.
func (HandleRow) String() string { return redacted }

// GoString returns a constant protected handle-row representation.
func (HandleRow) GoString() string { return redacted }

// Format prevents handle-row data from reaching formatting sinks.
func (HandleRow) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected handle-row serialization.
func (HandleRow) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// String returns a constant protected profile-row representation.
func (ProfileRow) String() string { return redacted }

// GoString returns a constant protected profile-row representation.
func (ProfileRow) GoString() string { return redacted }

// Format prevents profile-row data from reaching formatting sinks.
func (ProfileRow) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected profile-row serialization.
func (ProfileRow) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// String returns a constant protected credential-row representation.
func (CredentialRow) String() string { return redacted }

// GoString returns a constant protected credential-row representation.
func (CredentialRow) GoString() string { return redacted }

// Format prevents credential-row data from reaching formatting sinks.
func (CredentialRow) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected credential-row serialization.
func (CredentialRow) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// String returns a constant protected policy-row representation.
func (PolicyRow) String() string { return redacted }

// GoString returns a constant protected policy-row representation.
func (PolicyRow) GoString() string { return redacted }

// Format prevents policy-row data from reaching formatting sinks.
func (PolicyRow) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected policy-row serialization.
func (PolicyRow) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// String returns a constant protected key-material-row representation.
func (KeyMaterialRow) String() string { return redacted }

// GoString returns a constant protected key-material-row representation.
func (KeyMaterialRow) GoString() string { return redacted }

// Format prevents private key material from reaching formatting sinks.
func (KeyMaterialRow) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected key-material-row serialization.
func (KeyMaterialRow) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// String returns a constant protected row-set representation.
func (Rows) String() string { return redacted }

// GoString returns a constant protected row-set representation.
func (Rows) GoString() string { return redacted }

// Format prevents complete row projections from reaching formatting sinks.
func (Rows) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected row-set serialization.
func (Rows) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// String returns a constant protected authority-endpoint representation.
func (AuthorityEndpoint) String() string { return redacted }

// GoString returns a constant protected authority-endpoint representation.
func (AuthorityEndpoint) GoString() string { return redacted }

// Format prevents authority endpoints from reaching formatting sinks.
func (AuthorityEndpoint) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected authority-endpoint serialization.
func (AuthorityEndpoint) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// String returns a constant protected LDAP-authority representation.
func (LDAPAuthority) String() string { return redacted }

// GoString returns a constant protected LDAP-authority representation.
func (LDAPAuthority) GoString() string { return redacted }

// Format prevents LDAP authority data from reaching formatting sinks.
func (LDAPAuthority) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected LDAP-authority serialization.
func (LDAPAuthority) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// String returns a constant protected SQL-authority representation.
func (SQLAuthority) String() string { return redacted }

// GoString returns a constant protected SQL-authority representation.
func (SQLAuthority) GoString() string { return redacted }

// Format prevents SQL authority data from reaching formatting sinks.
func (SQLAuthority) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected SQL-authority serialization.
func (SQLAuthority) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// String returns a constant protected plan-intent representation.
func (PlanIntent) String() string { return redacted }

// GoString returns a constant protected plan-intent representation.
func (PlanIntent) GoString() string { return redacted }

// Format prevents plan intent data from reaching formatting sinks.
func (PlanIntent) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected plan-intent serialization.
func (PlanIntent) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// String returns a constant protected allocated-credential representation.
func (AllocatedCredential) String() string { return redacted }

// GoString returns a constant protected allocated-credential representation.
func (AllocatedCredential) GoString() string { return redacted }

// Format prevents allocated credential data from reaching formatting sinks.
func (AllocatedCredential) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected allocated-credential serialization.
func (AllocatedCredential) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// String returns a constant protected DNS-policy representation.
func (DNSPolicy) String() string { return redacted }

// GoString returns a constant protected DNS-policy representation.
func (DNSPolicy) GoString() string { return redacted }

// Format prevents resolver policy data from reaching formatting sinks.
func (DNSPolicy) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected DNS-policy serialization.
func (DNSPolicy) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }
