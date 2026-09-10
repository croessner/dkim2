package config

import "fmt"

// BatchReviseCapability is a comparison-only independent complete-fanout credential.
type BatchReviseCapability struct {
	state *protectedState
	token *runtimeToken
}

// BatchReviseCapabilityFile returns the protected complete-fanout capability path.
func (c ServerConfig) BatchReviseCapabilityFile() string {
	if c.state == nil {
		return ""
	}
	return c.state.batchReviseCapabilityFile
}

// BatchReviseEnabled reports explicitly configured complete-fanout authority.
func (c ServerConfig) BatchReviseEnabled() bool {
	return c.state != nil && c.state.batchReviseCapabilityFile != ""
}

// BatchReviseCapability returns the non-owning same-generation capability handle.
func (p *RuntimePreparation) BatchReviseCapability() BatchReviseCapability {
	if p == nil {
		return BatchReviseCapability{}
	}
	return BatchReviseCapability{state: p.state, token: p.token}
}

// Equal compares exact bytes only after the protected runtime handoff commits.
func (c BatchReviseCapability) Equal(candidate []byte) bool {
	return equalProtectedCapability(c.state, c.token, candidate, protectedBatchRevise)
}

// String returns a content-free capability representation.
func (BatchReviseCapability) String() string { return protectedRedactedText }

// GoString returns a content-free capability representation.
func (BatchReviseCapability) GoString() string { return protectedRedactedText }

// Format prevents diagnostic traversal of protected capability material.
func (BatchReviseCapability) Format(state fmt.State, _ rune) { writeProtectedRedacted(state) }

// MarshalJSON refuses diagnostic serialization of the capability.
func (BatchReviseCapability) MarshalJSON() ([]byte, error) { return nil, newError(CodeSerialization) }

// MarshalText refuses diagnostic serialization of the capability.
func (BatchReviseCapability) MarshalText() ([]byte, error) { return nil, newError(CodeSerialization) }
