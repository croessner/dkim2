package datasourceadmin

import (
	"fmt"
	"sync"

	"github.com/croessner/dkim2/provider"
)

// DomainCredential contains one complete generated selector and native key pair.
type DomainCredential struct {
	Algorithm    string
	HandleID     string
	Selector     string
	PublicSPKI   []byte
	PrivatePKCS8 []byte
}

// String returns a constant protected domain-credential representation.
func (DomainCredential) String() string { return redacted }

// GoString returns a constant protected domain-credential representation.
func (DomainCredential) GoString() string { return redacted }

// Format prevents generated key material from reaching formatting sinks.
func (DomainCredential) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected domain-credential serialization.
func (DomainCredential) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// DomainAddition owns one complete validated single-domain append operation.
type DomainAddition struct {
	mu     sync.Mutex
	rows   Rows
	closed bool
}

// NewDomainAddition validates and owns one exact new-domain row set.
func NewDomainAddition(
	intent PlanIntent,
	profileID string,
	credentials []DomainCredential,
) (*DomainAddition, error) {
	if intent.Version != domainIntentVersionV1 || len(credentials) == 0 || len(credentials) > 2 ||
		len(intent.Algorithms) != len(credentials) {
		return nil, newError(CodeInvalid)
	}
	allocated := make([]AllocatedCredential, len(credentials))
	rows := Rows{
		Profiles: []ProfileRow{{ID: profileID, Domain: intent.Domain, Status: recordStatusActive}},
		Policies: []PolicyRow{{
			TenantID: intent.TenantID, Domain: intent.Domain, Use: intent.ProfileUse,
			ProfileID: profileID, Status: recordStatusActive, Rollout: intent.Rollout,
			Compatibility: intent.Compatibility,
		}},
	}
	for index, credential := range credentials {
		if credential.Algorithm != intent.Algorithms[index] ||
			index > 0 && credentials[index-1].Algorithm >= credential.Algorithm {
			clearRows(&rows)
			return nil, newError(CodeInvalid)
		}
		allocated[index] = AllocatedCredential{
			Algorithm: credential.Algorithm, HandleID: credential.HandleID, Selector: credential.Selector,
		}
		rows.Handles = append(rows.Handles, HandleRow{ID: credential.HandleID})
		rows.Credentials = append(rows.Credentials, CredentialRow{
			ProfileID: profileID, Algorithm: credential.Algorithm, Selector: credential.Selector,
			PublicSPKI: append([]byte(nil), credential.PublicSPKI...), HandleID: credential.HandleID,
		})
		rows.KeyMaterial = append(rows.KeyMaterial, KeyMaterialRow{
			TenantID: intent.TenantID, Domain: intent.Domain, Use: intent.ProfileUse,
			HandleID: credential.HandleID, Algorithm: credential.Algorithm,
			PublicSPKI:   append([]byte(nil), credential.PublicSPKI...),
			PrivatePKCS8: append([]byte(nil), credential.PrivatePKCS8...),
		})
	}
	if !validPlanIntent(intent, profileID, allocated) || validateRows(1, rows, provider.DefaultLimits()) != nil {
		clearRows(&rows)
		return nil, newError(CodeInvalid)
	}
	return &DomainAddition{rows: rows}, nil
}

// NewSnapshot constructs the initial complete generation from this domain addition.
func (a *DomainAddition) NewSnapshot(schema string, generation uint64) (*Snapshot, error) {
	if a == nil {
		return nil, newError(CodeInvalid)
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil, newError(CodeInvalid)
	}
	rows := cloneRows(a.rows)
	a.mu.Unlock()
	defer clearRows(&rows)
	return NewSnapshot(schema, generation, rows)
}

// AddDomain clones the source and appends one validated domain without mutating either owner.
func (s *Snapshot) AddDomain(
	schema string,
	generation uint64,
	addition *DomainAddition,
) (*Snapshot, error) {
	if s == nil || addition == nil {
		return nil, newError(CodeInvalid)
	}
	s.mu.Lock()
	if s.closed || generation <= s.generation {
		s.mu.Unlock()
		return nil, newError(CodeConflict)
	}
	rows := cloneRows(s.rows)
	s.mu.Unlock()
	addition.mu.Lock()
	if addition.closed {
		addition.mu.Unlock()
		clearRows(&rows)
		return nil, newError(CodeInvalid)
	}
	extra := cloneRows(addition.rows)
	addition.mu.Unlock()
	appendRows(&rows, &extra)
	defer clearRows(&rows)
	return NewSnapshot(schema, generation, rows)
}

// appendRows transfers every detached appended row into one complete projection.
func appendRows(target *Rows, extra *Rows) {
	if target == nil || extra == nil {
		return
	}
	target.Handles = append(target.Handles, extra.Handles...)
	target.Profiles = append(target.Profiles, extra.Profiles...)
	target.Credentials = append(target.Credentials, extra.Credentials...)
	target.Policies = append(target.Policies, extra.Policies...)
	target.KeyMaterial = append(target.KeyMaterial, extra.KeyMaterial...)
	*extra = Rows{}
}

// Close erases and releases all retained generated domain key material.
func (a *DomainAddition) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	clearRows(&a.rows)
	a.closed = true
	return nil
}

// String returns a constant protected domain-addition representation.
func (*DomainAddition) String() string { return redacted }

// GoString returns a constant protected domain-addition representation.
func (*DomainAddition) GoString() string { return redacted }

// Format prevents domain additions from reaching formatting sinks.
func (*DomainAddition) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected domain-addition serialization.
func (*DomainAddition) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }
