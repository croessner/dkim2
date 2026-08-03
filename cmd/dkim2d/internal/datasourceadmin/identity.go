package datasourceadmin

import (
	"context"
	"fmt"
)

// IdentityProjection owns the collision-relevant identities of complete snapshots.
type IdentityProjection struct {
	selectors  map[string]struct{}
	profileIDs map[string]struct{}
	handleIDs  map[string]struct{}
	policies   map[policyIdentity]struct{}
	closed     bool
}

// policyIdentity is one exact tenant, signing-domain, and profile-use collision key.
type policyIdentity struct {
	tenantID string
	domain   string
	use      string
}

// newIdentityProjection constructs one empty protected collision index.
func newIdentityProjection() *IdentityProjection {
	return &IdentityProjection{
		selectors: make(map[string]struct{}), profileIDs: make(map[string]struct{}),
		handleIDs: make(map[string]struct{}), policies: make(map[policyIdentity]struct{}),
	}
}

// IdentityProjection returns a detached protected collision index.
func (s *Snapshot) IdentityProjection(ctx context.Context) (*IdentityProjection, error) {
	projection := newIdentityProjection()
	err := s.WithRows(ctx, func(rows Rows) error {
		for _, profile := range rows.Profiles {
			projection.profileIDs[profile.ID] = struct{}{}
		}
		for _, credential := range rows.Credentials {
			projection.selectors[credential.Selector] = struct{}{}
			projection.handleIDs[credential.HandleID] = struct{}{}
		}
		for _, handle := range rows.Handles {
			projection.handleIDs[handle.ID] = struct{}{}
		}
		for _, policy := range rows.Policies {
			projection.policies[policyIdentity{
				tenantID: policy.TenantID, domain: policy.Domain, use: policy.Use,
			}] = struct{}{}
		}
		return nil
	})
	if err != nil {
		_ = projection.Close()
		return nil, err
	}
	return projection, nil
}

// Merge adds another complete protected collision index.
func (p *IdentityProjection) Merge(other *IdentityProjection) error {
	if p == nil || other == nil || p.closed || other.closed {
		return newError(CodeInvalid)
	}
	for value := range other.selectors {
		p.selectors[value] = struct{}{}
	}
	for value := range other.profileIDs {
		p.profileIDs[value] = struct{}{}
	}
	for value := range other.handleIDs {
		p.handleIDs[value] = struct{}{}
	}
	for value := range other.policies {
		p.policies[value] = struct{}{}
	}
	return nil
}

// SelectorUsed reports an exact selector collision.
func (p *IdentityProjection) SelectorUsed(value string) bool {
	if p == nil || p.closed {
		return true
	}
	_, present := p.selectors[value]
	return present
}

// ProfileIDUsed reports an exact profile-identifier collision.
func (p *IdentityProjection) ProfileIDUsed(value string) bool {
	if p == nil || p.closed {
		return true
	}
	_, present := p.profileIDs[value]
	return present
}

// HandleIDUsed reports an exact handle-identifier collision.
func (p *IdentityProjection) HandleIDUsed(value string) bool {
	if p == nil || p.closed {
		return true
	}
	_, present := p.handleIDs[value]
	return present
}

// PolicyUsed reports an exact tenant, signing-domain, and profile-use collision.
func (p *IdentityProjection) PolicyUsed(tenantID, domain, use string) bool {
	if p == nil || p.closed {
		return true
	}
	_, present := p.policies[policyIdentity{tenantID: tenantID, domain: domain, use: use}]
	return present
}

// Close releases every collision-relevant identity.
func (p *IdentityProjection) Close() error {
	if p == nil || p.closed {
		return nil
	}
	clear(p.selectors)
	clear(p.profileIDs)
	clear(p.handleIDs)
	clear(p.policies)
	p.selectors, p.profileIDs, p.handleIDs, p.policies = nil, nil, nil, nil
	p.closed = true
	return nil
}

// String returns a constant protected identity-projection representation.
func (*IdentityProjection) String() string { return redacted }

// GoString returns a constant protected identity-projection representation.
func (*IdentityProjection) GoString() string { return redacted }

// Format prevents snapshot identities from reaching formatting sinks.
func (*IdentityProjection) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected identity-projection serialization.
func (*IdentityProjection) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }
