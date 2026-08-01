// Package migration owns offline legacy OpenDKIM inventory and publication.
package migration

import (
	"fmt"
	"io"
	"time"
)

const redacted = "dkim2d_migration{redacted}"

const (
	migrationReportSchema      = "dkim2.opendkim-bootstrap-report.v2"
	migrationSchemaVersion     = "dkim2-datasource-v2"
	migrationResultSuccess     = "success"
	migrationResultFailure     = "failure"
	migrationFailureNone       = "none"
	ldapTransportSecure        = "ldaps"
	legacyObjectClass          = "objectClass"
	legacySelector             = "DKIMSelector"
	legacyDomain               = "DKIMDomain"
	legacyAssociatedDomain     = "associatedDomain"
	legacyKeyType              = "DKIMKeyType"
	legacyKey                  = "DKIMKey"
	legacyActive               = "DKIMActive"
	datasourceStateCommitted   = "committed"
	datasourceStateStaging     = "staging"
	ldapTopObjectClass         = "top"
	ldapSchemaVersionAttribute = "dkim2SchemaVersion"
	ldapGenerationAttribute    = "dkim2Generation"
	ldapDatasetStateAttribute  = "dkim2DatasetState"
	ldapHandleAttribute        = "dkim2HandleID"
	ldapProfileAttribute       = "dkim2ProfileID"
	ldapSigningDomainAttribute = "dkim2SigningDomain"
	ldapRecordStatusAttribute  = "dkim2RecordStatus"
	ldapTenantAttribute        = "dkim2TenantID"
	ldapProfileUseAttribute    = "dkim2ProfileUse"
	ldapRolloutAttribute       = "dkim2Rollout"
	ldapCompatibilityAttribute = "dkim2Compatibility"
	ldapPrivatePKCS8Attribute  = "dkim2PrivateKeyPKCS8"
)

// Target identifies one closed DKIM2 publication backend.
type Target string

const (
	// TargetLDAP selects the versioned LDAP datasource.
	TargetLDAP Target = "ldap"
	// TargetPostgreSQL selects the versioned PostgreSQL datasource.
	TargetPostgreSQL Target = "postgresql"
)

// Algorithm identifies one closed legacy key class.
type Algorithm string

const (
	// AlgorithmRSA identifies one legacy RSA record.
	AlgorithmRSA Algorithm = "rsa"
	// AlgorithmEd25519 identifies one legacy Ed25519 record.
	AlgorithmEd25519 Algorithm = "ed25519"
)

// LegacyRecord is one validated nonsecret inventory record.
type LegacyRecord struct {
	selector        string
	sourceSelector  string
	domain          string
	associated      string
	algorithm       Algorithm
	active          bool
	ignoredIdentity bool
	ignoredCreated  bool
	ignoredModified bool
}

// Active reports whether the complete record participates in migration.
func (r LegacyRecord) Active() bool { return r.active }

// String returns a constant protected record summary.
func (LegacyRecord) String() string { return redacted }

// GoString returns a constant protected record representation.
func (LegacyRecord) GoString() string { return redacted }

// Format prevents formatting verbs from exposing legacy identity.
func (LegacyRecord) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON emits an empty object without source identity.
func (LegacyRecord) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// Mapping supplies every DKIM2 fact that legacy OpenDKIM does not own.
type Mapping struct {
	Domain          string `yaml:"domain"`
	SourceSelector  string `yaml:"source_selector,omitempty"`
	Selector        string `yaml:"selector"`
	TenantID        string `yaml:"tenant_id"`
	ProfileID       string `yaml:"profile_id"`
	ProfileUse      string `yaml:"profile_use"`
	HandleID        string `yaml:"handle_id"`
	Rollout         string `yaml:"rollout"`
	Compatibility   string `yaml:"compatibility"`
	FeedbackRouteID string `yaml:"feedback_route_id,omitempty"`
	NotBefore       string `yaml:"not_before,omitempty"`
	NotAfter        string `yaml:"not_after,omitempty"`
}

// legacySelector returns the explicit source selector or the target selector
// for backward-compatible same-selector migrations.
func (m Mapping) legacySelector() string {
	if m.SourceSelector != "" {
		return m.SourceSelector
	}
	return m.Selector
}

// Plan is one exact noninferential mapping plan.
type Plan struct {
	Generation      string    `yaml:"generation"`
	ExpectedCurrent string    `yaml:"expected_current"`
	Target          Target    `yaml:"target"`
	Mappings        []Mapping `yaml:"mappings"`
}

// InventoryCounts contains only bounded nonidentity totals.
type InventoryCounts struct {
	Records                uint32 `json:"records"`
	Active                 uint32 `json:"active"`
	Inactive               uint32 `json:"inactive"`
	RSA                    uint32 `json:"rsa"`
	Ed25519                uint32 `json:"ed25519"`
	IgnoredIdentityFields  uint32 `json:"ignored_identity_fields"`
	IgnoredTimestampFields uint32 `json:"ignored_timestamp_fields"`
	ValidatedPlanMappings  uint32 `json:"validated_plan_mappings"`
	SkippedInactiveHistory uint32 `json:"skipped_inactive_history"`
}

// PhaseState contains only closed attempt/completion facts.
type PhaseState struct {
	Attempted bool `json:"attempted"`
	Completed bool `json:"completed"`
}

// Report is the deterministic secret-safe migration result.
type Report struct {
	Schema           string          `json:"schema"`
	ToolVersion      string          `json:"tool_version"`
	Target           Target          `json:"target"`
	Mode             string          `json:"mode"`
	Result           string          `json:"result"`
	FailureClass     string          `json:"failure_class"`
	Counts           InventoryCounts `json:"counts"`
	Inventory        PhaseState      `json:"inventory"`
	Plan             PhaseState      `json:"plan"`
	KeyValidation    PhaseState      `json:"key_validation"`
	DNSProof         PhaseState      `json:"dns_proof"`
	KeyMaterialStage PhaseState      `json:"key_material_stage"`
	DatasetStage     PhaseState      `json:"dataset_stage"`
	Publication      PhaseState      `json:"publication"`
}

// String returns a constant protected report representation.
func (Report) String() string { return redacted }

// GoString returns a constant protected report Go representation.
func (Report) GoString() string { return redacted }

// Format prevents formatting verbs from exposing nested report state.
func (Report) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// validity parses an optional all-or-none canonical UTC range.
func (m Mapping) validity() (time.Time, time.Time, bool) {
	if m.NotBefore == "" || m.NotAfter == "" {
		return time.Time{}, time.Time{}, m.NotBefore == "" && m.NotAfter == ""
	}
	before, firstErr := time.Parse(time.RFC3339Nano, m.NotBefore)
	after, secondErr := time.Parse(time.RFC3339Nano, m.NotAfter)
	return before, after, firstErr == nil && secondErr == nil &&
		before.Location() == time.UTC && after.Location() == time.UTC &&
		before.Format(time.RFC3339Nano) == m.NotBefore &&
		after.Format(time.RFC3339Nano) == m.NotAfter && before.Before(after)
}
