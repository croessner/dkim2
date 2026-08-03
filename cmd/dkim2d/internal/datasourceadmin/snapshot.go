package datasourceadmin

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"github.com/croessner/dkim2/provider"
)

const (
	// SchemaVersionV2 identifies the deployed native custody schema.
	SchemaVersionV2 = "dkim2-datasource-v2"
	// SchemaVersionV3 identifies operation-bound administrative generations.
	SchemaVersionV3 = "dkim2-datasource-v3"
)

// HandleRow is one opaque handle projection.
type HandleRow struct{ ID string }

// ProfileRow is one public signing profile projection.
type ProfileRow struct {
	ID           string
	Domain       string
	Status       string
	NotBeforeUTC *string
	NotAfterUTC  *string
}

// CredentialRow is one public selector-to-handle projection.
type CredentialRow struct {
	ProfileID  string
	Algorithm  string
	Selector   string
	PublicSPKI []byte
	HandleID   string
}

// PolicyRow is one exact tenant/domain/use profile binding.
type PolicyRow struct {
	TenantID        string
	Domain          string
	Use             string
	ProfileID       string
	Status          string
	Rollout         string
	Compatibility   string
	FeedbackRouteID *string
}

// KeyMaterialRow is one canonical native private-key binding.
type KeyMaterialRow struct {
	TenantID     string
	Domain       string
	Use          string
	HandleID     string
	Algorithm    string
	PublicSPKI   []byte
	PrivatePKCS8 []byte
}

// Rows contains one complete generation without provider records or metadata.
type Rows struct {
	Handles     []HandleRow
	Profiles    []ProfileRow
	Credentials []CredentialRow
	Policies    []PolicyRow
	KeyMaterial []KeyMaterialRow
}

// Snapshot owns one complete validated provider-neutral generation.
type Snapshot struct {
	mu         sync.Mutex
	schema     string
	generation uint64
	rows       Rows
	closed     bool
}

// NewSnapshot validates and takes detached ownership of one complete generation.
func NewSnapshot(schema string, generation uint64, rows Rows) (*Snapshot, error) {
	if (schema != SchemaVersionV2 && schema != SchemaVersionV3) || generation == 0 {
		return nil, newError(CodeInvalid)
	}
	owned := cloneRows(rows)
	if err := validateRows(generation, owned); err != nil {
		clearRows(&owned)
		return nil, err
	}
	return &Snapshot{schema: schema, generation: generation, rows: owned}, nil
}

// validateRows reuses runtime datasource and native-custody validators.
func validateRows(generation uint64, rows Rows) error {
	dataset, err := mapRuntimeDataset(generation, rows)
	if err != nil || dataset == nil || !dataset.Valid() || dataset.Generation() != generation {
		return newError(CodeInvalid)
	}
	materials, err := mapNativeMaterials(generation, rows.KeyMaterial)
	if err != nil {
		return newError(CodeInvalid)
	}
	defer func() {
		for _, material := range materials {
			_ = material.Close()
		}
	}()
	registry, err := signingstore.OpenNativeRegistry(generation, materials)
	if err != nil {
		return newError(CodeInvalid)
	}
	defer func() { _ = registry.Close(context.Background()) }()
	resolver, err := dataset.NewSigningResolver(registry.Bindings(), time.Now().UTC())
	if err != nil || resolver == nil {
		return newError(CodeInvalid)
	}
	if err := resolver.Close(context.Background()); err != nil {
		return newError(CodeInvalid)
	}
	return nil
}

// mapRuntimeDataset validates the protected administrative rows through the
// same provider constructors used by runtime datasource adapters.
func mapRuntimeDataset(generation uint64, rows Rows) (*provider.Dataset, error) {
	limits := provider.DefaultLimits()
	handles := make([]string, 0, len(rows.Handles))
	for _, row := range rows.Handles {
		handles = append(handles, row.ID)
	}
	type profileAssembly struct {
		row         ProfileRow
		credentials []provider.Credential
	}
	profiles := make([]profileAssembly, len(rows.Profiles))
	for index, row := range rows.Profiles {
		profiles[index].row = row
	}
	for _, row := range rows.Credentials {
		algorithm, err := parseAdministrativeAlgorithm(row.Algorithm)
		if err != nil {
			return nil, err
		}
		credential, err := provider.NewCredential(
			row.Selector, algorithm, row.PublicSPKI, row.HandleID, limits,
		)
		if err != nil {
			return nil, err
		}
		matches := 0
		for index := range profiles {
			if profiles[index].row.ID == row.ProfileID {
				profiles[index].credentials = append(profiles[index].credentials, credential)
				matches++
			}
		}
		if matches != 1 {
			return nil, newError(CodeInvalid)
		}
	}
	neutralProfiles := make([]provider.Profile, 0, len(profiles))
	for _, assembly := range profiles {
		status, err := provider.ParseRecordStatus(assembly.row.Status)
		if err != nil {
			return nil, err
		}
		notBefore, notAfter, err := parseAdministrativeValidity(
			assembly.row.NotBeforeUTC, assembly.row.NotAfterUTC,
		)
		if err != nil {
			return nil, err
		}
		profile, err := provider.NewProfile(
			assembly.row.ID, assembly.row.Domain, status, assembly.credentials,
			notBefore, notAfter, limits,
		)
		if err != nil {
			return nil, err
		}
		neutralProfiles = append(neutralProfiles, profile)
	}
	policies := make([]provider.Policy, 0, len(rows.Policies))
	for _, row := range rows.Policies {
		use, err := provider.ParseProfileUse(row.Use)
		if err != nil {
			return nil, err
		}
		status, err := provider.ParseRecordStatus(row.Status)
		if err != nil {
			return nil, err
		}
		rollout, err := provider.ParseRollout(row.Rollout)
		if err != nil {
			return nil, err
		}
		compatibility, err := provider.ParseCompatibility(row.Compatibility)
		if err != nil {
			return nil, err
		}
		feedback := ""
		if row.FeedbackRouteID != nil {
			feedback = *row.FeedbackRouteID
		}
		policy, err := provider.NewPolicy(
			row.TenantID, row.Domain, use, row.ProfileID, status,
			rollout, compatibility, feedback, limits,
		)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	return provider.NewDataset(generation, handles, neutralProfiles, policies, limits)
}

// mapNativeMaterials validates and detaches the complete private-key set.
func mapNativeMaterials(
	generation uint64,
	rows []KeyMaterialRow,
) ([]*signingstore.NativeKeyMaterial, error) {
	if generation == 0 || len(rows) == 0 || len(rows) > provider.HardLimits().MaxHandles {
		return nil, newError(CodeInvalid)
	}
	materials := make([]*signingstore.NativeKeyMaterial, 0, len(rows))
	for _, row := range rows {
		use, err := provider.ParseProfileUse(row.Use)
		if err != nil {
			closeNativeMaterials(materials)
			return nil, err
		}
		algorithm, err := parseAdministrativeAlgorithm(row.Algorithm)
		if err != nil {
			closeNativeMaterials(materials)
			return nil, err
		}
		material, err := signingstore.NewNativeKeyMaterial(
			generation, row.TenantID, row.Domain, use, row.HandleID, algorithm,
			row.PublicSPKI, row.PrivatePKCS8,
		)
		if err != nil {
			closeNativeMaterials(materials)
			return nil, err
		}
		materials = append(materials, material)
	}
	return materials, nil
}

// closeNativeMaterials erases every temporary private-key owner.
func closeNativeMaterials(materials []*signingstore.NativeKeyMaterial) {
	for _, material := range materials {
		_ = material.Close()
	}
}

// parseAdministrativeAlgorithm maps the closed native signing vocabulary.
func parseAdministrativeAlgorithm(value string) (provider.Algorithm, error) {
	switch value {
	case string(provider.AlgorithmRSASHA256):
		return provider.AlgorithmRSASHA256, nil
	case string(provider.AlgorithmEd25519SHA256):
		return provider.AlgorithmEd25519SHA256, nil
	default:
		return "", newError(CodeInvalid)
	}
}

// parseAdministrativeValidity validates one canonical optional UTC interval.
func parseAdministrativeValidity(before, after *string) (time.Time, time.Time, error) {
	if (before == nil) != (after == nil) {
		return time.Time{}, time.Time{}, newError(CodeInvalid)
	}
	if before == nil {
		return time.Time{}, time.Time{}, nil
	}
	start, err := time.Parse(time.RFC3339Nano, *before)
	if err != nil || start.Location() != time.UTC || start.Format(time.RFC3339Nano) != *before {
		return time.Time{}, time.Time{}, newError(CodeInvalid)
	}
	end, err := time.Parse(time.RFC3339Nano, *after)
	if err != nil || end.Location() != time.UTC || end.Format(time.RFC3339Nano) != *after || !start.Before(end) {
		return time.Time{}, time.Time{}, newError(CodeInvalid)
	}
	return start, end, nil
}

// Generation returns the exact generation or zero after close.
func (s *Snapshot) Generation() uint64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0
	}
	return s.generation
}

// SchemaVersion returns the closed schema identifier or empty after close.
func (s *Snapshot) SchemaVersion() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ""
	}
	return s.schema
}

// WithRows supplies a detached protected projection and erases it after the callback.
func (s *Snapshot) WithRows(ctx context.Context, use func(Rows) error) error {
	if s == nil || ctx == nil || use == nil || ctx.Err() != nil {
		return newError(CodeInvalid)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return newError(CodeInvalid)
	}
	rows := cloneRows(s.rows)
	s.mu.Unlock()
	defer clearRows(&rows)
	if err := use(rows); err != nil {
		return newError(CodeUnavailable)
	}
	return nil
}

// CloneTo creates a complete identical logical generation with a higher number.
func (s *Snapshot) CloneTo(schema string, generation uint64) (*Snapshot, error) {
	if s == nil {
		return nil, newError(CodeInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || generation <= s.generation {
		return nil, newError(CodeConflict)
	}
	return NewSnapshot(schema, generation, s.rows)
}

// Close destroys all retained public and private key bytes and invalidates the snapshot.
func (s *Snapshot) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	clearRows(&s.rows)
	s.schema = ""
	s.generation = 0
	s.closed = true
	return nil
}

// String returns a constant protected snapshot representation.
func (*Snapshot) String() string { return redacted }

// GoString returns a constant protected Go representation.
func (*Snapshot) GoString() string { return redacted }

// Format prevents formatting verbs from traversing snapshot rows.
func (*Snapshot) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic protected snapshot serialization.
func (*Snapshot) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// cloneRows makes one deep detached row projection.
func cloneRows(rows Rows) Rows {
	result := Rows{Handles: append([]HandleRow(nil), rows.Handles...)}
	for _, row := range rows.Profiles {
		row.NotBeforeUTC, row.NotAfterUTC = cloneText(row.NotBeforeUTC), cloneText(row.NotAfterUTC)
		result.Profiles = append(result.Profiles, row)
	}
	for _, row := range rows.Credentials {
		row.PublicSPKI = append([]byte(nil), row.PublicSPKI...)
		result.Credentials = append(result.Credentials, row)
	}
	for _, row := range rows.Policies {
		row.FeedbackRouteID = cloneText(row.FeedbackRouteID)
		result.Policies = append(result.Policies, row)
	}
	for _, row := range rows.KeyMaterial {
		row.PublicSPKI = append([]byte(nil), row.PublicSPKI...)
		row.PrivatePKCS8 = append([]byte(nil), row.PrivatePKCS8...)
		result.KeyMaterial = append(result.KeyMaterial, row)
	}
	return result
}

// cloneText detaches one nullable canonical string.
func cloneText(value *string) *string {
	if value == nil {
		return nil
	}
	detached := *value
	return &detached
}

// clearRows erases every protected byte slice and releases identity strings.
func clearRows(rows *Rows) {
	if rows == nil {
		return
	}
	for index := range rows.Credentials {
		clear(rows.Credentials[index].PublicSPKI)
		rows.Credentials[index].PublicSPKI = nil
	}
	for index := range rows.KeyMaterial {
		clear(rows.KeyMaterial[index].PublicSPKI)
		clear(rows.KeyMaterial[index].PrivatePKCS8)
		rows.KeyMaterial[index].PublicSPKI = nil
		rows.KeyMaterial[index].PrivatePKCS8 = nil
	}
	*rows = Rows{}
}
