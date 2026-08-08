// Package sqlsnapshot maps fixed SQL rows into storage-neutral datasets.
package sqlsnapshot

import (
	"bytes"
	"context"
	"strconv"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"github.com/croessner/dkim2/provider"
)

// MetadataRow is one explicit dataset metadata projection.
type MetadataRow struct {
	Generation      string
	SchemaVersion   string
	DatasetState    string
	OperationID     *string
	CandidateDigest []byte
	SourceGeneration string
	PointerDigest   []byte
	WasActive       bool
}

// HandleRow is one explicit opaque handle projection.
type HandleRow struct {
	Generation string
	HandleID   string
}

// ProfileRow is one explicit profile projection.
type ProfileRow struct {
	Generation   string
	ProfileID    string
	Domain       string
	Status       string
	NotBeforeUTC *string
	NotAfterUTC  *string
}

// CredentialRow is one explicit public credential projection.
type CredentialRow struct {
	Generation    string
	ProfileID     string
	Algorithm     string
	Selector      string
	PublicKeySPKI []byte
	HandleID      string
}

// PolicyRow is one explicit administrative policy projection.
type PolicyRow struct {
	Generation      string
	TenantID        string
	Domain          string
	Use             string
	ProfileID       string
	Status          string
	Rollout         string
	Compatibility   string
	FeedbackRouteID *string
}

// KeyMaterialRow is one explicit native private-key projection.
type KeyMaterialRow struct {
	Generation   string
	TenantID     string
	Domain       string
	Use          string
	HandleID     string
	Algorithm    string
	PublicSPKI   []byte
	PrivatePKCS8 []byte
}

// DatasetRows contains one transactionally fenced exact generation.
type DatasetRows struct {
	Current     MetadataRow
	Final       MetadataRow
	Handles     []HandleRow
	Profiles    []ProfileRow
	Credentials []CredentialRow
	Policies    []PolicyRow
	KeyMaterial []KeyMaterialRow
}

// MapNativeKeyMaterial validates and detaches one exact native SQL key set.
func MapNativeKeyMaterial(
	rows []KeyMaterialRow,
	generation uint64,
) ([]*signingstore.NativeKeyMaterial, error) {
	if generation == 0 || len(rows) == 0 || len(rows) > provider.HardLimits().MaxHandles {
		return nil, provider.NewError(provider.ErrorCodeMalformedData)
	}
	materials := make([]*signingstore.NativeKeyMaterial, 0, len(rows))
	success := false
	defer func() {
		if !success {
			closeNativeMaterials(materials)
		}
	}()
	for _, row := range rows {
		rowGeneration, err := parseGeneration(row.Generation)
		if err != nil || rowGeneration != generation {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		use, err := provider.ParseProfileUse(row.Use)
		if err != nil {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		algorithm, err := parseAlgorithm(row.Algorithm)
		if err != nil {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		material, err := signingstore.NewNativeKeyMaterial(
			generation, row.TenantID, row.Domain, use, row.HandleID, algorithm,
			row.PublicSPKI, row.PrivatePKCS8,
		)
		if err != nil {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		materials = append(materials, material)
	}
	success = true
	return materials, nil
}

// closeNativeMaterials clears every retained native SQL key value.
func closeNativeMaterials(materials []*signingstore.NativeKeyMaterial) {
	for _, material := range materials {
		_ = material.Close()
	}
}

// clearKeyMaterialRows clears detached SQL public and private key buffers.
func clearKeyMaterialRows(rows []KeyMaterialRow) {
	for index := range rows {
		clear(rows[index].PublicSPKI)
		clear(rows[index].PrivatePKCS8)
		rows[index].PublicSPKI = nil
		rows[index].PrivatePKCS8 = nil
	}
}

// ClearKeyMaterialRows clears detached SQL public and private key buffers.
func ClearKeyMaterialRows(rows []KeyMaterialRow) {
	clearKeyMaterialRows(rows)
}

type assembledProfile struct {
	id          string
	domain      string
	status      provider.RecordStatus
	notBefore   time.Time
	notAfter    time.Time
	credentials []provider.Credential
}

// MapDataset validates one stable row snapshot through provider-neutral owners.
//
//nolint:gocyclo // The fixed row classes retain explicit independent validation.
func MapDataset(rows DatasetRows, limits provider.Limits) (*provider.Dataset, error) {
	if limits.Validate() != nil {
		return nil, provider.NewError(provider.ErrorCodeInvalidRequest)
	}
	generation, err := mapMetadata(rows.Current)
	if err != nil {
		return nil, err
	}
	finalGeneration, err := mapMetadata(rows.Final)
	if err != nil || finalGeneration != generation || !metadataEqual(rows.Current, rows.Final) {
		return nil, provider.NewError(provider.ErrorCodeUnavailable)
	}
	handles := make([]string, 0, len(rows.Handles))
	for _, row := range rows.Handles {
		rowGeneration, mapErr := parseGeneration(row.Generation)
		if mapErr != nil || rowGeneration != generation {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		handles = append(handles, row.HandleID)
	}
	profiles := make([]assembledProfile, 0, len(rows.Profiles))
	for _, row := range rows.Profiles {
		rowGeneration, mapErr := parseGeneration(row.Generation)
		if mapErr != nil || rowGeneration != generation {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		status, mapErr := provider.ParseRecordStatus(row.Status)
		if mapErr != nil {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		notBefore, notAfter, mapErr := parseValidity(row.NotBeforeUTC, row.NotAfterUTC)
		if mapErr != nil {
			return nil, mapErr
		}
		profiles = append(profiles, assembledProfile{
			id: row.ProfileID, domain: row.Domain, status: status,
			notBefore: notBefore, notAfter: notAfter,
		})
	}
	for _, row := range rows.Credentials {
		rowGeneration, mapErr := parseGeneration(row.Generation)
		if mapErr != nil || rowGeneration != generation {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		algorithm, mapErr := parseAlgorithm(row.Algorithm)
		if mapErr != nil {
			return nil, mapErr
		}
		credential, mapErr := provider.NewCredential(
			row.Selector, algorithm, row.PublicKeySPKI, row.HandleID, limits,
		)
		if mapErr != nil {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		matches := 0
		for index := range profiles {
			if profiles[index].id == row.ProfileID {
				profiles[index].credentials = append(profiles[index].credentials, credential)
				matches++
			}
		}
		if matches != 1 {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
	}
	neutralProfiles := make([]provider.Profile, 0, len(profiles))
	for _, row := range profiles {
		profile, mapErr := provider.NewProfile(
			row.id, row.domain, row.status, row.credentials,
			row.notBefore, row.notAfter, limits,
		)
		if mapErr != nil {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		neutralProfiles = append(neutralProfiles, profile)
	}
	policies := make([]provider.Policy, 0, len(rows.Policies))
	for _, row := range rows.Policies {
		rowGeneration, mapErr := parseGeneration(row.Generation)
		if mapErr != nil || rowGeneration != generation {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		use, mapErr := provider.ParseProfileUse(row.Use)
		if mapErr != nil {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		status, mapErr := provider.ParseRecordStatus(row.Status)
		if mapErr != nil {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		rollout, mapErr := provider.ParseRollout(row.Rollout)
		if mapErr != nil {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		compatibility, mapErr := provider.ParseCompatibility(row.Compatibility)
		if mapErr != nil {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		feedback := ""
		if row.FeedbackRouteID != nil {
			feedback = *row.FeedbackRouteID
		}
		policy, mapErr := provider.NewPolicy(
			row.TenantID, row.Domain, use, row.ProfileID, status,
			rollout, compatibility, feedback, limits,
		)
		if mapErr != nil {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		policies = append(policies, policy)
	}
	dataset, err := provider.NewDataset(generation, handles, neutralProfiles, policies, limits)
	if err != nil {
		return nil, err
	}
	if err := verifyProtectedGeneration(rows, generation); err != nil {
		return nil, err
	}
	return dataset, nil
}

// mapMetadata validates exact committed metadata.
func mapMetadata(row MetadataRow) (uint64, error) {
	if row.DatasetState != datasetStateCommitted ||
		row.SchemaVersion != datasourceadmin.SchemaVersionV2 &&
			row.SchemaVersion != datasourceadmin.SchemaVersionV3 {
		return 0, provider.NewError(provider.ErrorCodeMalformedData)
	}
	if row.SchemaVersion == datasourceadmin.SchemaVersionV2 &&
		(row.OperationID != nil || len(row.CandidateDigest) != 0 || len(row.PointerDigest) != 0) ||
		row.SchemaVersion == datasourceadmin.SchemaVersionV3 &&
			(row.OperationID == nil || len(row.CandidateDigest) != 32 ||
				len(row.PointerDigest) != 32 || !bytes.Equal(row.CandidateDigest, row.PointerDigest)) {
		return 0, provider.NewError(provider.ErrorCodeMalformedData)
	}
	return parseGeneration(row.Generation)
}

// metadataEqual compares the complete stable current-generation fence.
func metadataEqual(left, right MetadataRow) bool {
	if left.Generation != right.Generation || left.SchemaVersion != right.SchemaVersion ||
		left.DatasetState != right.DatasetState || left.WasActive != right.WasActive ||
		!bytes.Equal(left.CandidateDigest, right.CandidateDigest) ||
		!bytes.Equal(left.PointerDigest, right.PointerDigest) ||
		(left.OperationID == nil) != (right.OperationID == nil) {
		return false
	}
	return left.OperationID == nil || *left.OperationID == *right.OperationID
}

// verifyProtectedGeneration reconstructs the complete canonical private
// candidate so v3 runtime publication cannot trust metadata alone.
func verifyProtectedGeneration(rows DatasetRows, generation uint64) error {
	protected := administrativeRows(rows)
	defer clearAdministrativeRows(&protected)
	snapshot, err := datasourceadmin.NewSnapshot(rows.Current.SchemaVersion, generation, protected)
	if err != nil {
		return provider.NewError(provider.ErrorCodeMalformedData)
	}
	if rows.Current.SchemaVersion == datasourceadmin.SchemaVersionV2 {
		_ = snapshot.Close()
		return nil
	}
	binding, err := datasourceadmin.NewOperationBinding(*rows.Current.OperationID)
	if err != nil {
		_ = snapshot.Close()
		return provider.NewError(provider.ErrorCodeMalformedData)
	}
	content, err := datasourceadmin.NewCandidateContent(snapshot)
	if err != nil {
		_ = snapshot.Close()
		return provider.NewError(provider.ErrorCodeMalformedData)
	}
	var candidate *datasourceadmin.PublicationEnvelope
	err = binding.WithValue(
		context.Background(),
		func(operation string) error {
			var candidateErr error
		if rows.Current.SourceGeneration != "" {
			source, sourceErr := parseGeneration(rows.Current.SourceGeneration)
			if sourceErr != nil { return sourceErr }
			candidate, candidateErr = datasourceadmin.NewCampaignPublicationEnvelope(operation, source, content)
		} else {
			candidate, candidateErr = datasourceadmin.NewPublicationEnvelope(operation, content)
		}
			return candidateErr
		},
	)
	if err != nil || candidate == nil {
		_ = content.Close()
		return provider.NewError(provider.ErrorCodeMalformedData)
	}
	defer candidate.Close() //nolint:errcheck // Protected readback cleanup has no recovery action.
	stored, err := datasourceadmin.ParseCandidateContentDigest(rows.Current.CandidateDigest)
	if err != nil || !candidate.Digest().Equal(stored) {
		return provider.NewError(provider.ErrorCodeMalformedData)
	}
	return nil
}

// administrativeRows projects generation-fenced scan DTOs into the single
// protected datasource administration model.
func administrativeRows(rows DatasetRows) datasourceadmin.Rows {
	result := datasourceadmin.Rows{}
	for _, row := range rows.Handles {
		result.Handles = append(result.Handles, datasourceadmin.HandleRow{ID: row.HandleID})
	}
	for _, row := range rows.Profiles {
		result.Profiles = append(result.Profiles, datasourceadmin.ProfileRow{
			ID: row.ProfileID, Domain: row.Domain, Status: row.Status,
			NotBeforeUTC: cloneNullableText(row.NotBeforeUTC), NotAfterUTC: cloneNullableText(row.NotAfterUTC),
		})
	}
	for _, row := range rows.Credentials {
		result.Credentials = append(result.Credentials, datasourceadmin.CredentialRow{
			ProfileID: row.ProfileID, Algorithm: row.Algorithm, Selector: row.Selector,
			PublicSPKI: append([]byte(nil), row.PublicKeySPKI...), HandleID: row.HandleID,
		})
	}
	for _, row := range rows.Policies {
		result.Policies = append(result.Policies, datasourceadmin.PolicyRow{
			TenantID: row.TenantID, Domain: row.Domain, Use: row.Use, ProfileID: row.ProfileID,
			Status: row.Status, Rollout: row.Rollout, Compatibility: row.Compatibility,
			FeedbackRouteID: cloneNullableText(row.FeedbackRouteID),
		})
	}
	for _, row := range rows.KeyMaterial {
		result.KeyMaterial = append(result.KeyMaterial, datasourceadmin.KeyMaterialRow{
			TenantID: row.TenantID, Domain: row.Domain, Use: row.Use, HandleID: row.HandleID,
			Algorithm: row.Algorithm, PublicSPKI: append([]byte(nil), row.PublicSPKI...),
			PrivatePKCS8: append([]byte(nil), row.PrivatePKCS8...),
		})
	}
	return result
}

// cloneNullableText detaches one exact optional SQL text value.
func cloneNullableText(value *string) *string {
	if value == nil {
		return nil
	}
	detached := *value
	return &detached
}

// clearAdministrativeRows erases every protected byte buffer.
func clearAdministrativeRows(rows *datasourceadmin.Rows) {
	if rows == nil {
		return
	}
	for index := range rows.Credentials {
		clear(rows.Credentials[index].PublicSPKI)
	}
	for index := range rows.KeyMaterial {
		clear(rows.KeyMaterial[index].PublicSPKI)
		clear(rows.KeyMaterial[index].PrivatePKCS8)
	}
	*rows = datasourceadmin.Rows{}
}

// parseGeneration preserves canonical full-range unsigned decimal values.
func parseGeneration(value string) (uint64, error) {
	if value == "" || len(value) > 20 || len(value) > 1 && value[0] == '0' {
		return 0, provider.NewError(provider.ErrorCodeMalformedData)
	}
	generation, err := strconv.ParseUint(value, 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != value {
		return 0, provider.NewError(provider.ErrorCodeMalformedData)
	}
	return generation, nil
}

// parseValidity validates an all-or-none exact UTC RFC3339Nano interval.
func parseValidity(before, after *string) (time.Time, time.Time, error) {
	if (before == nil) != (after == nil) {
		return time.Time{}, time.Time{}, provider.NewError(provider.ErrorCodeMalformedData)
	}
	if before == nil {
		return time.Time{}, time.Time{}, nil
	}
	start, err := parseTime(*before)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	end, err := parseTime(*after)
	if err != nil || !start.Before(end) {
		return time.Time{}, time.Time{}, provider.NewError(provider.ErrorCodeMalformedData)
	}
	return start, end, nil
}

// parseTime accepts only canonical UTC RFC3339Nano text.
func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, provider.NewError(provider.ErrorCodeMalformedData)
	}
	return parsed, nil
}

// parseAlgorithm maps one exact closed algorithm string.
func parseAlgorithm(value string) (provider.Algorithm, error) {
	switch value {
	case string(provider.AlgorithmRSASHA256):
		return provider.AlgorithmRSASHA256, nil
	case string(provider.AlgorithmEd25519SHA256):
		return provider.AlgorithmEd25519SHA256, nil
	default:
		return "", provider.NewError(provider.ErrorCodeMalformedData)
	}
}
