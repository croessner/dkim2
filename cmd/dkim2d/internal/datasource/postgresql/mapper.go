// Package postgresql maps fixed PostgreSQL rows into storage-neutral datasets.
package postgresql

import (
	"strconv"
	"time"

	"github.com/croessner/dkim2/provider"
)

const schemaVersion = "dkim2-datasource-v1"

// MetadataRow is one explicit dataset metadata projection.
type MetadataRow struct {
	Generation    string
	SchemaVersion string
	DatasetState  string
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

// DatasetRows contains one transactionally fenced exact generation.
type DatasetRows struct {
	Current     MetadataRow
	Final       MetadataRow
	Handles     []HandleRow
	Profiles    []ProfileRow
	Credentials []CredentialRow
	Policies    []PolicyRow
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
	if err != nil || finalGeneration != generation {
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
	return provider.NewDataset(generation, handles, neutralProfiles, policies, limits)
}

// mapMetadata validates exact committed metadata.
func mapMetadata(row MetadataRow) (uint64, error) {
	if row.SchemaVersion != schemaVersion || row.DatasetState != "committed" {
		return 0, provider.NewError(provider.ErrorCodeMalformedData)
	}
	return parseGeneration(row.Generation)
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
