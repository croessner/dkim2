// Package ldap maps bounded LDAP records into storage-neutral datasets.
package ldap

import (
	"bytes"
	"strconv"
	"time"

	"github.com/croessner/dkim2/provider"
)

const schemaVersion = "dkim2-datasource-v1"

const (
	attrObjectClass     = "objectClass"
	attrSchemaVersion   = "dkim2SchemaVersion"
	attrGeneration      = "dkim2Generation"
	attrDatasetState    = "dkim2DatasetState"
	attrHandleID        = "dkim2HandleID"
	attrProfileID       = "dkim2ProfileID"
	attrSigningDomain   = "dkim2SigningDomain"
	attrRecordStatus    = "dkim2RecordStatus"
	attrNotBefore       = "dkim2NotBefore"
	attrNotAfter        = "dkim2NotAfter"
	attrAlgorithm       = "dkim2Algorithm"
	attrSelector        = "dkim2Selector"
	attrPublicSPKI      = "dkim2PublicKeySPKI"
	attrTenantID        = "dkim2TenantID"
	attrProfileUse      = "dkim2ProfileUse"
	attrRollout         = "dkim2Rollout"
	attrCompatibility   = "dkim2Compatibility"
	attrFeedbackRouteID = "dkim2FeedbackRouteID"
)

// RecordClass identifies one closed LDAP record mapping.
type RecordClass string

const (
	// RecordClassDataset identifies current or generation metadata.
	RecordClassDataset RecordClass = "dataset"
	// RecordClassHandle identifies an opaque handle declaration.
	RecordClassHandle RecordClass = "handle"
	// RecordClassProfile identifies a signing profile.
	RecordClassProfile RecordClass = "profile"
	// RecordClassCredential identifies one public credential.
	RecordClassCredential RecordClass = "credential"
	// RecordClassPolicy identifies one exact administrative policy.
	RecordClassPolicy RecordClass = "policy"
)

// Entry is one bounded backend record with only explicitly requested attributes.
type Entry struct {
	Class      RecordClass
	Attributes map[string][][]byte
}

// DatasetRecords contains one fenced complete LDAP generation.
type DatasetRecords struct {
	Current     Entry
	Root        Entry
	Handles     []Entry
	Profiles    []Entry
	Credentials []Entry
	Policies    []Entry
}

type profileRecord struct {
	id        string
	domain    string
	status    provider.RecordStatus
	notBefore time.Time
	notAfter  time.Time
}

type credentialRecord struct {
	profileID string
	value     provider.Credential
}

// MapDataset validates one fenced record set through the storage-neutral owner.
func MapDataset(records DatasetRecords, limits provider.Limits) (*provider.Dataset, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	currentGeneration, err := mapMetadata(records.Current)
	if err != nil {
		return nil, err
	}
	rootGeneration, err := mapMetadata(records.Root)
	if err != nil || currentGeneration != rootGeneration {
		return nil, provider.NewError(provider.ErrorCodeMalformedData)
	}
	handleIDs := make([]string, 0, len(records.Handles))
	for _, entry := range records.Handles {
		generation, handle, mapErr := mapHandle(entry)
		if mapErr != nil || generation != currentGeneration {
			return nil, classifyMappingError(mapErr)
		}
		handleIDs = append(handleIDs, handle)
	}
	profileRecords := make([]profileRecord, 0, len(records.Profiles))
	for _, entry := range records.Profiles {
		generation, record, mapErr := mapProfile(entry)
		if mapErr != nil || generation != currentGeneration {
			return nil, classifyMappingError(mapErr)
		}
		profileRecords = append(profileRecords, record)
	}
	credentialRecords := make([]credentialRecord, 0, len(records.Credentials))
	for _, entry := range records.Credentials {
		generation, record, mapErr := mapCredential(entry, limits)
		if mapErr != nil || generation != currentGeneration {
			return nil, classifyMappingError(mapErr)
		}
		credentialRecords = append(credentialRecords, record)
	}
	profiles := make([]provider.Profile, 0, len(profileRecords))
	for _, record := range profileRecords {
		credentials := make([]provider.Credential, 0, limits.MaxCredentialsPerProfile)
		for _, credential := range credentialRecords {
			if credential.profileID == record.id {
				credentials = append(credentials, credential.value)
			}
		}
		profile, profileErr := provider.NewProfile(
			record.id, record.domain, record.status, credentials,
			record.notBefore, record.notAfter, limits,
		)
		if profileErr != nil {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		profiles = append(profiles, profile)
	}
	policies := make([]provider.Policy, 0, len(records.Policies))
	for _, entry := range records.Policies {
		generation, policy, mapErr := mapPolicy(entry, limits)
		if mapErr != nil || generation != currentGeneration {
			return nil, classifyMappingError(mapErr)
		}
		policies = append(policies, policy)
	}
	return provider.NewDataset(currentGeneration, handleIDs, profiles, policies, limits)
}

// mapMetadata validates one exact committed datasource metadata entry.
func mapMetadata(entry Entry) (uint64, error) {
	values, err := exactAttributes(entry, RecordClassDataset, []string{
		attrSchemaVersion, attrGeneration, attrDatasetState,
	}, nil)
	if err != nil || string(values[attrSchemaVersion]) != schemaVersion ||
		string(values[attrDatasetState]) != "committed" {
		return 0, provider.NewError(provider.ErrorCodeMalformedData)
	}
	return parseGeneration(values[attrGeneration])
}

// mapHandle validates one exact opaque handle declaration.
func mapHandle(entry Entry) (uint64, string, error) {
	values, err := exactAttributes(entry, RecordClassHandle, []string{
		attrGeneration, attrHandleID,
	}, nil)
	if err != nil {
		return 0, "", err
	}
	generation, err := parseGeneration(values[attrGeneration])
	if err != nil {
		return 0, "", err
	}
	handle := string(values[attrHandleID])
	if len(handle) == 0 || len(handle) > provider.HardLimits().MaxIdentifierBytes {
		return 0, "", provider.NewError(provider.ErrorCodeMalformedData)
	}
	return generation, handle, nil
}

// mapProfile validates one exact profile record before credential assembly.
func mapProfile(entry Entry) (uint64, profileRecord, error) {
	values, err := exactAttributes(entry, RecordClassProfile, []string{
		attrGeneration, attrProfileID, attrSigningDomain, attrRecordStatus,
	}, []string{attrNotBefore, attrNotAfter})
	if err != nil {
		return 0, profileRecord{}, err
	}
	generation, err := parseGeneration(values[attrGeneration])
	if err != nil {
		return 0, profileRecord{}, err
	}
	status, err := provider.ParseRecordStatus(string(values[attrRecordStatus]))
	if err != nil {
		return 0, profileRecord{}, err
	}
	notBeforeText, beforePresent := values[attrNotBefore]
	notAfterText, afterPresent := values[attrNotAfter]
	if beforePresent != afterPresent {
		return 0, profileRecord{}, provider.NewError(provider.ErrorCodeMalformedData)
	}
	var notBefore, notAfter time.Time
	if beforePresent {
		notBefore, err = parseCanonicalTime(notBeforeText)
		if err == nil {
			notAfter, err = parseCanonicalTime(notAfterText)
		}
		if err != nil {
			return 0, profileRecord{}, err
		}
	}
	return generation, profileRecord{
		id: string(values[attrProfileID]), domain: string(values[attrSigningDomain]),
		status: status, notBefore: notBefore, notAfter: notAfter,
	}, nil
}

// mapCredential validates one exact public credential record.
func mapCredential(entry Entry, limits provider.Limits) (uint64, credentialRecord, error) {
	values, err := exactAttributes(entry, RecordClassCredential, []string{
		attrGeneration, attrProfileID, attrAlgorithm, attrSelector,
		attrPublicSPKI, attrHandleID,
	}, nil)
	if err != nil {
		return 0, credentialRecord{}, err
	}
	generation, err := parseGeneration(values[attrGeneration])
	if err != nil {
		return 0, credentialRecord{}, err
	}
	var algorithm provider.Algorithm
	switch string(values[attrAlgorithm]) {
	case string(provider.AlgorithmRSASHA256):
		algorithm = provider.AlgorithmRSASHA256
	case string(provider.AlgorithmEd25519SHA256):
		algorithm = provider.AlgorithmEd25519SHA256
	default:
		return 0, credentialRecord{}, provider.NewError(provider.ErrorCodeMalformedData)
	}
	credential, err := provider.NewCredential(
		string(values[attrSelector]), algorithm,
		values[attrPublicSPKI], string(values[attrHandleID]), limits,
	)
	if err != nil {
		return 0, credentialRecord{}, provider.NewError(provider.ErrorCodeMalformedData)
	}
	return generation, credentialRecord{
		profileID: string(values[attrProfileID]), value: credential,
	}, nil
}

// mapPolicy validates one exact administrative policy record.
func mapPolicy(entry Entry, limits provider.Limits) (uint64, provider.Policy, error) {
	values, err := exactAttributes(entry, RecordClassPolicy, []string{
		attrGeneration, attrTenantID, attrSigningDomain,
		attrProfileUse, attrProfileID, attrRecordStatus,
		attrRollout, attrCompatibility,
	}, []string{attrFeedbackRouteID})
	if err != nil {
		return 0, provider.Policy{}, err
	}
	generation, err := parseGeneration(values[attrGeneration])
	if err != nil {
		return 0, provider.Policy{}, err
	}
	use, err := provider.ParseProfileUse(string(values[attrProfileUse]))
	if err != nil {
		return 0, provider.Policy{}, err
	}
	status, err := provider.ParseRecordStatus(string(values[attrRecordStatus]))
	if err != nil {
		return 0, provider.Policy{}, err
	}
	rollout, err := provider.ParseRollout(string(values[attrRollout]))
	if err != nil {
		return 0, provider.Policy{}, err
	}
	compatibility, err := provider.ParseCompatibility(string(values[attrCompatibility]))
	if err != nil {
		return 0, provider.Policy{}, err
	}
	policy, err := provider.NewPolicy(
		string(values[attrTenantID]), string(values[attrSigningDomain]), use,
		string(values[attrProfileID]), status, rollout, compatibility,
		string(values[attrFeedbackRouteID]), limits,
	)
	if err != nil {
		return 0, provider.Policy{}, provider.NewError(provider.ErrorCodeMalformedData)
	}
	return generation, policy, nil
}

// exactAttributes checks class, allowlist, singleton cardinality, and bounds.
func exactAttributes(
	entry Entry,
	class RecordClass,
	required []string,
	optional []string,
) (map[string][]byte, error) {
	if entry.Class != class || len(entry.Attributes) > 18 {
		return nil, provider.NewError(provider.ErrorCodeMalformedData)
	}
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, name := range required {
		allowed[name] = true
	}
	for _, name := range optional {
		allowed[name] = true
	}
	output := make(map[string][]byte, len(entry.Attributes))
	total := 0
	for name, values := range entry.Attributes {
		if !allowed[name] || len(values) != 1 || values[0] == nil {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		if len(values[0]) > 4096 || total > (1<<20)-len(values[0]) {
			return nil, provider.NewError(provider.ErrorCodeLimitExceeded)
		}
		total += len(values[0])
		output[name] = bytes.Clone(values[0])
	}
	for _, name := range required {
		if _, found := output[name]; !found {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
	}
	return output, nil
}

// parseGeneration parses one canonical full-range unsigned decimal generation.
func parseGeneration(value []byte) (uint64, error) {
	if len(value) == 0 || len(value) > 20 || len(value) > 1 && value[0] == '0' {
		return 0, provider.NewError(provider.ErrorCodeMalformedData)
	}
	generation, err := strconv.ParseUint(string(value), 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != string(value) {
		return 0, provider.NewError(provider.ErrorCodeMalformedData)
	}
	return generation, nil
}

// parseCanonicalTime parses exact UTC RFC3339Nano text.
func parseCanonicalTime(value []byte) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, string(value))
	if err != nil || parsed.Location() != time.UTC ||
		parsed.Format(time.RFC3339Nano) != string(value) {
		return time.Time{}, provider.NewError(provider.ErrorCodeMalformedData)
	}
	return parsed, nil
}

// classifyMappingError preserves known failures and closes mismatches.
func classifyMappingError(err error) error {
	if err == nil {
		return provider.NewError(provider.ErrorCodeMalformedData)
	}
	if provider.ErrorCodeOf(err) == provider.ErrorCodeInternalInvariant {
		return provider.NewError(provider.ErrorCodeMalformedData)
	}
	return err
}
