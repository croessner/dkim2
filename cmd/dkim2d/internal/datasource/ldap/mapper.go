// Package ldap maps bounded LDAP records into storage-neutral datasets.
package ldap

import (
	"bytes"
	"context"
	"strconv"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"github.com/croessner/dkim2/provider"
)

const schemaVersion = datasourceadmin.SchemaVersionV2

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
	attrPrivatePKCS8    = "dkim2PrivateKeyPKCS8"
	attrCandidateDigest = "dkim2CandidateDigest"
	attrOperationID     = "dkim2OperationID"
	attrSourceGeneration = "dkim2SourceGeneration"
	attrWasActive       = "dkim2WasActive"
	attrAdminLockOwner  = "dkim2AdminLockOwner"
	attrAdminRevision   = "dkim2AdminRevision"
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
	// RecordClassKeyMaterial identifies one native private signing key.
	RecordClassKeyMaterial RecordClass = "key_material"
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
	KeyMaterial []Entry
}

// MapNativeKeyMaterial validates and detaches one exact native LDAP key set.
func MapNativeKeyMaterial(
	entries []Entry,
	generation uint64,
) ([]*signingstore.NativeKeyMaterial, error) {
	if generation == 0 || len(entries) == 0 ||
		len(entries) > provider.HardLimits().MaxHandles {
		return nil, provider.NewError(provider.ErrorCodeMalformedData)
	}
	materials := make([]*signingstore.NativeKeyMaterial, 0, len(entries))
	success := false
	defer func() {
		if !success {
			closeNativeMaterials(materials)
		}
	}()
	for _, entry := range entries {
		entryGeneration, material, err := mapNativeKeyMaterial(entry)
		if err != nil || entryGeneration != generation {
			return nil, classifyMappingError(err)
		}
		materials = append(materials, material)
	}
	success = true
	return materials, nil
}

// mapNativeKeyMaterial validates one exact LDAP native-key record.
func mapNativeKeyMaterial(
	entry Entry,
) (uint64, *signingstore.NativeKeyMaterial, error) {
	values, err := exactAttributesWithLimit(entry, RecordClassKeyMaterial, []string{
		attrGeneration, attrTenantID, attrSigningDomain, attrProfileUse,
		attrHandleID, attrAlgorithm, attrPublicSPKI, attrPrivatePKCS8,
	}, nil, maxPrivateAttributeBytes)
	if err != nil {
		return 0, nil, err
	}
	defer clearAttributeValues(values)
	generation, err := parseGeneration(values[attrGeneration])
	if err != nil {
		return 0, nil, err
	}
	use, err := provider.ParseProfileUse(string(values[attrProfileUse]))
	if err != nil {
		return 0, nil, err
	}
	algorithm, err := parseLDAPAlgorithm(values[attrAlgorithm])
	if err != nil {
		return 0, nil, err
	}
	material, err := signingstore.NewNativeKeyMaterial(
		generation, string(values[attrTenantID]), string(values[attrSigningDomain]),
		use, string(values[attrHandleID]), algorithm,
		values[attrPublicSPKI], values[attrPrivatePKCS8],
	)
	if err != nil {
		return 0, nil, provider.NewError(provider.ErrorCodeMalformedData)
	}
	return generation, material, nil
}

// parseLDAPAlgorithm maps one exact native signing algorithm.
func parseLDAPAlgorithm(value []byte) (provider.Algorithm, error) {
	switch string(value) {
	case string(provider.AlgorithmRSASHA256):
		return provider.AlgorithmRSASHA256, nil
	case string(provider.AlgorithmEd25519SHA256):
		return provider.AlgorithmEd25519SHA256, nil
	default:
		return "", provider.NewError(provider.ErrorCodeMalformedData)
	}
}

// closeNativeMaterials clears every retained native-key value.
func closeNativeMaterials(materials []*signingstore.NativeKeyMaterial) {
	for _, material := range materials {
		_ = material.Close()
	}
}

// clearAttributeValues clears detached LDAP attribute buffers.
func clearAttributeValues(values map[string][]byte) {
	for name, value := range values {
		clear(value)
		delete(values, name)
	}
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
	current, err := mapCurrentMetadata(records.Current)
	if err != nil {
		return nil, err
	}
	root, err := mapGenerationMetadata(records.Root)
	if err != nil || !current.matchesRoot(root) {
		return nil, provider.NewError(provider.ErrorCodeMalformedData)
	}
	currentGeneration := current.generation
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
	dataset, err := provider.NewDataset(currentGeneration, handleIDs, profiles, policies, limits)
	if err != nil {
		return nil, err
	}
	if current.schema == datasourceadmin.SchemaVersionV3 && verifyV3CandidateDigest(records, root) != nil {
		return nil, provider.NewError(provider.ErrorCodeMalformedData)
	}
	return dataset, nil
}

type datasetMetadata struct {
	schema     string
	generation uint64
	state      datasourceadmin.GenerationState
	operation  datasourceadmin.OperationBinding
	digest     datasourceadmin.CandidateContentDigest
	sourceGeneration uint64
	wasActive  bool
}

// equal proves two bounded metadata reads are the same exact fence.
func (m datasetMetadata) equal(other datasetMetadata) bool {
	return m.schema == other.schema && m.generation == other.generation && m.state == other.state &&
		m.wasActive == other.wasActive && m.operation.Initialized() == other.operation.Initialized() &&
		(!m.operation.Initialized() || m.operation.Equal(other.operation)) &&
		m.digest.Valid() == other.digest.Valid() && (!m.digest.Valid() || m.digest.Equal(other.digest))
}

// mapCurrentMetadata validates one exact v2 or v3 committed current fence.
func mapCurrentMetadata(entry Entry) (datasetMetadata, error) {
	metadata, err := mapDatasetMetadata(entry, false)
	if err != nil || metadata.state != datasourceadmin.StateCommitted || metadata.wasActive ||
		metadata.schema == datasourceadmin.SchemaVersionV3 && metadata.operation.Initialized() {
		return datasetMetadata{}, provider.NewError(provider.ErrorCodeMalformedData)
	}
	return metadata, nil
}

// mapGenerationMetadata validates one exact v2 or v3 generation root.
func mapGenerationMetadata(entry Entry) (datasetMetadata, error) {
	return mapDatasetMetadata(entry, true)
}

// mapDatasetMetadata owns the closed v2/v3 LDAP metadata combinations.
func mapDatasetMetadata(entry Entry, root bool) (datasetMetadata, error) {
	values, err := exactAttributes(entry, RecordClassDataset, []string{
		attrSchemaVersion, attrGeneration, attrDatasetState,
	}, []string{attrCandidateDigest, attrOperationID, attrSourceGeneration, attrWasActive})
	if err != nil {
		return datasetMetadata{}, err
	}
	defer clearAttributeValues(values)
	metadata := datasetMetadata{schema: string(values[attrSchemaVersion])}
	metadata.generation, err = parseGeneration(values[attrGeneration])
	if err != nil {
		return datasetMetadata{}, err
	}
	switch string(values[attrDatasetState]) {
	case string(datasourceadmin.StateStaging):
		metadata.state = datasourceadmin.StateStaging
	case string(datasourceadmin.StateCommitted):
		metadata.state = datasourceadmin.StateCommitted
	default:
		return datasetMetadata{}, provider.NewError(provider.ErrorCodeMalformedData)
	}
	wasActive, wasActivePresent := values[attrWasActive]
	if wasActivePresent {
		if !root || metadata.state != datasourceadmin.StateCommitted || string(wasActive) != "TRUE" {
			return datasetMetadata{}, provider.NewError(provider.ErrorCodeMalformedData)
		}
		metadata.wasActive = true
	}
		digestBytes, digestPresent := values[attrCandidateDigest]
	operationBytes, operationPresent := values[attrOperationID]
	sourceBytes, sourcePresent := values[attrSourceGeneration]
	switch metadata.schema {
	case datasourceadmin.SchemaVersionV2:
		if digestPresent || operationPresent || sourcePresent || metadata.state != datasourceadmin.StateCommitted {
			return datasetMetadata{}, provider.NewError(provider.ErrorCodeMalformedData)
		}
	case datasourceadmin.SchemaVersionV3:
		if !digestPresent || root != operationPresent {
			return datasetMetadata{}, provider.NewError(provider.ErrorCodeMalformedData)
		}
		metadata.digest, err = datasourceadmin.ParseCandidateContentDigest(digestBytes)
		if err != nil {
			return datasetMetadata{}, provider.NewError(provider.ErrorCodeMalformedData)
		}
		if root {
			metadata.operation, err = datasourceadmin.NewOperationBinding(string(operationBytes))
			if err != nil {
				return datasetMetadata{}, provider.NewError(provider.ErrorCodeMalformedData)
			}
			if sourcePresent {
				metadata.sourceGeneration, err = parseGeneration(sourceBytes)
				if err != nil || metadata.sourceGeneration >= metadata.generation { return datasetMetadata{}, provider.NewError(provider.ErrorCodeMalformedData) }
			}
		}
	default:
		return datasetMetadata{}, provider.NewError(provider.ErrorCodeMalformedData)
	}
	return metadata, nil
}

// matchesRoot proves current and generation metadata form one nonmixed committed fence.
func (m datasetMetadata) matchesRoot(root datasetMetadata) bool {
	if m.schema != root.schema || m.generation != root.generation ||
		m.state != datasourceadmin.StateCommitted || root.state != datasourceadmin.StateCommitted {
		return false
	}
	if m.schema == datasourceadmin.SchemaVersionV3 {
		return m.digest.Valid() && root.digest.Valid() && m.digest.Equal(root.digest) &&
			root.operation.Initialized()
	}
	return !m.digest.Valid() && !root.digest.Valid() && !root.operation.Initialized()
}

// verifyV3CandidateDigest recomputes protected content from canonical LDAP readback.
func verifyV3CandidateDigest(records DatasetRecords, metadata datasetMetadata) error {
	rows, err := mapAdministrativeRows(records, metadata.generation)
	if err != nil {
		return err
	}
	defer clearAdministrativeRows(&rows)
	snapshot, err := datasourceadmin.NewSnapshot(
		datasourceadmin.SchemaVersionV3, metadata.generation, rows,
	)
	if err != nil {
		return provider.NewError(provider.ErrorCodeMalformedData)
	}
	content, err := datasourceadmin.NewCandidateContent(snapshot)
	if err != nil {
		_ = snapshot.Close()
		return provider.NewError(provider.ErrorCodeMalformedData)
	}
	var candidate *datasourceadmin.PublicationEnvelope
	if err := metadata.operation.WithValue(context.Background(), func(value string) error {
		var candidateErr error
		if metadata.sourceGeneration != 0 {
			candidate, candidateErr = datasourceadmin.NewCampaignPublicationEnvelope(value, metadata.sourceGeneration, content)
		} else {
			candidate, candidateErr = datasourceadmin.NewPublicationEnvelope(value, content)
		}
		return candidateErr
	}); err != nil || candidate == nil {
		_ = content.Close()
		return provider.NewError(provider.ErrorCodeMalformedData)
	}
	defer candidate.Close() //nolint:errcheck // Protected verification cleanup has no recovery action.
	if !candidate.Digest().Equal(metadata.digest) {
		return provider.NewError(provider.ErrorCodeMalformedData)
	}
	return nil
}

// mapAdministrativeRows maps every exact LDAP content class into neutral protected rows.
func mapAdministrativeRows(records DatasetRecords, generation uint64) (datasourceadmin.Rows, error) {
	rows := datasourceadmin.Rows{}
	success := false
	defer func() {
		if !success {
			clearAdministrativeRows(&rows)
		}
	}()
	for _, entry := range records.Handles {
		values, err := exactAttributes(entry, RecordClassHandle, []string{attrGeneration, attrHandleID}, nil)
		if err != nil || !generationValueMatches(values, generation) {
			clearAttributeValues(values)
			return datasourceadmin.Rows{}, provider.NewError(provider.ErrorCodeMalformedData)
		}
		rows.Handles = append(rows.Handles, datasourceadmin.HandleRow{ID: string(values[attrHandleID])})
		clearAttributeValues(values)
	}
	for _, entry := range records.Profiles {
		values, err := exactAttributes(entry, RecordClassProfile, []string{
			attrGeneration, attrProfileID, attrSigningDomain, attrRecordStatus,
		}, []string{attrNotBefore, attrNotAfter})
		if err != nil || !generationValueMatches(values, generation) {
			clearAttributeValues(values)
			return datasourceadmin.Rows{}, provider.NewError(provider.ErrorCodeMalformedData)
		}
		row := datasourceadmin.ProfileRow{
			ID: string(values[attrProfileID]), Domain: string(values[attrSigningDomain]),
			Status: string(values[attrRecordStatus]),
		}
		if value, present := values[attrNotBefore]; present {
			text := string(value)
			row.NotBeforeUTC = &text
		}
		if value, present := values[attrNotAfter]; present {
			text := string(value)
			row.NotAfterUTC = &text
		}
		rows.Profiles = append(rows.Profiles, row)
		clearAttributeValues(values)
	}
	for _, entry := range records.Credentials {
		values, err := exactAttributes(entry, RecordClassCredential, []string{
			attrGeneration, attrProfileID, attrAlgorithm, attrSelector, attrPublicSPKI, attrHandleID,
		}, nil)
		if err != nil || !generationValueMatches(values, generation) {
			clearAttributeValues(values)
			return datasourceadmin.Rows{}, provider.NewError(provider.ErrorCodeMalformedData)
		}
		rows.Credentials = append(rows.Credentials, datasourceadmin.CredentialRow{
			ProfileID: string(values[attrProfileID]), Algorithm: string(values[attrAlgorithm]),
			Selector: string(values[attrSelector]), PublicSPKI: bytes.Clone(values[attrPublicSPKI]),
			HandleID: string(values[attrHandleID]),
		})
		clearAttributeValues(values)
	}
	for _, entry := range records.Policies {
		values, err := exactAttributes(entry, RecordClassPolicy, []string{
			attrGeneration, attrTenantID, attrSigningDomain, attrProfileUse, attrProfileID,
			attrRecordStatus, attrRollout, attrCompatibility,
		}, []string{attrFeedbackRouteID})
		if err != nil || !generationValueMatches(values, generation) {
			clearAttributeValues(values)
			return datasourceadmin.Rows{}, provider.NewError(provider.ErrorCodeMalformedData)
		}
		row := datasourceadmin.PolicyRow{
			TenantID: string(values[attrTenantID]), Domain: string(values[attrSigningDomain]),
			Use: string(values[attrProfileUse]), ProfileID: string(values[attrProfileID]),
			Status: string(values[attrRecordStatus]), Rollout: string(values[attrRollout]),
			Compatibility: string(values[attrCompatibility]),
		}
		if value, present := values[attrFeedbackRouteID]; present {
			text := string(value)
			row.FeedbackRouteID = &text
		}
		rows.Policies = append(rows.Policies, row)
		clearAttributeValues(values)
	}
	for _, entry := range records.KeyMaterial {
		values, err := exactAttributesWithLimit(entry, RecordClassKeyMaterial, []string{
			attrGeneration, attrTenantID, attrSigningDomain, attrProfileUse, attrHandleID,
			attrAlgorithm, attrPublicSPKI, attrPrivatePKCS8,
		}, nil, maxPrivateAttributeBytes)
		if err != nil || !generationValueMatches(values, generation) {
			clearAttributeValues(values)
			return datasourceadmin.Rows{}, provider.NewError(provider.ErrorCodeMalformedData)
		}
		rows.KeyMaterial = append(rows.KeyMaterial, datasourceadmin.KeyMaterialRow{
			TenantID: string(values[attrTenantID]), Domain: string(values[attrSigningDomain]),
			Use: string(values[attrProfileUse]), HandleID: string(values[attrHandleID]),
			Algorithm: string(values[attrAlgorithm]), PublicSPKI: bytes.Clone(values[attrPublicSPKI]),
			PrivatePKCS8: bytes.Clone(values[attrPrivatePKCS8]),
		})
		clearAttributeValues(values)
	}
	success = true
	return rows, nil
}

// generationValueMatches validates one canonical row generation.
func generationValueMatches(values map[string][]byte, generation uint64) bool {
	parsed, err := parseGeneration(values[attrGeneration])
	return err == nil && parsed == generation
}

// clearAdministrativeRows destroys every detached LDAP public/private key buffer.
func clearAdministrativeRows(rows *datasourceadmin.Rows) {
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
	*rows = datasourceadmin.Rows{}
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
	return exactAttributesWithLimit(entry, class, required, optional, 4096)
}

const maxPrivateAttributeBytes = 64 << 10

// exactAttributesWithLimit validates one closed attribute projection with an
// explicit per-value bound for protected native key records.
func exactAttributesWithLimit(
	entry Entry,
	class RecordClass,
	required []string,
	optional []string,
	maximumValueBytes int,
) (output map[string][]byte, resultErr error) {
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
	output = make(map[string][]byte, len(entry.Attributes))
	defer func() {
		if resultErr != nil {
			clearAttributeValues(output)
			output = nil
		}
	}()
	total := 0
	for name, values := range entry.Attributes {
		if !allowed[name] || len(values) != 1 || values[0] == nil {
			return nil, provider.NewError(provider.ErrorCodeMalformedData)
		}
		if len(values[0]) > maximumValueBytes || total > (1<<20)-len(values[0]) {
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
