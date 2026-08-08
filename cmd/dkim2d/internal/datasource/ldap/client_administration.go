package ldap

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
	goldap "github.com/go-ldap/ldap/v3"
)

const (
	datasetObjectClass                = "dkim2Dataset"
	administrativeMetadataObjectClass = "dkim2AdministrativeMetadata"
	administrationLockObjectClass     = "dkim2AdministrationLock"
	topObjectClass                    = "top"
	handleObjectClass                 = "dkim2Handle"
	profileObjectClass                = "dkim2Profile"
	credentialObjectClass             = "dkim2Credential"
	policyObjectClass                 = "dkim2Policy"
	keyMaterialObjectClass            = "dkim2KeyMaterial"
	handlesUnit                       = "handles"
	profilesUnit                      = "profiles"
	credentialsUnit                   = "credentials"
	policiesUnit                      = "policies"
	keyMaterialUnit                   = "key-material"
)

var generationUnits = []string{handlesUnit, profilesUnit, credentialsUnit, policiesUnit, keyMaterialUnit}

// ReadCurrentOptional reads exact current metadata or proves the current DN absent.
func (c *goLDAPClient) ReadCurrentOptional(ctx context.Context) (Entry, bool, error) {
	entry, present, err := c.readOptionalMetadata(ctx, "cn=current,"+c.baseDN)
	return entry, present, err
}

// readOptionalMetadata performs one bounded base-object metadata search.
func (c *goLDAPClient) readOptionalMetadata(ctx context.Context, base string) (Entry, bool, error) {
	request := goldap.NewSearchRequest(
		base, goldap.ScopeBaseObject, goldap.NeverDerefAliases, 2, 0, false,
		"(objectClass=dkim2Dataset)",
		[]string{
			attrSchemaVersion, attrGeneration, attrDatasetState,
			attrCandidateDigest, attrOperationID, attrSourceGeneration, attrWasActive,
		}, nil,
	)
	request.EnforceSizeLimit = true
	result, err := c.search(ctx, request)
	if goldap.IsErrorWithCode(err, goldap.LDAPResultNoSuchObject) {
		return Entry{}, false, nil
	}
	if err != nil || result == nil || len(result.Referrals) != 0 || len(result.Entries) != 1 {
		return Entry{}, false, errors.New("ldap metadata unavailable")
	}
	defer clearLDAPProtectedAttributeBytes(result.Entries)
	entry, err := convertEntry(RecordClassDataset, result.Entries[0])
	if err != nil {
		return Entry{}, false, errors.New("ldap metadata unavailable")
	}
	return entry, true, nil
}

// ListGenerationRoots returns every bounded generation root through critical paging.
func (c *goLDAPClient) ListGenerationRoots(
	ctx context.Context,
	limits datasourceadmin.GenerationLimits,
) ([]Entry, error) {
	return listGenerationRoots(ctx, "ou=generations,"+c.baseDN, limits, c.search)
}

// ListRetentionGenerationRoots reads the separate bounded historical-recovery inventory.
func (c *goLDAPClient) ListRetentionGenerationRoots(ctx context.Context, limits datasourceadmin.RetentionRecoveryLimits) ([]Entry, error) {
	return listRetentionGenerationRoots(ctx, "ou=generations,"+c.baseDN, limits, c.search)
}

// ldapSearchOperation is the narrow transport seam owned by bounded
// administration paging.
type ldapSearchOperation func(context.Context, *goldap.SearchRequest) (*goldap.SearchResult, error)

// listGenerationRoots validates every page as one globally unique, complete
// direct-child inventory and requires critical opaque-cookie paging.
func listGenerationRoots(
	ctx context.Context,
	base string,
	limits datasourceadmin.GenerationLimits,
	search ldapSearchOperation,
) ([]Entry, error) {
	if ctx == nil || base == "" || limits.Validate() != nil || search == nil {
		return nil, errors.New("ldap inventory unavailable")
	}
	entries := make([]Entry, 0, min(int(limits.MaxGenerations), 64))
	seen := make(map[uint64]struct{}, min(int(limits.MaxGenerations), 64))
	success := false
	defer func() {
		if !success {
			clearEntries(entries)
		}
	}()
	cookie := []byte(nil)
	bytesRead := 0
	for pages := uint32(0); pages <= limits.MaxGenerations; pages++ {
		pageSize := min(int(limits.MaxGenerations)+1, 256)
		control := newCriticalPagingControl(uint32(pageSize), cookie)
		request := goldap.NewSearchRequest(
			base, goldap.ScopeSingleLevel, goldap.NeverDerefAliases,
			int(limits.MaxGenerations)+1, 0, false, "(objectClass=*)",
			[]string{"*"}, []goldap.Control{control},
		)
		request.EnforceSizeLimit = true
		result, err := search(ctx, request)
		if err != nil || result == nil || len(result.Referrals) != 0 {
			return nil, errors.New("ldap inventory unavailable")
		}
		pageEntries, pageBytes, mapErr := mapGenerationRootPage(base, result.Entries)
		clearLDAPProtectedAttributeBytes(result.Entries)
		if mapErr != nil || pageBytes > int(limits.MaxSnapshotBytes) ||
			bytesRead > int(limits.MaxSnapshotBytes)-pageBytes {
			clearEntries(pageEntries)
			return nil, errors.New("ldap inventory unavailable")
		}
		bytesRead += pageBytes
		paging, ok := goldap.FindControl(result.Controls, goldap.ControlTypePaging).(*goldap.ControlPaging)
		if !ok || paging == nil || len(paging.Cookie) > 4096 {
			clearEntries(pageEntries)
			return nil, errors.New("ldap inventory unavailable")
		}
		for _, entry := range pageEntries {
			if len(entries) >= int(limits.MaxGenerations) {
				clearEntries(pageEntries)
				return nil, errors.New("ldap inventory unavailable")
			}
			metadata, metadataErr := mapInventoryGenerationMetadata(entry)
			if metadataErr != nil {
				clearEntries(pageEntries)
				return nil, errors.New("ldap inventory unavailable")
			}
			if _, duplicate := seen[metadata.generation]; duplicate {
				clearEntries(pageEntries)
				return nil, errors.New("ldap inventory unavailable")
			}
			seen[metadata.generation] = struct{}{}
			entries = append(entries, entry)
		}
		if len(paging.Cookie) == 0 {
			success = true
			return entries, nil
		}
		cookie = append(cookie[:0], paging.Cookie...)
	}
	return nil, errors.New("ldap inventory unavailable")
}

// listRetentionGenerationRoots keeps recovery pagination independent of allocation ceilings.
func listRetentionGenerationRoots(ctx context.Context, base string, limits datasourceadmin.RetentionRecoveryLimits, search ldapSearchOperation) ([]Entry, error) {
	if ctx == nil || base == "" || limits.Validate() != nil || search == nil {
		return nil, errors.New("ldap recovery inventory unavailable")
	}
	entries := make([]Entry, 0, min(int(limits.MaxGenerations), 64))
	seen := make(map[uint64]struct{}, min(int(limits.MaxGenerations), 64))
	success := false
	defer func() {
		if !success {
			clearEntries(entries)
		}
	}()
	cookie := []byte(nil)
	bytesRead := 0
	for pages := uint32(0); pages <= limits.MaxGenerations; pages++ {
		control := newCriticalPagingControl(limits.PageSize, cookie)
		request := goldap.NewSearchRequest(base, goldap.ScopeSingleLevel, goldap.NeverDerefAliases, int(limits.MaxGenerations), 0, false, "(objectClass=*)", []string{"*"}, []goldap.Control{control})
		request.EnforceSizeLimit = true
		result, err := search(ctx, request)
		if err != nil || result == nil || len(result.Referrals) != 0 {
			return nil, errors.New("ldap recovery inventory unavailable")
		}
		pageEntries, pageBytes, mapErr := mapGenerationRootPage(base, result.Entries)
		clearLDAPProtectedAttributeBytes(result.Entries)
		if mapErr != nil || pageBytes > int(limits.MaxReadBytes) || bytesRead > int(limits.MaxReadBytes)-pageBytes {
			clearEntries(pageEntries)
			return nil, errors.New("ldap recovery inventory unavailable")
		}
		bytesRead += pageBytes
		paging, ok := goldap.FindControl(result.Controls, goldap.ControlTypePaging).(*goldap.ControlPaging)
		if !ok || paging == nil || len(paging.Cookie) > 4096 {
			clearEntries(pageEntries)
			return nil, errors.New("ldap recovery inventory unavailable")
		}
		for _, entry := range pageEntries {
			if len(entries) >= int(limits.MaxGenerations) {
				clearEntries(pageEntries)
				return nil, errors.New("ldap recovery inventory unavailable")
			}
			metadata, metadataErr := mapInventoryGenerationMetadata(entry)
			if metadataErr != nil {
				clearEntries(pageEntries)
				return nil, errors.New("ldap recovery inventory unavailable")
			}
			if _, duplicate := seen[metadata.generation]; duplicate {
				clearEntries(pageEntries)
				return nil, errors.New("ldap recovery inventory unavailable")
			}
			seen[metadata.generation] = struct{}{}
			entries = append(entries, entry)
		}
		if len(paging.Cookie) == 0 {
			success = true
			return entries, nil
		}
		cookie = append(cookie[:0], paging.Cookie...)
	}
	return nil, errors.New("ldap recovery inventory unavailable")
}

// mapGenerationRootPage validates and detaches one complete inventory page.
func mapGenerationRootPage(base string, sources []*goldap.Entry) ([]Entry, int, error) {
	entries := make([]Entry, 0, len(sources))
	bytesRead := 0
	seen := make(map[uint64]struct{}, len(sources))
	for _, source := range sources {
		entry, generation, err := mapGenerationRootSourceWithNumber(base, source)
		if err != nil {
			clearEntries(entries)
			return nil, 0, err
		}
		if _, duplicate := seen[generation]; duplicate {
			clearEntry(&entry)
			clearEntries(entries)
			return nil, 0, errLDAPPartial
		}
		seen[generation] = struct{}{}
		entrySize, sizeErr := ldapSourceEntryBytes(source)
		if sizeErr != nil || bytesRead > int(^uint(0)>>1)-entrySize {
			clearEntry(&entry)
			clearEntries(entries)
			return nil, 0, errLDAPPartial
		}
		bytesRead += entrySize
		entries = append(entries, entry)
	}
	return entries, bytesRead, nil
}

// ldapSourceEntryBytes counts every returned DN, attribute name, and value.
func ldapSourceEntryBytes(source *goldap.Entry) (int, error) {
	if source == nil || len(source.DN) > 4096 {
		return 0, errLDAPPartial
	}
	total := len(source.DN)
	for _, attribute := range source.Attributes {
		if attribute == nil || len(attribute.Name) > 128 || len(attribute.ByteValues) > 4 {
			return 0, errLDAPPartial
		}
		for _, value := range attribute.ByteValues {
			if len(value) > maxPrivateAttributeBytes || total > int(^uint(0)>>1)-len(attribute.Name)-len(value) {
				return 0, errLDAPPartial
			}
			total += len(attribute.Name) + len(value)
		}
	}
	return total, nil
}

// mapGenerationRootSource validates one exact direct generation root.
func mapGenerationRootSource(base string, source *goldap.Entry) (Entry, error) {
	entry, _, err := mapGenerationRootSourceWithNumber(base, source)
	return entry, err
}

// mapGenerationRootSourceWithNumber returns one exact detached root and its RDN number.
func mapGenerationRootSourceWithNumber(base string, source *goldap.Entry) (Entry, uint64, error) {
	if source == nil || !sourceInventoryRootClassesValid(source) {
		return Entry{}, 0, errLDAPPartial
	}
	dn, dnErr := goldap.ParseDN(source.DN)
	parent, parentErr := goldap.ParseDN(base)
	if dnErr != nil || parentErr != nil || len(dn.RDNs) != len(parent.RDNs)+1 ||
		!(&goldap.DN{RDNs: dn.RDNs[1:]}).Equal(parent) || len(dn.RDNs[0].Attributes) != 1 ||
		!strings.EqualFold(dn.RDNs[0].Attributes[0].Type, attrGeneration) {
		return Entry{}, 0, errLDAPPartial
	}
	generation, err := parseGeneration([]byte(dn.RDNs[0].Attributes[0].Value))
	if err != nil || len(source.GetAttributeValues("cn")) != 1 ||
		source.GetAttributeValue("cn") != "generation-"+strconv.FormatUint(generation, 10) {
		return Entry{}, 0, errLDAPPartial
	}
	entry, err := projectSourceEntry(RecordClassDataset, source, []string{
		attrSchemaVersion, attrGeneration, attrDatasetState,
		attrCandidateDigest, attrOperationID, attrSourceGeneration, attrWasActive,
	})
	if err != nil {
		return Entry{}, 0, err
	}
	metadata, err := mapInventoryGenerationMetadata(entry)
	if err != nil || metadata.generation != generation {
		clearEntry(&entry)
		return Entry{}, 0, errLDAPPartial
	}
	return entry, generation, nil
}

// ReadGenerationRecords reads and structurally validates one complete bounded subtree.
func (c *goLDAPClient) ReadGenerationRecords(
	ctx context.Context,
	generation uint64,
	limits provider.Limits,
	generationLimits datasourceadmin.GenerationLimits,
) (DatasetRecords, bool, error) {
	if generation == 0 || limits.Validate() != nil || generationLimits.Validate() != nil {
		return DatasetRecords{}, false, errors.New("ldap generation unavailable")
	}
	root := c.generationRoot(generation)
	maximum := int(generationLimits.MaxSnapshotRows)
	pageSize := min(maximum, 256)
	cookie := []byte(nil)
	entries := make([]*goldap.Entry, 0, min(maximum, 64))
	bytesRead := 0
	for pages := 0; pages <= maximum; pages++ {
		control := newCriticalPagingControl(uint32(pageSize), cookie)
		request := goldap.NewSearchRequest(
			root, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
			maximum+1, 0, false, "(objectClass=*)", []string{"*"}, []goldap.Control{control},
		)
		request.EnforceSizeLimit = true
		result, err := c.search(ctx, request)
		if goldap.IsErrorWithCode(err, goldap.LDAPResultNoSuchObject) {
			return DatasetRecords{}, false, nil
		}
		if err != nil || result == nil || len(result.Referrals) != 0 {
			return DatasetRecords{}, false, errors.New("ldap generation unavailable")
		}
		defer clearLDAPProtectedAttributeBytes(result.Entries)
		paging, ok := goldap.FindControl(result.Controls, goldap.ControlTypePaging).(*goldap.ControlPaging)
		if !ok || paging == nil || len(paging.Cookie) > 4096 {
			return DatasetRecords{}, false, errors.New("ldap generation unavailable")
		}
		for _, entry := range result.Entries {
			if entry == nil || len(entries) >= maximum || len(entry.DN) > 4096 {
				return DatasetRecords{}, false, errLDAPPartial
			}
			entrySize := len(entry.DN)
			for _, attribute := range entry.Attributes {
				if attribute == nil || len(attribute.Name) > 128 || len(attribute.ByteValues) > 4 {
					return DatasetRecords{}, false, errLDAPPartial
				}
				for _, value := range attribute.ByteValues {
					entrySize += len(attribute.Name) + len(value)
				}
			}
			if entrySize > int(generationLimits.MaxSnapshotBytes) ||
				bytesRead > int(generationLimits.MaxSnapshotBytes)-entrySize {
				return DatasetRecords{}, false, errLDAPPartial
			}
			bytesRead += entrySize
			entries = append(entries, entry)
		}
		if len(paging.Cookie) == 0 {
			records, mapErr := mapCompleteGenerationEntries(entries, root, generation)
			if mapErr != nil {
				return DatasetRecords{}, true, errLDAPPartial
			}
			return records, true, nil
		}
		cookie = append(cookie[:0], paging.Cookie...)
	}
	return DatasetRecords{}, false, errLDAPPartial
}

// ReadAdministrationLock reads one exact base revision and optional owner.
func (c *goLDAPClient) ReadAdministrationLock(
	ctx context.Context,
) (datasourceadmin.AdministrationLockObservation, error) {
	request := goldap.NewSearchRequest(
		c.baseDN, goldap.ScopeBaseObject, goldap.NeverDerefAliases, 2, 0, false,
		"(objectClass=dkim2AdministrationLock)",
		[]string{attrAdminRevision, attrAdminLockOwner}, nil,
	)
	request.EnforceSizeLimit = true
	result, err := c.search(ctx, request)
	if err != nil || result == nil || len(result.Referrals) != 0 || len(result.Entries) != 1 {
		return datasourceadmin.AdministrationLockObservation{}, errors.New("ldap lock unavailable")
	}
	defer clearLDAPProtectedAttributeBytes(result.Entries)
	revisionValues := result.Entries[0].GetRawAttributeValues(attrAdminRevision)
	ownerValues := result.Entries[0].GetRawAttributeValues(attrAdminLockOwner)
	if len(revisionValues) != 1 || len(ownerValues) > 1 {
		return datasourceadmin.AdministrationLockObservation{}, errors.New("ldap lock unavailable")
	}
	revision, err := parseGeneration(revisionValues[0])
	if err != nil {
		return datasourceadmin.AdministrationLockObservation{}, errors.New("ldap lock unavailable")
	}
	if len(ownerValues) == 0 {
		return datasourceadmin.NewAdministrationLockObservation(
			revision, datasourceadmin.OperationBinding{}, false,
		)
	}
	owner, err := datasourceadmin.NewOperationBinding(string(ownerValues[0]))
	if err != nil {
		return datasourceadmin.AdministrationLockObservation{}, errors.New("ldap lock unavailable")
	}
	return datasourceadmin.NewAdministrationLockObservation(revision, owner, true)
}

// ClaimAdministrationLock applies one critical ownerless revision assertion.
func (c *goLDAPClient) ClaimAdministrationLock(
	ctx context.Context,
	operation datasourceadmin.OperationBinding,
	revision uint64,
) error {
	filter := "(&(" + attrAdminRevision + "=" + strconv.FormatUint(revision, 10) + ")(!(" +
		attrAdminLockOwner + "=*)))"
	assertion, err := NewCriticalAssertionControl(filter)
	if err != nil {
		return errLDAPConflict
	}
	request := goldap.NewModifyRequest(c.baseDN, []goldap.Control{assertion})
	var operationValue string
	if err := operation.WithValue(ctx, func(value string) error {
		operationValue = value
		return nil
	}); err != nil {
		return errLDAPConflict
	}
	request.Add(attrAdminLockOwner, []string{operationValue})
	if err := c.call(ctx, func() error { return c.connection.Modify(request) }); err != nil {
		return errLDAPReconcile
	}
	return nil
}

// ReleaseAdministrationLock clears exact ownership and increments revision atomically.
func (c *goLDAPClient) ReleaseAdministrationLock(
	ctx context.Context,
	lock datasourceadmin.AdministrationLock,
) error {
	var owner string
	if err := lock.Owner().WithValue(ctx, func(value string) error {
		owner = value
		return nil
	}); err != nil || lock.Revision() == ^uint64(0) {
		return errLDAPConflict
	}
	filter := "(&(" + attrAdminRevision + "=" + strconv.FormatUint(lock.Revision(), 10) + ")(" +
		attrAdminLockOwner + "=" + goldap.EscapeFilter(owner) + "))"
	assertion, err := NewCriticalAssertionControl(filter)
	if err != nil {
		return errLDAPConflict
	}
	request := goldap.NewModifyRequest(c.baseDN, []goldap.Control{assertion})
	request.Delete(attrAdminLockOwner, []string{owner})
	request.Replace(attrAdminRevision, []string{strconv.FormatUint(lock.Revision()+1, 10)})
	if err := c.call(ctx, func() error { return c.connection.Modify(request) }); err != nil {
		return errLDAPReconcile
	}
	return nil
}

// AddCandidate creates one complete inactive v3 subtree without editing prior generations.
func (c *goLDAPClient) AddCandidate(
	ctx context.Context,
	candidate *datasourceadmin.PublicationEnvelope,
) error {
	if candidate == nil || candidate.Generation() == 0 {
		return errLDAPConflict
	}
	var operation string
	var digest []byte
	var source uint64
	if err := candidate.WithMetadata(ctx, func(binding datasourceadmin.OperationBinding, frozen uint64, value datasourceadmin.CandidateContentDigest) error {
		source = frozen
		digest = value.Bytes()
		return binding.WithValue(ctx, func(text string) error {
			operation = text
			return nil
		})
	}); err != nil {
		clear(digest)
		return errLDAPConflict
	}
	defer clear(digest)
	generation := strconv.FormatUint(candidate.Generation(), 10)
	root := c.generationRoot(candidate.Generation())
	if err := candidate.WithRows(ctx, func(rows datasourceadmin.Rows) error {
		requests := candidateAddRequests(root, generation, operation, source, digest, rows)
		for _, request := range requests {
			current := request
			if err := c.call(ctx, func() error { return c.connection.Add(current) }); err != nil {
				return errLDAPReconcile
			}
		}
		return nil
	}); err != nil {
		return errLDAPReconcile
	}
	return nil
}

// SealCandidate performs only the exact operation/digest staging-to-committed root change.
func (c *goLDAPClient) SealCandidate(
	ctx context.Context,
	generation uint64,
	operation datasourceadmin.OperationBinding,
	digest datasourceadmin.CandidateContentDigest,
) error {
	filter, err := v3RootAssertionFilter(ctx, generation, datasourceadmin.StateStaging, operation, digest, true)
	if err != nil {
		return errLDAPConflict
	}
	assertion, err := NewCriticalAssertionControl(filter)
	if err != nil {
		return errLDAPConflict
	}
	request := goldap.NewModifyRequest(c.generationRoot(generation), []goldap.Control{assertion})
	request.Replace(attrDatasetState, []string{string(datasourceadmin.StateCommitted)})
	if err := c.call(ctx, func() error { return c.connection.Modify(request) }); err != nil {
		return errLDAPReconcile
	}
	return nil
}

// MarkWasActive adds only monotonic history evidence to the exact observed old root.
func (c *goLDAPClient) MarkWasActive(ctx context.Context, metadata datasetMetadata) error {
	if metadata.wasActive {
		return nil
	}
	filter, err := metadata.rootAssertionFilter(ctx, true)
	if err != nil {
		return errLDAPConflict
	}
	assertion, err := NewCriticalAssertionControl(filter)
	if err != nil {
		return errLDAPConflict
	}
	request := goldap.NewModifyRequest(c.generationRoot(metadata.generation), []goldap.Control{assertion})
	request.Add(attrWasActive, []string{"TRUE"})
	if err := c.call(ctx, func() error { return c.connection.Modify(request) }); err != nil {
		return errLDAPReconcile
	}
	return nil
}

// ReplaceCurrent applies one critical assertion only to the existing current entry.
func (c *goLDAPClient) ReplaceCurrent(
	ctx context.Context,
	expected datasetMetadata,
	candidate datasetMetadata,
) error {
	filter, err := expected.currentAssertionFilter()
	if err != nil {
		return errLDAPConflict
	}
	assertion, err := NewCriticalAssertionControl(filter)
	if err != nil {
		return errLDAPConflict
	}
	request := goldap.NewModifyRequest("cn=current,"+c.baseDN, []goldap.Control{assertion})
	if expected.schema != datasourceadmin.SchemaVersionV3 {
		request.Add(attrObjectClass, []string{administrativeMetadataObjectClass})
	}
	request.Replace(attrSchemaVersion, []string{datasourceadmin.SchemaVersionV3})
	request.Replace(attrGeneration, []string{strconv.FormatUint(candidate.generation, 10)})
	request.Replace(attrDatasetState, []string{string(datasourceadmin.StateCommitted)})
	digest := candidate.digest.Bytes()
	defer clear(digest)
	request.Replace(attrCandidateDigest, []string{string(digest)})
	if err := c.call(ctx, func() error { return c.connection.Modify(request) }); err != nil {
		return errLDAPReconcile
	}
	return nil
}

// AddCurrent creates one exact digest-only v3 current fence atomically.
func (c *goLDAPClient) AddCurrent(ctx context.Context, candidate datasetMetadata) error {
	request := goldap.NewAddRequest("cn=current,"+c.baseDN, nil)
	request.Attribute(attrObjectClass, []string{topObjectClass, datasetObjectClass, administrativeMetadataObjectClass})
	request.Attribute("cn", []string{"current"})
	request.Attribute(attrSchemaVersion, []string{datasourceadmin.SchemaVersionV3})
	request.Attribute(attrGeneration, []string{strconv.FormatUint(candidate.generation, 10)})
	request.Attribute(attrDatasetState, []string{string(datasourceadmin.StateCommitted)})
	digest := candidate.digest.Bytes()
	defer clear(digest)
	request.Attribute(attrCandidateDigest, []string{string(digest)})
	if err := c.call(ctx, func() error { return c.connection.Add(request) }); err != nil {
		return errLDAPReconcile
	}
	return nil
}

// generationRoot returns the exact provider-owned DN for one numeric generation.
func (c *goLDAPClient) generationRoot(generation uint64) string {
	return "dkim2Generation=" + goldap.EscapeDN(strconv.FormatUint(generation, 10)) +
		",ou=generations," + c.baseDN
}

// mapCompleteGenerationEntries validates exact root, containers, records, and attributes.
func mapCompleteGenerationEntries(
	entries []*goldap.Entry,
	root string,
	generation uint64,
) (records DatasetRecords, resultErr error) {
	defer func() {
		if resultErr != nil {
			clearDatasetRecords(&records)
			clearLDAPProtectedAttributeBytes(entries)
			records = DatasetRecords{}
		}
	}()
	units := make(map[string]bool, len(generationUnits))
	rootSeen := false
	for _, entry := range entries {
		if entry == nil {
			return DatasetRecords{}, errLDAPPartial
		}
		switch {
		case ldapDNEqual(entry.DN, root):
			if rootSeen || !sourceRootClassesValid(entry) {
				return DatasetRecords{}, errLDAPPartial
			}
			mapped, err := projectSourceEntry(RecordClassDataset, entry, []string{
				attrSchemaVersion, attrGeneration, attrDatasetState,
				attrCandidateDigest, attrOperationID, attrSourceGeneration, attrWasActive,
			})
			if err != nil {
				return DatasetRecords{}, err
			}
			records.Root = mapped
			rootSeen = true
		case generationUnit(entry.DN, root) != "":
			unit := generationUnit(entry.DN, root)
			if units[unit] || !sourceHasOnlyClasses(entry, topObjectClass, "organizationalUnit") ||
				len(entry.GetAttributeValues("ou")) != 1 || entry.GetAttributeValue("ou") != unit {
				return DatasetRecords{}, errLDAPPartial
			}
			units[unit] = true
		case strings.HasSuffix(strings.ToLower(entry.DN), ","+strings.ToLower(root)):
			class, unit, ok := sourceRecordClass(entry, root)
			if !ok {
				return DatasetRecords{}, errLDAPPartial
			}
			mapped, err := projectSourceEntry(class, entry, recordClassAttributes(class))
			if err != nil {
				return DatasetRecords{}, err
			}
			switch unit {
			case handlesUnit:
				records.Handles = append(records.Handles, mapped)
			case profilesUnit:
				records.Profiles = append(records.Profiles, mapped)
			case credentialsUnit:
				records.Credentials = append(records.Credentials, mapped)
			case policiesUnit:
				records.Policies = append(records.Policies, mapped)
			case keyMaterialUnit:
				records.KeyMaterial = append(records.KeyMaterial, mapped)
			default:
				return DatasetRecords{}, errLDAPPartial
			}
		default:
			return DatasetRecords{}, errLDAPPartial
		}
	}
	if !rootSeen || len(units) != len(generationUnits) {
		return DatasetRecords{}, errLDAPPartial
	}
	for _, entry := range append(append(append(append(append(
		[]Entry{}, records.Handles...), records.Profiles...), records.Credentials...), records.Policies...), records.KeyMaterial...) {
		parsed, err := parseGeneration(entry.Attributes[attrGeneration][0])
		if err != nil || parsed != generation {
			return DatasetRecords{}, errLDAPPartial
		}
	}
	return records, nil
}

// projectSourceEntry enforces a closed user-attribute set and detaches mapped values.
func projectSourceEntry(class RecordClass, source *goldap.Entry, attributes []string) (Entry, error) {
	allowed := append([]string{attrObjectClass, "cn"}, attributes...)
	if class == RecordClassDataset {
		allowed = append(allowed, attrWasActive)
	}
	for _, attribute := range source.Attributes {
		if attribute == nil || !containsFold(allowed, attribute.Name) {
			return Entry{}, errLDAPPartial
		}
	}
	projected := &goldap.Entry{DN: source.DN}
	for _, name := range attributes {
		values := source.GetRawAttributeValues(name)
		if len(values) == 0 {
			continue
		}
		attribute := &goldap.EntryAttribute{Name: name}
		for _, value := range values {
			attribute.ByteValues = append(attribute.ByteValues, bytes.Clone(value))
			attribute.Values = append(attribute.Values, string(value))
		}
		projected.Attributes = append(projected.Attributes, attribute)
	}
	return convertProjectedEntry(class, projected)
}

// convertProjectedEntry detaches one closed projection and destroys every
// administration-sensitive intermediate copy on success and failure.
func convertProjectedEntry(class RecordClass, projected *goldap.Entry) (Entry, error) {
	defer clearLDAPProtectedAttributeBytes([]*goldap.Entry{projected})
	return convertEntry(class, projected)
}

// recordClassAttributes returns the sole allowed projected attributes for one class.
func recordClassAttributes(class RecordClass) []string {
	switch class {
	case RecordClassHandle:
		return []string{attrGeneration, attrHandleID}
	case RecordClassProfile:
		return []string{attrGeneration, attrProfileID, attrSigningDomain, attrRecordStatus, attrNotBefore, attrNotAfter}
	case RecordClassCredential:
		return []string{attrGeneration, attrProfileID, attrAlgorithm, attrSelector, attrPublicSPKI, attrHandleID}
	case RecordClassPolicy:
		return []string{attrGeneration, attrTenantID, attrSigningDomain, attrProfileUse, attrProfileID, attrRecordStatus, attrRollout, attrCompatibility, attrFeedbackRouteID}
	case RecordClassKeyMaterial:
		return []string{attrGeneration, attrTenantID, attrSigningDomain, attrProfileUse, attrHandleID, attrAlgorithm, attrPublicSPKI, attrPrivatePKCS8}
	default:
		return nil
	}
}

// sourceRecordClass validates one record structural class and exact parent unit.
func sourceRecordClass(entry *goldap.Entry, root string) (RecordClass, string, bool) {
	classes := []struct {
		name  string
		class RecordClass
		unit  string
	}{
		{handleObjectClass, RecordClassHandle, handlesUnit},
		{profileObjectClass, RecordClassProfile, profilesUnit},
		{credentialObjectClass, RecordClassCredential, credentialsUnit},
		{policyObjectClass, RecordClassPolicy, policiesUnit},
		{keyMaterialObjectClass, RecordClassKeyMaterial, keyMaterialUnit},
	}
	matched := 0
	var selected struct {
		class RecordClass
		unit  string
	}
	for _, candidate := range classes {
		if sourceHasOnlyClasses(entry, topObjectClass, candidate.name) {
			matched++
			selected.class, selected.unit = candidate.class, candidate.unit
		}
	}
	parent := "ou=" + selected.unit + "," + root
	entryDN, entryErr := goldap.ParseDN(entry.DN)
	parentDN, parentErr := goldap.ParseDN(parent)
	return selected.class, selected.unit, matched == 1 && entryErr == nil && parentErr == nil &&
		len(entryDN.RDNs) == len(parentDN.RDNs)+1 &&
		(&goldap.DN{RDNs: entryDN.RDNs[1:]}).Equal(parentDN)
}

// generationUnit identifies one exact direct generation container DN.
func generationUnit(dn string, root string) string {
	for _, unit := range generationUnits {
		if ldapDNEqual(dn, "ou="+unit+","+root) {
			return unit
		}
	}
	return ""
}

// ldapDNEqual compares parsed LDAP DNs without exposing them.
func ldapDNEqual(left string, right string) bool {
	leftDN, leftErr := goldap.ParseDN(left)
	rightDN, rightErr := goldap.ParseDN(right)
	return leftErr == nil && rightErr == nil && leftDN.Equal(rightDN)
}

// sourceHasClasses reports whether every requested class is present case-insensitively.
func sourceHasClasses(entry *goldap.Entry, names ...string) bool {
	values := entry.GetAttributeValues(attrObjectClass)
	for _, name := range names {
		if !containsFold(values, name) {
			return false
		}
	}
	return true
}

// sourceHasOnlyClasses rejects unexpected structural or auxiliary classes.
func sourceHasOnlyClasses(entry *goldap.Entry, names ...string) bool {
	values := entry.GetAttributeValues(attrObjectClass)
	if len(values) != len(names) || !sourceHasClasses(entry, names...) {
		return false
	}
	for _, value := range values {
		if !containsFold(names, value) {
			return false
		}
	}
	return true
}

// sourceInventoryRootClassesValid admits exact v1 roots only for conservative
// history enumeration; full generation reads remain v2/v3-only.
func sourceInventoryRootClassesValid(entry *goldap.Entry) bool {
	schema := entry.GetAttributeValues(attrSchemaVersion)
	if len(schema) == 1 && schema[0] == datasourceadmin.SchemaVersionV1 {
		return sourceHasOnlyClasses(entry, topObjectClass, datasetObjectClass)
	}
	return sourceRootClassesValid(entry)
}

// sourceRootClassesValid accepts only the exact v2 or v3 root class set.
func sourceRootClassesValid(entry *goldap.Entry) bool {
	schema := entry.GetAttributeValues(attrSchemaVersion)
	if len(schema) != 1 {
		return false
	}
	if schema[0] == datasourceadmin.SchemaVersionV2 {
		return sourceHasOnlyClasses(entry, topObjectClass, datasetObjectClass)
	}
	if schema[0] == datasourceadmin.SchemaVersionV3 {
		return sourceHasOnlyClasses(entry, topObjectClass, datasetObjectClass, administrativeMetadataObjectClass)
	}
	return false
}

// containsFold reports case-insensitive membership for LDAP descriptors.
func containsFold(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(value, expected) {
			return true
		}
	}
	return false
}

// candidateAddRequests constructs the complete fixed v3 LDAP subtree mutation list.
func candidateAddRequests(
	root string,
	generation string,
	operation string,
	source uint64,
	digest []byte,
	rows datasourceadmin.Rows,
) []*goldap.AddRequest {
	metadata := map[string][]string{
		attrObjectClass: {topObjectClass, datasetObjectClass, administrativeMetadataObjectClass},
		"cn":            {"generation-" + generation}, attrSchemaVersion: {datasourceadmin.SchemaVersionV3},
		attrGeneration: {generation}, attrDatasetState: {string(datasourceadmin.StateStaging)},
		attrOperationID: {operation}, attrCandidateDigest: {string(digest)},
	}
	if source != 0 {
		metadata[attrSourceGeneration] = []string{strconv.FormatUint(source, 10)}
	}
	requests := []*goldap.AddRequest{newAdminAdd(root, metadata)}
	for _, unit := range generationUnits {
		requests = append(requests, newAdminAdd("ou="+unit+","+root, map[string][]string{
			attrObjectClass: {topObjectClass, "organizationalUnit"}, "ou": {unit},
		}))
	}
	for index, row := range rows.Handles {
		requests = append(requests, newAdminAdd(recordDN(index, handlesUnit, root), map[string][]string{
			attrObjectClass: {topObjectClass, handleObjectClass}, "cn": {recordCN(index)},
			attrGeneration: {generation}, attrHandleID: {row.ID},
		}))
	}
	for index, row := range rows.Profiles {
		attributes := map[string][]string{
			attrObjectClass: {topObjectClass, profileObjectClass}, "cn": {recordCN(index)},
			attrGeneration: {generation}, attrProfileID: {row.ID}, attrSigningDomain: {row.Domain},
			attrRecordStatus: {row.Status},
		}
		if row.NotBeforeUTC != nil {
			attributes[attrNotBefore], attributes[attrNotAfter] = []string{*row.NotBeforeUTC}, []string{*row.NotAfterUTC}
		}
		requests = append(requests, newAdminAdd(recordDN(index, profilesUnit, root), attributes))
	}
	for index, row := range rows.Credentials {
		requests = append(requests, newAdminAdd(recordDN(index, credentialsUnit, root), map[string][]string{
			attrObjectClass: {topObjectClass, credentialObjectClass}, "cn": {recordCN(index)}, attrGeneration: {generation},
			attrProfileID: {row.ProfileID}, attrAlgorithm: {row.Algorithm}, attrSelector: {row.Selector},
			attrPublicSPKI: {string(row.PublicSPKI)}, attrHandleID: {row.HandleID},
		}))
	}
	for index, row := range rows.Policies {
		attributes := map[string][]string{
			attrObjectClass: {topObjectClass, policyObjectClass}, "cn": {recordCN(index)}, attrGeneration: {generation},
			attrTenantID: {row.TenantID}, attrSigningDomain: {row.Domain}, attrProfileUse: {row.Use},
			attrProfileID: {row.ProfileID}, attrRecordStatus: {row.Status}, attrRollout: {row.Rollout},
			attrCompatibility: {row.Compatibility},
		}
		if row.FeedbackRouteID != nil {
			attributes[attrFeedbackRouteID] = []string{*row.FeedbackRouteID}
		}
		requests = append(requests, newAdminAdd(recordDN(index, policiesUnit, root), attributes))
	}
	for index, row := range rows.KeyMaterial {
		requests = append(requests, newAdminAdd(recordDN(index, keyMaterialUnit, root), map[string][]string{
			attrObjectClass: {topObjectClass, keyMaterialObjectClass}, "cn": {recordCN(index)}, attrGeneration: {generation},
			attrTenantID: {row.TenantID}, attrSigningDomain: {row.Domain}, attrProfileUse: {row.Use},
			attrHandleID: {row.HandleID}, attrAlgorithm: {row.Algorithm},
			attrPublicSPKI: {string(row.PublicSPKI)}, attrPrivatePKCS8: {string(row.PrivatePKCS8)},
		}))
	}
	return requests
}

// newAdminAdd constructs one deterministic LDAP Add request.
func newAdminAdd(dn string, attributes map[string][]string) *goldap.AddRequest {
	request := goldap.NewAddRequest(dn, nil)
	names := make([]string, 0, len(attributes))
	for name := range attributes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		values := attributes[name]
		request.Attribute(name, values)
	}
	return request
}

// recordDN derives one storage-only bounded record DN.
func recordDN(index int, unit string, root string) string {
	return "cn=" + recordCN(index) + ",ou=" + unit + "," + root
}

// recordCN returns one deterministic storage-only record key.
func recordCN(index int) string { return "record-" + strconv.Itoa(index+1) }

// v3RootAssertionFilter binds exact immutable root metadata and optional history absence.
func v3RootAssertionFilter(
	ctx context.Context,
	generation uint64,
	state datasourceadmin.GenerationState,
	operation datasourceadmin.OperationBinding,
	digest datasourceadmin.CandidateContentDigest,
	requireNoHistory bool,
) (string, error) {
	metadata := datasetMetadata{
		schema: datasourceadmin.SchemaVersionV3, generation: generation, state: state,
		operation: operation, digest: digest,
	}
	return metadata.rootAssertionFilter(ctx, requireNoHistory)
}

// rootAssertionFilter constructs one exact same-entry generation metadata fence.
func (m datasetMetadata) rootAssertionFilter(ctx context.Context, requireNoHistory bool) (string, error) {
	if m.generation == 0 || (m.state != datasourceadmin.StateStaging && m.state != datasourceadmin.StateCommitted) {
		return "", errLDAPConflict
	}
	filter := "(&(objectClass=" + datasetObjectClass + ")(" + attrSchemaVersion + "=" + m.schema + ")(" +
		attrGeneration + "=" + strconv.FormatUint(m.generation, 10) + ")(" + attrDatasetState + "=" + string(m.state) + ")"
	switch m.schema {
	case datasourceadmin.SchemaVersionV3:
		if !m.operation.Initialized() || !m.digest.Valid() {
			return "", errLDAPConflict
		}
		var operation string
		if err := m.operation.WithValue(ctx, func(value string) error { operation = value; return nil }); err != nil {
			return "", errLDAPConflict
		}
		digest := m.digest.Bytes()
		defer clear(digest)
		filter += "(" + attrOperationID + "=" + goldap.EscapeFilter(operation) + ")(" +
			attrCandidateDigest + "=" + goldap.EscapeFilter(string(digest)) + ")"
	case datasourceadmin.SchemaVersionV2:
		filter += "(!(" + attrOperationID + "=*))(!(" + attrCandidateDigest + "=*))"
	default:
		return "", errLDAPConflict
	}
	if requireNoHistory {
		filter += "(!(" + attrWasActive + "=*))"
	}
	return filter + ")", nil
}

// currentAssertionFilter constructs one exact current-entry-only RFC 4528 fence.
func (m datasetMetadata) currentAssertionFilter() (string, error) {
	if m.generation == 0 || m.state != datasourceadmin.StateCommitted {
		return "", errLDAPConflict
	}
	filter := "(&(objectClass=" + datasetObjectClass + ")(" + attrSchemaVersion + "=" + m.schema + ")(" +
		attrGeneration + "=" + strconv.FormatUint(m.generation, 10) + ")(" + attrDatasetState + "=committed)"
	switch m.schema {
	case datasourceadmin.SchemaVersionV3:
		if !m.digest.Valid() {
			return "", errLDAPConflict
		}
		digest := m.digest.Bytes()
		defer clear(digest)
		filter += "(" + attrCandidateDigest + "=" + goldap.EscapeFilter(string(digest)) + ")"
	case datasourceadmin.SchemaVersionV2:
		filter += "(!(" + attrCandidateDigest + "=*))"
	default:
		return "", errLDAPConflict
	}
	return filter + "(!(" + attrOperationID + "=*))(!(" + attrWasActive + "=*)))", nil
}

var _ administrationClient = (*goLDAPClient)(nil)
