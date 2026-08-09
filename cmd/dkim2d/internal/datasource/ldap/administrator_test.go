package ldap

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/rotationadmin"
	"github.com/croessner/dkim2/provider"
	goldap "github.com/go-ldap/ldap/v3"
)

const testGenerationBaseDN = "ou=generations,ou=dkim2,dc=example,dc=test"

type administrationConnectorFake struct {
	client    Client
	authority AdministrationAuthority
}

// Connect returns one role-scoped synthetic administration client.
func (c administrationConnectorFake) Connect(context.Context) (Client, error) { return c.client, nil }

// AdministrationAuthority returns one opaque synthetic bind identity.
func (c administrationConnectorFake) AdministrationAuthority() AdministrationAuthority {
	return c.authority
}

type administrationClientFake struct {
	*fakeClient
	current          Entry
	currentPresent   bool
	roots            []Entry
	generations      map[uint64]DatasetRecords
	lock             datasourceadmin.AdministrationLockObservation
	stageRecords     DatasetRecords
	stageCalls       int
	sealCalls        int
	markCalls        int
	replaceCalls     int
	addCurrentCalls  int
	generationReads  int
	returnedRecords  []DatasetRecords
	mutationErr      error
	addErrAfterWrite error
}

type movingCurrentAdministrationClient struct {
	*administrationClientFake
	finalCurrent Entry
	currentReads int
}

// TestNewAdministratorRejectsAliasedRoleAuthority reproduces construction of
// a three-role administrator over one effective LDAP bind identity.
func TestNewAdministratorRejectsAliasedRoleAuthority(t *testing.T) {
	client := &administrationClientFake{fakeClient: &fakeClient{}}
	snapshot := newAdministrationConnectorFake(t, client, "snapshot")
	stager := newAdministrationConnectorFake(t, client, "stager")
	activator := newAdministrationConnectorFake(t, client, "activator")
	limits := datasourceadmin.GenerationLimits{
		MaxGenerations: 256, MaxOutstandingCandidates: 8,
		MaxSnapshotRows: 4096, MaxSnapshotBytes: 32 << 20,
		BackendDeadline: 2 * time.Second,
	}
	if administrator, err := NewAdministrator(
		snapshot, stager, activator, provider.DefaultLimits(), limits,
	); err != nil || administrator == nil {
		t.Fatal("three distinct administration authorities rejected")
	}
	for _, test := range []struct {
		name      string
		snapshot  AdministrationConnector
		stager    AdministrationConnector
		activator AdministrationConnector
	}{
		{name: "same connector", snapshot: snapshot, stager: snapshot, activator: activator},
		{
			name: "snapshot and stager same authority", snapshot: snapshot,
			stager:    administrationConnectorFake{client: client, authority: snapshot.authority},
			activator: activator,
		},
		{
			name: "snapshot and activator same authority", snapshot: snapshot, stager: stager,
			activator: administrationConnectorFake{client: client, authority: snapshot.authority},
		},
		{
			name: "stager and activator same authority", snapshot: snapshot, stager: stager,
			activator: administrationConnectorFake{client: client, authority: stager.authority},
		},
		{
			name: "invalid authority", snapshot: snapshot,
			stager: administrationConnectorFake{client: client}, activator: activator,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			administrator, err := NewAdministrator(
				test.snapshot, test.stager, test.activator,
				provider.DefaultLimits(), limits,
			)
			if administrator != nil || datasourceadmin.CodeOf(err) != datasourceadmin.CodeInvalid {
				t.Fatal("aliased or invalid administration authority accepted")
			}
		})
	}
}

// ReadCurrentOptional returns one initial pointer and then a different final
// pointer to reproduce a move across the stable-inventory fence.
func (c *movingCurrentAdministrationClient) ReadCurrentOptional(context.Context) (Entry, bool, error) {
	c.currentReads++
	if c.currentReads == 1 {
		return cloneEntry(c.current), c.currentPresent, nil
	}
	return cloneEntry(c.finalCurrent), true, nil
}

// TestCriticalAssertionControlRejectsInvalidFilters freezes the shared RFC 4528 owner.
func TestCriticalAssertionControlRejectsInvalidFilters(t *testing.T) {
	control, err := NewCriticalAssertionControl("(&(dkim2AdminRevision=1)(!(dkim2AdminLockOwner=*)))")
	if err != nil || control == nil || control.GetControlType() != "1.3.6.1.1.12" {
		t.Fatal("construct critical RFC 4528 assertion")
	}
	encoded := control.Encode()
	if encoded == nil || len(encoded.Children) != 3 || encoded.Children[1].Value != true {
		t.Fatal("assertion control was not encoded as critical")
	}
	if _, err := NewCriticalAssertionControl("(&"); err == nil {
		t.Fatal("invalid assertion filter accepted")
	}
	if control.GetControlType() == goldap.ControlTypePaging {
		t.Fatal("assertion control reused the paging OID")
	}
}

// TestCompleteGenerationProjectionRejectsStructuralAmbiguity freezes the closed LDAP subtree shape.
func TestCompleteGenerationProjectionRejectsStructuralAmbiguity(t *testing.T) {
	candidate, _, operation := administrationCandidateFixture(t, 2)
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var entries []*goldap.Entry
	if err := candidate.WithRows(ctx, func(rows datasourceadmin.Rows) error {
		var operationValue string
		if err := operation.WithValue(ctx, func(value string) error { operationValue = value; return nil }); err != nil {
			return err
		}
		digest := candidate.Digest().Bytes()
		defer clear(digest)
		for _, request := range candidateAddRequests(
			"dkim2Generation=2,ou=generations,ou=dkim2,dc=example,dc=test",
			"2", operationValue, 0, digest, rows,
		) {
			entry := &goldap.Entry{DN: request.DN}
			for _, attribute := range request.Attributes {
				projected := &goldap.EntryAttribute{Name: attribute.Type}
				for _, value := range attribute.Vals {
					projected.Values = append(projected.Values, value)
					projected.ByteValues = append(projected.ByteValues, []byte(value))
				}
				entry.Attributes = append(entry.Attributes, projected)
			}
			entries = append(entries, entry)
		}
		return nil
	}); err != nil {
		t.Fatal("construct LDAP subtree fixture")
	}
	defer clearLDAPProtectedAttributeBytes(entries)
	root := "dkim2Generation=2,ou=generations,ou=dkim2,dc=example,dc=test"
	exact, err := mapCompleteGenerationEntries(entries, root, 2)
	if err != nil {
		t.Fatal("exact complete LDAP subtree rejected")
	}
	clearDatasetRecords(&exact)

	clone := cloneLDAPEntries(entries)
	clone[0].Attributes = append(clone[0].Attributes, &goldap.EntryAttribute{
		Name: "description", Values: []string{"surplus"}, ByteValues: [][]byte{[]byte("surplus")},
	})
	if _, err := mapCompleteGenerationEntries(clone, root, 2); err == nil {
		t.Fatal("surplus root attribute accepted")
	}
	clearLDAPProtectedAttributeBytes(clone)

	clone = cloneLDAPEntries(entries)
	for _, entry := range clone {
		if strings.Contains(entry.DN, "ou=handles,") && strings.HasPrefix(entry.DN, "cn=") {
			entry.DN = "cn=nested," + entry.DN
			break
		}
	}
	if _, err := mapCompleteGenerationEntries(clone, root, 2); err == nil {
		t.Fatal("nested record DN accepted")
	}
	clearLDAPProtectedAttributeBytes(clone)

	clone = cloneLDAPEntries(entries)
	for _, entry := range clone {
		if strings.Contains(entry.DN, "ou=key-material,") && strings.HasPrefix(entry.DN, "cn=") {
			for _, attribute := range entry.Attributes {
				if attribute.Name == attrGeneration {
					attribute.Values, attribute.ByteValues = []string{"3"}, [][]byte{[]byte("3")}
				}
			}
			break
		}
	}
	if _, err := mapCompleteGenerationEntries(clone, root, 2); err == nil {
		t.Fatal("wrong-generation private key accepted")
	}
	clearLDAPProtectedAttributeBytes(clone)

	clone = cloneLDAPEntries(entries)
	for index, entry := range clone {
		if strings.Contains(entry.DN, "ou=key-material,") && strings.HasPrefix(entry.DN, "cn=") {
			clone = append(clone[:index], clone[index+1:]...)
			break
		}
	}
	partial, err := mapCompleteGenerationEntries(clone, root, 2)
	if err == nil {
		partialCandidate, _, candidateErr := candidateFromRecords(ctx, partial)
		if partialCandidate != nil {
			_ = partialCandidate.Close()
		}
		clearDatasetRecords(&partial)
		if candidateErr == nil {
			t.Fatal("partial generation without key material accepted")
		}
	}
	clearLDAPProtectedAttributeBytes(clone)

	clone = cloneLDAPEntries(entries)
	for _, entry := range clone {
		if strings.Contains(entry.DN, "ou=key-material,") && strings.HasPrefix(entry.DN, "cn=") {
			clone = append(clone, cloneLDAPEntries([]*goldap.Entry{entry})[0])
			break
		}
	}
	duplicate, err := mapCompleteGenerationEntries(clone, root, 2)
	if err == nil {
		duplicateCandidate, _, candidateErr := candidateFromRecords(ctx, duplicate)
		if duplicateCandidate != nil {
			_ = duplicateCandidate.Close()
		}
		clearDatasetRecords(&duplicate)
		if candidateErr == nil {
			t.Fatal("duplicate generation record accepted")
		}
	}
	clearLDAPProtectedAttributeBytes(clone)
}

// TestGenerationRootPagingRequiresCriticalOpaqueGlobalInventory freezes two
// pages, cookie propagation, and cross-page duplicate/foreign-child denial.
func TestGenerationRootPagingRequiresCriticalOpaqueGlobalInventory(t *testing.T) {
	base := testGenerationBaseDN
	limits := datasourceadmin.GenerationLimits{
		MaxGenerations: 300, MaxOutstandingCandidates: 8,
		MaxSnapshotRows: 4096, MaxSnapshotBytes: 32 << 20,
		BackendDeadline: 2 * time.Second,
	}
	tests := []struct {
		name       string
		second     *goldap.Entry
		wantErr    bool
		wantNumber uint64
	}{
		{name: "two exact pages", second: generationRootLDAPSource(base, 2), wantNumber: 2},
		{name: "global duplicate", second: generationRootLDAPSource(base, 1), wantErr: true},
		{name: "foreign direct child", second: generationRootLDAPSource(base, 2), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "foreign direct child" {
				test.second.DN = "cn=foreign," + base
			}
			calls := 0
			search := func(_ context.Context, request *goldap.SearchRequest) (*goldap.SearchResult, error) {
				calls++
				if request.BaseDN != base || request.Scope != goldap.ScopeSingleLevel ||
					request.Filter != "(objectClass=*)" || len(request.Attributes) != 1 ||
					request.Attributes[0] != "*" || len(request.Controls) != 1 {
					t.Fatal("generation inventory search projection drifted")
				}
				control, ok := request.Controls[0].(*criticalPagingControl)
				if !ok || control.size != 256 || (calls == 1 && len(control.cookie) != 0) ||
					(calls == 2 && !bytes.Equal(control.cookie, []byte("next-page"))) ||
					control.Encode().Children[1].Value != true {
					t.Fatal("generation inventory paging was not critical and opaque")
				}
				entry := generationRootLDAPSource(base, 1)
				cookie := []byte("next-page")
				if calls == 2 {
					entry = test.second
					cookie = nil
				}
				return &goldap.SearchResult{
					Entries:  []*goldap.Entry{entry},
					Controls: []goldap.Control{&goldap.ControlPaging{PagingSize: 256, Cookie: cookie}},
				}, nil
			}
			entries, err := listGenerationRoots(t.Context(), base, limits, search)
			if test.wantErr {
				if err == nil || entries != nil || calls != 2 {
					t.Fatal("invalid global generation inventory did not fail closed")
				}
				return
			}
			defer clearEntries(entries)
			if err != nil || len(entries) != 2 || calls != 2 {
				t.Fatal("complete two-page generation inventory rejected")
			}
			metadata, metadataErr := mapGenerationMetadata(entries[1])
			if metadataErr != nil || metadata.generation != test.wantNumber {
				t.Fatal("second generation page was not retained exactly")
			}
		})
	}
}

// TestGenerationRootPagingRetainsCommittedV1History proves transport paging
// uses the same conservative legacy grammar as allocation inventory.
func TestGenerationRootPagingRetainsCommittedV1History(t *testing.T) {
	base := testGenerationBaseDN
	legacy := generationRootLDAPSource(base, 1)
	for _, attribute := range legacy.Attributes {
		if attribute.Name == attrSchemaVersion {
			attribute.Values = []string{datasourceadmin.SchemaVersionV1}
			attribute.ByteValues = [][]byte{[]byte(datasourceadmin.SchemaVersionV1)}
		}
	}
	if !sourceInventoryRootClassesValid(legacy) {
		t.Fatal("v1 inventory root class grammar rejected")
	}
	projected, _, projectionErr := mapGenerationRootSourceWithNumber(base, legacy)
	if projectionErr != nil {
		t.Fatalf("v1 source projection rejected: %v", projectionErr)
	}
	clearEntry(&projected)
	page, _, err := mapGenerationRootPage(base, []*goldap.Entry{legacy})
	if err != nil || len(page) != 1 {
		t.Fatalf("v1 inventory root projection rejected: %v", err)
	}
	if _, err := mapInventoryGenerationMetadata(page[0]); err != nil {
		clearEntries(page)
		t.Fatal("v1 inventory root metadata rejected")
	}
	clearEntries(page)
	search := func(_ context.Context, _ *goldap.SearchRequest) (*goldap.SearchResult, error) {
		return &goldap.SearchResult{Entries: []*goldap.Entry{legacy}, Controls: []goldap.Control{&goldap.ControlPaging{PagingSize: 256}}}, nil
	}
	limits := datasourceadmin.GenerationLimits{MaxGenerations: 16, MaxOutstandingCandidates: 8, MaxSnapshotRows: 64, MaxSnapshotBytes: 1 << 20, BackendDeadline: time.Second}
	entries, err := listGenerationRoots(t.Context(), base, limits, search)
	if err != nil || len(entries) != 1 {
		t.Fatal("committed metadata-free v1 history was rejected by paging")
	}
	defer clearEntries(entries)
	metadata, err := mapInventoryGenerationMetadata(entries[0])
	if err != nil || metadata.schema != datasourceadmin.SchemaVersionV1 || metadata.generation != 1 {
		t.Fatal("paged v1 history lost its conservative inventory projection")
	}
}

// generationRootLDAPSource constructs one exact direct v2 root source for
// bounded paging tests.
func generationRootLDAPSource(base string, generation uint64) *goldap.Entry {
	value := strconv.FormatUint(generation, 10)
	return &goldap.Entry{DN: attrGeneration + "=" + value + "," + base, Attributes: []*goldap.EntryAttribute{
		{Name: attrObjectClass, Values: []string{topObjectClass, datasetObjectClass}, ByteValues: [][]byte{[]byte(topObjectClass), []byte(datasetObjectClass)}},
		{Name: "cn", Values: []string{"generation-" + value}, ByteValues: [][]byte{[]byte("generation-" + value)}},
		{Name: attrSchemaVersion, Values: []string{datasourceadmin.SchemaVersionV2}, ByteValues: [][]byte{[]byte(datasourceadmin.SchemaVersionV2)}},
		{Name: attrGeneration, Values: []string{value}, ByteValues: [][]byte{[]byte(value)}},
		{Name: attrDatasetState, Values: []string{"committed"}, ByteValues: [][]byte{[]byte("committed")}},
	}}
}

// TestV2AssertionFiltersForbidV3Metadata freezes the forward-only compatibility fence.
func TestV2AssertionFiltersForbidV3Metadata(t *testing.T) {
	metadata := datasetMetadata{
		schema: datasourceadmin.SchemaVersionV2, generation: 7, state: datasourceadmin.StateCommitted,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	root, err := metadata.rootAssertionFilter(ctx, false)
	if err != nil || !strings.Contains(root, "(!(dkim2OperationID=*))") ||
		!strings.Contains(root, "(!(dkim2CandidateDigest=*))") {
		t.Fatal("v2 root assertion permits mixed v3 metadata")
	}
	current, err := metadata.currentAssertionFilter()
	if err != nil || !strings.Contains(current, "(!(dkim2CandidateDigest=*))") ||
		!strings.Contains(current, "(!(dkim2OperationID=*))") {
		t.Fatal("v2 current assertion permits mixed v3 metadata")
	}
}

// TestProtectedLDAPSourceValuesAreCleared freezes source-buffer destruction after projection.
func TestProtectedLDAPSourceValuesAreCleared(t *testing.T) {
	entry := &goldap.Entry{Attributes: []*goldap.EntryAttribute{
		{Name: attrPrivatePKCS8, Values: []string{"private"}, ByteValues: [][]byte{[]byte("private")}},
		{Name: attrCandidateDigest, Values: []string{"digest"}, ByteValues: [][]byte{[]byte("digest")}},
		{Name: attrOperationID, Values: []string{"operation"}, ByteValues: [][]byte{[]byte("operation")}},
		{Name: attrAdminLockOwner, Values: []string{"owner"}, ByteValues: [][]byte{[]byte("owner")}},
		{Name: attrGeneration, Values: []string{"1"}, ByteValues: [][]byte{[]byte("1")}},
	}}
	clearLDAPProtectedAttributeBytes([]*goldap.Entry{entry})
	for _, attribute := range entry.Attributes[:4] {
		if len(attribute.Values) != 0 || len(attribute.ByteValues) != 0 {
			t.Fatal("protected LDAP source value retained")
		}
	}
	if len(entry.Attributes[4].Values) != 1 || entry.Attributes[4].Values[0] != "1" {
		t.Fatal("nonprotected LDAP source value was destroyed")
	}
}

// cloneLDAPEntries detaches synthetic go-ldap entries for destructive negative tests.
func cloneLDAPEntries(entries []*goldap.Entry) []*goldap.Entry {
	cloned := make([]*goldap.Entry, 0, len(entries))
	for _, entry := range entries {
		copyEntry := &goldap.Entry{DN: entry.DN}
		for _, attribute := range entry.Attributes {
			copyEntry.Attributes = append(copyEntry.Attributes, &goldap.EntryAttribute{
				Name: attribute.Name, Values: append([]string(nil), attribute.Values...),
			})
			for _, value := range attribute.ByteValues {
				copyEntry.Attributes[len(copyEntry.Attributes)-1].ByteValues = append(
					copyEntry.Attributes[len(copyEntry.Attributes)-1].ByteValues, bytes.Clone(value),
				)
			}
		}
		cloned = append(cloned, copyEntry)
	}
	return cloned
}

// ReadCurrentOptional returns exact synthetic pointer presence.
func (c *administrationClientFake) ReadCurrentOptional(context.Context) (Entry, bool, error) {
	return cloneEntry(c.current), c.currentPresent, nil
}

// ListGenerationRoots returns detached bounded generation metadata.
func (c *administrationClientFake) ListGenerationRoots(context.Context, datasourceadmin.GenerationLimits) ([]Entry, error) {
	result := make([]Entry, len(c.roots))
	for index := range c.roots {
		result[index] = cloneEntry(c.roots[index])
	}
	return result, nil
}

// ListRetentionGenerationRoots returns detached roots under the independent recovery limit.
func (c *administrationClientFake) ListRetentionGenerationRoots(_ context.Context, limits datasourceadmin.RetentionRecoveryLimits, budget *retentionReadBudget) ([]Entry, error) {
	if len(c.roots) > int(limits.MaxGenerations) {
		return nil, errLDAPPartial
	}
	for _, root := range c.roots {
		if !budget.consume(entryBytes(root)) {
			return nil, errLDAPPartial
		}
	}
	return c.ListGenerationRoots(context.Background(), datasourceadmin.GenerationLimits{MaxGenerations: 1, MaxOutstandingCandidates: 1, MaxSnapshotRows: 1, MaxSnapshotBytes: 1, BackendDeadline: time.Second})
}

// ReadGenerationRecords returns one detached complete synthetic subtree.
func (c *administrationClientFake) ReadGenerationRecords(
	_ context.Context,
	generation uint64,
	_ provider.Limits,
	_ datasourceadmin.GenerationLimits,
) (DatasetRecords, bool, error) {
	c.generationReads++
	records, present := c.generations[generation]
	detached := cloneDatasetRecords(records)
	c.returnedRecords = append(c.returnedRecords, detached)
	return detached, present, nil
}

// ReadAdministrationLock returns one protected owner/revision sight.
func (c *administrationClientFake) ReadAdministrationLock(context.Context) (datasourceadmin.AdministrationLockObservation, error) {
	return c.lock, nil
}

// ClaimAdministrationLock applies one exact ownerless revision assertion.
func (c *administrationClientFake) ClaimAdministrationLock(
	_ context.Context,
	operation datasourceadmin.OperationBinding,
	revision uint64,
) error {
	if c.mutationErr != nil {
		return c.mutationErr
	}
	if !c.lock.Valid() || c.lock.Claimed() || c.lock.Revision() != revision {
		return errLDAPConflict
	}
	c.lock, _ = datasourceadmin.NewAdministrationLockObservation(revision, operation, true)
	return nil
}

// ReleaseAdministrationLock applies one exact same-owner revision assertion.
func (c *administrationClientFake) ReleaseAdministrationLock(
	_ context.Context,
	lock datasourceadmin.AdministrationLock,
) error {
	if c.mutationErr != nil {
		return c.mutationErr
	}
	if !c.lock.Claimed() || c.lock.Revision() != lock.Revision() || !c.lock.Owner().Equal(lock.Owner()) {
		return errLDAPConflict
	}
	c.lock, _ = datasourceadmin.NewAdministrationLockObservation(lock.Revision()+1, datasourceadmin.OperationBinding{}, false)
	return nil
}

// AddCandidate installs one precomputed complete staging fixture.
func (c *administrationClientFake) AddCandidate(context.Context, *datasourceadmin.PublicationEnvelope) error {
	c.stageCalls++
	if c.mutationErr != nil {
		return c.mutationErr
	}
	generation := c.stageRecords.Root.Attributes[attrGeneration][0]
	parsed, _ := parseGeneration(generation)
	c.generations[parsed] = cloneDatasetRecords(c.stageRecords)
	c.roots = append(c.roots, cloneEntry(c.stageRecords.Root))
	return nil
}

// SealCandidate changes only exact staging root state to committed.
func (c *administrationClientFake) SealCandidate(
	_ context.Context,
	_ uint64,
	_ datasourceadmin.OperationBinding,
	_ datasourceadmin.CandidateContentDigest,
) error {
	c.sealCalls++
	if c.mutationErr != nil {
		return c.mutationErr
	}
	for generation, records := range c.generations {
		records.Root.Attributes[attrDatasetState] = [][]byte{[]byte("committed")}
		c.generations[generation] = records
	}
	for index := range c.roots {
		if values := c.roots[index].Attributes[attrDatasetState]; len(values) == 1 && string(values[0]) == "staging" {
			c.roots[index].Attributes[attrDatasetState] = [][]byte{[]byte("committed")}
		}
	}
	return nil
}

// MarkWasActive records monotonic old-current evidence.
func (c *administrationClientFake) MarkWasActive(_ context.Context, metadata datasetMetadata) error {
	c.markCalls++
	if c.mutationErr != nil {
		return c.mutationErr
	}
	for generation, records := range c.generations {
		if generation == metadata.generation {
			records.Root.Attributes[attrWasActive] = [][]byte{[]byte("TRUE")}
			c.generations[generation] = records
		}
	}
	return nil
}

// ReplaceCurrent applies one established exact current-pointer fence.
func (c *administrationClientFake) ReplaceCurrent(
	_ context.Context,
	_ datasetMetadata,
	candidate datasetMetadata,
) error {
	c.replaceCalls++
	if c.mutationErr != nil {
		return c.mutationErr
	}
	c.current = currentEntry(candidate)
	c.currentPresent = true
	return nil
}

// AddCurrent applies one absent-current atomic Add fence.
func (c *administrationClientFake) AddCurrent(_ context.Context, candidate datasetMetadata) error {
	c.addCurrentCalls++
	if c.mutationErr != nil {
		return c.mutationErr
	}
	if c.currentPresent {
		return errLDAPConflict
	}
	c.current = currentEntry(candidate)
	c.currentPresent = true
	return c.addErrAfterWrite
}

// TestAdministratorLockLifecycleUsesExactOwnerRevision freezes persistent lock fencing.
func TestAdministratorLockLifecycleUsesExactOwnerRevision(t *testing.T) {
	operation, _ := datasourceadmin.NewOperationBinding("aibqibiga4eascqlbqgzav3y4m")
	ownerless, _ := datasourceadmin.NewAdministrationLockObservation(1, datasourceadmin.OperationBinding{}, false)
	client := &administrationClientFake{fakeClient: &fakeClient{}, lock: ownerless}
	administrator := newAdministratorFixture(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lock, err := administrator.Claim(ctx, operation, 1)
	if err != nil || !lock.ValidFor(operation) || lock.Revision() != 1 {
		t.Fatal("claim exact ownerless revision")
	}
	next, err := administrator.Release(ctx, lock)
	if err != nil || next != 2 {
		t.Fatal("release exact same-owner revision")
	}
	if repeated, err := administrator.Release(ctx, lock); err != nil || repeated != 2 {
		t.Fatal("exact completed release was not idempotent")
	}
}

// TestAdministratorStagesCanonicalReadbackBeforeSeal freezes full private/public equivalence.
func TestAdministratorStagesCanonicalReadbackBeforeSeal(t *testing.T) {
	candidate, records, operation := administrationCandidateFixture(t, 2)
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	claimed, _ := datasourceadmin.NewAdministrationLockObservation(1, operation, true)
	currentRecords := minimalRecords(t)
	client := &administrationClientFake{
		fakeClient: &fakeClient{}, lock: claimed,
		current: cloneEntry(currentRecords.Current), currentPresent: true,
		roots:        []Entry{cloneEntry(currentRecords.Root)},
		generations:  map[uint64]DatasetRecords{1: currentRecords},
		stageRecords: records,
	}
	administrator := newAdministratorFixture(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lock, _ := datasourceadmin.NewAdministrationLock(operation, 1)
	staged, err := administrator.Stage(ctx, lock, operation, candidate)
	if err != nil || !candidate.PreparedEvidence().Matches(staged) ||
		client.stageCalls != 1 || client.sealCalls != 1 {
		t.Fatal("stage did not prove exact canonical readback before sealing")
	}

	client = &administrationClientFake{
		fakeClient: &fakeClient{}, lock: claimed,
		current: cloneEntry(currentRecords.Current), currentPresent: true,
		roots:        []Entry{cloneEntry(currentRecords.Root)},
		generations:  map[uint64]DatasetRecords{1: currentRecords},
		stageRecords: cloneDatasetRecords(records),
	}
	client.stageRecords.KeyMaterial[0].Attributes[attrPrivatePKCS8][0][0] ^= 0xff
	administrator = newAdministratorFixture(t, client)
	if _, err := administrator.Stage(ctx, lock, operation, candidate); datasourceadmin.CodeOf(err) != datasourceadmin.CodeReconcileRequired ||
		client.sealCalls != 0 {
		t.Fatal("mismatched private readback reached staging seal")
	}
}

// TestRetentionRecoveryBudgetCombinesRootAndRecordBytes proves the recovery
// ceiling applies to every LDAP response, not only complete child readback.
func TestRetentionRecoveryBudgetCombinesRootAndRecordBytes(t *testing.T) {
	records := minimalRecords(t)
	client := &administrationClientFake{
		fakeClient: &fakeClient{}, current: cloneEntry(records.Current), currentPresent: true,
		roots: []Entry{cloneEntry(records.Root)}, generations: map[uint64]DatasetRecords{1: records},
	}
	administrator := newAdministratorFixture(t, client)
	total := entryBytes(records.Current) + entryBytes(records.Root) + datasetRecordsDecodedBytes(records) + entryBytes(records.Current)
	limits := datasourceadmin.DefaultRetentionRecoveryLimits()
	limits.MaxReadBytes = uint32(total - 1)
	if _, err := administrator.RetentionRecoveryInventory(t.Context(), limits); datasourceadmin.CodeOf(err) != datasourceadmin.CodeLimitExceeded {
		t.Fatal("LDAP recovery accepted root and record bytes beyond one shared limit")
	}
}

// TestAdministratorPublishesOneCompleteRotationCampaignCandidate freezes LDAP campaign composition.
func TestAdministratorPublishesOneCompleteRotationCampaignCandidate(t *testing.T) {
	currentRecords := minimalRecords(t)
	rows, err := mapAdministrativeRows(currentRecords, 1)
	if err != nil {
		t.Fatal("map campaign source rows")
	}
	source, err := datasourceadmin.NewSnapshotWithLimits(datasourceadmin.SchemaVersionV3, 1, rows, provider.ProductionLimits())
	clearAdministrativeRows(&rows)
	if err != nil {
		t.Fatal("construct campaign source")
	}
	defer source.Close() //nolint:errcheck // Test cleanup has no recovery.
	operationID := "aibqibiga4eascqlbqgzav3y4m"
	intent, err := rotationadmin.NewIntent(admincontract.ModeNormal, operationID, "")
	if err != nil {
		t.Fatal("construct campaign intent")
	}
	plan, err := rotationadmin.Freeze(t.Context(), source, 2, intent, rotationadmin.DefaultLimits())
	if err != nil {
		t.Fatal("freeze complete LDAP campaign")
	}
	defer plan.Close() //nolint:errcheck // Test cleanup has no recovery.
	preparer, err := rotationadmin.NewPreparer(rotationadmin.NativeKeyFactory{RSABits: 2048}, provider.ProductionLimits())
	if err != nil {
		t.Fatal("construct campaign preparer")
	}
	prepared, err := preparer.Prepare(t.Context(), plan, source)
	if err != nil {
		t.Fatal("prepare complete LDAP candidate")
	}
	defer prepared.Close() //nolint:errcheck // Test cleanup has no recovery.
	var stageRecords DatasetRecords
	if err := prepared.WithEnvelope(t.Context(), func(candidate *datasourceadmin.PublicationEnvelope) error {
		stageRecords = ldapRecordsForCampaignCandidate(t, candidate)
		return nil
	}); err != nil {
		t.Fatal("project campaign candidate")
	}
	claimed, _ := datasourceadmin.NewAdministrationLockObservation(1, sourceOperation(t, operationID), true)
	client := &administrationClientFake{
		fakeClient: &fakeClient{}, lock: claimed, current: cloneEntry(currentRecords.Current), currentPresent: true,
		roots: []Entry{cloneEntry(currentRecords.Root)}, generations: map[uint64]DatasetRecords{1: currentRecords},
		stageRecords: stageRecords,
	}
	administrator := newAdministratorFixture(t, client)
	journal, _ := rotationadmin.NewJournal(plan)
	_ = journal.BeginPreparing()
	_ = journal.RecordPrepared(prepared)
	operation := sourceOperation(t, operationID)
	lock, _ := datasourceadmin.NewAdministrationLock(operation, 1)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	// Seed one exact durable candidate to reproduce a crash before journal stage acknowledgement.
	var stageErr error
	if err := prepared.WithEnvelope(ctx, func(candidate *datasourceadmin.PublicationEnvelope) error {
		if !lock.ValidFor(operation) || !candidate.Binding().Equal(operation) || candidate.Generation() != 2 || !candidate.Digest().Valid() {
			t.Fatal("campaign fixture violated LDAP stage preconditions")
		}
		_, stageErr = administrator.Stage(ctx, lock, operation, candidate)
		return nil
	}); err != nil || stageErr != nil {
		t.Fatalf("direct LDAP campaign stage rejected: callback=%v code=%s", err, datasourceadmin.CodeOf(stageErr))
	}
	published, err := rotationadmin.Publish(ctx, plan, prepared, journal, administrator, lock, administrator.generations)
	if err != nil || published == nil || journal.State() != rotationadmin.StateStaged || client.stageCalls != 1 || client.sealCalls != 1 {
		t.Fatalf("LDAP did not publish and prove exactly one complete campaign candidate: err=%v state=%s stage=%d seal=%d", err, journal.State(), client.stageCalls, client.sealCalls)
	}
	_ = published.Close()
}

// TestAdministratorResumesOnlyExactSameOperationCandidate freezes crash-safe staging idempotency.
func TestAdministratorResumesOnlyExactSameOperationCandidate(t *testing.T) {
	candidate, records, operation := administrationCandidateFixture(t, 2)
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	claimed, _ := datasourceadmin.NewAdministrationLockObservation(1, operation, true)
	currentRecords := minimalRecords(t)
	client := &administrationClientFake{
		fakeClient: &fakeClient{}, lock: claimed,
		current: cloneEntry(currentRecords.Current), currentPresent: true,
		roots: []Entry{cloneEntry(currentRecords.Root), cloneEntry(records.Root)},
		generations: map[uint64]DatasetRecords{
			1: cloneDatasetRecords(currentRecords), 2: cloneDatasetRecords(records),
		},
	}
	administrator := newAdministratorFixture(t, client)
	lock, _ := datasourceadmin.NewAdministrationLock(operation, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	evidence, err := administrator.Stage(ctx, lock, operation, candidate)
	if err != nil || !evidence.Digest().Equal(candidate.Digest()) || client.stageCalls != 0 || client.sealCalls != 1 {
		t.Fatal("exact same-operation staging candidate was not resumed by readback and seal")
	}
	evidence, err = administrator.Stage(ctx, lock, operation, candidate)
	if err != nil || !evidence.Digest().Equal(candidate.Digest()) || client.stageCalls != 0 || client.sealCalls != 1 {
		t.Fatal("exact already-sealed candidate was not resumed without mutation")
	}

	wrong := cloneDatasetRecords(records)
	wrong.Root.Attributes[attrCandidateDigest][0][0] ^= 0xff
	client = &administrationClientFake{
		fakeClient: &fakeClient{}, lock: claimed,
		current: cloneEntry(currentRecords.Current), currentPresent: true,
		roots: []Entry{cloneEntry(currentRecords.Root), cloneEntry(wrong.Root)},
		generations: map[uint64]DatasetRecords{
			1: cloneDatasetRecords(currentRecords), 2: wrong,
		},
	}
	administrator = newAdministratorFixture(t, client)
	if _, err := administrator.Stage(ctx, lock, operation, candidate); err == nil ||
		datasourceadmin.CodeOf(err) != datasourceadmin.CodeReconcileRequired ||
		client.stageCalls != 0 || client.sealCalls != 0 {
		t.Fatal("mismatched same-generation candidate did not fail into reconciliation")
	}

	wrongOperation := cloneDatasetRecords(records)
	wrongOperation.Root.Attributes[attrOperationID] = [][]byte{[]byte("aibqibiga4eascqlbqgzav3x4m")}
	client = &administrationClientFake{
		fakeClient: &fakeClient{}, lock: claimed,
		current: cloneEntry(currentRecords.Current), currentPresent: true,
		roots: []Entry{cloneEntry(currentRecords.Root), cloneEntry(wrongOperation.Root)},
		generations: map[uint64]DatasetRecords{
			1: cloneDatasetRecords(currentRecords), 2: wrongOperation,
		},
	}
	administrator = newAdministratorFixture(t, client)
	if _, err := administrator.Stage(ctx, lock, operation, candidate); err == nil ||
		datasourceadmin.CodeOf(err) != datasourceadmin.CodeReconcileRequired ||
		client.stageCalls != 0 || client.sealCalls != 0 {
		t.Fatal("wrong-operation same-generation candidate reached staging mutation")
	}
}

// TestAdministratorRejectsMovingCurrentInventory reproduces a pointer change
// between the first and final current reads around root enumeration.
func TestAdministratorRejectsMovingCurrentInventory(t *testing.T) {
	current := minimalRecords(t)
	defer clearDatasetRecords(&current)
	candidateContent, candidate, _ := administrationCandidateFixture(t, 2)
	defer candidateContent.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer clearDatasetRecords(&candidate)
	candidate.Root.Attributes[attrDatasetState] = [][]byte{[]byte("committed")}
	metadata, err := mapGenerationMetadata(candidate.Root)
	if err != nil {
		t.Fatal("construct moved-current metadata")
	}
	base := &administrationClientFake{
		fakeClient: &fakeClient{}, current: cloneEntry(current.Current), currentPresent: true,
		roots: []Entry{cloneEntry(current.Root), cloneEntry(candidate.Root)},
	}
	moving := &movingCurrentAdministrationClient{
		administrationClientFake: base, finalCurrent: currentEntry(metadata),
	}
	administrator := newAdministratorFixture(t, moving)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	inventory, err := administrator.Inventory(ctx, administrator.generations)
	if datasourceadmin.CodeOf(err) != datasourceadmin.CodeConflict ||
		inventory.Current != 0 || len(inventory.Generations) != 0 || moving.currentReads != 2 {
		t.Fatal("moving current pointer escaped the stable-inventory fence")
	}
}

// TestAdministratorActivationTouchesOnlyHistoryAndCurrent freezes both pointer branches.
func TestAdministratorActivationTouchesOnlyHistoryAndCurrent(t *testing.T) {
	candidate, records, operation := administrationCandidateFixture(t, 2)
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	records.Root.Attributes[attrDatasetState] = [][]byte{[]byte("committed")}
	claimed, _ := datasourceadmin.NewAdministrationLockObservation(1, operation, true)
	currentRecords := minimalRecords(t)
	client := &administrationClientFake{
		fakeClient: &fakeClient{}, lock: claimed, current: cloneEntry(currentRecords.Current), currentPresent: true,
		roots:       []Entry{cloneEntry(currentRecords.Root), cloneEntry(records.Root)},
		generations: map[uint64]DatasetRecords{1: currentRecords, 2: records},
	}
	administrator := newAdministratorFixture(t, client)
	lock, _ := datasourceadmin.NewAdministrationLock(operation, 1)
	activation, _ := datasourceadmin.NewActivation(
		lock, operation, 1, 2, candidate.PreparedEvidence(),
		datasourceadmin.NewStagedEvidence(candidate.Digest()),
	)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := administrator.Activate(ctx, activation); err != nil ||
		client.markCalls != 1 || client.replaceCalls != 1 || client.addCurrentCalls != 0 {
		t.Fatal("established activation did not use exact history and pointer operations")
	}

	bootstrapCandidate, bootstrapRecords, bootstrapOperation := administrationCandidateFixture(t, 1)
	defer bootstrapCandidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	bootstrapRecords.Root.Attributes[attrDatasetState] = [][]byte{[]byte("committed")}
	bootstrapClaimed, _ := datasourceadmin.NewAdministrationLockObservation(1, bootstrapOperation, true)
	client = &administrationClientFake{
		fakeClient: &fakeClient{}, lock: bootstrapClaimed, currentPresent: false,
		roots:       []Entry{cloneEntry(bootstrapRecords.Root)},
		generations: map[uint64]DatasetRecords{1: bootstrapRecords},
	}
	administrator = newAdministratorFixture(t, client)
	bootstrapLock, _ := datasourceadmin.NewAdministrationLock(bootstrapOperation, 1)
	bootstrap, _ := datasourceadmin.NewActivation(
		bootstrapLock, bootstrapOperation, 0, 1, bootstrapCandidate.PreparedEvidence(),
		datasourceadmin.NewStagedEvidence(bootstrapCandidate.Digest()),
	)
	if err := administrator.Activate(ctx, bootstrap); err != nil ||
		client.addCurrentCalls != 1 || client.markCalls != 0 || client.replaceCalls != 0 {
		t.Fatal("bootstrap activation did not use absent-current Add only")
	}
}

// TestAdministratorBootstrapAmbiguousAddRequiresExactObservation proves an
// applied-but-error Add never returns success and is resolved only by readback.
func TestAdministratorBootstrapAmbiguousAddRequiresExactObservation(t *testing.T) {
	candidate, records, operation := administrationCandidateFixture(t, 1)
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer clearDatasetRecords(&records)
	records.Root.Attributes[attrDatasetState] = [][]byte{[]byte("committed")}
	claimed, _ := datasourceadmin.NewAdministrationLockObservation(1, operation, true)
	client := &administrationClientFake{
		fakeClient: &fakeClient{}, lock: claimed, currentPresent: false,
		roots: []Entry{cloneEntry(records.Root)}, generations: map[uint64]DatasetRecords{1: records},
		addErrAfterWrite: errLDAPConflict,
	}
	administrator := newAdministratorFixture(t, client)
	lock, _ := datasourceadmin.NewAdministrationLock(operation, 1)
	activation, _ := datasourceadmin.NewActivation(
		lock, operation, 0, 1, candidate.PreparedEvidence(),
		datasourceadmin.NewStagedEvidence(candidate.Digest()),
	)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := administrator.Activate(ctx, activation); datasourceadmin.CodeOf(err) != datasourceadmin.CodeReconcileRequired {
		t.Fatal("ambiguous bootstrap Add inferred activation success")
	}
	observation, err := administrator.Observe(ctx, operation, 1, 0, administrator.generations)
	if err != nil || observation.State() != datasourceadmin.PublicationExactCommitted ||
		observation.CurrentGeneration() != 1 {
		t.Fatal("ambiguous bootstrap Add lacked exact independent readback classification")
	}
}

// TestAdministratorCrashHeldLockRejectsDifferentOperation proves an exact
// held owner cannot be stolen, used for staging, or released by another owner.
func TestAdministratorCrashHeldLockRejectsDifferentOperation(t *testing.T) {
	held, _ := datasourceadmin.NewOperationBinding("aibqibiga4eascqlbqgzav3y4m")
	foreignCandidate, foreignRecords, foreign := administrationCandidateFixtureWithOperation(
		t, 2, "aibqibiga4eascqlbqgzav3x4m",
	)
	defer foreignCandidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer clearDatasetRecords(&foreignRecords)
	observation, _ := datasourceadmin.NewAdministrationLockObservation(1, held, true)
	client := &administrationClientFake{fakeClient: &fakeClient{}, lock: observation}
	administrator := newAdministratorFixture(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := administrator.Claim(ctx, foreign, 1); datasourceadmin.CodeOf(err) != datasourceadmin.CodeConflict {
		t.Fatal("different operation stole a crash-held lock")
	}
	foreignLock, _ := datasourceadmin.NewAdministrationLock(foreign, 1)
	if _, err := administrator.Stage(ctx, foreignLock, foreign, foreignCandidate); datasourceadmin.CodeOf(err) != datasourceadmin.CodeConflict || client.stageCalls != 0 {
		t.Fatal("different operation used a crash-held lock for staging")
	}
	if _, err := administrator.Release(ctx, foreignLock); datasourceadmin.CodeOf(err) != datasourceadmin.CodeConflict ||
		!client.lock.Claimed() || !client.lock.Owner().Equal(held) {
		t.Fatal("different operation released a crash-held lock")
	}
}

// TestAdministratorObservationBindsExpectedCurrentAfterActivation reproduces
// the lifecycle readback that must retain old-current history after the
// candidate itself becomes current.
func TestAdministratorObservationBindsExpectedCurrentAfterActivation(t *testing.T) {
	candidate, records, operation := administrationCandidateFixture(t, 2)
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	records.Root.Attributes[attrDatasetState] = [][]byte{[]byte("committed")}
	currentRecords := minimalRecords(t)
	currentRecords.Root.Attributes[attrWasActive] = [][]byte{[]byte("TRUE")}
	candidateMetadata, err := mapGenerationMetadata(records.Root)
	if err != nil {
		t.Fatal("map candidate metadata")
	}
	client := &administrationClientFake{
		fakeClient: &fakeClient{}, current: currentEntry(candidateMetadata), currentPresent: true,
		roots: []Entry{cloneEntry(currentRecords.Root), cloneEntry(records.Root)},
		generations: map[uint64]DatasetRecords{
			1: cloneDatasetRecords(currentRecords), 2: cloneDatasetRecords(records),
		},
	}
	administrator := newAdministratorFixture(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	observation, err := administrator.Observe(ctx, operation, 2, 1, administrator.generations)
	if err != nil || observation.CurrentGeneration() != 2 || !observation.OldCurrentWasActive() {
		t.Fatal("post-activation observation lost exact old-current history")
	}
	inspected, info, err := administrator.Inspect(ctx, operation, 2, 1, administrator.generations)
	if inspected != nil {
		defer inspected.Close() //nolint:errcheck // Test cleanup has no recovery.
	}
	if err != nil || inspected == nil || !info.Current {
		t.Fatal("inspection did not stable-read exact current identity")
	}
}

// TestGenerationRootProjectionRejectsEveryForeignDirectChild reproduces the
// inventory hole caused by filtering the enumeration to dataset roots.
func TestGenerationRootProjectionRejectsEveryForeignDirectChild(t *testing.T) {
	base := testGenerationBaseDN
	root := &goldap.Entry{DN: "dkim2Generation=9," + base, Attributes: []*goldap.EntryAttribute{
		{Name: attrObjectClass, Values: []string{topObjectClass, datasetObjectClass}, ByteValues: [][]byte{[]byte(topObjectClass), []byte(datasetObjectClass)}},
		{Name: "cn", Values: []string{"generation-9"}, ByteValues: [][]byte{[]byte("generation-9")}},
		{Name: attrSchemaVersion, Values: []string{datasourceadmin.SchemaVersionV2}, ByteValues: [][]byte{[]byte(datasourceadmin.SchemaVersionV2)}},
		{Name: attrGeneration, Values: []string{"9"}, ByteValues: [][]byte{[]byte("9")}},
		{Name: attrDatasetState, Values: []string{"committed"}, ByteValues: [][]byte{[]byte("committed")}},
	}}
	entry, err := mapGenerationRootSource(base, root)
	if err != nil {
		t.Fatal("exact direct generation root rejected")
	}
	clearEntry(&entry)
	foreign := cloneLDAPEntries([]*goldap.Entry{root})[0]
	foreign.DN = "cn=foreign-999999," + base
	if _, err := mapGenerationRootSource(base, foreign); err == nil {
		t.Fatal("high-generation foreign direct child was hidden from inventory")
	}
}

// TestCollisionInventoryPreflightAndAggregateBound reproduces both pre-I/O
// ceiling enforcement and aggregate retained-snapshot accounting.
func TestCollisionInventoryPreflightAndAggregateBound(t *testing.T) {
	operation, _ := datasourceadmin.NewOperationBinding("aibqibiga4eascqlbqgzav3y4m")
	claimed, _ := datasourceadmin.NewAdministrationLockObservation(1, operation, true)
	lock, _ := datasourceadmin.NewAdministrationLock(operation, 1)
	current := minimalRecords(t)
	candidate, staging, _ := administrationCandidateFixture(t, 2)
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	client := &administrationClientFake{
		fakeClient: &fakeClient{}, lock: claimed, current: cloneEntry(current.Current), currentPresent: true,
		roots:       []Entry{cloneEntry(current.Root), cloneEntry(staging.Root)},
		generations: map[uint64]DatasetRecords{1: current, 2: staging},
	}
	limits := datasourceadmin.GenerationLimits{
		MaxGenerations: 4, MaxOutstandingCandidates: 1, MaxSnapshotRows: 4096,
		MaxSnapshotBytes: 32 << 20, BackendDeadline: 2 * time.Second,
	}
	administrator := newAdministratorWithLimits(t, client, limits)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := administrator.ReadCollisionInventory(ctx, lock, limits); datasourceadmin.CodeOf(err) != datasourceadmin.CodeLimitExceeded || client.generationReads != 0 {
		t.Fatal("at-ceiling allocation performed protected subtree I/O")
	}

	client = &administrationClientFake{
		fakeClient: &fakeClient{}, lock: claimed, current: cloneEntry(current.Current), currentPresent: true,
		roots:       []Entry{cloneEntry(current.Root), cloneEntry(staging.Root)},
		generations: map[uint64]DatasetRecords{1: current, 2: staging},
	}
	firstBytes := datasetRecordsSize(current)
	secondBytes := datasetRecordsSize(staging)
	limits.MaxOutstandingCandidates = 2
	limits.MaxSnapshotBytes = uint32(max(firstBytes, secondBytes) + min(firstBytes, secondBytes)/2)
	administrator = newAdministratorWithLimits(t, client, limits)
	if _, err := administrator.ReadCollisionInventory(ctx, lock, limits); datasourceadmin.CodeOf(err) != datasourceadmin.CodeLimitExceeded {
		t.Fatal("aggregate collision snapshot bytes exceeded without rejection")
	}
	for index := range client.returnedRecords {
		if len(client.returnedRecords[index].KeyMaterial) != 0 && client.returnedRecords[index].KeyMaterial[0].Attributes != nil {
			t.Fatal("iteration-retained key records were not cleared on aggregate failure")
		}
	}
}

// TestStagingHistoryIsRejectedBeforeSeal reproduces invalid lifecycle history
// on a never-active staging generation.
func TestStagingHistoryIsRejectedBeforeSeal(t *testing.T) {
	candidate, records, operation := administrationCandidateFixture(t, 2)
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	records.Root.Attributes[attrWasActive] = [][]byte{[]byte("TRUE")}
	claimed, _ := datasourceadmin.NewAdministrationLockObservation(1, operation, true)
	current := minimalRecords(t)
	client := &administrationClientFake{
		fakeClient: &fakeClient{}, lock: claimed, current: cloneEntry(current.Current), currentPresent: true,
		roots:       []Entry{cloneEntry(current.Root), cloneEntry(records.Root)},
		generations: map[uint64]DatasetRecords{1: current, 2: records},
	}
	administrator := newAdministratorFixture(t, client)
	lock, _ := datasourceadmin.NewAdministrationLock(operation, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := administrator.Stage(ctx, lock, operation, candidate); err == nil || client.sealCalls != 0 {
		t.Fatal("staging WasActive history reached the seal transition")
	}
}

// TestProtectedLateConversionFailureClearsSource reproduces partial detached
// Dataset and key-material copies surviving a late malformed attribute.
func TestProtectedLateConversionFailureClearsSource(t *testing.T) {
	for _, fixture := range []struct {
		class RecordClass
		name  string
	}{
		{RecordClassDataset, attrCandidateDigest},
		{RecordClassKeyMaterial, attrPrivatePKCS8},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			protected := bytes.Repeat([]byte{0x5a}, 32)
			source := &goldap.Entry{DN: "cn=record", Attributes: []*goldap.EntryAttribute{
				{Name: fixture.name, Values: []string{string(protected)}, ByteValues: [][]byte{protected}},
				{Name: "broken", Values: []string{""}, ByteValues: nil},
			}}
			if _, err := convertEntry(fixture.class, source); err == nil {
				t.Fatal("late malformed attribute accepted")
			}
			if len(source.Attributes[0].ByteValues) != 0 || len(source.Attributes[0].Values) != 0 {
				t.Fatal("protected source survived late conversion failure")
			}
		})
	}
}

// TestProjectedEntryClearsProtectedCopiesAfterSuccess proves detached values
// remain valid while every protected intermediate projection is destroyed.
func TestProjectedEntryClearsProtectedCopiesAfterSuccess(t *testing.T) {
	for _, fixture := range []struct {
		class      RecordClass
		attributes []*goldap.EntryAttribute
	}{
		{
			class: RecordClassDataset,
			attributes: []*goldap.EntryAttribute{
				{Name: attrCandidateDigest, Values: []string{"digest-copy"}, ByteValues: [][]byte{[]byte("digest-copy")}},
				{Name: attrOperationID, Values: []string{"operation-copy"}, ByteValues: [][]byte{[]byte("operation-copy")}},
			},
		},
		{
			class: RecordClassKeyMaterial,
			attributes: []*goldap.EntryAttribute{
				{Name: attrPrivatePKCS8, Values: []string{"private-copy"}, ByteValues: [][]byte{[]byte("private-copy")}},
			},
		},
	} {
		projected := &goldap.Entry{DN: "cn=projected", Attributes: fixture.attributes}
		detached, err := convertProjectedEntry(fixture.class, projected)
		if err != nil {
			t.Fatal("valid protected projection rejected")
		}
		for _, attribute := range projected.Attributes {
			if len(attribute.Values) != 0 || len(attribute.ByteValues) != 0 {
				t.Fatal("protected intermediate projection survived successful conversion")
			}
		}
		for _, attribute := range fixture.attributes {
			if len(detached.Attributes[attribute.Name]) != 1 || len(detached.Attributes[attribute.Name][0]) == 0 {
				t.Fatal("detached protected projection was destroyed with its source copy")
			}
		}
		clearEntry(&detached)
	}
}

// datasetRecordsSize returns the detached decoded bytes retained by one fake readback.
func datasetRecordsSize(records DatasetRecords) int {
	total := entryBytes(records.Root)
	for _, entries := range [][]Entry{records.Handles, records.Profiles, records.Credentials, records.Policies, records.KeyMaterial} {
		for _, entry := range entries {
			total += entryBytes(entry)
		}
	}
	return total
}

// newAdministratorFixture constructs one bounded three-role coordinator over a synthetic client.
func newAdministratorFixture(t *testing.T, client Client) *Administrator {
	t.Helper()
	return newAdministratorWithLimits(t, client, datasourceadmin.GenerationLimits{
		MaxGenerations: 256, MaxOutstandingCandidates: 8,
		MaxSnapshotRows: 4096, MaxSnapshotBytes: 32 << 20,
		BackendDeadline: 2 * time.Second,
	})
}

// newAdministratorWithLimits constructs one coordinator with exact test bounds.
func newAdministratorWithLimits(
	t *testing.T,
	client Client,
	limits datasourceadmin.GenerationLimits,
) *Administrator {
	t.Helper()
	administrator, err := NewAdministrator(
		newAdministrationConnectorFake(t, client, "snapshot"),
		newAdministrationConnectorFake(t, client, "stager"),
		newAdministrationConnectorFake(t, client, "activator"),
		provider.DefaultLimits(), limits,
	)
	if err != nil {
		t.Fatal("construct LDAP administrator")
	}
	return administrator
}

// newAdministrationConnectorFake binds one shared synthetic client to a
// distinct canonical LDAP administration authority.
func newAdministrationConnectorFake(
	t *testing.T,
	client Client,
	role string,
) administrationConnectorFake {
	t.Helper()
	authority, err := newAdministrationAuthority(
		"cn=dkim2-" + role + ",ou=services,dc=example,dc=test",
	)
	if err != nil {
		t.Fatal("construct synthetic LDAP administration authority")
	}
	return administrationConnectorFake{client: client, authority: authority}
}

// administrationCandidateFixture constructs exact v3 staging records and their protected owner.
func administrationCandidateFixture(
	t *testing.T,
	generation uint64,
) (*datasourceadmin.PublicationEnvelope, DatasetRecords, datasourceadmin.OperationBinding) {
	return administrationCandidateFixtureWithOperation(t, generation, "aibqibiga4eascqlbqgzav3y4m")
}

// administrationCandidateFixtureWithOperation constructs exact v3 staging
// records for one explicit protected operation owner.
func administrationCandidateFixtureWithOperation(
	t *testing.T,
	generation uint64,
	operationID string,
) (*datasourceadmin.PublicationEnvelope, DatasetRecords, datasourceadmin.OperationBinding) {
	t.Helper()
	base := minimalRecords(t)
	rows, err := mapAdministrativeRows(base, 1)
	if err != nil {
		t.Fatal("map administrative fixture rows")
	}
	defer clearAdministrativeRows(&rows)
	snapshot, err := datasourceadmin.NewSnapshot(datasourceadmin.SchemaVersionV3, generation, rows)
	if err != nil {
		t.Fatal("construct administrative fixture snapshot")
	}
	content, err := datasourceadmin.NewCandidateContent(snapshot)
	if err != nil {
		_ = snapshot.Close()
		t.Fatal("construct administrative fixture content")
	}
	candidate, err := datasourceadmin.NewPublicationEnvelope(operationID, content)
	if err != nil {
		_ = content.Close()
		t.Fatal("construct administrative fixture envelope")
	}
	operation := candidate.Binding()
	digest := candidate.Digest().Bytes()
	t.Cleanup(func() { clear(digest) })
	generationText := strconv.FormatUint(generation, 10)
	updateGeneration := func(entries []Entry) {
		for index := range entries {
			entries[index].Attributes[attrGeneration] = [][]byte{[]byte(generationText)}
		}
	}
	updateGeneration(base.Handles)
	updateGeneration(base.Profiles)
	updateGeneration(base.Credentials)
	updateGeneration(base.Policies)
	updateGeneration(base.KeyMaterial)
	root := Entry{Class: RecordClassDataset, Attributes: map[string][][]byte{
		attrSchemaVersion: {[]byte(datasourceadmin.SchemaVersionV3)},
		attrGeneration:    {[]byte(generationText)}, attrDatasetState: {[]byte("staging")},
		attrCandidateDigest: {bytes.Clone(digest)}, attrOperationID: {[]byte(operationID)},
	}}
	base.Current, base.Root = Entry{}, root
	return candidate, base, operation
}

// cloneDatasetRecords detaches one complete synthetic LDAP generation.
func cloneDatasetRecords(records DatasetRecords) DatasetRecords {
	result := DatasetRecords{Current: cloneEntry(records.Current), Root: cloneEntry(records.Root)}
	clone := func(entries []Entry) []Entry {
		output := make([]Entry, len(entries))
		for index := range entries {
			output[index] = cloneEntry(entries[index])
		}
		return output
	}
	result.Handles, result.Profiles = clone(records.Handles), clone(records.Profiles)
	result.Credentials, result.Policies = clone(records.Credentials), clone(records.Policies)
	result.KeyMaterial = clone(records.KeyMaterial)
	return result
}

// sourceOperation constructs one protected operation fixture.
func sourceOperation(t *testing.T, operationID string) datasourceadmin.OperationBinding {
	t.Helper()
	operation, err := datasourceadmin.NewOperationBinding(operationID)
	if err != nil {
		t.Fatal("construct operation fixture")
	}
	return operation
}

// ldapRecordsForCampaignCandidate projects one complete envelope through the LDAP add mapper.
func ldapRecordsForCampaignCandidate(t *testing.T, candidate *datasourceadmin.PublicationEnvelope) DatasetRecords {
	t.Helper()
	operation := candidate.Binding()
	var operationValue string
	if err := operation.WithValue(t.Context(), func(value string) error { operationValue = value; return nil }); err != nil {
		t.Fatal("read candidate operation")
	}
	digest := candidate.Digest().Bytes()
	defer clear(digest)
	root := "dkim2Generation=2,ou=generations,ou=dkim2,dc=example,dc=test"
	var entries []*goldap.Entry
	if err := candidate.WithRows(t.Context(), func(rows datasourceadmin.Rows) error {
		for _, request := range candidateAddRequests(root, "2", operationValue, candidate.SourceGeneration(), digest, rows) {
			entry := &goldap.Entry{DN: request.DN}
			for _, attribute := range request.Attributes {
				projected := &goldap.EntryAttribute{Name: attribute.Type}
				for _, value := range attribute.Vals {
					projected.Values = append(projected.Values, value)
					projected.ByteValues = append(projected.ByteValues, []byte(value))
				}
				entry.Attributes = append(entry.Attributes, projected)
			}
			entries = append(entries, entry)
		}
		return nil
	}); err != nil {
		t.Fatal("project candidate add requests")
	}
	defer clearLDAPProtectedAttributeBytes(entries)
	records, err := mapCompleteGenerationEntries(entries, root, 2)
	if err != nil {
		t.Fatal("map complete campaign generation")
	}
	return records
}

// currentEntry projects exact v3 current metadata without operation or history fields.
func currentEntry(metadata datasetMetadata) Entry {
	return Entry{Class: RecordClassDataset, Attributes: map[string][][]byte{
		attrSchemaVersion: {[]byte(datasourceadmin.SchemaVersionV3)},
		attrGeneration:    {[]byte(strconv.FormatUint(metadata.generation, 10))}, attrDatasetState: {[]byte("committed")},
		attrCandidateDigest: {metadata.digest.Bytes()},
	}}
}
