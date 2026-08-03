package migration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strconv"

	datasourceldap "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/ldap"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/sqlsnapshot"
	"github.com/croessner/dkim2/provider"
	goldap "github.com/go-ldap/ldap/v3"
)

const (
	ldapDatasetObjectClass     = "dkim2Dataset"
	ldapAlgorithmAttribute     = "dkim2Algorithm"
	ldapPublicKeySPKIAttribute = "dkim2PublicKeySPKI"
)

// LDAPPublisher owns one verified, authenticated LDAP publication connection.
type LDAPPublisher struct {
	client *ldapInventoryClient
}

// NewLDAPPublisherClient opens one separate verified-TLS LDAP publisher principal.
func NewLDAPPublisherClient(
	ctx context.Context,
	source SourceConfig,
	password []byte,
	rootsDER [][]byte,
) (*LDAPPublisher, func() error, error) {
	client, closeClient, err := NewLDAPInventoryClient(ctx, source, password, rootsDER)
	if err != nil {
		return nil, nil, errors.New("ldap publication unavailable")
	}
	concrete, ok := client.(*ldapInventoryClient)
	if !ok || concrete == nil {
		_ = closeClient()
		return nil, nil, errors.New("ldap publication unavailable")
	}
	return &LDAPPublisher{client: concrete}, closeClient, nil
}

// Current reads one exact committed LDAP fence or proves an entirely empty backend.
func (p *LDAPPublisher) Current(ctx context.Context) (uint64, error) {
	entry, absent, err := p.readCurrent(ctx)
	if err != nil {
		return 0, errors.New("ldap publication unavailable")
	}
	if absent {
		if !p.emptyGenerationContainer(ctx) {
			return 0, errors.New("ldap publication unavailable")
		}
		return 0, nil
	}
	schemaValues := entry.GetRawAttributeValues(ldapSchemaVersionAttribute)
	generationValues := entry.GetRawAttributeValues(ldapGenerationAttribute)
	stateValues := entry.GetRawAttributeValues(ldapDatasetStateAttribute)
	if len(schemaValues) != 1 || len(generationValues) != 1 ||
		len(stateValues) != 1 ||
		!supportedPublicationFenceVersion(string(schemaValues[0])) ||
		string(stateValues[0]) != datasourceStateCommitted {
		return 0, errors.New("ldap publication unavailable")
	}
	generation, err := parseGeneration(string(generationValues[0]))
	if err != nil {
		return 0, errors.New("ldap publication unavailable")
	}
	return generation, nil
}

// supportedPublicationFenceVersion permits an administrative v1 current
// fence only so one complete v2 generation can replace it without fallback.
func supportedPublicationFenceVersion(version string) bool {
	return version == "dkim2-datasource-v1" || version == migrationSchemaVersion
}

// Publish stages, validates, commits, and assertion-fences one LDAP generation.
func (p *LDAPPublisher) Publish(
	ctx context.Context,
	expected uint64,
	candidate PublicationCandidate,
) error {
	if p == nil || p.client == nil || ctx == nil || candidate.Generation() == 0 ||
		candidate.Generation() <= expected {
		return errors.New("ldap publication unavailable")
	}
	rows, rowsErr := candidate.detachedRows(ctx)
	if rowsErr != nil {
		return errors.New("ldap publication unavailable")
	}
	defer clearCandidateRows(&rows)
	generation := strconv.FormatUint(candidate.Generation(), 10)
	if expected == 0 && p.claimBootstrap(ctx, generation) != nil {
		return errors.New("ldap publication unavailable")
	}
	if p.addCandidate(ctx, rows) != nil ||
		p.validateCandidateReadback(ctx, candidate.Generation(), rows) != nil {
		return errors.New("ldap publication unavailable")
	}
	rootDN := p.generationRoot(generation)
	commit := goldap.NewModifyRequest(rootDN, nil)
	commit.Replace(ldapDatasetStateAttribute, []string{datasourceStateCommitted})
	if err := p.client.call(ctx, func() error {
		return p.client.connection.Modify(commit)
	}); err != nil {
		return errors.New("ldap publication unavailable")
	}
	currentDN := "cn=current," + p.client.baseDN
	if expected == 0 {
		assertion, assertionErr := datasourceldap.NewCriticalAssertionControl(
			"(&(" + ldapSchemaVersionAttribute + "=" + migrationSchemaVersion + ")(" +
				ldapGenerationAttribute + "=" + generation + ")(" +
				ldapDatasetStateAttribute + "=" + datasourceStateStaging + "))",
		)
		if assertionErr != nil {
			return errors.New("ldap publication unavailable")
		}
		activate := goldap.NewModifyRequest(currentDN, []goldap.Control{
			assertion,
		})
		activate.Replace(ldapDatasetStateAttribute, []string{datasourceStateCommitted})
		if err := p.client.call(ctx, func() error {
			return p.client.connection.Modify(activate)
		}); err != nil {
			return errors.New("ldap publication unavailable")
		}
		return nil
	}
	fence, err := newEstablishedCurrentFenceRequest(currentDN, expected, generation)
	if err != nil {
		return errors.New("ldap publication unavailable")
	}
	if err := p.client.call(ctx, func() error {
		return p.client.connection.Modify(fence)
	}); err != nil {
		return errors.New("ldap publication unavailable")
	}
	return nil
}

// newEstablishedCurrentFenceRequest upgrades the schema and generation under
// one exact committed v1-or-v2 assertion so mixed current metadata is impossible.
func newEstablishedCurrentFenceRequest(
	currentDN string,
	expected uint64,
	generation string,
) (*goldap.ModifyRequest, error) {
	filter := "(&(" + ldapGenerationAttribute + "=" + strconv.FormatUint(expected, 10) + ")(" +
		ldapDatasetStateAttribute + "=" + datasourceStateCommitted + ")(|(" +
		ldapSchemaVersionAttribute + "=dkim2-datasource-v1)(" +
		ldapSchemaVersionAttribute + "=" + migrationSchemaVersion + ")))"
	assertion, err := datasourceldap.NewCriticalAssertionControl(filter)
	if err != nil {
		return nil, errors.New("ldap publication unavailable")
	}
	fence := goldap.NewModifyRequest(currentDN, []goldap.Control{assertion})
	fence.Replace(ldapGenerationAttribute, []string{generation})
	fence.Replace(ldapSchemaVersionAttribute, []string{migrationSchemaVersion})
	return fence, nil
}

// claimBootstrap atomically reserves an absent current DN in noncurrent staging state.
func (p *LDAPPublisher) claimBootstrap(ctx context.Context, generation string) error {
	if p == nil || p.client == nil || ctx == nil || generation == "" {
		return errors.New("ldap publication unavailable")
	}
	request := newLDAPAdd(
		"cn=current,"+p.client.baseDN,
		map[string][]string{
			legacyObjectClass:          {ldapTopObjectClass, ldapDatasetObjectClass},
			"cn":                       {"current"},
			ldapSchemaVersionAttribute: {migrationSchemaVersion},
			ldapGenerationAttribute:    {generation},
			ldapDatasetStateAttribute:  {datasourceStateStaging},
		},
	)
	if err := p.client.call(ctx, func() error {
		return p.client.connection.Add(request)
	}); err != nil {
		return errors.New("ldap publication unavailable")
	}
	return nil
}

// addCandidate creates one complete staging subtree without editing prior content.
func (p *LDAPPublisher) addCandidate(
	ctx context.Context,
	rows sqlsnapshot.DatasetRows,
) error {
	generation := rows.Current.Generation
	rootDN := p.generationRoot(generation)
	requests := []*goldap.AddRequest{
		newLDAPAdd(rootDN, map[string][]string{
			legacyObjectClass:          {ldapTopObjectClass, ldapDatasetObjectClass},
			"cn":                       {"generation-" + generation},
			ldapSchemaVersionAttribute: {migrationSchemaVersion},
			ldapGenerationAttribute:    {generation}, ldapDatasetStateAttribute: {datasourceStateStaging},
		}),
	}
	for _, unit := range []string{"handles", "profiles", "credentials", "policies", "key-material"} {
		requests = append(requests, newLDAPAdd(
			"ou="+unit+","+rootDN,
			map[string][]string{legacyObjectClass: {ldapTopObjectClass, "organizationalUnit"}, "ou": {unit}},
		))
	}
	for index, row := range rows.Handles {
		requests = append(requests, newLDAPAdd(
			ldapRecordDN(index, "handles", rootDN),
			map[string][]string{
				legacyObjectClass: {ldapTopObjectClass, "dkim2Handle"}, "cn": {ldapRecordCN(index)},
				ldapGenerationAttribute: {row.Generation}, ldapHandleAttribute: {row.HandleID},
			},
		))
	}
	for index, row := range rows.Profiles {
		attributes := map[string][]string{
			legacyObjectClass: {ldapTopObjectClass, "dkim2Profile"}, "cn": {ldapRecordCN(index)},
			ldapGenerationAttribute: {row.Generation}, ldapProfileAttribute: {row.ProfileID},
			ldapSigningDomainAttribute: {row.Domain}, ldapRecordStatusAttribute: {row.Status},
		}
		if row.NotBeforeUTC != nil {
			attributes["dkim2NotBefore"] = []string{*row.NotBeforeUTC}
			attributes["dkim2NotAfter"] = []string{*row.NotAfterUTC}
		}
		requests = append(requests, newLDAPAdd(
			ldapRecordDN(index, "profiles", rootDN), attributes,
		))
	}
	for index, row := range rows.Credentials {
		request := goldap.NewAddRequest(
			ldapRecordDN(index, "credentials", rootDN), nil,
		)
		request.Attribute(legacyObjectClass, []string{ldapTopObjectClass, "dkim2Credential"})
		request.Attribute("cn", []string{ldapRecordCN(index)})
		request.Attribute(ldapGenerationAttribute, []string{row.Generation})
		request.Attribute(ldapProfileAttribute, []string{row.ProfileID})
		request.Attribute(ldapAlgorithmAttribute, []string{row.Algorithm})
		request.Attribute("dkim2Selector", []string{row.Selector})
		request.Attribute(ldapPublicKeySPKIAttribute, []string{string(row.PublicKeySPKI)})
		request.Attribute(ldapHandleAttribute, []string{row.HandleID})
		requests = append(requests, request)
	}
	for index, row := range rows.Policies {
		attributes := map[string][]string{
			legacyObjectClass: {ldapTopObjectClass, "dkim2Policy"}, "cn": {ldapRecordCN(index)},
			ldapGenerationAttribute: {row.Generation}, ldapTenantAttribute: {row.TenantID},
			ldapSigningDomainAttribute: {row.Domain}, ldapProfileUseAttribute: {row.Use},
			ldapProfileAttribute: {row.ProfileID}, ldapRecordStatusAttribute: {row.Status},
			ldapRolloutAttribute: {row.Rollout}, ldapCompatibilityAttribute: {row.Compatibility},
		}
		if row.FeedbackRouteID != nil {
			attributes["dkim2FeedbackRouteID"] = []string{*row.FeedbackRouteID}
		}
		requests = append(requests, newLDAPAdd(
			ldapRecordDN(index, "policies", rootDN), attributes,
		))
	}
	for index, row := range rows.KeyMaterial {
		request := goldap.NewAddRequest(
			ldapRecordDN(index, "key-material", rootDN), nil,
		)
		request.Attribute(legacyObjectClass, []string{ldapTopObjectClass, "dkim2KeyMaterial"})
		request.Attribute("cn", []string{ldapRecordCN(index)})
		request.Attribute(ldapGenerationAttribute, []string{row.Generation})
		request.Attribute(ldapTenantAttribute, []string{row.TenantID})
		request.Attribute(ldapSigningDomainAttribute, []string{row.Domain})
		request.Attribute(ldapProfileUseAttribute, []string{row.Use})
		request.Attribute(ldapHandleAttribute, []string{row.HandleID})
		request.Attribute(ldapAlgorithmAttribute, []string{row.Algorithm})
		request.Attribute(ldapPublicKeySPKIAttribute, []string{string(row.PublicSPKI)})
		request.Attribute(ldapPrivatePKCS8Attribute, []string{string(row.PrivatePKCS8)})
		requests = append(requests, request)
	}
	for _, request := range requests {
		current := request
		if err := p.client.call(ctx, func() error {
			return p.client.connection.Add(current)
		}); err != nil {
			return errors.New("ldap publication unavailable")
		}
	}
	return nil
}

// validateCandidateReadback maps the complete staged subtree through the runtime owner.
func (p *LDAPPublisher) validateCandidateReadback(
	ctx context.Context,
	candidateGeneration uint64,
	rows sqlsnapshot.DatasetRows,
) error {
	generation := rows.Current.Generation
	rootDN := p.generationRoot(generation)
	attributes := []string{
		legacyObjectClass, "ou", ldapSchemaVersionAttribute, ldapGenerationAttribute, ldapDatasetStateAttribute,
		ldapHandleAttribute, ldapProfileAttribute, ldapSigningDomainAttribute,
		ldapRecordStatusAttribute, "dkim2NotBefore", "dkim2NotAfter", ldapAlgorithmAttribute,
		"dkim2Selector", ldapPublicKeySPKIAttribute, ldapTenantAttribute, ldapProfileUseAttribute,
		ldapRolloutAttribute, ldapCompatibilityAttribute, "dkim2FeedbackRouteID",
		ldapPrivatePKCS8Attribute,
	}
	request := goldap.NewSearchRequest(
		rootDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		len(rows.Handles)+len(rows.Profiles)+
			len(rows.Credentials)+len(rows.Policies)+
			len(rows.KeyMaterial)+7,
		0, false, "(objectClass=*)", attributes, nil,
	)
	var result *goldap.SearchResult
	if err := p.client.call(ctx, func() error {
		var searchErr error
		result, searchErr = p.client.connection.Search(request)
		return searchErr
	}); err != nil || result == nil || len(result.Referrals) != 0 ||
		len(result.Entries) != len(rows.Handles)+len(rows.Profiles)+
			len(rows.Credentials)+len(rows.Policies)+
			len(rows.KeyMaterial)+6 {
		return errors.New("ldap publication readback unavailable")
	}
	records, err := publicationLDAPRecords(result.Entries, generation)
	if err != nil {
		return err
	}
	dataset, err := datasourceldap.MapDataset(records, provider.DefaultLimits())
	if err != nil || dataset == nil || !dataset.Valid() ||
		dataset.Generation() != candidateGeneration {
		return errors.New("ldap publication readback invalid")
	}
	if !candidateLDAPReadbackMatches(rows, records) {
		return errors.New("ldap publication readback mismatched")
	}
	return nil
}

// publicationLDAPRecords classifies exact staged readback entries.
//
//nolint:gocyclo // The closed LDAP structural-class matrix is intentionally explicit.
func publicationLDAPRecords(
	entries []*goldap.Entry,
	generation string,
) (datasourceldap.DatasetRecords, error) {
	records := datasourceldap.DatasetRecords{}
	rootSeen := false
	units := make(map[string]struct{}, 5)
	metadata := datasourceldap.Entry{
		Class: datasourceldap.RecordClassDataset,
		Attributes: map[string][][]byte{
			ldapSchemaVersionAttribute: {[]byte(migrationSchemaVersion)},
			ldapGenerationAttribute:    {[]byte(generation)},
			ldapDatasetStateAttribute:  {[]byte(datasourceStateCommitted)},
		},
	}
	records.Current = metadata
	for _, entry := range entries {
		if entry == nil {
			return datasourceldap.DatasetRecords{}, errors.New("ldap publication readback entry unavailable")
		}
		classes := entry.GetAttributeValues(legacyObjectClass)
		var class datasourceldap.RecordClass
		recognized := 0
		for _, expected := range []string{
			ldapDatasetObjectClass, "dkim2Handle", "dkim2Profile",
			"dkim2Credential", "dkim2Policy", "dkim2KeyMaterial",
		} {
			if containsLDAPValue(classes, expected) {
				recognized++
			}
		}
		switch {
		case recognized != 1 && containsLDAPValue(classes, "organizationalUnit"):
			values := entry.GetAttributeValues("ou")
			if recognized != 0 || len(values) != 1 ||
				!slices.Contains([]string{"handles", "profiles", "credentials", "policies", "key-material"}, values[0]) {
				return datasourceldap.DatasetRecords{}, errors.New("ldap publication readback unit malformed")
			}
			if _, duplicate := units[values[0]]; duplicate {
				return datasourceldap.DatasetRecords{}, errors.New("ldap publication readback unit duplicated")
			}
			units[values[0]] = struct{}{}
			continue
		case recognized != 1:
			return datasourceldap.DatasetRecords{}, errors.New("ldap publication readback class malformed")
		case containsLDAPValue(classes, ldapDatasetObjectClass):
			class = datasourceldap.RecordClassDataset
		case containsLDAPValue(classes, "dkim2Handle"):
			class = datasourceldap.RecordClassHandle
		case containsLDAPValue(classes, "dkim2Profile"):
			class = datasourceldap.RecordClassProfile
		case containsLDAPValue(classes, "dkim2Credential"):
			class = datasourceldap.RecordClassCredential
		case containsLDAPValue(classes, "dkim2Policy"):
			class = datasourceldap.RecordClassPolicy
		case containsLDAPValue(classes, "dkim2KeyMaterial"):
			class = datasourceldap.RecordClassKeyMaterial
		}
		mapped := datasourceldap.Entry{
			Class: class, Attributes: make(map[string][][]byte),
		}
		for _, attribute := range entry.Attributes {
			if attribute == nil || attribute.Name == legacyObjectClass {
				continue
			}
			if attribute.Name == "cn" || attribute.Name == "ou" {
				continue
			}
			mapped.Attributes[attribute.Name] = cloneLDAPValues(attribute.ByteValues)
		}
		if class == datasourceldap.RecordClassDataset {
			if rootSeen {
				return datasourceldap.DatasetRecords{}, errors.New("ldap publication readback root duplicated")
			}
			if len(mapped.Attributes[ldapDatasetStateAttribute]) != 1 ||
				string(mapped.Attributes[ldapDatasetStateAttribute][0]) != datasourceStateStaging {
				return datasourceldap.DatasetRecords{}, errors.New("ldap publication readback root state malformed")
			}
			mapped.Attributes[ldapDatasetStateAttribute] = [][]byte{[]byte(datasourceStateCommitted)}
			records.Root = mapped
			rootSeen = true
		} else {
			switch class {
			case datasourceldap.RecordClassHandle:
				records.Handles = append(records.Handles, mapped)
			case datasourceldap.RecordClassProfile:
				records.Profiles = append(records.Profiles, mapped)
			case datasourceldap.RecordClassCredential:
				records.Credentials = append(records.Credentials, mapped)
			case datasourceldap.RecordClassPolicy:
				records.Policies = append(records.Policies, mapped)
			case datasourceldap.RecordClassKeyMaterial:
				records.KeyMaterial = append(records.KeyMaterial, mapped)
			}
		}
	}
	if !rootSeen || len(units) != 5 {
		return datasourceldap.DatasetRecords{}, errors.New("ldap publication readback structure incomplete")
	}
	return records, nil
}

// candidateLDAPReadbackMatches proves staged public records equal the plan.
func candidateLDAPReadbackMatches(
	rows sqlsnapshot.DatasetRows,
	actual datasourceldap.DatasetRecords,
) bool {
	expected := candidateLDAPRecords(rows)
	return ldapEntrySetMatches(actual.Handles, expected.Handles) &&
		ldapEntrySetMatches(actual.Profiles, expected.Profiles) &&
		ldapEntrySetMatches(actual.Credentials, expected.Credentials) &&
		ldapEntrySetMatches(actual.Policies, expected.Policies) &&
		ldapEntrySetMatches(actual.KeyMaterial, expected.KeyMaterial)
}

// candidateLDAPRecords projects exact expected LDAP attributes from SQL-neutral rows.
func candidateLDAPRecords(rows sqlsnapshot.DatasetRows) datasourceldap.DatasetRecords {
	records := datasourceldap.DatasetRecords{}
	for _, row := range rows.Handles {
		records.Handles = append(records.Handles, ldapExpectedEntry(
			datasourceldap.RecordClassHandle,
			map[string][][]byte{
				ldapGenerationAttribute: {[]byte(row.Generation)},
				ldapHandleAttribute:     {[]byte(row.HandleID)},
			},
		))
	}
	for _, row := range rows.Profiles {
		attributes := map[string][][]byte{
			ldapGenerationAttribute:    {[]byte(row.Generation)},
			ldapProfileAttribute:       {[]byte(row.ProfileID)},
			ldapSigningDomainAttribute: {[]byte(row.Domain)},
			ldapRecordStatusAttribute:  {[]byte(row.Status)},
		}
		if row.NotBeforeUTC != nil {
			attributes["dkim2NotBefore"] = [][]byte{[]byte(*row.NotBeforeUTC)}
			attributes["dkim2NotAfter"] = [][]byte{[]byte(*row.NotAfterUTC)}
		}
		records.Profiles = append(records.Profiles, ldapExpectedEntry(
			datasourceldap.RecordClassProfile, attributes,
		))
	}
	for _, row := range rows.Credentials {
		records.Credentials = append(records.Credentials, ldapExpectedEntry(
			datasourceldap.RecordClassCredential,
			map[string][][]byte{
				ldapGenerationAttribute: {[]byte(row.Generation)},
				ldapProfileAttribute:    {[]byte(row.ProfileID)},
				"dkim2Algorithm":        {[]byte(row.Algorithm)},
				"dkim2Selector":         {[]byte(row.Selector)},
				"dkim2PublicKeySPKI":    {append([]byte(nil), row.PublicKeySPKI...)},
				ldapHandleAttribute:     {[]byte(row.HandleID)},
			},
		))
	}
	for _, row := range rows.Policies {
		attributes := map[string][][]byte{
			ldapGenerationAttribute:    {[]byte(row.Generation)},
			ldapTenantAttribute:        {[]byte(row.TenantID)},
			ldapSigningDomainAttribute: {[]byte(row.Domain)},
			ldapProfileUseAttribute:    {[]byte(row.Use)},
			ldapProfileAttribute:       {[]byte(row.ProfileID)},
			ldapRecordStatusAttribute:  {[]byte(row.Status)},
			ldapRolloutAttribute:       {[]byte(row.Rollout)},
			ldapCompatibilityAttribute: {[]byte(row.Compatibility)},
		}
		if row.FeedbackRouteID != nil {
			attributes["dkim2FeedbackRouteID"] = [][]byte{[]byte(*row.FeedbackRouteID)}
		}
		records.Policies = append(records.Policies, ldapExpectedEntry(
			datasourceldap.RecordClassPolicy, attributes,
		))
	}
	for _, row := range rows.KeyMaterial {
		records.KeyMaterial = append(records.KeyMaterial, ldapExpectedEntry(
			datasourceldap.RecordClassKeyMaterial,
			map[string][][]byte{
				ldapGenerationAttribute:    {[]byte(row.Generation)},
				ldapTenantAttribute:        {[]byte(row.TenantID)},
				ldapSigningDomainAttribute: {[]byte(row.Domain)},
				ldapProfileUseAttribute:    {[]byte(row.Use)},
				ldapHandleAttribute:        {[]byte(row.HandleID)},
				"dkim2Algorithm":           {[]byte(row.Algorithm)},
				"dkim2PublicKeySPKI":       {append([]byte(nil), row.PublicSPKI...)},
				ldapPrivatePKCS8Attribute:  {append([]byte(nil), row.PrivatePKCS8...)},
			},
		))
	}
	return records
}

// ldapExpectedEntry retains one detached exact expected attribute set.
func ldapExpectedEntry(
	class datasourceldap.RecordClass,
	attributes map[string][][]byte,
) datasourceldap.Entry {
	return datasourceldap.Entry{Class: class, Attributes: attributes}
}

// ldapEntrySetMatches compares order-independent exact public record sets.
func ldapEntrySetMatches(actual, expected []datasourceldap.Entry) bool {
	if len(actual) != len(expected) {
		return false
	}
	actualDigests := make([][sha256.Size]byte, len(actual))
	expectedDigests := make([][sha256.Size]byte, len(expected))
	for index := range actual {
		actualDocument, actualErr := json.Marshal(actual[index])
		expectedDocument, expectedErr := json.Marshal(expected[index])
		if actualErr != nil || expectedErr != nil {
			return false
		}
		actualDigests[index] = sha256.Sum256(actualDocument)
		expectedDigests[index] = sha256.Sum256(expectedDocument)
	}
	slices.SortFunc(actualDigests, func(left, right [sha256.Size]byte) int {
		return bytes.Compare(left[:], right[:])
	})
	slices.SortFunc(expectedDigests, func(left, right [sha256.Size]byte) int {
		return bytes.Compare(left[:], right[:])
	})
	return slices.Equal(actualDigests, expectedDigests)
}

// readCurrent fetches exact LDAP current metadata and preserves proven absence.
func (p *LDAPPublisher) readCurrent(ctx context.Context) (*goldap.Entry, bool, error) {
	if p == nil || p.client == nil || ctx == nil {
		return nil, false, errors.New("ldap publication unavailable")
	}
	request := goldap.NewSearchRequest(
		"cn=current,"+p.client.baseDN, goldap.ScopeBaseObject,
		goldap.NeverDerefAliases, 2, 0, false,
		"(objectClass="+ldapDatasetObjectClass+")",
		[]string{ldapSchemaVersionAttribute, ldapGenerationAttribute, ldapDatasetStateAttribute}, nil,
	)
	var result *goldap.SearchResult
	err := p.client.call(ctx, func() error {
		var searchErr error
		result, searchErr = p.client.connection.Search(request)
		return searchErr
	})
	if goldap.IsErrorWithCode(err, goldap.LDAPResultNoSuchObject) {
		return nil, true, nil
	}
	if err != nil || result == nil || len(result.Referrals) != 0 ||
		len(result.Entries) != 1 {
		return nil, false, errors.New("ldap publication unavailable")
	}
	return result.Entries[0], false, nil
}

// emptyGenerationContainer proves that no staged or committed generation exists.
func (p *LDAPPublisher) emptyGenerationContainer(ctx context.Context) bool {
	if p == nil || p.client == nil || ctx == nil {
		return false
	}
	request := goldap.NewSearchRequest(
		"ou=generations,"+p.client.baseDN, goldap.ScopeSingleLevel,
		goldap.NeverDerefAliases, 1, 0, true, "(objectClass=*)", []string{"1.1"}, nil,
	)
	var result *goldap.SearchResult
	if err := p.client.call(ctx, func() error {
		var searchErr error
		result, searchErr = p.client.connection.Search(request)
		return searchErr
	}); err != nil || result == nil || len(result.Referrals) != 0 {
		return false
	}
	return len(result.Entries) == 0
}

// generationRoot derives one exact validated generation subtree.
func (p *LDAPPublisher) generationRoot(generation string) string {
	return "dkim2Generation=" + generation + ",ou=generations," + p.client.baseDN
}

// newLDAPAdd creates one deterministic attribute add request.
func newLDAPAdd(dn string, attributes map[string][]string) *goldap.AddRequest {
	request := goldap.NewAddRequest(dn, nil)
	for _, name := range []string{
		legacyObjectClass, "cn", "ou", ldapSchemaVersionAttribute, ldapGenerationAttribute,
		ldapDatasetStateAttribute, ldapHandleAttribute, ldapProfileAttribute,
		ldapSigningDomainAttribute, ldapRecordStatusAttribute, "dkim2NotBefore",
		"dkim2NotAfter", ldapTenantAttribute, ldapProfileUseAttribute, ldapRolloutAttribute,
		ldapCompatibilityAttribute, "dkim2FeedbackRouteID",
	} {
		if values := attributes[name]; len(values) != 0 {
			request.Attribute(name, values)
		}
	}
	return request
}

// ldapRecordDN derives one storage-only sequence RDN.
func ldapRecordDN(index int, unit string, root string) string {
	return "cn=" + ldapRecordCN(index) + ",ou=" + unit + "," + root
}

// ldapRecordCN derives one bounded storage-only sequence value.
func ldapRecordCN(index int) string { return strconv.Itoa(index + 1) }

// containsLDAPValue reports exact membership in one small attribute set.
func containsLDAPValue(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

// cloneLDAPValues detaches one bounded readback attribute.
func cloneLDAPValues(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for index, value := range values {
		cloned[index] = append([]byte(nil), value...)
	}
	return cloned
}
