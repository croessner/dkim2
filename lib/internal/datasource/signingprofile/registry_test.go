package signingprofile

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/datasource"
	"github.com/croessner/dkim2/internal/signing"
)

// TestRegistryProjectsExactProfileFactsIntoSigning verifies pure authorized projection without a signer capability.
func TestRegistryProjectsExactProfileFactsIntoSigning(t *testing.T) {
	fixture := newProjectionFixture(t, "selector", datasource.ProfileUseOriginator)
	projected, err := fixture.registry.ProjectProfile(
		fixture.resolvedProfile,
		fixture.profileRequest,
		signing.DefaultLimits(),
	)
	if err != nil || !projected.Valid() || projected.Domain() != "example.test" {
		t.Fatalf("ProjectProfile() valid=%t error=%v", projected.Valid(), err)
	}
	credentials := projected.Credentials()
	if len(credentials) != 1 || credentials[0].Selector() != "selector" ||
		credentials[0].Algorithm() != signing.AlgorithmEd25519SHA256 {
		t.Fatal("ProjectProfile() credential facts differ")
	}
}

// TestRegistryRejectsDuplicateAndUnsatisfiableBindings verifies one exact entry owns each handle ID.
func TestRegistryRejectsDuplicateAndUnsatisfiableBindings(t *testing.T) {
	fixture := newProjectionFixture(t, "selector", datasource.ProfileUseOriginator)
	entry := fixture.entry
	if registry, err := NewRegistry([]Entry{entry, entry}, datasource.DefaultLimits()); registry.Valid() ||
		datasource.ErrorCodeOf(err) != datasource.ErrorCodeAmbiguous {
		t.Fatalf("NewRegistry(duplicate) valid=%t error=%v", registry.Valid(), err)
	}
	missingID, err := datasource.NewKeyHandleID("key.missing")
	if err != nil {
		t.Fatal(err)
	}
	if invalid, entryErr := NewEntry(
		fixture.profile,
		missingID,
		fixture.handle,
		[]datasource.ProfileUse{datasource.ProfileUseOriginator},
		datasource.DefaultLimits(),
	); invalid.Valid() || datasource.ErrorCodeOf(entryErr) != datasource.ErrorCodeInvalidRequest {
		t.Fatalf("NewEntry(missing credential) valid=%t error=%v", invalid.Valid(), entryErr)
	}
}

// TestRegistryRequiresCanonicalNonemptyAllowedUses verifies exact authorization-set ownership.
func TestRegistryRequiresCanonicalNonemptyAllowedUses(t *testing.T) {
	fixture := newProjectionFixture(t, "selector", datasource.ProfileUseOriginator)
	handleID := fixture.profile.Credentials()[0].KeyHandleID()
	tests := [][]datasource.ProfileUse{
		nil,
		{},
		{0},
		{datasource.ProfileUse(255)},
		{datasource.ProfileUseOriginator, datasource.ProfileUseOriginator},
	}
	for index, uses := range tests {
		entry, err := NewEntry(
			fixture.profile,
			handleID,
			fixture.handle,
			uses,
			datasource.DefaultLimits(),
		)
		if entry.Valid() || datasource.ErrorCodeOf(err) != datasource.ErrorCodeInvalidRequest {
			t.Fatalf("invalid use case %d accepted", index)
		}
	}
}

// TestRegistryFailsClosedOnUseAndCredentialDrift verifies exact registry facts are rechecked at projection.
func TestRegistryFailsClosedOnUseAndCredentialDrift(t *testing.T) {
	fixture := newProjectionFixture(t, "selector", datasource.ProfileUseOriginator)
	transitRequest, err := datasource.NewProfileRequest(
		fixture.profile.ID(),
		datasource.ProfileUseOrdinaryTransit,
		fixture.at,
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if projected, projectErr := fixture.registry.ProjectProfile(
		fixture.resolvedProfile,
		transitRequest,
		signing.DefaultLimits(),
	); projected.Valid() || datasource.ErrorCodeOf(projectErr) != datasource.ErrorCodeInactive {
		t.Fatalf("ProjectProfile(unauthorized use) valid=%t error=%v", projected.Valid(), projectErr)
	}

	drifted := newDatasourceProfile(
		t,
		fixture.profile.ID(),
		"other",
		fixture.profile.Credentials()[0].KeyHandleID(),
	)
	resolved, err := datasource.NewResolvedProfile(1, drifted)
	if err != nil {
		t.Fatal(err)
	}
	driftRequest, err := datasource.NewProfileRequest(
		drifted.ID(),
		datasource.ProfileUseOriginator,
		fixture.at,
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if projected, projectErr := fixture.registry.ProjectProfile(
		resolved,
		driftRequest,
		signing.DefaultLimits(),
	); projected.Valid() || datasource.ErrorCodeOf(projectErr) != datasource.ErrorCodeInactive {
		t.Fatalf("ProjectProfile(drift) valid=%t error=%v", projected.Valid(), projectErr)
	}
}

// TestRegistryProjectsOnlyEligibleExactPolicy verifies policy facts remain administrative selection only.
func TestRegistryProjectsOnlyEligibleExactPolicy(t *testing.T) {
	fixture := newProjectionFixture(t, "selector", datasource.ProfileUseOriginator)
	tenant, err := datasource.NewTenantID("tenant.example")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := datasource.NewPolicy(
		tenant,
		fixture.profile.SigningDomain(),
		datasource.ProfileUseOriginator,
		fixture.profile.ID(),
		datasource.RecordStatusActive,
		datasource.RolloutEnforce,
		datasource.CompatibilityStrict,
		datasource.FeedbackRouteID{},
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := datasource.NewResolvedPolicy(1, policy, fixture.resolvedProfile)
	if err != nil {
		t.Fatal(err)
	}
	request, err := datasource.NewPolicyRequest(
		tenant,
		fixture.profile.SigningDomain(),
		datasource.ProfileUseOriginator,
		fixture.at,
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	projected, err := fixture.registry.ProjectPolicy(resolved, request, signing.DefaultLimits())
	if err != nil || !projected.Valid() {
		t.Fatalf("ProjectPolicy() valid=%t error=%v", projected.Valid(), err)
	}

	observe, err := datasource.NewPolicy(
		tenant,
		fixture.profile.SigningDomain(),
		datasource.ProfileUseOriginator,
		fixture.profile.ID(),
		datasource.RecordStatusActive,
		datasource.RolloutObserve,
		datasource.CompatibilityStrict,
		datasource.FeedbackRouteID{},
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	observeResult, err := datasource.NewResolvedPolicy(1, observe, fixture.resolvedProfile)
	if err != nil {
		t.Fatal(err)
	}
	if denied, projectErr := fixture.registry.ProjectPolicy(observeResult, request, signing.DefaultLimits()); denied.Valid() ||
		datasource.ErrorCodeOf(projectErr) != datasource.ErrorCodeInactive {
		t.Fatalf("ProjectPolicy(observe) valid=%t error=%v", denied.Valid(), projectErr)
	}
}

// TestRegistryFormattingDoesNotExposeBindingFacts verifies opaque handles and identifiers remain protected.
func TestRegistryFormattingDoesNotExposeBindingFacts(t *testing.T) {
	fixture := newProjectionFixture(t, "marker-selector", datasource.ProfileUseOriginator)
	for name, value := range map[string]any{"entry": fixture.entry, "registry": fixture.registry} {
		formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q", value, value, value, value, value)
		if strings.Contains(formatted, "marker-selector") || !strings.Contains(formatted, "redacted") {
			t.Fatalf("%s formatting was not redacted", name)
		}
	}
}

// TestRegistryRetainsNarrowLimitsForEntriesRequestsAndResults proves every
// later projection remains bounded by the immutable registry contract.
func TestRegistryRetainsNarrowLimitsForEntriesRequestsAndResults(t *testing.T) {
	fixture := newProjectionFixture(t, "selector", datasource.ProfileUseOriginator)
	limits := datasource.DefaultLimits()
	limits.MaxHandles = 1
	limits.MaxIdentifierBytes = max(
		fixture.profile.ID().ByteLen(),
		fixture.entry.KeyHandleID().ByteLen(),
	)
	limits.MaxDomainBytes = len(fixture.profile.SigningDomain())
	limits.MaxDomainLabels = 2
	limits.MaxSelectorBytes = len("selector")
	limits.MaxSelectorLabels = 1

	exactEntry, err := NewEntry(
		fixture.profile,
		fixture.entry.KeyHandleID(),
		fixture.handle,
		[]datasource.ProfileUse{datasource.ProfileUseOriginator},
		limits,
	)
	if err != nil || !exactEntry.ValidForLimits(limits) {
		t.Fatalf("NewEntry(exact narrowed limits) valid=%t error=%v",
			exactEntry.ValidForLimits(limits), err)
	}
	registry, err := NewRegistry([]Entry{exactEntry}, limits)
	if err != nil || !registry.Valid() {
		t.Fatalf("NewRegistry(exact narrowed limits) valid=%t error=%v", registry.Valid(), err)
	}

	entryOneOver := limits
	entryOneOver.MaxSelectorBytes--
	if entry, entryErr := NewEntry(
		fixture.profile,
		fixture.entry.KeyHandleID(),
		fixture.handle,
		[]datasource.ProfileUse{datasource.ProfileUseOriginator},
		entryOneOver,
	); entry.Valid() || datasource.ErrorCodeOf(entryErr) != datasource.ErrorCodeLimitExceeded {
		t.Fatalf("NewEntry(selector one over) valid=%t code=%s",
			entry.Valid(), datasource.ErrorCodeOf(entryErr))
	}
	if got, registryErr := NewRegistry(
		[]Entry{exactEntry, exactEntry}, limits,
	); got.Valid() || datasource.ErrorCodeOf(registryErr) != datasource.ErrorCodeLimitExceeded {
		t.Fatalf("NewRegistry(handle count one over) valid=%t code=%s",
			got.Valid(), datasource.ErrorCodeOf(registryErr))
	}

	longID, err := datasource.NewProfileID(strings.Repeat("p", limits.MaxIdentifierBytes+1))
	if err != nil {
		t.Fatalf("NewProfileID(long request fixture) error = %v", err)
	}
	longRequest, err := datasource.NewProfileRequest(
		longID,
		datasource.ProfileUseOriginator,
		fixture.at,
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("NewProfileRequest(long request fixture) error = %v", err)
	}
	if projected, projectErr := registry.ProjectProfile(
		fixture.resolvedProfile, longRequest, signing.DefaultLimits(),
	); projected.Valid() || datasource.ErrorCodeOf(projectErr) != datasource.ErrorCodeLimitExceeded {
		t.Fatalf("ProjectProfile(request over retained limit) valid=%t code=%s",
			projected.Valid(), datasource.ErrorCodeOf(projectErr))
	}

	longProfile := newDatasourceProfile(
		t,
		fixture.profile.ID(),
		"long-selector",
		fixture.entry.KeyHandleID(),
	)
	longResult, err := datasource.NewResolvedProfile(2, longProfile)
	if err != nil {
		t.Fatalf("NewResolvedProfile(long result fixture) error = %v", err)
	}
	if projected, projectErr := registry.ProjectProfile(
		longResult, fixture.profileRequest, signing.DefaultLimits(),
	); projected.Valid() || datasource.ErrorCodeOf(projectErr) != datasource.ErrorCodeLimitExceeded {
		t.Fatalf("ProjectProfile(result over retained limit) valid=%t code=%s",
			projected.Valid(), datasource.ErrorCodeOf(projectErr))
	}
}

// TestEntryValidityOwnsCompleteCanonicalFacts proves entry validity checks all
// non-digest grammar while allowing the full SHA-256 value space.
func TestEntryValidityOwnsCompleteCanonicalFacts(t *testing.T) {
	fixture := newProjectionFixture(t, "selector", datasource.ProfileUseOriginator)
	zeroDigest := fixture.entry
	zeroDigest.keyDigest = [32]byte{}
	if !zeroDigest.Valid() {
		t.Fatal("Entry.Valid() rejected the valid all-zero SHA-256 value space")
	}

	cases := map[string]func(*Entry){
		"incomplete":       func(entry *Entry) { entry.complete = false },
		"zero handle ID":   func(entry *Entry) { entry.handleID = datasource.KeyHandleID{} },
		"zero handle":      func(entry *Entry) { entry.handle = signing.PrivateKeyHandle{} },
		"zero profile ID":  func(entry *Entry) { entry.profileID = datasource.ProfileID{} },
		"invalid domain":   func(entry *Entry) { entry.domain = ".example.test" },
		"invalid selector": func(entry *Entry) { entry.selector = "bad..selector" },
		"unknown algorithm": func(entry *Entry) {
			entry.algorithm = datasource.Algorithm("unknown")
		},
		"empty uses": func(entry *Entry) { entry.uses = nil },
		"duplicate uses": func(entry *Entry) {
			entry.uses = []datasource.ProfileUse{datasource.ProfileUseOriginator, datasource.ProfileUseOriginator}
		},
		"unordered uses": func(entry *Entry) {
			entry.uses = []datasource.ProfileUse{datasource.ProfileUseNextDomainTransit, datasource.ProfileUseOriginator}
		},
		"unknown use": func(entry *Entry) { entry.uses = []datasource.ProfileUse{datasource.ProfileUse(255)} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			entry := fixture.entry
			mutate(&entry)
			if entry.Valid() {
				t.Fatal("Entry.Valid() accepted corrupted facts")
			}
		})
	}
}

// TestEntryAllowedUsesAreCanonicalAndDetached proves both construction input
// and accessor results cannot mutate an entry's authorization set.
func TestEntryAllowedUsesAreCanonicalAndDetached(t *testing.T) {
	fixture := newProjectionFixture(t, "selector", datasource.ProfileUseOriginator)
	input := []datasource.ProfileUse{
		datasource.ProfileUseNextDomainTransit,
		datasource.ProfileUseOriginator,
	}
	entry, err := NewEntry(
		fixture.profile,
		fixture.entry.KeyHandleID(),
		fixture.handle,
		input,
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("NewEntry() error = %v", err)
	}
	input[0] = datasource.ProfileUseOrdinaryTransit
	want := []datasource.ProfileUse{
		datasource.ProfileUseOriginator,
		datasource.ProfileUseNextDomainTransit,
	}
	first := entry.AllowedUses()
	if !slices.Equal(first, want) {
		t.Fatalf("AllowedUses() = %v, want canonical set %v", first, want)
	}
	first[0] = datasource.ProfileUseOrdinaryTransit
	if got := entry.AllowedUses(); !slices.Equal(got, want) {
		t.Fatalf("AllowedUses() retained mutable accessor storage")
	}
}

// TestRegistryRejectsDifferentValidPublicKeyDigest proves exact SPKI digest
// drift fails closed even when every other credential fact is unchanged.
func TestRegistryRejectsDifferentValidPublicKeyDigest(t *testing.T) {
	fixture := newProjectionFixture(t, "selector", datasource.ProfileUseOriginator)
	credential := newDatasourceCredential(
		t,
		"selector",
		datasource.AlgorithmEd25519SHA256,
		fixture.entry.KeyHandleID(),
		0x7a,
	)
	drifted, err := datasource.NewProfile(
		fixture.profile.ID(),
		fixture.profile.SigningDomain(),
		datasource.RecordStatusActive,
		[]datasource.Credential{credential},
		time.Time{},
		time.Time{},
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("NewProfile(digest drift) error = %v", err)
	}
	result, err := datasource.NewResolvedProfile(2, drifted)
	if err != nil {
		t.Fatalf("NewResolvedProfile(digest drift) error = %v", err)
	}
	if projected, projectErr := fixture.registry.ProjectProfile(
		result, fixture.profileRequest, signing.DefaultLimits(),
	); projected.Valid() || datasource.ErrorCodeOf(projectErr) != datasource.ErrorCodeInactive {
		t.Fatalf("ProjectProfile(different valid SPKI) valid=%t code=%s",
			projected.Valid(), datasource.ErrorCodeOf(projectErr))
	}
}

// TestRegistryProjectsDualAlgorithmsWithDistinctIDsAndOnePhysicalHandle proves
// canonical RSA-then-Ed projection permits explicit distinct bindings to one handle.
func TestRegistryProjectsDualAlgorithmsWithDistinctIDsAndOnePhysicalHandle(t *testing.T) {
	profileID := mustProjectionProfileID(t, "profile.dual")
	rsaID := mustProjectionHandleID(t, "key.dual.rsa")
	edID := mustProjectionHandleID(t, "key.dual.ed")
	rsaCredential := newDatasourceCredential(
		t, "rsa", datasource.AlgorithmRSASHA256, rsaID, 0,
	)
	edCredential := newDatasourceCredential(
		t, "ed", datasource.AlgorithmEd25519SHA256, edID, 0x42,
	)
	profile, err := datasource.NewProfile(
		profileID,
		"example.test",
		datasource.RecordStatusActive,
		[]datasource.Credential{edCredential, rsaCredential},
		time.Time{},
		time.Time{},
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("NewProfile(dual) error = %v", err)
	}
	handle, err := signing.NewPrivateKeyHandle([]byte("one-physical-provider-handle"))
	if err != nil {
		t.Fatalf("NewPrivateKeyHandle() error = %v", err)
	}
	rsaEntry := mustProjectionEntry(t, profile, rsaID, handle, datasource.ProfileUseOriginator)
	edEntry := mustProjectionEntry(t, profile, edID, handle, datasource.ProfileUseOriginator)
	registry, err := NewRegistry(
		[]Entry{edEntry, rsaEntry},
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("NewRegistry(dual) RSA-valid=%t Ed-valid=%t error = %v",
			rsaEntry.Valid(), edEntry.Valid(), err)
	}
	result, request := projectionResultAndRequest(t, profile, datasource.ProfileUseOriginator)
	projected, err := registry.ProjectProfile(result, request, signing.DefaultLimits())
	if err != nil {
		t.Fatalf("ProjectProfile(dual) error = %v", err)
	}
	credentials := projected.Credentials()
	if len(credentials) != 2 ||
		credentials[0].Algorithm() != signing.AlgorithmRSASHA256 ||
		credentials[1].Algorithm() != signing.AlgorithmEd25519SHA256 {
		t.Fatalf("ProjectProfile(dual) did not preserve RSA-then-Ed order")
	}

	assertProjectionFailure(
		t,
		"missing binding",
		mustProjectionRegistry(t, rsaEntry),
		result,
		request,
		datasource.ErrorCodeNotFound,
	)
	mismatchedEd := edEntry
	mismatchedEd.selector = "wrong-ed"
	assertProjectionFailure(
		t,
		"mismatched binding",
		mustProjectionRegistry(t, rsaEntry, mismatchedEd),
		result,
		request,
		datasource.ErrorCodeInactive,
	)
	unauthorizedEd := mustProjectionEntry(
		t, profile, edID, handle, datasource.ProfileUseOrdinaryTransit,
	)
	assertProjectionFailure(
		t,
		"unauthorized binding",
		mustProjectionRegistry(t, rsaEntry, unauthorizedEd),
		result,
		request,
		datasource.ErrorCodeInactive,
	)
}

// TestRegistryMapsCorruptionAndInvalidCallsToClosedErrors proves corrupt
// registry/results and malformed requests/options never become signing profiles.
func TestRegistryMapsCorruptionAndInvalidCallsToClosedErrors(t *testing.T) {
	fixture := newProjectionFixture(t, "selector", datasource.ProfileUseOriginator)
	corrupted := fixture.registry
	corrupted.complete = false
	if projected, err := corrupted.ProjectProfile(
		fixture.resolvedProfile, fixture.profileRequest, signing.DefaultLimits(),
	); projected.Valid() || datasource.ErrorCodeOf(err) != datasource.ErrorCodeInternalInvariant {
		t.Fatalf("ProjectProfile(corrupt registry) valid=%t code=%s",
			projected.Valid(), datasource.ErrorCodeOf(err))
	}
	if projected, err := fixture.registry.ProjectProfile(
		datasource.ResolvedProfile{}, fixture.profileRequest, signing.DefaultLimits(),
	); projected.Valid() || datasource.ErrorCodeOf(err) != datasource.ErrorCodeInternalInvariant {
		t.Fatalf("ProjectProfile(corrupt result) valid=%t code=%s",
			projected.Valid(), datasource.ErrorCodeOf(err))
	}
	if projected, err := fixture.registry.ProjectProfile(
		fixture.resolvedProfile, datasource.ProfileRequest{}, signing.DefaultLimits(),
	); projected.Valid() || datasource.ErrorCodeOf(err) != datasource.ErrorCodeInvalidRequest {
		t.Fatalf("ProjectProfile(malformed request) valid=%t code=%s",
			projected.Valid(), datasource.ErrorCodeOf(err))
	}
	if projected, err := fixture.registry.ProjectProfile(
		fixture.resolvedProfile, fixture.profileRequest, signing.Limits{},
	); projected.Valid() || datasource.ErrorCodeOf(err) != datasource.ErrorCodeInvalidRequest {
		t.Fatalf("ProjectProfile(malformed signing limits) valid=%t code=%s",
			projected.Valid(), datasource.ErrorCodeOf(err))
	}
	if projected, err := fixture.registry.ProjectPolicy(
		datasource.ResolvedPolicy{}, datasource.PolicyRequest{}, signing.DefaultLimits(),
	); projected.Valid() || datasource.ErrorCodeOf(err) != datasource.ErrorCodeInternalInvariant {
		t.Fatalf("ProjectPolicy(corrupt result) valid=%t code=%s",
			projected.Valid(), datasource.ErrorCodeOf(err))
	}
}

// TestRegistryMapsNarrowedRSABoundToLimitExceeded proves a valid but
// operation-over-limit RSA key cannot enter a signing profile.
func TestRegistryMapsNarrowedRSABoundToLimitExceeded(t *testing.T) {
	profileID := mustProjectionProfileID(t, "profile.rsa")
	handleID := mustProjectionHandleID(t, "key.rsa")
	credential := newDatasourceCredential(
		t, "rsa", datasource.AlgorithmRSASHA256, handleID, 0,
	)
	profile, err := datasource.NewProfile(
		profileID,
		"example.test",
		datasource.RecordStatusActive,
		[]datasource.Credential{credential},
		time.Time{},
		time.Time{},
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("NewProfile(RSA) error = %v", err)
	}
	handle, err := signing.NewPrivateKeyHandle([]byte("rsa-provider-handle"))
	if err != nil {
		t.Fatalf("NewPrivateKeyHandle() error = %v", err)
	}
	entry := mustProjectionEntry(t, profile, handleID, handle, datasource.ProfileUseOriginator)
	registry := mustProjectionRegistry(t, entry)
	result, request := projectionResultAndRequest(t, profile, datasource.ProfileUseOriginator)
	limits := signing.DefaultLimits()
	limits.MaxRSABits = limits.MinRSABits
	if err := limits.Validate(); err != nil {
		t.Fatalf("narrowed signing limits invalid: %v", err)
	}
	if projected, projectErr := registry.ProjectProfile(
		result, request, limits,
	); projected.Valid() || datasource.ErrorCodeOf(projectErr) != datasource.ErrorCodeLimitExceeded {
		t.Fatalf("ProjectProfile(RSA over operation limit) valid=%t code=%s",
			projected.Valid(), datasource.ErrorCodeOf(projectErr))
	}
}

// TestRegistryRejectsConflictingDerivedProfileGroups proves a ProfileID owns
// one bounded domain and one unambiguous algorithm and selector set.
func TestRegistryRejectsConflictingDerivedProfileGroups(t *testing.T) {
	profileID := mustProjectionProfileID(t, "profile.group")
	handle, err := signing.NewPrivateKeyHandle([]byte("group-conflict-handle"))
	if err != nil {
		t.Fatalf("signing.NewPrivateKeyHandle() error = %v", err)
	}

	_, domainRSA := newSingleCredentialEntry(
		t, profileID, "example.test", "rsa", datasource.AlgorithmRSASHA256,
		"key.group.domain.rsa", handle, datasource.ProfileUseOriginator, 0,
	)
	_, domainEd := newSingleCredentialEntry(
		t, profileID, "other.test", "ed", datasource.AlgorithmEd25519SHA256,
		"key.group.domain.ed", handle, datasource.ProfileUseOriginator, 0x42,
	)
	assertRegistryConstructionError(
		t,
		"conflicting domain",
		[]Entry{domainEd, domainRSA},
		datasource.DefaultLimits(),
		datasource.ErrorCodeAmbiguous,
	)

	_, rsaOne := newSingleCredentialEntry(
		t, profileID, "example.test", "rsa-one", datasource.AlgorithmRSASHA256,
		"key.group.rsa.one", handle, datasource.ProfileUseOriginator, 0,
	)
	_, rsaTwo := newSingleCredentialEntry(
		t, profileID, "example.test", "rsa-two", datasource.AlgorithmRSASHA256,
		"key.group.rsa.two", handle, datasource.ProfileUseOriginator, 0,
	)
	assertRegistryConstructionError(
		t,
		"duplicate algorithm",
		[]Entry{rsaOne, rsaTwo},
		datasource.DefaultLimits(),
		datasource.ErrorCodeAmbiguous,
	)

	_, selectorRSA := newSingleCredentialEntry(
		t, profileID, "example.test", "same", datasource.AlgorithmRSASHA256,
		"key.group.selector.rsa", handle, datasource.ProfileUseOriginator, 0,
	)
	_, selectorEd := newSingleCredentialEntry(
		t, profileID, "example.test", "same", datasource.AlgorithmEd25519SHA256,
		"key.group.selector.ed", handle, datasource.ProfileUseOriginator, 0x52,
	)
	assertRegistryConstructionError(
		t,
		"duplicate selector",
		[]Entry{selectorEd, selectorRSA},
		datasource.DefaultLimits(),
		datasource.ErrorCodeAmbiguous,
	)

	_, third := newSingleCredentialEntry(
		t, profileID, "example.test", "third", datasource.AlgorithmEd25519SHA256,
		"key.group.third", handle, datasource.ProfileUseOriginator, 0x62,
	)
	assertRegistryConstructionError(
		t,
		"credentials one over",
		[]Entry{rsaOne, selectorEd, third},
		datasource.DefaultLimits(),
		datasource.ErrorCodeLimitExceeded,
	)
}

// TestRegistryRetainsBoundedProfileGroupCount proves derived ProfileID groups
// honor the retained exact maximum before registry publication.
func TestRegistryRetainsBoundedProfileGroupCount(t *testing.T) {
	handle, err := signing.NewPrivateKeyHandle([]byte("group-count-handle"))
	if err != nil {
		t.Fatalf("signing.NewPrivateKeyHandle() error = %v", err)
	}
	_, first := newSingleCredentialEntry(
		t,
		mustProjectionProfileID(t, "profile.group.one"),
		"example.test",
		"one",
		datasource.AlgorithmEd25519SHA256,
		"key.group.one",
		handle,
		datasource.ProfileUseOriginator,
		0x31,
	)
	_, second := newSingleCredentialEntry(
		t,
		mustProjectionProfileID(t, "profile.group.two"),
		"example.test",
		"two",
		datasource.AlgorithmEd25519SHA256,
		"key.group.two",
		handle,
		datasource.ProfileUseOriginator,
		0x32,
	)
	limits := datasource.DefaultLimits()
	limits.MaxProfiles = 1
	if registry, registryErr := NewRegistry([]Entry{first}, limits); registryErr != nil ||
		!registry.Valid() {
		t.Fatalf("NewRegistry(exact profile-group limit) valid=%t error=%v",
			registry.Valid(), registryErr)
	}
	assertRegistryConstructionError(
		t,
		"profile groups one over",
		[]Entry{first, second},
		limits,
		datasource.ErrorCodeLimitExceeded,
	)
}

// TestRegistryRejectsExtraEntryAgainstResolvedProfile proves a valid derived
// group cannot silently project a strict subset of its credential bindings.
func TestRegistryRejectsExtraEntryAgainstResolvedProfile(t *testing.T) {
	profileID := mustProjectionProfileID(t, "profile.extra")
	handle, err := signing.NewPrivateKeyHandle([]byte("extra-entry-handle"))
	if err != nil {
		t.Fatalf("signing.NewPrivateKeyHandle() error = %v", err)
	}
	rsaProfile, rsaEntry := newSingleCredentialEntry(
		t, profileID, "example.test", "rsa", datasource.AlgorithmRSASHA256,
		"key.extra.rsa", handle, datasource.ProfileUseOriginator, 0,
	)
	_, edEntry := newSingleCredentialEntry(
		t, profileID, "example.test", "ed", datasource.AlgorithmEd25519SHA256,
		"key.extra.ed", handle, datasource.ProfileUseOriginator, 0x73,
	)
	registry := mustProjectionRegistry(t, edEntry, rsaEntry)
	result, request := projectionResultAndRequest(
		t, rsaProfile, datasource.ProfileUseOriginator,
	)
	assertProjectionFailure(
		t,
		"extra registry entry",
		registry,
		result,
		request,
		datasource.ErrorCodeInactive,
	)
}

// TestRegistryCanonicalGroupsDetachCallerEntries proves group order is
// RSA-then-Ed25519 and registry storage owns caller-provided slices.
func TestRegistryCanonicalGroupsDetachCallerEntries(t *testing.T) {
	profileID := mustProjectionProfileID(t, "profile.detached")
	rsaID := mustProjectionHandleID(t, "key.detached.rsa")
	edID := mustProjectionHandleID(t, "key.detached.ed")
	handle, err := signing.NewPrivateKeyHandle([]byte("detached-group-handle"))
	if err != nil {
		t.Fatalf("signing.NewPrivateKeyHandle() error = %v", err)
	}
	rsaCredential := newDatasourceCredential(
		t, "rsa", datasource.AlgorithmRSASHA256, rsaID, 0,
	)
	edCredential := newDatasourceCredential(
		t, "ed", datasource.AlgorithmEd25519SHA256, edID, 0x34,
	)
	profile, err := datasource.NewProfile(
		profileID,
		"example.test",
		datasource.RecordStatusActive,
		[]datasource.Credential{edCredential, rsaCredential},
		time.Time{},
		time.Time{},
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("datasource.NewProfile() error = %v", err)
	}
	rsaEntry := mustProjectionEntry(
		t, profile, rsaID, handle, datasource.ProfileUseOriginator,
	)
	edEntry := mustProjectionEntry(
		t, profile, edID, handle, datasource.ProfileUseOriginator,
	)
	input := []Entry{edEntry, rsaEntry}
	registry, err := NewRegistry(input, datasource.DefaultLimits())
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	input[0].uses[0] = datasource.ProfileUseOrdinaryTransit
	input[1] = Entry{}
	group, found := registry.groups[profileID]
	if !found || group.domain != "example.test" ||
		!slices.Equal(group.handles, []datasource.KeyHandleID{rsaID, edID}) {
		t.Fatalf("derived group is missing or not canonical")
	}
	if !registry.Valid() {
		t.Fatal("registry retained caller entry or allowed-use storage")
	}
	result, request := projectionResultAndRequest(
		t, profile, datasource.ProfileUseOriginator,
	)
	projected, projectErr := registry.ProjectProfile(
		result, request, signing.DefaultLimits(),
	)
	if projectErr != nil || !projected.Valid() {
		t.Fatalf("ProjectProfile(detached input) valid=%t error=%v",
			projected.Valid(), projectErr)
	}
}

type projectionFixture struct {
	at              time.Time
	profile         datasource.Profile
	resolvedProfile datasource.ResolvedProfile
	profileRequest  datasource.ProfileRequest
	handle          signing.PrivateKeyHandle
	entry           Entry
	registry        Registry
}

// newProjectionFixture constructs one deterministic Ed25519 projection fixture.
func newProjectionFixture(t *testing.T, selector string, use datasource.ProfileUse) projectionFixture {
	t.Helper()
	profileID, err := datasource.NewProfileID("profile.example")
	if err != nil {
		t.Fatal(err)
	}
	handleID, err := datasource.NewKeyHandleID("key.example")
	if err != nil {
		t.Fatal(err)
	}
	profile := newDatasourceProfile(t, profileID, selector, handleID)
	at := time.Unix(1_700_000_000, 0)
	resolved, err := datasource.NewResolvedProfile(1, profile)
	if err != nil {
		t.Fatal(err)
	}
	request, err := datasource.NewProfileRequest(profileID, use, at, datasource.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	handle, err := signing.NewPrivateKeyHandle([]byte("inert-test-handle"))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := NewEntry(
		profile,
		handleID,
		handle,
		[]datasource.ProfileUse{use},
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]Entry{entry}, datasource.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return projectionFixture{
		at: at, profile: profile, resolvedProfile: resolved, profileRequest: request,
		handle: handle, entry: entry, registry: registry,
	}
}

// newDatasourceProfile constructs one deterministic active datasource profile.
func newDatasourceProfile(t *testing.T, profileID datasource.ProfileID, selector string, handleID datasource.KeyHandleID) datasource.Profile {
	t.Helper()
	credential := newDatasourceCredential(
		t,
		selector,
		datasource.AlgorithmEd25519SHA256,
		handleID,
		1,
	)
	profile, err := datasource.NewProfile(
		profileID,
		"example.test",
		datasource.RecordStatusActive,
		[]datasource.Credential{credential},
		time.Time{},
		time.Time{},
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

// newDatasourceCredential constructs deterministic valid public key material.
func newDatasourceCredential(
	t *testing.T,
	selector string,
	algorithm datasource.Algorithm,
	handleID datasource.KeyHandleID,
	edSeed byte,
) datasource.Credential {
	t.Helper()
	var publicKey any
	switch algorithm {
	case datasource.AlgorithmRSASHA256:
		modulus := new(big.Int).Lsh(big.NewInt(1), 2047)
		modulus.Add(modulus, big.NewInt(0x31))
		publicKey = &rsa.PublicKey{N: modulus, E: 65537}
	case datasource.AlgorithmEd25519SHA256:
		publicKey = ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
		for index := range publicKey.(ed25519.PublicKey) {
			publicKey.(ed25519.PublicKey)[index] = edSeed + byte(index)
		}
	default:
		t.Fatal("unsupported credential fixture algorithm")
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	credential, err := datasource.NewCredential(
		selector,
		algorithm,
		spki,
		handleID,
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("datasource.NewCredential() error = %v", err)
	}
	return credential
}

// newSingleCredentialEntry constructs one independently valid derived-group entry.
func newSingleCredentialEntry(
	t *testing.T,
	profileID datasource.ProfileID,
	domain string,
	selector string,
	algorithm datasource.Algorithm,
	handleValue string,
	handle signing.PrivateKeyHandle,
	use datasource.ProfileUse,
	edSeed byte,
) (datasource.Profile, Entry) {
	t.Helper()
	handleID := mustProjectionHandleID(t, handleValue)
	credential := newDatasourceCredential(
		t, selector, algorithm, handleID, edSeed,
	)
	profile, err := datasource.NewProfile(
		profileID,
		domain,
		datasource.RecordStatusActive,
		[]datasource.Credential{credential},
		time.Time{},
		time.Time{},
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("datasource.NewProfile() error = %v", err)
	}
	entry := mustProjectionEntry(t, profile, handleID, handle, use)
	return profile, entry
}

// assertRegistryConstructionError proves invalid derived groups publish no registry.
func assertRegistryConstructionError(
	t *testing.T,
	name string,
	entries []Entry,
	limits datasource.Limits,
	code datasource.ErrorCode,
) {
	t.Helper()
	registry, err := NewRegistry(entries, limits)
	if registry.Valid() || datasource.ErrorCodeOf(err) != code {
		t.Fatalf("%s: NewRegistry() valid=%t code=%s, want %s",
			name, registry.Valid(), datasource.ErrorCodeOf(err), code)
	}
}

// mustProjectionProfileID constructs one valid profile identifier fixture.
func mustProjectionProfileID(t *testing.T, value string) datasource.ProfileID {
	t.Helper()
	id, err := datasource.NewProfileID(value)
	if err != nil {
		t.Fatalf("datasource.NewProfileID() error = %v", err)
	}
	return id
}

// mustProjectionHandleID constructs one valid handle identifier fixture.
func mustProjectionHandleID(t *testing.T, value string) datasource.KeyHandleID {
	t.Helper()
	id, err := datasource.NewKeyHandleID(value)
	if err != nil {
		t.Fatalf("datasource.NewKeyHandleID() error = %v", err)
	}
	return id
}

// mustProjectionEntry constructs one valid registry binding fixture.
func mustProjectionEntry(
	t *testing.T,
	profile datasource.Profile,
	handleID datasource.KeyHandleID,
	handle signing.PrivateKeyHandle,
	use datasource.ProfileUse,
) Entry {
	t.Helper()
	entry, err := NewEntry(
		profile,
		handleID,
		handle,
		[]datasource.ProfileUse{use},
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("NewEntry() error = %v", err)
	}
	return entry
}

// mustProjectionRegistry constructs one valid immutable registry fixture.
func mustProjectionRegistry(t *testing.T, entries ...Entry) Registry {
	t.Helper()
	registry, err := NewRegistry(entries, datasource.DefaultLimits())
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	return registry
}

// projectionResultAndRequest constructs one matched resolved-profile call.
func projectionResultAndRequest(
	t *testing.T,
	profile datasource.Profile,
	use datasource.ProfileUse,
) (datasource.ResolvedProfile, datasource.ProfileRequest) {
	t.Helper()
	result, err := datasource.NewResolvedProfile(1, profile)
	if err != nil {
		t.Fatalf("datasource.NewResolvedProfile() error = %v", err)
	}
	request, err := datasource.NewProfileRequest(
		profile.ID(),
		use,
		time.Unix(1_700_000_000, 0),
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("datasource.NewProfileRequest() error = %v", err)
	}
	return result, request
}

// assertProjectionFailure proves projection failures return no partial profile.
func assertProjectionFailure(
	t *testing.T,
	name string,
	registry Registry,
	result datasource.ResolvedProfile,
	request datasource.ProfileRequest,
	code datasource.ErrorCode,
) {
	t.Helper()
	projected, err := registry.ProjectProfile(result, request, signing.DefaultLimits())
	if projected.Valid() || datasource.ErrorCodeOf(err) != code {
		t.Fatalf("%s: ProjectProfile() valid=%t code=%s, want %s",
			name, projected.Valid(), datasource.ErrorCodeOf(err), code)
	}
}
