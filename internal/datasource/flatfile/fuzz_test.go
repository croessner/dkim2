package flatfile

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/croessner/dkim2/internal/datasource"
	"github.com/croessner/dkim2/internal/datasource/memory"
)

const (
	fuzzJSONInputBytes    = 4096
	fuzzPublicKeyBytes    = 256
	fuzzParityMarkerBytes = 8
)

// FuzzStrictJSON proves bounded strict decoding is deterministic,
// transactional, immutable, and closed for arbitrary byte documents.
func FuzzStrictJSON(f *testing.F) {
	fixture, err := os.ReadFile("testdata/valid-v1.json")
	if err != nil {
		f.Fatal("public fuzz seed is unavailable")
	}
	f.Add(fixture)
	f.Add([]byte(`{"version":"dkim2-datasource-v1","handles":[],"profiles":[],"policies":[]}`))
	f.Add([]byte(`{"version":"dkim2-datasource-v1","version":"dkim2-datasource-v1"}`))
	f.Add([]byte{0xff})

	f.Fuzz(func(t *testing.T, document []byte) {
		if len(document) > fuzzJSONInputBytes {
			return
		}
		leftInput := bytes.Clone(document)
		rightInput := bytes.Clone(document)
		left, leftErr := Decode(flatfileTestGeneration, leftInput, datasource.DefaultLimits())
		right, rightErr := Decode(flatfileTestGeneration, rightInput, datasource.DefaultLimits())
		assertFuzzDecodeDeterminism(t, left, leftErr, right, rightErr)
		if bytes.Equal(document, fixture) && leftErr != nil {
			t.Fatal("known-valid strict JSON fixture was rejected")
		}
		if leftErr != nil {
			return
		}
		leftUsage, leftUsageErr := left.Usage()
		rightUsage, rightUsageErr := right.Usage()
		if leftUsageErr != nil || rightUsageErr != nil ||
			leftUsage != rightUsage ||
			leftUsage.Bytes() > datasource.DefaultLimits().MaxDecodedStringBytes ||
			leftUsage.Records() > datasource.DefaultLimits().MaxRecords {
			t.Fatal("successful strict decode violated bounded accounting")
		}
		for index := range leftInput {
			leftInput[index] ^= 0xff
		}
		if !left.Valid() {
			t.Fatal("strict decode retained caller-owned document bytes")
		}
	})
}

// FuzzCrossReferences proves malformed public keys, duplicate bindings, and
// dangling profile/handle facts fail deterministically without partial state.
func FuzzCrossReferences(f *testing.F) {
	fixture, err := os.ReadFile("testdata/valid-v1.json")
	if err != nil {
		f.Fatal("public fuzz seed is unavailable")
	}
	canonicalPublicKey, err := base64.StdEncoding.DecodeString(
		"MCowBQYDK2VwAyEAIClZTFkgcVVuQpqSIcMJ98ohgPBzN3SrWTX3gbhSofw=",
	)
	if err != nil {
		f.Fatal("public key fuzz seed is invalid")
	}
	f.Add(canonicalPublicKey, uint8(0))
	f.Add([]byte{}, uint8(0))
	f.Add([]byte{}, uint8(1))
	f.Add([]byte{}, uint8(2))
	f.Add([]byte{0x30, 0x00}, uint8(3))
	f.Add([]byte{}, uint8(4))
	f.Add([]byte("public-only"), uint8(5))

	f.Fuzz(func(t *testing.T, publicKey []byte, rawScenario uint8) {
		if len(publicKey) > fuzzPublicKeyBytes {
			return
		}
		scenario := rawScenario % 6
		document := fuzzCrossReferenceDocument(t, fixture, publicKey, scenario)
		left, leftErr := Decode(flatfileTestGeneration, document, datasource.DefaultLimits())
		right, rightErr := Decode(flatfileTestGeneration, bytes.Clone(document), datasource.DefaultLimits())
		assertFuzzDecodeDeterminism(t, left, leftErr, right, rightErr)

		switch scenario {
		case 1, 2, 3, 5:
			if datasource.ErrorCodeOf(leftErr) != datasource.ErrorCodeMalformedData {
				t.Fatal("dangling or incompatible cross-reference was not malformed")
			}
		case 4:
			if datasource.ErrorCodeOf(leftErr) != datasource.ErrorCodeAmbiguous {
				t.Fatal("duplicate cross-reference was not ambiguous")
			}
		case 0:
			if bytes.Equal(publicKey, canonicalPublicKey) && leftErr != nil {
				t.Fatal("known-valid public key cross-reference was rejected")
			}
			if leftErr == nil {
				usage, usageErr := left.Usage()
				if usageErr != nil || !usage.ValidForLimits(datasource.DefaultLimits()) {
					t.Fatal("accepted public key produced invalid accounting")
				}
			}
		}
	})
}

// FuzzProviderParity proves memory and pure flat-file snapshots return the
// same exact closed outcomes for bounded exact and missing lookup facts.
func FuzzProviderParity(f *testing.F) {
	for scenario := range uint8(8) {
		f.Add([]byte{scenario}, scenario)
	}

	f.Fuzz(func(t *testing.T, markerBytes []byte, rawScenario uint8) {
		if len(markerBytes) > fuzzParityMarkerBytes {
			return
		}
		marker := hex.EncodeToString(markerBytes)
		if marker == "" {
			marker = "0"
		}
		flat := mustDecodeSnapshot(t, mustFlatfileDocument(t), datasource.DefaultLimits())
		exactProfile, profileErr := flat.ResolveProfile(
			context.Background(),
			mustFlatfileProfileRequest(t),
		)
		exactPolicy, policyErr := flat.ResolvePolicy(
			context.Background(),
			mustFlatfilePolicyRequest(t),
		)
		if profileErr != nil || policyErr != nil {
			t.Fatal("parity fixture did not resolve")
		}
		profile := exactProfile.Profile()
		policy := exactPolicy.Policy()
		handles := make([]datasource.KeyHandleID, 0, profile.CredentialCount())
		for _, credential := range profile.Credentials() {
			handles = append(handles, credential.KeyHandleID())
		}
		inMemory, err := memory.New(
			flatfileTestGeneration,
			handles,
			[]datasource.Profile{profile},
			[]datasource.Policy{policy},
			datasource.DefaultLimits(),
		)
		if err != nil {
			t.Fatal("parity memory fixture did not publish")
		}

		scenario := rawScenario % 8
		if scenario == 0 || scenario == 1 || scenario == 2 || scenario == 7 {
			exerciseFuzzProfileParity(t, flat, inMemory, profile, marker, scenario)
			return
		}
		exerciseFuzzPolicyParity(t, flat, inMemory, policy, marker, scenario)
	})
}

// exerciseFuzzProfileParity runs exact, missing, unauthorized-use, and
// cancellation profile cases against both pure providers.
func exerciseFuzzProfileParity(
	t *testing.T,
	flat *Snapshot,
	inMemory *memory.Provider,
	profile datasource.Profile,
	marker string,
	scenario uint8,
) {
	t.Helper()
	profileID := profile.ID()
	use := datasource.ProfileUseOriginator
	var err error
	if scenario == 1 {
		profileID, err = datasource.NewProfileID("missing." + marker)
		if err != nil {
			t.Fatal("bounded missing profile identifier was invalid")
		}
	}
	if scenario == 2 {
		use = datasource.ProfileUseOrdinaryTransit
	}
	request, requestErr := datasource.NewProfileRequest(
		profileID,
		use,
		flatfileTestTime,
		datasource.DefaultLimits(),
	)
	if requestErr != nil {
		t.Fatal("bounded profile request was invalid")
	}
	ctx := context.Background()
	if scenario == 7 {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		ctx = cancelled
	}
	left, leftErr := flat.ResolveProfile(ctx, request)
	right, rightErr := inMemory.ResolveProfile(ctx, request)
	assertFuzzProfileParity(t, left, leftErr, right, rightErr)
	switch scenario {
	case 0, 2:
		if leftErr != nil || !left.Valid() || !right.Valid() {
			t.Fatal("known exact profile lookup did not succeed")
		}
	case 1:
		if datasource.ErrorCodeOf(leftErr) != datasource.ErrorCodeNotFound {
			t.Fatal("missing profile lookup did not return not_found")
		}
	case 7:
		if !errors.Is(leftErr, context.Canceled) ||
			!errors.Is(rightErr, context.Canceled) {
			t.Fatal("cancelled profile lookup did not preserve context identity")
		}
	}
}

// exerciseFuzzPolicyParity runs exact and independently missing policy facts
// against both pure providers.
func exerciseFuzzPolicyParity(
	t *testing.T,
	flat *Snapshot,
	inMemory *memory.Provider,
	policy datasource.Policy,
	marker string,
	scenario uint8,
) {
	t.Helper()
	tenant := policy.TenantID()
	domain := policy.SigningDomain()
	use := policy.Use()
	var err error
	switch scenario {
	case 4:
		tenant, err = datasource.NewTenantID("missing." + marker)
	case 5:
		domain = "missing-" + marker + ".test"
	case 6:
		use = datasource.ProfileUseOrdinaryTransit
	}
	if err != nil {
		t.Fatal("bounded missing tenant identifier was invalid")
	}
	request, requestErr := datasource.NewPolicyRequest(
		tenant,
		domain,
		use,
		flatfileTestTime,
		datasource.DefaultLimits(),
	)
	if requestErr != nil {
		t.Fatal("bounded policy request was invalid")
	}
	left, leftErr := flat.ResolvePolicy(context.Background(), request)
	right, rightErr := inMemory.ResolvePolicy(context.Background(), request)
	assertFuzzPolicyParity(t, left, leftErr, right, rightErr)
	if scenario == 3 {
		if leftErr != nil || !left.Valid() || !right.Valid() {
			t.Fatal("known exact policy lookup did not succeed")
		}
	} else if datasource.ErrorCodeOf(leftErr) != datasource.ErrorCodeNotFound {
		t.Fatal("missing policy lookup did not return not_found")
	}
}

// assertFuzzDecodeDeterminism validates one complete success or a direct
// persisted-data failure without exposing input bytes.
func assertFuzzDecodeDeterminism(
	t *testing.T,
	left *Snapshot,
	leftErr error,
	right *Snapshot,
	rightErr error,
) {
	t.Helper()
	if datasource.ErrorCodeOf(leftErr) != datasource.ErrorCodeOf(rightErr) ||
		(left == nil) != (right == nil) {
		t.Fatal("strict decoding was nondeterministic")
	}
	if leftErr == nil {
		if left == nil || right == nil || !left.Valid() || !right.Valid() {
			t.Fatal("strict decoder returned partial success")
		}
		return
	}
	if left != nil || right != nil {
		t.Fatal("strict decoder returned partial failure state")
	}
	switch datasource.ErrorCodeOf(leftErr) {
	case datasource.ErrorCodeMalformedData,
		datasource.ErrorCodeAmbiguous,
		datasource.ErrorCodeLimitExceeded:
	default:
		t.Fatal("strict decoder returned a non-closed persisted-data failure")
	}
}

// fuzzCrossReferenceDocument applies one bounded synthetic mutation to the
// public-only flat-file fixture.
func fuzzCrossReferenceDocument(
	t *testing.T,
	fixture []byte,
	publicKey []byte,
	scenario uint8,
) []byte {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal(fixture, &root); err != nil {
		t.Fatal("public cross-reference fixture was invalid")
	}
	handles, handlesOK := root[flatfileHandlesCollection].([]any)
	profiles, profilesOK := root[flatfileProfilesCollection].([]any)
	if !handlesOK || !profilesOK || len(handles) != 1 || len(profiles) != 1 {
		t.Fatal("public cross-reference fixture shape changed")
	}
	profile, profileOK := profiles[0].(map[string]any)
	if !profileOK {
		t.Fatal("public profile fixture shape changed")
	}
	credentials, credentialsOK := profile["credentials"].([]any)
	if !credentialsOK || len(credentials) != 1 {
		t.Fatal("public credential fixture shape changed")
	}
	credential, credentialOK := credentials[0].(map[string]any)
	if !credentialOK {
		t.Fatal("public credential fixture shape changed")
	}
	switch scenario {
	case 0:
		credential["public_key_spki"] = base64.StdEncoding.EncodeToString(publicKey)
	case 1:
		credential["handle_id"] = "key.missing"
	case 2:
		profile["credentials"] = append(credentials, credential)
	case 3:
		credential["algorithm"] = "rsa-sha256"
	case 4:
		root[flatfileHandlesCollection] = append(handles, handles[0])
	case 5:
		profile["id"] = "profile.missing"
	}
	document, err := json.Marshal(root)
	if err != nil {
		t.Fatal("bounded cross-reference mutation could not be encoded")
	}
	if len(document) > fuzzJSONInputBytes {
		t.Fatal("bounded cross-reference mutation exceeded its allocation contract")
	}
	return document
}

// assertFuzzProfileParity compares complete profile outcomes without printing
// request- or provider-controlled values.
func assertFuzzProfileParity(
	t *testing.T,
	left datasource.ResolvedProfile,
	leftErr error,
	right datasource.ResolvedProfile,
	rightErr error,
) {
	t.Helper()
	if datasource.ErrorCodeOf(leftErr) != datasource.ErrorCodeOf(rightErr) ||
		datasource.ValidateProfileOutcome(left, leftErr) != nil ||
		datasource.ValidateProfileOutcome(right, rightErr) != nil {
		t.Fatal("profile providers returned different closed outcome shapes")
	}
	if leftErr != nil {
		if left.Valid() || right.Valid() {
			t.Fatal("profile provider returned partial failure")
		}
		return
	}
	leftProfile := left.Profile()
	rightProfile := right.Profile()
	if !left.Valid() || !right.Valid() ||
		left.Generation() != right.Generation() ||
		left.ProfileID() != right.ProfileID() ||
		!equalFuzzProfileFacts(leftProfile, rightProfile) {
		t.Fatal("profile providers returned different exact facts")
	}
}

// assertFuzzPolicyParity compares complete policy outcomes and their embedded
// generation-consistent profiles.
func assertFuzzPolicyParity(
	t *testing.T,
	left datasource.ResolvedPolicy,
	leftErr error,
	right datasource.ResolvedPolicy,
	rightErr error,
) {
	t.Helper()
	if datasource.ErrorCodeOf(leftErr) != datasource.ErrorCodeOf(rightErr) ||
		datasource.ValidatePolicyOutcome(left, leftErr) != nil ||
		datasource.ValidatePolicyOutcome(right, rightErr) != nil {
		t.Fatal("policy providers returned different closed outcome shapes")
	}
	if leftErr != nil {
		if left.Valid() || right.Valid() {
			t.Fatal("policy provider returned partial failure")
		}
		return
	}
	if !left.Valid() || !right.Valid() ||
		left.Generation() != right.Generation() ||
		left.Policy() != right.Policy() ||
		!equalFuzzProfileFacts(left.Profile(), right.Profile()) {
		t.Fatal("policy providers returned different exact facts")
	}
}

// equalFuzzProfileFacts compares all provider-visible exact profile and public
// credential facts without serializing protected values.
func equalFuzzProfileFacts(left datasource.Profile, right datasource.Profile) bool {
	if left.ID() != right.ID() ||
		left.SigningDomain() != right.SigningDomain() ||
		left.Status() != right.Status() ||
		left.CredentialCount() != right.CredentialCount() {
		return false
	}
	leftNotBefore, leftNotAfter, leftHasWindow := left.ValidityWindow()
	rightNotBefore, rightNotAfter, rightHasWindow := right.ValidityWindow()
	if leftHasWindow != rightHasWindow ||
		!leftNotBefore.Equal(rightNotBefore) ||
		!leftNotAfter.Equal(rightNotAfter) {
		return false
	}
	leftCredentials := left.Credentials()
	rightCredentials := right.Credentials()
	for index := range leftCredentials {
		if leftCredentials[index].Selector() != rightCredentials[index].Selector() ||
			leftCredentials[index].Algorithm() != rightCredentials[index].Algorithm() ||
			leftCredentials[index].KeyHandleID() != rightCredentials[index].KeyHandleID() ||
			leftCredentials[index].PublicKeySPKISHA256() !=
				rightCredentials[index].PublicKeySPKISHA256() ||
			!bytes.Equal(
				leftCredentials[index].PublicKeySPKIDER(),
				rightCredentials[index].PublicKeySPKIDER(),
			) {
			return false
		}
	}
	return true
}
