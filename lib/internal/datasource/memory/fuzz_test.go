package memory

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/datasource"
)

const fuzzMappingMarkerBytes = 8

// FuzzSnapshotMapping proves immutable snapshot construction closes
// ambiguity, dangling references, reused handles, and configured bounds.
func FuzzSnapshotMapping(f *testing.F) {
	for scenario := uint8(0); scenario < 9; scenario++ {
		f.Add([]byte{scenario}, scenario, scenario)
	}

	f.Fuzz(func(t *testing.T, markerBytes []byte, rawScenario uint8, rawGeneration uint8) {
		if len(markerBytes) > fuzzMappingMarkerBytes {
			return
		}
		marker := hex.EncodeToString(markerBytes)
		if marker == "" {
			marker = "0"
		}
		fixture := newMemoryFixtureWithMarker(t, marker)
		handles := fixture.handles()
		profiles := fixture.profiles()
		policies := fixture.policies()
		limits := fixture.limits
		expectedCode := datasource.ErrorCode("")

		switch rawScenario % 9 {
		case 0:
		case 1:
			handles = append(handles, fixture.handleID)
			expectedCode = datasource.ErrorCodeAmbiguous
		case 2:
			profiles = append(profiles, fixture.profile)
			expectedCode = datasource.ErrorCodeAmbiguous
		case 3:
			policies = append(policies, fixture.policy)
			expectedCode = datasource.ErrorCodeAmbiguous
		case 4:
			missing := mustMemoryHandleID(t, "handle.missing."+marker)
			profiles = append(profiles, fixture.profileWithHandle(
				t,
				"profile.missing."+marker,
				"missing-"+marker+".test",
				"missing-"+marker,
				missing,
			))
			expectedCode = datasource.ErrorCodeMalformedData
		case 5:
			missingID := mustMemoryProfileID(t, "profile.missing."+marker)
			policies = append(policies, fixture.policyWith(
				t,
				"tenant.missing."+marker,
				fixture.profile.SigningDomain(),
				datasource.ProfileUseOriginator,
				missingID,
				datasource.RecordStatusActive,
				datasource.RolloutEnforce,
			))
			expectedCode = datasource.ErrorCodeMalformedData
		case 6:
			limits.MaxProfiles = 1
			secondHandle := mustMemoryHandleID(t, "handle.second."+marker)
			handles = append(handles, secondHandle)
			profiles = append(profiles, fixture.profileWithHandle(
				t,
				"profile.second."+marker,
				"second-"+marker+".test",
				"second-"+marker,
				secondHandle,
			))
			expectedCode = datasource.ErrorCodeLimitExceeded
		case 7:
			profiles = append(profiles, fixture.profileWithHandle(
				t,
				"profile.reused."+marker,
				"reused-"+marker+".test",
				"reused-"+marker,
				fixture.handleID,
			))
			expectedCode = datasource.ErrorCodeAmbiguous
		case 8:
			policies = append(policies, fixture.policyWith(
				t,
				"tenant.other."+marker,
				"other-"+marker+".test",
				datasource.ProfileUseOriginator,
				fixture.profile.ID(),
				datasource.RecordStatusActive,
				datasource.RolloutEnforce,
			))
			expectedCode = datasource.ErrorCodeMalformedData
		}

		generation := uint64(rawGeneration) + 1
		providerA, errA := New(generation, handles, profiles, policies, limits)
		providerB, errB := New(generation, handles, profiles, policies, limits)
		if datasource.ErrorCodeOf(errA) != datasource.ErrorCodeOf(errB) ||
			(providerA == nil) != (providerB == nil) {
			t.Fatal("snapshot mapping was nondeterministic")
		}
		if expectedCode != "" {
			if providerA != nil || datasource.ErrorCodeOf(errA) != expectedCode {
				t.Fatal("invalid snapshot mapping returned the wrong closed outcome")
			}
			return
		}
		if errA != nil || providerA == nil || providerB == nil ||
			!providerA.Valid() || !providerB.Valid() {
			t.Fatal("valid snapshot mapping did not publish")
		}
		request := mustMemoryProfileRequest(
			t,
			fixture.profile.ID(),
			datasource.ProfileUseOriginator,
			time.Unix(1_700_000_000, 0),
			limits,
		)
		before, beforeErr := providerA.ResolveProfile(context.Background(), request)
		if beforeErr != nil || !before.Valid() || before.Generation() != generation {
			t.Fatal("published snapshot did not resolve exact profile facts")
		}
		handles[0] = datasource.KeyHandleID{}
		profiles[0] = datasource.Profile{}
		policies[0] = datasource.Policy{}
		credentials := before.Profile().Credentials()
		publicKey := credentials[0].PublicKeySPKIDER()
		publicKey[0] ^= 0xff
		after, afterErr := providerA.ResolveProfile(context.Background(), request)
		if afterErr != nil || !after.Valid() ||
			after.Profile().Credentials()[0].PublicKeySPKISHA256() !=
				credentials[0].PublicKeySPKISHA256() {
			t.Fatal("published snapshot aliased caller-controlled state")
		}
	})
}
