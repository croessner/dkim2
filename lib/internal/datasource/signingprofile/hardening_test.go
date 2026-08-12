package signingprofile

import (
	"context"
	"crypto/ed25519"
	"reflect"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/datasource"
	"github.com/croessner/dkim2/internal/datasource/memory"
	"github.com/croessner/dkim2/internal/signing"
)

// TestConcurrentRegistryAndAdapterProjectionKeepsDistinctHandlesIsolated
// proves shared physical capability storage cannot cross logical bindings.
func TestConcurrentRegistryAndAdapterProjectionKeepsDistinctHandlesIsolated(t *testing.T) {
	t.Parallel()

	firstHandle, err := signing.NewPrivateKeyHandle([]byte("first-inert-capability"))
	if err != nil {
		t.Fatal("first inert handle construction failed")
	}
	secondHandle, err := signing.NewPrivateKeyHandle([]byte("second-inert-capability"))
	if err != nil {
		t.Fatal("second inert handle construction failed")
	}
	firstID := mustProjectionProfileID(t, "profile.concurrent.one")
	secondID := mustProjectionProfileID(t, "profile.concurrent.two")
	sharedID := mustProjectionProfileID(t, "profile.concurrent.shared")
	firstProfile, firstEntry := newSingleCredentialEntry(
		t,
		firstID,
		"one.test",
		"one",
		datasource.AlgorithmEd25519SHA256,
		"handle.concurrent.one",
		firstHandle,
		datasource.ProfileUseOriginator,
		1,
	)
	secondProfile, secondEntry := newSingleCredentialEntry(
		t,
		secondID,
		"two.test",
		"two",
		datasource.AlgorithmEd25519SHA256,
		"handle.concurrent.two",
		secondHandle,
		datasource.ProfileUseOriginator,
		2,
	)
	sharedProfile, sharedEntry := newSingleCredentialEntry(
		t,
		sharedID,
		"shared.test",
		"shared",
		datasource.AlgorithmEd25519SHA256,
		"handle.concurrent.shared",
		firstHandle,
		datasource.ProfileUseOriginator,
		3,
	)
	registry := mustProjectionRegistry(t, firstEntry, secondEntry, sharedEntry)
	provider, err := memory.New(
		1,
		[]datasource.KeyHandleID{
			firstEntry.KeyHandleID(),
			secondEntry.KeyHandleID(),
			sharedEntry.KeyHandleID(),
		},
		[]datasource.Profile{firstProfile, secondProfile, sharedProfile},
		nil,
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatal("concurrent projection provider construction failed")
	}
	adapter, err := NewAdapter(provider, registry, signing.DefaultLimits())
	if err != nil {
		t.Fatal("concurrent projection adapter construction failed")
	}

	const workers = 64
	start := make(chan struct{})
	results := make(chan bool, workers)
	at := time.Unix(1_700_000_000, 0).UTC()
	firstResolved, firstRequest := projectionResultAndRequest(
		t,
		firstProfile,
		datasource.ProfileUseOriginator,
	)
	secondResolved, secondRequest := projectionResultAndRequest(
		t,
		secondProfile,
		datasource.ProfileUseOriginator,
	)
	sharedResolved, sharedRequest := projectionResultAndRequest(
		t,
		sharedProfile,
		datasource.ProfileUseOriginator,
	)
	type projectionCase struct {
		profile          datasource.Profile
		resolved         datasource.ResolvedProfile
		request          datasource.ProfileRequest
		expected         signing.Profile
		expectedHandle   signing.PrivateKeyHandle
		expectedDomain   string
		expectedSelector string
	}
	cases := []projectionCase{
		{
			profile: firstProfile, resolved: firstResolved, request: firstRequest,
			expected:       mustExpectedConcurrentProjection(t, firstProfile, firstHandle),
			expectedHandle: firstHandle,
			expectedDomain: "one.test", expectedSelector: "one",
		},
		{
			profile: secondProfile, resolved: secondResolved, request: secondRequest,
			expected:       mustExpectedConcurrentProjection(t, secondProfile, secondHandle),
			expectedHandle: secondHandle,
			expectedDomain: "two.test", expectedSelector: "two",
		},
		{
			profile: sharedProfile, resolved: sharedResolved, request: sharedRequest,
			expected:       mustExpectedConcurrentProjection(t, sharedProfile, firstHandle),
			expectedHandle: firstHandle,
			expectedDomain: "shared.test", expectedSelector: "shared",
		},
	}
	for worker := range workers {
		test := cases[worker%len(cases)]
		go func() {
			<-start
			matched, matchedErr := registry.matchedEntries(
				test.profile,
				datasource.ProfileUseOriginator,
			)
			direct, directErr := registry.ProjectProfile(
				test.resolved,
				test.request,
				signing.DefaultLimits(),
			)
			projected, projectedErr := adapter.ResolveProfile(
				context.Background(),
				test.profile.ID(),
				datasource.ProfileUseOriginator,
				at,
			)
			if matchedErr != nil || len(matched) != 1 ||
				matched[0].handle != test.expectedHandle ||
				directErr != nil || projectedErr != nil ||
				!exactConcurrentProjection(
					direct,
					test.expectedDomain,
					test.expectedSelector,
				) ||
				!exactConcurrentProjection(
					projected,
					test.expectedDomain,
					test.expectedSelector,
				) ||
				!reflect.DeepEqual(direct, test.expected) ||
				!reflect.DeepEqual(projected, test.expected) {
				results <- false
				return
			}
			credentials := projected.Credentials()
			publicKey, ok := credentials[0].PublicKey().(ed25519.PublicKey)
			if !ok {
				results <- false
				return
			}
			publicKey[0] ^= 0xff
			credentials[0] = signing.Credential{}
			again, againErr := adapter.ResolveProfile(
				context.Background(),
				test.profile.ID(),
				datasource.ProfileUseOriginator,
				at,
			)
			results <- againErr == nil &&
				exactConcurrentProjection(
					again,
					test.expectedDomain,
					test.expectedSelector,
				) &&
				reflect.DeepEqual(again, test.expected)
		}()
	}
	close(start)
	for range workers {
		if !<-results {
			t.Fatal("concurrent projection crossed or aliased logical handle facts")
		}
	}
}

// mustExpectedConcurrentProjection constructs an independent exact signing
// oracle whose private handle remains visible only through structural equality.
func mustExpectedConcurrentProjection(
	t *testing.T,
	profile datasource.Profile,
	handle signing.PrivateKeyHandle,
) signing.Profile {
	t.Helper()
	source := profile.Credentials()[0]
	credential, err := signing.NewCredential(
		source.Selector(),
		source.Algorithm(),
		source.PublicKey(),
		handle,
		signing.DefaultLimits(),
	)
	if err != nil {
		t.Fatal("expected concurrent credential construction failed")
	}
	expected, err := signing.NewProfile(
		profile.SigningDomain(),
		[]signing.Credential{credential},
	)
	if err != nil {
		t.Fatal("expected concurrent profile construction failed")
	}
	return expected
}

// exactConcurrentProjection validates the exact bounded public profile facts
// needed to distinguish concurrent logical handle groups.
func exactConcurrentProjection(
	profile signing.Profile,
	expectedDomain string,
	expectedSelector string,
) bool {
	if !profile.Valid() || profile.Domain() != expectedDomain {
		return false
	}
	credentials := profile.Credentials()
	return len(credentials) == 1 &&
		credentials[0].Valid() &&
		credentials[0].Selector() == expectedSelector &&
		credentials[0].Algorithm() == signing.AlgorithmEd25519SHA256
}
