package signingprofile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/croessner/dkim2/internal/datasource"
	"github.com/croessner/dkim2/internal/signing"
)

const fuzzProjectionMarkerBytes = 8

type projectionFuzzCase struct {
	result       datasource.ResolvedProfile
	request      datasource.ProfileRequest
	limits       signing.Limits
	expectedCode datasource.ErrorCode
}

// FuzzSigningProjection proves pure datasource-to-signing projection is
// deterministic, exact, detached, and closed under authorization drift.
func FuzzSigningProjection(f *testing.F) {
	for scenario := uint8(0); scenario < 5; scenario++ {
		f.Add([]byte{scenario}, scenario)
	}

	f.Fuzz(func(t *testing.T, markerBytes []byte, rawScenario uint8) {
		if len(markerBytes) > fuzzProjectionMarkerBytes {
			return
		}
		marker := hex.EncodeToString(markerBytes)
		if marker == "" {
			marker = "0"
		}
		selector := "s" + marker
		fixture := newProjectionFixture(
			t,
			selector,
			datasource.ProfileUseOriginator,
		)
		testCase := buildProjectionFuzzCase(t, fixture, selector, marker, rawScenario%5)
		left, leftErr := fixture.registry.ProjectProfile(
			testCase.result,
			testCase.request,
			testCase.limits,
		)
		right, rightErr := fixture.registry.ProjectProfile(
			testCase.result,
			testCase.request,
			testCase.limits,
		)
		if datasource.ErrorCodeOf(leftErr) != datasource.ErrorCodeOf(rightErr) ||
			left.Valid() != right.Valid() {
			t.Fatal("signing projection was nondeterministic")
		}
		if testCase.expectedCode != "" {
			if left.Valid() || right.Valid() ||
				datasource.ErrorCodeOf(leftErr) != testCase.expectedCode {
				t.Fatal("signing projection returned the wrong closed failure")
			}
			return
		}
		assertSuccessfulProjectionFuzzCase(t, fixture, testCase, selector, left, leftErr, right, rightErr)
	})
}

// buildProjectionFuzzCase constructs one bounded exact, drifted, missing, or
// narrowed projection input without retaining caller-controlled byte slices.
func buildProjectionFuzzCase(
	t *testing.T,
	fixture projectionFixture,
	selector string,
	marker string,
	scenario uint8,
) projectionFuzzCase {
	t.Helper()
	testCase := projectionFuzzCase{
		result:  fixture.resolvedProfile,
		request: fixture.profileRequest,
		limits:  signing.DefaultLimits(),
	}
	switch scenario {
	case 0:
	case 1:
		request, err := datasource.NewProfileRequest(
			fixture.profile.ID(),
			datasource.ProfileUseOrdinaryTransit,
			fixture.at,
			datasource.DefaultLimits(),
		)
		if err != nil {
			t.Fatal("bounded unauthorized projection request was invalid")
		}
		testCase.request = request
		testCase.expectedCode = datasource.ErrorCodeInactive
	case 2:
		drifted := newDatasourceProfile(
			t,
			fixture.profile.ID(),
			selector+"x",
			fixture.profile.Credentials()[0].KeyHandleID(),
		)
		result, err := datasource.NewResolvedProfile(1, drifted)
		if err != nil {
			t.Fatal("bounded drifted projection result was invalid")
		}
		testCase.result = result
		testCase.expectedCode = datasource.ErrorCodeInactive
	case 3:
		missingID, err := datasource.NewProfileID("profile.missing." + marker)
		if err != nil {
			t.Fatal("bounded missing projection identifier was invalid")
		}
		missing := newDatasourceProfile(
			t,
			missingID,
			selector,
			fixture.profile.Credentials()[0].KeyHandleID(),
		)
		testCase.result, err = datasource.NewResolvedProfile(1, missing)
		if err != nil {
			t.Fatal("bounded missing projection result was invalid")
		}
		testCase.request, err = datasource.NewProfileRequest(
			missingID,
			datasource.ProfileUseOriginator,
			fixture.at,
			datasource.DefaultLimits(),
		)
		if err != nil {
			t.Fatal("bounded missing projection request was invalid")
		}
		testCase.expectedCode = datasource.ErrorCodeNotFound
	case 4:
		testCase.limits.MaxMessageBytes = 0
		testCase.expectedCode = datasource.ErrorCodeInvalidRequest
	}
	return testCase
}

// assertSuccessfulProjectionFuzzCase verifies exact credential facts and
// proves returned credentials and public-key bytes are fully detached.
func assertSuccessfulProjectionFuzzCase(
	t *testing.T,
	fixture projectionFixture,
	testCase projectionFuzzCase,
	selector string,
	left signing.Profile,
	leftErr error,
	right signing.Profile,
	rightErr error,
) {
	t.Helper()
	if leftErr != nil || rightErr != nil ||
		!left.Valid() || !right.Valid() ||
		left.Domain() != fixture.profile.SigningDomain() {
		t.Fatal("valid signing projection did not preserve profile facts")
	}
	leftCredentials := left.Credentials()
	rightCredentials := right.Credentials()
	sourceCredential := fixture.profile.Credentials()[0]
	if len(leftCredentials) != 1 || len(rightCredentials) != 1 ||
		leftCredentials[0].Selector() != selector ||
		rightCredentials[0].Selector() != selector ||
		leftCredentials[0].Algorithm() != sourceCredential.Algorithm() ||
		rightCredentials[0].Algorithm() != sourceCredential.Algorithm() {
		t.Fatal("valid signing projection changed credential facts")
	}
	leftKey, leftOK := leftCredentials[0].PublicKey().(ed25519.PublicKey)
	rightKey, rightOK := rightCredentials[0].PublicKey().(ed25519.PublicKey)
	sourceKey, sourceOK := sourceCredential.PublicKey().(ed25519.PublicKey)
	if !leftOK || !rightOK || !sourceOK ||
		!bytes.Equal(leftKey, sourceKey) ||
		!bytes.Equal(rightKey, sourceKey) {
		t.Fatal("valid signing projection changed public key facts")
	}
	leftKey[0] ^= 0xff
	leftCredentials[0] = signing.Credential{}
	again, againErr := fixture.registry.ProjectProfile(
		testCase.result,
		testCase.request,
		testCase.limits,
	)
	againCredentials := again.Credentials()
	if againErr != nil || !again.Valid() ||
		len(againCredentials) != 1 ||
		againCredentials[0].Selector() != selector {
		t.Fatal("signing projection aliased returned credential state")
	}
	againKey, againOK := againCredentials[0].PublicKey().(ed25519.PublicKey)
	if !againOK || !bytes.Equal(againKey, sourceKey) {
		t.Fatal("signing projection aliased returned public key state")
	}
}
