package httpjson

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

type testCapabilityMatcher struct {
	value []byte
	calls int
	seen  []byte
}

// Equal performs the test seam's exact comparison.
func (m *testCapabilityMatcher) Equal(value []byte) bool {
	m.calls++
	m.seen = value
	return bytes.Equal(m.value, value)
}

// TestAuthenticateLocalCapabilityFreezesClosedCanonicalComparison covers all public failure shapes.
func TestAuthenticateLocalCapabilityFreezesClosedCanonicalComparison(t *testing.T) {
	t.Parallel()
	secret := bytes.Repeat([]byte{0xa5}, 32)
	canonical := base64.RawURLEncoding.EncodeToString(secret)
	cases := []struct {
		name   string
		values []string
		ok     bool
		calls  int
	}{
		{name: testMissingName},
		{name: transportTestEmpty, values: []string{""}},
		{name: "whitespace", values: []string{" " + canonical}},
		{name: "padded", values: []string{canonical + "="}},
		{name: testCommaName, values: []string{canonical + ","}},
		{name: testDuplicateName, values: []string{canonical, canonical}},
		{name: "wrong length", values: []string{canonical[:42]}},
		{name: transportTestMalformed, values: []string{canonical[:42] + "*"}},
		{name: testMismatchName, values: []string{base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xb6}, 32))}, calls: 1},
		{name: observationSuccess, values: []string{canonical}, ok: true, calls: 1},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodPost, testProcessPath, nil)
			for _, value := range testCase.values {
				request.Header.Add(localCapabilityHeader, value)
			}
			matcher := &testCapabilityMatcher{value: secret}
			result, ok := authenticateLocalCapability(request, matcher)
			if ok != testCase.ok || matcher.calls != testCase.calls {
				t.Fatalf("authenticateLocalCapability() = (%v, calls %d), want (%v, %d)", ok, matcher.calls, testCase.ok, testCase.calls)
			}
			if values := result.Header.Values(localCapabilityHeader); len(values) != 0 {
				t.Fatal("capability header survived preflight")
			}
			if localCapabilityAuthenticated(result.Context()) != testCase.ok {
				t.Fatal("private authentication marker mismatch")
			}
			if matcher.calls == 1 && !allZeroBytes(matcher.seen) {
				t.Fatal("decoded capability backing survived authentication")
			}
		})
	}
}

// allZeroBytes reports whether a transient protected backing was scrubbed.
func allZeroBytes(value []byte) bool {
	for _, element := range value {
		if element != 0 {
			return false
		}
	}
	return true
}

// TestAuthenticateLocalCapabilityRejectsTypedNilMatcherWithoutRetainingHeader proves composition safety.
func TestAuthenticateLocalCapabilityRejectsTypedNilMatcherWithoutRetainingHeader(t *testing.T) {
	t.Parallel()
	var matcher *testCapabilityMatcher
	request := httptest.NewRequest(http.MethodPost, testProcessPath, nil)
	request.Header.Set(
		localCapabilityHeader,
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, 32)),
	)
	result, ok := authenticateLocalCapability(request, matcher)
	if ok || result == nil || len(result.Header.Values(localCapabilityHeader)) != 0 ||
		localCapabilityAuthenticated(result.Context()) {
		t.Fatal("typed-nil matcher authenticated or retained capability")
	}
}

// TestAuthenticateOperationCapabilityUsesDedicatedDSNHeader proves the DSN
// route cannot authenticate with the ordinary operation credential field.
func TestAuthenticateOperationCapabilityUsesDedicatedDSNHeader(t *testing.T) {
	t.Parallel()
	secret := bytes.Repeat([]byte{0xa5}, 32)
	canonical := base64.RawURLEncoding.EncodeToString(secret)
	for _, testCase := range []struct {
		name   string
		header string
		ok     bool
	}{
		{name: "dedicated header", header: dsnSignCapabilityHeader, ok: true},
		{name: "ordinary header", header: localCapabilityHeader},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodPost, dsnSignPath, nil)
			request.Header.Set(testCase.header, canonical)
			matcher := &testCapabilityMatcher{value: secret}
			result, ok := authenticateOperationCapability(request, matcher)
			if ok != testCase.ok || matcher.calls != boolInt(testCase.ok) ||
				len(result.Header.Values(localCapabilityHeader)) != 0 ||
				len(result.Header.Values(dsnSignCapabilityHeader)) != 0 {
				t.Fatalf("authenticateOperationCapability() = (%v, calls %d)", ok, matcher.calls)
			}
		})
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
