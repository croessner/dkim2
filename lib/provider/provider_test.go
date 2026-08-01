package provider

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

type panickingProviderCodeError struct{}

// Error returns one bounded hostile-classifier diagnostic.
func (*panickingProviderCodeError) Error() string { return "provider code failure" }

// Code panics if the public classifier does not contain injected behavior.
func (*panickingProviderCodeError) Code() ErrorCode { panic("provider code panic") }

// TestErrorCodeOfContainsHostileDirectClassifiers proves the dual classifier
// neither traverses wrapped errors nor permits panics or typed nil calls.
func TestErrorCodeOfContainsHostileDirectClassifiers(t *testing.T) {
	var typedNil *panickingProviderCodeError
	for _, err := range []error{typedNil, &panickingProviderCodeError{}} {
		if code := ErrorCodeOf(err); code != ErrorCodeInternalInvariant {
			t.Fatalf("ErrorCodeOf(hostile)=%q", code)
		}
	}
}

// TestDatasetBridgeDelegatesValidation proves the public bridge uses the
// authoritative constructors and preserves exact lookup semantics.
func TestDatasetBridgeDelegatesValidation(t *testing.T) {
	t.Parallel()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate synthetic public key")
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal("marshal synthetic public key")
	}
	limits := DefaultLimits()
	credential, err := NewCredential(
		"selector", AlgorithmEd25519SHA256, spki, "handle", limits,
	)
	if err != nil {
		t.Fatal("construct credential")
	}
	profile, err := NewProfile(
		"profile", "example.test", RecordStatusActive,
		[]Credential{credential}, time.Time{}, time.Time{}, limits,
	)
	if err != nil {
		t.Fatal("construct profile")
	}
	policy, err := NewPolicy(
		"tenant", "example.test", ProfileUseOriginator, "profile",
		RecordStatusActive, RolloutEnforce, CompatibilityStrict, "", limits,
	)
	if err != nil {
		t.Fatal("construct policy")
	}
	dataset, err := NewDataset(
		7, []string{"handle"}, []Profile{profile}, []Policy{policy}, limits,
	)
	if err != nil {
		t.Fatal("construct dataset")
	}
	at := time.Unix(1, 0).UTC()
	resolvedPolicy, resolvedProfile, err := dataset.ResolvePolicy(
		context.Background(), "tenant", "example.test",
		ProfileUseOriginator, at,
	)
	if err != nil || !resolvedPolicy.Valid() || !resolvedProfile.Valid() ||
		dataset.Generation() != 7 {
		t.Fatal("resolve exact policy")
	}
	_, _, err = dataset.ResolvePolicy(
		context.Background(), "tenant", "sub.example.test",
		ProfileUseOriginator, at,
	)
	if ErrorCodeOf(err) != ErrorCodeNotFound {
		t.Fatal("suffix lookup must not fall back")
	}
}

// TestDatasetEquivalentRequiresExactFacts proves same-generation identity
// checks accept exact immutable copies and reject changed valid records.
func TestDatasetEquivalentRequiresExactFacts(t *testing.T) {
	t.Parallel()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate synthetic public key")
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal("marshal synthetic public key")
	}
	limits := DefaultLimits()
	credential, err := NewCredential(
		"selector", AlgorithmEd25519SHA256, spki, "handle", limits,
	)
	if err != nil {
		t.Fatal("construct credential")
	}
	build := func(domain string) *Dataset {
		t.Helper()
		profile, profileErr := NewProfile(
			"profile", domain, RecordStatusActive,
			[]Credential{credential}, time.Time{}, time.Time{}, limits,
		)
		if profileErr != nil {
			t.Fatal("construct profile")
		}
		policy, policyErr := NewPolicy(
			"tenant", domain, ProfileUseOriginator, "profile",
			RecordStatusActive, RolloutEnforce, CompatibilityStrict, "", limits,
		)
		if policyErr != nil {
			t.Fatal("construct policy")
		}
		dataset, datasetErr := NewDataset(
			11, []string{"handle"}, []Profile{profile}, []Policy{policy}, limits,
		)
		if datasetErr != nil {
			t.Fatal("construct dataset")
		}
		return dataset
	}
	first := build("example.test")
	if !first.Equivalent(build("example.test")) {
		t.Fatal("exact immutable datasets must be equivalent")
	}
	if first.Equivalent(build("changed.example")) {
		t.Fatal("changed same-generation facts must not be equivalent")
	}
}

// TestBridgeValuesAreRedacted proves generic formatting and JSON never expose
// protected datasource facts.
func TestBridgeValuesAreRedacted(t *testing.T) {
	t.Parallel()
	values := []any{Credential{}, Profile{}, Policy{}, &Dataset{}}
	for _, value := range values {
		formatted := fmt.Sprintf("%+v", value)
		if formatted != redacted {
			t.Fatalf("unexpected protected formatting class")
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal("marshal redacted value")
		}
		if string(encoded) != "{}" {
			t.Fatal("unexpected protected JSON shape")
		}
	}
}
