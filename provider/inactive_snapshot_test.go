package provider

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	"github.com/croessner/dkim2"
)

// TestSigningResolverSeparatesSnapshotValidationFromAuthorization preserves
// disabled, rollout, and time-window gates while loading the complete dataset.
func TestSigningResolverSeparatesSnapshotValidationFromAuthorization(t *testing.T) {
	at := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		profile RecordStatus
		policy  RecordStatus
		rollout Rollout
		before  time.Time
		after   time.Time
		allowed bool
	}{
		{name: "active", profile: RecordStatusActive, policy: RecordStatusActive, rollout: RolloutEnforce, allowed: true},
		{name: "disabled", profile: RecordStatusDisabled, policy: RecordStatusDisabled, rollout: RolloutOff},
		{name: "policy disabled", profile: RecordStatusActive, policy: RecordStatusDisabled, rollout: RolloutOff},
		{name: "profile disabled", profile: RecordStatusDisabled, policy: RecordStatusActive, rollout: RolloutEnforce},
		{name: "off", profile: RecordStatusActive, policy: RecordStatusActive, rollout: RolloutOff},
		{name: "observe", profile: RecordStatusActive, policy: RecordStatusActive, rollout: RolloutObserve},
		{name: "future", profile: RecordStatusActive, policy: RecordStatusActive, rollout: RolloutEnforce, before: at.Add(time.Hour), after: at.Add(2 * time.Hour)},
		{name: "expired", profile: RecordStatusActive, policy: RecordStatusActive, rollout: RolloutEnforce, before: at.Add(-2 * time.Hour), after: at.Add(-time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			dataset, bindings := mixedPolicyDataset(t, test.profile, test.policy, test.rollout, test.before, test.after)
			resolver, err := dataset.NewSigningResolver(bindings, at)
			if err != nil || resolver == nil {
				t.Fatal("complete immutable dataset rejected during construction")
			}
			t.Cleanup(func() { _ = resolver.Close(context.Background()) })
			active, err := resolver.ResolvePolicy(t.Context(), "tenant", "active.test", ProfileUseOriginator, at)
			if err != nil || !active.Valid() {
				t.Fatal("inactive sibling prevented active profile resolution")
			}
			resolved, err := resolver.ResolvePolicy(t.Context(), "tenant", "inactive.test", ProfileUseOrdinaryTransit, at)
			if test.allowed {
				if err != nil || !resolved.Valid() {
					t.Fatal("eligible profile failed runtime authorization")
				}
			} else if ErrorCodeOf(err) != ErrorCodeInactive || resolved.Valid() {
				t.Fatal("inert snapshot inspection granted inactive signing authority")
			}
			if test.name == "future" {
				later, err := resolver.ResolvePolicy(t.Context(), "tenant", "inactive.test", ProfileUseOrdinaryTransit, test.before.Add(time.Minute))
				if err != nil || !later.Valid() {
					t.Fatal("validity window was frozen at registry construction")
				}
			}
		})
	}
}

// TestSigningResolverValidatesInactiveBindings proves no inactive key or
// selection is skipped when the complete registry is constructed.
func TestSigningResolverValidatesInactiveBindings(t *testing.T) {
	dataset, bindings := mixedPolicyDataset(t, RecordStatusDisabled, RecordStatusDisabled, RolloutOff, time.Time{}, time.Time{})
	for _, test := range []struct {
		name   string
		mutate func([]Binding) []Binding
	}{
		{name: "duplicate", mutate: func(values []Binding) []Binding { return append(values, values[1]) }},
		{name: "zero", mutate: func(values []Binding) []Binding { values[1] = Binding{}; return values }},
		{name: "wrong digest", mutate: func(values []Binding) []Binding {
			handle, _ := dkim2.NewPrivateKeyHandle([]byte("inactive-handle"))
			values[1], _ = NewBinding("tenant", "inactive.test", ProfileUseOrdinaryTransit, "inactive-handle", handle, AlgorithmEd25519SHA256, [sha256.Size]byte{})
			return values
		}},
		{name: "wrong tenant", mutate: func(values []Binding) []Binding {
			handle, _ := dkim2.NewPrivateKeyHandle([]byte("inactive-handle"))
			values[1], _ = NewBinding("other-tenant", "inactive.test", ProfileUseOrdinaryTransit, "inactive-handle", handle, AlgorithmEd25519SHA256, [sha256.Size]byte{1})
			return values
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := test.mutate(append([]Binding(nil), bindings...))
			resolver, err := dataset.NewSigningResolver(changed, time.Now().UTC())
			if err == nil || resolver != nil {
				t.Fatal("malformed inactive binding bypassed static validation")
			}
		})
	}
}

// mixedPolicyDataset constructs independent active and configurable inactive
// public-key bindings; it retains no private signing capability.
func mixedPolicyDataset(t *testing.T, profileStatus, policyStatus RecordStatus, rollout Rollout, before, after time.Time) (*Dataset, []Binding) {
	t.Helper()
	limits := DefaultLimits()
	var profiles []Profile
	var policies []Policy
	var bindings []Binding
	var handles []string
	for index, label := range []string{"active", "inactive"} {
		seed := make([]byte, ed25519.SeedSize)
		seed[0] = byte(index + 1)
		private := ed25519.NewKeyFromSeed(seed)
		spki, err := x509.MarshalPKIXPublicKey(private.Public())
		clear(private)
		clear(seed)
		if err != nil {
			t.Fatal("encode synthetic public key")
		}
		domain, id, handleID := label+".test", label+"-profile", label+"-handle"
		use, ps, as, mode := ProfileUseOriginator, RecordStatusActive, RecordStatusActive, RolloutEnforce
		start, end := time.Time{}, time.Time{}
		if index == 1 {
			use, ps, as, mode, start, end = ProfileUseOrdinaryTransit, profileStatus, policyStatus, rollout, before, after
		}
		credential, err := NewCredential(label+"-selector", AlgorithmEd25519SHA256, spki, handleID, limits)
		if err != nil {
			t.Fatal("construct fixture credential")
		}
		profile, err := NewProfile(id, domain, ps, []Credential{credential}, start, end, limits)
		if err != nil {
			t.Fatal("construct fixture profile")
		}
		policy, err := NewPolicy("tenant", domain, use, id, as, mode, CompatibilityStrict, "", limits)
		if err != nil {
			t.Fatal("construct fixture policy")
		}
		handle, err := dkim2.NewPrivateKeyHandle([]byte(handleID))
		if err != nil {
			t.Fatal("construct inert fixture handle")
		}
		binding, err := NewBinding("tenant", domain, use, handleID, handle, AlgorithmEd25519SHA256, sha256.Sum256(spki))
		if err != nil {
			t.Fatal("construct fixture binding")
		}
		profiles, policies = append(profiles, profile), append(policies, policy)
		handles, bindings = append(handles, handleID), append(bindings, binding)
	}
	dataset, err := NewDataset(7, handles, profiles, policies, limits)
	if err != nil {
		t.Fatal("construct mixed fixture dataset")
	}
	return dataset, bindings
}
