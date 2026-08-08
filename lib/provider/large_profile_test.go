package provider

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"
	"time"
)

const largeDomainCount = 10000

// TestProductionLimitsLoadTenThousandDualAlgorithmDomains proves the supported corpus.
func TestProductionLimitsLoadTenThousandDualAlgorithmDomains(t *testing.T) {
	limits := ProductionLimits()
	if err := limits.Validate(); err != nil {
		t.Fatal("production limits invalid")
	}
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate Ed25519 fixture")
	}
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("generate RSA fixture")
	}
	edSPKI, err := x509.MarshalPKIXPublicKey(edPublic)
	if err != nil {
		t.Fatal("marshal Ed25519 fixture")
	}
	rsaSPKI, err := x509.MarshalPKIXPublicKey(&rsaPrivate.PublicKey)
	if err != nil {
		t.Fatal("marshal RSA fixture")
	}
	handles := make([]string, 0, largeDomainCount*2)
	profiles := make([]Profile, 0, largeDomainCount)
	policies := make([]Policy, 0, largeDomainCount)
	for index := 0; index < largeDomainCount; index++ {
		domain := fmt.Sprintf("d%05d.example.test", index)
		profileID := fmt.Sprintf("profile-%05d", index)
		edHandle, rsaHandle := fmt.Sprintf("ed-%05d", index), fmt.Sprintf("rsa-%05d", index)
		edCredential, credentialErr := NewCredential(fmt.Sprintf("e%05d", index), AlgorithmEd25519SHA256, edSPKI, edHandle, limits)
		if credentialErr != nil {
			t.Fatal("construct Ed25519 credential")
		}
		rsaCredential, credentialErr := NewCredential(fmt.Sprintf("r%05d", index), AlgorithmRSASHA256, rsaSPKI, rsaHandle, limits)
		if credentialErr != nil {
			t.Fatal("construct RSA credential")
		}
		profile, profileErr := NewProfile(profileID, domain, RecordStatusActive, []Credential{edCredential, rsaCredential}, time.Time{}, time.Time{}, limits)
		if profileErr != nil {
			t.Fatal("construct profile")
		}
		policy, policyErr := NewPolicy("tenant", domain, ProfileUseOriginator, profileID, RecordStatusActive, RolloutEnforce, CompatibilityStrict, "", limits)
		if policyErr != nil {
			t.Fatal("construct policy")
		}
		handles = append(handles, edHandle, rsaHandle)
		profiles = append(profiles, profile)
		policies = append(policies, policy)
	}
	dataset, err := NewDataset(7, handles, profiles, policies, limits)
	if err != nil {
		t.Fatal("large production dataset rejected")
	}
	for _, index := range []int{0, largeDomainCount / 2, largeDomainCount - 1} {
		domain := fmt.Sprintf("d%05d.example.test", index)
		_, profile, resolveErr := dataset.ResolvePolicy(context.Background(), "tenant", domain, ProfileUseOriginator, time.Now().UTC())
		if resolveErr != nil || !profile.Valid() {
			t.Fatal("large production dataset lookup failed")
		}
	}
}

// TestDatasourceLimitProfilesRemainFiniteAndNonWidenable covers partial widening.
func TestDatasourceLimitProfilesRemainFiniteAndNonWidenable(t *testing.T) {
	if DefaultLimits().MaxProfiles >= ProductionLimits().MaxProfiles || ProductionLimits().MaxProfiles > HardLimits().MaxProfiles {
		t.Fatal("limit profile ordering invalid")
	}
	widened := ProductionLimits()
	widened.MaxProfiles = HardLimits().MaxProfiles + 1
	if widened.Validate() == nil {
		t.Fatal("widened profile accepted")
	}
}
