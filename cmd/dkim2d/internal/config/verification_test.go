package config

import (
	"testing"
)

// TestVerificationAllowSubdomainFromConfiguration proves that the Draft-09
// Section 11.1 choice defaults to the conforming upward match, accepts YAML,
// environment placeholders, and environment overrides, rejects malformed
// booleans, and fails closed on a missing placeholder variable.
func TestVerificationAllowSubdomainFromConfiguration(t *testing.T) {
	snapshot, err := Load([]byte(redisYAML()), FlagValues{})
	if err != nil || !snapshot.Verification().Valid() || !snapshot.Verification().AllowSubdomainFrom() {
		t.Fatalf("allow_subdomain_from must default to true: error=%v", err)
	}
	document := redisYAML() + "verification:\n  domain_policy:\n    allow_subdomain_from: false\n"
	snapshot, err = Load([]byte(document), FlagValues{})
	if err != nil || snapshot.Verification().AllowSubdomainFrom() {
		t.Fatalf("explicit false was not applied: error=%v", err)
	}
	placeholder := redisYAML() + "verification:\n  domain_policy:\n    allow_subdomain_from: ${TEST_ALLOW_SUBDOMAIN_FROM}\n"
	t.Setenv("TEST_ALLOW_SUBDOMAIN_FROM", "false")
	snapshot, err = Load([]byte(placeholder), FlagValues{})
	if err != nil || snapshot.Verification().AllowSubdomainFrom() {
		t.Fatalf("placeholder value was not applied: error=%v", err)
	}
	missing := redisYAML() + "verification:\n  domain_policy:\n    allow_subdomain_from: ${TEST_MISSING_ALLOW_SUBDOMAIN_FROM}\n"
	if _, err := Load([]byte(missing), FlagValues{}); CodeOf(err) != CodeInvalidPlaceholder {
		t.Fatalf("missing placeholder variable error = %v", err)
	}
	t.Setenv("DKIM2D_VERIFICATION_DOMAIN_POLICY_ALLOW_SUBDOMAIN_FROM", "true")
	snapshot, err = Load([]byte(document), FlagValues{})
	if err != nil || !snapshot.Verification().AllowSubdomainFrom() {
		t.Fatalf("environment override was not applied: error=%v", err)
	}
	t.Setenv("DKIM2D_VERIFICATION_DOMAIN_POLICY_ALLOW_SUBDOMAIN_FROM", "maybe")
	if _, err := Load([]byte(document), FlagValues{}); err == nil {
		t.Fatal("malformed boolean accepted")
	}
	if (VerificationConfig{}).AllowSubdomainFrom() || snapshot.Verification().String() != typedConfigRedactedText {
		t.Fatal("zero view or formatting is not fail-closed")
	}
}
