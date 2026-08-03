package datasourceadmin

import "testing"

// TestIdentityProjectionTracksExactPolicyIdentity freezes domain-onboarding collision scope.
func TestIdentityProjectionTracksExactPolicyIdentity(t *testing.T) {
	snapshot, err := NewSnapshot(SchemaVersionV2, 1, validRows(t, 1))
	if err != nil {
		t.Fatal("construct identity projection snapshot")
	}
	defer snapshot.Close() //nolint:errcheck // Test cleanup has no recovery action.
	projection, err := snapshot.IdentityProjection(t.Context())
	if err != nil {
		t.Fatal("construct identity projection")
	}
	defer projection.Close() //nolint:errcheck // Test cleanup has no recovery action.
	if !projection.PolicyUsed(testTenant, testDomain, profileUseOriginator) ||
		projection.PolicyUsed("other-tenant", testDomain, profileUseOriginator) ||
		projection.PolicyUsed(testTenant, "other.example.test", profileUseOriginator) ||
		projection.PolicyUsed(testTenant, testDomain, "other-use") {
		t.Fatal("policy collision projection did not preserve the exact tuple")
	}
}
