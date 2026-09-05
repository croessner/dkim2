package config

import (
	"strings"
	"testing"
)

// verificationLocalityYAML returns one LDAP-backed document that carries only
// the process capability and the received-DSN locality tenant.
func verificationLocalityYAML() string {
	return removeYAMLField(ldapSigningYAML(), "  sign_capability_file:") +
		"process:\n  default_tenant: " + testTenant + "\n"
}

// propagationOnlyYAML returns one LDAP-backed document whose only route
// capability is the propagation capability over the memory replay backend.
func propagationOnlyYAML() string {
	document := removeYAMLField(ldapSigningYAML(), "  sign_capability_file:")
	document = strings.Replace(
		document,
		"  capability_file: /secure/"+testGeneration+"/capability\n",
		"  capability_file: /secure/"+testGeneration+"/capability\n"+
			"  dsn_propagate_capability_file: /secure/"+testGeneration+"/dsn-propagate-capability\n",
		1,
	)
	return strings.Replace(
		document,
		"replay:\n  backend: disabled\n",
		"replay:\n  backend: memory\n  hmac_key_file: /secure/"+testGeneration+"/hmac\n  epoch: 1\n",
		1,
	)
}

// TestLoadAcceptsDatasourceForLocalityWithoutSigningRoutes proves the three
// valid datasource shapes: a verification-only daemon that resolves
// received-DSN locality through the datasource without any signing route, a
// propagation-only daemon whose sole route capability is the propagation
// capability, and the full signing daemon. A datasource with neither a route
// capability nor a locality tenant stays refused, because nothing would
// consume it.
func TestLoadAcceptsDatasourceForLocalityWithoutSigningRoutes(t *testing.T) {
	clearStableEnvironment(t)
	locality, err := Load([]byte(verificationLocalityYAML()), FlagValues{})
	if err != nil {
		t.Fatalf("verification-only locality document returned code %s", CodeOf(err))
	}
	if !locality.Signing().Enabled() || locality.ProcessDefaultTenant() != testTenant ||
		locality.Server().SigningRouteEnabled() || locality.Server().AnyRouteCapability() ||
		!locality.SigningDatasourceConsumed() {
		t.Fatal("verification-only locality document did not keep the datasource without a route")
	}
	propagation, err := Load([]byte(propagationOnlyYAML()), FlagValues{})
	if err != nil {
		t.Fatalf("propagation-only document returned code %s", CodeOf(err))
	}
	if propagation.Server().SigningRouteEnabled() ||
		!propagation.Server().DSNPropagateEnabled() ||
		!propagation.Server().AnyRouteCapability() ||
		!propagation.SigningDatasourceConsumed() {
		t.Fatal("propagation-only document did not stand alone as a route capability")
	}
	full, err := Load([]byte(ldapSigningYAML()), FlagValues{})
	if err != nil || !full.Server().SigningRouteEnabled() || !full.SigningDatasourceConsumed() {
		t.Fatalf("full signing document returned code %s", CodeOf(err))
	}
	orphan := removeYAMLField(ldapSigningYAML(), "  sign_capability_file:")
	if _, err := Load([]byte(orphan), FlagValues{}); CodeOf(err) != CodeInvalidMatrix {
		t.Fatalf("datasource without any consumer returned code %s", CodeOf(err))
	}
}
