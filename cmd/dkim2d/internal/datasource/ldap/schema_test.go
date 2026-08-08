package ldap

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestSchemaOwnsExactPermanentAllocation proves the schema has no OID gaps,
// aliases, or extra DKIM2 definitions.
func TestSchemaOwnsExactPermanentAllocation(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "..", "..", "..", "contrib", "schema", "ldap", "rnsdkim2.schema")
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read committed LDAP schema")
	}
	text := string(document)
	attributePattern := regexp.MustCompile(`attributetype \( RNSDKIM2at:(\d+) NAME '([^']+)'`)
	classPattern := regexp.MustCompile(`objectclass \( RNSDKIM2oc:(\d+) NAME '([^']+)'`)
	attributes := attributePattern.FindAllStringSubmatch(text, -1)
	classes := classPattern.FindAllStringSubmatch(text, -1)
	if len(attributes) != 29 || len(classes) != 9 {
		t.Fatal("unexpected LDAP allocation count")
	}
	expectedAttributes := []string{
		attrSchemaVersion, attrGeneration, attrDatasetState,
		attrHandleID, attrProfileID, attrSigningDomain,
		attrRecordStatus, attrNotBefore, attrNotAfter,
		attrAlgorithm, attrSelector, attrPublicSPKI,
		attrTenantID, attrProfileUse, attrRollout,
		attrCompatibility, attrFeedbackRouteID, attrPrivatePKCS8,
		"dkim2CandidateDigest", "dkim2OperationID", "dkim2WasActive",
		"dkim2AdminLockOwner", "dkim2AdminRevision", "dkim2TerminalState",
		"dkim2TerminalReason", "dkim2TerminalTime", "dkim2SourceGeneration", "dkim2CurrentGeneration", "dkim2SourceSchema",
	}
	for index, match := range attributes {
		if match[1] != strconv.Itoa(index+1) || match[2] != expectedAttributes[index] {
			t.Fatal("LDAP attribute allocation changed")
		}
	}
	expectedClasses := []string{
		datasetObjectClass, handleObjectClass, profileObjectClass, credentialObjectClass, policyObjectClass,
		keyMaterialObjectClass, administrativeMetadataObjectClass, administrationLockObjectClass, "dkim2CampaignTerminal",
	}
	for index, match := range classes {
		if match[1] != strconv.Itoa(index+1) || match[2] != expectedClasses[index] {
			t.Fatal("LDAP object-class allocation changed")
		}
	}
	if strings.Count(text, " SINGLE-VALUE )") != 29 {
		t.Fatal("every allocated attribute must be single-valued")
	}
}

// TestOperatorLDAPBundleMatchesNativeCustody proves the deployable v2/v3 layout,
// role-separated ACL, operator reference, and architecture stay aligned.
func TestOperatorLDAPBundleMatchesNativeCustody(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "..", "..", "..")
	read := func(relative ...string) string {
		t.Helper()
		document, err := os.ReadFile(filepath.Join(append([]string{root}, relative...)...))
		if err != nil {
			t.Fatal("read committed LDAP operator artifact")
		}
		return string(document)
	}

	layout := read("contrib", "schema", "ldap", "layout.ldif")
	for _, forbidden := range []string{
		"dkim2-datasource-v1", "dn: cn=current,", "objectClass: dkim2KeyMaterial",
		"dkim2PrivateKeyPKCS8:",
	} {
		if strings.Contains(layout, forbidden) {
			t.Fatal("empty LDAP layout contains an active or secret-bearing generation")
		}
	}
	for _, required := range []string{
		"dn: ou=dkim2,dc=example,dc=test",
		"dn: ou=generations,ou=dkim2,dc=example,dc=test",
		"Do not pre-create cn=current or a generation",
		"objectClass: dkim2AdministrationLock",
		"dkim2AdminRevision: 1",
	} {
		if !strings.Contains(layout, required) {
			t.Fatal("empty LDAP layout is missing its v2 bootstrap contract")
		}
	}
	indexes := read("contrib", "schema", "ldap", "indexes.conf")
	for _, required := range []string{
		"dkim2CandidateDigest,dkim2OperationID,dkim2WasActive eq",
		"dkim2AdminLockOwner,dkim2AdminRevision eq",
	} {
		if !strings.Contains(indexes, required) {
			t.Fatal("LDAP index example is missing v3 administration metadata")
		}
	}

	acl := read("contrib", "schema", "ldap", "acl.conf")
	if strings.Contains(acl, "DKIMKey") {
		t.Fatal("native LDAP ACL contains a legacy OpenDKIM attribute")
	}
	privateRule := strings.Index(acl, "attrs=dkim2PrivateKeyPKCS8")
	publicRule := strings.Index(acl, "attrs=entry,objectClass,cn,ou")
	if privateRule < 0 || publicRule < 0 || privateRule >= publicRule {
		t.Fatal("LDAP private-key ACL does not precede the public datasource rule")
	}
	for _, required := range []string{
		`cn=dkim2-runtime,ou=services,dc=example,dc=test" read`,
		`cn=dkim2-snapshot,ou=services,dc=example,dc=test" read`,
		`cn=dkim2-activator,ou=services,dc=example,dc=test" read`,
		`by set.expand="(user & [cn=dkim2-stager,ou=services,dc=example,dc=test])`,
		"by * none",
	} {
		if !strings.Contains(acl[privateRule:publicRule], required) {
			t.Fatal("LDAP private-key ACL is missing a closed authority rule")
		}
	}
	if strings.Contains(acl, `cn=dkim2-publisher,ou=services,dc=example,dc=test" write`) ||
		strings.Contains(acl, `cn=dkim2-stager,ou=services,dc=example,dc=test" write`) {
		t.Fatal("LDAP publisher ACL uses a broad write level")
	}
	for _, required := range []string{
		`access to dn.exact="ou=generations,ou=dkim2,dc=example,dc=test"`,
		"attrs=children",
		`cn=dkim2-stager,ou=services,dc=example,dc=test" =dcsra`,
		"attrs=dkim2AdminLockOwner,dkim2AdminRevision",
		"attrs=dkim2CandidateDigest,dkim2OperationID,dkim2SourceGeneration",
		"attrs=dkim2WasActive",
		`cn=dkim2-purger,ou=services,dc=example,dc=test]) + ([cn=current,ou=dkim2,dc=example,dc=test]/dkim2Generation & [$2])" none`,
		`dkim2DatasetState & [committed])" =dcsr`,
	} {
		if !strings.Contains(acl, required) {
			t.Fatal("LDAP bootstrap ACL is missing its bounded create/read privilege")
		}
	}

	reference := read("docs", "operator", "ldap-schema-reference.md")
	architecture := read("docs", "ARCHITECTURE.md")
	for _, required := range []string{
		"All 23 attributes are single-valued",
		"`dkim2PrivateKeyPKCS8` | `RNSDKIM2at:18`",
		"`dkim2KeyMaterial` | `RNSDKIM2oc:6`",
		"`dkim2CandidateDigest` | `RNSDKIM2at:19`",
		"`dkim2AdministrationLock` | `RNSDKIM2oc:8`",
	} {
		if !strings.Contains(reference, required) {
			t.Fatal("LDAP operator reference is missing native custody allocation")
		}
	}
	for _, required := range []string{
		"| `RNSDKIM2at:18` | `dkim2PrivateKeyPKCS8` |",
		"| `RNSDKIM2at:23` | `dkim2AdminRevision` |",
		"| `RNSDKIM2oc:6` | `dkim2KeyMaterial` |",
		"| `RNSDKIM2oc:8` | `dkim2AdministrationLock` |",
	} {
		if !strings.Contains(architecture, required) {
			t.Fatal("architecture is missing native LDAP allocation")
		}
	}
}
