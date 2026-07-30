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
	if len(attributes) != 17 || len(classes) != 5 {
		t.Fatal("unexpected LDAP allocation count")
	}
	expectedAttributes := []string{
		attrSchemaVersion, attrGeneration, attrDatasetState,
		attrHandleID, attrProfileID, attrSigningDomain,
		attrRecordStatus, attrNotBefore, attrNotAfter,
		attrAlgorithm, attrSelector, attrPublicSPKI,
		attrTenantID, attrProfileUse, attrRollout,
		attrCompatibility, attrFeedbackRouteID,
	}
	for index, match := range attributes {
		if match[1] != strconv.Itoa(index+1) || match[2] != expectedAttributes[index] {
			t.Fatal("LDAP attribute allocation changed")
		}
	}
	expectedClasses := []string{
		"dkim2Dataset", "dkim2Handle", "dkim2Profile", "dkim2Credential", "dkim2Policy",
	}
	for index, match := range classes {
		if match[1] != strconv.Itoa(index+1) || match[2] != expectedClasses[index] {
			t.Fatal("LDAP object-class allocation changed")
		}
	}
	if strings.Count(text, " SINGLE-VALUE )") != 17 {
		t.Fatal("every allocated attribute must be single-valued")
	}
}
