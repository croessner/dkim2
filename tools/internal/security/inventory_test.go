package security

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestRepositoryInventoryMatchesEveryFirstPartyFuzzTarget freezes drift closure.
func TestRepositoryInventoryMatchesEveryFirstPartyFuzzTarget(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	if err := ValidateInventory(root); err != nil {
		t.Fatalf("ValidateInventory() error = %v", err)
	}
	if got := len(Targets()); got != 93 {
		t.Fatalf("target count = %d, want 93", got)
	}
	if got := len(ResourceOwners()); got != 17 {
		t.Fatalf("resource owner count = %d, want 17", got)
	}
}

// TestTargetInventoryRejectsDuplicateMissingAndCommandSelectingEntries protects runner closure.
func TestTargetInventoryRejectsDuplicateMissingAndCommandSelectingEntries(t *testing.T) {
	valid := Targets()
	if err := validateTargetRecords(valid); err != nil {
		t.Fatal(err)
	}
	duplicate := append([]FuzzTarget(nil), valid...)
	duplicate = append(duplicate, valid[len(valid)-1])
	if err := validateTargetRecords(duplicate); err == nil {
		t.Fatal("duplicate target was accepted")
	}
	malformed := append([]FuzzTarget(nil), valid...)
	malformed[0].Function = "FuzzSafe|TestUnexpected"
	if err := validateTargetRecords(malformed); err == nil {
		t.Fatal("command-selecting function was accepted")
	}
	missing := append([]FuzzTarget(nil), valid...)
	missing = missing[:0]
	if err := validateTargetRecords(missing); err == nil {
		t.Fatal("empty target inventory was accepted")
	}
}

// TestDiscoveryIgnoresVendorAndRejectsUnexpectedFirstPartyTargets proves independent scanning.
func TestDiscoveryIgnoresVendorAndRejectsUnexpectedFirstPartyTargets(t *testing.T) {
	root := t.TempDir()
	writeSource := func(relative, function string) {
		t.Helper()
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		input := "package fixture\n\nfunc " + function + "(f interface{}) {}\n"
		if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeSource("lib/first_test.go", "FuzzFirst")
	writeSource("vendor/example/vendor_test.go", "FuzzIgnored")
	discovered, err := discoverFuzzTargets(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(discovered) != 1 || discovered[0].Function != "FuzzFirst" {
		t.Fatalf("discovered = %#v", discovered)
	}
}

// TestProofDiscoveryBindsTheExactSourcePath prevents same-name tests from masking drift.
func TestProofDiscoveryBindsTheExactSourcePath(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "lib", "owner_test.go")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	input := "package fixture\n\nfunc TestExactBoundary(t interface{}) {}\n"
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	functions, err := discoverTestFunctions(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := functions["lib/owner_test.go#TestExactBoundary"]; !ok {
		t.Fatalf("proof index = %#v", functions)
	}
	if _, ok := functions["lib/other_test.go#TestExactBoundary"]; ok {
		t.Fatal("same-name proof was accepted at the wrong source path")
	}
}

// TestInventoryMetadataIsClosedAndSecretSafe protects evidence vocabulary.
func TestInventoryMetadataIsClosedAndSecretSafe(t *testing.T) {
	for _, current := range Targets() {
		joined := strings.Join([]string{
			current.ID,
			current.Module,
			current.Package,
			current.Function,
			current.Source,
			current.Boundary,
			current.Class,
			current.SeedSource,
			strings.Join(current.Properties, " "),
			current.BoundingStrategy,
			current.ExternalIO,
			current.RegressionOwner,
			current.Duration,
		}, " ")
		for _, forbidden := range []string{
			"PRIVATE KEY",
			"Bearer ",
			"password=",
			"--exec",
			"http://",
			"https://",
		} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("target %q contains forbidden metadata class", current.ID)
			}
		}
		if slices.Contains(current.Properties, "") {
			t.Fatalf("target %q has an empty property", current.ID)
		}
	}
}

// TestResourceInventoryRejectsDuplicateDimensionAndOwner protects one-source ownership.
func TestResourceInventoryRejectsDuplicateDimensionAndOwner(t *testing.T) {
	owners := ResourceOwners()
	duplicateOwner := append([]ResourceOwner(nil), owners...)
	duplicateOwner = append(duplicateOwner, owners[len(owners)-1])
	if err := validateResourceOwners(duplicateOwner); err == nil {
		t.Fatal("duplicate owner was accepted")
	}
	duplicateDimension := append([]ResourceOwner(nil), owners...)
	duplicateDimension[0].Dimensions = []string{"bytes", "bytes"}
	if err := validateResourceOwners(duplicateDimension); err == nil {
		t.Fatal("duplicate dimension was accepted")
	}
}
