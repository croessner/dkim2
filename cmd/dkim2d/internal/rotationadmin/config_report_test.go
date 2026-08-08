package rotationadmin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadConfigRequiresFiveDistinctProtectedRoles freezes the purge and closer authority boundaries.
func TestLoadConfigRequiresFiveDistinctProtectedRoles(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(directory, 0700) != nil {
		t.Fatal("protect test directory")
	}
	secretPaths := make([]string, 5)
	for index := range secretPaths {
		secretPaths[index] = filepath.Join(directory, "role-"+string(rune('a'+index)))
		if err := os.WriteFile(secretPaths[index], []byte("secret"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(directory, "rotation.yaml")
	document := "version: dkim2-rotation-admin-v1\nauthority_id: aaaaaaaaaaaaaaaaaaaaaaaaae\nbackend: ldap\ndeadline: 30s\nlimits:\n  max_work_items: 16\n  max_dns_batch_records: 4\n  max_dns_batches: 4\nroles:\n  snapshot:\n    name: snapshot\n    secret_file: " + secretPaths[0] + "\n  staging:\n    name: staging\n    secret_file: " + secretPaths[1] + "\n  activation:\n    name: activation\n    secret_file: " + secretPaths[2] + "\n  purge:\n    name: purge\n    secret_file: " + secretPaths[3] + "\n  closer:\n    name: closer\n    secret_file: " + secretPaths[4] + "\n"
	if err := os.WriteFile(configPath, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal("five distinct protected roles rejected")
	}
	defer loaded.Close() //nolint:errcheck // Test cleanup cannot affect the assertion.
	if loaded.Backend() != "ldap" || loaded.Limits().MaxWorkItems != 16 {
		t.Fatal("configuration facts drifted")
	}
	if err := os.WriteFile(configPath, []byte(strings.Replace(document, "name: purge", "name: staging", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if duplicate, duplicateErr := LoadConfig(configPath); duplicateErr == nil || duplicate != nil {
		t.Fatal("duplicate authority role accepted")
	}
}

// TestEncodeCommandReportRejectsIdentityMarkers freezes report privacy and stable output shape.
func TestEncodeCommandReportRejectsIdentityMarkers(t *testing.T) {
	report := CommandReport{Command: "status", State: StatePrepared, Backend: "ldap", WorkCount: 4, RecordCount: 8, BatchCount: 2, ResultClass: "success"}
	for _, machine := range []bool{false, true} {
		encoded, err := EncodeCommandReport(report, machine)
		if err != nil || len(encoded) == 0 {
			t.Fatal("safe report rejected")
		}
		for _, toxic := range []string{"example.test", "cn=", "password", "private", "digest"} {
			if strings.Contains(string(encoded), toxic) {
				t.Fatalf("report exposed toxic marker %q", toxic)
			}
		}
	}
	if encoded, err := EncodeCommandReport(CommandReport{Command: "status", Backend: "ldap", ResultClass: "example.test"}, true); err == nil || encoded != nil {
		t.Fatal("identity-shaped result class accepted")
	}
}
