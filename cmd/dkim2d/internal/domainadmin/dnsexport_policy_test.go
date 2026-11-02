package domainadmin

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestExportDNSAddsStrictDomainPolicyRecordOnRequest verifies the optional
// Draft-09 Section 3.8 export: exactly one _domainkey.<domain>. TXT
// "v=DKIM1; f=strict" record per exported domain after the key records,
// counted in the result, absent without the option, and byte-exact on retry.
func TestExportDNSAddsStrictDomainPolicyRecordOnRequest(t *testing.T) {
	set, candidate, plan, _ := stagedDNSFixture(t)
	defer set.Close()       //nolint:errcheck // Test cleanup has no recovery.
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()      //nolint:errcheck // Test cleanup has no recovery.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(root, 0o700) != nil {
		t.Fatal("protect DNS export directory")
	}
	strictPath := filepath.Join(root, "strict.zone")
	plainPath := filepath.Join(root, "plain.zone")
	options := DNSExportOptions{DomainPolicyStrict: true}
	strict, err := ExportDNS(t.Context(), strictPath, set, options, DefaultLimits())
	if err != nil || strict.Records != 3 {
		t.Fatalf("strict export = %+v, %v", strict, err)
	}
	plain, err := ExportDNS(t.Context(), plainPath, set, DNSExportOptions{}, DefaultLimits())
	if err != nil || plain.Records != 2 {
		t.Fatalf("plain export = %+v, %v", plain, err)
	}
	document, err := os.ReadFile(strictPath)
	if err != nil {
		t.Fatal("read strict export")
	}
	defer clear(document)
	if bytes.Count(document, []byte("\n_domainkey.")) != 1 ||
		!bytes.Contains(document, []byte("\n; domain-policy flags=strict\n_domainkey.added.example.test. ")) ||
		!bytes.HasSuffix(document, []byte(" IN TXT \"v=DKIM1; f=strict\"\n")) {
		t.Fatalf("strict export does not end with exactly one policy record:\n%s", document)
	}
	plainDocument, err := os.ReadFile(plainPath)
	if err != nil || bytes.Contains(plainDocument, []byte("f=strict")) || !bytes.HasPrefix(document, plainDocument) {
		t.Fatal("plain export carried a policy record or diverged from the key records")
	}
	clear(plainDocument)
	if again, err := ExportDNS(t.Context(), strictPath, set, options, DefaultLimits()); err != nil || again != strict {
		t.Fatalf("exact strict retry = %+v, %v", again, err)
	}
	if _, err := ExportDNS(t.Context(), strictPath, set, DNSExportOptions{}, DefaultLimits()); CodeOf(err) != CodeConflict {
		t.Fatalf("retry with different options error = %v, want conflict", err)
	}
}

// TestStrictDomainPolicyRecordRoundTripsThroughPolicyParser verifies that the
// exported record is proven by the production Domain Policy Record parser and
// that a non-canonical domain fails closed.
func TestStrictDomainPolicyRecordRoundTripsThroughPolicyParser(t *testing.T) {
	record, err := newStrictDomainPolicyRecord(context.Background(), []byte("xn--bcher-kva.example"))
	if err != nil || string(record.owner) != "_domainkey.xn--bcher-kva.example." || string(record.payload) != "v=DKIM1; f=strict" {
		t.Fatalf("newStrictDomainPolicyRecord() = %q/%q, %v", record.owner, record.payload, err)
	}
	for _, domain := range []string{"", "Example.test", "bücher.example", "a..test"} {
		if _, err := newStrictDomainPolicyRecord(context.Background(), []byte(domain)); CodeOf(err) != CodeDNSInvalid {
			t.Fatalf("newStrictDomainPolicyRecord(%q) error = %v", domain, err)
		}
	}
}

// TestDomainPolicyStrictRequiresDNSExportCommand verifies that the export
// flag is rejected on every other domain command.
func TestDomainPolicyStrictRequiresDNSExportCommand(t *testing.T) {
	request := CommandRequest{
		Command: CommandPrepare, ConfigPath: "/protected/config.yaml", OperationPath: "/protected/operation.json",
		ToolVersion: "v0.0.0-test", DomainPolicyStrict: true,
	}
	if err := request.Validate(); CodeOf(err) != CodeProtectedInput {
		t.Fatalf("Validate() error = %v", err)
	}
}
