package domainadmin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/croessner/dkim2/provider"
)

// TestDNSRecordMatchesOpendkimManageMLDSA44Record proves the dkim2d DNS
// export renders exactly the "v=DKIM1; k=mldsa44; p=<raw 1312-octet key>"
// record opendkim-manage-go publishes for the same credential (no h=), that
// the zone presentation chunks it into bounded TXT strings, that the selector
// namespace for mldsa44 is distinct, and that substituting the algorithm fails.
func TestDNSRecordMatchesOpendkimManageMLDSA44Record(t *testing.T) {
	content, err := os.ReadFile("../signingstore/testdata/opendkim-manage-go-mldsa44.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		PublicSPKI string `json:"public_spki_base64"`
		DNSRecord  string `json:"dns_record"`
	}
	if err := json.Unmarshal(content, &fixture); err != nil {
		t.Fatal(err)
	}
	spki, err := base64.StdEncoding.DecodeString(fixture.PublicSPKI)
	if err != nil {
		t.Fatal(err)
	}
	record, err := newDNSRecord(context.Background(), "example.test", "d2m-selector", provider.AlgorithmMLDSA44, spki)
	if err != nil {
		t.Fatalf("newDNSRecord() error = %v", err)
	}
	if string(record.payload) != fixture.DNSRecord || strings.Contains(fixture.DNSRecord, "h=") {
		t.Fatal("dkim2d record differs from the opendkim-manage-go record")
	}
	clearDNSRecord(&record)
	zone, err := FormatCanonicalDNSRecord(context.Background(), "example.test", "d2m-selector", provider.AlgorithmMLDSA44, spki, 3600)
	if err != nil || !strings.Contains(string(zone), "k=mldsa44") {
		t.Fatalf("FormatCanonicalDNSRecord() error = %v", err)
	}
	for _, algorithm := range []provider.Algorithm{provider.AlgorithmEd25519SHA256, provider.AlgorithmRSASHA256} {
		if _, _, err := dnsKeyValue(algorithm, spki); err == nil {
			t.Fatalf("ML-DSA-44 SPKI accepted as %s", algorithm)
		}
	}
	if prefix, err := selectorPrefix(provider.AlgorithmMLDSA44); err != nil || prefix != "d2m-" {
		t.Fatalf("selectorPrefix(mldsa44) = %q, %v", prefix, err)
	}
}
