package main

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestValidateRowInputsRejectsCrossRowContracts keeps build IDs bound to one ABI row.
func TestValidateRowInputsRejectsCrossRowContracts(t *testing.T) {
	t.Parallel()
	digestA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	patch := []byte("source-matched transport-filter patch\n")
	patchDigest := sha256.Sum256(patch)
	patchSHA256 := hex.EncodeToString(patchDigest[:])
	validSource := []byte("format=dkim2-exim-source-manifest-v1\nexim_version=4.99.5\nsource_sha256=" + digestA + "\nlocal_scan_header_sha256=" + digestA + "\ntransport_filter_patch_sha256=" + patchSHA256 + "\nfeature_international_mail=1\n")
	validProbe := []byte("format=dkim2-exim-probe-contract-v1\nexim_version=4.99.5\nsource_sha256=" + digestA + "\nlocal_scan_header_sha256=" + digestA + "\ntransport_filter_patch_sha256=" + patchSHA256 + "\nfeature_international_mail=1\n")
	if err := validateRowInputs("4.99.5", validSource, validProbe, patch); err != nil {
		t.Fatalf("validateRowInputs() error = %v", err)
	}
	if err := validateRowInputs("4.99.5", validSource, []byte("format=dkim2-exim-probe-contract-v1\nexim_version=4.99.1\nsource_sha256="+digestA+"\nlocal_scan_header_sha256="+digestA+"\ntransport_filter_patch_sha256="+patchSHA256+"\nfeature_international_mail=1\n"), patch); err == nil {
		t.Fatal("validateRowInputs() accepted a cross-version probe")
	}
	if err := validateRowInputs("4.99.5", validSource, []byte("format=dkim2-exim-probe-contract-v1\nexim_version=4.99.5\nsource_sha256="+digestB+"\nlocal_scan_header_sha256="+digestA+"\ntransport_filter_patch_sha256="+patchSHA256+"\nfeature_international_mail=1\n"), patch); err == nil {
		t.Fatal("validateRowInputs() accepted a cross-source probe")
	}
	if err := validateRowInputs("4.99.5", validSource, []byte("format=dkim2-exim-probe-contract-v1\nexim_version=4.99.5\nsource_sha256="+digestA+"\nlocal_scan_header_sha256="+digestB+"\ntransport_filter_patch_sha256="+patchSHA256+"\nfeature_international_mail=1\n"), patch); err == nil {
		t.Fatal("validateRowInputs() accepted a cross-header probe")
	}
	if err := validateRowInputs("4.99.5", validSource, []byte("format=dkim2-exim-probe-contract-v1\nexim_version=4.99.5\nsource_sha256="+digestA+"\nlocal_scan_header_sha256="+digestA+"\ntransport_filter_patch_sha256="+patchSHA256+"\nfeature_international_mail=0\n"), patch); err == nil {
		t.Fatal("validateRowInputs() accepted a missing feature contract")
	}
	if err := validateRowInputs("4.99.5", validSource, validProbe, []byte("different patch\n")); err == nil {
		t.Fatal("validateRowInputs() accepted a different transport-filter patch")
	}
}
