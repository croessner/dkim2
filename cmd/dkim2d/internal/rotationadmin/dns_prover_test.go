package rotationadmin

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// TestDNSBatchProverExportsWithinProtectedDocumentBound proves the campaign
// exporter uses the central owner-only document size fence.
func TestDNSBatchProverExportsWithinProtectedDocumentBound(t *testing.T) {
	plan, prepared := preparedCampaign(t, 1)
	defer plan.Close()     //nolint:errcheck
	defer prepared.Close() //nolint:errcheck
	policy := datasourceadmin.DNSPolicy{
		ResolverClass:        canonicalRecursiveResolver,
		ResolverEndpoints:    []string{"127.0.0.1:53"},
		ExportTTLSeconds:     300,
		ProofLifetimeSeconds: 60,
	}
	prover, err := NewDNSBatchProver(policy, time.Second)
	if err != nil {
		t.Fatal("construct DNS batch prover")
	}
	batches, err := BuildDNSBatches(t.Context(), prepared, 2, DefaultLimits())
	if err != nil || len(batches) != 1 {
		t.Fatal("build one complete DNS batch")
	}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(directory, 0o700) != nil {
		t.Fatal("protect export directory")
	}
	path := filepath.Join(directory, "dns-batch.txt")
	result, err := prover.ExportBatchDNS(t.Context(), path, prepared, batches[0])
	if err != nil || result.Records != 1 {
		t.Fatalf("export campaign DNS batch: err=%v records=%d bytes=%d", err, result.Records, result.Bytes)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 || info.Size() == 0 {
		t.Fatal("export is not one nonempty owner-only document")
	}
}
