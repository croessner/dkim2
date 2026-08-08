package rotationadmin

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/provider"
)

// TestJournalRequiresDeterministicCompleteFreshDNSProgress freezes the activation gate.
func TestJournalRequiresDeterministicCompleteFreshDNSProgress(t *testing.T) {
	plan, prepared := preparedCampaign(t, 3)
	defer plan.Close()     //nolint:errcheck // Test cleanup has no recovery.
	defer prepared.Close() //nolint:errcheck // Test cleanup has no recovery.

	before := mustCandidateDigest(t, prepared)
	batches, err := BuildDNSBatches(t.Context(), prepared, 1, DefaultLimits())
	if err != nil || len(batches) != 3 {
		t.Fatal("deterministic DNS batches rejected")
	}
	repeated, err := BuildDNSBatches(t.Context(), prepared, 1, DefaultLimits())
	if err != nil || len(repeated) != len(batches) || !before.Equal(mustCandidateDigest(t, prepared)) {
		t.Fatal("batch retry changed candidate identity")
	}
	for index := range batches {
		if batches[index].Ordinal != repeated[index].Ordinal || !batches[index].Digest().Equal(repeated[index].Digest()) {
			t.Fatal("batch retry changed boundaries or commitment")
		}
	}

	journal, err := NewJournal(plan)
	if err != nil || journal.BeginPreparing() != nil || journal.RecordPrepared(prepared) != nil ||
		journal.RecordStaged(before) != nil {
		t.Fatal("campaign did not reach exact staged state")
	}
	now := time.Unix(2_000_000_000, 0).UTC()
	if err := journal.RecordBatchProof(batches[1], now, "dns-v1"); err == nil {
		t.Fatal("reordered batch advanced progress")
	}
	if err := journal.RecordBatchProof(batches[0], now, "dns-v1"); err != nil {
		t.Fatal("first exact batch rejected")
	}
	if err := journal.RecordBatchProof(batches[0], now, "dns-v1"); err == nil {
		t.Fatal("duplicate batch advanced progress")
	}
	for _, batch := range batches[1:] {
		if err := journal.RecordBatchProof(batch, now, "dns-v1"); err != nil {
			t.Fatal("contiguous batch rejected")
		}
	}
	if journal.State() != StateDNSComplete || journal.BeginActivation(now.Add(6*time.Minute), 5*time.Minute) == nil {
		t.Fatal("missing or stale proof authorized activation")
	}
	if journal.BeginActivation(now.Add(4*time.Minute), 5*time.Minute) != nil || journal.RecordActivated() != nil ||
		journal.State() != StateActivated {
		t.Fatal("fresh complete proof did not authorize one activation")
	}
	if journal.RecordActivated() == nil {
		t.Fatal("activation advanced twice")
	}
}

// TestJournalLegacyActivatingWithoutTimestampRequiresReconciliation preserves
// the v1 read contract without granting legacy crash journals retry authority.
func TestJournalLegacyActivatingWithoutTimestampRequiresReconciliation(t *testing.T) {
	plan, prepared := preparedCampaign(t, 1)
	defer plan.Close()     //nolint:errcheck
	defer prepared.Close() //nolint:errcheck
	journal, _ := NewJournal(plan)
	_ = journal.BeginPreparing()
	_ = journal.RecordPrepared(prepared)
	_ = journal.RecordStaged(mustCandidateDigest(t, prepared))
	now := time.Unix(2_000_000_000, 0).UTC()
	batches, _ := BuildDNSBatches(t.Context(), prepared, DefaultLimits().MaxDNSBatchRecords, DefaultLimits())
	for _, batch := range batches {
		_ = journal.RecordBatchProof(batch, now, "dns-v1")
	}
	if journal.BeginActivation(now, time.Minute) != nil {
		t.Fatal("activation fixture rejected")
	}
	document, err := encodeJournal(journal, 1)
	if err != nil {
		t.Fatal("journal encode rejected")
	}
	marker := []byte(`,"activation_unix":`)
	start := bytes.Index(document, marker)
	end := -1
	if start >= 0 {
		if relative := bytes.IndexByte(document[start+len(marker):], ','); relative >= 0 {
			end = start + len(marker) + relative
		}
	}
	if start < 0 || end < 0 {
		t.Fatal("activation timestamp wire field missing")
	}
	legacy := append(append([]byte(nil), document[:start]...), document[end:]...)
	decoded, decodeErr := decodeJournal(legacy)
	if decodeErr != nil || decoded == nil || decoded.State() != StateReconcileRequired || decoded.failureClass != "legacy_activation_timestamp" {
		t.Fatal("legacy activating journal was rejected or gained retry authority")
	}
}

// TestJournalProtectedStoreRoundTripAndConflict freezes resume and mutual exclusion.
func TestJournalProtectedStoreRoundTripAndConflict(t *testing.T) {
	plan, prepared := preparedCampaign(t, 1)
	defer plan.Close()     //nolint:errcheck // Test cleanup has no recovery.
	defer prepared.Close() //nolint:errcheck // Test cleanup has no recovery.
	journal, err := NewJournal(plan)
	if err != nil {
		t.Fatal("journal rejected")
	}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(directory, 0o700) != nil {
		t.Fatal("protect journal directory")
	}
	path := filepath.Join(directory, "campaign.json")
	store, err := OpenJournalStore(t.Context(), path)
	if err != nil {
		t.Fatal("protected store rejected")
	}
	if second, secondErr := OpenJournalStore(t.Context(), path); secondErr == nil || second != nil {
		t.Fatal("second campaign bypassed the stable sibling lock")
	}
	if loaded, exists, loadErr := store.Load(t.Context()); loadErr != nil || exists || loaded != nil {
		t.Fatal("empty journal load rejected")
	}
	if store.Save(t.Context(), journal) != nil || journal.BeginPreparing() != nil || store.Save(t.Context(), journal) != nil {
		t.Fatal("journal CAS progression rejected")
	}
	if store.Close() != nil {
		t.Fatal("journal store close rejected")
	}

	reopened, err := OpenJournalStore(t.Context(), path)
	if err != nil {
		t.Fatal("protected journal resume rejected")
	}
	defer reopened.Close() //nolint:errcheck // Test cleanup has no recovery.
	resumed, exists, err := reopened.Load(t.Context())
	if err != nil || !exists || resumed.State() != StatePreparing || !journal.Equivalent(resumed) {
		t.Fatal("exact journal revision did not resume")
	}
	if resumed.RequireReconciliation("ambiguous_save") != nil || resumed.BeginPreparing() == nil {
		t.Fatal("reconciliation state permitted blind retry")
	}
}

// TestJournalStrictDecodeRejectsDuplicateUnknownAndTamperedEvidence freezes protected input parsing.
func TestJournalStrictDecodeRejectsDuplicateUnknownAndTamperedEvidence(t *testing.T) {
	plan, prepared := preparedCampaign(t, 1)
	defer plan.Close()     //nolint:errcheck // Test cleanup has no recovery.
	defer prepared.Close() //nolint:errcheck // Test cleanup has no recovery.
	journal, _ := NewJournal(plan)
	_ = journal.BeginPreparing()
	_ = journal.RecordPrepared(prepared)
	document, err := encodeJournal(journal, 1)
	if err != nil {
		t.Fatal("journal encode rejected")
	}
	defer clear(document)
	duplicate := bytes.Replace(document, []byte(`"version":`), []byte(`"version":"dkim2-rotation-campaign-journal-v1","version":`), 1)
	if decoded, decodeErr := decodeJournal(duplicate); decodeErr == nil || decoded != nil {
		t.Fatal("duplicate protected key accepted")
	}
	unknown := bytes.Replace(document, []byte(`"revision":1`), []byte(`"revision":1,"unknown":true`), 1)
	if decoded, decodeErr := decodeJournal(unknown); decodeErr == nil || decoded != nil {
		t.Fatal("unknown protected field accepted")
	}
	invalidMode := strings.Replace(string(document), `"mode":"normal"`, `"mode":"future"`, 1)
	if decoded, decodeErr := decodeJournal([]byte(invalidMode)); decodeErr == nil || decoded != nil {
		t.Fatal("unknown mode accepted")
	}
}

// TestBuildDNSBatchesRequiresParserValidCandidateRecords freezes DNS-04 round-trip validation.
func TestBuildDNSBatchesRequiresParserValidCandidateRecords(t *testing.T) {
	plan, prepared := preparedCampaign(t, 1)
	defer plan.Close()     //nolint:errcheck // Test cleanup has no recovery.
	defer prepared.Close() //nolint:errcheck // Test cleanup has no recovery.
	prepared.mu.Lock()
	prepared.dnsInputs[0].publicSPKI[0] ^= 0xff
	prepared.mu.Unlock()
	if batches, err := BuildDNSBatches(t.Context(), prepared, 1, DefaultLimits()); err == nil || batches != nil {
		t.Fatal("candidate record bypassed the production DNS parser")
	}
}

// preparedCampaign constructs one immutable normal campaign fixture.
func preparedCampaign(t *testing.T, count int) (*Plan, *Prepared) {
	t.Helper()
	source := campaignSource(t, count)
	defer source.Close() //nolint:errcheck // Fixture source transfers no ownership.
	intent, err := NewIntent(admincontract.ModeNormal, campaignOperation, "")
	if err != nil {
		t.Fatal("intent fixture rejected")
	}
	plan, err := Freeze(t.Context(), source, 8, intent, DefaultLimits())
	if err != nil {
		t.Fatal("plan fixture rejected")
	}
	preparer, err := NewPreparer(&deterministicKeyFactory{}, provider.ProductionLimits())
	if err != nil {
		_ = plan.Close()
		t.Fatal("preparer fixture rejected")
	}
	prepared, err := preparer.Prepare(t.Context(), plan, source)
	if err != nil {
		_ = plan.Close()
		t.Fatalf("prepared fixture rejected: %v", err)
	}
	return plan, prepared
}
