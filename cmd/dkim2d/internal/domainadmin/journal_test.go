package domainadmin

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// TestJournalRoundTripRetainsClosedProtectedEvidence freezes the sole internal codec.
func TestJournalRoundTripRetainsClosedProtectedEvidence(t *testing.T) {
	journal, plan := plannedJournalFixture(t)
	defer journal.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()    //nolint:errcheck // Test cleanup has no recovery.
	document, err := encodeJournalForTest(journal, 1)
	if err != nil {
		t.Fatal("planned journal encode rejected")
	}
	defer clear(document)
	for _, forbidden := range [][]byte{[]byte("verified"), []byte("PRIVATE KEY"), []byte("private_pkcs8"), []byte("raw_dns")} {
		if bytes.Contains(document, forbidden) {
			t.Fatal("forbidden journal field or material persisted")
		}
	}
	decoded, err := decodeJournal(document)
	if err != nil {
		t.Fatal("canonical journal round trip rejected")
	}
	defer decoded.Close() //nolint:errcheck // Test cleanup has no recovery.
	if decoded.State() != StatePlanned || decoded.Revision() != 1 || !decoded.plan.digest.Equal(plan.Digest()) {
		t.Fatal("journal round trip changed protected plan evidence")
	}
}

// TestJournalPromotionRecoveryRequiresExactProtectedIdentity freezes the ambiguous-CAS comparison.
func TestJournalPromotionRecoveryRequiresExactProtectedIdentity(t *testing.T) {
	attempted, plan := plannedJournalFixture(t)
	defer attempted.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()      //nolint:errcheck // Test cleanup has no recovery.
	document, err := encodeJournalForTest(attempted, 7)
	if err != nil {
		t.Fatal("encode attempted promotion journal")
	}
	defer clear(document)
	differentDigestBytes := bytes.Repeat([]byte{0x5a}, sha256.Size)
	differentDigest, err := datasourceadmin.ParsePlanDigest(differentDigestBytes)
	clear(differentDigestBytes)
	if err != nil || differentDigest.Equal(plan.Digest()) {
		t.Fatal("construct distinct valid promotion recovery digest")
	}
	for _, test := range []struct {
		name   string
		mutate func(*Journal)
		want   bool
	}{
		{name: "exact with different document revision", mutate: func(*Journal) {}, want: true},
		{name: "lock revision", mutate: func(journal *Journal) {
			journal.plan.lockRevision++
		}},
		{name: "operation", mutate: func(journal *Journal) {
			journal.plan.operation, _ = datasourceadmin.NewOperationBinding("aibqibiga4eascqlbqgzav3y4m")
		}},
		{name: "plan digest", mutate: func(journal *Journal) {
			journal.plan.digest = differentDigest
		}},
		{name: "authority", mutate: func(journal *Journal) {
			journal.plan.authority.AuthorityID = "foreign-authority"
		}},
		{name: "state", mutate: func(journal *Journal) {
			journal.state = StatePreparing
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			loaded, decodeErr := decodeJournal(document)
			if decodeErr != nil {
				t.Fatal("decode promotion recovery journal")
			}
			defer loaded.Close() //nolint:errcheck // Test cleanup has no recovery.
			loaded.mu.Lock()
			loaded.plan.mu.Lock()
			test.mutate(loaded)
			loaded.plan.mu.Unlock()
			loaded.mu.Unlock()
			if loaded.matchesPromotionRecovery(attempted) != test.want {
				t.Fatal("promotion recovery identity comparison returned the wrong result")
			}
		})
	}
}

// TestJournalDecodeRejectsPersistedPlanFenceSubstitution freezes exact fact invariants.
func TestJournalDecodeRejectsPersistedPlanFenceSubstitution(t *testing.T) {
	journal, plan := plannedJournalFixture(t)
	defer journal.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()    //nolint:errcheck // Test cleanup has no recovery.
	wire := journalWireForTest(t, journal, 1)
	cases := map[string]func(*journalWire){
		"zero lock revision":       func(value *journalWire) { value.AdministrationRevision = 0 },
		"candidate equals current": func(value *journalWire) { value.CandidateGeneration = value.ExpectedCurrent },
		"candidate below current":  func(value *journalWire) { value.CandidateGeneration = value.ExpectedCurrent - 1 },
		"zero candidate":           func(value *journalWire) { value.CandidateGeneration = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			changed := wire
			mutate(&changed)
			document, err := json.Marshal(changed)
			if err != nil {
				t.Fatal("marshal invalid wire fixture")
			}
			if decoded, err := decodeJournal(document); err == nil || decoded != nil {
				t.Fatal("invalid persisted plan fence accepted")
			}
		})
	}
}

// TestJournalActivationLineageBindsExactOwnerAndRevision freezes ambiguous-activation recovery identity.
func TestJournalActivationLineageBindsExactOwnerAndRevision(t *testing.T) {
	journal, plan := stagedJournalFixture(t)
	defer journal.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()    //nolint:errcheck // Test cleanup has no recovery.
	journal.mu.Lock()
	journal.state = StateDNSProven
	journal.mu.Unlock()
	completed := time.Unix(1_800_000_000, 0).UTC()
	proof := activationProofForJournal(t, journal, completed)
	defer proof.Close() //nolint:errcheck // Test cleanup has no recovery.
	lock, _ := journal.AdministrationLock()
	if err := journal.BeginActivating(proof, lock, completed, false, true); err != nil {
		t.Fatal("exact activation lineage rejected")
	}
	wire := journalWireForTest(t, journal, 1)
	if wire.Activation == nil || wire.Activation.OperationID != wire.OperationID ||
		wire.Activation.AdministrationRevision != wire.AdministrationRevision {
		t.Fatal("activation lineage did not persist the exact claim owner and revision")
	}
	otherOperation := planAuthorityID
	if otherOperation == wire.OperationID {
		otherOperation = "aibqibiga4eascqlbqgzav3y4m"
	}
	wire.Activation.OperationID = otherOperation
	document, _ := json.Marshal(wire)
	if decoded, err := decodeJournal(document); err == nil || decoded != nil {
		t.Fatal("activation lock-owner substitution accepted")
	}
	wire = journalWireForTest(t, journal, 1)
	wire.Activation.AdministrationRevision++
	document, _ = json.Marshal(wire)
	if decoded, err := decodeJournal(document); err == nil || decoded != nil {
		t.Fatal("activation lock-revision substitution accepted")
	}
}

// activationProofForJournal constructs one exact live in-process proof fixture.
func activationProofForJournal(t *testing.T, journal *Journal, completed time.Time) *DNSProof {
	t.Helper()
	journal.mu.Lock()
	defer journal.mu.Unlock()
	lifetime := time.Duration(journal.plan.dns.ProofLifetimeSeconds) * time.Second
	return &DNSProof{
		plan: journal.plan.digest, staged: journal.staged, completed: completed,
		expires: completed.Add(lifetime), path: ResolverPathSystem,
		cacheResponsibility: DNSCacheOperatorManaged, recordCount: uint32(len(journal.plan.credentials)),
	}
}

// TestJournalDuplicateDepthAndTokenLimitsFailClosed freezes bounded JSON parsing.
func TestJournalDuplicateDepthAndTokenLimitsFailClosed(t *testing.T) {
	for name, document := range map[string][]byte{
		"duplicate": []byte(`{"version":"a","version":"b"}`),
		"deep":      []byte(strings.Repeat("[", maxJournalJSONDepth+2) + "0" + strings.Repeat("]", maxJournalJSONDepth+2)),
		"tokens":    []byte("[" + strings.Repeat("0,", maxJournalJSONTokens) + "0]"),
	} {
		t.Run(name, func(t *testing.T) {
			if validateUniqueJSON(document) == nil {
				t.Fatal("abusive JSON accepted")
			}
		})
	}
}

// TestJournalStoreAtomicallyCreatesReloadsAndRejectsConcurrentOwner freezes transaction ownership.
func TestJournalStoreAtomicallyCreatesReloadsAndRejectsConcurrentOwner(t *testing.T) {
	journal, plan := plannedJournalFixture(t)
	defer journal.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()    //nolint:errcheck // Test cleanup has no recovery.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("resolve journal test directory")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal("protect journal test directory")
	}
	path := filepath.Join(root, "operation.json")
	store, err := OpenJournalStore(t.Context(), path, DefaultLimits())
	if err != nil {
		t.Fatal("open protected journal store")
	}
	if second, err := OpenJournalStore(t.Context(), path, DefaultLimits()); CodeOf(err) != CodeConflict || second != nil {
		t.Fatal("concurrent stable sibling lock owner accepted")
	}
	if loaded, exists, err := store.Load(t.Context()); err != nil || exists || loaded != nil {
		t.Fatal("absent journal did not produce an exact negative read")
	}
	if err := store.Save(t.Context(), journal); err != nil || journal.Revision() != 1 {
		t.Fatal("first atomic journal save rejected")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatal("journal final entry is not owner-only regular content")
	}
	if err := store.Close(); err != nil {
		t.Fatal("close first journal store")
	}
	reopened, err := OpenJournalStore(t.Context(), path, DefaultLimits())
	if err != nil {
		t.Fatal("reopen protected journal store")
	}
	defer reopened.Close() //nolint:errcheck // Test cleanup has no recovery.
	loaded, exists, err := reopened.Load(t.Context())
	if err != nil || !exists || loaded == nil || loaded.Revision() != 1 {
		t.Fatal("saved journal did not survive atomic reopen")
	}
	defer loaded.Close() //nolint:errcheck // Test cleanup has no recovery.
	loaded.mu.Lock()
	loaded.revision = 0
	loaded.mu.Unlock()
	if CodeOf(reopened.Save(t.Context(), loaded)) != CodeConflict {
		t.Fatal("stale journal revision replaced current content")
	}
}

// TestJournalLoadRejectsTruncatedUnknownAndDuplicateDocuments freezes corrupt-file handling.
func TestJournalLoadRejectsTruncatedUnknownAndDuplicateDocuments(t *testing.T) {
	for name, document := range map[string][]byte{
		"truncated": []byte(`{"version":`),
		"unknown":   []byte(`{"version":"unknown"}`),
		"duplicate": []byte(`{"version":"a","version":"b"}`),
	} {
		t.Run(name, func(t *testing.T) {
			root, _ := filepath.EvalSymlinks(t.TempDir())
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal("protect corrupt journal directory")
			}
			path := filepath.Join(root, "operation.json")
			if err := os.WriteFile(path, document, 0o600); err != nil {
				t.Fatal("write corrupt journal fixture")
			}
			store, err := OpenJournalStore(t.Context(), path, DefaultLimits())
			if err != nil {
				t.Fatal("open corrupt journal transaction")
			}
			defer store.Close() //nolint:errcheck // Test cleanup has no recovery.
			if loaded, exists, err := store.Load(t.Context()); CodeOf(err) != CodeProtectedInput || loaded != nil || exists {
				t.Fatal("corrupt journal did not fail closed")
			}
		})
	}
}

// plannedJournalFixture constructs one exact established-backend planned operation.
func plannedJournalFixture(t *testing.T) (*Journal, *Plan) {
	t.Helper()
	allocation, _ := allocatePlanFixture(t)
	defer allocation.Close() //nolint:errcheck // Test cleanup has no recovery.
	plan, err := NewPlan(t.Context(), datasourceadmin.BackendLDAP, planAuthority(), allocation, planDNSPolicy())
	if err != nil {
		t.Fatal("construct journal plan")
	}
	journal, err := NewJournal(plan)
	if err != nil {
		_ = plan.Close()
		t.Fatal("construct planned journal")
	}
	return journal, plan
}

// stagedJournalFixture constructs exact prepared and independently read-back evidence.
func stagedJournalFixture(t *testing.T) (*Journal, *Plan) {
	t.Helper()
	journal, plan := plannedJournalFixture(t)
	prepared, staged := candidateEvidenceFixture(t)
	if journal.BeginPreparing() != nil || journal.RecordPrepared(prepared) != nil || journal.RecordStaged(staged) != nil {
		_ = journal.Close()
		_ = plan.Close()
		t.Fatal("construct staged journal")
	}
	return journal, plan
}

// candidateEvidenceFixture constructs distinct typed phases carrying one exact content digest.
func candidateEvidenceFixture(t *testing.T) (datasourceadmin.PreparedEvidence, datasourceadmin.StagedEvidence) {
	t.Helper()
	value := bytes.Repeat([]byte{0x5a}, 32)
	prepared, err := datasourceadmin.ParsePreparedEvidence(value)
	if err != nil {
		t.Fatal("construct prepared evidence")
	}
	staged, err := datasourceadmin.ParseStagedEvidence(value)
	clear(value)
	if err != nil {
		t.Fatal("construct staged evidence")
	}
	return prepared, staged
}

// journalWireForTest encodes directly into the closed internal transfer type.
func journalWireForTest(t *testing.T, journal *Journal, revision uint64) journalWire {
	t.Helper()
	journal.mu.Lock()
	defer journal.mu.Unlock()
	wire, err := journalToWire(journal, revision)
	if err != nil {
		t.Fatal("construct journal wire fixture")
	}
	return wire
}

// encodeJournalForTest encodes while holding the journal owner lock.
func encodeJournalForTest(journal *Journal, revision uint64) ([]byte, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	return encodeJournalLocked(journal, revision)
}
