package domainadmin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

const substituteTenant = "substitute-tenant"

// TestExportDNSRejectsForeignProtectedDocumentsWithoutMutation freezes create-only ownership.
func TestExportDNSRejectsForeignProtectedDocumentsWithoutMutation(t *testing.T) {
	set, candidate, plan, _ := stagedDNSFixture(t)
	defer set.Close()       //nolint:errcheck // Test cleanup has no recovery.
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()      //nolint:errcheck // Test cleanup has no recovery.
	intentPath := writeIntentFixture(t, "version: dkim2-domain-intent-v1\ndomain: example.test\ntenant_id: outbound\nprofile_use: originator\nalgorithms: [ed25519-sha256]\nrollout: enforce\ncompatibility: strict\n")
	foreignRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(foreignRoot, 0o700) != nil {
		t.Fatal("protect foreign export fixture")
	}
	foreignPath := filepath.Join(foreignRoot, "foreign.txt")
	if os.WriteFile(foreignPath, []byte("owner-only foreign document\n"), 0o600) != nil {
		t.Fatal("write foreign export fixture")
	}
	for _, path := range []string{intentPath, foreignPath} {
		before, beforeInfo, beforeEntries := protectedArtifactSnapshot(t, path)
		if _, exportErr := ExportDNS(t.Context(), path, set, DefaultLimits()); CodeOf(exportErr) != CodeConflict {
			t.Fatal("foreign protected document was not rejected as a conflict")
		}
		after, afterInfo, afterEntries := protectedArtifactSnapshot(t, path)
		if !bytes.Equal(before, after) || !os.SameFile(beforeInfo, afterInfo) || !slices.Equal(beforeEntries, afterEntries) {
			t.Fatal("foreign protected document or its directory was mutated")
		}
		clear(before)
		clear(after)
	}
}

// TestExportDNSExactRetryDoesNotReplaceArtifact freezes byte-exact idempotency after success.
func TestExportDNSExactRetryDoesNotReplaceArtifact(t *testing.T) {
	set, candidate, plan, _ := stagedDNSFixture(t)
	defer set.Close()       //nolint:errcheck // Test cleanup has no recovery.
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()      //nolint:errcheck // Test cleanup has no recovery.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(root, 0o700) != nil {
		t.Fatal("protect retry export fixture")
	}
	path := filepath.Join(root, "records.zone")
	first, err := ExportDNS(t.Context(), path, set, DefaultLimits())
	if err != nil {
		t.Fatal("create deterministic DNS artifact")
	}
	before, beforeInfo, beforeEntries := protectedArtifactSnapshot(t, path)
	second, err := ExportDNS(t.Context(), path, set, DefaultLimits())
	if err != nil || second != first {
		t.Fatal("exact deterministic DNS retry was not idempotent")
	}
	after, afterInfo, afterEntries := protectedArtifactSnapshot(t, path)
	if !bytes.Equal(before, after) || !os.SameFile(beforeInfo, afterInfo) || !slices.Equal(beforeEntries, afterEntries) {
		t.Fatal("exact deterministic DNS retry replaced or mutated the artifact")
	}
	clear(before)
	clear(after)
}

// TestExportDNSConcurrentExactRetriesDoNotReplaceArtifact freezes idempotent operator races.
func TestExportDNSConcurrentExactRetriesDoNotReplaceArtifact(t *testing.T) {
	set, candidate, plan, _ := stagedDNSFixture(t)
	defer set.Close()       //nolint:errcheck // Test cleanup has no recovery.
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()      //nolint:errcheck // Test cleanup has no recovery.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(root, 0o700) != nil {
		t.Fatal("protect concurrent retry fixture")
	}
	path := filepath.Join(root, "records.zone")
	want, err := ExportDNS(t.Context(), path, set, DefaultLimits())
	if err != nil {
		t.Fatal("create concurrent retry artifact")
	}
	before, beforeInfo, beforeEntries := protectedArtifactSnapshot(t, path)
	const workers = 8
	errorsFound := make(chan error, workers)
	results := make(chan DNSExportResult, workers)
	var group sync.WaitGroup
	for range workers {
		group.Go(func() {
			result, exportErr := ExportDNS(t.Context(), path, set, DefaultLimits())
			errorsFound <- exportErr
			results <- result
		})
	}
	group.Wait()
	close(errorsFound)
	close(results)
	for exportErr := range errorsFound {
		if exportErr != nil {
			t.Fatal("concurrent exact retry failed")
		}
	}
	for result := range results {
		if result != want {
			t.Fatal("concurrent exact retry changed bounded result")
		}
	}
	after, afterInfo, afterEntries := protectedArtifactSnapshot(t, path)
	if !bytes.Equal(before, after) || !os.SameFile(beforeInfo, afterInfo) ||
		!slices.Equal(beforeEntries, afterEntries) {
		t.Fatal("concurrent exact retries replaced deterministic artifact")
	}
	clear(before)
	clear(after)
}

// protectedArtifactSnapshot captures content, inode identity, and sorted sibling names.
func protectedArtifactSnapshot(t *testing.T, path string) ([]byte, os.FileInfo, []string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read protected artifact snapshot")
	}
	info, err := os.Lstat(path)
	if err != nil {
		clear(content)
		t.Fatal("stat protected artifact snapshot")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		clear(content)
		t.Fatal("read protected artifact directory")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	return content, info, names
}

// TestStagedDNSSetEncodesRSAAndEd25519AndRoundTrips freezes exact DNS-04 key representation.
func TestStagedDNSSetEncodesRSAAndEd25519AndRoundTrips(t *testing.T) {
	set, candidate, plan, staged := stagedDNSFixture(t)
	defer set.Close()       //nolint:errcheck // Test cleanup has no recovery.
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()      //nolint:errcheck // Test cleanup has no recovery.
	if err := set.WithRecords(t.Context(), func(records []DNSRecord) error {
		if len(records) != 2 {
			t.Fatal("dual staged candidate did not produce exactly two DNS records")
		}
		for _, record := range records {
			separator := bytes.LastIndex(record.payload, []byte("; p="))
			if separator < 0 {
				t.Fatal("DNS record omitted p tag")
			}
			decoded, err := base64.StdEncoding.DecodeString(string(record.payload[separator+4:]))
			if err != nil {
				t.Fatal("DNS p value is not canonical padded base64")
			}
			switch record.algorithm {
			case provider.AlgorithmRSASHA256:
				key, err := x509.ParsePKCS1PublicKey(decoded)
				if err != nil || key == nil || len(record.payload) <= txtChunkBytes || bytes.Equal(decoded, record.publicSPKI) {
					t.Fatal("RSA DNS value was not exact PKCS#1 public DER")
				}
			case provider.AlgorithmEd25519SHA256:
				if len(decoded) != ed25519.PublicKeySize {
					t.Fatal("Ed25519 DNS value was not exact raw 32-byte public key")
				}
				spki, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(decoded))
				if err != nil || !bytes.Equal(spki, record.publicSPKI) {
					clear(spki)
					t.Fatal("Ed25519 raw DNS value did not reproduce staged SPKI")
				}
				clear(spki)
			default:
				t.Fatal("unexpected staged DNS algorithm")
			}
			joined := bytes.Join(txtChunks(record.payload, txtChunkBytes), nil)
			if !bytes.Equal(joined, record.payload) {
				t.Fatal("TXT chunk concatenation changed logical RR bytes")
			}
			clear(decoded)
		}
		return nil
	}); err != nil {
		t.Fatal("read staged DNS records")
	}
	if !set.staged.Digest().Equal(staged.Digest()) {
		t.Fatal("staged DNS set lost its exact backend readback evidence")
	}
}

// TestTXTChunkBoundariesAndPresentationGolden freezes short, exact, and multi-chunk output.
func TestTXTChunkBoundariesAndPresentationGolden(t *testing.T) {
	for _, length := range []int{1, txtChunkBytes, txtChunkBytes + 1, txtChunkBytes * 2} {
		payload := bytes.Repeat([]byte{'A'}, length)
		chunks := txtChunks(payload, txtChunkBytes)
		if len(chunks) != (length+txtChunkBytes-1)/txtChunkBytes || !bytes.Equal(bytes.Join(chunks, nil), payload) {
			t.Fatal("TXT boundary chunking drifted")
		}
		for _, chunk := range chunks {
			if len(chunk) == 0 || len(chunk) > txtChunkBytes {
				t.Fatal("TXT character string exceeded fixed boundary")
			}
		}
	}
	payload := bytes.Repeat([]byte{'B'}, txtChunkBytes+1)
	record := DNSRecord{
		owner: []byte("selector._domainkey.example.test."), selector: []byte("selector"),
		payload: payload, algorithm: provider.AlgorithmRSASHA256,
	}
	document, err := formatDNSExport([]DNSRecord{record}, 300, 4096)
	if err != nil {
		t.Fatal("format deterministic DNS export")
	}
	want := "; dkim2-dns-export-v1\n; ttl-seconds=300\n" +
		"; algorithm=rsa-sha256 selector=selector\n" +
		"selector._domainkey.example.test. 300 IN TXT \"" + strings.Repeat("B", 200) + "\" \"B\"\n"
	if string(document) != want {
		t.Fatal("deterministic TXT presentation golden drifted")
	}
	clear(document)
}

// TestExportDNSWritesOnlyExplicitProtectedArtifact freezes filesystem and privacy behavior.
func TestExportDNSWritesOnlyExplicitProtectedArtifact(t *testing.T) {
	set, candidate, plan, _ := stagedDNSFixture(t)
	defer set.Close()       //nolint:errcheck // Test cleanup has no recovery.
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()      //nolint:errcheck // Test cleanup has no recovery.
	root, _ := filepath.EvalSymlinks(t.TempDir())
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal("protect DNS export directory")
	}
	path := filepath.Join(root, "records.zone")
	result, err := ExportDNS(t.Context(), path, set, DefaultLimits())
	if err != nil || result.Records != 2 || result.Bytes == 0 {
		t.Fatal("protected DNS export rejected")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != int64(result.Bytes) {
		t.Fatal("DNS export was not one explicit owner-only regular artifact")
	}
	document, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(document, []byte(" IN TXT \"v=DKIM1;")) ||
		bytes.Contains(document, []byte("PRIVATE KEY")) || bytes.Contains(document, []byte("PKCS8")) {
		clear(document)
		t.Fatal("DNS export content shape or privacy drifted")
	}
	clear(document)
	marker := "identity-marker"
	protectedValues := []any{set, DNSRecord{domain: []byte(marker), payload: []byte(marker)}}
	for _, value := range protectedValues {
		rendered := fmt.Sprintf("%+v", value)
		if !strings.Contains(rendered, redacted) || strings.Contains(rendered, marker) {
			t.Fatal("DNS identity reached formatting sink")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("DNS identity reached generic JSON sink")
		}
	}
}

// TestDNSRecordRejectsSPKIAndAlgorithmSubstitution freezes confused-key inputs.
func TestDNSRecordRejectsSPKIAndAlgorithmSubstitution(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate substitution fixture")
	}
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal("marshal substitution fixture")
	}
	defer clear(spki)
	if record, err := newDNSRecord(t.Context(), "example.test", "selector", provider.AlgorithmRSASHA256, spki); CodeOf(err) != CodeDNSAlgorithmMismatch || len(record.payload) != 0 {
		t.Fatal("Ed25519 SPKI accepted as RSA DNS key")
	}
	noncanonical := append(append([]byte(nil), spki...), 0)
	defer clear(noncanonical)
	if record, err := newDNSRecord(t.Context(), "example.test", "selector", provider.AlgorithmEd25519SHA256, noncanonical); CodeOf(err) != CodeDNSInvalid || len(record.payload) != 0 {
		t.Fatal("noncanonical SPKI accepted for DNS export")
	}
}

// TestStagedDNSSetRejectsEvidenceAndRecordLimits freezes staged-readback ownership.
func TestStagedDNSSetRejectsEvidenceAndRecordLimits(t *testing.T) {
	set, candidate, plan, _ := stagedDNSFixture(t)
	defer set.Close()       //nolint:errcheck // Test cleanup has no recovery.
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()      //nolint:errcheck // Test cleanup has no recovery.
	otherBytes := bytes.Repeat([]byte{0x42}, 32)
	other, _ := datasourceadmin.ParseStagedEvidence(otherBytes)
	clear(otherBytes)
	metadata := committedDNSGeneration(plan, candidate)
	if otherSet, err := NewStagedDNSSet(t.Context(), plan, candidate, metadata, other, DefaultLimits()); CodeOf(err) != CodeConflict || otherSet != nil {
		t.Fatal("different staged digest selected DNS proof inputs")
	}
	limits := DefaultLimits()
	limits.MaxDNSRecords = 1
	if limited, err := NewStagedDNSSet(t.Context(), plan, candidate, metadata, set.staged, limits); CodeOf(err) != CodeConflict || limited != nil {
		t.Fatal("DNS record cap was exceeded")
	}
}

// TestStagedDNSSetRejectsNoncommittedCurrentAndMismatchedGeneration freezes authoritative provenance.
func TestStagedDNSSetRejectsNoncommittedCurrentAndMismatchedGeneration(t *testing.T) {
	set, candidate, plan, staged := stagedDNSFixture(t)
	defer set.Close()       //nolint:errcheck // Test cleanup has no recovery.
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()      //nolint:errcheck // Test cleanup has no recovery.
	valid := committedDNSGeneration(plan, candidate)
	otherOperation, err := datasourceadmin.NewOperationBinding("aebagbafaydqqcikbmga2dqpca")
	if err != nil {
		t.Fatal("construct mismatched operation")
	}
	tests := []datasourceadmin.GenerationInfo{
		{Generation: valid.Generation, State: datasourceadmin.StateStaging, Operation: valid.Operation},
		{Generation: valid.Generation, Current: true, State: datasourceadmin.StateCommitted, Operation: valid.Operation},
		{Generation: valid.Generation + 1, State: datasourceadmin.StateCommitted, Operation: valid.Operation},
		{Generation: valid.Generation, State: datasourceadmin.StateCommitted, Operation: otherOperation},
	}
	for _, metadata := range tests {
		if selected, selectErr := NewStagedDNSSet(
			t.Context(), plan, candidate, metadata, staged, DefaultLimits(),
		); CodeOf(selectErr) != CodeConflict || selected != nil {
			t.Fatal("non-authoritative candidate provenance selected DNS inputs")
		}
	}
}

// TestStagedDNSSetRejectsPlanRowSubstitution freezes complete profile and policy binding.
func TestStagedDNSSetRejectsPlanRowSubstitution(t *testing.T) {
	set, candidate, plan, _ := stagedDNSFixture(t)
	defer set.Close()       //nolint:errcheck // Test cleanup has no recovery.
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	defer plan.Close()      //nolint:errcheck // Test cleanup has no recovery.
	plan.mu.Lock()
	intent := plan.intent.clone()
	profileID := plan.profileID
	credentials := append([]AllocatedIdentity(nil), plan.credentials...)
	operation := plan.operation
	plan.mu.Unlock()
	defer clearAllocatedIdentities(credentials)
	if err := candidate.WithRows(t.Context(), func(rows datasourceadmin.Rows) error {
		if !exactPlannedRows(rows, intent, profileID, credentials) {
			t.Fatal("canonical staged rows did not match their exact plan")
		}
		rows.Profiles[0].Domain = "substitute.example.test"
		if exactPlannedRows(rows, intent, profileID, credentials) {
			t.Fatal("profile substitution matched the plan")
		}
		rows.Profiles[0].Domain = intent.Domain()
		rows.Profiles[0].Status = "disabled"
		if exactPlannedRows(rows, intent, profileID, credentials) {
			t.Fatal("profile status substitution matched the plan")
		}
		rows.Profiles[0].Status = provider.RecordStatusActive.String()
		rows.Policies[0].Rollout = "observe"
		if exactPlannedRows(rows, intent, profileID, credentials) {
			t.Fatal("policy substitution matched the plan")
		}
		rows.Policies[0].Rollout = intent.Rollout().String()
		rows.Policies[0].TenantID = substituteTenant
		if exactPlannedRows(rows, intent, profileID, credentials) {
			t.Fatal("policy tenant substitution matched the plan")
		}
		rows.Policies[0].TenantID = intent.TenantID()
		rows.Policies[0].Use = "next-domain-transit"
		if exactPlannedRows(rows, intent, profileID, credentials) {
			t.Fatal("policy use substitution matched the plan")
		}
		rows.Policies[0].Use = intent.ProfileUse().String()
		rows.Credentials = append(rows.Credentials, rows.Credentials[0])
		if exactPlannedRows(rows, intent, profileID, credentials) {
			t.Fatal("extra selected-profile credential matched the plan")
		}
		rows.Credentials = rows.Credentials[:len(rows.Credentials)-1]
		rows.KeyMaterial[0].TenantID = substituteTenant
		if exactPlannedRows(rows, intent, profileID, credentials) {
			t.Fatal("native key ownership substitution matched the plan")
		}
		rows.KeyMaterial[0].TenantID = intent.TenantID()
		rows.KeyMaterial[0].Use = "next-domain-transit"
		if exactPlannedRows(rows, intent, profileID, credentials) {
			t.Fatal("native key use substitution matched the plan")
		}
		return nil
	}); err != nil {
		t.Fatal("inspect exact staged row binding")
	}

	var substituted *datasourceadmin.Snapshot
	var substitutedErr error
	if err := candidate.WithRows(t.Context(), func(rows datasourceadmin.Rows) error {
		rows.Policies[0].TenantID = substituteTenant
		for index := range rows.KeyMaterial {
			rows.KeyMaterial[index].TenantID = substituteTenant
		}
		substituted, substitutedErr = datasourceadmin.NewSnapshot(
			datasourceadmin.SchemaVersionV3, candidate.Generation(), rows,
		)
		return substitutedErr
	}); err != nil || substituted == nil {
		t.Fatalf("construct valid but plan-substituted candidate: datasource_code=%s", datasourceadmin.CodeOf(substitutedErr))
	}
	operationID := ""
	if err := operation.WithValue(t.Context(), func(value string) error {
		operationID = value
		return nil
	}); err != nil {
		_ = substituted.Close()
		t.Fatal("read exact operation binding")
	}
	substituteContent, err := datasourceadmin.NewCandidateContent(substituted)
	if err != nil {
		_ = substituted.Close()
		t.Fatal("construct substituted candidate content")
	}
	substituteCandidate, err := datasourceadmin.NewPublicationEnvelope(operationID, substituteContent)
	if err != nil {
		_ = substituteContent.Close()
		t.Fatal("construct substituted publication envelope")
	}
	defer substituteCandidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	substituteStaged := datasourceadmin.NewStagedEvidence(substituteCandidate.Digest())
	if selected, selectErr := NewStagedDNSSet(
		t.Context(), plan, substituteCandidate, committedDNSGeneration(plan, substituteCandidate),
		substituteStaged, DefaultLimits(),
	); CodeOf(selectErr) != CodeConflict || selected != nil {
		t.Fatal("valid unrelated policy candidate selected DNS inputs")
	}
}

// TestExactRecordTransportRejectsOwnerAndContextSubstitution freezes parser input binding.
func TestExactRecordTransportRejectsOwnerAndContextSubstitution(t *testing.T) {
	transport := exactRecordTransport{owner: "s._domainkey.example.test.", payload: []byte("v=DKIM1; p=")}
	if _, err := transport.LookupTXT(t.Context(), "other._domainkey.example.test."); err == nil {
		t.Fatal("in-memory parser transport accepted a different owner")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := transport.LookupTXT(cancelled, transport.owner); err == nil {
		t.Fatal("in-memory parser transport ignored caller cancellation")
	}
	if record, err := newDNSRecord(
		cancelled, "example.test", "selector", provider.AlgorithmEd25519SHA256, []byte("unused"),
	); CodeOf(err) != CodeUnavailable || len(record.payload) != 0 {
		t.Fatal("DNS record conversion performed work after caller cancellation")
	}
}

// stagedDNSFixture constructs a dual-algorithm exact staged candidate projection.
func stagedDNSFixture(
	t *testing.T,
) (*StagedDNSSet, *datasourceadmin.PublicationEnvelope, *Plan, datasourceadmin.StagedEvidence) {
	t.Helper()
	limits := DefaultLimits()
	allocator, err := newIdentityAllocator(limits, &incrementingEntropy{})
	if err != nil {
		t.Fatal("construct DNS allocation owner")
	}
	locker := &administrationLockerFake{revision: 41}
	reader := &collisionReaderFake{build: func(
		ctx context.Context,
		lock datasourceadmin.AdministrationLock,
		generationLimits datasourceadmin.GenerationLimits,
	) (*datasourceadmin.CollisionInventory, error) {
		return datasourceadmin.NewCollisionInventory(ctx, lock, datasourceadmin.Inventory{}, nil, generationLimits)
	}}
	intent := testIntent(t, provider.AlgorithmEd25519SHA256, provider.AlgorithmRSASHA256)
	allocation, _, err := allocator.allocateForTest(t.Context(), intent, reader, locker, 41, testAdminGenerationLimits())
	if err != nil {
		t.Fatal("construct DNS allocation")
	}
	defer allocation.Close() //nolint:errcheck // Fixture transfers every needed value.
	plan, err := NewPlan(t.Context(), datasourceadmin.BackendLDAP, planAuthority(), allocation, planDNSPolicy())
	if err != nil {
		t.Fatal("construct DNS plan")
	}
	generator, err := NewKeyGenerator(KeyPolicy{RSAModulusBits: 2048, RSAExponent: approvedRSAExponent}, limits)
	if err != nil {
		_ = plan.Close()
		t.Fatal("construct DNS key generator")
	}
	keys, err := generator.Generate(t.Context(), allocation)
	if err != nil {
		_ = plan.Close()
		t.Fatal("generate DNS fixture keys")
	}
	defer keys.Close() //nolint:errcheck // Candidate owns detached key bytes.
	addition, err := keys.DomainAddition(t.Context())
	if err != nil {
		_ = plan.Close()
		t.Fatal("construct DNS domain addition")
	}
	defer addition.Close() //nolint:errcheck // Candidate owns detached key bytes.
	snapshot, err := addition.NewSnapshot(datasourceadmin.SchemaVersionV3, 1)
	if err != nil {
		_ = plan.Close()
		t.Fatal("construct DNS candidate snapshot")
	}
	operationID := ""
	if err := allocation.Operation().WithValue(t.Context(), func(value string) error {
		operationID = value
		return nil
	}); err != nil {
		_ = snapshot.Close()
		_ = plan.Close()
		t.Fatal("read fixture operation")
	}
	content, err := datasourceadmin.NewCandidateContent(snapshot)
	if err != nil {
		_ = snapshot.Close()
		_ = plan.Close()
		t.Fatal("construct DNS candidate content")
	}
	candidate, err := datasourceadmin.NewPublicationEnvelope(operationID, content)
	if err != nil {
		_ = content.Close()
		_ = plan.Close()
		t.Fatal("construct DNS publication envelope")
	}
	staged := datasourceadmin.NewStagedEvidence(candidate.Digest())
	set, err := NewStagedDNSSet(t.Context(), plan, candidate, committedDNSGeneration(plan, candidate), staged, limits)
	if err != nil {
		_ = candidate.Close()
		_ = plan.Close()
		t.Fatal("construct staged DNS set")
	}
	return set, candidate, plan, staged
}

// committedDNSGeneration constructs the backend-authoritative readback metadata fixture.
func committedDNSGeneration(plan *Plan, candidate *datasourceadmin.PublicationEnvelope) datasourceadmin.GenerationInfo {
	return datasourceadmin.GenerationInfo{
		Generation: candidate.Generation(), State: datasourceadmin.StateCommitted, Operation: plan.operation,
	}
}
