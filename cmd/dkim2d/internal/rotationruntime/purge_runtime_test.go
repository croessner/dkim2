package rotationruntime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/rotationadmin"
)

// retentionInventoryBackend supplies stable provider inventory evidence while
// preserving the production campaignBackend shape for runtime wiring tests.
type retentionInventoryBackend struct {
	datasourceadmin.GenerationPublisher
	datasourceadmin.AdministrationLocker
	inventory datasourceadmin.Inventory
}

// retentionRecoverySequence supplies independently observed full recovery snapshots.
type retentionRecoverySequence struct {
	views []datasourceadmin.RetentionInventory
	calls int
}

// terminalRuntimeRecorder proves the recovery adapter has a terminal-reader
// authority even where legacy test inventory contains no frozen campaigns.
type terminalRuntimeRecorder struct{}

func (terminalRuntimeRecorder) RecordTerminal(context.Context, datasourceadmin.TerminalRecord) error {
	return nil
}

func (terminalRuntimeRecorder) ReadTerminal(context.Context, datasourceadmin.OperationBinding) (datasourceadmin.TerminalRecord, bool, error) {
	return datasourceadmin.TerminalRecord{}, false, nil
}

type terminalRuntimeRecord struct {
	record datasourceadmin.TerminalRecord
}

func (terminalRuntimeRecord) RecordTerminal(context.Context, datasourceadmin.TerminalRecord) error {
	return nil
}

func (r terminalRuntimeRecord) ReadTerminal(context.Context, datasourceadmin.OperationBinding) (datasourceadmin.TerminalRecord, bool, error) {
	return r.record, true, nil
}

// RetentionRecoveryInventory returns the next provider observation.
func (s *retentionRecoverySequence) RetentionRecoveryInventory(context.Context) (datasourceadmin.RetentionInventory, error) {
	if s == nil || len(s.views) == 0 {
		return datasourceadmin.RetentionInventory{}, errUnavailable
	}
	index := s.calls
	if index >= len(s.views) {
		index = len(s.views) - 1
	}
	s.calls++
	return s.views[index], nil
}

// RetentionRecoveryInventory returns full key-free historical evidence without allocation ceilings.
func (b *retentionInventoryBackend) RetentionRecoveryInventory(_ context.Context) (datasourceadmin.RetentionInventory, error) {
	rows := make([]datasourceadmin.RetentionGeneration, 0, len(b.inventory.Generations))
	for _, generation := range b.inventory.Generations {
		digest, err := admincontract.ParseDigest(generation.ContentDigest.Bytes())
		if err != nil {
			return datasourceadmin.RetentionInventory{}, err
		}
		rows = append(rows, datasourceadmin.RetentionGeneration{Generation: generation.Generation, Schema: generation.Schema, State: generation.State, WasActive: generation.WasActive, Complete: generation.State == datasourceadmin.StateCommitted, Ownership: datasourceadmin.RetentionOwnershipTrusted, ContentDigest: digest})
	}
	return datasourceadmin.RetentionInventory{Version: "runtime-test-recovery-v1", Current: b.inventory.Current, Generations: rows}, nil
}

// Inventory returns the exact test-owned stable backend view.
func (b *retentionInventoryBackend) Inventory(_ context.Context, _ datasourceadmin.GenerationLimits) (datasourceadmin.Inventory, error) {
	return b.inventory, nil
}

// ReadCurrent is not part of retention plan/apply and must not be reached.
func (*retentionInventoryBackend) ReadCurrent(context.Context, datasourceadmin.GenerationLimits) (*datasourceadmin.Snapshot, error) {
	return nil, errUnavailable
}

// ReadCollisionInventory is not part of retention plan/apply and must not be reached.
func (*retentionInventoryBackend) ReadCollisionInventory(context.Context, datasourceadmin.AdministrationLock, datasourceadmin.GenerationLimits) (*datasourceadmin.CollisionInventory, error) {
	return nil, errUnavailable
}

// purgeRuntimeExecutor records the exact destructive callback requested by the runtime.
type purgeRuntimeExecutor struct {
	calls   int
	targets int
}

// Purge confirms the one exact provider callback after extracting bounded targets.
func (e *purgeRuntimeExecutor) Purge(ctx context.Context, command rotationadmin.PurgeCommand) (rotationadmin.PurgeExecutionResult, error) {
	e.calls++
	if err := command.WithTargets(ctx, func(targets []admincontract.PurgeTarget) error {
		e.targets = len(targets)
		return nil
	}); err != nil {
		return rotationadmin.PurgeExecutionResult{}, err
	}
	return rotationadmin.PurgeExecutionResult{Committed: true}, nil
}

// TestPurgePlanAndApplyUseFreshInventoryAndTheDedicatedExecutor proves the
// runtime creates a protected artifact, rereads inventory, and invokes the
// fourth provider authority only after exact artifact verification.
func TestPurgePlanAndApplyUseFreshInventoryAndTheDedicatedExecutor(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(directory, 0700) != nil {
		t.Fatal("protect test directory")
	}
	backend := &retentionInventoryBackend{inventory: retentionRuntimeInventory(t, 10000)}
	executor := &purgeRuntimeExecutor{}
	runtime := &CampaignRuntime{
		backend: backend, purge: executor, recovery: newRetentionRecoveryAdapter(backend, terminalRuntimeRecorder{}), class: backendLDAP, limits: retentionRuntimeLimits(), authority: retentionRuntimeAuthority(),
	}
	artifact := filepath.Join(directory, "purge-plan.yaml")
	planned, err := runtime.planPurge(t.Context(), Request{Command: CommandPurgePlan, Output: artifact})
	if err != nil || planned.ResultClass != "planned" || planned.WorkCount == 0 {
		t.Fatal("retention plan was not created from eligible inventory")
	}
	document, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := rotationadmin.ParsePurgePlanArtifact(document)
	if err != nil || !plan.ArtifactDigest().Valid() {
		t.Fatal("runtime did not persist a parseable exact protected artifact")
	}
	if err := plan.Close(); err != nil {
		t.Fatal(err)
	}
	applied, err := runtime.applyPurge(t.Context(), Request{Command: CommandPurgeApply, Plan: artifact, Apply: true})
	if err != nil || applied.ResultClass != "purged" || executor.calls != 1 || executor.targets != int(planned.WorkCount) {
		t.Fatal("runtime did not bind apply to the protected artifact and dedicated executor")
	}
}

// TestRecoveryAdapterUsesDedicatedTerminalReader proves the runtime path marks
// a never-active candidate closed only after an exact terminal-reader match.
func TestRecoveryAdapterUsesDedicatedTerminalReader(t *testing.T) {
	operation, err := datasourceadmin.NewOperationBinding("aebagbafaydqqcikbmga2dqpca")
	if err != nil {
		t.Fatal(err)
	}
	digestBytes := make([]byte, 32)
	digestBytes[0] = 9
	digest, err := datasourceadmin.ParseCandidateContentDigest(digestBytes)
	if err != nil {
		t.Fatal(err)
	}
	contractDigest, err := admincontract.ParseDigest(digest.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	record, err := datasourceadmin.NewTerminalRecord(operation, datasourceadmin.SchemaVersionV3, datasourceadmin.SchemaVersionV3, 7, 8, 8, digest, datasourceadmin.TerminalClosed, "activated", time.Unix(2_000_000_000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	view := datasourceadmin.RetentionInventory{Version: "runtime-terminal-v1", Current: 8, Generations: []datasourceadmin.RetentionGeneration{
		{Generation: 7, Schema: datasourceadmin.SchemaVersionV3, State: datasourceadmin.StateCommitted, WasActive: true, Complete: true, Ownership: datasourceadmin.RetentionOwnershipTrusted, ContentDigest: contractDigest},
		{Generation: 8, Operation: operation, SourceGeneration: 7, Schema: datasourceadmin.SchemaVersionV3, State: datasourceadmin.StateCommitted, Complete: true, Ownership: datasourceadmin.RetentionOwnershipTrusted, ContentDigest: contractDigest},
	}}
	reader := newRetentionRecoveryAdapter(&retentionRecoverySequence{views: []datasourceadmin.RetentionInventory{view}}, terminalRuntimeRecord{record: record})
	result, err := datasourceadmin.ReadRetentionRecoveryInventory(t.Context(), reader, datasourceadmin.DefaultRetentionRecoveryLimits())
	if err != nil || !result.Generations[1].Closed || result.Generations[1].Ownership != datasourceadmin.RetentionOwnershipTrusted {
		t.Fatal("runtime recovery did not join exact dedicated terminal evidence")
	}
}

// TestPurgePlanFailsClosedWithoutEligibleRetention proves a bounded but
// ineligible inventory never creates an empty or deceptive plan artifact.
func TestPurgePlanFailsClosedWithoutEligibleRetention(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(directory, 0700) != nil {
		t.Fatal("protect test directory")
	}
	runtime := &CampaignRuntime{
		backend: &retentionInventoryBackend{inventory: retentionRuntimeInventory(t, 8)}, class: backendLDAP, limits: retentionRuntimeLimits(), authority: retentionRuntimeAuthority(),
	}
	artifact := filepath.Join(directory, "purge-plan.yaml")
	runtime.recovery = newRetentionRecoveryAdapter(runtime.backend.(*retentionInventoryBackend), terminalRuntimeRecorder{})
	report, planErr := runtime.planPurge(t.Context(), Request{Command: CommandPurgePlan, Output: artifact})
	if planErr == nil || report.ResultClass != "no_eligible" {
		t.Fatal("ineligible retention inventory was accepted")
	}
	if _, err := os.Stat(artifact); !os.IsNotExist(err) {
		t.Fatal("ineligible retention inventory created an artifact")
	}
}

// TestPurgeApplyRequiresTheExplicitApplyFence prevents direct runtime callers
// from bypassing the CLI's one bare destructive authorization token.
func TestPurgeApplyRequiresTheExplicitApplyFence(t *testing.T) {
	backend := &retentionInventoryBackend{inventory: retentionRuntimeInventory(t, 130)}
	runtime := &CampaignRuntime{backend: backend, purge: &purgeRuntimeExecutor{}, recovery: newRetentionRecoveryAdapter(backend, terminalRuntimeRecorder{}), class: backendLDAP, limits: retentionRuntimeLimits(), authority: retentionRuntimeAuthority()}
	if _, err := runtime.applyPurge(t.Context(), Request{Command: CommandPurgeApply, Plan: "/tmp/plan"}); err == nil {
		t.Fatal("purge apply without the explicit apply fence was accepted")
	}
}

// TestRetentionRecoveryRejectsStaleNonTargetChange proves the runtime does
// not overlook a changed historical record merely because it is not a target.
func TestRetentionRecoveryRejectsStaleNonTargetChange(t *testing.T) {
	backend := &retentionInventoryBackend{inventory: retentionRuntimeInventory(t, 10000)}
	first, err := backend.RetentionRecoveryInventory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.Generations = append([]datasourceadmin.RetentionGeneration(nil), first.Generations...)
	changed := make([]byte, 32)
	changed[0] = 1
	digest, err := admincontract.ParseDigest(changed)
	if err != nil {
		t.Fatal(err)
	}
	second.Generations[len(second.Generations)-1].ContentDigest = digest
	reader := newRetentionRecoveryAdapter(&retentionRecoverySequence{views: []datasourceadmin.RetentionInventory{first, second}}, terminalRuntimeRecorder{})
	if _, err := datasourceadmin.ReadRetentionRecoveryInventory(t.Context(), reader, datasourceadmin.DefaultRetentionRecoveryLimits()); err == nil {
		t.Fatal("stale non-target recovery change was accepted")
	}
}

// retentionRuntimeInventory builds active historical records that exceed the
// finite policy bound; these are the currently available real purge candidates.
func retentionRuntimeInventory(t *testing.T, count uint64) datasourceadmin.Inventory {
	t.Helper()
	generations := make([]datasourceadmin.GenerationInfo, 0, count)
	for generation := uint64(1); generation <= count; generation++ {
		bytes := make([]byte, 32)
		bytes[0], bytes[31] = byte(generation), byte(generation>>8)
		digest, err := datasourceadmin.ParseCandidateContentDigest(bytes)
		if err != nil {
			t.Fatal(err)
		}
		generations = append(generations, datasourceadmin.GenerationInfo{Generation: generation, Current: generation == count, State: datasourceadmin.StateCommitted, WasActive: true, Schema: datasourceadmin.SchemaVersionV3, ContentDigest: digest})
	}
	return datasourceadmin.Inventory{Current: count, Generations: generations}
}

// retentionRuntimeLimits returns the production-safe inventory ceilings used by the composed runtime.
func retentionRuntimeLimits() datasourceadmin.GenerationLimits {
	return datasourceadmin.GenerationLimits{MaxGenerations: 4096, MaxOutstandingCandidates: 8, MaxSnapshotRows: 65536, MaxSnapshotBytes: 512 << 20, BackendDeadline: 2 * time.Minute}
}

// retentionRuntimeAuthority returns one complete isolated four-role LDAP authority.
func retentionRuntimeAuthority() datasourceadmin.AuthorityDescriptor {
	var trust [32]byte
	trust[0] = 1
	return datasourceadmin.AuthorityDescriptor{AuthorityID: "aebagbafaydqqcikbmga2dqpca", Endpoints: []datasourceadmin.AuthorityEndpoint{{Scheme: "ldaps", Host: "ldap.example.test", Port: 636, TLSServerName: "ldap.example.test"}}, LDAP: &datasourceadmin.LDAPAuthority{BaseDN: "dc=example,dc=test", SnapshotPrincipal: "snapshot", StagingPrincipal: "staging", ActivationPrincipal: "activation", PurgePrincipal: "purger"}, TrustFingerprints: [][32]byte{trust}}
}
