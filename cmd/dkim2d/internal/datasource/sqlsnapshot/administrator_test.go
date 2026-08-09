package sqlsnapshot

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

// TestCurrentPointerFenceRejectsFormattingAndSerialization proves active
// pointer digests cannot escape through generic diagnostic sinks.
func TestCurrentPointerFenceRejectsFormattingAndSerialization(t *testing.T) {
	digest := []byte("current-pointer-digest-secret-000")
	fence := CurrentPointerFence{generation: "7", pointerDigest: append([]byte(nil), digest...)}
	assertProtectedFenceFormatting(t, fence, string(digest))
}

// TestCandidateRootFenceRejectsFormattingAndSerialization proves operation
// and digest material cannot escape through generic diagnostic sinks.
func TestCandidateRootFenceRejectsFormattingAndSerialization(t *testing.T) {
	digest := []byte("candidate-root-digest-secret-000")
	fence := CandidateRootFence{
		generation: "8", operation: testOperationOne,
		digest: append([]byte(nil), digest...), revision: 3,
	}
	assertProtectedFenceFormatting(t, fence, testOperationOne, string(digest))
}

// assertProtectedFenceFormatting requires one protected value across common sinks.
func assertProtectedFenceFormatting(t *testing.T, value any, secrets ...string) {
	t.Helper()
	for _, format := range []string{"%v", "%+v", "%#v"} {
		formatted := fmt.Sprintf(format, value)
		if formatted != administratorRedacted {
			t.Fatalf("protected fence escaped through %s", format)
		}
		for _, secret := range secrets {
			if strings.Contains(formatted, secret) {
				t.Fatalf("protected fence secret escaped through %s", format)
			}
		}
	}
	if stringer, ok := value.(fmt.Stringer); !ok || stringer.String() != administratorRedacted {
		t.Fatal("protected fence lacks constant String representation")
	}
	if goStringer, ok := value.(fmt.GoStringer); !ok || goStringer.GoString() != administratorRedacted {
		t.Fatal("protected fence lacks constant GoString representation")
	}
	if encoded, err := json.Marshal(value); err == nil || len(encoded) != 0 {
		t.Fatal("protected fence accepted JSON serialization")
	}
}

// TestFenceCallbacksDetachAndClearProtectedBytes proves provider callbacks do
// not retain aliases and callback buffers are erased after use.
func TestFenceCallbacksDetachAndClearProtectedBytes(t *testing.T) {
	digest := nonzeroDigest(7)
	candidate, err := newCandidateRootFence("8", testOperationOne, digest, 3)
	if err != nil {
		t.Fatal("construct protected candidate fence")
	}
	var borrowedCandidate []byte
	if err := candidate.WithProtectedValues(t.Context(), func(operation string, detached []byte) error {
		if operation != testOperationOne || string(detached) != string(digest) {
			t.Fatal("candidate callback received changed protected values")
		}
		borrowedCandidate = detached
		detached[0] ^= 0xff
		return nil
	}); err != nil {
		t.Fatal("use protected candidate values")
	}
	if !allZeroBytes(borrowedCandidate) {
		t.Fatal("candidate callback digest was not erased")
	}
	if err := candidate.WithProtectedValues(t.Context(), func(_ string, detached []byte) error {
		if string(detached) != string(digest) {
			t.Fatal("candidate callback mutated owned digest")
		}
		return nil
	}); err != nil {
		t.Fatal("reuse protected candidate values")
	}

	current := CurrentPointerFence{generation: "7", pointerDigest: append([]byte(nil), digest...)}
	var borrowedCurrent []byte
	if err := current.WithPointerDigest(t.Context(), func(detached []byte) error {
		borrowedCurrent = detached
		detached[0] ^= 0xff
		return nil
	}); err != nil {
		t.Fatal("use protected current digest")
	}
	if !allZeroBytes(borrowedCurrent) {
		t.Fatal("current callback digest was not erased")
	}
	if err := current.WithPointerDigest(t.Context(), func(detached []byte) error {
		if string(detached) != string(digest) {
			t.Fatal("current callback mutated owned digest")
		}
		return nil
	}); err != nil {
		t.Fatal("reuse protected current digest")
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if datasourceadmin.CodeOf(candidate.WithProtectedValues(canceled, func(string, []byte) error { return nil })) != datasourceadmin.CodeInvalid ||
		datasourceadmin.CodeOf(current.WithPointerDigest(canceled, func([]byte) error { return nil })) != datasourceadmin.CodeInvalid {
		t.Fatal("canceled fence callback context was accepted")
	}
}

// allZeroBytes reports whether one callback-owned buffer was erased.
func allZeroBytes(value []byte) bool {
	for _, octet := range value {
		if octet != 0 {
			return false
		}
	}
	return true
}

const (
	testOperationOne   = "aebagbafaydqqcikbmga2dqpca"
	testOperationTwo   = "aibqibiga4eascqlbqgy3dymc4"
	testOperationThree = "aibqibiga4eascqlbqgzav3y4m"
	testHandleID       = "handle"
	testDomain         = "example.test"
	testProfileID      = "profile"
)

type administrationMemory struct {
	lockRevision  uint64
	lockOwner     *string
	current       string
	currentDigest []byte
	metadata      map[string]MetadataRow
	rows          map[string]DatasetRows
	failCommit    bool
	commits       int
	beginModes    []AdministrationMode
	lockReads     []bool
	driftOnRead   bool
	driftOwner    *string
	events        []string
}

type memoryAdministrationConnector struct {
	backend   *administrationMemory
	mode      AdministrationMode
	authority AdministrationAuthority
}

// Authority returns one synthetic distinct role identity.
func (c memoryAdministrationConnector) Authority() AdministrationAuthority { return c.authority }

// Begin returns one copy-on-commit synthetic transaction.
func (c memoryAdministrationConnector) Begin(_ context.Context, mode AdministrationMode) (AdministrationTransaction, error) {
	if mode != c.mode {
		return nil, errors.New("wrong mode")
	}
	c.backend.beginModes = append(c.backend.beginModes, mode)
	return &memoryAdministrationTransaction{
		backend: c.backend, state: cloneAdministrationMemory(c.backend), mode: mode,
	}, nil
}

// Close completes the synthetic connector lifecycle.
func (memoryAdministrationConnector) Close() {}

type memoryAdministrationTransaction struct {
	backend *administrationMemory
	state   *administrationMemory
	mode    AdministrationMode
	closed  bool
}

type oversizedKeyPageTransaction struct {
	AdministrationTransaction
	page []KeyMaterialRow
}

type activationReadFailure uint8

const (
	failActivationReadLock activationReadFailure = iota + 1
	failActivationReadCurrent
	failActivationCandidateLock
	failActivationCandidateReadback
)

type failingActivationConnector struct {
	AdministrationConnector
	failure activationReadFailure
}

// Begin wraps one activation transaction with an injected typed read failure.
func (c failingActivationConnector) Begin(ctx context.Context, mode AdministrationMode) (AdministrationTransaction, error) {
	transaction, err := c.AdministrationConnector.Begin(ctx, mode)
	if err != nil {
		return nil, err
	}
	return &failingActivationTransaction{AdministrationTransaction: transaction, failure: c.failure}, nil
}

type failingActivationTransaction struct {
	AdministrationTransaction
	failure activationReadFailure
}

// ReadLock injects one typed physical-lock read failure.
func (t *failingActivationTransaction) ReadLock(ctx context.Context, locked bool) (uint64, *string, error) {
	if t.failure == failActivationReadLock {
		return 0, nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return t.AdministrationTransaction.ReadLock(ctx, locked)
}

// ReadCurrentOptional injects one typed current-lock read failure.
func (t *failingActivationTransaction) ReadCurrentOptional(ctx context.Context, locked bool) (MetadataRow, bool, error) {
	if t.failure == failActivationReadCurrent {
		return MetadataRow{}, false, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return t.AdministrationTransaction.ReadCurrentOptional(ctx, locked)
}

// LockCandidateRoot injects one typed candidate-root backend failure.
func (t *failingActivationTransaction) LockCandidateRoot(ctx context.Context, fence CandidateRootFence) (MetadataRow, error) {
	if t.failure == failActivationCandidateLock {
		return MetadataRow{}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return t.AdministrationTransaction.LockCandidateRoot(ctx, fence)
}

// HandlePageFor injects one typed full-candidate readback failure.
func (t *failingActivationTransaction) HandlePageFor(ctx context.Context, generation, after string, limit int) ([]HandleRow, error) {
	if t.failure == failActivationCandidateReadback {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return t.AdministrationTransaction.HandlePageFor(ctx, generation, after, limit)
}

// KeyMaterialPageFor returns one intentionally nonconforming private-key page.
func (t *oversizedKeyPageTransaction) KeyMaterialPageFor(_ context.Context, _, after string, _ int) ([]KeyMaterialRow, error) {
	if after != "" {
		return nil, nil
	}
	return t.page, nil
}

// Isolation returns the exact mode-specific synthetic transaction properties.
func (t *memoryAdministrationTransaction) Isolation(context.Context) (string, bool, error) {
	if t.mode == AdministrationSnapshot {
		return repeatableReadIsolation, true, nil
	}
	return serializableIsolation, false, nil
}

// ReadLock returns the synthetic singleton lock.
func (t *memoryAdministrationTransaction) ReadLock(_ context.Context, locked bool) (uint64, *string, error) {
	t.backend.lockReads = append(t.backend.lockReads, locked)
	if locked {
		t.backend.events = append(t.backend.events, "singleton_lock")
	}
	if !locked && t.backend.driftOnRead {
		return t.state.lockRevision, cloneNullableText(t.backend.driftOwner), nil
	}
	return t.state.lockRevision, cloneNullableText(t.state.lockOwner), nil
}

// ReadCurrentOptional returns the synthetic current root and pointer digest.
func (t *memoryAdministrationTransaction) ReadCurrentOptional(_ context.Context, locked bool) (MetadataRow, bool, error) {
	if locked {
		t.backend.events = append(t.backend.events, "current_lock")
	}
	if t.state.current == "" {
		return MetadataRow{}, false, nil
	}
	row := cloneMetadataRow(t.state.metadata[t.state.current])
	row.PointerDigest = append([]byte(nil), t.state.currentDigest...)
	return row, true, nil
}

// LockCandidateRoot records one exact synthetic candidate-root lock.
func (t *memoryAdministrationTransaction) LockCandidateRoot(
	ctx context.Context,
	fence CandidateRootFence,
) (MetadataRow, error) {
	t.backend.events = append(t.backend.events, "candidate_root_lock")
	row, found := t.state.metadata[fence.Generation()]
	matched := false
	accessErr := fence.WithProtectedValues(ctx, func(operation string, digest []byte) error {
		matched = found && row.OperationID != nil && *row.OperationID == operation &&
			string(row.CandidateDigest) == string(digest) &&
			t.state.lockRevision == fence.Revision() &&
			t.state.lockOwner != nil && *t.state.lockOwner == operation
		return nil
	})
	if accessErr != nil {
		return MetadataRow{}, accessErr
	}
	if !matched {
		return MetadataRow{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	return cloneMetadataRow(row), nil
}

// GenerationPage returns one sorted synthetic metadata page.
func (t *memoryAdministrationTransaction) GenerationPage(_ context.Context, after string, limit int, _ bool) ([]MetadataRow, error) {
	keys := make([]int, 0, len(t.state.metadata))
	for key := range t.state.metadata {
		value, _ := strconv.Atoi(key)
		keys = append(keys, value)
	}
	sort.Ints(keys)
	afterValue, _ := strconv.Atoi(after)
	output := make([]MetadataRow, 0, limit)
	for _, value := range keys {
		if value > afterValue && len(output) < limit {
			output = append(output, cloneMetadataRow(t.state.metadata[strconv.Itoa(value)]))
		}
	}
	return output, nil
}

// HandlePageFor returns one synthetic handle page.
func (t *memoryAdministrationTransaction) HandlePageFor(_ context.Context, generation, after string, limit int) ([]HandleRow, error) {
	if t.mode == AdministrationActivation && after == "" {
		t.backend.events = append(t.backend.events, "candidate_readback")
	}
	rows := append([]HandleRow(nil), t.state.rows[generation].Handles...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].HandleID < rows[j].HandleID })
	return filterHandles(rows, after, limit), nil
}

// ProfilePageFor returns one synthetic profile page.
func (t *memoryAdministrationTransaction) ProfilePageFor(_ context.Context, generation, after string, limit int) ([]ProfileRow, error) {
	rows := append([]ProfileRow(nil), t.state.rows[generation].Profiles...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].ProfileID < rows[j].ProfileID })
	output := make([]ProfileRow, 0, limit)
	for _, row := range rows {
		if row.ProfileID > after && len(output) < limit {
			output = append(output, row)
		}
	}
	return output, nil
}

// CredentialPageFor returns one synthetic credential page.
func (t *memoryAdministrationTransaction) CredentialPageFor(_ context.Context, generation, profile, algorithm string, limit int) ([]CredentialRow, error) {
	rows := cloneDatasetRows(t.state.rows[generation]).Credentials
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].ProfileID < rows[j].ProfileID || rows[i].ProfileID == rows[j].ProfileID && rows[i].Algorithm < rows[j].Algorithm
	})
	output := make([]CredentialRow, 0, limit)
	for _, row := range rows {
		if row.ProfileID > profile || row.ProfileID == profile && row.Algorithm > algorithm {
			if len(output) < limit {
				output = append(output, row)
			}
		}
	}
	return output, nil
}

// PolicyPageFor returns one synthetic policy page.
func (t *memoryAdministrationTransaction) PolicyPageFor(_ context.Context, generation, tenant, domain, use string, limit int) ([]PolicyRow, error) {
	rows := append([]PolicyRow(nil), t.state.rows[generation].Policies...)
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		return a.TenantID+"\x00"+a.Domain+"\x00"+a.Use < b.TenantID+"\x00"+b.Domain+"\x00"+b.Use
	})
	output := make([]PolicyRow, 0, limit)
	for _, row := range rows {
		if tupleGreater(row.TenantID, row.Domain, row.Use, tenant, domain, use) && len(output) < limit {
			output = append(output, row)
		}
	}
	return output, nil
}

// KeyMaterialPageFor returns one synthetic private-key page.
func (t *memoryAdministrationTransaction) KeyMaterialPageFor(_ context.Context, generation, after string, limit int) ([]KeyMaterialRow, error) {
	rows := cloneDatasetRows(t.state.rows[generation]).KeyMaterial
	sort.Slice(rows, func(i, j int) bool { return rows[i].HandleID < rows[j].HandleID })
	output := make([]KeyMaterialRow, 0, limit)
	for _, row := range rows {
		if row.HandleID > after && len(output) < limit {
			output = append(output, row)
		}
	}
	return output, nil
}

// ClaimLock claims one exact synthetic revision.
func (t *memoryAdministrationTransaction) ClaimLock(_ context.Context, revision uint64, owner string) (int64, error) {
	if t.state.lockRevision != revision || t.state.lockOwner != nil {
		return 0, nil
	}
	t.state.lockOwner = &owner
	return 1, nil
}

// ReleaseLock releases one exact synthetic revision.
func (t *memoryAdministrationTransaction) ReleaseLock(_ context.Context, revision uint64, owner string) (int64, error) {
	if t.state.lockRevision != revision || t.state.lockOwner == nil || *t.state.lockOwner != owner {
		return 0, nil
	}
	t.state.lockRevision++
	t.state.lockOwner = nil
	return 1, nil
}

// InsertGeneration inserts one synthetic v3 root.
func (t *memoryAdministrationTransaction) InsertGeneration(_ context.Context, row MetadataRow) error {
	if _, found := t.state.metadata[row.Generation]; found {
		return errors.New("duplicate")
	}
	t.state.metadata[row.Generation] = cloneMetadataRow(row)
	return nil
}

// InsertRows inserts one complete synthetic candidate.
func (t *memoryAdministrationTransaction) InsertRows(_ context.Context, rows DatasetRows) error {
	t.state.rows[rows.Current.Generation] = cloneDatasetRows(rows)
	return nil
}

// SealGeneration seals one exact synthetic candidate.
func (t *memoryAdministrationTransaction) SealGeneration(_ context.Context, generation, operation string, digest []byte) (int64, error) {
	row, found := t.state.metadata[generation]
	if !found || row.OperationID == nil || *row.OperationID != operation || string(row.CandidateDigest) != string(digest) || row.DatasetState != datasetStateStaging {
		return 0, nil
	}
	row.DatasetState = datasetStateCommitted
	t.state.metadata[generation] = row
	return 1, nil
}

// ActivateCurrent performs one synthetic exact pointer transition.
func (t *memoryAdministrationTransaction) ActivateCurrent(
	ctx context.Context,
	current CurrentPointerFence,
	candidate CandidateRootFence,
) (int64, error) {
	t.backend.events = append(t.backend.events, "mutation")
	root, found := t.state.metadata[candidate.Generation()]
	matched := false
	var selectedDigest []byte
	accessErr := candidate.WithProtectedValues(ctx, func(operation string, digest []byte) error {
		return current.WithPointerDigest(ctx, func(pointerDigest []byte) error {
			matched = found && root.OperationID != nil && *root.OperationID == operation &&
				string(root.CandidateDigest) == string(digest) &&
				root.DatasetState == datasetStateCommitted &&
				t.state.lockRevision == candidate.Revision() && t.state.lockOwner != nil &&
				*t.state.lockOwner == operation &&
				(t.state.current == "" || t.state.current == current.Generation()) &&
				string(t.state.currentDigest) == string(pointerDigest)
			selectedDigest = append([]byte(nil), digest...)
			return nil
		})
	})
	defer clear(selectedDigest)
	if accessErr != nil || !matched {
		return 0, nil
	}
	if current.Generation() != "0" {
		old := t.state.metadata[current.Generation()]
		old.WasActive = true
		t.state.metadata[current.Generation()] = old
	}
	t.state.current = candidate.Generation()
	t.state.currentDigest = append([]byte(nil), selectedDigest...)
	return 1, nil
}

// Commit publishes the synthetic transaction copy or returns an ambiguous failure.
func (t *memoryAdministrationTransaction) Commit(context.Context) error {
	t.backend.commits++
	if t.backend.failCommit {
		return errors.New("ambiguous")
	}
	copyAdministrationMemory(t.backend, t.state)
	t.closed = true
	return nil
}

// Rollback closes one incomplete synthetic transaction.
func (t *memoryAdministrationTransaction) Rollback(context.Context) error {
	t.closed = true
	return nil
}

// TestAdministratorEndToEndAndIdempotency proves lock, stage, bootstrap,
// established rotation, already-active history, and same-operation replay.
func TestAdministratorEndToEndAndIdempotency(t *testing.T) {
	administrator, backend := newMemoryAdministrator(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	first := testCandidate(t, 1, testOperationOne)
	defer first.Close() //nolint:errcheck // Test cleanup has no recovery action.
	operationOne, _ := datasourceadmin.NewOperationBinding(testOperationOne)
	lock, err := administrator.Claim(ctx, operationOne, 1)
	if err != nil {
		t.Fatal("claim first lock")
	}
	staged, err := administrator.Stage(ctx, lock, operationOne, first)
	if err != nil || backend.current != "" {
		t.Fatalf("stage changed current or failed: %s", datasourceadmin.CodeOf(err))
	}
	if _, err := administrator.Stage(ctx, lock, operationOne, first); err != nil {
		t.Fatal("same candidate replay was not idempotent")
	}
	activation, _ := datasourceadmin.NewActivation(lock, operationOne, 0, 1, first.PreparedEvidence(), staged)
	if err := administrator.Activate(ctx, activation); err != nil || backend.current != "1" {
		t.Fatal("bootstrap activation failed")
	}
	if next, err := administrator.Release(ctx, lock); err != nil || next != 2 {
		t.Fatal("release first lock")
	}

	second := testCandidate(t, 2, testOperationTwo)
	defer second.Close() //nolint:errcheck // Test cleanup has no recovery action.
	operationTwo, _ := datasourceadmin.NewOperationBinding(testOperationTwo)
	lockTwo, _ := administrator.Claim(ctx, operationTwo, 2)
	stagedTwo, err := administrator.Stage(ctx, lockTwo, operationTwo, second)
	if err != nil {
		t.Fatal("stage second generation")
	}
	activationTwo, _ := datasourceadmin.NewActivation(lockTwo, operationTwo, 1, 2, second.PreparedEvidence(), stagedTwo)
	if err := administrator.Activate(ctx, activationTwo); err != nil || backend.current != "2" || !backend.metadata["1"].WasActive {
		t.Fatal("first established rotation failed")
	}
	_, _ = administrator.Release(ctx, lockTwo)

	current := backend.metadata["2"]
	current.WasActive = true
	backend.metadata["2"] = current
	third := testCandidate(t, 3, testOperationThree)
	defer third.Close() //nolint:errcheck // Test cleanup has no recovery action.
	operationThree, _ := datasourceadmin.NewOperationBinding(testOperationThree)
	lockThree, _ := administrator.Claim(ctx, operationThree, 3)
	stagedThree, _ := administrator.Stage(ctx, lockThree, operationThree, third)
	activationThree, _ := datasourceadmin.NewActivation(lockThree, operationThree, 2, 3, third.PreparedEvidence(), stagedThree)
	if err := administrator.Activate(ctx, activationThree); err != nil || backend.current != "3" || !backend.metadata["2"].WasActive {
		t.Fatal("already-active current rotation failed")
	}
}

// TestAdministratorMismatchTamperAndAmbiguousCommitFailClosed proves wrong
// operation, private readback corruption, and commit uncertainty never retry.
func TestAdministratorMismatchTamperAndAmbiguousCommitFailClosed(t *testing.T) {
	administrator, backend := newMemoryAdministrator(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	candidate := testCandidate(t, 1, testOperationOne)
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery action.
	operation, _ := datasourceadmin.NewOperationBinding(testOperationOne)
	lock, _ := administrator.Claim(ctx, operation, 1)
	backend.failCommit = true
	if _, err := administrator.Stage(ctx, lock, operation, candidate); datasourceadmin.CodeOf(err) != datasourceadmin.CodeReconcileRequired || backend.commits != 2 {
		t.Fatalf("ambiguous stage commit was retried or misclassified: %s commits=%d", datasourceadmin.CodeOf(err), backend.commits)
	}
	backend.failCommit = false
	if _, err := administrator.Stage(ctx, lock, operation, candidate); err != nil {
		t.Fatal("stage after reconciled absence")
	}
	rows := backend.rows["1"]
	rows.KeyMaterial[0].PrivatePKCS8[0] ^= 1
	backend.rows["1"] = rows
	if _, _, err := administrator.Inspect(ctx, operation, 1, 0, testGenerationLimits()); err == nil {
		t.Fatal("private-key readback tamper was accepted")
	}
	wrong, _ := datasourceadmin.NewOperationBinding(testOperationTwo)
	if _, err := administrator.Stage(ctx, lock, wrong, candidate); datasourceadmin.CodeOf(err) != datasourceadmin.CodeInvalid {
		t.Fatal("wrong-operation stage was accepted")
	}
}

// TestAdministratorRejectsMalformedCurrentPointerMetadata proves inventory,
// current read, and activation never heal or accept v2/v3 pointer ambiguity.
func TestAdministratorRejectsMalformedCurrentPointerMetadata(t *testing.T) {
	for _, test := range []struct {
		name       string
		version    string
		operation  *string
		rootDigest []byte
		pointer    []byte
	}{
		{
			name: "v2 pointer must be absent", version: datasourceadmin.SchemaVersionV2,
			pointer: nonzeroDigest(1),
		},
		{
			name: "v3 pointer must equal root", version: datasourceadmin.SchemaVersionV3,
			operation: operationPointer(testOperationOne), rootDigest: nonzeroDigest(2),
			pointer: nonzeroDigest(3),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			administrator, backend := newMemoryAdministrator(t)
			backend.current = "1"
			backend.currentDigest = append([]byte(nil), test.pointer...)
			backend.metadata["1"] = MetadataRow{
				Generation: "1", SchemaVersion: test.version,
				DatasetState: datasetStateCommitted, OperationID: test.operation,
				CandidateDigest: append([]byte(nil), test.rootDigest...),
			}
			candidate := testCandidate(t, 2, testOperationTwo)
			defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery action.
			installCommittedCandidate(t, backend, candidate, testOperationTwo)
			owner := testOperationTwo
			backend.lockOwner = &owner
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := administrator.Inventory(ctx, testGenerationLimits()); datasourceadmin.CodeOf(err) != datasourceadmin.CodeConflict {
				t.Fatalf("inventory accepted malformed current pointer metadata: %s", datasourceadmin.CodeOf(err))
			}
			if snapshot, err := administrator.ReadCurrent(ctx, testGenerationLimits()); datasourceadmin.CodeOf(err) != datasourceadmin.CodeConflict {
				if snapshot != nil {
					_ = snapshot.Close()
				}
				t.Fatalf("current read accepted malformed pointer metadata: %s", datasourceadmin.CodeOf(err))
			}
			operation, _ := datasourceadmin.NewOperationBinding(testOperationTwo)
			lock, _ := datasourceadmin.NewAdministrationLock(operation, 1)
			staged := datasourceadmin.NewStagedEvidence(candidate.Digest())
			activation, _ := datasourceadmin.NewActivation(
				lock, operation, 1, 2, candidate.PreparedEvidence(), staged,
			)
			if err := administrator.Activate(ctx, activation); datasourceadmin.CodeOf(err) != datasourceadmin.CodeConflict {
				t.Fatalf("activation accepted malformed current pointer metadata: %s", datasourceadmin.CodeOf(err))
			}
			if backend.current != "1" || string(backend.currentDigest) != string(test.pointer) {
				t.Fatal("rejected current metadata was healed or mutated")
			}
		})
	}
}

// TestAdministratorActivationLocksCandidateBeforeReadbackAndMutation proves
// the root lock ordering that makes the complete digest readback stable.
func TestAdministratorActivationLocksCandidateBeforeReadbackAndMutation(t *testing.T) {
	administrator, backend := newMemoryAdministrator(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	candidate := testCandidate(t, 1, testOperationOne)
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery action.
	operation, _ := datasourceadmin.NewOperationBinding(testOperationOne)
	lock, _ := administrator.Claim(ctx, operation, 1)
	staged, err := administrator.Stage(ctx, lock, operation, candidate)
	if err != nil {
		t.Fatal("stage candidate")
	}
	backend.events = nil
	activation, _ := datasourceadmin.NewActivation(
		lock, operation, 0, 1, candidate.PreparedEvidence(), staged,
	)
	if err := administrator.Activate(ctx, activation); err != nil {
		t.Fatalf("activate candidate: %s", datasourceadmin.CodeOf(err))
	}
	want := []string{"singleton_lock", "current_lock", "candidate_root_lock", "candidate_readback", "mutation"}
	if len(backend.events) != len(want) {
		t.Fatalf("activation lock order = %v, want %v", backend.events, want)
	}
	for index := range want {
		if backend.events[index] != want[index] {
			t.Fatalf("activation lock order = %v, want %v", backend.events, want)
		}
	}
}

// TestAdministratorRejectsForeignOrMismatchedCandidateRootBeforeReadback
// proves exact locked metadata is required before protected content is read.
func TestAdministratorRejectsForeignOrMismatchedCandidateRootBeforeReadback(t *testing.T) {
	for _, test := range []struct {
		name   string
		tamper func(*MetadataRow)
	}{
		{
			name: "foreign operation",
			tamper: func(row *MetadataRow) {
				operation := testOperationTwo
				row.OperationID = &operation
			},
		},
		{
			name: "mismatched digest",
			tamper: func(row *MetadataRow) {
				row.CandidateDigest = nonzeroDigest(9)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			administrator, backend := newMemoryAdministrator(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			candidate := testCandidate(t, 1, testOperationOne)
			defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery action.
			operation, _ := datasourceadmin.NewOperationBinding(testOperationOne)
			lock, _ := administrator.Claim(ctx, operation, 1)
			staged, err := administrator.Stage(ctx, lock, operation, candidate)
			if err != nil {
				t.Fatal("stage candidate")
			}
			row := cloneMetadataRow(backend.metadata["1"])
			test.tamper(&row)
			backend.metadata["1"] = row
			backend.events = nil
			activation, _ := datasourceadmin.NewActivation(
				lock, operation, 0, 1, candidate.PreparedEvidence(), staged,
			)
			if err := administrator.Activate(ctx, activation); datasourceadmin.CodeOf(err) != datasourceadmin.CodeConflict {
				t.Fatalf("candidate-root mismatch misclassified: %s", datasourceadmin.CodeOf(err))
			}
			if len(backend.events) != 3 || backend.events[2] != "candidate_root_lock" {
				t.Fatalf("candidate-root mismatch crossed readback boundary: %v", backend.events)
			}
			if backend.current != "" {
				t.Fatal("candidate-root mismatch mutated current")
			}
		})
	}
}

// TestAdministratorPreservesActivationReadErrors proves authoritative
// conflicts remain distinct from cancellation or backend unavailability.
func TestAdministratorPreservesActivationReadErrors(t *testing.T) {
	administrator, backend := newMemoryAdministrator(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	candidate := testCandidate(t, 1, testOperationOne)
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery action.
	operation, _ := datasourceadmin.NewOperationBinding(testOperationOne)
	lock, _ := administrator.Claim(ctx, operation, 1)
	staged, err := administrator.Stage(ctx, lock, operation, candidate)
	if err != nil {
		t.Fatal("stage failure-taxonomy candidate")
	}
	activation, _ := datasourceadmin.NewActivation(
		lock, operation, 0, 1, candidate.PreparedEvidence(), staged,
	)
	for _, test := range []struct {
		name    string
		failure activationReadFailure
	}{
		{name: "physical lock", failure: failActivationReadLock},
		{name: "current lock", failure: failActivationReadCurrent},
		{name: "candidate root lock", failure: failActivationCandidateLock},
		{name: "full candidate readback", failure: failActivationCandidateReadback},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := memoryConnectorFor(backend, "failure_snapshot", AdministrationSnapshot)
			stager := memoryConnectorFor(backend, "failure_stager", AdministrationStaging)
			activator := memoryConnectorFor(backend, "failure_activator", AdministrationActivation)
			failing := failingActivationConnector{
				AdministrationConnector: activator, failure: test.failure,
			}
			candidateAdministrator, constructErr := NewAdministrator(
				snapshot, stager, failing, provider.DefaultLimits(), testGenerationLimits(), 2,
			)
			if constructErr != nil {
				t.Fatal("construct failure-taxonomy administrator")
			}
			defer candidateAdministrator.Close()
			if activateErr := candidateAdministrator.Activate(ctx, activation); datasourceadmin.CodeOf(activateErr) != datasourceadmin.CodeUnavailable {
				t.Fatalf("activation read failure misclassified: %s", datasourceadmin.CodeOf(activateErr))
			}
			if backend.current != "" {
				t.Fatal("activation read failure mutated current")
			}
		})
	}
}

// TestMapDatasetV3RequiresExactPointerDigestAndPrivateReadback proves runtime
// v3 validation binds the current pointer and canonical private content.
func TestMapDatasetV3RequiresExactPointerDigestAndPrivateReadback(t *testing.T) {
	candidate := testCandidate(t, 1, testOperationOne)
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery action.
	operation := testOperationOne
	metadata := MetadataRow{
		Generation: "1", SchemaVersion: datasourceadmin.SchemaVersionV3,
		DatasetState: datasetStateCommitted, OperationID: &operation,
		CandidateDigest: candidate.Digest().Bytes(), PointerDigest: candidate.Digest().Bytes(),
	}
	rows, err := candidateDatasetRows(t.Context(), candidate, metadata)
	if err != nil {
		t.Fatal("project candidate")
	}
	defer clearDatasetRows(&rows)
	if _, err := MapDataset(rows, provider.DefaultLimits()); err != nil {
		t.Fatal("exact v3 runtime dataset rejected")
	}
	rows.Final.PointerDigest[0] ^= 1
	if _, err := MapDataset(rows, provider.DefaultLimits()); err == nil {
		t.Fatal("pointer digest drift was accepted")
	}
}

// TestRecoveryGenerationLimitsRejectsExhaustedBudgetBeforeRead proves a
// metadata-near-exhausted recovery call cannot start another full snapshot.
func TestRecoveryGenerationLimitsRejectsExhaustedBudgetBeforeRead(t *testing.T) {
	base := testGenerationLimits()
	limited, ok := recoveryGenerationLimits(base, retentionReadBudget{remaining: 1})
	if !ok || limited.MaxSnapshotBytes != 1 {
		t.Fatal("one remaining byte was not passed as the pre-read snapshot limit")
	}
	if _, ok := recoveryGenerationLimits(base, retentionReadBudget{}); ok {
		t.Fatal("exhausted recovery budget started another generation read")
	}
}

// TestAdministratorRejectsAliasedAuthoritiesAndOutstandingCeiling proves
// construction-time role separation and bounded inactive-candidate allocation.
func TestAdministratorRejectsAliasedAuthoritiesAndOutstandingCeiling(t *testing.T) {
	backend := newAdministrationMemory()
	authority, _ := NewAdministrationAuthority("same_role")
	connector := memoryAdministrationConnector{backend: backend, mode: AdministrationSnapshot, authority: authority}
	if _, err := NewAdministrator(connector, connector, connector, provider.DefaultLimits(), testGenerationLimits(), 2); err == nil {
		t.Fatal("aliased administration authorities accepted")
	}
	administrator, bounded := newMemoryAdministrator(t)
	bounded.current = "1"
	bounded.metadata["1"] = MetadataRow{
		Generation: "1", SchemaVersion: datasourceadmin.SchemaVersionV2,
		DatasetState: datasetStateCommitted,
	}
	for generation := 2; generation <= int(testGenerationLimits().MaxOutstandingCandidates)+1; generation++ {
		operation := testOperationOne
		bounded.metadata[strconv.Itoa(generation)] = MetadataRow{
			Generation: strconv.Itoa(generation), SchemaVersion: datasourceadmin.SchemaVersionV3,
			DatasetState: datasetStateCommitted, OperationID: &operation, CandidateDigest: make([]byte, 32),
		}
		bounded.metadata[strconv.Itoa(generation)].CandidateDigest[0] = byte(generation)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	operation, _ := datasourceadmin.NewOperationBinding(testOperationTwo)
	lock, _ := datasourceadmin.NewAdministrationLock(operation, 1)
	owner := testOperationTwo
	bounded.lockOwner = &owner
	candidate := testCandidate(t, uint64(testGenerationLimits().MaxOutstandingCandidates)+2, testOperationTwo)
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery action.
	if _, err := administrator.Stage(ctx, lock, operation, candidate); datasourceadmin.CodeOf(err) != datasourceadmin.CodeLimitExceeded {
		t.Fatalf("outstanding candidate ceiling was not enforced: %s", datasourceadmin.CodeOf(err))
	}
}

// TestAdministratorStageRequiresExactPhysicalLock rejects ownerless and
// foreign singleton state before any candidate content is inserted.
func TestAdministratorStageRequiresExactPhysicalLock(t *testing.T) {
	foreignOwner := testOperationTwo
	for _, test := range []struct {
		name  string
		owner *string
	}{
		{name: "missing owner"},
		{name: "foreign owner", owner: &foreignOwner},
	} {
		t.Run(test.name, func(t *testing.T) {
			administrator, backend := newMemoryAdministrator(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			operation, _ := datasourceadmin.NewOperationBinding(testOperationOne)
			lock, _ := datasourceadmin.NewAdministrationLock(operation, 1)
			backend.lockOwner = cloneNullableText(test.owner)
			candidate := testCandidate(t, 1, testOperationOne)
			defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery action.
			if _, err := administrator.Stage(ctx, lock, operation, candidate); datasourceadmin.CodeOf(err) != datasourceadmin.CodeConflict {
				t.Fatalf("stage without exact physical lock was not rejected: %s", datasourceadmin.CodeOf(err))
			}
			if len(backend.metadata) != 0 || len(backend.rows) != 0 {
				t.Fatal("rejected stage inserted candidate content")
			}
		})
	}
}

// TestCollisionInventoryUsesStagerPhysicalLock proves collision reads run in
// one serializable staging transaction and recheck the owner before commit.
func TestCollisionInventoryUsesStagerPhysicalLock(t *testing.T) {
	administrator, backend := newMemoryAdministrator(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	operation, _ := datasourceadmin.NewOperationBinding(testOperationOne)
	lock, err := administrator.Claim(ctx, operation, 1)
	if err != nil {
		t.Fatal("claim collision inventory lock")
	}
	backend.beginModes = nil
	backend.lockReads = nil
	inventory, err := administrator.ReadCollisionInventory(ctx, lock, testGenerationLimits())
	if err != nil {
		t.Fatalf("read empty collision inventory: %s", datasourceadmin.CodeOf(err))
	}
	defer inventory.Close() //nolint:errcheck // Test cleanup has no recovery action.
	if len(backend.beginModes) != 1 || backend.beginModes[0] != AdministrationStaging {
		t.Fatal("collision inventory did not use the staging connector")
	}
	if len(backend.lockReads) != 2 || !backend.lockReads[0] || backend.lockReads[1] {
		t.Fatalf("collision inventory lock sequence was not physical-read then recheck: %v", backend.lockReads)
	}

	backend.beginModes = nil
	backend.lockReads = nil
	backend.driftOnRead = true
	foreignOwner := testOperationTwo
	backend.driftOwner = &foreignOwner
	if drifted, readErr := administrator.ReadCollisionInventory(ctx, lock, testGenerationLimits()); datasourceadmin.CodeOf(readErr) != datasourceadmin.CodeConflict {
		if drifted != nil {
			_ = drifted.Close()
		}
		t.Fatalf("collision inventory accepted lock drift: %s", datasourceadmin.CodeOf(readErr))
	}
}

// TestAdministratorRejectsOversizedPrivatePagesIncrementally proves private
// buffers are erased when either the page or shared byte ceiling is exceeded.
func TestAdministratorRejectsOversizedPrivatePagesIncrementally(t *testing.T) {
	administrator, _ := newMemoryAdministrator(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	base, err := administrator.stager.Begin(ctx, AdministrationStaging)
	if err != nil {
		t.Fatal("begin synthetic transaction")
	}
	tests := []struct {
		name       string
		page       []KeyMaterialRow
		limits     datasourceadmin.GenerationLimits
		wantErased bool
	}{
		{
			name: "page row count",
			page: []KeyMaterialRow{
				{HandleID: "a", PrivatePKCS8: []byte{1}},
				{HandleID: "b", PrivatePKCS8: []byte{2}},
				{HandleID: "c", PrivatePKCS8: []byte{3}},
			},
			limits:     testGenerationLimits(),
			wantErased: true,
		},
		{
			name: "shared bytes",
			page: []KeyMaterialRow{{
				HandleID: "a", PrivatePKCS8: make([]byte, 1024),
			}},
			limits: datasourceadmin.GenerationLimits{
				MaxGenerations: 16, MaxOutstandingCandidates: 2,
				MaxSnapshotRows: 64, MaxSnapshotBytes: 128,
				BackendDeadline: 2 * time.Second,
			},
			wantErased: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for index := range test.page {
				for octet := range test.page[index].PrivatePKCS8 {
					test.page[index].PrivatePKCS8[octet] = byte(index + 1)
				}
			}
			tx := &oversizedKeyPageTransaction{AdministrationTransaction: base, page: test.page}
			if rows, readErr := administrator.readRows(ctx, tx, "1", test.limits); datasourceadmin.CodeOf(readErr) != datasourceadmin.CodeLimitExceeded {
				clearDatasetRows(&rows)
				t.Fatalf("oversized private page misclassified: %s", datasourceadmin.CodeOf(readErr))
			}
			if test.wantErased {
				for _, row := range test.page {
					for _, octet := range row.PrivatePKCS8 {
						if octet != 0 {
							t.Fatal("rejected private page was not erased")
						}
					}
				}
			}
		})
	}
}

// newMemoryAdministrator constructs one shared synthetic three-role authority.
func newMemoryAdministrator(t *testing.T) (*Administrator, *administrationMemory) {
	t.Helper()
	backend := newAdministrationMemory()
	administrator, err := NewAdministrator(
		memoryConnectorFor(backend, "snapshot_role", AdministrationSnapshot),
		memoryConnectorFor(backend, "staging_role", AdministrationStaging),
		memoryConnectorFor(backend, "activation_role", AdministrationActivation),
		provider.DefaultLimits(), testGenerationLimits(), 2,
	)
	if err != nil {
		t.Fatal("construct memory administrator")
	}
	return administrator, backend
}

// memoryConnectorFor constructs one synthetic role-scoped connector.
func memoryConnectorFor(backend *administrationMemory, role string, mode AdministrationMode) memoryAdministrationConnector {
	authority, _ := NewAdministrationAuthority(role)
	return memoryAdministrationConnector{backend: backend, mode: mode, authority: authority}
}

// newAdministrationMemory constructs one empty ownerless backend.
func newAdministrationMemory() *administrationMemory {
	return &administrationMemory{lockRevision: 1, metadata: map[string]MetadataRow{}, rows: map[string]DatasetRows{}}
}

// testGenerationLimits returns finite administration bounds.
func testGenerationLimits() datasourceadmin.GenerationLimits {
	return datasourceadmin.GenerationLimits{MaxGenerations: 16, MaxOutstandingCandidates: 2, MaxSnapshotRows: 64, MaxSnapshotBytes: 1 << 20, BackendDeadline: 2 * time.Second}
}

// testCandidate constructs one complete canonical native-key candidate.
func testCandidate(t *testing.T, generation uint64, operation string) *datasourceadmin.PublicationEnvelope {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate candidate key")
	}
	spki, _ := x509.MarshalPKIXPublicKey(public)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(private)
	rows := datasourceadmin.Rows{
		Handles:     []datasourceadmin.HandleRow{{ID: testHandleID}},
		Profiles:    []datasourceadmin.ProfileRow{{ID: testProfileID, Domain: testDomain, Status: "active"}},
		Credentials: []datasourceadmin.CredentialRow{{ProfileID: testProfileID, Algorithm: "ed25519-sha256", Selector: "selector", PublicSPKI: spki, HandleID: testHandleID}},
		Policies:    []datasourceadmin.PolicyRow{{TenantID: "tenant", Domain: testDomain, Use: "originator", ProfileID: testProfileID, Status: "active", Rollout: "enforce", Compatibility: "strict"}},
		KeyMaterial: []datasourceadmin.KeyMaterialRow{{TenantID: "tenant", Domain: testDomain, Use: "originator", HandleID: testHandleID, Algorithm: "ed25519-sha256", PublicSPKI: spki, PrivatePKCS8: pkcs8}},
	}
	snapshot, err := datasourceadmin.NewSnapshot(datasourceadmin.SchemaVersionV3, generation, rows)
	if err != nil {
		t.Fatal("construct candidate snapshot")
	}
	content, err := datasourceadmin.NewCandidateContent(snapshot)
	if err != nil {
		t.Fatal("construct candidate content")
	}
	candidate, err := datasourceadmin.NewPublicationEnvelope(operation, content)
	if err != nil {
		_ = content.Close()
		t.Fatal("construct publication envelope")
	}
	return candidate
}

// installCommittedCandidate adds one exact committed synthetic candidate.
func installCommittedCandidate(
	t *testing.T,
	backend *administrationMemory,
	candidate *datasourceadmin.PublicationEnvelope,
	operation string,
) {
	t.Helper()
	metadata := MetadataRow{
		Generation:    strconv.FormatUint(candidate.Generation(), 10),
		SchemaVersion: datasourceadmin.SchemaVersionV3,
		DatasetState:  datasetStateCommitted, OperationID: &operation,
		CandidateDigest: candidate.Digest().Bytes(),
	}
	rows, err := candidateDatasetRows(t.Context(), candidate, metadata)
	if err != nil {
		t.Fatal("project committed candidate")
	}
	backend.metadata[metadata.Generation] = cloneMetadataRow(metadata)
	backend.rows[metadata.Generation] = cloneDatasetRows(rows)
	clearDatasetRows(&rows)
}

// nonzeroDigest returns one valid nonzero candidate-digest byte sequence.
func nonzeroDigest(marker byte) []byte {
	digest := make([]byte, 32)
	digest[0] = marker
	return digest
}

// operationPointer returns one detached operation pointer for test metadata.
func operationPointer(operation string) *string { return &operation }

// cloneAdministrationMemory deep-copies one synthetic backend transaction state.
func cloneAdministrationMemory(source *administrationMemory) *administrationMemory {
	result := newAdministrationMemory()
	copyAdministrationMemory(result, source)
	result.failCommit = source.failCommit
	return result
}

// copyAdministrationMemory replaces one synthetic backend with a deep copy.
func copyAdministrationMemory(target, source *administrationMemory) {
	target.lockRevision = source.lockRevision
	target.lockOwner = cloneNullableText(source.lockOwner)
	target.current = source.current
	target.currentDigest = append([]byte(nil), source.currentDigest...)
	target.metadata = map[string]MetadataRow{}
	target.rows = map[string]DatasetRows{}
	for key, row := range source.metadata {
		target.metadata[key] = cloneMetadataRow(row)
	}
	for key, rows := range source.rows {
		target.rows[key] = cloneDatasetRows(rows)
	}
}

// cloneMetadataRow detaches one synthetic metadata row.
func cloneMetadataRow(row MetadataRow) MetadataRow {
	row.OperationID = cloneNullableText(row.OperationID)
	row.CandidateDigest = append([]byte(nil), row.CandidateDigest...)
	row.PointerDigest = append([]byte(nil), row.PointerDigest...)
	return row
}

// cloneDatasetRows detaches one complete synthetic generation.
func cloneDatasetRows(rows DatasetRows) DatasetRows {
	result := rows
	result.Current = cloneMetadataRow(rows.Current)
	result.Final = cloneMetadataRow(rows.Final)
	result.Handles = append([]HandleRow(nil), rows.Handles...)
	result.Profiles = append([]ProfileRow(nil), rows.Profiles...)
	result.Credentials = append([]CredentialRow(nil), rows.Credentials...)
	for index := range result.Credentials {
		result.Credentials[index].PublicKeySPKI = append([]byte(nil), rows.Credentials[index].PublicKeySPKI...)
	}
	result.Policies = append([]PolicyRow(nil), rows.Policies...)
	result.KeyMaterial = append([]KeyMaterialRow(nil), rows.KeyMaterial...)
	for index := range result.KeyMaterial {
		result.KeyMaterial[index].PublicSPKI = append([]byte(nil), rows.KeyMaterial[index].PublicSPKI...)
		result.KeyMaterial[index].PrivatePKCS8 = append([]byte(nil), rows.KeyMaterial[index].PrivatePKCS8...)
	}
	return result
}

// filterHandles returns one bounded keyset page.
func filterHandles(rows []HandleRow, after string, limit int) []HandleRow {
	output := make([]HandleRow, 0, limit)
	for _, row := range rows {
		if row.HandleID > after && len(output) < limit {
			output = append(output, row)
		}
	}
	return output
}
