package sqlsnapshot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

const administratorRedacted = "sql_snapshot_administrator{redacted}"

// AdministrationMode identifies one closed SQL role and transaction purpose.
type AdministrationMode uint8

const (
	// AdministrationSnapshot opens one stable read-only authority.
	AdministrationSnapshot AdministrationMode = iota + 1
	// AdministrationStaging opens one serializable staging authority.
	AdministrationStaging
	// AdministrationActivation opens one serializable activation authority.
	AdministrationActivation
)

// AdministrationAuthority is one opaque canonical SQL role identity.
type AdministrationAuthority struct {
	digest      [sha256.Size]byte
	initialized bool
}

// NewAdministrationAuthority derives a protected identity from one canonical role.
func NewAdministrationAuthority(role string) (AdministrationAuthority, error) {
	if !validAdministrationRole(role) {
		return AdministrationAuthority{}, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	digest := sha256.Sum256([]byte("dkim2 sql administration authority v1\x00" + role))
	return AdministrationAuthority{digest: digest, initialized: true}, nil
}

// validAdministrationRole accepts one bounded canonical effective SQL identity.
func validAdministrationRole(role string) bool {
	if role == "" || len(role) > 256 || strings.TrimSpace(role) != role ||
		strings.ContainsRune(role, '\x00') {
		return false
	}
	for index, character := range role {
		if character >= 'a' && character <= 'z' || character == '_' || character == '-' ||
			index > 0 && character >= '0' && character <= '9' ||
			index > 0 && (character == '@' || character == '%' || character == '.' || character == ':') {
			continue
		}
		return false
	}
	return true
}

// Valid reports whether the authority owns a canonical role identity.
func (a AdministrationAuthority) Valid() bool { return a.initialized }

// Equal reports whether two initialized authorities are identical.
func (a AdministrationAuthority) Equal(other AdministrationAuthority) bool {
	return a.initialized && other.initialized &&
		subtle.ConstantTimeCompare(a.digest[:], other.digest[:]) == 1
}

// String returns a constant protected representation.
func (AdministrationAuthority) String() string { return administratorRedacted }

// GoString returns a constant protected Go representation.
func (AdministrationAuthority) GoString() string { return administratorRedacted }

// Format prevents role identities from reaching formatting sinks.
func (AdministrationAuthority) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, administratorRedacted)
}

// MarshalJSON rejects generic authority serialization.
func (AdministrationAuthority) MarshalJSON() ([]byte, error) {
	return nil, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
}

// AdministrationConnector opens transactions under one immutable SQL role.
type AdministrationConnector interface {
	Authority() AdministrationAuthority
	Begin(context.Context, AdministrationMode) (AdministrationTransaction, error)
	Close()
}

// AdministrationTransaction exposes only fixed provider-neutral SQL actions.
type AdministrationTransaction interface {
	Isolation(context.Context) (string, bool, error)
	ReadLock(context.Context, bool) (uint64, *string, error)
	ReadCurrentOptional(context.Context, bool) (MetadataRow, bool, error)
	LockCandidateRoot(context.Context, CandidateRootFence) (MetadataRow, error)
	GenerationPage(context.Context, string, int, bool) ([]MetadataRow, error)
	HandlePageFor(context.Context, string, string, int) ([]HandleRow, error)
	ProfilePageFor(context.Context, string, string, int) ([]ProfileRow, error)
	CredentialPageFor(context.Context, string, string, string, int) ([]CredentialRow, error)
	PolicyPageFor(context.Context, string, string, string, string, int) ([]PolicyRow, error)
	KeyMaterialPageFor(context.Context, string, string, int) ([]KeyMaterialRow, error)
	ClaimLock(context.Context, uint64, string) (int64, error)
	ReleaseLock(context.Context, uint64, string) (int64, error)
	InsertGeneration(context.Context, MetadataRow) error
	InsertRows(context.Context, DatasetRows) error
	SealGeneration(context.Context, string, string, []byte) (int64, error)
	ActivateCurrent(context.Context, CurrentPointerFence, CandidateRootFence) (int64, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// CurrentPointerFence owns one exact absent, v2-null, or v3-digest current fence.
type CurrentPointerFence struct {
	generation    string
	pointerDigest []byte
}

// Generation returns the exact decimal current generation or zero bootstrap fence.
func (f CurrentPointerFence) Generation() string { return f.generation }

// WithPointerDigest supplies a detached digest to one bounded provider callback.
func (f CurrentPointerFence) WithPointerDigest(ctx context.Context, use func([]byte) error) error {
	if ctx == nil || use == nil || ctx.Err() != nil || !validCurrentFenceGeneration(f.generation) {
		return datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	digest := append([]byte(nil), f.pointerDigest...)
	defer clear(digest)
	if err := use(digest); err != nil {
		return datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return nil
}

// String returns a constant protected current-pointer fence representation.
func (CurrentPointerFence) String() string { return administratorRedacted }

// GoString returns a constant protected current-pointer fence representation.
func (CurrentPointerFence) GoString() string { return administratorRedacted }

// Format prevents current-pointer metadata from reaching formatting sinks.
func (CurrentPointerFence) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, administratorRedacted)
}

// MarshalJSON rejects generic current-pointer fence serialization.
func (CurrentPointerFence) MarshalJSON() ([]byte, error) {
	return nil, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
}

// CandidateRootFence owns exact operation, digest, and administration-lock facts.
type CandidateRootFence struct {
	generation string
	operation  string
	digest     []byte
	revision   uint64
}

// Generation returns the exact decimal candidate generation.
func (f CandidateRootFence) Generation() string { return f.generation }

// Revision returns the exact administration-lock revision.
func (f CandidateRootFence) Revision() uint64 { return f.revision }

// WithProtectedValues supplies operation and detached digest to one bounded provider callback.
func (f CandidateRootFence) WithProtectedValues(
	ctx context.Context,
	use func(string, []byte) error,
) error {
	if ctx == nil || use == nil || ctx.Err() != nil || f.revision == 0 {
		return datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	if _, err := parseGeneration(f.generation); err != nil {
		return datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	if _, err := datasourceadmin.NewOperationBinding(f.operation); err != nil {
		return datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	if _, err := datasourceadmin.ParseCandidateContentDigest(f.digest); err != nil {
		return datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	digest := append([]byte(nil), f.digest...)
	defer clear(digest)
	if err := use(f.operation, digest); err != nil {
		return datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return nil
}

// String returns a constant protected candidate-root fence representation.
func (CandidateRootFence) String() string { return administratorRedacted }

// GoString returns a constant protected candidate-root fence representation.
func (CandidateRootFence) GoString() string { return administratorRedacted }

// Format prevents candidate-root metadata from reaching formatting sinks.
func (CandidateRootFence) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, administratorRedacted)
}

// MarshalJSON rejects generic candidate-root fence serialization.
func (CandidateRootFence) MarshalJSON() ([]byte, error) {
	return nil, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
}

// validCurrentFenceGeneration accepts bootstrap zero or one canonical generation.
func validCurrentFenceGeneration(generation string) bool {
	if generation == "0" {
		return true
	}
	_, err := parseGeneration(generation)
	return err == nil
}

// Administrator owns common bounded SQL snapshot, stage, and activation semantics.
type Administrator struct {
	snapshot    AdministrationConnector
	stager      AdministrationConnector
	activator   AdministrationConnector
	limits      provider.Limits
	generations datasourceadmin.GenerationLimits
	pageSize    int
}

// NewAdministrator validates distinct role authorities and finite SQL bounds.
func NewAdministrator(
	snapshot AdministrationConnector,
	stager AdministrationConnector,
	activator AdministrationConnector,
	limits provider.Limits,
	generations datasourceadmin.GenerationLimits,
	pageSize int,
) (*Administrator, error) {
	if snapshot == nil || stager == nil || activator == nil || limits.Validate() != nil ||
		generations.Validate() != nil || pageSize <= 0 || pageSize > 256 {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	readAuthority, stageAuthority, activateAuthority :=
		snapshot.Authority(), stager.Authority(), activator.Authority()
	if !readAuthority.Valid() || !stageAuthority.Valid() || !activateAuthority.Valid() ||
		readAuthority.Equal(stageAuthority) || readAuthority.Equal(activateAuthority) ||
		stageAuthority.Equal(activateAuthority) {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	return &Administrator{
		snapshot: snapshot, stager: stager, activator: activator,
		limits: limits, generations: generations, pageSize: pageSize,
	}, nil
}

// ReadCurrent returns one stable complete current generation.
func (a *Administrator) ReadCurrent(
	ctx context.Context,
	limits datasourceadmin.GenerationLimits,
) (*datasourceadmin.Snapshot, error) {
	tx, finish, err := a.begin(ctx, a.snapshot, AdministrationSnapshot, limits)
	if err != nil {
		return nil, err
	}
	defer finish(false)
	inventory, metadata, err := a.readInventory(ctx, tx, limits, false)
	if err != nil || inventory.Current == 0 {
		return nil, administrationReadError(err)
	}
	snapshot, _, err := a.readGeneration(ctx, tx, metadata.Generation, limits)
	if err != nil {
		return nil, err
	}
	final, present, err := tx.ReadCurrentOptional(ctx, false)
	if err != nil || !present || !metadataEqual(metadata, final) {
		_ = snapshot.Close()
		return nil, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	if _, err := validateCurrentMetadata(final); err != nil {
		_ = snapshot.Close()
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		_ = snapshot.Close()
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	finish(true)
	return snapshot, nil
}

// Inventory returns one stable bounded generation inventory.
func (a *Administrator) Inventory(
	ctx context.Context,
	limits datasourceadmin.GenerationLimits,
) (datasourceadmin.Inventory, error) {
	tx, finish, err := a.begin(ctx, a.snapshot, AdministrationSnapshot, limits)
	if err != nil {
		return datasourceadmin.Inventory{}, err
	}
	defer finish(false)
	inventory, _, err := a.readInventory(ctx, tx, limits, false)
	if err != nil {
		return datasourceadmin.Inventory{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return datasourceadmin.Inventory{}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	finish(true)
	return inventory, nil
}

// RetentionRecoveryInventory reads and verifies complete historical evidence without allocation ceilings.
func (a *Administrator) RetentionRecoveryInventory(ctx context.Context) (datasourceadmin.RetentionInventory, error) {
	if a == nil || ctx == nil || ctx.Err() != nil { return datasourceadmin.RetentionInventory{}, datasourceadmin.NewError(datasourceadmin.CodeInvalid) }
	tx, finish, err := a.begin(ctx, a.snapshot, AdministrationSnapshot, a.generations)
	if err != nil { return datasourceadmin.RetentionInventory{}, err }
	defer finish(false)
	current, present, err := tx.ReadCurrentOptional(ctx, false)
	if err != nil || !present || validateCurrentRetentionMetadata(current) != nil { return datasourceadmin.RetentionInventory{}, datasourceadmin.NewError(datasourceadmin.CodeConflict) }
	currentGeneration, err := parseGeneration(current.Generation)
	if err != nil { return datasourceadmin.RetentionInventory{}, datasourceadmin.NewError(datasourceadmin.CodeConflict) }
	rows := make([]datasourceadmin.RetentionGeneration, 0)
	cursor := ""
	for {
		page, pageErr := tx.GenerationPage(ctx, cursor, 1024, false)
		if pageErr != nil { return datasourceadmin.RetentionInventory{}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable) }
		if len(page) == 0 { break }
		if len(page) > 1024 || len(rows)+len(page) > 16384 { return datasourceadmin.RetentionInventory{}, datasourceadmin.NewError(datasourceadmin.CodeLimitExceeded) }
		for _, metadata := range page {
			if compareGenerationText(metadata.Generation, cursor) <= 0 { return datasourceadmin.RetentionInventory{}, datasourceadmin.NewError(datasourceadmin.CodeConflict) }
			snapshot, verified, readErr := a.readGeneration(ctx, tx, metadata.Generation, a.generations)
			if readErr != nil || !metadataEqual(metadata, verified) { _ = snapshot.Close(); return datasourceadmin.RetentionInventory{}, datasourceadmin.NewError(datasourceadmin.CodeConflict) }
			_ = snapshot.Close()
			info, mapErr := generationInfoFromMetadata(verified, verified.Generation == current.Generation)
			if mapErr != nil { return datasourceadmin.RetentionInventory{}, mapErr }
			row := datasourceadmin.RetentionGeneration{Generation: info.Generation, Operation: info.Operation, SourceGeneration: info.SourceGeneration, Schema: info.Schema, State: info.State, WasActive: info.WasActive, Ownership: datasourceadmin.RetentionOwnershipTrusted}
			if info.Schema == datasourceadmin.SchemaVersionV3 && info.ContentDigest.Valid() {
				digest, digestErr := admincontract.ParseDigest(info.ContentDigest.Bytes()); if digestErr != nil { return datasourceadmin.RetentionInventory{}, datasourceadmin.NewError(datasourceadmin.CodeConflict) }
				row.ContentDigest, row.Complete = digest, true
			}
			rows = append(rows, row)
			cursor = metadata.Generation
		}
	}
	final, finalPresent, finalErr := tx.ReadCurrentOptional(ctx, false)
	if finalErr != nil || !finalPresent || !metadataEqual(current, final) { return datasourceadmin.RetentionInventory{}, datasourceadmin.NewError(datasourceadmin.CodeConflict) }
	if err := tx.Commit(ctx); err != nil { return datasourceadmin.RetentionInventory{}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable) }
	finish(true)
	return datasourceadmin.RetentionInventory{Version: "sqlsnapshot-recovery-v1", Current: currentGeneration, Generations: rows}, nil
}

// validateCurrentRetentionMetadata reuses the current fence while retaining a bounded error mapping.
func validateCurrentRetentionMetadata(metadata MetadataRow) error { _, err := validateCurrentMetadata(metadata); return err }

// Current returns the exact current classification or proven empty state.
func (a *Administrator) Current(
	ctx context.Context,
	limits datasourceadmin.GenerationLimits,
) (datasourceadmin.GenerationInfo, error) {
	inventory, err := a.Inventory(ctx, limits)
	if err != nil || inventory.Current == 0 {
		return datasourceadmin.GenerationInfo{}, err
	}
	for _, info := range inventory.Generations {
		if info.Current {
			return info, nil
		}
	}
	return datasourceadmin.GenerationInfo{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
}

// ObserveAdministrationLock reads one owner/revision sight without mutation.
func (a *Administrator) ObserveAdministrationLock(
	ctx context.Context,
) (datasourceadmin.AdministrationLockObservation, error) {
	tx, finish, err := a.begin(ctx, a.snapshot, AdministrationSnapshot, a.generations)
	if err != nil {
		return datasourceadmin.AdministrationLockObservation{}, err
	}
	defer finish(false)
	revision, owner, err := tx.ReadLock(ctx, false)
	if err != nil {
		return datasourceadmin.AdministrationLockObservation{}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	observation, err := lockObservation(revision, owner)
	if err != nil {
		return datasourceadmin.AdministrationLockObservation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return datasourceadmin.AdministrationLockObservation{}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	finish(true)
	return observation, nil
}

// Claim atomically acquires or confirms one exact ownerless revision.
func (a *Administrator) Claim(
	ctx context.Context,
	operation datasourceadmin.OperationBinding,
	revision uint64,
) (datasourceadmin.AdministrationLock, error) {
	if !operation.Initialized() || revision == 0 {
		return datasourceadmin.AdministrationLock{}, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	var operationText string
	if err := operation.WithValue(ctx, func(value string) error { operationText = value; return nil }); err != nil {
		return datasourceadmin.AdministrationLock{}, err
	}
	tx, finish, err := a.begin(ctx, a.stager, AdministrationStaging, a.generations)
	if err != nil {
		return datasourceadmin.AdministrationLock{}, err
	}
	defer finish(false)
	observedRevision, owner, err := tx.ReadLock(ctx, true)
	if err != nil {
		return datasourceadmin.AdministrationLock{}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	if owner != nil {
		if observedRevision != revision || *owner != operationText {
			return datasourceadmin.AdministrationLock{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		if err := tx.Commit(ctx); err != nil {
			return datasourceadmin.AdministrationLock{}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
		finish(true)
		return datasourceadmin.NewAdministrationLock(operation, revision)
	}
	if observedRevision != revision {
		return datasourceadmin.AdministrationLock{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	affected, err := tx.ClaimLock(ctx, revision, operationText)
	if err != nil || affected != 1 || tx.Commit(ctx) != nil {
		return datasourceadmin.AdministrationLock{}, datasourceadmin.NewError(datasourceadmin.CodeReconcileRequired)
	}
	finish(true)
	return datasourceadmin.NewAdministrationLock(operation, revision)
}

// Release clears only the exact owner and advances its revision once.
func (a *Administrator) Release(
	ctx context.Context,
	lock datasourceadmin.AdministrationLock,
) (uint64, error) {
	if !lock.ValidFor(lock.Owner()) || lock.Revision() == ^uint64(0) {
		return 0, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	var owner string
	if err := lock.Owner().WithValue(ctx, func(value string) error { owner = value; return nil }); err != nil {
		return 0, err
	}
	tx, finish, err := a.begin(ctx, a.stager, AdministrationStaging, a.generations)
	if err != nil {
		return 0, err
	}
	defer finish(false)
	revision, observedOwner, err := tx.ReadLock(ctx, true)
	next := lock.Revision() + 1
	if err != nil {
		return 0, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	if observedOwner == nil {
		if revision != next {
			return 0, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		if err := tx.Commit(ctx); err != nil {
			return 0, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
		finish(true)
		return next, nil
	}
	if revision != lock.Revision() || *observedOwner != owner {
		return 0, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	affected, err := tx.ReleaseLock(ctx, revision, owner)
	if err != nil || affected != 1 || tx.Commit(ctx) != nil {
		return 0, datasourceadmin.NewError(datasourceadmin.CodeReconcileRequired)
	}
	finish(true)
	return next, nil
}

// Stage writes, rereads, verifies, and seals one exact candidate without moving current.
func (a *Administrator) Stage(
	ctx context.Context,
	lock datasourceadmin.AdministrationLock,
	operation datasourceadmin.OperationBinding,
	candidate *datasourceadmin.PublicationEnvelope,
) (datasourceadmin.StagedEvidence, error) {
	if candidate == nil || !lock.ValidFor(operation) || !candidate.Binding().Equal(operation) ||
		candidate.Generation() == 0 || !candidate.Digest().Valid() {
		return datasourceadmin.StagedEvidence{}, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	tx, finish, err := a.begin(ctx, a.stager, AdministrationStaging, a.generations)
	if err != nil {
		return datasourceadmin.StagedEvidence{}, err
	}
	defer finish(false)
	if err := requireLock(ctx, tx, lock, true); err != nil {
		return datasourceadmin.StagedEvidence{}, err
	}
	inventory, _, err := a.readInventory(ctx, tx, a.generations, false)
	if err != nil {
		return datasourceadmin.StagedEvidence{}, err
	}
	var operationText string
	if err := operation.WithValue(ctx, func(value string) error { operationText = value; return nil }); err != nil {
		return datasourceadmin.StagedEvidence{}, err
	}
	generationText := strconv.FormatUint(candidate.Generation(), 10)
	existing, found := generationInfo(inventory, candidate.Generation())
	mutated := false
	if found {
		if existing.Current || !existing.Operation.Initialized() || !existing.Operation.Equal(operation) {
			return datasourceadmin.StagedEvidence{}, datasourceadmin.NewError(datasourceadmin.CodeReconcileRequired)
		}
	} else {
		allocated, allocateErr := datasourceadmin.AllocateGeneration(inventory, a.generations)
		if allocateErr != nil {
			return datasourceadmin.StagedEvidence{}, allocateErr
		}
		if allocated != candidate.Generation() {
			return datasourceadmin.StagedEvidence{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		metadata := MetadataRow{
			Generation: generationText, SchemaVersion: datasourceadmin.SchemaVersionV3,
			DatasetState: datasetStateStaging, OperationID: &operationText,
			CandidateDigest: candidate.Digest().Bytes(), SourceGeneration: strconv.FormatUint(candidate.SourceGeneration(), 10),
		}
		if candidate.SourceGeneration() == 0 {
			metadata.SourceGeneration = ""
		}
		rows, rowsErr := candidateDatasetRows(ctx, candidate, metadata)
		if rowsErr != nil {
			return datasourceadmin.StagedEvidence{}, rowsErr
		}
		defer clearDatasetRows(&rows)
		if err := tx.InsertGeneration(ctx, metadata); err != nil || tx.InsertRows(ctx, rows) != nil {
			return datasourceadmin.StagedEvidence{}, datasourceadmin.NewError(datasourceadmin.CodeReconcileRequired)
		}
		mutated = true
	}
	readback, metadata, err := a.readCandidate(ctx, tx, operation, generationText, a.generations)
	if err != nil {
		return datasourceadmin.StagedEvidence{}, err
	}
	if !readback.Digest().Equal(candidate.Digest()) {
		_ = readback.Close()
		return datasourceadmin.StagedEvidence{}, datasourceadmin.NewError(datasourceadmin.CodeReconcileRequired)
	}
	defer readback.Close() //nolint:errcheck // Protected readback cleanup has no recovery action.
	if metadata.DatasetState == datasetStateStaging {
		affected, sealErr := tx.SealGeneration(ctx, generationText, operationText, candidate.Digest().Bytes())
		if sealErr != nil || affected != 1 {
			return datasourceadmin.StagedEvidence{}, datasourceadmin.NewError(datasourceadmin.CodeReconcileRequired)
		}
		mutated = true
		sealed, sealedMetadata, sealedErr := a.readCandidate(ctx, tx, operation, generationText, a.generations)
		if sealedErr != nil {
			return datasourceadmin.StagedEvidence{}, sealedErr
		}
		if sealedMetadata.DatasetState != datasetStateCommitted || !sealed.Digest().Equal(candidate.Digest()) {
			_ = sealed.Close()
			return datasourceadmin.StagedEvidence{}, datasourceadmin.NewError(datasourceadmin.CodeReconcileRequired)
		}
		_ = sealed.Close()
	} else if metadata.DatasetState != datasetStateCommitted {
		return datasourceadmin.StagedEvidence{}, datasourceadmin.NewError(datasourceadmin.CodeReconcileRequired)
	}
	if err := tx.Commit(ctx); err != nil {
		code := datasourceadmin.CodeUnavailable
		if mutated {
			code = datasourceadmin.CodeReconcileRequired
		}
		return datasourceadmin.StagedEvidence{}, datasourceadmin.NewError(code)
	}
	finish(true)
	return datasourceadmin.NewStagedEvidence(candidate.Digest()), nil
}

// Inspect returns one complete exact candidate from stable readback.
func (a *Administrator) Inspect(
	ctx context.Context,
	operation datasourceadmin.OperationBinding,
	generation uint64,
	expectedCurrent uint64,
	limits datasourceadmin.GenerationLimits,
) (*datasourceadmin.PublicationEnvelope, datasourceadmin.GenerationInfo, error) {
	if !operation.Initialized() || generation == 0 || generation <= expectedCurrent {
		return nil, datasourceadmin.GenerationInfo{}, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	tx, finish, err := a.begin(ctx, a.snapshot, AdministrationSnapshot, limits)
	if err != nil {
		return nil, datasourceadmin.GenerationInfo{}, err
	}
	defer finish(false)
	inventory, _, err := a.readInventory(ctx, tx, limits, false)
	if err != nil || inventory.Current != expectedCurrent && inventory.Current != generation {
		return nil, datasourceadmin.GenerationInfo{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	info, found := generationInfo(inventory, generation)
	if !found {
		return nil, datasourceadmin.GenerationInfo{}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	candidate, _, err := a.readCandidate(ctx, tx, operation, strconv.FormatUint(generation, 10), limits)
	if err != nil {
		return nil, datasourceadmin.GenerationInfo{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		_ = candidate.Close()
		return nil, datasourceadmin.GenerationInfo{}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	finish(true)
	return candidate, info, nil
}

// Observe classifies one requested candidate from fresh authoritative readback.
func (a *Administrator) Observe(
	ctx context.Context,
	operation datasourceadmin.OperationBinding,
	generation uint64,
	expectedCurrent uint64,
	limits datasourceadmin.GenerationLimits,
) (datasourceadmin.PublicationObservation, error) {
	if !operation.Initialized() || generation == 0 || generation <= expectedCurrent {
		return datasourceadmin.PublicationObservation{}, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	tx, finish, err := a.begin(ctx, a.snapshot, AdministrationSnapshot, limits)
	if err != nil {
		return datasourceadmin.PublicationObservation{}, err
	}
	defer finish(false)
	inventory, _, err := a.readInventory(ctx, tx, limits, false)
	if err != nil || inventory.Current != expectedCurrent && inventory.Current != generation {
		return datasourceadmin.PublicationObservation{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	info, found := generationInfo(inventory, generation)
	if !found {
		return datasourceadmin.NewPublicationObservation(
			inventory.Current, generation, datasourceadmin.PublicationAbsent,
			datasourceadmin.OperationBinding{}, datasourceadmin.StagedEvidence{}, false,
		)
	}
	candidate, _, readErr := a.readCandidate(ctx, tx, operation, strconv.FormatUint(generation, 10), limits)
	if readErr != nil || candidate == nil || !info.Operation.Equal(operation) {
		return datasourceadmin.NewPublicationObservation(
			inventory.Current, generation, datasourceadmin.PublicationMismatch,
			datasourceadmin.OperationBinding{}, datasourceadmin.StagedEvidence{}, false,
		)
	}
	defer candidate.Close() //nolint:errcheck // Observation cleanup has no recovery action.
	state := datasourceadmin.PublicationExactCommitted
	if info.State == datasourceadmin.StateStaging {
		state = datasourceadmin.PublicationExactStaging
	}
	oldWasActive := false
	if expectedCurrent != 0 {
		old, present := generationInfo(inventory, expectedCurrent)
		if !present {
			return datasourceadmin.PublicationObservation{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		oldWasActive = old.WasActive
	}
	return datasourceadmin.NewPublicationObservation(
		inventory.Current, generation, state, operation,
		datasourceadmin.NewStagedEvidence(candidate.Digest()), oldWasActive,
	)
}

// Activate atomically marks established history and moves the current pointer.
func (a *Administrator) Activate(ctx context.Context, activation datasourceadmin.Activation) error {
	if !activation.Valid() {
		return datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	tx, finish, err := a.begin(ctx, a.activator, AdministrationActivation, a.generations)
	if err != nil {
		return err
	}
	defer finish(false)
	if err := requireLock(ctx, tx, activation.Lock(), true); err != nil {
		return err
	}
	current, present, err := tx.ReadCurrentOptional(ctx, true)
	if err != nil {
		return err
	}
	if present != (activation.ExpectedCurrent() != 0) {
		return datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	currentFence := CurrentPointerFence{generation: "0"}
	if present {
		currentFence, err = validateCurrentMetadata(current)
		if err != nil || currentFence.Generation() != strconv.FormatUint(activation.ExpectedCurrent(), 10) {
			return datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
	}
	var operationText string
	if err := activation.Operation().WithValue(ctx, func(value string) error {
		operationText = value
		return nil
	}); err != nil {
		return err
	}
	candidateFence, err := newCandidateRootFence(
		strconv.FormatUint(activation.CandidateGeneration(), 10), operationText,
		candidateDigestBytes(activation.Staged()), activation.Lock().Revision(),
	)
	if err != nil {
		return err
	}
	lockedMetadata, err := tx.LockCandidateRoot(ctx, candidateFence)
	if err != nil {
		return err
	}
	if validateCandidateRootMetadata(lockedMetadata, candidateFence) != nil {
		return datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	candidate, metadata, err := a.readCandidate(
		ctx, tx, activation.Operation(), strconv.FormatUint(activation.CandidateGeneration(), 10), a.generations,
	)
	if err != nil {
		return err
	}
	if !metadataEqual(lockedMetadata, metadata) ||
		metadata.DatasetState != datasetStateCommitted ||
		!activation.Prepared().Matches(datasourceadmin.NewStagedEvidence(candidate.Digest())) ||
		!activation.Staged().Digest().Equal(candidate.Digest()) {
		_ = candidate.Close()
		return datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	_ = candidate.Close()
	if activation.ExpectedCurrent() == 0 && activation.CandidateGeneration() != 1 {
		return datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	affected, mutationErr := tx.ActivateCurrent(ctx, currentFence, candidateFence)
	if mutationErr != nil || affected != 1 || tx.Commit(ctx) != nil {
		return datasourceadmin.NewError(datasourceadmin.CodeReconcileRequired)
	}
	finish(true)
	return nil
}

// candidateDigestBytes detaches one protected staged digest for SQL metadata.
func candidateDigestBytes(staged datasourceadmin.StagedEvidence) []byte {
	return staged.Digest().Bytes()
}

// newCandidateRootFence validates and owns exact candidate-lock arguments.
func newCandidateRootFence(
	generation string,
	operation string,
	digest []byte,
	revision uint64,
) (CandidateRootFence, error) {
	if _, err := parseGeneration(generation); err != nil || revision == 0 {
		return CandidateRootFence{}, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	if _, err := datasourceadmin.NewOperationBinding(operation); err != nil {
		return CandidateRootFence{}, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	if _, err := datasourceadmin.ParseCandidateContentDigest(digest); err != nil {
		return CandidateRootFence{}, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	return CandidateRootFence{
		generation: generation, operation: operation,
		digest: append([]byte(nil), digest...), revision: revision,
	}, nil
}

// validateCandidateRootMetadata binds one locked root to its exact fence.
func validateCandidateRootMetadata(row MetadataRow, fence CandidateRootFence) error {
	if row.Generation != fence.generation || row.SchemaVersion != datasourceadmin.SchemaVersionV3 ||
		row.DatasetState != datasetStateCommitted || row.OperationID == nil ||
		*row.OperationID != fence.operation || !bytes.Equal(row.CandidateDigest, fence.digest) ||
		len(row.PointerDigest) != 0 {
		return datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	if _, err := datasourceadmin.ParseCandidateContentDigest(row.CandidateDigest); err != nil {
		return datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	return nil
}

// ReadCollisionInventory returns current and outstanding identities under an unchanged lock.
func (a *Administrator) ReadCollisionInventory(
	ctx context.Context,
	lock datasourceadmin.AdministrationLock,
	limits datasourceadmin.GenerationLimits,
) (*datasourceadmin.CollisionInventory, error) {
	if !lock.ValidFor(lock.Owner()) {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	tx, finish, err := a.begin(ctx, a.stager, AdministrationStaging, limits)
	if err != nil {
		return nil, err
	}
	defer finish(false)
	if err := requireLock(ctx, tx, lock, true); err != nil {
		return nil, err
	}
	inventory, _, err := a.readInventory(ctx, tx, limits, false)
	if err != nil {
		return nil, err
	}
	snapshots := make([]datasourceadmin.CollisionSnapshot, 0)
	for _, info := range inventory.Generations {
		if !info.Current && !info.Outstanding() {
			continue
		}
		snapshot, _, readErr := a.readGeneration(ctx, tx, strconv.FormatUint(info.Generation, 10), limits)
		if readErr != nil {
			closeCollisionSnapshots(snapshots)
			return nil, readErr
		}
		snapshots = append(snapshots, datasourceadmin.CollisionSnapshot{Info: info, Snapshot: snapshot})
	}
	if err := requireLock(ctx, tx, lock, false); err != nil {
		closeCollisionSnapshots(snapshots)
		return nil, err
	}
	result, err := datasourceadmin.NewCollisionInventory(ctx, lock, inventory, snapshots, limits)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		_ = result.Close()
		return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	finish(true)
	return result, nil
}

// begin opens and proves one role-scoped bounded transaction.
func (a *Administrator) begin(
	ctx context.Context,
	connector AdministrationConnector,
	mode AdministrationMode,
	limits datasourceadmin.GenerationLimits,
) (AdministrationTransaction, func(bool), error) {
	if a == nil || connector == nil || limits.Validate() != nil || ctx == nil || ctx.Err() != nil {
		return nil, func(bool) {}, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	deadline, present := ctx.Deadline()
	if !present || time.Until(deadline) > limits.BackendDeadline {
		return nil, func(bool) {}, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	tx, err := connector.Begin(ctx, mode)
	if err != nil || tx == nil {
		return nil, func(bool) {}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	done := false
	finish := func(committed bool) {
		if done {
			return
		}
		done = true
		if !committed {
			_ = tx.Rollback(context.Background())
		}
	}
	isolation, readOnly, err := tx.Isolation(ctx)
	wantReadOnly := mode == AdministrationSnapshot
	wantIsolation := serializableIsolation
	if wantReadOnly {
		wantIsolation = repeatableReadIsolation
	}
	isolationOK := isolation == wantIsolation
	if wantReadOnly {
		isolationOK = isolationOK || isolation == serializableIsolation
	}
	if err != nil || readOnly != wantReadOnly || !isolationOK {
		finish(false)
		return nil, func(bool) {}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return tx, finish, nil
}

// readInventory reads one bounded metadata set with an exact current reread.
func (a *Administrator) readInventory(
	ctx context.Context,
	tx AdministrationTransaction,
	limits datasourceadmin.GenerationLimits,
	locked bool,
) (datasourceadmin.Inventory, MetadataRow, error) {
	current, currentPresent, err := tx.ReadCurrentOptional(ctx, locked)
	if err != nil {
		return datasourceadmin.Inventory{}, MetadataRow{}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	if currentPresent {
		if _, err := validateCurrentMetadata(current); err != nil {
			return datasourceadmin.Inventory{}, MetadataRow{}, err
		}
	}
	rows := make([]MetadataRow, 0)
	cursor := "0"
	for len(rows) <= int(limits.MaxGenerations) {
		page, pageErr := tx.GenerationPage(ctx, cursor, a.pageSize, locked)
		if pageErr != nil {
			return datasourceadmin.Inventory{}, MetadataRow{}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
		if len(page) == 0 {
			break
		}
		if len(page) > a.pageSize || len(rows) > int(limits.MaxGenerations)-len(page) {
			return datasourceadmin.Inventory{}, MetadataRow{}, datasourceadmin.NewError(datasourceadmin.CodeLimitExceeded)
		}
		next := page[len(page)-1].Generation
		if compareGenerationText(next, cursor) <= 0 {
			return datasourceadmin.Inventory{}, MetadataRow{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		rows = append(rows, page...)
		cursor = next
	}
	inventory := datasourceadmin.Inventory{}
	if currentPresent {
		generation, parseErr := parseGeneration(current.Generation)
		if parseErr != nil {
			return datasourceadmin.Inventory{}, MetadataRow{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		inventory.Current = generation
	}
	for _, row := range rows {
		info, mapErr := generationInfoFromMetadata(row, currentPresent && row.Generation == current.Generation)
		if mapErr != nil {
			return datasourceadmin.Inventory{}, MetadataRow{}, mapErr
		}
		inventory.Generations = append(inventory.Generations, info)
	}
	final, finalPresent, err := tx.ReadCurrentOptional(ctx, locked)
	if err != nil || finalPresent != currentPresent || finalPresent && !metadataEqual(current, final) {
		return datasourceadmin.Inventory{}, MetadataRow{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	if finalPresent {
		if _, err := validateCurrentMetadata(final); err != nil {
			return datasourceadmin.Inventory{}, MetadataRow{}, err
		}
	}
	canonical := inventory.Canonicalize()
	if err := datasourceadmin.ValidateInventory(canonical, limits); err != nil {
		return datasourceadmin.Inventory{}, MetadataRow{}, err
	}
	return canonical, current, nil
}

// validateCurrentMetadata owns the exact v2-null and v3-equal pointer contract.
func validateCurrentMetadata(row MetadataRow) (CurrentPointerFence, error) {
	if _, err := parseGeneration(row.Generation); err != nil ||
		row.DatasetState != datasetStateCommitted {
		return CurrentPointerFence{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	switch row.SchemaVersion {
	case datasourceadmin.SchemaVersionV2:
		if row.OperationID != nil || len(row.CandidateDigest) != 0 || len(row.PointerDigest) != 0 {
			return CurrentPointerFence{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		return CurrentPointerFence{generation: row.Generation}, nil
	case datasourceadmin.SchemaVersionV3:
		if row.OperationID == nil || len(row.CandidateDigest) != sha256.Size ||
			len(row.PointerDigest) != sha256.Size ||
			!bytes.Equal(row.CandidateDigest, row.PointerDigest) {
			return CurrentPointerFence{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		if _, err := datasourceadmin.NewOperationBinding(*row.OperationID); err != nil {
			return CurrentPointerFence{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		if _, err := datasourceadmin.ParseCandidateContentDigest(row.CandidateDigest); err != nil {
			return CurrentPointerFence{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		return CurrentPointerFence{
			generation:    row.Generation,
			pointerDigest: append([]byte(nil), row.PointerDigest...),
		}, nil
	default:
		return CurrentPointerFence{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
}

// generationInfoFromMetadata validates one inventory metadata row.
func generationInfoFromMetadata(row MetadataRow, current bool) (datasourceadmin.GenerationInfo, error) {
	generation, err := parseGeneration(row.Generation)
	if err != nil || row.SchemaVersion != datasourceadmin.SchemaVersionV2 &&
		row.SchemaVersion != datasourceadmin.SchemaVersionV3 ||
		row.DatasetState != datasetStateStaging && row.DatasetState != datasetStateCommitted {
		return datasourceadmin.GenerationInfo{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	state := datasourceadmin.StateStaging
	if row.DatasetState == datasetStateCommitted {
		state = datasourceadmin.StateCommitted
	}
	var operation datasourceadmin.OperationBinding
	var contentDigest datasourceadmin.CandidateContentDigest
	var sourceGeneration uint64
	if row.SchemaVersion == datasourceadmin.SchemaVersionV2 {
		if row.OperationID != nil || len(row.CandidateDigest) != 0 {
			return datasourceadmin.GenerationInfo{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
	} else {
		if row.OperationID == nil || len(row.CandidateDigest) != 32 {
			return datasourceadmin.GenerationInfo{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		operation, err = datasourceadmin.NewOperationBinding(*row.OperationID)
		if err != nil {
			return datasourceadmin.GenerationInfo{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		contentDigest, err = datasourceadmin.ParseCandidateContentDigest(row.CandidateDigest)
		if err != nil {
			return datasourceadmin.GenerationInfo{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		if row.SourceGeneration != "" {
			sourceGeneration, err = parseGeneration(row.SourceGeneration)
			if err != nil || sourceGeneration >= generation {
				return datasourceadmin.GenerationInfo{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
			}
		}
	}
	return datasourceadmin.GenerationInfo{
		Generation: generation, Current: current, State: state,
		WasActive: row.WasActive, Operation: operation, SourceGeneration: sourceGeneration, Schema: row.SchemaVersion, ContentDigest: contentDigest,
	}, nil
}

// readGeneration returns one complete bounded protected snapshot.
func (a *Administrator) readGeneration(
	ctx context.Context,
	tx AdministrationTransaction,
	generation string,
	limits datasourceadmin.GenerationLimits,
) (*datasourceadmin.Snapshot, MetadataRow, error) {
	metadataRows, err := tx.GenerationPage(ctx, previousGenerationText(generation), 1, false)
	if err != nil || len(metadataRows) != 1 || metadataRows[0].Generation != generation {
		return nil, MetadataRow{}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	metadata := metadataRows[0]
	rows, err := a.readRows(ctx, tx, generation, limits)
	if err != nil {
		return nil, MetadataRow{}, err
	}
	defer clearDatasetRows(&rows)
	protected := administrativeRows(rows)
	defer clearAdministrativeRows(&protected)
	generationNumber, err := parseGeneration(generation)
	if err != nil {
		return nil, MetadataRow{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	snapshot, err := datasourceadmin.NewSnapshot(metadata.SchemaVersion, generationNumber, protected)
	if err != nil {
		return nil, MetadataRow{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	if metadata.SchemaVersion == datasourceadmin.SchemaVersionV3 {
		verification, verificationErr := datasourceadmin.NewSnapshot(
			metadata.SchemaVersion, generationNumber, protected,
		)
		if verificationErr != nil {
			_ = snapshot.Close()
			return nil, MetadataRow{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		candidate, candidateErr := candidateFromSnapshot(ctx, metadata, verification)
		if candidateErr != nil {
			_ = verification.Close()
			_ = snapshot.Close()
			return nil, MetadataRow{}, candidateErr
		}
		_ = candidate.Close()
	}
	return snapshot, metadata, nil
}

// readCandidate reconstructs one exact operation-bound canonical candidate.
func (a *Administrator) readCandidate(
	ctx context.Context,
	tx AdministrationTransaction,
	operation datasourceadmin.OperationBinding,
	generation string,
	limits datasourceadmin.GenerationLimits,
) (*datasourceadmin.PublicationEnvelope, MetadataRow, error) {
	snapshot, metadata, err := a.readGeneration(ctx, tx, generation, limits)
	if err != nil {
		return nil, MetadataRow{}, err
	}
	candidate, err := candidateFromSnapshot(ctx, metadata, snapshot)
	if err != nil || !candidate.Binding().Equal(operation) {
		_ = candidate.Close()
		_ = snapshot.Close()
		return nil, MetadataRow{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	return candidate, metadata, nil
}

// candidateFromSnapshot binds and verifies exact stored v3 metadata.
func candidateFromSnapshot(
	ctx context.Context,
	metadata MetadataRow,
	snapshot *datasourceadmin.Snapshot,
) (*datasourceadmin.PublicationEnvelope, error) {
	if snapshot == nil || metadata.SchemaVersion != datasourceadmin.SchemaVersionV3 ||
		metadata.OperationID == nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	stored, err := datasourceadmin.ParseCandidateContentDigest(metadata.CandidateDigest)
	if err != nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	var candidate *datasourceadmin.PublicationEnvelope
	binding, err := datasourceadmin.NewOperationBinding(*metadata.OperationID)
	if err != nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	content, err := datasourceadmin.NewCandidateContent(snapshot)
	if err != nil {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	err = binding.WithValue(ctx, func(value string) error {
		var candidateErr error
			if metadata.SourceGeneration != "" {
				source, sourceErr := parseGeneration(metadata.SourceGeneration)
				if sourceErr != nil { return sourceErr }
				candidate, candidateErr = datasourceadmin.NewCampaignPublicationEnvelope(value, source, content)
			} else {
				candidate, candidateErr = datasourceadmin.NewPublicationEnvelope(value, content)
			}
		return candidateErr
	})
	if err != nil || candidate == nil || !candidate.Digest().Equal(stored) {
		_ = candidate.Close()
		_ = content.Close()
		return nil, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	return candidate, nil
}

// candidateDatasetRows projects one protected candidate into generation-bearing inserts.
func candidateDatasetRows(
	ctx context.Context,
	candidate *datasourceadmin.PublicationEnvelope,
	metadata MetadataRow,
) (DatasetRows, error) {
	rows := DatasetRows{Current: metadata, Final: metadata}
	err := candidate.WithRows(ctx, func(protected datasourceadmin.Rows) error {
		for _, row := range protected.Handles {
			rows.Handles = append(rows.Handles, HandleRow{Generation: metadata.Generation, HandleID: row.ID})
		}
		for _, row := range protected.Profiles {
			rows.Profiles = append(rows.Profiles, ProfileRow{
				Generation: metadata.Generation, ProfileID: row.ID, Domain: row.Domain,
				Status: row.Status, NotBeforeUTC: cloneNullableText(row.NotBeforeUTC),
				NotAfterUTC: cloneNullableText(row.NotAfterUTC),
			})
		}
		for _, row := range protected.Credentials {
			rows.Credentials = append(rows.Credentials, CredentialRow{
				Generation: metadata.Generation, ProfileID: row.ProfileID,
				Algorithm: row.Algorithm, Selector: row.Selector,
				PublicKeySPKI: append([]byte(nil), row.PublicSPKI...), HandleID: row.HandleID,
			})
		}
		for _, row := range protected.Policies {
			rows.Policies = append(rows.Policies, PolicyRow{
				Generation: metadata.Generation, TenantID: row.TenantID, Domain: row.Domain,
				Use: row.Use, ProfileID: row.ProfileID, Status: row.Status,
				Rollout: row.Rollout, Compatibility: row.Compatibility,
				FeedbackRouteID: cloneNullableText(row.FeedbackRouteID),
			})
		}
		for _, row := range protected.KeyMaterial {
			rows.KeyMaterial = append(rows.KeyMaterial, KeyMaterialRow{
				Generation: metadata.Generation, TenantID: row.TenantID, Domain: row.Domain,
				Use: row.Use, HandleID: row.HandleID, Algorithm: row.Algorithm,
				PublicSPKI:   append([]byte(nil), row.PublicSPKI...),
				PrivatePKCS8: append([]byte(nil), row.PrivatePKCS8...),
			})
		}
		return nil
	})
	if err != nil {
		clearDatasetRows(&rows)
		return DatasetRows{}, err
	}
	return rows, nil
}

// readRows reads every deterministic generation row class within shared bounds.
func (a *Administrator) readRows(
	ctx context.Context,
	tx AdministrationTransaction,
	generation string,
	limits datasourceadmin.GenerationLimits,
) (DatasetRows, error) {
	rows := DatasetRows{}
	budget := snapshotReadBudget{
		maximumRows:  int(limits.MaxSnapshotRows),
		maximumBytes: int(limits.MaxSnapshotBytes),
	}
	var err error
	rows.Handles, err = readHandlePages(ctx, tx, generation, a.pageSize, &budget)
	if err == nil {
		rows.Profiles, err = readProfilePages(ctx, tx, generation, a.pageSize, &budget)
	}
	if err == nil {
		rows.Credentials, err = readCredentialPages(ctx, tx, generation, a.pageSize, &budget)
	}
	if err == nil {
		rows.Policies, err = readPolicyPages(ctx, tx, generation, a.pageSize, &budget)
	}
	if err == nil {
		rows.KeyMaterial, err = readKeyMaterialPages(ctx, tx, generation, a.pageSize, &budget)
	}
	if err != nil {
		clearDatasetRows(&rows)
		return DatasetRows{}, err
	}
	return rows, nil
}

// snapshotReadBudget enforces one cumulative row and byte ceiling while pages arrive.
type snapshotReadBudget struct {
	maximumRows  int
	maximumBytes int
	rows         int
	bytes        int
}

// add reserves one page against the shared snapshot ceilings without overflow.
func (b *snapshotReadBudget) add(rowCount, byteCount int) error {
	if b == nil || rowCount < 0 || byteCount < 0 || rowCount > b.maximumRows-b.rows ||
		byteCount > b.maximumBytes-b.bytes {
		return datasourceadmin.NewError(datasourceadmin.CodeLimitExceeded)
	}
	b.rows += rowCount
	b.bytes += byteCount
	return nil
}

// readHandlePages reads one complete bounded handle class.
func readHandlePages(ctx context.Context, tx AdministrationTransaction, generation string, size int, budget *snapshotReadBudget) ([]HandleRow, error) {
	output, cursor := make([]HandleRow, 0), ""
	for {
		page, err := tx.HandlePageFor(ctx, generation, cursor, size)
		if err != nil {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
		if len(page) > size {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeLimitExceeded)
		}
		if len(page) == 0 {
			return output, nil
		}
		next := page[len(page)-1].HandleID
		if next <= cursor {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		if err := budget.add(len(page), handleBytes(page)); err != nil {
			return nil, err
		}
		output, cursor = append(output, page...), next
	}
}

// readProfilePages reads one complete bounded profile class.
func readProfilePages(ctx context.Context, tx AdministrationTransaction, generation string, size int, budget *snapshotReadBudget) ([]ProfileRow, error) {
	output, cursor := make([]ProfileRow, 0), ""
	for {
		page, err := tx.ProfilePageFor(ctx, generation, cursor, size)
		if err != nil {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
		if len(page) > size {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeLimitExceeded)
		}
		if len(page) == 0 {
			return output, nil
		}
		next := page[len(page)-1].ProfileID
		if next <= cursor {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		if err := budget.add(len(page), profileBytes(page)); err != nil {
			return nil, err
		}
		output, cursor = append(output, page...), next
	}
}

// readCredentialPages reads one complete bounded credential class.
func readCredentialPages(ctx context.Context, tx AdministrationTransaction, generation string, size int, budget *snapshotReadBudget) ([]CredentialRow, error) {
	output, profile, algorithm := make([]CredentialRow, 0), "", ""
	for {
		page, err := tx.CredentialPageFor(ctx, generation, profile, algorithm, size)
		if err != nil {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
		if len(page) > size {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeLimitExceeded)
		}
		if len(page) == 0 {
			return output, nil
		}
		last := page[len(page)-1]
		if last.ProfileID < profile || last.ProfileID == profile && last.Algorithm <= algorithm {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		if err := budget.add(len(page), credentialBytes(page)); err != nil {
			return nil, err
		}
		output, profile, algorithm = append(output, page...), last.ProfileID, last.Algorithm
	}
}

// readPolicyPages reads one complete bounded policy class.
func readPolicyPages(ctx context.Context, tx AdministrationTransaction, generation string, size int, budget *snapshotReadBudget) ([]PolicyRow, error) {
	output, tenant, domain, use := make([]PolicyRow, 0), "", "", ""
	for {
		page, err := tx.PolicyPageFor(ctx, generation, tenant, domain, use, size)
		if err != nil {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
		if len(page) > size {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeLimitExceeded)
		}
		if len(page) == 0 {
			return output, nil
		}
		last := page[len(page)-1]
		if !tupleGreater(last.TenantID, last.Domain, last.Use, tenant, domain, use) {
			return nil, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		if err := budget.add(len(page), policyBytes(page)); err != nil {
			return nil, err
		}
		output, tenant, domain, use = append(output, page...), last.TenantID, last.Domain, last.Use
	}
}

// readKeyMaterialPages reads one complete bounded private-key class.
func readKeyMaterialPages(ctx context.Context, tx AdministrationTransaction, generation string, size int, budget *snapshotReadBudget) ([]KeyMaterialRow, error) {
	output, cursor := make([]KeyMaterialRow, 0), ""
	for {
		page, err := tx.KeyMaterialPageFor(ctx, generation, cursor, size)
		if err != nil {
			clearKeyMaterialRows(page)
			clearKeyMaterialRows(output)
			return nil, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
		}
		if len(page) > size {
			clearKeyMaterialRows(page)
			clearKeyMaterialRows(output)
			return nil, datasourceadmin.NewError(datasourceadmin.CodeLimitExceeded)
		}
		if len(page) == 0 {
			return output, nil
		}
		next := page[len(page)-1].HandleID
		if next <= cursor {
			clearKeyMaterialRows(page)
			clearKeyMaterialRows(output)
			return nil, datasourceadmin.NewError(datasourceadmin.CodeConflict)
		}
		if err := budget.add(len(page), keyMaterialBytes(page)); err != nil {
			clearKeyMaterialRows(page)
			clearKeyMaterialRows(output)
			return nil, err
		}
		output, cursor = append(output, page...), next
	}
}

// requireLock proves one exact durable SQL owner/revision under row lock.
func requireLock(ctx context.Context, tx AdministrationTransaction, lock datasourceadmin.AdministrationLock, locked bool) error {
	revision, owner, err := tx.ReadLock(ctx, locked)
	if err != nil {
		return err
	}
	if owner == nil || revision != lock.Revision() {
		return datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	var expected string
	if err := lock.Owner().WithValue(ctx, func(value string) error { expected = value; return nil }); err != nil || *owner != expected {
		return datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	return nil
}

// lockObservation maps one exact nullable owner into the protected contract.
func lockObservation(revision uint64, owner *string) (datasourceadmin.AdministrationLockObservation, error) {
	if owner == nil {
		return datasourceadmin.NewAdministrationLockObservation(revision, datasourceadmin.OperationBinding{}, false)
	}
	binding, err := datasourceadmin.NewOperationBinding(*owner)
	if err != nil {
		return datasourceadmin.AdministrationLockObservation{}, datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	return datasourceadmin.NewAdministrationLockObservation(revision, binding, true)
}

// generationInfo returns one exact inventory item.
func generationInfo(inventory datasourceadmin.Inventory, generation uint64) (datasourceadmin.GenerationInfo, bool) {
	for _, info := range inventory.Generations {
		if info.Generation == generation {
			return info, true
		}
	}
	return datasourceadmin.GenerationInfo{}, false
}

// compareGenerationText compares canonical unsigned decimal generation values.
func compareGenerationText(left, right string) int {
	left = strings.TrimLeft(left, "0")
	right = strings.TrimLeft(right, "0")
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	return strings.Compare(left, right)
}

// previousGenerationText returns the exact preceding cursor for a known generation.
func previousGenerationText(generation string) string {
	value, err := strconv.ParseUint(generation, 10, 64)
	if err != nil || value <= 1 {
		return "0"
	}
	return strconv.FormatUint(value-1, 10)
}

// clearDatasetRows erases all detached SQL key buffers.
func clearDatasetRows(rows *DatasetRows) {
	if rows == nil {
		return
	}
	for index := range rows.Credentials {
		clear(rows.Credentials[index].PublicKeySPKI)
	}
	clearKeyMaterialRows(rows.KeyMaterial)
	clear(rows.Current.CandidateDigest)
	clear(rows.Final.CandidateDigest)
	*rows = DatasetRows{}
}

// closeCollisionSnapshots destroys all locally retained protected snapshots.
func closeCollisionSnapshots(values []datasourceadmin.CollisionSnapshot) {
	for index := range values {
		if values[index].Snapshot != nil {
			_ = values[index].Snapshot.Close()
		}
	}
}

// administrationReadError preserves a classified read failure or returns unavailable.
func administrationReadError(err error) error {
	if err == nil {
		return datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	if code := datasourceadmin.CodeOf(err); code != datasourceadmin.CodeNone {
		return err
	}
	return datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
}

// String returns a constant protected administrator summary.
func (*Administrator) String() string { return administratorRedacted }

// GoString returns a constant protected administrator representation.
func (*Administrator) GoString() string { return administratorRedacted }

// Format prevents backend and candidate data from reaching formatting sinks.
func (*Administrator) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, administratorRedacted)
}

// MarshalJSON rejects generic administrator serialization.
func (*Administrator) MarshalJSON() ([]byte, error) {
	return nil, errors.New("sql administration unavailable")
}

// Close releases all role-scoped connectors.
func (a *Administrator) Close() {
	if a == nil {
		return
	}
	a.snapshot.Close()
	a.stager.Close()
	a.activator.Close()
}
