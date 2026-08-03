package domainadmin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base32"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

const (
	testAdminDomain      = "example.test"
	testAdminAddedDomain = "added.example.test"
	testAdminProfileUse  = "originator"
	testAdminTenant      = "tenant"
	testAdminRollout     = "enforce"
	testAdminCompat      = "strict"
)

type incrementingEntropy struct {
	mu    sync.Mutex
	value byte
}

// Read fills each request with one new nonzero byte value.
func (r *incrementingEntropy) Read(value []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.value++
	for index := range value {
		value[index] = r.value
	}
	return len(value), nil
}

type constantEntropy byte

// Read fills every request with one fixed nonzero byte.
func (r constantEntropy) Read(value []byte) (int, error) {
	for index := range value {
		value[index] = byte(r)
	}
	return len(value), nil
}

type zeroThenEntropy struct{ reads int }

// Read returns one syntactically unusable all-zero draw before valid entropy.
func (r *zeroThenEntropy) Read(value []byte) (int, error) {
	r.reads++
	for index := range value {
		value[index] = 0
		if r.reads > 1 {
			value[index] = 1
		}
	}
	return len(value), nil
}

type administrationLockerFake struct {
	mu             sync.Mutex
	revision       uint64
	owner          datasourceadmin.OperationBinding
	claims         int
	releases       int
	malformedClaim bool
	claimErr       bool
	releaseErr     bool
	finiteRelease  bool
}

// Claim provides one exact owner/revision fake claim.
func (l *administrationLockerFake) Claim(
	_ context.Context,
	owner datasourceadmin.OperationBinding,
	expected uint64,
) (datasourceadmin.AdministrationLock, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.claims++
	if l.claimErr || l.owner.Initialized() || expected != l.revision {
		return datasourceadmin.AdministrationLock{}, errors.New("claim failed")
	}
	if l.malformedClaim {
		return datasourceadmin.NewAdministrationLock(owner, expected+1)
	}
	lock, err := datasourceadmin.NewAdministrationLock(owner, expected)
	if err == nil {
		l.owner = owner
	}
	return lock, err
}

// Release clears one exact claim and increments its revision.
func (l *administrationLockerFake) Release(
	ctx context.Context,
	lock datasourceadmin.AdministrationLock,
) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.releases++
	deadline, finite := ctx.Deadline()
	l.finiteRelease = finite && time.Until(deadline) > 0 && time.Until(deadline) <= 30*time.Second
	if l.releaseErr || !l.owner.Equal(lock.Owner()) || lock.Revision() != l.revision {
		return 0, errors.New("release failed")
	}
	l.owner = datasourceadmin.OperationBinding{}
	l.revision++
	return l.revision, nil
}

// ObserveAdministrationLock returns one exact read-only fake lock sight.
func (l *administrationLockerFake) ObserveAdministrationLock(
	_ context.Context,
) (datasourceadmin.AdministrationLockObservation, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return datasourceadmin.NewAdministrationLockObservation(l.revision, l.owner, l.owner.Initialized())
}

type collisionReaderFake struct {
	mu    sync.Mutex
	build func(context.Context, datasourceadmin.AdministrationLock, datasourceadmin.GenerationLimits) (*datasourceadmin.CollisionInventory, error)
	calls int
}

// ReadCurrent is unused because allocation requires the atomic collision operation.
func (*collisionReaderFake) ReadCurrent(context.Context, datasourceadmin.GenerationLimits) (*datasourceadmin.Snapshot, error) {
	return nil, errors.New("unused")
}

// Inventory is unused because allocation requires the atomic collision operation.
func (*collisionReaderFake) Inventory(context.Context, datasourceadmin.GenerationLimits) (datasourceadmin.Inventory, error) {
	return datasourceadmin.Inventory{}, errors.New("unused")
}

// ReadCollisionInventory returns one scripted exact lock-bound view.
func (r *collisionReaderFake) ReadCollisionInventory(
	ctx context.Context,
	lock datasourceadmin.AdministrationLock,
	limits datasourceadmin.GenerationLimits,
) (*datasourceadmin.CollisionInventory, error) {
	r.mu.Lock()
	r.calls++
	build := r.build
	r.mu.Unlock()
	return build(ctx, lock, limits)
}

// TestIdentityAllocatorRetriesOperationCollisionUnderNewRevision freezes bounded restart.
func TestIdentityAllocatorRetriesOperationCollisionUnderNewRevision(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxAllocationAttempts = 3
	allocator, err := newIdentityAllocator(limits, &incrementingEntropy{})
	if err != nil {
		t.Fatal("allocator fixture rejected")
	}
	locker := &administrationLockerFake{revision: 7}
	reader := &collisionReaderFake{}
	reader.build = func(ctx context.Context, lock datasourceadmin.AdministrationLock, limits datasourceadmin.GenerationLimits) (*datasourceadmin.CollisionInventory, error) {
		operation := datasourceadmin.OperationBinding{}
		if reader.calls == 1 {
			operation = lock.Owner()
		}
		return currentCollisionView(ctx, t, lock, limits, operation, "existing-profile", "existing-handle", "existing-selector")
	}
	allocation, lock, err := allocator.allocateForTest(t.Context(), testIntent(t, provider.AlgorithmEd25519SHA256), reader, locker, 7, testAdminGenerationLimits())
	if err != nil || allocation == nil || lock.Revision() != 8 || reader.calls != 2 || locker.claims != 2 || locker.releases != 1 || !locker.finiteRelease {
		t.Fatal("operation collision did not restart under the next exact revision")
	}
	defer allocation.Close() //nolint:errcheck // Test cleanup has no recovery.
	if allocation.CandidateGeneration() != 2 {
		t.Fatal("allocation lost the bounded candidate generation")
	}
	for _, credential := range allocation.credentials {
		if !strings.HasPrefix(credential.handleID, "h-") ||
			len(strings.TrimPrefix(credential.handleID, "h-")) != 26 {
			t.Fatal("generated handle lost its h-prefixed 128-bit token construction")
		}
	}
	if _, err := locker.Release(t.Context(), lock); err != nil {
		t.Fatal("release successful allocation claim")
	}
}

// TestIdentityAllocatorExhaustsCompleteSnapshotCollisions freezes selector and handle scope.
func TestIdentityAllocatorExhaustsCompleteSnapshotCollisions(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxAllocationAttempts = 2
	allocator, err := newIdentityAllocator(limits, constantEntropy(1))
	if err != nil {
		t.Fatal("allocator fixture rejected")
	}
	token := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes.Repeat([]byte{1}, entropyBytes128)))
	locker := &administrationLockerFake{revision: 5}
	reader := &collisionReaderFake{build: func(ctx context.Context, lock datasourceadmin.AdministrationLock, limits datasourceadmin.GenerationLimits) (*datasourceadmin.CollisionInventory, error) {
		return currentCollisionView(ctx, t, lock, limits, datasourceadmin.OperationBinding{}, "existing-profile", "h-"+token, "d2e-"+token)
	}}
	allocation, _, err := allocator.allocateForTest(t.Context(), testIntent(t, provider.AlgorithmEd25519SHA256), reader, locker, 5, testAdminGenerationLimits())
	if CodeOf(err) != CodeConflict || allocation != nil || locker.releases != 1 || !locker.finiteRelease {
		t.Fatal("complete snapshot collision attempts did not fail closed")
	}
}

// TestIdentityAllocatorFailsClosedOnIncompleteViewAndMalformedClaim freezes drift handling.
func TestIdentityAllocatorFailsClosedOnIncompleteViewAndMalformedClaim(t *testing.T) {
	limits := DefaultLimits()
	allocator, _ := newIdentityAllocator(limits, &incrementingEntropy{})
	invalidLocker := &administrationLockerFake{revision: 2}
	invalidReader := &collisionReaderFake{build: func(context.Context, datasourceadmin.AdministrationLock, datasourceadmin.GenerationLimits) (*datasourceadmin.CollisionInventory, error) {
		return nil, errors.New("must not run")
	}}
	if allocation, _, err := allocator.allocateForTest(t.Context(), Intent{}, invalidReader, invalidLocker, 2, testAdminGenerationLimits()); CodeOf(err) != CodeInvalidIntent || allocation != nil || invalidLocker.claims != 0 || invalidReader.calls != 0 {
		t.Fatal("invalid intent reached claim or backend input")
	}
	malformed := &administrationLockerFake{revision: 3, malformedClaim: true}
	reader := &collisionReaderFake{build: func(context.Context, datasourceadmin.AdministrationLock, datasourceadmin.GenerationLimits) (*datasourceadmin.CollisionInventory, error) {
		return nil, errors.New("must not run")
	}}
	if allocation, _, err := allocator.allocateForTest(t.Context(), testIntent(t, provider.AlgorithmEd25519SHA256), reader, malformed, 3, testAdminGenerationLimits()); CodeOf(err) != CodeReconcileRequired || allocation != nil || reader.calls != 0 || malformed.releases != 0 {
		t.Fatal("malformed successful claim was not classified as uncertain")
	}
	locker := &administrationLockerFake{revision: 4}
	drift := &collisionReaderFake{build: func(ctx context.Context, lock datasourceadmin.AdministrationLock, generationLimits datasourceadmin.GenerationLimits) (*datasourceadmin.CollisionInventory, error) {
		current := collisionSnapshot(t, 1, "current-profile", "current-handle", "current-selector")
		inventory := datasourceadmin.Inventory{Current: 1, Generations: []datasourceadmin.GenerationInfo{
			{Generation: 1, Current: true, State: datasourceadmin.StateCommitted, WasActive: true},
			{Generation: 2, State: datasourceadmin.StateStaging},
		}}
		return datasourceadmin.NewCollisionInventory(ctx, lock, inventory, []datasourceadmin.CollisionSnapshot{{Info: inventory.Generations[0], Snapshot: current}}, generationLimits)
	}}
	if allocation, _, err := allocator.allocateForTest(t.Context(), testIntent(t, provider.AlgorithmEd25519SHA256), drift, locker, 4, testAdminGenerationLimits()); CodeOf(err) != CodeUnavailable || allocation != nil || locker.releases != 1 {
		t.Fatal("concurrent candidate insertion did not fail closed and release")
	}

	locker = &administrationLockerFake{revision: 6}
	wrongLock := &collisionReaderFake{build: func(ctx context.Context, lock datasourceadmin.AdministrationLock, generationLimits datasourceadmin.GenerationLimits) (*datasourceadmin.CollisionInventory, error) {
		otherOwner, _ := datasourceadmin.NewOperationBinding("aebagbafaydqqcikbmga2dqpca")
		other, _ := datasourceadmin.NewAdministrationLock(otherOwner, lock.Revision())
		return currentCollisionView(ctx, t, other, generationLimits, datasourceadmin.OperationBinding{}, "existing-profile", "existing-handle", "existing-selector")
	}}
	if allocation, _, err := allocator.allocateForTest(t.Context(), testIntent(t, provider.AlgorithmEd25519SHA256), wrongLock, locker, 6, testAdminGenerationLimits()); CodeOf(err) != CodeUnavailable || allocation != nil || locker.releases != 1 {
		t.Fatal("collision view bound to another lock was accepted")
	}
}

// TestIdentityAllocatorRejectsExistingTenantDomainUsePolicy freezes duplicate-domain onboarding.
func TestIdentityAllocatorRejectsExistingTenantDomainUsePolicy(t *testing.T) {
	allocator, err := newIdentityAllocator(DefaultLimits(), &incrementingEntropy{})
	if err != nil {
		t.Fatal("construct duplicate-policy allocator")
	}
	locker := &administrationLockerFake{revision: 41}
	reader := &collisionReaderFake{build: func(
		ctx context.Context,
		lock datasourceadmin.AdministrationLock,
		limits datasourceadmin.GenerationLimits,
	) (*datasourceadmin.CollisionInventory, error) {
		source := collisionSnapshot(t, 1, "existing-profile", "existing-handle", "existing-selector")
		var duplicate *datasourceadmin.Snapshot
		if err := source.WithRows(ctx, func(rows datasourceadmin.Rows) error {
			rows.Profiles[0].Domain = testAdminAddedDomain
			rows.Policies[0].Domain = testAdminAddedDomain
			rows.KeyMaterial[0].Domain = testAdminAddedDomain
			var createErr error
			duplicate, createErr = datasourceadmin.NewSnapshot(datasourceadmin.SchemaVersionV2, 1, rows)
			return createErr
		}); err != nil {
			_ = source.Close()
			return nil, err
		}
		_ = source.Close()
		info := datasourceadmin.GenerationInfo{Generation: 1, Current: true, State: datasourceadmin.StateCommitted}
		return datasourceadmin.NewCollisionInventory(
			ctx, lock, datasourceadmin.Inventory{Current: 1, Generations: []datasourceadmin.GenerationInfo{info}},
			[]datasourceadmin.CollisionSnapshot{{Info: info, Snapshot: duplicate}}, limits,
		)
	}}
	allocation, _, err := allocator.allocateForTest(
		t.Context(), testIntent(t, provider.AlgorithmEd25519SHA256), reader, locker, 41, testAdminGenerationLimits(),
	)
	if CodeOf(err) != CodeConflict || allocation != nil || locker.releases != 1 {
		t.Fatal("existing tenant/domain/use policy reached identity allocation")
	}
}

// TestIdentityAllocatorRetriesSyntacticallyUnusableOperationDraw freezes bounded retry.
func TestIdentityAllocatorRetriesSyntacticallyUnusableOperationDraw(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxAllocationAttempts = 2
	entropy := &zeroThenEntropy{}
	allocator, err := newIdentityAllocator(limits, entropy)
	if err != nil {
		t.Fatal("allocator fixture rejected")
	}
	operation, err := allocator.allocateOperation(t.Context())
	if err != nil || !operation.Initialized() || entropy.reads != 2 {
		t.Fatal("syntactically unusable operation draw was not retried")
	}
}

// currentCollisionView constructs one exact current-generation collision view.
func currentCollisionView(
	ctx context.Context,
	t *testing.T,
	lock datasourceadmin.AdministrationLock,
	limits datasourceadmin.GenerationLimits,
	operation datasourceadmin.OperationBinding,
	profileID string,
	handleID string,
	selector string,
) (*datasourceadmin.CollisionInventory, error) {
	t.Helper()
	info := datasourceadmin.GenerationInfo{Generation: 1, Current: true, State: datasourceadmin.StateCommitted, WasActive: true, Operation: operation}
	return datasourceadmin.NewCollisionInventory(ctx, lock, datasourceadmin.Inventory{Current: 1, Generations: []datasourceadmin.GenerationInfo{info}}, []datasourceadmin.CollisionSnapshot{{Info: info, Snapshot: collisionSnapshot(t, 1, profileID, handleID, selector)}}, limits)
}

// collisionSnapshot constructs one complete canonical Ed25519 snapshot.
func collisionSnapshot(t *testing.T, generation uint64, profileID, handleID, selector string) *datasourceadmin.Snapshot {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(generation)}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	privatePKCS8, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal("marshal collision fixture")
	}
	publicSPKI, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal("marshal collision public key")
	}
	rows := datasourceadmin.Rows{
		Handles:     []datasourceadmin.HandleRow{{ID: handleID}},
		Profiles:    []datasourceadmin.ProfileRow{{ID: profileID, Domain: testAdminDomain, Status: "active"}},
		Credentials: []datasourceadmin.CredentialRow{{ProfileID: profileID, Algorithm: string(provider.AlgorithmEd25519SHA256), Selector: selector, PublicSPKI: publicSPKI, HandleID: handleID}},
		Policies:    []datasourceadmin.PolicyRow{{TenantID: testAdminTenant, Domain: testAdminDomain, Use: testAdminProfileUse, ProfileID: profileID, Status: "active", Rollout: testAdminRollout, Compatibility: testAdminCompat}},
		KeyMaterial: []datasourceadmin.KeyMaterialRow{{TenantID: testAdminTenant, Domain: testAdminDomain, Use: testAdminProfileUse, HandleID: handleID, Algorithm: string(provider.AlgorithmEd25519SHA256), PublicSPKI: append([]byte(nil), publicSPKI...), PrivatePKCS8: privatePKCS8}},
	}
	snapshot, err := datasourceadmin.NewSnapshot(datasourceadmin.SchemaVersionV2, generation, rows)
	clear(private)
	clear(privatePKCS8)
	if err != nil {
		t.Fatal("construct collision snapshot")
	}
	return snapshot
}

// testIntent constructs one authoritative canonical intent.
func testIntent(t *testing.T, algorithms ...provider.Algorithm) Intent {
	t.Helper()
	values := make([]string, len(algorithms))
	for index, algorithm := range algorithms {
		values[index] = string(algorithm)
	}
	intent, err := newIntent(intentDocument{Version: intentVersion, Domain: testAdminAddedDomain, TenantID: testAdminTenant, ProfileUse: testAdminProfileUse, Algorithms: values, Rollout: testAdminRollout, Compatibility: testAdminCompat})
	if err != nil {
		t.Fatal("construct intent fixture")
	}
	return intent
}

// testAdminGenerationLimits returns one fully finite collision-read policy.
func testAdminGenerationLimits() datasourceadmin.GenerationLimits {
	return datasourceadmin.GenerationLimits{MaxGenerations: 256, MaxOutstandingCandidates: 8, MaxSnapshotRows: 4096, MaxSnapshotBytes: 32 << 20, BackendDeadline: 30 * time.Second}
}
