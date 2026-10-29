package config

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// TestProtectedRuntimeHandoffActivatesOnlyAfterCommit proves the two-phase owner transition.
func TestProtectedRuntimeHandoffActivatesOnlyAfterCommit(t *testing.T) {
	state := testProtectedRuntimeState()
	state.phase = protectedOwnedByPrebootstrap
	owner := &Prebootstrap{state: state}
	exactCapability := append([]byte(nil), state.capability[:]...)

	preparation, err := owner.PrepareRuntime()
	if err != nil {
		t.Fatalf("PrepareRuntime() failed with code %s", CodeOf(err))
	}
	startup := preparation.StartupReplay()
	capability := preparation.ProcessCapability()

	if capability.Equal(exactCapability) {
		t.Fatal("prepared capability activated before commit")
	}
	if err := startup.UseReplayMaterial(func(material ReplayMaterial) error {
		if !bytes.HasPrefix(material.HMAC(), []byte(testHMACMarker)) {
			t.Fatal("startup replay borrow changed protected bytes")
		}
		return nil
	}); err != nil {
		t.Fatalf("startup replay borrow failed with code %s", CodeOf(err))
	}

	runtime, err := owner.CommitRuntime(preparation)
	if err != nil {
		t.Fatalf("CommitRuntime() failed with code %s", CodeOf(err))
	}
	if runtime == nil {
		t.Fatal("CommitRuntime() returned no runtime owner")
	}
	if err := startup.UseReplayMaterial(func(ReplayMaterial) error { return nil }); CodeOf(err) != CodeProtectedClosed {
		t.Fatalf("startup replay borrow remained active with code %s", CodeOf(err))
	}
	if !capability.Equal(exactCapability) {
		t.Fatal("process capability did not activate after commit")
	}
	if _, err := owner.CommitRuntime(preparation); CodeOf(err) != CodeProtectedTransferred {
		t.Fatalf("second CommitRuntime() returned code %s", CodeOf(err))
	}
	if err := owner.Close(); CodeOf(err) != CodeProtectedTransferred {
		t.Fatalf("prebootstrap Close() after commit returned code %s", CodeOf(err))
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("runtime Close() failed with code %s", CodeOf(err))
	}
}

// TestRuntimePreparationSnapshotPreservesPhaseAndGeneration freezes atomic HTTP provenance.
func TestRuntimePreparationSnapshotPreservesPhaseAndGeneration(t *testing.T) {
	owner, preparation, _, _, state := testPreparedProtectedRuntime(t)
	loaded, err := Load([]byte(`config:
  version: dkim2d-config-v1
protected:
  generation: 0123456789abcdef0123456789abcdef
server:
  capability_file: /secure/0123456789abcdef0123456789abcdef/capability
replay:
  backend: disabled
`), FlagValues{})
	if err != nil {
		t.Fatalf("Load() failed with code %s", CodeOf(err))
	}
	state.snapshot = loaded
	snapshot := preparation.Snapshot()
	if !snapshot.Valid() ||
		snapshot.Generation() != state.snapshot.Generation() {
		t.Fatal("prepared snapshot crossed protected generations")
	}
	if strings.Contains(fmt.Sprintf("%+v", preparation), snapshot.Generation()) {
		t.Fatal("runtime preparation formatting exposed its generation")
	}
	var zero RuntimePreparation
	if zero.Snapshot().Valid() {
		t.Fatal("zero runtime preparation exposed a snapshot")
	}
	forged := &RuntimePreparation{state: state, token: &runtimeToken{marker: 1}}
	if forged.Snapshot().Valid() {
		t.Fatal("foreign runtime token exposed a snapshot")
	}
	runtime, err := owner.CommitRuntime(preparation)
	if err != nil {
		t.Fatalf("CommitRuntime() failed with code %s", CodeOf(err))
	}
	if preparation.Snapshot().Valid() {
		t.Fatal("preparation snapshot remained active after commit")
	}
	if runtime.Snapshot().Generation() != snapshot.Generation() {
		t.Fatal("runtime commit changed snapshot generation")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("runtime Close() failed with code %s", CodeOf(err))
	}
	if preparation.Snapshot().Valid() {
		t.Fatal("preparation snapshot revived after release")
	}
}

// TestProtectedRuntimeCommitRejectsActiveBorrow proves commit and borrowing linearize.
func TestProtectedRuntimeCommitRejectsActiveBorrow(t *testing.T) {
	state := testProtectedRuntimeState()
	state.phase = protectedOwnedByPrebootstrap
	owner := &Prebootstrap{state: state}
	preparation, err := owner.PrepareRuntime()
	if err != nil {
		t.Fatalf("PrepareRuntime() failed with code %s", CodeOf(err))
	}
	startup := preparation.StartupReplay()

	entered := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- startup.UseReplayMaterial(func(ReplayMaterial) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	if runtime, err := owner.CommitRuntime(preparation); runtime != nil ||
		CodeOf(err) != CodeProtectedTransferred {
		t.Fatalf("CommitRuntime() during borrow returned runtime=%v code=%s", runtime, CodeOf(err))
	}
	if err := owner.Close(); CodeOf(err) != CodeProtectedTransferred {
		t.Fatalf("Close() during borrow returned code %s", CodeOf(err))
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatalf("startup borrow failed with code %s", CodeOf(err))
	}
	runtime, err := owner.CommitRuntime(preparation)
	if err != nil || runtime == nil {
		t.Fatalf("CommitRuntime() after borrow failed with code %s", CodeOf(err))
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("runtime Close() failed with code %s", CodeOf(err))
	}
}

// TestProtectedRuntimePreparationRejectsForeignTokens proves handles cannot cross owners.
func TestProtectedRuntimePreparationRejectsForeignTokens(t *testing.T) {
	firstState := testProtectedRuntimeState()
	firstState.phase = protectedOwnedByPrebootstrap
	first := &Prebootstrap{state: firstState}
	firstPreparation, err := first.PrepareRuntime()
	if err != nil {
		t.Fatalf("first PrepareRuntime() failed with code %s", CodeOf(err))
	}

	secondState := testProtectedRuntimeState()
	secondState.phase = protectedOwnedByPrebootstrap
	second := &Prebootstrap{state: secondState}
	secondPreparation, err := second.PrepareRuntime()
	if err != nil {
		t.Fatalf("second PrepareRuntime() failed with code %s", CodeOf(err))
	}
	if runtime, err := first.CommitRuntime(secondPreparation); runtime != nil ||
		CodeOf(err) != CodeProtectedTransferred {
		t.Fatalf("foreign CommitRuntime() returned runtime=%v code=%s", runtime, CodeOf(err))
	}
	if firstPreparation.ProcessCapability().Equal(firstState.capability[:]) {
		t.Fatal("first capability activated before commit")
	}
	if err := firstPreparation.StartupReplay().UseReplayMaterial(func(material ReplayMaterial) error {
		if !bytes.HasPrefix(material.HMAC(), []byte(testHMACMarker)) {
			t.Fatal("first preparation lent foreign material")
		}
		return nil
	}); err != nil {
		t.Fatalf("first preparation replay borrow failed with code %s", CodeOf(err))
	}
	_ = first.Close()
	_ = second.Close()
}

// TestProtectedReleaseClearsOwnedBackingBytes proves release zeroizes retained aliases.
func TestProtectedReleaseClearsOwnedBackingBytes(t *testing.T) {
	for _, runtimeOwned := range []bool{false, true} {
		state := testProtectedRuntimeState()
		state.phase = protectedOwnedByPrebootstrap
		owner := &Prebootstrap{state: state}
		capabilityAlias := state.capability[:]
		state.dsnSignCapability = [exactKeyBytes]byte{0xd8}
		state.hasDSNSign = true
		dsnSignCapabilityAlias := state.dsnSignCapability[:]
		hmacAlias := state.hmac[:]
		redisPasswordAlias := state.redisPassword
		sentinelPasswordAlias := state.redisSentinelPassword
		clientCertificateAlias := state.redisClientCertificatePEM
		clientKeyAlias := state.redisClientKeyPEM
		rootAliases := append([][]byte(nil), state.rootCertificatesDER...)

		var err error
		if runtimeOwned {
			preparation, prepareErr := owner.PrepareRuntime()
			if prepareErr != nil {
				t.Fatalf("PrepareRuntime() failed with code %s", CodeOf(prepareErr))
			}
			runtime, commitErr := owner.CommitRuntime(preparation)
			if commitErr != nil {
				t.Fatalf("CommitRuntime() failed with code %s", CodeOf(commitErr))
			}
			err = runtime.Close()
		} else {
			err = owner.Close()
		}
		if err != nil {
			t.Fatalf("release runtimeOwned=%t failed with code %s", runtimeOwned, CodeOf(err))
		}
		if !allZeroBytes(capabilityAlias) || !allZeroBytes(dsnSignCapabilityAlias) ||
			!allZeroBytes(hmacAlias) ||
			!allZeroBytes(redisPasswordAlias) || !allZeroBytes(sentinelPasswordAlias) ||
			!allZeroBytes(clientCertificateAlias) || !allZeroBytes(clientKeyAlias) {
			t.Fatalf("release runtimeOwned=%t retained password bytes", runtimeOwned)
		}
		for _, rootAlias := range rootAliases {
			if !allZeroBytes(rootAlias) {
				t.Fatalf("release runtimeOwned=%t retained DER bytes", runtimeOwned)
			}
		}
		if state.redisPassword != nil || state.redisSentinelPassword != nil ||
			state.redisClientCertificatePEM != nil || state.redisClientKeyPEM != nil ||
			state.rootCertificatesDER != nil || state.hasHMAC {
			t.Fatalf("release runtimeOwned=%t retained protected references", runtimeOwned)
		}
	}
}

// TestProtectedRuntimeConcurrentCommitHasOneOwner proves exactly one commit wins.
func TestProtectedRuntimeConcurrentCommitHasOneOwner(t *testing.T) {
	state := testProtectedRuntimeState()
	state.phase = protectedOwnedByPrebootstrap
	owner := &Prebootstrap{state: state}
	preparation, err := owner.PrepareRuntime()
	if err != nil {
		t.Fatalf("PrepareRuntime() failed with code %s", CodeOf(err))
	}

	const callers = 16
	var wait sync.WaitGroup
	wait.Add(callers)
	results := make(chan *RuntimeMaterial, callers)
	for range callers {
		go func() {
			defer wait.Done()
			runtime, _ := owner.CommitRuntime(preparation)
			results <- runtime
		}()
	}
	wait.Wait()
	close(results)

	var runtime *RuntimeMaterial
	for candidate := range results {
		if candidate == nil {
			continue
		}
		if runtime != nil {
			t.Fatal("concurrent CommitRuntime() created multiple runtime owners")
		}
		runtime = candidate
	}
	if runtime == nil {
		t.Fatal("concurrent CommitRuntime() created no runtime owner")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("runtime Close() failed with code %s", CodeOf(err))
	}
}

// TestProtectedRuntimePreparationIsExactOnceAndClosedByRollback freezes preparation lifecycle.
func TestProtectedRuntimePreparationIsExactOnceAndClosedByRollback(t *testing.T) {
	owner, preparation, startup, capability, state := testPreparedProtectedRuntime(t)
	exactCapability := append([]byte(nil), state.capability[:]...)
	redisPasswordAlias := state.redisPassword
	sentinelPasswordAlias := state.redisSentinelPassword
	rootAlias := state.rootCertificatesDER[0]

	if duplicate, err := owner.PrepareRuntime(); duplicate != nil ||
		CodeOf(err) != CodeProtectedTransferred {
		t.Fatalf("duplicate PrepareRuntime() returned preparation=%v code=%s", duplicate, CodeOf(err))
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("prepared owner Close() failed with code %s", CodeOf(err))
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("repeated prepared owner Close() failed with code %s", CodeOf(err))
	}
	if preparation.StartupReplay().Snapshot().Valid() ||
		capability.Equal(exactCapability) {
		t.Fatal("prepared handles remained active after rollback")
	}
	if err := startup.UseReplayMaterial(func(ReplayMaterial) error { return nil }); CodeOf(err) != CodeProtectedClosed {
		t.Fatalf("startup handle after rollback returned code %s", CodeOf(err))
	}
	if runtime, err := owner.CommitRuntime(preparation); runtime != nil ||
		CodeOf(err) != CodeProtectedTransferred {
		t.Fatalf("commit after rollback returned runtime=%v code=%s", runtime, CodeOf(err))
	}
	if next, err := owner.PrepareRuntime(); next != nil ||
		CodeOf(err) != CodeProtectedClosed {
		t.Fatalf("prepare after rollback returned preparation=%v code=%s", next, CodeOf(err))
	}
	if !allZeroBytes(redisPasswordAlias) || !allZeroBytes(sentinelPasswordAlias) ||
		!allZeroBytes(rootAlias) {
		t.Fatal("prepared rollback retained protected backing bytes")
	}
}

// TestProtectedRuntimeCommitAndRollbackRaceHasOneTerminalOwner proves linearized handoff.
func TestProtectedRuntimeCommitAndRollbackRaceHasOneTerminalOwner(t *testing.T) {
	for range 128 {
		owner, preparation, startup, capability, state := testPreparedProtectedRuntime(t)
		exactCapability := append([]byte(nil), state.capability[:]...)
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)

		var (
			runtime   *RuntimeMaterial
			commitErr error
			closeErr  error
		)
		go func() {
			defer wait.Done()
			<-start
			runtime, commitErr = owner.CommitRuntime(preparation)
		}()
		go func() {
			defer wait.Done()
			<-start
			closeErr = owner.Close()
		}()
		close(start)
		wait.Wait()

		switch {
		case runtime != nil:
			if commitErr != nil || CodeOf(closeErr) != CodeProtectedTransferred {
				t.Fatalf("commit winner returned commit=%s close=%s", CodeOf(commitErr), CodeOf(closeErr))
			}
			if !capability.Equal(exactCapability) {
				t.Fatal("commit winner did not activate capability")
			}
			if err := runtime.Close(); err != nil {
				t.Fatalf("runtime winner Close() failed with code %s", CodeOf(err))
			}
			if err := owner.Close(); CodeOf(err) != CodeProtectedTransferred {
				t.Fatalf("stale prebootstrap owner returned code %s", CodeOf(err))
			}
		case closeErr == nil:
			if CodeOf(commitErr) != CodeProtectedTransferred {
				t.Fatalf("rollback winner returned commit code %s", CodeOf(commitErr))
			}
			if capability.Equal(exactCapability) {
				t.Fatal("rollback winner activated capability")
			}
			if err := startup.UseReplayMaterial(func(ReplayMaterial) error { return nil }); CodeOf(err) != CodeProtectedClosed {
				t.Fatalf("rollback startup handle returned code %s", CodeOf(err))
			}
		default:
			t.Fatalf("handoff race had no owner commit=%s close=%s", CodeOf(commitErr), CodeOf(closeErr))
		}
	}
}

// TestProtectedRuntimeRejectsZeroAndForgedOwners proves terminal provenance remains exact.
func TestProtectedRuntimeRejectsZeroAndForgedOwners(t *testing.T) {
	owner, preparation, _, _, state := testPreparedProtectedRuntime(t)
	if runtime, err := owner.CommitRuntime(nil); runtime != nil ||
		CodeOf(err) != CodeProtectedTransferred {
		t.Fatalf("nil CommitRuntime() returned runtime=%v code=%s", runtime, CodeOf(err))
	}
	if runtime, err := owner.CommitRuntime(&RuntimePreparation{}); runtime != nil ||
		CodeOf(err) != CodeProtectedTransferred {
		t.Fatalf("zero CommitRuntime() returned runtime=%v code=%s", runtime, CodeOf(err))
	}
	forged := &RuntimeMaterial{state: state, token: &runtimeToken{marker: 1}}
	if err := forged.Close(); CodeOf(err) != CodeProtectedTransferred {
		t.Fatalf("forged runtime Close() returned code %s", CodeOf(err))
	}
	runtime, err := owner.CommitRuntime(preparation)
	if err != nil {
		t.Fatalf("CommitRuntime() failed with code %s", CodeOf(err))
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("runtime Close() failed with code %s", CodeOf(err))
	}
	if err := forged.Close(); CodeOf(err) != CodeProtectedTransferred {
		t.Fatalf("terminal forged runtime Close() returned code %s", CodeOf(err))
	}
	if err := owner.Close(); CodeOf(err) != CodeProtectedTransferred {
		t.Fatalf("terminal stale owner returned code %s", CodeOf(err))
	}
}

// TestReplayRuntimePreparationPreservesOneGenerationAcrossCommit freezes atomic replay provenance.
func TestReplayRuntimePreparationPreservesOneGenerationAcrossCommit(t *testing.T) {
	owner, preparation, _, _, state := testPreparedProtectedRuntime(t)
	replayPreparation := preparation.ReplayRuntime()
	var startupHMAC, startupPassword []byte
	if err := replayPreparation.UseReplayMaterial(
		func(material ReplayMaterial) error {
			startupHMAC = append([]byte(nil), material.HMAC()...)
			startupPassword = append([]byte(nil), material.Password()...)
			return nil
		},
	); err != nil {
		t.Fatalf("prepared replay borrow failed with code %s", CodeOf(err))
	}
	if !bytes.Equal(startupHMAC, state.hmac[:]) || string(startupPassword) != testRedisPassMarker {
		t.Fatal("prepared replay borrow crossed generations")
	}
	runtime, err := owner.CommitRuntime(preparation)
	if err != nil {
		t.Fatalf("CommitRuntime() failed with code %s", CodeOf(err))
	}
	if err := replayPreparation.UseReplayMaterial(
		func(ReplayMaterial) error { return nil },
	); CodeOf(err) != CodeProtectedClosed {
		t.Fatalf("startup replay remained active with code %s", CodeOf(err))
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("runtime Close() failed with code %s", CodeOf(err))
	}
	if err := replayPreparation.UseReplayMaterial(func(ReplayMaterial) error { return nil }); CodeOf(err) != CodeProtectedClosed {
		t.Fatalf("replay preparation revived after close with code %s", CodeOf(err))
	}
	var zero ReplayRuntimePreparation
	if zero.Snapshot().Valid() {
		t.Fatal("zero replay preparation exposed a snapshot")
	}
	if err := zero.UseReplayMaterial(func(ReplayMaterial) error { return nil }); CodeOf(err) != CodeProtectedClosed {
		t.Fatalf("zero replay preparation returned code %s", CodeOf(err))
	}
}
