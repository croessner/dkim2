package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

const (
	testCapabilityMarker = "CAPABILITY_PRIVATE_MARKER"
	testHMACMarker       = "HMAC_PRIVATE_MARKER"
	testAppPassMarker    = "APPLICATION_PRIVATE_MARKER"
	testAuditPassMarker  = "AUDITOR_PRIVATE_MARKER"
	testRootMarker       = "ROOT_PRIVATE_MARKER"
)

// TestProcessCapabilityComparisonIsOpaqueAndExact freezes the comparison-only
// capability contract and rejects every non-exact candidate.
func TestProcessCapabilityComparisonIsOpaqueAndExact(t *testing.T) {
	runtime, _, _, capability, state := testCommittedProtectedRuntime(t)
	exact := append([]byte(nil), state.capability[:]...)

	if !capability.Equal(exact) {
		t.Fatal("ProcessCapability.Equal() rejected the exact capability")
	}
	different := append([]byte(nil), exact...)
	different[len(different)-1] ^= 0xff
	for _, candidate := range [][]byte{
		nil,
		exact[:len(exact)-1],
		append(exact, 0),
		different,
	} {
		if capability.Equal(candidate) {
			t.Fatal("ProcessCapability.Equal() accepted a non-exact candidate")
		}
	}

	if err := runtime.Close(); err != nil {
		t.Fatalf("RuntimeMaterial.Close() failed with code %s", CodeOf(err))
	}
	if capability.Equal(exact) {
		t.Fatal("ProcessCapability.Equal() accepted a candidate after release")
	}
	if (ProcessCapability{}).Equal(exact) {
		t.Fatal("zero ProcessCapability accepted a candidate")
	}
}

// TestProtectedOwnersRejectSerialization freezes JSON and text resistance for
// every protected owner and capability handle.
func TestProtectedOwnersRejectSerialization(t *testing.T) {
	prebootstrap, preparation, startup, auditor, capability, _ := testPreparedProtectedRuntime(t)
	replayPreparation := preparation.ReplayRuntime()
	runtime, err := prebootstrap.CommitRuntime(preparation)
	if err != nil {
		t.Fatalf("CommitRuntime() failed with code %s", CodeOf(err))
	}

	for _, value := range []any{
		*prebootstrap, prebootstrap,
		*preparation, preparation,
		startup, &startup,
		auditor, &auditor,
		replayPreparation, &replayPreparation,
		*runtime, runtime,
		capability, &capability,
	} {
		encoded, err := json.Marshal(value)
		if encoded != nil || CodeOf(err) != CodeSerialization {
			t.Fatalf("%T allowed JSON serialization", value)
		}
		marshaler, ok := value.(interface{ MarshalText() ([]byte, error) })
		if !ok {
			t.Fatalf("%T lacks explicit text-serialization rejection", value)
		}
		encoded, err = marshaler.MarshalText()
		if encoded != nil || CodeOf(err) != CodeSerialization {
			t.Fatalf("%T allowed text serialization", value)
		}
	}
}

// TestProtectedFormattingStaysContentFreeInNestedSinks exercises formatting
// paths that otherwise bypass ordinary String methods.
func TestProtectedFormattingStaysContentFreeInNestedSinks(t *testing.T) {
	owner, preparation, startup, auditor, capability, _ := testPreparedProtectedRuntime(t)
	replayPreparation := preparation.ReplayRuntime()
	runtime, err := owner.CommitRuntime(preparation)
	if err != nil {
		t.Fatalf("CommitRuntime() failed with code %s", CodeOf(err))
	}
	values := []any{
		*preparation,
		preparation,
		startup,
		&startup,
		auditor,
		&auditor,
		replayPreparation,
		&replayPreparation,
		*runtime,
		runtime,
		capability,
		&capability,
		any(capability),
		[]any{
			owner, preparation, startup, auditor, replayPreparation,
			runtime, capability, &capability,
		},
		map[string]any{
			"owner": owner, "preparation": preparation, "startup": startup,
			"auditor": auditor, "replay": replayPreparation,
			"runtime": runtime, "capability": capability,
		},
		struct {
			Owner       *Prebootstrap
			Preparation *RuntimePreparation
			Startup     ReplayStartupMaterial
			Auditor     ReplayAuditorMaterial
			Replay      ReplayRuntimePreparation
			Runtime     *RuntimeMaterial
			Capability  ProcessCapability
		}{
			Owner: owner, Preparation: preparation, Startup: startup,
			Auditor: auditor, Replay: replayPreparation,
			Runtime: runtime, Capability: capability,
		},
	}
	markers := []string{
		testCapabilityMarker,
		testHMACMarker,
		testAppPassMarker,
		testAuditPassMarker,
		testRootMarker,
	}
	for _, value := range values {
		for _, format := range []string{"%s", "%q", "%v", "%+v", "%#v", "%x", "%p"} {
			rendered := fmt.Sprintf(format, value)
			for _, marker := range markers {
				needles := []string{
					marker,
					hex.EncodeToString([]byte(marker)),
					decimalByteNeedle([]byte(marker)),
				}
				if containsAnyProtectedNeedle(rendered, needles) {
					t.Fatalf("protected formatting exposed a marker for %T with %s", value, format)
				}
			}
		}
	}
}

// decimalByteNeedle renders the prefix shared by slice and fixed-array diagnostics.
func decimalByteNeedle(value []byte) string {
	var rendered strings.Builder
	rendered.WriteByte('[')
	for index, octet := range value {
		if index > 0 {
			rendered.WriteByte(' ')
		}
		rendered.WriteString(strconv.Itoa(int(octet)))
	}
	return rendered.String()
}

// containsAnyProtectedNeedle reports whether one diagnostic carries a secret encoding.
func containsAnyProtectedNeedle(rendered string, needles []string) bool {
	for _, needle := range needles {
		if needle != "" && strings.Contains(rendered, needle) {
			return true
		}
	}
	return false
}

// TestReplayMaterialMapsToxicCallbackErrors freezes content-free outward failures.
func TestReplayMaterialMapsToxicCallbackErrors(t *testing.T) {
	owner, _, startup, _, _, _ := testPreparedProtectedRuntime(t)
	err := startup.UseReplayMaterial(func(hmac, _, _ []byte, _ [][]byte) error {
		return fmt.Errorf("toxic:%x", hmac)
	})
	if CodeOf(err) != CodeProtectedContent {
		t.Fatalf("toxic callback failure returned code %s", CodeOf(err))
	}
	for _, marker := range []string{testHMACMarker, fmt.Sprintf("%x", []byte(testHMACMarker))} {
		if strings.Contains(err.Error(), marker) {
			t.Fatal("UseReplayMaterial() exposed callback error content")
		}
	}
	_ = owner.Close()
}

// TestReplayMaterialContainsToxicPanics clears clones and returns only a stable code.
func TestReplayMaterialContainsToxicPanics(t *testing.T) {
	for _, panicWithError := range []bool{false, true} {
		owner, preparation, startup, _, _, _ := testPreparedProtectedRuntime(t)
		var borrowed []byte
		err := startup.UseReplayMaterial(func(hmac, _, _ []byte, _ [][]byte) error {
			borrowed = hmac
			if panicWithError {
				panic(fmt.Errorf("toxic:%x", hmac))
			}
			panic("toxic:" + string(hmac))
		})
		if CodeOf(err) != CodeProtectedContent || !allZeroBytes(borrowed) {
			t.Fatalf("toxic panic returned code %s or retained bytes", CodeOf(err))
		}
		if err := startup.UseReplayMaterial(func(_, _, _ []byte, _ [][]byte) error { return nil }); err != nil {
			t.Fatalf("owner unusable after contained panic: %s", CodeOf(err))
		}
		runtime, err := owner.CommitRuntime(preparation)
		if err != nil {
			t.Fatalf("CommitRuntime() after contained panic failed: %s", CodeOf(err))
		}
		if err := runtime.Close(); err != nil {
			t.Fatalf("owner close after contained panic failed: %s", CodeOf(err))
		}
	}
}

// TestReplayMaterialBorrowIsIsolated freezes callback-local cloning, deferred
// clone clearing, and rejection of nested ownership operations.
func TestReplayMaterialBorrowIsIsolated(t *testing.T) {
	owner, preparation, startup, _, _, state := testPreparedProtectedRuntime(t)
	var (
		borrowedHMAC      []byte
		borrowedAppPass   []byte
		borrowedAuditPass []byte
		borrowedRoots     [][]byte
		nestedBorrowCode  Code
		activeReleaseCode Code
	)
	err := startup.UseReplayMaterial(func(hmac, applicationPassword, auditorPassword []byte, rootsDER [][]byte) error {
		borrowedHMAC = hmac
		borrowedAppPass = applicationPassword
		borrowedAuditPass = auditorPassword
		borrowedRoots = rootsDER
		nestedBorrowCode = CodeOf(startup.UseReplayMaterial(
			func(_, _, _ []byte, _ [][]byte) error { return nil },
		))
		activeReleaseCode = CodeOf(owner.Close())
		clear(hmac)
		clear(applicationPassword)
		clear(auditorPassword)
		for index := range rootsDER {
			clear(rootsDER[index])
		}
		return nil
	})
	if err != nil {
		t.Fatalf("UseReplayMaterial() failed with code %s", CodeOf(err))
	}
	if nestedBorrowCode != CodeProtectedClosed {
		t.Fatalf("nested UseReplayMaterial() returned code %s", nestedBorrowCode)
	}
	if activeReleaseCode != CodeProtectedTransferred {
		t.Fatalf("Close() during active borrow returned code %s", activeReleaseCode)
	}
	if !allZeroBytes(borrowedHMAC) ||
		!allZeroBytes(borrowedAppPass) ||
		!allZeroBytes(borrowedAuditPass) ||
		len(borrowedRoots) != 1 ||
		borrowedRoots[0] != nil {
		t.Fatal("UseReplayMaterial() retained callback-local protected bytes after return")
	}
	if !strings.Contains(string(state.hmac[:]), testHMACMarker) ||
		!strings.Contains(string(state.applicationPassword), testAppPassMarker) ||
		!strings.Contains(string(state.auditorPassword), testAuditPassMarker) ||
		!strings.Contains(string(state.rootCertificatesDER[0]), testRootMarker) {
		t.Fatal("UseReplayMaterial() allowed callback mutation of owned material")
	}
	runtime, err := owner.CommitRuntime(preparation)
	if err != nil {
		t.Fatalf("CommitRuntime() after borrow return failed with code %s", CodeOf(err))
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() after borrow return failed with code %s", CodeOf(err))
	}
}

// TestReplayMaterialBorrowRejectsConcurrentUse freezes immediate closed errors
// for overlapping borrows without waiting on the active callback.
func TestReplayMaterialBorrowRejectsConcurrentUse(t *testing.T) {
	owner, _, startup, _, _, _ := testPreparedProtectedRuntime(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- startup.UseReplayMaterial(func(_, _, _ []byte, _ [][]byte) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	if err := startup.UseReplayMaterial(func(_, _, _ []byte, _ [][]byte) error { return nil }); CodeOf(err) != CodeProtectedClosed {
		t.Fatalf("concurrent UseReplayMaterial() returned code %s", CodeOf(err))
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatalf("active UseReplayMaterial() failed with code %s", CodeOf(err))
	}
	_ = owner.Close()
}

// TestReplayAuditorBorrowUsesLeastAuthority proves periodic audits receive only one fresh clone.
func TestReplayAuditorBorrowUsesLeastAuthority(t *testing.T) {
	runtime, auditor, _, _, state := testCommittedProtectedRuntime(t)
	var borrowed []byte
	err := auditor.UseReplayAuditorPassword(func(auditorPassword []byte) error {
		borrowed = auditorPassword
		if string(auditorPassword) != testAuditPassMarker {
			t.Fatal("auditor-only borrow changed credential bytes")
		}
		clear(auditorPassword)
		return nil
	})
	if err != nil || !allZeroBytes(borrowed) {
		t.Fatalf("UseReplayAuditorPassword() failed with code %s or retained bytes", CodeOf(err))
	}
	if string(state.auditorPassword) != testAuditPassMarker ||
		!strings.Contains(string(state.hmac[:]), testHMACMarker) ||
		!strings.Contains(string(state.applicationPassword), testAppPassMarker) ||
		!strings.Contains(string(state.rootCertificatesDER[0]), testRootMarker) {
		t.Fatal("auditor-only borrow mutated owner state or broadened authority")
	}
	_ = runtime.Close()
}

// TestReplayAuditorBorrowContainsFailures proves errors and panics release the shared gate.
func TestReplayAuditorBorrowContainsFailures(t *testing.T) {
	for _, panicCallback := range []bool{false, true} {
		runtime, auditor, _, _, _ := testCommittedProtectedRuntime(t)
		var borrowed []byte
		err := auditor.UseReplayAuditorPassword(func(auditorPassword []byte) error {
			borrowed = auditorPassword
			if panicCallback {
				panic("toxic:" + string(auditorPassword))
			}
			return fmt.Errorf("toxic:%x", auditorPassword)
		})
		if CodeOf(err) != CodeProtectedContent || !allZeroBytes(borrowed) ||
			strings.Contains(err.Error(), testAuditPassMarker) {
			t.Fatal("auditor-only failure escaped content or retained bytes")
		}
		if retryErr := auditor.UseReplayAuditorPassword(func([]byte) error { return nil }); retryErr != nil {
			t.Fatalf("auditor owner unusable after failure: %s", CodeOf(retryErr))
		}
		if closeErr := runtime.Close(); closeErr != nil {
			t.Fatalf("auditor owner close after failure: %s", CodeOf(closeErr))
		}
	}
}

// TestReplayAuditorBorrowSharesTheExclusiveGate proves full and narrow borrows never overlap.
func TestReplayAuditorBorrowSharesTheExclusiveGate(t *testing.T) {
	runtime, auditor, startup, _, _ := testCommittedProtectedRuntime(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- auditor.UseReplayAuditorPassword(func([]byte) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	if err := startup.UseReplayMaterial(func(_, _, _ []byte, _ [][]byte) error { return nil }); CodeOf(err) != CodeProtectedClosed {
		t.Fatalf("overlapping full borrow returned code %s", CodeOf(err))
	}
	if err := auditor.UseReplayAuditorPassword(func([]byte) error { return nil }); CodeOf(err) != CodeProtectedClosed {
		t.Fatalf("overlapping auditor borrow returned code %s", CodeOf(err))
	}
	if err := runtime.Close(); CodeOf(err) != CodeProtectedTransferred {
		t.Fatalf("close during auditor borrow returned code %s", CodeOf(err))
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatalf("active auditor borrow failed with code %s", CodeOf(err))
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close after auditor borrow failed with code %s", CodeOf(err))
	}
	if err := auditor.UseReplayAuditorPassword(func([]byte) error { return nil }); CodeOf(err) != CodeProtectedClosed {
		t.Fatalf("borrow after close returned code %s", CodeOf(err))
	}
}

// TestReplayAuditorBorrowRejectsMissingAuthority proves the narrow seam is Valkey-only.
func TestReplayAuditorBorrowRejectsMissingAuthority(t *testing.T) {
	var nilAuditor ReplayAuditorMaterial
	if err := nilAuditor.UseReplayAuditorPassword(func([]byte) error { return nil }); CodeOf(err) != CodeProtectedClosed {
		t.Fatalf("nil runtime borrow returned code %s", CodeOf(err))
	}
	runtime, auditor, _, _, state := testCommittedProtectedRuntime(t)
	if err := auditor.UseReplayAuditorPassword(nil); CodeOf(err) != CodeProtectedClosed {
		t.Fatalf("nil callback borrow returned code %s", CodeOf(err))
	}
	state.auditorPassword = nil
	if err := auditor.UseReplayAuditorPassword(func([]byte) error { return nil }); CodeOf(err) != CodeProtectedContent {
		t.Fatalf("missing auditor credential returned code %s", CodeOf(err))
	}
	if state.borrowed {
		t.Fatal("missing auditor credential left borrow gate occupied")
	}
	_ = runtime.Close()
}

// testProtectedRuntimeState constructs one runtime-owned protected fixture
// without involving filesystem policy.
func testProtectedRuntimeState() *protectedState {
	state := &protectedState{
		phase:               protectedOwnedByRuntime,
		hasHMAC:             true,
		applicationPassword: []byte(testAppPassMarker),
		auditorPassword:     []byte(testAuditPassMarker),
		rootCertificatesDER: [][]byte{[]byte(testRootMarker)},
	}
	copy(state.capability[:], []byte(testCapabilityMarker))
	copy(state.hmac[:], []byte(testHMACMarker))
	return state
}

// testPreparedProtectedRuntime constructs one exact prepared non-owning handle set.
func testPreparedProtectedRuntime(
	t *testing.T,
) (
	*Prebootstrap,
	*RuntimePreparation,
	ReplayStartupMaterial,
	ReplayAuditorMaterial,
	ProcessCapability,
	*protectedState,
) {
	t.Helper()
	state := testProtectedRuntimeState()
	state.phase = protectedOwnedByPrebootstrap
	owner := &Prebootstrap{state: state}
	preparation, err := owner.PrepareRuntime()
	if err != nil {
		t.Fatalf("PrepareRuntime() failed with code %s", CodeOf(err))
	}
	return owner, preparation, preparation.StartupReplay(),
		preparation.ReplayAuditor(), preparation.ProcessCapability(), state
}

// testCommittedProtectedRuntime constructs one committed runtime and its prepared handles.
func testCommittedProtectedRuntime(
	t *testing.T,
) (
	*RuntimeMaterial,
	ReplayAuditorMaterial,
	ReplayStartupMaterial,
	ProcessCapability,
	*protectedState,
) {
	t.Helper()
	owner, preparation, startup, auditor, capability, state := testPreparedProtectedRuntime(t)
	runtime, err := owner.CommitRuntime(preparation)
	if err != nil {
		t.Fatalf("CommitRuntime() failed with code %s", CodeOf(err))
	}
	return runtime, auditor, startup, capability, state
}

// allZeroBytes reports whether a callback-local protected clone was cleared.
func allZeroBytes(value []byte) bool {
	for _, octet := range value {
		if octet != 0 {
			return false
		}
	}
	return true
}
