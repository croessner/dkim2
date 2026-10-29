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
	testRedisPassMarker  = "REDIS_PASSWORD_PRIVATE_MARKER"
	testSentinelMarker   = "SENTINEL_PASSWORD_PRIVATE_MARKER"
	testClientCertMarker = "CLIENT_CERTIFICATE_PRIVATE_MARKER"
	testClientKeyMarker  = "CLIENT_KEY_PRIVATE_MARKER"
	testRootMarker       = "ROOT_PRIVATE_MARKER"
)

// TestProcessCapabilityComparisonIsOpaqueAndExact freezes the comparison-only
// capability contract and rejects every non-exact candidate.
func TestProcessCapabilityComparisonIsOpaqueAndExact(t *testing.T) {
	runtime, _, capability, state := testCommittedProtectedRuntime(t)
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
	prebootstrap, preparation, startup, capability, _ := testPreparedProtectedRuntime(t)
	material := ReplayMaterial{lease: &replayMaterialLease{hmac: []byte(testHMACMarker), password: []byte(testRedisPassMarker)}}
	replayPreparation := preparation.ReplayRuntime()
	runtime, err := prebootstrap.CommitRuntime(preparation)
	if err != nil {
		t.Fatalf("CommitRuntime() failed with code %s", CodeOf(err))
	}

	for _, value := range []any{
		*prebootstrap, prebootstrap,
		*preparation, preparation,
		startup, &startup,
		material, &material,
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
	owner, preparation, startup, capability, _ := testPreparedProtectedRuntime(t)
	material := ReplayMaterial{lease: &replayMaterialLease{
		hmac: []byte(testHMACMarker), password: []byte(testRedisPassMarker),
		sentinelPassword: []byte(testSentinelMarker), clientCertificatePEM: []byte(testClientCertMarker),
		clientKeyPEM: []byte(testClientKeyMarker), rootsDER: [][]byte{[]byte(testRootMarker)},
	}}
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
		material,
		&material,
		replayPreparation,
		&replayPreparation,
		*runtime,
		runtime,
		capability,
		&capability,
		any(capability),
		[]any{
			owner, preparation, startup, material, replayPreparation,
			runtime, capability, &capability,
		},
		map[string]any{
			"owner": owner, "preparation": preparation, "startup": startup,
			"material": material, "replay": replayPreparation,
			"runtime": runtime, "capability": capability,
		},
		struct {
			Owner       *Prebootstrap
			Preparation *RuntimePreparation
			Startup     ReplayStartupMaterial
			Material    ReplayMaterial
			Replay      ReplayRuntimePreparation
			Runtime     *RuntimeMaterial
			Capability  ProcessCapability
		}{
			Owner: owner, Preparation: preparation, Startup: startup,
			Material: material, Replay: replayPreparation,
			Runtime: runtime, Capability: capability,
		},
	}
	markers := []string{
		testCapabilityMarker,
		testHMACMarker,
		testRedisPassMarker,
		testSentinelMarker,
		testClientCertMarker,
		testClientKeyMarker,
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
	owner, _, startup, _, _ := testPreparedProtectedRuntime(t)
	err := startup.UseReplayMaterial(func(material ReplayMaterial) error {
		return fmt.Errorf("toxic:%x:%s", material.HMAC(), material.Password())
	})
	if CodeOf(err) != CodeProtectedContent {
		t.Fatalf("toxic callback failure returned code %s", CodeOf(err))
	}
	for _, marker := range []string{testHMACMarker, fmt.Sprintf("%x", []byte(testHMACMarker)), testRedisPassMarker} {
		if strings.Contains(err.Error(), marker) {
			t.Fatal("UseReplayMaterial() exposed callback error content")
		}
	}
	_ = owner.Close()
}

// TestReplayMaterialContainsToxicPanics clears clones and returns only a stable code.
func TestReplayMaterialContainsToxicPanics(t *testing.T) {
	for _, panicWithError := range []bool{false, true} {
		owner, preparation, startup, _, _ := testPreparedProtectedRuntime(t)
		var borrowed ReplayMaterial
		err := startup.UseReplayMaterial(func(material ReplayMaterial) error {
			borrowed = material
			if panicWithError {
				panic(fmt.Errorf("toxic:%x", material.HMAC()))
			}
			panic("toxic:" + string(material.Password()))
		})
		if CodeOf(err) != CodeProtectedContent || !allZeroBytes(borrowed.HMAC()) || !allZeroBytes(borrowed.Password()) ||
			!allZeroBytes(borrowed.ClientKeyPEM()) {
			t.Fatalf("toxic panic returned code %s or retained bytes", CodeOf(err))
		}
		if err := startup.UseReplayMaterial(func(ReplayMaterial) error { return nil }); err != nil {
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
	owner, preparation, startup, _, state := testPreparedProtectedRuntime(t)
	var (
		borrowed          ReplayMaterial
		nestedBorrowCode  Code
		activeReleaseCode Code
	)
	err := startup.UseReplayMaterial(func(material ReplayMaterial) error {
		borrowed = material
		if string(material.Password()) != testRedisPassMarker ||
			string(material.SentinelPassword()) != testSentinelMarker ||
			string(material.ClientCertificatePEM()) != testClientCertMarker ||
			string(material.ClientKeyPEM()) != testClientKeyMarker ||
			len(material.RootsDER()) != 1 || string(material.RootsDER()[0]) != testRootMarker {
			t.Fatal("UseReplayMaterial() lent different material")
		}
		nestedBorrowCode = CodeOf(startup.UseReplayMaterial(func(ReplayMaterial) error { return nil }))
		activeReleaseCode = CodeOf(owner.Close())
		for _, value := range [][]byte{
			material.HMAC(), material.Password(), material.SentinelPassword(),
			material.ClientCertificatePEM(), material.ClientKeyPEM(),
		} {
			for index := range value {
				value[index] = 'x'
			}
		}
		for index := range material.RootsDER() {
			clear(material.RootsDER()[index])
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
	if !allZeroBytes(borrowed.HMAC()) ||
		!allZeroBytes(borrowed.Password()) ||
		!allZeroBytes(borrowed.SentinelPassword()) ||
		!allZeroBytes(borrowed.ClientCertificatePEM()) ||
		!allZeroBytes(borrowed.ClientKeyPEM()) ||
		len(borrowed.RootsDER()) != 1 ||
		borrowed.RootsDER()[0] != nil {
		t.Fatal("UseReplayMaterial() retained callback-local protected bytes after return")
	}
	if !protectedReplayStateIntact(state) {
		t.Fatal("UseReplayMaterial() allowed callback mutation of owned material")
	}
	runtime, err := owner.CommitRuntime(preparation)
	if err != nil {
		t.Fatalf("CommitRuntime() after borrow return failed with code %s", CodeOf(err))
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() after borrow return failed with code %s", CodeOf(err))
	}
	if state.redisPassword != nil || state.redisSentinelPassword != nil ||
		state.redisClientCertificatePEM != nil || state.redisClientKeyPEM != nil {
		t.Fatal("runtime Close() retained Redis protected material")
	}
}

// TestReplayMaterialOmitsUnconfiguredOptionalRoles proves absent optional
// Redis material is lent as nil rather than as an empty credential.
func TestReplayMaterialOmitsUnconfiguredOptionalRoles(t *testing.T) {
	owner, _, startup, _, state := testPreparedProtectedRuntime(t)
	state.redisPassword = nil
	state.redisSentinelPassword = nil
	state.redisClientCertificatePEM = nil
	state.redisClientKeyPEM = nil
	state.rootCertificatesDER = nil
	err := startup.UseReplayMaterial(func(material ReplayMaterial) error {
		if len(material.HMAC()) != exactKeyBytes || material.Password() != nil || material.SentinelPassword() != nil ||
			material.ClientCertificatePEM() != nil || material.ClientKeyPEM() != nil || len(material.RootsDER()) != 0 {
			t.Fatal("UseReplayMaterial() invented absent optional material")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("UseReplayMaterial() failed with code %s", CodeOf(err))
	}
	var zero ReplayStartupMaterial
	if CodeOf(zero.UseReplayMaterial(func(ReplayMaterial) error { return nil })) != CodeProtectedClosed ||
		CodeOf(startup.UseReplayMaterial(nil)) != CodeProtectedClosed {
		t.Fatal("UseReplayMaterial() accepted a missing owner or callback")
	}
	_ = owner.Close()
}

// TestReplayMaterialBorrowRejectsConcurrentUse freezes immediate closed errors
// for overlapping borrows without waiting on the active callback.
func TestReplayMaterialBorrowRejectsConcurrentUse(t *testing.T) {
	owner, _, startup, _, _ := testPreparedProtectedRuntime(t)
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
	if err := startup.UseReplayMaterial(func(ReplayMaterial) error { return nil }); CodeOf(err) != CodeProtectedClosed {
		t.Fatalf("concurrent UseReplayMaterial() returned code %s", CodeOf(err))
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatalf("active UseReplayMaterial() failed with code %s", CodeOf(err))
	}
	_ = owner.Close()
}

// protectedReplayStateIntact reports whether the owner still holds the
// original replay fixture markers after a borrow.
func protectedReplayStateIntact(state *protectedState) bool {
	return strings.Contains(string(state.hmac[:]), testHMACMarker) &&
		string(state.redisPassword) == testRedisPassMarker &&
		string(state.redisSentinelPassword) == testSentinelMarker &&
		string(state.redisClientCertificatePEM) == testClientCertMarker &&
		string(state.redisClientKeyPEM) == testClientKeyMarker &&
		strings.Contains(string(state.rootCertificatesDER[0]), testRootMarker)
}

// testProtectedRuntimeState constructs one runtime-owned protected fixture
// without involving filesystem policy.
func testProtectedRuntimeState() *protectedState {
	state := &protectedState{
		phase:                     protectedOwnedByRuntime,
		hasHMAC:                   true,
		redisPassword:             []byte(testRedisPassMarker),
		redisSentinelPassword:     []byte(testSentinelMarker),
		redisClientCertificatePEM: []byte(testClientCertMarker),
		redisClientKeyPEM:         []byte(testClientKeyMarker),
		rootCertificatesDER:       [][]byte{[]byte(testRootMarker)},
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
	return owner, preparation, preparation.StartupReplay(), preparation.ProcessCapability(), state
}

// testCommittedProtectedRuntime constructs one committed runtime and its prepared handles.
func testCommittedProtectedRuntime(
	t *testing.T,
) (
	*RuntimeMaterial,
	ReplayStartupMaterial,
	ProcessCapability,
	*protectedState,
) {
	t.Helper()
	owner, preparation, startup, capability, state := testPreparedProtectedRuntime(t)
	runtime, err := owner.CommitRuntime(preparation)
	if err != nil {
		t.Fatalf("CommitRuntime() failed with code %s", CodeOf(err))
	}
	return runtime, startup, capability, state
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
