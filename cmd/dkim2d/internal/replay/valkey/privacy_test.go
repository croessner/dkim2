package valkey

import (
	"context"
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	dkim2 "github.com/croessner/dkim2"
	valkeygo "github.com/valkey-io/valkey-go"
)

// privacyContract freezes the protected formatting and serialization boundary.
type privacyContract interface {
	fmt.Stringer
	fmt.GoStringer
	fmt.Formatter
	json.Marshaler
	encoding.TextMarshaler
}

// requirePrivacyContract makes both value and pointer method sets compile-time obligations.
func requirePrivacyContract[T privacyContract]() {}

// TestStorePrivacyCoversPointerAndDereferencedValue prevents lock-bearing value formatting bypass.
func TestStorePrivacyCoversPointerAndDereferencedValue(t *testing.T) {
	requirePrivacyContract[Store]()
	requirePrivacyContract[*Store]()

	client := &fakeCommandClient{key: syntheticSecretMarker}
	store := mustCommandStore(t, client)
	authority := auditAuthority{
		endpoint:      syntheticSecretMarker,
		tlsServerName: syntheticSecretMarker,
	}
	applicationUsername := syntheticSecretMarker
	attestation := OperatorAttestation{saveSchedule: syntheticSecretMarker}
	store.authority = &authority
	store.applicationUsername = &applicationUsername
	store.attestation = &attestation
	dereferenced := reflect.ValueOf(store).Elem().Interface()
	for name, value := range map[string]any{
		testNamePointer: store,
		"dereferenced":  dereferenced,
	} {
		t.Run(name, func(t *testing.T) {
			for _, format := range []string{"%v", testFormatDetailed, testFormatGoSyntax, "%s", "%q", "%x", "%X"} {
				if formatted := fmt.Sprintf(format, value); formatted != storeRedactedText {
					t.Fatalf("format %q produced non-redacted output %q", format, formatted)
				}
			}
			if formatted := fmt.Sprintf("%p", value); containsProtectedMarker(formatted) {
				t.Fatal("pointer formatting exposed protected store state")
			}
			if encoded, err := json.Marshal(value); err == nil || len(encoded) != 0 {
				t.Fatal("replay store unexpectedly marshaled as JSON")
			}
			textMarshaler, ok := value.(encoding.TextMarshaler)
			if !ok {
				t.Fatal("replay store does not own text-marshaling rejection")
			}
			if encoded, err := textMarshaler.MarshalText(); err == nil || len(encoded) != 0 {
				t.Fatal("replay store unexpectedly marshaled as text")
			}
		})
	}
}

// TestOperatorAttestationInputPrivacyIsContentFreeAndSerializationRejected protects raw assertions.
func TestOperatorAttestationInputPrivacyIsContentFreeAndSerializationRejected(t *testing.T) {
	requirePrivacyContract[OperatorAttestationInput]()
	requirePrivacyContract[*OperatorAttestationInput]()

	input := validOperatorAttestationInput()
	input.SaveSchedule = syntheticSecretMarker
	for name, value := range map[string]any{
		"value":         input,
		testNamePointer: &input,
	} {
		t.Run(name, func(t *testing.T) {
			for _, format := range []string{"%v", testFormatDetailed, testFormatGoSyntax, "%s", "%q", "%x", "%X"} {
				if formatted := fmt.Sprintf(format, value); formatted != operatorAttestationRedactedText {
					t.Fatalf("format %q produced non-redacted output %q", format, formatted)
				}
			}
			if name == testNamePointer {
				if formatted := fmt.Sprintf("%p", value); containsProtectedMarker(formatted) {
					t.Fatal("pointer formatting exposed protected operator input")
				}
			}
			if encoded, err := json.Marshal(value); err == nil || len(encoded) != 0 {
				t.Fatal("operator attestation input unexpectedly marshaled as JSON")
			}
			textMarshaler, ok := value.(encoding.TextMarshaler)
			if !ok {
				t.Fatal("operator attestation input does not own text-marshaling rejection")
			}
			if encoded, err := textMarshaler.MarshalText(); err == nil || len(encoded) != 0 {
				t.Fatal("operator attestation input unexpectedly marshaled as text")
			}
		})
	}
}

// TestCopiedStoreSharesChecksRevalidationStateAndCloseOwnership freezes wrapper identity.
func TestCopiedStoreSharesChecksRevalidationStateAndCloseOwnership(t *testing.T) {
	owned := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	store := mustProductionStore(t, validProductionDependencies(t, owned))
	copied := *store
	if copied.storeCore != store.storeCore {
		t.Fatal("copied replay store split its private core")
	}

	store.client = &fakeCommandClient{
		command: fakeCommand{},
		result:  resultFromMessage(t, cachedMessage(t, '+', "OK")),
	}
	key := validReplayKey(t)
	var wait sync.WaitGroup
	wait.Add(3)
	var check dkim2.ReplayCheck
	var checkErr error
	var revalidateErr error
	go func() {
		defer wait.Done()
		check, checkErr = copied.CheckAndRemember(
			context.Background(),
			key,
			dkim2.DefaultReplayRetention(),
		)
	}()
	go func() {
		defer wait.Done()
		revalidateErr = store.Revalidate(context.Background(), validAuditorConfig())
	}()
	go func() {
		defer wait.Done()
		for range 64 {
			if state := copied.State(); state != dkim2.ReplayStoreReady {
				t.Errorf("copied state=%q while shared operations were healthy", state)
				return
			}
		}
	}()
	wait.Wait()
	if checkErr != nil || check != dkim2.ReplayCheckFirstSeen {
		t.Fatalf("copied check=%q code=%q", check, dkim2.ReplayErrorCodeOf(checkErr))
	}
	if revalidateErr != nil {
		t.Fatalf("original revalidation code=%q", dkim2.ReplayErrorCodeOf(revalidateErr))
	}
	if store.State() != dkim2.ReplayStoreReady || copied.State() != dkim2.ReplayStoreReady {
		t.Fatal("copied wrapper did not share ready state")
	}

	wait.Add(2)
	closeErrors := make(chan error, 2)
	go func() {
		defer wait.Done()
		closeErrors <- store.Close(context.Background())
	}()
	go func() {
		defer wait.Done()
		closeErrors <- copied.Close(context.Background())
	}()
	wait.Wait()
	close(closeErrors)
	for err := range closeErrors {
		if err != nil {
			t.Fatalf("shared close failed with code %q", dkim2.ReplayErrorCodeOf(err))
		}
	}
	if owned.closeCalls.Load() != 1 ||
		store.State() != dkim2.ReplayStoreClosed ||
		copied.State() != dkim2.ReplayStoreClosed ||
		!nilInterface(store.client) ||
		!nilInterface(copied.client) {
		t.Fatal("copied wrapper split terminal lifecycle or client ownership")
	}
}

// TestNilAndZeroStoreWrappersFailClosedWithoutPanics freezes invalid wrapper behavior.
func TestNilAndZeroStoreWrappersFailClosedWithoutPanics(t *testing.T) {
	for name, store := range map[string]*Store{
		testNameNil: nil,
		"zero":      {},
	} {
		t.Run(name, func(t *testing.T) {
			if state := store.State(); state != dkim2.ReplayStoreDegraded {
				t.Fatalf("invalid wrapper state=%q", state)
			}
			if _, err := store.CheckAndRemember(
				context.Background(),
				dkim2.ReplayKey{},
				dkim2.DefaultReplayRetention(),
			); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInvalidRequest {
				t.Fatalf("invalid wrapper check code=%q", dkim2.ReplayErrorCodeOf(err))
			}
			if err := store.Revalidate(
				context.Background(),
				validAuditorConfig(),
			); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorMisconfigured {
				t.Fatalf("invalid wrapper revalidation code=%q", dkim2.ReplayErrorCodeOf(err))
			}
			if err := store.Close(context.Background()); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorMisconfigured {
				t.Fatalf("invalid wrapper close code=%q", dkim2.ReplayErrorCodeOf(err))
			}
		})
	}
}

// containsProtectedMarker recognizes only synthetic private test content.
func containsProtectedMarker(value string) bool {
	return strings.Contains(value, syntheticSecretMarker)
}
