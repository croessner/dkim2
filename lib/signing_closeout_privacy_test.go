package dkim2

import (
	"bytes"
	"context"
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/routeplan"
)

const signingCloseoutSecretMarker = "SECRET-SIGNING-CLOSEOUT-MARKER"

type signingCloseoutMarkerError struct{}

// Error returns toxic provider text that must never cross the signing boundary.
func (signingCloseoutMarkerError) Error() string { return signingCloseoutSecretMarker }

type signingCloseoutFailingSigner struct{}

// SignDigest returns one deliberately unclassified marker-bearing provider error.
func (signingCloseoutFailingSigner) SignDigest(
	context.Context,
	PrivateKeyHandle,
	PrivateKeySignRequest,
) (PrivateKeySignResult, error) {
	return PrivateKeySignResult{}, signingCloseoutMarkerError{}
}

// TestSigningCloseoutPrivacyMatrix exercises formatting, marshaling, providers, and closed results.
func TestSigningCloseoutPrivacyMatrix(t *testing.T) {
	fixture := newPublicSigningFixture(t)
	markerHandle, err := NewPrivateKeyHandle([]byte(signingCloseoutSecretMarker + "-handle"))
	if err != nil {
		t.Fatalf("NewPrivateKeyHandle() error = %v", err)
	}
	credential, err := NewRSASigningCredential(
		signingCloseoutSecretMarker+"-selector", &fixture.provider.rsaKey.PublicKey, markerHandle,
	)
	if err != nil {
		t.Fatalf("NewRSASigningCredential() error = %v", err)
	}
	profile, err := NewRSASigningProfile(signingCloseoutSecretMarker+".example", credential)
	if err != nil {
		t.Fatalf("NewRSASigningProfile() error = %v", err)
	}
	metadata, err := NewSigningMetadata([]byte(signingCloseoutSecretMarker+"-nonce"), true, nil)
	if err != nil {
		t.Fatalf("NewSigningMetadata() error = %v", err)
	}
	raw := []byte("From: " + signingCloseoutSecretMarker + "@example.test\r\nSubject: marker\r\n\r\nbody\r\n")
	reversePath := []byte("<sender@" + signingCloseoutSecretMarker + ".example>")
	source, err := NewSigningSource(raw)
	if err != nil {
		t.Fatalf("NewSigningSource() error = %v", err)
	}
	entry, err := NewOriginatorRouteEntry(
		source, reversePath,
		[][]byte{[]byte("<recipient@example.net>")}, RouteDisclosureSingle,
		[]byte(signingCloseoutSecretMarker+"-route"),
	)
	if err != nil {
		t.Fatalf("NewOriginatorRouteEntry() error = %v", err)
	}
	fanout, err := NewRouteFanoutRequest([]RouteEntry{entry})
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest() error = %v", err)
	}
	plan, tickets, err := fixture.facade.PlanRouteFanout(context.Background(), fanout)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout() tickets=%d error=%v", len(tickets), err)
	}
	request := NewOriginatorSigningRequest(
		raw, reversePath,
		[][]byte{[]byte("<recipient@example.net>")}, tickets[0], profile, metadata,
		SigningTransportFinalNetworkPreDotStuffing,
	)
	result, recovery, err := fixture.facade.SignOriginator(context.Background(), request)
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf("SignOriginator() valid=%t recovery=%t error=%v", result.Valid(), recovery.Valid(), err)
	}
	unrestricted, ok := result.Unrestricted()
	if !ok {
		t.Fatal("SignOriginator() did not return unrestricted output")
	}
	verification, capability, err := fixture.facade.VerifyForRevision(
		context.Background(),
		NewVerifyRequest(
			unrestricted.Bytes(), reversePath,
			[][]byte{[]byte("<recipient@example.net>")},
		),
	)
	if err != nil || verification.Status() != RevisionVerificationVerified || !capability.Valid() {
		t.Fatalf("VerifyForRevision() status=%q capability=%t error=%v",
			verification.Status(), capability.Valid(), err)
	}

	values := []any{
		markerHandle, credential, profile, metadata, source, entry, fanout, plan, tickets[0],
		request, result, unrestricted, verification, capability,
		PrivateKeySignRequest{}, NewPrivateKeySignResult([]byte(signingCloseoutSecretMarker)),
	}
	for _, value := range values {
		assertSigningCloseoutValuePrivacy(t, value)
	}

	localScenario := prepareLocalReleaseScenario(t)
	oobScenario := prepareNextDomainReleaseScenario(t)
	assertSigningCloseoutRestrictedPrivacy(t, localScenario.restricted, [][]byte{
		localScenario.raw, localScenario.reversePath, localScenario.routeScope,
		localScenario.forwardPaths[0],
	})
	assertSigningCloseoutRestrictedPrivacy(t, oobScenario.releaseVariant, [][]byte{
		oobScenario.raw, oobScenario.reversePath, oobScenario.routeScope,
		oobScenario.receiver, oobScenario.forwardPaths[0],
	})

	assertSigningCloseoutProviderFailure(t, fixture, raw)
}

// assertSigningCloseoutRestrictedPrivacy checks actual protected fixture values and closed surfaces.
func assertSigningCloseoutRestrictedPrivacy(t *testing.T, restricted any, protected [][]byte) {
	t.Helper()
	assertSigningCloseoutValuePrivacy(t, restricted)
	assertSigningCloseoutRestrictedSurface(t, restricted)
	outputs := []string{
		fmt.Sprintf("%s", restricted), fmt.Sprintf("%q", restricted),
		fmt.Sprintf("%x", restricted), fmt.Sprintf("%X", restricted),
		fmt.Sprintf("%v", restricted), fmt.Sprintf("%+v", restricted),
		fmt.Sprintf("%#v", restricted),
	}
	if stringer, ok := restricted.(fmt.Stringer); ok {
		outputs = append(outputs, stringer.String())
	}
	if goStringer, ok := restricted.(fmt.GoStringer); ok {
		outputs = append(outputs, goStringer.GoString())
	}
	if encoded, err := json.Marshal(restricted); err == nil {
		outputs = append(outputs, string(encoded))
	}
	for _, output := range outputs {
		for _, secret := range protected {
			if len(secret) > 0 && bytes.Contains([]byte(output), secret) {
				t.Fatalf("restricted %T leaked protected fixture bytes", restricted)
			}
		}
	}
}

// assertSigningCloseoutValuePrivacy checks every formatting and marshaling surface.
func assertSigningCloseoutValuePrivacy(t *testing.T, value any) {
	t.Helper()
	for _, format := range []string{"%s", "%q", "%x", "%X", "%v", "%+v", "%#v"} {
		assertSigningCloseoutMarkerAbsent(t, fmt.Sprintf(format, value))
	}
	assertSigningCloseoutMarkerAbsent(t, fmt.Sprintf("test failure value=%#v", value))
	if stringer, ok := value.(fmt.Stringer); ok {
		assertSigningCloseoutMarkerAbsent(t, stringer.String())
	}
	if goStringer, ok := value.(fmt.GoStringer); ok {
		assertSigningCloseoutMarkerAbsent(t, goStringer.GoString())
	}
	if encoded, err := json.Marshal(value); err == nil {
		assertSigningCloseoutMarkerAbsent(t, string(encoded))
	}
	if marshaler, ok := value.(encoding.TextMarshaler); ok {
		if encoded, err := marshaler.MarshalText(); err == nil {
			assertSigningCloseoutMarkerAbsent(t, string(encoded))
		}
	}
	if marshaler, ok := value.(encoding.BinaryMarshaler); ok {
		if encoded, err := marshaler.MarshalBinary(); err == nil {
			assertSigningCloseoutMarkerAbsent(t, string(encoded))
		}
	}
}

// assertSigningCloseoutRestrictedSurface proves no generic byte, marshal, or release escape exists.
func assertSigningCloseoutRestrictedSurface(t *testing.T, value any) {
	t.Helper()
	valueType := reflect.TypeOf(value)
	for _, name := range []string{
		"Bytes", "RawBytes", "Marshal", "MarshalJSON", "MarshalText",
		"MarshalBinary", "AppendText", "Release",
	} {
		if _, ok := valueType.MethodByName(name); ok {
			t.Fatalf("%s exposes forbidden %s method", valueType, name)
		}
	}
	if _, ok := value.(json.Marshaler); ok {
		t.Fatalf("%s implements json.Marshaler", valueType)
	}
	if _, ok := value.(encoding.TextMarshaler); ok {
		t.Fatalf("%s implements encoding.TextMarshaler", valueType)
	}
	if _, ok := value.(encoding.BinaryMarshaler); ok {
		t.Fatalf("%s implements encoding.BinaryMarshaler", valueType)
	}
}

// assertSigningCloseoutProviderFailure proves toxic callback errors are classified without leakage.
func assertSigningCloseoutProviderFailure(t *testing.T, fixture publicSigningFixture, raw []byte) {
	t.Helper()
	signer, err := NewSigner(
		fixture.provider, publicRouteMemoryAuthority{value: routeplan.NewMemoryAuthority()},
		&authorizeOrdinary{}, signingCloseoutFailingSigner{},
		WithSigningClock(func() time.Time { return time.Unix(1_700_000_000, 0) }),
	)
	if err != nil {
		t.Fatalf("NewSigner(failing) error = %v", err)
	}
	source, err := NewSigningSource(raw)
	if err != nil {
		t.Fatalf("NewSigningSource(failing) error = %v", err)
	}
	entry, err := NewOriginatorRouteEntry(
		source, []byte("<sender@example.test>"), [][]byte{[]byte("<recipient@example.net>")},
		RouteDisclosureSingle, []byte("failing-route"),
	)
	if err != nil {
		t.Fatalf("NewOriginatorRouteEntry(failing) error = %v", err)
	}
	fanout, err := NewRouteFanoutRequest([]RouteEntry{entry})
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest(failing) error = %v", err)
	}
	_, tickets, err := signer.PlanRouteFanout(context.Background(), fanout)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout(failing) tickets=%d error=%v", len(tickets), err)
	}
	result, recovery, err := signer.SignOriginator(context.Background(), NewOriginatorSigningRequest(
		raw, []byte("<sender@example.test>"), [][]byte{[]byte("<recipient@example.net>")},
		tickets[0], fixture.profile, SigningMetadata{},
		SigningTransportFinalNetworkPreDotStuffing,
	))
	if err == nil || result.Valid() {
		t.Fatalf("marker callback result=%t recovery=%t error=%v", result.Valid(), recovery.Valid(), err)
	}
	for _, value := range []any{err, result, recovery} {
		assertSigningCloseoutValuePrivacy(t, value)
	}
}

// assertSigningCloseoutMarkerAbsent rejects direct or encoded toxic marker output.
func assertSigningCloseoutMarkerAbsent(t *testing.T, output string) {
	t.Helper()
	if strings.Contains(output, signingCloseoutSecretMarker) ||
		bytes.Contains([]byte(output), []byte(signingCloseoutSecretMarker)) {
		t.Fatalf("privacy surface leaked synthetic marker: %q", output)
	}
}
