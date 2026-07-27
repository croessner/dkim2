package signingprofile

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/datasource"
	"github.com/croessner/dkim2/internal/signing"
)

// TestSigningProfilePrivacyMatrixCoversHandlesRegistryAdapterAndFailures
// proves projection surfaces never serialize logical or physical handle facts.
func TestSigningProfilePrivacyMatrixCoversHandlesRegistryAdapterAndFailures(t *testing.T) {
	t.Parallel()

	const (
		marker                   = "privacy-signing-marker"
		redactedPrivateKeyHandle = "signing.PrivateKeyHandle{redacted}"
	)
	fixture := newProjectionFixture(
		t,
		marker,
		datasource.ProfileUseOriginator,
	)
	provider := &adapterProvider{
		resolveProfile: func(
			context.Context,
			datasource.ProfileRequest,
		) (datasource.ResolvedProfile, error) {
			return fixture.resolvedProfile, nil
		},
	}
	adapter, err := NewAdapter(provider, fixture.registry, signing.DefaultLimits())
	if err != nil {
		t.Fatal("privacy adapter construction failed")
	}
	markerHandle, err := signing.NewPrivateKeyHandle([]byte(marker))
	if err != nil {
		t.Fatal("privacy inert handle construction failed")
	}
	if markerHandle.String() != redactedPrivateKeyHandle ||
		markerHandle.GoString() != redactedPrivateKeyHandle {
		t.Fatal("privacy inert handle did not use its exact redacted summary")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		if fmt.Sprintf(format, markerHandle) != redactedPrivateKeyHandle {
			t.Fatal("privacy inert handle formatter was not exactly redacted")
		}
	}
	marshalOpaque := func(value any) ([]byte, error) {
		return json.Marshal(value)
	}
	handleJSON, handleJSONErr := marshalOpaque(markerHandle)
	handlePointerJSON, handlePointerJSONErr := marshalOpaque(&markerHandle)
	handleContainerJSON, handleContainerJSONErr := marshalOpaque([]any{markerHandle})
	if handleJSONErr != nil || handlePointerJSONErr != nil ||
		handleContainerJSONErr != nil ||
		string(handleJSON) != "{}" ||
		string(handlePointerJSON) != "{}" ||
		string(handleContainerJSON) != "[{}]" {
		t.Fatal("privacy inert handle JSON was not exactly opaque")
	}
	credential := fixture.profile.Credentials()[0]
	binding, err := NewBinding(
		"tenant."+marker,
		fixture.profile.SigningDomain(),
		"originator",
		"key."+marker,
		markerHandle,
		string(credential.Algorithm()),
		credential.PublicKeySPKISHA256(),
	)
	if err != nil {
		t.Fatal("privacy binding construction failed")
	}
	hostileProvider := &adapterProvider{
		resolveProfile: func(
			context.Context,
			datasource.ProfileRequest,
		) (datasource.ResolvedProfile, error) {
			raw := errors.New(marker)
			return datasource.ResolvedProfile{}, fmt.Errorf("provider wrapper: %w", raw)
		},
	}
	hostileAdapter, err := NewAdapter(
		hostileProvider,
		fixture.registry,
		signing.DefaultLimits(),
	)
	if err != nil {
		t.Fatal("privacy hostile adapter construction failed")
	}
	_, sanitizedAdapterErr := hostileAdapter.ResolveProfile(
		context.Background(),
		fixture.profile.ID(),
		datasource.ProfileUseOriginator,
		fixture.at,
	)
	if datasource.ErrorCodeOf(sanitizedAdapterErr) !=
		datasource.ErrorCodeInternalInvariant {
		t.Fatal("marker-bearing adapter error was not sanitized")
	}
	projected, err := fixture.registry.ProjectProfile(
		fixture.resolvedProfile,
		fixture.profileRequest,
		signing.DefaultLimits(),
	)
	if err != nil {
		t.Fatal("privacy projection construction failed")
	}
	unauthorized, err := datasource.NewProfileRequest(
		fixture.profile.ID(),
		datasource.ProfileUseOrdinaryTransit,
		fixture.at,
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatal("privacy denial request construction failed")
	}
	_, projectionErr := fixture.registry.ProjectProfile(
		fixture.resolvedProfile,
		unauthorized,
		signing.DefaultLimits(),
	)
	_, adapterErr := adapter.ResolvePolicy(
		context.Background(),
		mustProjectionTenantID(t, "tenant."+marker),
		fixture.profile.SigningDomain(),
		datasource.ProfileUseOriginator,
		fixture.at,
	)
	values := []any{
		fixture.handle,
		markerHandle,
		fixture.entry,
		binding,
		fixture.registry,
		adapter,
		projected,
		projectionErr,
		adapterErr,
		sanitizedAdapterErr,
		fmt.Errorf("outer projection failure: %w", projectionErr),
	}
	for _, value := range values {
		assertSigningProfilePrivacySurface(t, value, marker)
	}
}

// mustProjectionTenantID constructs one bounded privacy-only tenant identity.
func mustProjectionTenantID(t *testing.T, value string) datasource.TenantID {
	t.Helper()
	tenant, err := datasource.NewTenantID(value)
	if err != nil {
		t.Fatal("privacy tenant construction failed")
	}
	return tenant
}

// assertSigningProfilePrivacySurface checks formatting, optional text, and
// value/pointer/container JSON for registry and projection surfaces.
func assertSigningProfilePrivacySurface(t *testing.T, value any, marker string) {
	t.Helper()
	pointerValue := reflect.New(reflect.TypeOf(value))
	pointerValue.Elem().Set(reflect.ValueOf(value))
	pointer := pointerValue.Interface()
	for index, subject := range []any{value, pointer} {
		renderings := []string{
			fmt.Sprintf("%v", subject),
			fmt.Sprintf("%+v", subject),
			fmt.Sprintf("%#v", subject),
			fmt.Sprintf("%s", subject),
			fmt.Sprintf("%q", subject),
			fmt.Sprintf("%x", subject),
			fmt.Sprintf("%X", subject),
			fmt.Sprintf("%d", subject),
			fmt.Sprintf("%T", subject),
			fmt.Sprint(subject),
			fmt.Sprintln(subject),
		}
		if index == 1 {
			renderings = append(renderings, fmt.Sprintf("%p", subject))
		}
		for _, rendered := range renderings {
			if strings.Contains(rendered, marker) {
				t.Fatalf("signing-profile formatting exposed a protected marker for %T", subject)
			}
		}
		if marshaler, ok := subject.(encoding.TextMarshaler); ok {
			text, err := marshaler.MarshalText()
			if strings.Contains(string(text), marker) ||
				strings.Contains(fmt.Sprint(err), marker) {
				t.Fatal("signing-profile text marshaling exposed a protected marker")
			}
		}
	}
	for _, candidate := range []any{
		value,
		pointer,
		[]any{value},
		map[string]any{"safe": value},
	} {
		encoded, err := json.Marshal(candidate)
		if strings.Contains(string(encoded), marker) ||
			strings.Contains(fmt.Sprint(err), marker) {
			t.Fatal("signing-profile JSON marshaling exposed a protected marker")
		}
	}
}
