package memory

import (
	"context"
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/datasource"
)

// TestMemoryProviderPrivacyMatrixCoversConcretePointersAndContainers proves a
// marker-bearing immutable provider remains opaque on every generic surface.
func TestMemoryProviderPrivacyMatrixCoversConcretePointersAndContainers(t *testing.T) {
	t.Parallel()

	const marker = "privacy-memory-marker"
	fixture := newMemoryFixtureWithMarker(t, marker)
	provider := fixture.provider(t)
	usage, err := provider.Usage()
	if err != nil {
		t.Fatal("privacy memory usage was unavailable")
	}
	missingID := mustMemoryProfileID(t, "missing."+marker)
	request := mustMemoryProfileRequest(
		t,
		missingID,
		datasource.ProfileUseOriginator,
		time.Unix(1_700_000_000, 0),
		fixture.limits,
	)
	_, resolveErr := provider.ResolveProfile(context.Background(), request)
	if datasource.ErrorCodeOf(resolveErr) != datasource.ErrorCodeNotFound {
		t.Fatal("privacy memory missing lookup returned the wrong code")
	}
	values := []any{
		provider,
		usage,
		resolveErr,
		fmt.Errorf("outer memory failure: %w", resolveErr),
	}
	for _, value := range values {
		assertMemoryPrivacySurface(t, value, marker)
	}
}

// assertMemoryPrivacySurface checks controllable formatting, optional text,
// and JSON value/concrete-pointer/container surfaces.
func assertMemoryPrivacySurface(t *testing.T, value any, marker string) {
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
				t.Fatalf("memory formatting exposed a protected marker for %T", subject)
			}
		}
		if marshaler, ok := subject.(encoding.TextMarshaler); ok {
			text, err := marshaler.MarshalText()
			if strings.Contains(string(text), marker) ||
				strings.Contains(fmt.Sprint(err), marker) {
				t.Fatal("memory text marshaling exposed a protected marker")
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
			t.Fatal("memory JSON marshaling exposed a protected marker")
		}
	}
}
