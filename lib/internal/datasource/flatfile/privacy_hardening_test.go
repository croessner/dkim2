package flatfile

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
)

// TestFlatFilePrivacyMatrixCoversPathsParserReadsAndProviders proves stored
// file facts and every local failure class remain marker-free.
func TestFlatFilePrivacyMatrixCoversPathsParserReadsAndProviders(t *testing.T) {
	t.Parallel()

	const marker = "privacy-flatfile-marker"
	document := []byte(strings.ReplaceAll(
		string(mustFlatfileDocument(t)),
		"example",
		marker,
	))
	snapshot, err := Decode(
		flatfileTestGeneration,
		document,
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatal("privacy snapshot construction failed")
	}
	ops := newScriptedFilesystem(document)
	provider, err := newProvider(
		3,
		marker,
		datasource.DefaultLimits(),
		ops,
	)
	if err != nil {
		t.Fatal("privacy provider construction failed")
	}
	t.Cleanup(func() {
		_ = provider.Close(context.Background())
	})

	pathErr := validateFilename(marker + "/escape")
	_, parserErr := Decode(
		flatfileTestGeneration,
		[]byte(`{"`+marker+`":true}`),
		datasource.DefaultLimits(),
	)
	_, readerErr := DecodeReader(
		flatfileTestGeneration,
		privacyErrorReader{err: errors.New(marker)},
		datasource.DefaultLimits(),
	)
	if datasource.ErrorCodeOf(readerErr) != datasource.ErrorCodeUnavailable {
		t.Fatal("marker-bearing reader error was not sanitized")
	}
	ops.readFailure = operationFailed
	readErr := provider.Reload(context.Background())
	values := []any{
		snapshot,
		provider,
		pathErr,
		parserErr,
		readerErr,
		readErr,
		fmt.Errorf("outer flat-file failure: %w", readErr),
	}
	for _, value := range values {
		assertFlatFilePrivacySurface(t, value, marker)
	}
}

// privacyErrorReader returns one raw marker-bearing reader error.
type privacyErrorReader struct{ err error }

// Read returns no bytes and the configured raw error.
func (r privacyErrorReader) Read([]byte) (int, error) { return 0, r.err }

// assertFlatFilePrivacySurface checks generic formatting, optional text, and
// value/pointer/container JSON for one protected flat-file surface.
func assertFlatFilePrivacySurface(t *testing.T, value any, marker string) {
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
				t.Fatalf("flat-file formatting exposed a protected marker for %T", subject)
			}
		}
		if marshaler, ok := subject.(encoding.TextMarshaler); ok {
			text, err := marshaler.MarshalText()
			if strings.Contains(string(text), marker) ||
				strings.Contains(fmt.Sprint(err), marker) {
				t.Fatal("flat-file text marshaling exposed a protected marker")
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
			t.Fatal("flat-file JSON marshaling exposed a protected marker")
		}
	}
}
