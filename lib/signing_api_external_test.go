package dkim2_test

import (
	"context"
	"encoding"
	"encoding/json"
	"io"
	"reflect"
	"testing"

	dkim2 "github.com/croessner/dkim2"
)

// TestRestrictedSigningResultsExposeNoByteOrMarshalSurface proves the closed
// public API from an external consumer package.
func TestRestrictedSigningResultsExposeNoByteOrMarshalSurface(t *testing.T) {
	for _, value := range []any{
		dkim2.LocalOnlySignedMessage{},
		dkim2.OutOfBandAcceptanceSignedMessage{},
		dkim2.SigningResult{},
	} {
		for _, typ := range []reflect.Type{reflect.TypeOf(value), reflect.PointerTo(reflect.TypeOf(value))} {
			for _, method := range []string{
				"Bytes", "Release", "Raw", "Message", "Unwrap",
				"Marshal", "MarshalBinary", "MarshalJSON", "MarshalText",
				"AppendText", "WriteTo",
			} {
				if _, ok := typ.MethodByName(method); ok {
					t.Fatalf("%v exposes restricted method %s", typ, method)
				}
			}
		}
	}
	for _, value := range []any{
		dkim2.LocalOnlySignedMessage{},
		dkim2.OutOfBandAcceptanceSignedMessage{},
	} {
		if _, ok := value.(interface{ Bytes() []byte }); ok {
			t.Fatalf("%T satisfies generic byte interface", value)
		}
		if _, ok := value.(interface {
			Release(context.Context) ([]byte, error)
		}); ok {
			t.Fatalf("%T satisfies generic release interface", value)
		}
		if _, ok := value.(encoding.BinaryMarshaler); ok {
			t.Fatalf("%T satisfies encoding.BinaryMarshaler", value)
		}
		if _, ok := value.(encoding.TextMarshaler); ok {
			t.Fatalf("%T satisfies encoding.TextMarshaler", value)
		}
		if _, ok := value.(json.Marshaler); ok {
			t.Fatalf("%T satisfies json.Marshaler", value)
		}
		if _, ok := value.(io.WriterTo); ok {
			t.Fatalf("%T satisfies io.WriterTo", value)
		}
	}
	unrestricted := reflect.TypeFor[dkim2.UnrestrictedSignedMessage]()
	for _, restricted := range []reflect.Type{
		reflect.TypeFor[dkim2.LocalOnlySignedMessage](),
		reflect.TypeFor[dkim2.OutOfBandAcceptanceSignedMessage](),
	} {
		if restricted.AssignableTo(unrestricted) || restricted.ConvertibleTo(unrestricted) {
			t.Fatalf("%v can downgrade to %v", restricted, unrestricted)
		}
	}
	if _, ok := reflect.TypeFor[dkim2.UnrestrictedSignedMessage]().MethodByName("Bytes"); !ok {
		t.Fatal("UnrestrictedSignedMessage lacks Bytes")
	}
}
