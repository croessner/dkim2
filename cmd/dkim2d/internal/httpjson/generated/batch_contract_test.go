package generated

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/wire"
)

// TestBatchRevisionSchemaContract freezes the independent original/current, private-output, and capability shape.
func TestBatchRevisionSchemaContract(t *testing.T) {
	document, err := GetSwagger()
	if err != nil || document.Validate(context.Background()) != nil {
		t.Fatal("batch OpenAPI invalid")
	}
	for name, shape := range map[string][2]string{
		"BatchRevisionRequest":      {"api_version draft binding original copies", "api_version draft binding original copies"},
		"BatchRevisionOriginal":     {"message smtp", "message smtp"},
		"BatchRevisionCopy":         {"id delivery message smtp context via", "id delivery message smtp"},
		"BatchRevisionHop":          {"smtp context", "smtp context"},
		"BatchRevisionResponse":     {"api_version draft binding original_sha256 result disposition outputs", "api_version draft binding original_sha256 result disposition outputs"},
		"BatchRevisionOutput":       {"id current_sha256 result_sha256 insertion_offset header_fields_base64", "id current_sha256 result_sha256 insertion_offset header_fields_base64"},
		"BatchRevisionCapabilities": {"api_version draft protocol original_current full_fanout controlled_via max_copies max_controlled_hops max_aggregate_message_bytes max_request_bytes max_response_bytes max_header_fields external_null_sender", "api_version draft protocol original_current full_fanout controlled_via max_copies max_controlled_hops max_aggregate_message_bytes max_request_bytes max_response_bytes max_header_fields external_null_sender"},
	} {
		schema := requiredSchema(t, document, name)
		properties := make([]string, 0, len(schema.Properties))
		for property := range schema.Properties {
			properties = append(properties, property)
		}
		wantProperties, wantRequired := strings.Fields(shape[0]), strings.Fields(shape[1])
		required := slices.Clone(schema.Required)
		for _, values := range [][]string{properties, required, wantProperties, wantRequired} {
			slices.Sort(values)
		}
		if !slices.Equal(properties, wantProperties) || !slices.Equal(required, wantRequired) {
			t.Fatalf("batch schema inventory changed: %s", name)
		}
	}
	copies := requiredSchema(t, document, "BatchRevisionRequest").Properties["copies"].Value
	if copies.MinItems != 1 || copies.MaxItems == nil || *copies.MaxItems != 32 {
		t.Fatal("batch copy bound changed")
	}
	fields := requiredSchema(t, document, "BatchRevisionOutput").Properties["header_fields_base64"].Value
	if fields.MinItems != 1 || fields.MaxItems == nil || *fields.MaxItems != 3 {
		t.Fatal("private delta bound changed")
	}
	capabilities := requiredSchema(t, document, "BatchRevisionCapabilities")
	for name, want := range map[string]float64{"max_copies": 32, "max_controlled_hops": 1, "max_aggregate_message_bytes": 33554432, "max_request_bytes": 47878316, "max_response_bytes": 262144, "max_header_fields": 3} {
		bound := capabilities.Properties[name].Value
		if bound.Min == nil || bound.Max == nil || *bound.Min != want || *bound.Max != want {
			t.Fatalf("capability bound changed: %s", name)
		}
	}
	if !reflect.DeepEqual(capabilities.Properties["external_null_sender"].Value.Enum, []any{false}) {
		t.Fatal("ordinary null sender capability changed")
	}
	if reflect.TypeFor[CompletedHeaderField]() != reflect.TypeFor[wire.ProtectedString]() {
		t.Fatal("completed header field lost protected wire ownership")
	}
}
