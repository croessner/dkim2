package conformance

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const localSchemaResource = "https://dkim2.invalid/conformance/schema.json"

type closedSchemaLoader struct{}

// Load rejects every external schema resource.
func (closedSchemaLoader) Load(string) (any, error) {
	return nil, errors.New("external_schema_disabled")
}

// ValidateRepositoryJSONSchema validates one confined repository document against one confined schema.
func ValidateRepositoryJSONSchema(root, schemaPath, instancePath string, limit int64) error {
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return errors.New("schema_root")
	}
	defer func() { _ = rootHandle.Close() }()
	instance, err := readConfinedFile(rootHandle, instancePath, limit)
	if err != nil {
		return err
	}
	return ValidateJSONSchema(root, schemaPath, instance, limit)
}

// ValidateJSONSchema validates strict JSON bytes against one closed checked-in schema.
func ValidateJSONSchema(root, schemaPath string, instance []byte, limit int64) error {
	if int64(len(instance)) > limit {
		return errors.New("schema_instance")
	}
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return errors.New("schema_root")
	}
	defer func() { _ = rootHandle.Close() }()
	schemaInput, err := readConfinedFile(rootHandle, schemaPath, maxManifestBytes)
	if err != nil {
		return err
	}
	schemaDocument, err := decodeSchemaValue(schemaInput, maxManifestBytes)
	if err != nil {
		return err
	}
	instanceDocument, err := decodeSchemaValue(instance, limit)
	if err != nil {
		return err
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	compiler.UseLoader(closedSchemaLoader{})
	if err := compiler.AddResource(localSchemaResource, schemaDocument); err != nil {
		return errors.New("schema_compile")
	}
	schema, err := compiler.Compile(localSchemaResource)
	if err != nil {
		return errors.New("schema_compile")
	}
	if err := schema.Validate(instanceDocument); err != nil {
		return errors.New("schema_instance")
	}
	return nil
}

// decodeSchemaValue preserves JSON integer precision for schema evaluation.
func decodeSchemaValue(input []byte, limit int64) (any, error) {
	if int64(len(input)) > limit || !json.Valid(input) ||
		bytes.HasPrefix(input, []byte{0xef, 0xbb, 0xbf}) {
		return nil, errors.New("invalid_json")
	}
	if err := rejectDuplicateMembers(input); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("invalid_json")
	}
	return value, nil
}
