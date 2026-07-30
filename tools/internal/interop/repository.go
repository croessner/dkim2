//nolint:goconst // Candidate identifiers remain explicit in each closed source binding.
package interop

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/croessner/dkim2/tools/internal/artifactpath"
	"github.com/croessner/dkim2/tools/internal/conformance"
	"github.com/croessner/dkim2/tools/internal/strictjson"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	registryPath         = "testdata/interop/discovery-registry.json"
	registrySchemaPath   = "testdata/interop/schemas/discovery-registry.schema.json"
	catalogPath          = "testdata/interop/candidate-catalog.json"
	catalogSchemaPath    = "testdata/interop/schemas/candidate-catalog.schema.json"
	evidenceSchemaPath   = "testdata/interop/schemas/discovery-evidence.schema.json"
	comparisonSchemaPath = "testdata/interop/schemas/external-comparison.schema.json"
	maxSchemaBytes       = int64(512 << 10)
)

type closedSchemaLoader struct{}

// ArchiveIdentity records one bounded immutable source archive inventory.
type ArchiveIdentity struct {
	ID              string `json:"id"`
	ArchiveSHA256   string `json:"archive_sha256"`
	InventorySHA256 string `json:"inventory_sha256"`
	Files           int    `json:"files"`
}

// CheckRepository validates the closed registry and all local evidence schemas.
func CheckRepository(root string) error {
	content, err := readRepositoryFile(root, registryPath, maxRegistryBytes)
	if err != nil {
		return err
	}
	registry, err := LoadRegistry(content)
	if err != nil {
		return err
	}
	if err := conformance.ValidateRepositoryJSONSchema(
		root, registrySchemaPath, registryPath, maxRegistryBytes,
	); err != nil {
		return errors.New("registry_schema")
	}
	if _, err := ReadCandidateCatalog(root, registry); err != nil {
		return err
	}
	if err := conformance.ValidateRepositoryJSONSchema(
		root, catalogSchemaPath, catalogPath, maxRegistryBytes,
	); err != nil {
		return errors.New("catalog_schema")
	}
	for _, schemaPath := range []string{
		registrySchemaPath, catalogSchemaPath, evidenceSchemaPath, comparisonSchemaPath,
	} {
		content, err := readRepositoryFile(root, schemaPath, maxSchemaBytes)
		if err != nil {
			return err
		}
		if err := validateSchema(content); err != nil {
			return err
		}
	}
	return nil
}

// ReadCandidateCatalog validates reviewed classifications and immutable identities.
func ReadCandidateCatalog(root string, registry Registry) (CandidateCatalog, error) {
	content, err := readRepositoryFile(root, catalogPath, maxRegistryBytes)
	if err != nil {
		return CandidateCatalog{}, err
	}
	var catalog CandidateCatalog
	if err := strictjson.Decode(content, &catalog, maxJSONDepth, maxJSONTokens); err != nil {
		return CandidateCatalog{}, errors.New("catalog_json")
	}
	if catalog.Schema != CatalogSchema || len(catalog.Candidates) == 0 {
		return CandidateCatalog{}, errors.New("catalog_identity")
	}
	if err := validateCandidates(catalog.Candidates, registry); err != nil {
		return CandidateCatalog{}, err
	}
	return catalog, nil
}

// RegistryDigest returns the exact checked-in registry digest after validation.
func RegistryDigest(root string) (string, error) {
	content, err := readRepositoryFile(root, registryPath, maxRegistryBytes)
	if err != nil {
		return "", err
	}
	if _, err := LoadRegistry(content); err != nil {
		return "", err
	}
	return SHA256(content), nil
}

// ReadRegistry returns the validated repository discovery registry.
func ReadRegistry(root string) (Registry, []byte, error) {
	content, err := readRepositoryFile(root, registryPath, maxRegistryBytes)
	if err != nil {
		return Registry{}, nil, err
	}
	registry, err := LoadRegistry(content)
	if err != nil {
		return Registry{}, nil, err
	}
	return registry, content, nil
}

// InspectCandidateArchives validates the three fixed candidate source archives.
func InspectCandidateArchives(root string) ([]ArchiveIdentity, error) {
	registry, _, err := ReadRegistry(root)
	if err != nil {
		return nil, err
	}
	catalog, err := ReadCandidateCatalog(root, registry)
	if err != nil {
		return nil, err
	}
	expected := make(map[string]Candidate, len(catalog.Candidates))
	for _, candidate := range catalog.Candidates {
		expected[candidate.ID] = candidate
	}
	archives := []struct {
		id   string
		path string
	}{
		{id: "dkim2wg-interop", path: ".artifacts/interop/raw/dkim2wg-source.tar.gz"},
		{id: "dkim2wg-spec", path: ".artifacts/interop/raw/search-candidates/spec-source.tar.gz"},
		{id: "darkglobe-suite", path: ".artifacts/interop/raw/search-candidates/darkglobe-source.tar.gz"},
		{id: "mailauthlens", path: ".artifacts/interop/raw/search-candidates/mailauthlens-source.tar.gz"},
		{id: "stalwart-mail-auth", path: ".artifacts/interop/raw/stalwart-source.tar.gz"},
		{id: "turscar-dkim2", path: ".artifacts/interop/raw/turscar-source.tar.gz"},
		{id: "turscar-dkim2play", path: ".artifacts/interop/raw/search-candidates/dkim2play-source.tar.gz"},
	}
	result := make([]ArchiveIdentity, 0, len(archives))
	for _, archive := range archives {
		file, err := artifactpath.OpenFile(root, archive.path, registry.RetrievalPolicy.MaxResponseBytes)
		if err != nil {
			return nil, errors.New("archive_open")
		}
		snapshot, err := artifactpath.SnapshotOpenFile(file, registry.RetrievalPolicy.MaxResponseBytes)
		if err != nil {
			_ = file.Close()
			return nil, errors.New("archive_snapshot")
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			_ = file.Close()
			return nil, errors.New("archive_snapshot")
		}
		entries, inspectErr := InspectArchive(file, registry.RetrievalPolicy)
		closeErr := file.Close()
		if inspectErr != nil {
			return nil, inspectErr
		}
		if closeErr != nil {
			return nil, errors.New("archive_close")
		}
		encoded, err := CanonicalJSON(entries)
		if err != nil {
			return nil, err
		}
		result = append(result, ArchiveIdentity{
			ID: archive.id, ArchiveSHA256: snapshot.SHA256,
			InventorySHA256: SHA256(encoded), Files: len(entries),
		})
		candidate, exists := expected[archive.id]
		if !exists || candidate.SourceSHA256 != snapshot.SHA256 ||
			candidate.InventorySHA256 != SHA256(encoded) {
			return nil, errors.New("archive_identity")
		}
	}
	return result, nil
}

// readRepositoryFile performs a descriptor-confined stable regular-file read.
func readRepositoryFile(root, relative string, limit int64) ([]byte, error) {
	file, err := artifactpath.OpenFile(root, relative, limit)
	if err != nil {
		return nil, errors.New("repository_read")
	}
	defer func() { _ = file.Close() }()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(content)) > limit {
		return nil, errors.New("repository_read")
	}
	return content, nil
}

// Load rejects every external schema resource.
func (closedSchemaLoader) Load(string) (any, error) {
	return nil, errors.New("external_schema_disabled")
}

// validateSchema compiles one strict local-only JSON Schema document.
func validateSchema(content []byte) error {
	if len(content) == 0 || int64(len(content)) > maxSchemaBytes ||
		strictjson.Validate(content, maxJSONDepth, maxJSONTokens) != nil {
		return errors.New("schema_json")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return errors.New("schema_json")
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	compiler.UseLoader(closedSchemaLoader{})
	const resource = "https://dkim2.invalid/interop/schema.json"
	if err := compiler.AddResource(resource, document); err != nil {
		return errors.New("schema_compile")
	}
	if _, err := compiler.Compile(resource); err != nil {
		return errors.New("schema_compile")
	}
	return nil
}
