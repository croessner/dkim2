//nolint:goconst // Docker and OCI comparisons retain exact independent wire literals.
package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"

	"github.com/croessner/dkim2/tools/internal/artifactpath"
	"github.com/croessner/dkim2/tools/internal/strictjson"
)

type dockerArchiveManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type dockerInspect struct {
	ID     string `json:"Id"`
	Config struct {
		User        string            `json:"User"`
		Entrypoint  []string          `json:"Entrypoint"`
		Labels      map[string]string `json:"Labels"`
		Healthcheck *healthcheck      `json:"Healthcheck"`
	} `json:"Config"`
	RootFS struct {
		Type   string   `json:"Type"`
		Layers []string `json:"Layers"`
	} `json:"RootFS"`
}

// exportDockerArchive emits one descriptor-selected platform without network lookup.
func exportDockerArchive(
	loaded layout,
	_ string,
	selected platformReport,
	tag string,
	output io.Writer,
) error {
	if !validDockerTag(tag) {
		return errors.New("tag")
	}
	configBytes, layerBytes, err := selectedBlobs(loaded, selected)
	if err != nil {
		return err
	}
	layerTar, err := uncompressLayer(layerBytes, selected.DiffIDDigest)
	if err != nil {
		return err
	}
	configName := strings.TrimPrefix(selected.ConfigDigest, "sha256:") + ".json"
	layerName := strings.TrimPrefix(selected.DiffIDDigest, "sha256:") + "/layer.tar"
	manifestBytes, err := json.Marshal([]dockerArchiveManifest{{
		Config:   configName,
		RepoTags: []string{tag},
		Layers:   []string{layerName},
	}})
	if err != nil {
		return err
	}
	writer := tar.NewWriter(output)
	for _, entry := range []struct {
		name    string
		content []byte
	}{
		{name: configName, content: configBytes},
		{name: layerName, content: layerTar},
		{name: "manifest.json", content: manifestBytes},
	} {
		header := &tar.Header{
			Name:     entry.name,
			Mode:     0o600,
			Size:     int64(len(entry.content)),
			Typeflag: tar.TypeReg,
		}
		if err := writer.WriteHeader(header); err != nil {
			return err
		}
		if _, err := writer.Write(entry.content); err != nil {
			return err
		}
	}
	return writer.Close()
}

// selectedBlobs retrieves the exact config and layer bound by one report entry.
func selectedBlobs(loaded layout, selected platformReport) ([]byte, []byte, error) {
	manifestName := "blobs/sha256/" + strings.TrimPrefix(selected.ManifestDigest, "sha256:")
	manifestBytes, ok := loaded.files[manifestName]
	if !ok {
		return nil, nil, errors.New("manifest")
	}
	var imageManifest manifest
	if strictjson.Decode(manifestBytes, &imageManifest, 32, 4096) != nil ||
		imageManifest.Config.Digest != selected.ConfigDigest ||
		len(imageManifest.Layers) != 1 ||
		imageManifest.Layers[0].Digest != selected.LayerDigest {
		return nil, nil, errors.New("descriptor")
	}
	configBytes, err := loaded.descriptorBytes(imageManifest.Config)
	if err != nil {
		return nil, nil, err
	}
	layerBytes, err := loaded.descriptorBytes(imageManifest.Layers[0])
	if err != nil {
		return nil, nil, err
	}
	return configBytes, layerBytes, nil
}

// uncompressLayer verifies the runtime diff ID while producing Docker load bytes.
func uncompressLayer(content []byte, expectedDiffID string) ([]byte, error) {
	uncompressed, err := decodeLayer(content)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(uncompressed)
	if "sha256:"+hex.EncodeToString(sum[:]) != expectedDiffID {
		return nil, errors.New("diff id")
	}
	return uncompressed, nil
}

// verifyLoadedImage rebinds Docker config, rootfs, and binary bytes to one descriptor.
func verifyLoadedImage(
	product string,
	selected platformReport,
	inspectPath string,
	exportPath string,
) error {
	inspectContent, err := artifactpath.ReadFile("..", inspectPath, 1<<20)
	if err != nil || strictjson.Validate(inspectContent, 32, 8192) != nil {
		return errors.New("inspect")
	}
	var inspections []dockerInspect
	if json.Unmarshal(inspectContent, &inspections) != nil || len(inspections) != 1 {
		return errors.New("inspect")
	}
	inspection := inspections[0]
	if inspection.ID != selected.ConfigDigest ||
		inspection.Config.User != selected.User ||
		!equalStrings(inspection.Config.Entrypoint, selected.Entrypoint) ||
		!equalStringMaps(inspection.Config.Labels, selected.Labels) ||
		inspection.RootFS.Type != "layers" ||
		len(inspection.RootFS.Layers) != 1 ||
		inspection.RootFS.Layers[0] != selected.DiffIDDigest {
		return errors.New("loaded image")
	}
	if product == "dkim2d" {
		expected := []string{"CMD", "/usr/local/bin/dkim2d", "probe"}
		if inspection.Config.Healthcheck == nil ||
			!equalStrings(inspection.Config.Healthcheck.Test, expected) {
			return errors.New("healthcheck")
		}
	} else if inspection.Config.Healthcheck != nil {
		return errors.New("healthcheck")
	}
	if len(selected.Files) != 3 {
		return errors.New("inventory")
	}
	exportContent, err := artifactpath.ReadFile("..", exportPath, 128<<20)
	if err != nil {
		return errors.New("export")
	}
	return verifyExportedFiles(exportContent, selected.Files)
}

// verifyExportedFiles scans a bounded container export without extracting paths.
func verifyExportedFiles(content []byte, expected []fileRecord) error {
	if len(content) == 0 || len(content) > 128<<20 {
		return errors.New("export")
	}
	if len(expected) != 3 {
		return errors.New("inventory")
	}
	expectedByPath := make(map[string]fileRecord, len(expected))
	for _, file := range expected {
		if _, duplicate := expectedByPath[file.Path]; duplicate {
			return errors.New("inventory")
		}
		expectedByPath[file.Path] = file
	}
	reader := tar.NewReader(bytes.NewReader(content))
	found := make(map[string]bool, len(expected))
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nextErr
		}
		cleaned := "/" + path.Clean(strings.TrimPrefix(header.Name, "./"))
		if path.IsAbs(header.Name) || strings.HasPrefix(cleaned, "/../") ||
			header.Size < 0 || header.Size > 100<<20 {
			return errors.New("export entry")
		}
		if header.Typeflag == tar.TypeDir {
			if header.Linkname != "" || !allowedRuntimeDirectory(cleaned) {
				return errors.New("export directory")
			}
			continue
		}
		if allowedRuntimeFile(cleaned, header) {
			continue
		}
		expectedFile, ok := expectedByPath[cleaned]
		if !ok || found[cleaned] || header.Typeflag != tar.TypeReg ||
			header.Linkname != "" ||
			header.Mode != expectedFile.Mode || header.Uid != expectedFile.UID ||
			header.Gid != expectedFile.GID || header.Size != expectedFile.Size {
			return errors.New("export inventory")
		}
		fileContent, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(fileContent)) != header.Size {
			return errors.New("file")
		}
		sum := sha256.Sum256(fileContent)
		if hex.EncodeToString(sum[:]) != expectedFile.SHA256 {
			return errors.New("file")
		}
		found[cleaned] = true
	}
	if len(found) != len(expected) {
		return errors.New("file")
	}
	return nil
}

// allowedRuntimeDirectory recognizes Docker's closed injected mount inventory.
func allowedRuntimeDirectory(name string) bool {
	switch name {
	case "/dev", "/dev/pts", "/dev/shm", "/etc", "/proc", "/sys",
		"/usr", "/usr/local", "/usr/local/bin", "/usr/share",
		"/usr/share/licenses", "/usr/share/licenses/dkim2":
		return true
	default:
		return false
	}
}

// allowedRuntimeFile recognizes Docker's closed injected runtime-file inventory.
func allowedRuntimeFile(name string, header *tar.Header) bool {
	if header == nil || header.Uid != 0 || header.Gid != 0 || header.Size != 0 {
		return false
	}
	switch name {
	case "/.dockerenv", "/dev/console", "/etc/hostname", "/etc/hosts", "/etc/resolv.conf":
		return header.Typeflag == tar.TypeReg && header.Linkname == ""
	case "/etc/mtab":
		return header.Typeflag == tar.TypeSymlink && header.Linkname == "/proc/mounts"
	default:
		return false
	}
}

// validDockerTag accepts only a bounded local repository tag.
func validDockerTag(value string) bool {
	if len(value) == 0 || len(value) > 128 || strings.Count(value, ":") != 1 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' || character == ':' {
			continue
		}
		return false
	}
	return !strings.HasPrefix(value, "-") && !strings.HasSuffix(value, ":")
}

// equalStringMaps compares closed Docker label maps.
func equalStringMaps(left map[string]string, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
