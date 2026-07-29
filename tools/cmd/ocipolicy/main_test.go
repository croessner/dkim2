//nolint:goconst // Independent OCI tamper cases intentionally repeat exact archive literals.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/tools/internal/strictjson"
)

var testRuntimeNotice = []byte(runtimeNoticeHeader + `

===== go/LICENSE =====
Go license

===== go/PATENTS =====
Go patents

===== vendor/example.invalid/module/LICENSE =====
Dependency license
`)

// TestExportOCIPlatformLayoutWritesOnlyValidatedBlobsToANewConfinedDirectory freezes export ownership.
func TestExportOCIPlatformLayoutWritesOnlyValidatedBlobsToANewConfinedDirectory(t *testing.T) {
	configBytes := []byte(`{"architecture":"amd64","os":"linux"}`)
	layerBytes := []byte("layer")
	configSum := sha256.Sum256(configBytes)
	layerSum := sha256.Sum256(layerBytes)
	configDigest := "sha256:" + hex.EncodeToString(configSum[:])
	layerDigest := "sha256:" + hex.EncodeToString(layerSum[:])
	manifestBytes, err := json.Marshal(manifest{
		SchemaVersion: 2,
		MediaType:     imageManifestMediaType,
		Config: descriptor{
			MediaType: imageConfigMediaType,
			Digest:    configDigest,
			Size:      int64(len(configBytes)),
		},
		Layers: []descriptor{{
			MediaType: layerGzipMediaType,
			Digest:    layerDigest,
			Size:      int64(len(layerBytes)),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestSum := sha256.Sum256(manifestBytes)
	manifestDigest := "sha256:" + hex.EncodeToString(manifestSum[:])
	loaded := layout{files: map[string][]byte{
		"blobs/sha256/" + strings.TrimPrefix(manifestDigest, "sha256:"): manifestBytes,
		"blobs/sha256/" + strings.TrimPrefix(configDigest, "sha256:"):   configBytes,
		"blobs/sha256/" + strings.TrimPrefix(layerDigest, "sha256:"):    layerBytes,
	}}
	selected := platformReport{
		Platform:       "linux/amd64",
		ManifestDigest: manifestDigest,
		ConfigDigest:   configDigest,
		LayerDigest:    layerDigest,
	}
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(parent, "layout")
	if err := exportOCIPlatformLayout(loaded, selected, destination); err != nil {
		t.Fatal(err)
	}
	for name, expected := range map[string][]byte{
		"blobs/sha256/" + strings.TrimPrefix(manifestDigest, "sha256:"): manifestBytes,
		"blobs/sha256/" + strings.TrimPrefix(configDigest, "sha256:"):   configBytes,
		"blobs/sha256/" + strings.TrimPrefix(layerDigest, "sha256:"):    layerBytes,
	} {
		content, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(content, expected) {
			t.Fatalf("wrong exported content for %s", name)
		}
	}
	if err := exportOCIPlatformLayout(loaded, selected, destination); err == nil {
		t.Fatal("existing export destination was replaced")
	}
	outside := t.TempDir()
	linkedParent := filepath.Join(parent, "linked")
	if err := os.Symlink(outside, linkedParent); err != nil {
		t.Fatal(err)
	}
	if err := exportOCIPlatformLayout(
		loaded,
		selected,
		filepath.Join(linkedParent, "escape"),
	); err == nil {
		t.Fatal("symlinked export parent was accepted")
	}
}

// TestReadLayoutRejectsDuplicateAndLinkEntries freezes archive ambiguity handling.
func TestReadLayoutRejectsDuplicateAndLinkEntries(t *testing.T) {
	tests := []struct {
		name    string
		headers []*tar.Header
	}{
		{
			name: "duplicate",
			headers: []*tar.Header{
				{Name: "index.json", Mode: 0o600, Size: 2, Typeflag: tar.TypeReg},
				{Name: "index.json", Mode: 0o600, Size: 2, Typeflag: tar.TypeReg},
			},
		},
		{
			name: "symlink",
			headers: []*tar.Header{
				{Name: "index.json", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "elsewhere"},
			},
		},
		{
			name: "escape",
			headers: []*tar.Header{
				{Name: "../index.json", Mode: 0o600, Size: 2, Typeflag: tar.TypeReg},
			},
		},
		{
			name: "unexpected_file",
			headers: []*tar.Header{
				{Name: "unexpected.json", Mode: 0o444, Size: 2, Typeflag: tar.TypeReg},
			},
		},
		{
			name: "weak_directory_mode",
			headers: []*tar.Header{
				{Name: "blobs/", Mode: 0o777, Typeflag: tar.TypeDir},
			},
		},
		{
			name: "non_root_owner",
			headers: []*tar.Header{
				{Name: "index.json", Mode: 0o644, Uid: 1, Size: 2, Typeflag: tar.TypeReg},
			},
		},
		{
			name: "non_deterministic_time",
			headers: []*tar.Header{
				{
					Name: "index.json", Mode: 0o644, Size: 2,
					Typeflag: tar.TypeReg, ModTime: time.Unix(1, 0),
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "input.tar")
			writeTestArchive(t, archive, test.headers)
			if _, err := readLayout(archive); err == nil {
				t.Fatal("hostile archive was accepted")
			}
		})
	}
}

// TestValidateConfigRejectsLabelHealthAndHistoryDrift freezes runtime metadata closure.
func TestValidateConfigRejectsLabelHealthAndHistoryDrift(t *testing.T) {
	valid := testImageConfig("dkim2d")
	if err := validateConfig("dkim2d", "linux/amd64", valid); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*imageConfig)
	}{
		{
			name: "extra_label",
			mutate: func(value *imageConfig) {
				value.Config.Labels["unexpected"] = "value"
			},
		},
		{
			name: "created_label_drift",
			mutate: func(value *imageConfig) {
				value.Config.Labels["org.opencontainers.image.created"] =
					"1970-01-01T00:00:01Z"
			},
		},
		{
			name: "health_command",
			mutate: func(value *imageConfig) {
				value.Config.Healthcheck.Test = []string{"CMD", "true"}
			},
		},
		{
			name: "history_argument",
			mutate: func(value *imageConfig) {
				value.History[0].CreatedBy = "ARG VERSION=attacker"
			},
		},
		{
			name: "leading_zero_version",
			mutate: func(value *imageConfig) {
				value.Config.Labels["org.opencontainers.image.version"] = "v01.2.3"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := testImageConfig("dkim2d")
			test.mutate(&candidate)
			if err := validateConfig("dkim2d", "linux/amd64", candidate); err == nil {
				t.Fatal("hostile runtime config was accepted")
			}
		})
	}
}

// testImageConfig returns one exact daemon OCI config fixture.
func testImageConfig(product string) imageConfig {
	created := "1970-01-01T00:00:00Z"
	revision := strings.Repeat("1", 40)
	version := "v1.2.3"
	value := imageConfig{
		Architecture: "amd64",
		OS:           "linux",
		Created:      created,
	}
	value.Config.User = "2000:2000"
	value.Config.Entrypoint = []string{"/usr/local/bin/" + product}
	value.Config.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	value.Config.WorkingDir = "/"
	value.Config.Labels = map[string]string{
		"org.opencontainers.image.source":        "https://github.com/croessner/dkim2",
		"org.opencontainers.image.revision":      revision,
		"org.opencontainers.image.version":       version,
		"org.opencontainers.image.created":       created,
		"org.opencontainers.image.vendor":        "DKIM2 reference implementation",
		"org.opencontainers.image.documentation": "https://github.com/croessner/dkim2/tree/main/docs/operator",
		"org.opencontainers.image.licenses":      "NOASSERTION",
		"org.opencontainers.image.title":         product,
		"org.opencontainers.image.description":   "Loopback-only DKIM2 processing daemon",
	}
	value.Config.Healthcheck = &healthcheck{
		Test:     []string{"CMD", "/usr/local/bin/dkim2d", "probe"},
		Interval: int64(10 * time.Second),
		Timeout:  int64(3 * time.Second),
		Retries:  3,
	}
	value.RootFS.Type = "layers"
	value.RootFS.DiffIDs = []string{"sha256:" + strings.Repeat("2", 64)}
	commonLabels := "LABEL " +
		"org.opencontainers.image.source=https://github.com/croessner/dkim2 " +
		"org.opencontainers.image.revision=" + revision + " " +
		"org.opencontainers.image.version=" + version + " " +
		"org.opencontainers.image.created=" + created + " " +
		"org.opencontainers.image.vendor=DKIM2 reference implementation " +
		"org.opencontainers.image.documentation=https://github.com/croessner/dkim2/tree/main/docs/operator " +
		"org.opencontainers.image.licenses=NOASSERTION"
	commands := []struct {
		command string
		empty   bool
	}{
		{"ARG VERSION=" + version, true},
		{"ARG REVISION=" + revision, true},
		{"ARG SOURCE_DATE_EPOCH=0", true},
		{"ARG CREATED=" + created, true},
		{commonLabels, true},
		{"USER 2000:2000", true},
		{
			"LABEL org.opencontainers.image.title=dkim2d " +
				"org.opencontainers.image.description=Loopback-only DKIM2 processing daemon",
			true,
		},
		{"COPY /runtime/dkim2d/ / # buildkit", false},
		{
			"HEALTHCHECK {Test:[CMD /usr/local/bin/dkim2d probe] " +
				"Interval:10s Timeout:3s StartPeriod:0s StartInterval:0s Retries:3}",
			true,
		},
		{"ENTRYPOINT [\"/usr/local/bin/dkim2d\"]", true},
	}
	for _, command := range commands {
		value.History = append(value.History, historyEntry{
			Created:    created,
			CreatedBy:  command.command,
			Comment:    "buildkit.dockerfile.v0",
			EmptyLayer: command.empty,
		})
	}
	return value
}

// TestInspectLayerRejectsAmbiguousExtractionSemantics freezes one canonical layer.
func TestInspectLayerRejectsAmbiguousExtractionSemantics(t *testing.T) {
	created := time.Unix(0, 0).UTC()
	directories := []*tar.Header{
		{Name: "usr/", Mode: 0o555, Typeflag: tar.TypeDir, ModTime: created},
		{Name: "usr/local/", Mode: 0o555, Typeflag: tar.TypeDir, ModTime: created},
		{Name: "usr/local/bin/", Mode: 0o555, Typeflag: tar.TypeDir, ModTime: created},
		{Name: "usr/share/", Mode: 0o555, Typeflag: tar.TypeDir, ModTime: created},
		{Name: "usr/share/licenses/", Mode: 0o555, Typeflag: tar.TypeDir, ModTime: created},
		{Name: "usr/share/licenses/dkim2/", Mode: 0o555, Typeflag: tar.TypeDir, ModTime: created},
	}
	binary := &tar.Header{
		Name: "usr/local/bin/dkim2d", Mode: 0o555, Uid: 0, Gid: 0,
		Size: 1, Typeflag: tar.TypeReg, ModTime: created,
	}
	notice := &tar.Header{
		Name: runtimeNoticePath, Mode: 0o444, Uid: 0, Gid: 0,
		Size: int64(len(testRuntimeNotice)), Typeflag: tar.TypeReg, ModTime: created,
	}
	validHeaders := append(append([]*tar.Header{}, directories...), binary, notice)
	valid := writeLayer(t, validHeaders, nil)
	if _, _, err := inspectLayerInventory(valid, "dkim2d", created); err != nil {
		t.Fatal(err)
	}
	second := writeLayer(t, []*tar.Header{{
		Name: "unexpected", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg,
	}}, nil)
	if _, _, err := inspectLayerInventory(
		append(append([]byte{}, valid...), second...),
		"dkim2d",
		created,
	); err == nil {
		t.Fatal("concatenated gzip member was accepted")
	}
	if _, _, err := inspectLayerInventory(
		writeLayer(t, validHeaders, []byte("hidden payload")),
		"dkim2d",
		created,
	); err == nil {
		t.Fatal("payload after tar end marker was accepted")
	}
	tests := []struct {
		name   string
		header *tar.Header
	}{
		{
			name: "duplicate",
			header: &tar.Header{
				Name: "usr/local/bin/dkim2d", Mode: 0o555,
				Size: 1, Typeflag: tar.TypeReg,
			},
		},
		{
			name: "whiteout",
			header: &tar.Header{
				Name: "usr/local/bin/.wh.dkim2d", Mode: 0o600,
				Size: 0, Typeflag: tar.TypeReg,
			},
		},
		{
			name: "device",
			header: &tar.Header{
				Name: "usr/local/bin/device", Mode: 0o600,
				Typeflag: tar.TypeChar,
			},
		},
		{
			name: "hardlink",
			header: &tar.Header{
				Name: "usr/local/bin/alias", Mode: 0o555,
				Typeflag: tar.TypeLink, Linkname: "usr/local/bin/dkim2d",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headers := append(append([]*tar.Header{}, validHeaders...), test.header)
			layer := writeLayer(t, headers, nil)
			if _, _, err := inspectLayerInventory(
				layer,
				"dkim2d",
				created,
			); err == nil {
				t.Fatal("ambiguous layer inventory was accepted")
			}
		})
	}
	for _, hostile := range []*tar.Header{
		{Name: "/usr/", Mode: 0o555, Typeflag: tar.TypeDir, ModTime: created},
		{Name: "../usr/", Mode: 0o555, Typeflag: tar.TypeDir, ModTime: created},
		{Name: "usr/", Mode: 0o755, Typeflag: tar.TypeDir, ModTime: created},
		{Name: "usr/", Mode: 0o555, Typeflag: tar.TypeDir, ModTime: created, PAXRecords: map[string]string{"secret": "marker"}},
	} {
		headers := append([]*tar.Header{hostile}, validHeaders[1:]...)
		if _, _, err := inspectLayerInventory(
			writeLayer(t, headers, nil),
			"dkim2d",
			created,
		); err == nil {
			t.Fatal("hostile directory metadata was accepted")
		}
	}
}

// TestVerifyExportedFilesRequiresClosedDockerParity freezes post-load bytes.
func TestVerifyExportedFilesRequiresClosedDockerParity(t *testing.T) {
	content := []byte("binary")
	sum := sha256.Sum256(content)
	noticeSum := sha256.Sum256(testRuntimeNotice)
	expected := []fileRecord{
		{
			Path: "/usr/local/bin/dkim2d", Mode: 0o555, UID: 0, GID: 0,
			Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:]),
			Typeflag: tar.TypeReg,
		},
		{
			Path: "/" + runtimeNoticePath, Mode: 0o444, UID: 0, GID: 0,
			Size:     int64(len(testRuntimeNotice)),
			SHA256:   hex.EncodeToString(noticeSum[:]),
			Typeflag: tar.TypeReg,
		},
	}
	valid := writeExport(t, []*tar.Header{
		{Name: ".dockerenv", Mode: 0o755, Typeflag: tar.TypeReg},
		{Name: "dev", Mode: 0o755, Typeflag: tar.TypeDir},
		{Name: "usr", Mode: 0o555, Typeflag: tar.TypeDir},
		{Name: "usr/local", Mode: 0o555, Typeflag: tar.TypeDir},
		{Name: "usr/local/bin", Mode: 0o555, Typeflag: tar.TypeDir},
		{Name: "usr/share", Mode: 0o555, Typeflag: tar.TypeDir},
		{Name: "usr/share/licenses", Mode: 0o555, Typeflag: tar.TypeDir},
		{Name: "usr/share/licenses/dkim2", Mode: 0o555, Typeflag: tar.TypeDir},
		{
			Name: "usr/local/bin/dkim2d", Mode: 0o555,
			Size: int64(len(content)), Typeflag: tar.TypeReg,
		},
		{
			Name: runtimeNoticePath, Mode: 0o444,
			Size: int64(len(testRuntimeNotice)), Typeflag: tar.TypeReg,
		},
	}, map[string][]byte{
		"usr/local/bin/dkim2d": content,
		runtimeNoticePath:      testRuntimeNotice,
	})
	if err := verifyExportedFiles(valid, expected); err != nil {
		t.Fatal(err)
	}
	for _, hostile := range []*tar.Header{
		{
			Name: "usr/local/bin/alias", Mode: 0o555,
			Typeflag: tar.TypeLink, Linkname: "usr/local/bin/dkim2d",
		},
		{
			Name: "usr/local/bin/.wh.dkim2d", Mode: 0o600,
			Typeflag: tar.TypeReg,
		},
		{
			Name: "dev/host", Mode: 0o600,
			Typeflag: tar.TypeChar,
		},
	} {
		archive := appendExportEntry(t, valid, hostile)
		if err := verifyExportedFiles(archive, expected); err == nil {
			t.Fatal("hostile Docker export entry was accepted")
		}
	}
	wrongNotice := append([]byte{}, testRuntimeNotice...)
	wrongNotice[len(wrongNotice)-1] ^= 1
	tampered := writeExport(t, []*tar.Header{
		{Name: "usr", Mode: 0o555, Typeflag: tar.TypeDir},
		{Name: "usr/local", Mode: 0o555, Typeflag: tar.TypeDir},
		{Name: "usr/local/bin", Mode: 0o555, Typeflag: tar.TypeDir},
		{Name: "usr/share", Mode: 0o555, Typeflag: tar.TypeDir},
		{Name: "usr/share/licenses", Mode: 0o555, Typeflag: tar.TypeDir},
		{Name: "usr/share/licenses/dkim2", Mode: 0o555, Typeflag: tar.TypeDir},
		{Name: "usr/local/bin/dkim2d", Mode: 0o555, Size: int64(len(content)), Typeflag: tar.TypeReg},
		{Name: runtimeNoticePath, Mode: 0o444, Size: int64(len(wrongNotice)), Typeflag: tar.TypeReg},
	}, map[string][]byte{
		"usr/local/bin/dkim2d": content,
		runtimeNoticePath:      wrongNotice,
	})
	if err := verifyExportedFiles(tampered, expected); err == nil {
		t.Fatal("tampered public notice was accepted")
	}
}

// TestValidDockerTagRejectsRegistryAndOptionAmbiguity freezes local-only tags.
func TestValidDockerTagRejectsRegistryAndOptionAmbiguity(t *testing.T) {
	if !validDockerTag("dkim2-runtime-0123:local") {
		t.Fatal("valid local tag was rejected")
	}
	for _, value := range []string{
		"", "-foreign:local", "registry.example/dkim2:local",
		"dkim2:local:extra", strings.Repeat("a", 129) + ":local",
	} {
		if validDockerTag(value) {
			t.Fatalf("unsafe tag was accepted: %q", value)
		}
	}
}

// TestStrictJSONRejectsTrailingDocuments freezes one-document evidence parsing.
func TestStrictJSONRejectsTrailingDocuments(t *testing.T) {
	var value index
	if err := strictjson.Decode([]byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]} {}`), &value, 64, 1_000_000); err == nil {
		t.Fatal("trailing JSON document was accepted")
	}
}

// TestStrictJSONRejectsDuplicateKeys freezes global duplicate-member rejection.
func TestStrictJSONRejectsDuplicateKeys(t *testing.T) {
	var value index
	if err := strictjson.Decode([]byte(`{"schemaVersion":2,"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`), &value, 64, 1_000_000); err == nil {
		t.Fatal("duplicate JSON member was accepted")
	}
	var nested struct {
		Outer struct {
			Name string `json:"name"`
		} `json:"outer"`
	}
	if err := strictjson.Decode([]byte(`{"outer":{"name":"first","name":"second"}}`), &nested, 64, 1_000_000); err == nil {
		t.Fatal("nested duplicate JSON member was accepted")
	}
}

// FuzzReadLayoutArchive proves arbitrary bounded archive bytes never escape or panic.
func FuzzReadLayoutArchive(f *testing.F) {
	f.Add([]byte("not a tar archive"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			return
		}
		archive := filepath.Join(t.TempDir(), "input.tar")
		if err := os.WriteFile(archive, input, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _ = readLayout(archive)
	})
}

// writeTestArchive writes a small deterministic hostile archive fixture.
func writeTestArchive(t *testing.T, archive string, headers []*tar.Header) {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, header := range headers {
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg && header.Size > 0 {
			if _, err := writer.Write(bytes.Repeat([]byte{'x'}, int(header.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeLayer writes one deterministic gzip-compressed tar layer.
func writeLayer(t *testing.T, headers []*tar.Header, trailer []byte) []byte {
	t.Helper()
	var tarBuffer bytes.Buffer
	writer := tar.NewWriter(&tarBuffer)
	for _, header := range headers {
		copyHeader := *header
		if err := writer.WriteHeader(&copyHeader); err != nil {
			t.Fatal(err)
		}
		if copyHeader.Typeflag == tar.TypeReg && copyHeader.Size > 0 {
			content := bytes.Repeat([]byte{'x'}, int(copyHeader.Size))
			if copyHeader.Name == runtimeNoticePath {
				content = testRuntimeNotice
			}
			if _, err := writer.Write(content); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	tarBuffer.Write(trailer)
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	gzipWriter.ModTime = time.Time{}
	if _, err := gzipWriter.Write(tarBuffer.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

// writeExport writes a Docker export fixture with selected file bytes.
func writeExport(
	t *testing.T,
	headers []*tar.Header,
	contents map[string][]byte,
) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, header := range headers {
		copyHeader := *header
		if err := writer.WriteHeader(&copyHeader); err != nil {
			t.Fatal(err)
		}
		if copyHeader.Size > 0 {
			if _, err := writer.Write(contents[copyHeader.Name]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// appendExportEntry rewrites a Docker export with one additional hostile entry.
func appendExportEntry(t *testing.T, original []byte, hostile *tar.Header) []byte {
	t.Helper()
	var headers []*tar.Header
	contents := make(map[string][]byte)
	reader := tar.NewReader(bytes.NewReader(original))
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		copyHeader := *header
		headers = append(headers, &copyHeader)
		if header.Size > 0 {
			content, readErr := io.ReadAll(reader)
			if readErr != nil {
				t.Fatal(readErr)
			}
			contents[header.Name] = content
		}
	}
	headers = append(headers, hostile)
	return writeExport(t, headers, contents)
}
