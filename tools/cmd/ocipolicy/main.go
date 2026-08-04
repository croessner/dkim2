// Command ocipolicy validates and normalizes DKIM2 OCI image layouts.
//
//nolint:goconst // OCI policy checks keep exact schema and archive literals at each boundary.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/croessner/dkim2/tools/internal/artifactpath"
	"github.com/croessner/dkim2/tools/internal/strictjson"
)

const (
	imageIndexMediaType       = "application/vnd.oci.image.index.v1+json"
	imageManifestMediaType    = "application/vnd.oci.image.manifest.v1+json"
	imageConfigMediaType      = "application/vnd.oci.image.config.v1+json"
	layerGzipMediaType        = "application/vnd.oci.image.layer.v1.tar+gzip"
	maximumOCIArchiveBytes    = int64(256 << 20)
	maximumOCIBlobBytes       = int64(128 << 20)
	runtimeProjectLicensePath = "usr/share/licenses/dkim2/LICENSE"
	runtimeNoticePath         = "usr/share/licenses/dkim2/THIRD_PARTY_NOTICES.txt"
	runtimeNoticeHeader       = "Third-party license and notice files distributed with DKIM2 binaries"
)

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *platform         `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

type index struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Manifests     []descriptor `json:"manifests"`
}

type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}

type imageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Created      string `json:"created"`
	Config       struct {
		User         string            `json:"User"`
		Entrypoint   []string          `json:"Entrypoint"`
		Cmd          []string          `json:"Cmd"`
		Env          []string          `json:"Env"`
		Labels       map[string]string `json:"Labels"`
		Healthcheck  *healthcheck      `json:"Healthcheck,omitempty"`
		WorkingDir   string            `json:"WorkingDir"`
		Volumes      map[string]any    `json:"Volumes"`
		ExposedPorts map[string]any    `json:"ExposedPorts"`
	} `json:"config"`
	RootFS struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
	History []historyEntry `json:"history"`
}

type healthcheck struct {
	Test          []string `json:"Test"`
	Interval      int64    `json:"Interval,omitempty"`
	Timeout       int64    `json:"Timeout,omitempty"`
	StartPeriod   int64    `json:"StartPeriod,omitempty"`
	StartInterval int64    `json:"StartInterval,omitempty"`
	Retries       int      `json:"Retries,omitempty"`
}

type historyEntry struct {
	Created    string `json:"created"`
	CreatedBy  string `json:"created_by"`
	Comment    string `json:"comment"`
	EmptyLayer bool   `json:"empty_layer,omitempty"`
}

type fileRecord struct {
	Path     string          `json:"path"`
	Mode     int64           `json:"mode"`
	UID      int             `json:"uid"`
	GID      int             `json:"gid"`
	Size     int64           `json:"size"`
	SHA256   string          `json:"sha256"`
	Typeflag byte            `json:"typeflag"`
	Build    binaryBuildInfo `json:"build"`
}

type binaryBuildInfo struct {
	GoVersion string            `json:"go_version"`
	Main      moduleBuildInfo   `json:"main"`
	Deps      []moduleBuildInfo `json:"dependencies"`
	GOOS      string            `json:"goos"`
	GOARCH    string            `json:"goarch"`
	CGO       string            `json:"cgo_enabled"`
	Trimpath  string            `json:"trimpath"`
}

type moduleBuildInfo struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Sum     string `json:"sum"`
}

type platformReport struct {
	Platform       string            `json:"platform"`
	ManifestDigest string            `json:"manifest_digest"`
	ConfigDigest   string            `json:"config_digest"`
	LayerDigest    string            `json:"layer_digest"`
	DiffIDDigest   string            `json:"diff_id_digest"`
	User           string            `json:"user"`
	Entrypoint     []string          `json:"entrypoint"`
	Labels         map[string]string `json:"labels"`
	Files          []fileRecord      `json:"files"`
	Created        string            `json:"created"`
	Revision       string            `json:"revision"`
	Version        string            `json:"version"`
	Healthcheck    *healthcheck      `json:"healthcheck,omitempty"`
}

type report struct {
	Schema        string           `json:"schema"`
	Product       string           `json:"product"`
	SubjectDigest string           `json:"subject_digest"`
	Platforms     []platformReport `json:"platforms"`
}

type layout struct {
	files       map[string][]byte
	directories map[string]bool
	used        map[string]bool
}

type ociLayoutVersion struct {
	ImageLayoutVersion string `json:"imageLayoutVersion"`
}

// main validates arguments, inspects one OCI archive, and emits canonical JSON.
func main() {
	var archive string
	var product string
	var exportPlatform string
	var exportOCILayout string
	var dockerTag string
	var expectedManifest string
	var verifyInspect string
	var verifyExport string
	flag.StringVar(&archive, "archive", "", "OCI archive to inspect")
	flag.StringVar(&product, "product", "", "closed product name")
	flag.StringVar(&exportPlatform, "export-platform", "", "platform to export as a Docker archive")
	flag.StringVar(&exportOCILayout, "export-oci-layout", "", "new confined directory for one selected OCI platform")
	flag.StringVar(&dockerTag, "docker-tag", "", "local Docker tag for an exported archive")
	flag.StringVar(&expectedManifest, "expected-manifest", "", "required selected platform manifest")
	flag.StringVar(&verifyInspect, "verify-inspect", "", "Docker image inspect JSON to verify")
	flag.StringVar(&verifyExport, "verify-export", "", "Docker container export tar to verify")
	flag.Parse()
	if flag.NArg() != 0 || archive == "" || !validProduct(product) {
		usage()
		os.Exit(2)
	}
	loaded, err := readLayout(archive)
	if err != nil {
		fmt.Fprintf(os.Stderr, "OCI policy violation: %s\n", boundedErrorClass(err))
		os.Exit(1)
	}
	result, err := inspectLayout(loaded, product)
	if err != nil {
		fmt.Fprintf(os.Stderr, "OCI policy violation: %s\n", boundedErrorClass(err))
		os.Exit(1)
	}
	if exportPlatform != "" || dockerTag != "" || expectedManifest != "" ||
		verifyInspect != "" || verifyExport != "" || exportOCILayout != "" {
		selected, ok := selectPlatform(result, exportPlatform)
		if !ok || expectedManifest != selected.ManifestDigest {
			fmt.Fprintln(os.Stderr, "OCI policy violation: invalid artifact")
			os.Exit(1)
		}
		switch {
		case dockerTag != "" && verifyInspect == "" && verifyExport == "" &&
			exportOCILayout == "":
			if err := exportDockerArchive(loaded, product, selected, dockerTag, os.Stdout); err != nil {
				fmt.Fprintln(os.Stderr, "OCI policy violation: invalid artifact")
				os.Exit(1)
			}
			return
		case exportOCILayout != "" && dockerTag == "" &&
			verifyInspect == "" && verifyExport == "":
			if err := exportOCIPlatformLayout(loaded, selected, exportOCILayout); err != nil {
				fmt.Fprintln(os.Stderr, "OCI policy violation: invalid artifact")
				os.Exit(1)
			}
			return
		case dockerTag == "" && exportOCILayout == "" &&
			verifyInspect != "" && verifyExport != "":
			if err := verifyLoadedImage(product, selected, verifyInspect, verifyExport); err != nil {
				fmt.Fprintln(os.Stderr, "OCI policy violation: invalid artifact")
				os.Exit(1)
			}
			fmt.Println("loaded image verified")
			return
		default:
			usage()
			os.Exit(2)
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "OCI report failure")
		os.Exit(1)
	}
}

// usage emits the closed command surface without artifact-derived values.
func usage() {
	fmt.Fprintln(
		os.Stderr,
		"usage: ocipolicy -archive <path> -product <product> "+
			"[-export-platform <platform> -expected-manifest <digest> "+
			"(-docker-tag <tag>|-export-oci-layout <new-directory>|"+
			"-verify-inspect <path> -verify-export <path>)]",
	)
}

// selectPlatform returns one exact report entry.
func selectPlatform(result report, name string) (platformReport, bool) {
	for _, candidate := range result.Platforms {
		if candidate.Platform == name {
			return candidate, true
		}
	}
	return platformReport{}, false
}

// boundedErrorClass maps internal validation failures to a fixed diagnostic.
func boundedErrorClass(err error) string {
	_ = err
	return "invalid artifact"
}

// validProduct restricts policy selection to the three shipped products.
func validProduct(product string) bool {
	switch product {
	case "dkim2d", "dkim2-milter", "dkim2ctl":
		return true
	default:
		return false
	}
}

// inspectLayout validates a descriptor-safe in-memory OCI layout.
//
//nolint:gocyclo // The closed descriptor matrix stays linear for auditability.
func inspectLayout(loaded layout, product string) (report, error) {
	rootBytes, ok := loaded.files["index.json"]
	if !ok {
		return report{}, errors.New("missing index")
	}
	loaded.used["index.json"] = true
	layoutBytes, ok := loaded.files["oci-layout"]
	if !ok {
		return report{}, errors.New("missing layout")
	}
	loaded.used["oci-layout"] = true
	var version ociLayoutVersion
	if strictjson.Decode(layoutBytes, &version, 4, 16) != nil ||
		version.ImageLayoutVersion != "1.0.0" {
		return report{}, errors.New("invalid layout")
	}
	var root index
	if err := strictjson.Decode(rootBytes, &root, 64, 1_000_000); err != nil {
		return report{}, err
	}
	if root.SchemaVersion != 2 || root.MediaType != imageIndexMediaType || len(root.Manifests) != 1 {
		return report{}, errors.New("invalid root index")
	}
	subject := root.Manifests[0]
	if subject.MediaType != imageIndexMediaType || subject.Platform != nil ||
		len(subject.Annotations) != 1 {
		return report{}, errors.New("invalid subject descriptor")
	}
	subjectBytes, err := loaded.descriptorBytes(subject)
	if err != nil {
		return report{}, err
	}
	var subjectIndex index
	if err := strictjson.Decode(subjectBytes, &subjectIndex, 64, 1_000_000); err != nil {
		return report{}, err
	}
	if subjectIndex.SchemaVersion != 2 || subjectIndex.MediaType != imageIndexMediaType || len(subjectIndex.Manifests) != 2 {
		return report{}, errors.New("invalid platform index")
	}
	result := report{
		Schema:        "dkim2-oci-policy-v1",
		Product:       product,
		SubjectDigest: subject.Digest,
	}
	seen := make(map[string]bool)
	for _, imageDescriptor := range subjectIndex.Manifests {
		if imageDescriptor.MediaType != imageManifestMediaType ||
			imageDescriptor.Platform == nil || len(imageDescriptor.Annotations) != 0 {
			return report{}, errors.New("unexpected descriptor")
		}
		platformName := imageDescriptor.Platform.OS + "/" + imageDescriptor.Platform.Architecture
		if imageDescriptor.Platform.OS != "linux" ||
			(imageDescriptor.Platform.Architecture != "amd64" && imageDescriptor.Platform.Architecture != "arm64") ||
			seen[platformName] {
			return report{}, errors.New("invalid platform")
		}
		seen[platformName] = true
		platformResult, err := loaded.inspectPlatform(product, platformName, imageDescriptor)
		if err != nil {
			return report{}, err
		}
		result.Platforms = append(result.Platforms, platformResult)
	}
	if !seen["linux/amd64"] || !seen["linux/arm64"] {
		return report{}, errors.New("incomplete platform matrix")
	}
	sort.Slice(result.Platforms, func(i, j int) bool {
		return result.Platforms[i].Platform < result.Platforms[j].Platform
	})
	created := result.Platforms[0].Created
	if created == "" || result.Platforms[1].Created != created ||
		subject.Annotations["org.opencontainers.image.created"] != created ||
		len(loaded.directories) != 2 ||
		!loaded.directories["blobs"] || !loaded.directories["blobs/sha256"] ||
		len(loaded.used) != len(loaded.files) {
		return report{}, errors.New("layout closure")
	}
	for name := range loaded.files {
		if !loaded.used[name] {
			return report{}, errors.New("unexpected layout file")
		}
	}
	return result, nil
}

// exportOCIPlatformLayout writes one validated platform to a new confined OCI directory.
//
//nolint:gocyclo // Atomic export validation remains linear to preserve cleanup ordering.
func exportOCIPlatformLayout(
	loaded layout,
	selected platformReport,
	destination string,
) (returnErr error) {
	if destination == "" {
		return errors.New("destination")
	}
	cleaned := filepath.Clean(destination)
	parentPath := filepath.Dir(cleaned)
	base := filepath.Base(cleaned)
	if base == "." || base == ".." || filepath.IsAbs(base) {
		return errors.New("destination")
	}
	resolvedParent, err := filepath.EvalSymlinks(parentPath)
	if err != nil {
		return err
	}
	resolvedParent, err = filepath.Abs(resolvedParent)
	if err != nil {
		return err
	}
	absoluteParent, err := filepath.Abs(parentPath)
	if err != nil || resolvedParent != filepath.Clean(absoluteParent) {
		return errors.New("destination")
	}
	parentInfo, err := os.Lstat(parentPath)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&0o022 != 0 {
		return errors.New("destination")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || int(parentStat.Uid) != os.Geteuid() {
		return errors.New("destination")
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = parent.Close()
	}()
	if err := parent.Mkdir(base, 0o700); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			if removeErr := parent.RemoveAll(base); returnErr == nil && removeErr != nil {
				returnErr = removeErr
			}
		}
	}()
	target, err := parent.OpenRoot(base)
	if err != nil {
		return err
	}
	defer func() {
		_ = target.Close()
	}()
	if err := target.MkdirAll("blobs/sha256", 0o700); err != nil {
		return err
	}
	manifestName := "blobs/sha256/" +
		strings.TrimPrefix(selected.ManifestDigest, "sha256:")
	manifestBytes, ok := loaded.files[manifestName]
	if !ok {
		return errors.New("manifest")
	}
	var imageManifest manifest
	if strictjson.Decode(manifestBytes, &imageManifest, 32, 4096) != nil ||
		imageManifest.Config.Digest != selected.ConfigDigest ||
		len(imageManifest.Layers) != 1 ||
		imageManifest.Layers[0].Digest != selected.LayerDigest {
		return errors.New("manifest")
	}
	configBytes, err := loaded.descriptorBytes(imageManifest.Config)
	if err != nil {
		return err
	}
	layerBytes, err := loaded.descriptorBytes(imageManifest.Layers[0])
	if err != nil {
		return err
	}
	parts := strings.Split(selected.Platform, "/")
	if len(parts) != 2 {
		return errors.New("platform")
	}
	selectedDescriptor := descriptor{
		MediaType: imageManifestMediaType,
		Digest:    selected.ManifestDigest,
		Size:      int64(len(manifestBytes)),
		Platform:  &platform{OS: parts[0], Architecture: parts[1]},
	}
	indexBytes, err := json.Marshal(index{
		SchemaVersion: 2,
		MediaType:     imageIndexMediaType,
		Manifests:     []descriptor{selectedDescriptor},
	})
	if err != nil {
		return err
	}
	for _, output := range []struct {
		name    string
		content []byte
	}{
		{name: "oci-layout", content: []byte("{\"imageLayoutVersion\":\"1.0.0\"}\n")},
		{name: "index.json", content: indexBytes},
		{name: manifestName, content: manifestBytes},
		{
			name: "blobs/sha256/" +
				strings.TrimPrefix(selected.ConfigDigest, "sha256:"),
			content: configBytes,
		},
		{
			name: "blobs/sha256/" +
				strings.TrimPrefix(selected.LayerDigest, "sha256:"),
			content: layerBytes,
		},
	} {
		if err := target.WriteFile(output.name, output.content, 0o600); err != nil {
			return err
		}
	}
	complete = true
	return nil
}

// inspectPlatform validates one platform manifest, config, and filesystem.
func (l layout) inspectPlatform(product string, platformName string, imageDescriptor descriptor) (platformReport, error) {
	manifestBytes, err := l.descriptorBytes(imageDescriptor)
	if err != nil {
		return platformReport{}, err
	}
	var imageManifest manifest
	if err := strictjson.Decode(manifestBytes, &imageManifest, 64, 1_000_000); err != nil {
		return platformReport{}, err
	}
	if imageManifest.SchemaVersion != 2 || imageManifest.MediaType != imageManifestMediaType ||
		imageManifest.Config.MediaType != imageConfigMediaType || len(imageManifest.Layers) != 1 ||
		imageManifest.Layers[0].MediaType != layerGzipMediaType ||
		imageManifest.Config.Platform != nil ||
		len(imageManifest.Config.Annotations) != 0 ||
		imageManifest.Layers[0].Platform != nil {
		return platformReport{}, errors.New("invalid manifest")
	}
	configBytes, err := l.descriptorBytes(imageManifest.Config)
	if err != nil {
		return platformReport{}, err
	}
	var config imageConfig
	if err := strictjson.Decode(configBytes, &config, 64, 1_000_000); err != nil {
		return platformReport{}, err
	}
	if err := validateConfig(product, platformName, config); err != nil {
		return platformReport{}, err
	}
	created, err := time.Parse(time.RFC3339, config.Created)
	if err != nil ||
		!equalStringMaps(
			imageManifest.Layers[0].Annotations,
			map[string]string{
				"buildkit/rewritten-timestamp": fmt.Sprintf("%d", created.Unix()),
			},
		) {
		return platformReport{}, errors.New("invalid layer annotations")
	}
	layerBytes, err := l.descriptorBytes(imageManifest.Layers[0])
	if err != nil {
		return platformReport{}, err
	}
	files, err := inspectLayer(layerBytes, product, platformName, config.Created)
	if err != nil {
		return platformReport{}, err
	}
	return platformReport{
		Platform:       platformName,
		ManifestDigest: imageDescriptor.Digest,
		ConfigDigest:   imageManifest.Config.Digest,
		LayerDigest:    imageManifest.Layers[0].Digest,
		DiffIDDigest:   config.RootFS.DiffIDs[0],
		User:           config.Config.User,
		Entrypoint:     config.Config.Entrypoint,
		Labels:         config.Config.Labels,
		Files:          files,
		Created:        config.Created,
		Revision:       config.Config.Labels["org.opencontainers.image.revision"],
		Version:        config.Config.Labels["org.opencontainers.image.version"],
		Healthcheck:    config.Config.Healthcheck,
	}, nil
}

// validateConfig enforces the static runtime configuration contract.
func validateConfig(product string, platformName string, config imageConfig) error {
	parts := strings.Split(platformName, "/")
	if len(parts) != 2 || config.OS != parts[0] || config.Architecture != parts[1] ||
		config.Config.User != "2000:2000" ||
		len(config.Config.Entrypoint) != 1 ||
		config.Config.Entrypoint[0] != "/usr/local/bin/"+product ||
		len(config.Config.Cmd) != 0 ||
		!equalStrings(config.Config.Env, []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}) ||
		config.Config.WorkingDir != "/" || len(config.Config.Volumes) != 0 ||
		len(config.Config.ExposedPorts) != 0 ||
		config.RootFS.Type != "layers" || len(config.RootFS.DiffIDs) != 1 {
		return errors.New("invalid runtime config")
	}
	descriptions := map[string]string{
		"dkim2d":       "Loopback-only DKIM2 processing daemon",
		"dkim2-milter": "Unix-socket DKIM2 Milter adapter",
		"dkim2ctl":     "Generated-client DKIM2 conformance utility",
	}
	expectedLabels := map[string]string{
		"org.opencontainers.image.source":        "https://github.com/croessner/dkim2",
		"org.opencontainers.image.revision":      config.Config.Labels["org.opencontainers.image.revision"],
		"org.opencontainers.image.version":       config.Config.Labels["org.opencontainers.image.version"],
		"org.opencontainers.image.created":       config.Created,
		"org.opencontainers.image.vendor":        "DKIM2 reference implementation",
		"org.opencontainers.image.documentation": "https://github.com/croessner/dkim2/tree/main/docs/operator",
		"org.opencontainers.image.licenses":      "Apache-2.0",
		"org.opencontainers.image.title":         product,
		"org.opencontainers.image.description":   descriptions[product],
	}
	if !equalStringMaps(config.Config.Labels, expectedLabels) ||
		!validRevision(config.Config.Labels["org.opencontainers.image.revision"]) ||
		!validContainerVersion(config.Config.Labels["org.opencontainers.image.version"]) {
		return errors.New("unexpected labels")
	}
	created, err := time.Parse(time.RFC3339, config.Created)
	if err != nil || created.Format(time.RFC3339) != config.Created {
		return errors.New("invalid created")
	}
	if product == "dkim2d" {
		expected := []string{"CMD", "/usr/local/bin/dkim2d", "probe"}
		if config.Config.Healthcheck == nil ||
			!equalStrings(config.Config.Healthcheck.Test, expected) ||
			config.Config.Healthcheck.Interval != int64(10*time.Second) ||
			config.Config.Healthcheck.Timeout != int64(3*time.Second) ||
			config.Config.Healthcheck.Retries != 3 ||
			config.Config.Healthcheck.StartPeriod != 0 ||
			config.Config.Healthcheck.StartInterval != 0 {
			return errors.New("invalid daemon healthcheck")
		}
	} else if config.Config.Healthcheck != nil {
		return errors.New("unexpected healthcheck")
	}
	if !validHistory(product, config, created) {
		return errors.New("invalid history")
	}
	return nil
}

// validHistory enforces the exact non-secret BuildKit runtime history.
func validHistory(product string, config imageConfig, created time.Time) bool {
	labels := config.Config.Labels
	commonLabels := "LABEL " +
		"org.opencontainers.image.source=https://github.com/croessner/dkim2 " +
		"org.opencontainers.image.revision=" + labels["org.opencontainers.image.revision"] + " " +
		"org.opencontainers.image.version=" + labels["org.opencontainers.image.version"] + " " +
		"org.opencontainers.image.created=" + config.Created + " " +
		"org.opencontainers.image.vendor=DKIM2 reference implementation " +
		"org.opencontainers.image.documentation=https://github.com/croessner/dkim2/tree/main/docs/operator " +
		"org.opencontainers.image.licenses=Apache-2.0"
	expected := []struct {
		command string
		empty   bool
	}{
		{"ARG VERSION=" + labels["org.opencontainers.image.version"], true},
		{"ARG REVISION=" + labels["org.opencontainers.image.revision"], true},
		{fmt.Sprintf("ARG SOURCE_DATE_EPOCH=%d", created.Unix()), true},
		{"ARG CREATED=" + config.Created, true},
		{commonLabels, true},
		{"USER 2000:2000", true},
		{
			"LABEL org.opencontainers.image.title=" + product +
				" org.opencontainers.image.description=" +
				labels["org.opencontainers.image.description"],
			true,
		},
		{
			"COPY /runtime/" + product + "/ / # buildkit",
			false,
		},
	}
	if product == "dkim2d" {
		expected = append(expected, struct {
			command string
			empty   bool
		}{
			"HEALTHCHECK {Test:[CMD /usr/local/bin/dkim2d probe] " +
				"Interval:10s Timeout:3s StartPeriod:0s StartInterval:0s Retries:3}",
			true,
		})
	}
	expected = append(expected, struct {
		command string
		empty   bool
	}{
		"ENTRYPOINT [\"/usr/local/bin/" + product + "\"]",
		true,
	})
	if len(config.History) != len(expected) {
		return false
	}
	for index, entry := range config.History {
		current := expected[index]
		if entry.Created != config.Created ||
			entry.CreatedBy != current.command ||
			entry.Comment != "buildkit.dockerfile.v0" ||
			entry.EmptyLayer != current.empty {
			return false
		}
	}
	return true
}

// inspectBinaryBuild validates exact embedded module and toolchain identity.
func inspectBinaryBuild(
	product string,
	platformName string,
	content []byte,
) (binaryBuildInfo, error) {
	info, err := buildinfo.Read(bytes.NewReader(content))
	if err != nil || info == nil ||
		info.GoVersion != "go1.26.5" ||
		info.Path != "github.com/croessner/dkim2/cmd/"+product ||
		info.Main.Path != info.Path || info.Main.Version != "(devel)" ||
		info.Main.Sum != "" || info.Main.Replace != nil {
		return binaryBuildInfo{}, errors.New("invalid build info")
	}
	parts := strings.Split(platformName, "/")
	if len(parts) != 2 {
		return binaryBuildInfo{}, errors.New("invalid build platform")
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		if _, duplicate := settings[setting.Key]; duplicate {
			return binaryBuildInfo{}, errors.New("duplicate build setting")
		}
		settings[setting.Key] = setting.Value
	}
	featureKey := "GOAMD64"
	featureValue := "v1"
	if parts[1] == "arm64" {
		featureKey = "GOARM64"
		featureValue = "v8.0"
	}
	expectedSettings := map[string]string{
		"-buildmode":  "exe",
		"-compiler":   "gc",
		"-trimpath":   "true",
		"CGO_ENABLED": "0",
		"GOARCH":      parts[1],
		"GOOS":        parts[0],
		featureKey:    featureValue,
	}
	if !equalStringMaps(settings, expectedSettings) {
		return binaryBuildInfo{}, errors.New("invalid build settings")
	}
	result := binaryBuildInfo{
		GoVersion: info.GoVersion,
		Main: moduleBuildInfo{
			Path: info.Main.Path, Version: info.Main.Version, Sum: info.Main.Sum,
		},
		GOOS: parts[0], GOARCH: parts[1], CGO: "0", Trimpath: "true",
	}
	for _, dependency := range info.Deps {
		if dependency == nil || dependency.Path == "" ||
			dependency.Version == "" || dependency.Replace != nil {
			return binaryBuildInfo{}, errors.New("invalid dependency")
		}
		result.Deps = append(result.Deps, moduleBuildInfo{
			Path: dependency.Path, Version: dependency.Version, Sum: dependency.Sum,
		})
	}
	sort.Slice(result.Deps, func(left int, right int) bool {
		return result.Deps[left].Path < result.Deps[right].Path
	})
	for index := 1; index < len(result.Deps); index++ {
		if result.Deps[index-1].Path == result.Deps[index].Path {
			return binaryBuildInfo{}, errors.New("duplicate dependency")
		}
	}
	return result, nil
}

// validContainerVersion accepts development or exact stable SemVer labels.
func validContainerVersion(value string) bool {
	if value == "0.0.0-dev" {
		return true
	}
	if len(value) < 6 || !strings.HasPrefix(value, "v") {
		return false
	}
	parts := strings.Split(value[1:], ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 10 || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

// validSHA256 accepts one exact lowercase SHA-256 string.
func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

// validRevision accepts one exact lowercase full Git SHA-1 identity.
func validRevision(value string) bool {
	if len(value) != 40 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 20
}

// inspectLayer validates the filesystem and exact embedded Go build closure.
func inspectLayer(
	layerBytes []byte,
	product string,
	platformName string,
	created string,
) ([]fileRecord, error) {
	createdAt, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return nil, errors.New("invalid layer time")
	}
	files, binary, err := inspectLayerInventory(layerBytes, product, createdAt)
	if err != nil {
		return nil, err
	}
	build, err := inspectBinaryBuild(product, platformName, binary)
	if err != nil {
		return nil, err
	}
	binaryPath := "/usr/local/bin/" + product
	for index := range files {
		if files[index].Path == binaryPath {
			files[index].Build = build
			return files, nil
		}
	}
	return nil, errors.New("missing binary record")
}

// inspectLayerInventory validates the exact runtime directory and file inventory.
//
//nolint:gocyclo // The hostile tar-entry matrix stays linear for auditability.
func inspectLayerInventory(
	layerBytes []byte,
	product string,
	created time.Time,
) ([]fileRecord, []byte, error) {
	uncompressed, err := decodeLayer(layerBytes)
	if err != nil {
		return nil, nil, err
	}
	source := bytes.NewReader(uncompressed)
	tarReader := tar.NewReader(source)
	var files []fileRecord
	var binary []byte
	projectLicenseFound := false
	seen := make(map[string]bool)
	expectedDirectories := map[string]bool{
		"usr": false, "usr/local": false, "usr/local/bin": false,
		"usr/share": false, "usr/share/licenses": false,
		"usr/share/licenses/dkim2": false,
	}
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nil, nil, nextErr
		}
		cleaned := path.Clean(strings.TrimPrefix(header.Name, "./"))
		canonicalName := header.Name == cleaned
		if header.Typeflag == tar.TypeDir {
			canonicalName = header.Name == cleaned+"/"
		}
		//nolint:staticcheck // Deprecated Header.Xattrs must still be rejected if populated.
		if !canonicalName || cleaned == "." || path.IsAbs(header.Name) ||
			strings.HasPrefix(cleaned, "../") || seen[cleaned] ||
			header.Uid != 0 || header.Gid != 0 ||
			header.Uname != "" || header.Gname != "" ||
			header.Linkname != "" || header.Devmajor != 0 || header.Devminor != 0 ||
			len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 ||
			!header.AccessTime.IsZero() || !header.ChangeTime.IsZero() ||
			!header.ModTime.Equal(created) {
			return nil, nil, errors.New("invalid layer metadata")
		}
		seen[cleaned] = true
		if header.Typeflag == tar.TypeDir {
			if _, ok := expectedDirectories[cleaned]; !ok ||
				header.Mode != 0o555 || header.Size != 0 {
				return nil, nil, errors.New("invalid layer directory")
			}
			expectedDirectories[cleaned] = true
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Uid != 0 || header.Gid != 0 ||
			header.Size <= 0 || header.Mode&06000 != 0 || header.Linkname != "" {
			return nil, nil, errors.New("invalid layer inventory")
		}
		content, err := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if err != nil || int64(len(content)) != header.Size {
			return nil, nil, errors.New("invalid layer content")
		}
		switch cleaned {
		case "usr/local/bin/" + product:
			if header.Mode != 0o555 || header.Size > 100<<20 || binary != nil {
				return nil, nil, errors.New("invalid binary inventory")
			}
			binary = content
		case runtimeNoticePath:
			if header.Mode != 0o444 || header.Size > 8<<20 ||
				!validRuntimeNotice(content) {
				return nil, nil, errors.New("invalid notice inventory")
			}
		case runtimeProjectLicensePath:
			if header.Mode != 0o444 || header.Size > 32<<10 ||
				!validRuntimeProjectLicense(content) {
				return nil, nil, errors.New("invalid project license inventory")
			}
			projectLicenseFound = true
		default:
			return nil, nil, errors.New("invalid layer inventory")
		}
		sum := sha256.Sum256(content)
		files = append(files, fileRecord{
			Path:     "/" + cleaned,
			Mode:     header.Mode,
			UID:      header.Uid,
			GID:      header.Gid,
			Size:     header.Size,
			SHA256:   hex.EncodeToString(sum[:]),
			Typeflag: header.Typeflag,
		})
	}
	if len(files) != 3 || binary == nil || !projectLicenseFound {
		return nil, nil, errors.New("unexpected filesystem inventory")
	}
	for _, present := range expectedDirectories {
		if !present {
			return nil, nil, errors.New("missing layer directory")
		}
	}
	trailing, err := io.ReadAll(source)
	if err != nil {
		return nil, nil, errors.New("invalid tar trailer")
	}
	for _, value := range trailing {
		if value != 0 {
			return nil, nil, errors.New("invalid tar trailer")
		}
	}
	sort.Slice(files, func(left int, right int) bool {
		return files[left].Path < files[right].Path
	})
	return files, binary, nil
}

// validRuntimeProjectLicense verifies the Apache-2.0 license distributed with binaries.
func validRuntimeProjectLicense(content []byte) bool {
	return len(content) > 0 && len(content) <= 32<<10 &&
		bytes.HasPrefix(content, []byte("Copyright 2026 Christian Roessner\n\nApache License\n")) &&
		bytes.Contains(content, []byte("Version 2.0, January 2004")) &&
		bytes.Contains(content, []byte("http://www.apache.org/licenses/")) &&
		bytes.Contains(content, []byte("END OF TERMS AND CONDITIONS")) &&
		bytes.IndexByte(content, 0) < 0
}

// validRuntimeNotice verifies the minimum closed license-notice sections.
func validRuntimeNotice(content []byte) bool {
	if len(content) == 0 || len(content) > 8<<20 ||
		!bytes.HasPrefix(content, []byte(runtimeNoticeHeader+"\n")) ||
		bytes.IndexByte(content, 0) >= 0 {
		return false
	}
	goLicense := bytes.Index(content, []byte("\n===== go/LICENSE =====\n"))
	goPatents := bytes.Index(content, []byte("\n===== go/PATENTS =====\n"))
	vendorLicense := bytes.Index(content, []byte("\n===== vendor/"))
	return goLicense > 0 && goPatents > goLicense && vendorLicense > goPatents
}

// decodeLayer accepts exactly one bounded gzip member and no trailing payload.
func decodeLayer(content []byte) ([]byte, error) {
	source := bytes.NewReader(content)
	reader, err := gzip.NewReader(source)
	if err != nil {
		return nil, err
	}
	reader.Multistream(false)
	uncompressed, err := io.ReadAll(io.LimitReader(reader, (512<<20)+1))
	closeErr := reader.Close()
	if err != nil || closeErr != nil || len(uncompressed) > 512<<20 || source.Len() != 0 {
		return nil, errors.New("invalid gzip layer")
	}
	return uncompressed, nil
}

// readLayout reads a bounded regular OCI tar archive without extracting it.
//
//nolint:gocyclo // The hostile archive matrix stays linear for auditability.
func readLayout(archivePath string) (layout, error) {
	absolute, err := filepath.Abs(archivePath)
	if err != nil {
		return layout{}, errors.New("invalid archive")
	}
	parent := filepath.Dir(absolute)
	base := filepath.Base(absolute)
	file, err := artifactpath.OpenFile(parent, base, maximumOCIArchiveBytes)
	if err != nil {
		return layout{}, errors.New("invalid archive")
	}
	defer func() {
		_ = file.Close()
	}()
	before, err := artifactpath.SnapshotOpenFile(file, maximumOCIArchiveBytes)
	if err != nil || before.Size <= 0 {
		return layout{}, errors.New("invalid archive")
	}
	result := layout{
		files:       make(map[string][]byte),
		directories: make(map[string]bool),
		used:        make(map[string]bool),
	}
	reader := tar.NewReader(file)
	var total int64
	entries := 0
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return layout{}, nextErr
		}
		entries++
		if entries > 16 {
			return layout{}, errors.New("too many archive entries")
		}
		cleaned := path.Clean(strings.TrimSuffix(header.Name, "/"))
		//nolint:staticcheck // Deprecated Header.Xattrs must still be rejected if populated.
		if cleaned == "." || header.Name == "" ||
			strings.HasPrefix(cleaned, "../") || path.IsAbs(header.Name) ||
			header.Linkname != "" || header.Size < 0 ||
			header.Size > maximumOCIBlobBytes ||
			header.Uid != 0 || header.Gid != 0 ||
			header.Uname != "" || header.Gname != "" ||
			header.Devmajor != 0 || header.Devminor != 0 ||
			len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 ||
			!header.AccessTime.IsZero() || !header.ChangeTime.IsZero() ||
			!header.ModTime.Equal(time.Unix(0, 0).UTC()) {
			return layout{}, errors.New("invalid archive entry")
		}
		if header.Typeflag == tar.TypeDir {
			if header.Name != cleaned+"/" || header.Size != 0 ||
				header.Mode != 0o755 ||
				(cleaned != "blobs" && cleaned != "blobs/sha256") ||
				result.directories[cleaned] {
				return layout{}, errors.New("invalid archive directory")
			}
			result.directories[cleaned] = true
			continue
		}
		expectedMode := int64(0o444)
		if cleaned == "index.json" {
			expectedMode = 0o644
		}
		if header.Name != cleaned || header.Typeflag != tar.TypeReg ||
			header.Mode != expectedMode ||
			(cleaned != "index.json" && cleaned != "oci-layout" &&
				!validBlobPath(cleaned)) {
			return layout{}, errors.New("invalid archive entry type")
		}
		if _, exists := result.files[cleaned]; exists {
			return layout{}, errors.New("duplicate archive entry")
		}
		content, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(content)) != header.Size {
			return layout{}, errors.New("invalid archive content")
		}
		total += header.Size
		if total > maximumOCIArchiveBytes {
			return layout{}, errors.New("archive too large")
		}
		result.files[cleaned] = content
	}
	after, err := artifactpath.SnapshotOpenFile(file, maximumOCIArchiveBytes)
	if err != nil || !reflect.DeepEqual(before, after) {
		return layout{}, errors.New("archive changed")
	}
	return result, nil
}

// validBlobPath accepts one exact lowercase SHA-256 OCI blob path.
func validBlobPath(value string) bool {
	const prefix = "blobs/sha256/"
	return strings.HasPrefix(value, prefix) &&
		validSHA256(strings.TrimPrefix(value, prefix))
}

// descriptorBytes verifies a descriptor before returning its referenced blob.
func (l layout) descriptorBytes(value descriptor) ([]byte, error) {
	const prefix = "sha256:"
	if !strings.HasPrefix(value.Digest, prefix) || len(value.Digest) != len(prefix)+64 {
		return nil, errors.New("invalid digest")
	}
	hexDigest := strings.TrimPrefix(value.Digest, prefix)
	if _, err := hex.DecodeString(hexDigest); err != nil {
		return nil, errors.New("invalid digest")
	}
	name := "blobs/sha256/" + hexDigest
	content, ok := l.files[name]
	if !ok || int64(len(content)) != value.Size {
		return nil, errors.New("missing blob")
	}
	limit := int64(8 << 20)
	if value.MediaType == layerGzipMediaType {
		limit = 512 << 20
	}
	if value.Size < 0 || value.Size > limit {
		return nil, errors.New("blob too large")
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != hexDigest {
		return nil, errors.New("digest mismatch")
	}
	if l.used != nil {
		l.used[name] = true
	}
	return content, nil
}

// equalStrings compares exact ordered command arrays.
func equalStrings(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
