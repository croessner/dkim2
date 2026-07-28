package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	maxManifestBytes = 1 << 20
	maxArtifacts     = 4096
	maxCases         = 16384
	maxArtifactBytes = 16 << 20
)

var caseIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
var knownModules = stringSet(
	"lib", "cmd/dkim2d", "cmd/dkim2ctl", "cmd/dkim2-milter",
	"testdata/conformance", "contrib/qualification/postfix-milter", "scripts", "tools",
)

// LoadManifest loads, validates, and digest-binds the exact repository manifest.
func LoadManifest(root, path string) (Manifest, string, error) {
	if err := validateArtifactPath(path); err != nil {
		return Manifest{}, "", errors.New("manifest_path")
	}
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return Manifest{}, "", errors.New("manifest_root")
	}
	defer func() { _ = rootHandle.Close() }()
	input, err := readConfinedFile(rootHandle, path, maxManifestBytes)
	if err != nil {
		return Manifest{}, "", err
	}
	var manifest Manifest
	if err := DecodeStrictJSON(input, maxManifestBytes, &manifest); err != nil {
		return Manifest{}, "", err
	}
	if err := manifest.Validate(root); err != nil {
		return Manifest{}, "", err
	}
	return manifest, SHA256(input), nil
}

// LoadArtifactBytes reopens one artifact through the confined root and rebinds its digest.
func LoadArtifactBytes(root string, artifact Artifact) ([]byte, error) {
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return nil, errors.New("artifact_root")
	}
	defer func() { _ = rootHandle.Close() }()
	input, err := readConfinedFile(rootHandle, artifact.Path, maxArtifactBytes)
	if err != nil {
		return nil, err
	}
	if SHA256(input) != artifact.SHA256 {
		return nil, errors.New("artifact_tampered")
	}
	return input, nil
}

// ReadConfinedFile reads one bounded stable regular file without following symlinks.
func ReadConfinedFile(root, path string, limit int64) ([]byte, error) {
	if err := validateArtifactPath(path); err != nil {
		return nil, errors.New("artifact_path")
	}
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return nil, errors.New("artifact_root")
	}
	defer func() { _ = rootHandle.Close() }()
	return readConfinedFile(rootHandle, path, limit)
}

// readConfinedFile reads one stable regular non-symlink path through the fixed root.
func readConfinedFile(root *os.Root, path string, limit int64) ([]byte, error) {
	if err := rejectPathSymlinks(root, path); err != nil {
		return nil, err
	}
	file, err := root.Open(filepath.FromSlash(path))
	if err != nil {
		return nil, errors.New("artifact_read")
	}
	defer func() { _ = file.Close() }()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return nil, errors.New("artifact_type")
	}
	input, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(input)) > limit {
		return nil, errors.New("artifact_size")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() ||
		before.ModTime() != after.ModTime() {
		return nil, errors.New("artifact_unstable")
	}
	if err := rejectPathSymlinks(root, path); err != nil {
		return nil, err
	}
	pathInfo, err := root.Stat(filepath.FromSlash(path))
	if err != nil || !os.SameFile(after, pathInfo) {
		return nil, errors.New("artifact_unstable")
	}
	return input, nil
}

// Validate enforces manifest identity, ordering, closure, paths, and digests.
func (m Manifest) Validate(root string) error {
	suiteSet, err := m.validateIdentity()
	if err != nil {
		return err
	}
	artifactIDs, err := m.validateArtifacts(root)
	if err != nil {
		return err
	}
	return m.validateCases(suiteSet, artifactIDs)
}

// validateIdentity checks manifest identity, top-level bounds, and suite vocabulary.
func (m Manifest) validateIdentity() (map[string]bool, error) {
	if m.Schema != ManifestSchema || m.MessageDraft != MessageDraft ||
		m.DNSDraft != DNSDraft || m.SuiteVersion != "1" {
		return nil, errors.New("manifest_identity")
	}
	if len(m.Suites) == 0 || len(m.Artifacts) == 0 || len(m.Cases) == 0 ||
		len(m.Artifacts) > maxArtifacts || len(m.Cases) > maxCases ||
		!sortedUnique(m.Suites) {
		return nil, errors.New("manifest_order")
	}
	requiredCapabilities := map[string]string{
		capLibrary: supportedCapability, capDaemon: supportedCapability,
		capMilter: partialCapability, capPostfix: partialLinuxCapability,
		capExim: EximDeferred,
	}
	if !equalMap(m.Capabilities, requiredCapabilities) {
		return nil, errors.New("manifest_capabilities")
	}
	suiteSet := make(map[string]bool, len(m.Suites))
	for _, suite := range m.Suites {
		if !caseIDPattern.MatchString(suite) {
			return nil, errors.New("manifest_suite")
		}
		suiteSet[suite] = true
	}
	return suiteSet, nil
}

// validateArtifacts hashes each unique artifact and returns its closed identity set.
func (m Manifest) validateArtifacts(root string) (map[string]struct{}, error) {
	previous := ""
	foldedPaths := make(map[string]string, len(m.Artifacts))
	fileInfos := make([]os.FileInfo, 0, len(m.Artifacts))
	filePaths := make([]string, 0, len(m.Artifacts))
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return nil, errors.New("artifact_root")
	}
	defer func() { _ = rootHandle.Close() }()
	for _, artifact := range m.Artifacts {
		if artifact.ID <= previous || !caseIDPattern.MatchString(artifact.ID) {
			return nil, errors.New("manifest_order")
		}
		previous = artifact.ID
		if !knownModules[artifact.Module] {
			return nil, errors.New("manifest_artifact")
		}
		if err := validateArtifactPath(artifact.Path); err != nil {
			return nil, err
		}
		folded := strings.ToLower(artifact.Path)
		if _, collision := foldedPaths[folded]; collision {
			return nil, errors.New("artifact_case_collision")
		}
		foldedPaths[folded] = artifact.Path
		info, err := verifyArtifact(rootHandle, artifact)
		if err != nil {
			return nil, err
		}
		for index, prior := range fileInfos {
			if os.SameFile(prior, info) && filePaths[index] != artifact.Path {
				return nil, errors.New("artifact_hardlink")
			}
		}
		fileInfos = append(fileInfos, info)
		filePaths = append(filePaths, artifact.Path)
	}
	artifactIDs := make(map[string]struct{}, len(m.Artifacts))
	for _, artifact := range m.Artifacts {
		artifactIDs[artifact.ID] = struct{}{}
	}
	return artifactIDs, nil
}

// validateCases checks independent case bounds, ordering, and artifact graph closure.
func (m Manifest) validateCases(
	suiteSet map[string]bool,
	artifactIDs map[string]struct{},
) error {
	referenced := make(map[string]struct{}, len(m.Artifacts))
	previous := ""
	for _, manifestCase := range m.Cases {
		key := manifestCase.Suite + "\x00" + manifestCase.CaseID
		if key <= previous || !suiteSet[manifestCase.Suite] ||
			!caseIDPattern.MatchString(manifestCase.CaseID) ||
			!knownClasses[manifestCase.Class] || !knownRunners[manifestCase.Runner] ||
			len(manifestCase.Authority) == 0 || len(manifestCase.Authority) > 16 ||
			!knownProvenance(manifestCase.Provenance) ||
			!knownPlatforms[manifestCase.RequiredPlatform] ||
			(manifestCase.ExpectedOutcome != statePass && manifestCase.ExpectedOutcome != stateDeferred) ||
			manifestCase.Runner == runnerExim != (manifestCase.ExpectedOutcome == stateDeferred) ||
			!caseIDPattern.MatchString(manifestCase.Producer) ||
			(manifestCase.Runner == runnerExim) != (manifestCase.Producer == "none") ||
			len(manifestCase.Artifacts) == 0 || len(manifestCase.Artifacts) > 32 ||
			!sortedUnique(manifestCase.Artifacts) {
			return errors.New("manifest_case")
		}
		for _, authority := range manifestCase.Authority {
			if len(authority) == 0 || len(authority) > 160 ||
				strings.ContainsAny(authority, "\r\n\x00") {
				return errors.New("manifest_case")
			}
		}
		previous = key
		for _, artifactID := range manifestCase.Artifacts {
			if _, ok := artifactIDs[artifactID]; !ok {
				return errors.New("manifest_artifact_reference")
			}
			referenced[artifactID] = struct{}{}
		}
	}
	if len(referenced) != len(m.Artifacts) {
		return errors.New("manifest_orphan_artifact")
	}
	return nil
}

// verifyArtifact opens one regular file without following a terminal symlink and hashes that descriptor.
func verifyArtifact(root *os.Root, artifact Artifact) (os.FileInfo, error) {
	if err := rejectPathSymlinks(root, artifact.Path); err != nil {
		return nil, err
	}
	file, err := root.Open(filepath.FromSlash(artifact.Path))
	if err != nil {
		return nil, errors.New("artifact_read")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("artifact_type")
	}
	limited := io.LimitReader(file, maxArtifactBytes+1)
	hasher := sha256.New()
	count, err := io.Copy(hasher, limited)
	if err != nil || count > maxArtifactBytes {
		return nil, errors.New("artifact_size")
	}
	if hex.EncodeToString(hasher.Sum(nil)) != artifact.SHA256 {
		return nil, errors.New("artifact_tampered")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) || info.Size() != after.Size() ||
		info.ModTime() != after.ModTime() {
		return nil, errors.New("artifact_unstable")
	}
	if err := rejectPathSymlinks(root, artifact.Path); err != nil {
		return nil, err
	}
	pathInfo, err := root.Stat(filepath.FromSlash(artifact.Path))
	if err != nil || !os.SameFile(after, pathInfo) {
		return nil, errors.New("artifact_unstable")
	}
	return after, nil
}

// rejectPathSymlinks rejects every symlink component within a confined root.
func rejectPathSymlinks(root *os.Root, path string) error {
	components := strings.Split(filepath.FromSlash(path), string(filepath.Separator))
	current := ""
	for _, component := range components {
		current = filepath.Join(current, component)
		info, err := root.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("artifact_type")
		}
	}
	return nil
}

// validateArtifactPath enforces canonical slash-only repository-relative paths.
func validateArtifactPath(path string) error {
	if path == "" || strings.ContainsAny(path, "\\\x00") || strings.HasPrefix(path, "/") ||
		filepath.ToSlash(filepath.Clean(filepath.FromSlash(path))) != path ||
		path == "." || strings.HasPrefix(path, "../") || strings.Contains(path, "/../") {
		return errors.New("artifact_path")
	}
	return nil
}

// sortedUnique reports whether values are strictly lexical.
func sortedUnique(values []string) bool {
	return sort.StringsAreSorted(values) && len(values) == len(unique(values))
}

// unique returns the unique members of already sorted input.
func unique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	output := []string{values[0]}
	for _, value := range values[1:] {
		if value != output[len(output)-1] {
			output = append(output, value)
		}
	}
	return output
}
