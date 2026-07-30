//nolint:goconst // Closed module, state, and environment values stay visible at each boundary.
package reference

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/croessner/dkim2/tools/internal/artifactpath"
	"github.com/croessner/dkim2/tools/internal/conformance"
	"github.com/croessner/dkim2/tools/internal/interop"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/sys/unix"
)

const (
	moduleProofSchema = "dkim2.module-proof.v1"
	moduleProofPath   = ".artifacts/reference/module-proof.json"
	maxModuleBytes    = int64(256 << 20)
)

var proofModules = []string{"cmd/dkim2-milter", "cmd/dkim2ctl", "cmd/dkim2d", "tools"}

// ModuleIdentity records one exact private-proxy module artifact.
type ModuleIdentity struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Mode    string `json:"mode"`
	H1      string `json:"h1"`
}

// ModuleCheck records one standalone module and its resolved graph identity.
type ModuleCheck struct {
	Directory   string `json:"directory"`
	GraphSHA256 string `json:"graph_sha256"`
	State       string `json:"state"`
}

// ModuleProof binds private proxy bytes and standalone checks to one candidate.
type ModuleProof struct {
	Schema                  string           `json:"schema"`
	BaseRevision            string           `json:"base_revision"`
	CandidateSnapshotSHA256 string           `json:"candidate_snapshot_sha256"`
	ProductVersion          string           `json:"product_version"`
	ProxySHA256             string           `json:"proxy_sha256"`
	Modules                 []ModuleIdentity `json:"modules"`
	Checks                  []ModuleCheck    `json:"checks"`
	Network                 string           `json:"network"`
	ChecksumDatabase        string           `json:"checksum_database"`
	Workspace               string           `json:"workspace"`
	State                   string           `json:"state"`
}

// BuildPrivateProxy creates one invocation-owned exact read-only GOPROXY.
func BuildPrivateProxy(root string) (ModuleProof, string, func() error, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return ModuleProof{}, "", nil, errors.New("module_root")
	}
	revision, err := conformance.CurrentRevision(root)
	if err != nil || revision != candidateBaseRevision {
		return ModuleProof{}, "", nil, errors.New("module_base")
	}
	snapshot, err := conformance.ProduceSnapshot(root, revision)
	if err != nil {
		return ModuleProof{}, "", nil, errors.New("module_candidate")
	}
	parent := filepath.Join(root, ".artifacts", "reference")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return ModuleProof{}, "", nil, errors.New("module_work")
	}
	work, err := os.MkdirTemp(parent, ".module-proof.")
	if err != nil {
		return ModuleProof{}, "", nil, errors.New("module_work")
	}
	cleanup := func() error {
		return removeProofWork(work)
	}
	proxy := filepath.Join(work, "proxy")
	if err := os.MkdirAll(proxy, 0o700); err != nil {
		_ = cleanup()
		return ModuleProof{}, "", nil, errors.New("module_work")
	}
	graphModules, err := requiredModuleGraph(root, work, snapshot)
	if err != nil {
		_ = cleanup()
		return ModuleProof{}, "", nil, err
	}
	identities, err := populatePrivateProxy(root, proxy, snapshot, graphModules)
	if err != nil {
		_ = cleanup()
		return ModuleProof{}, "", nil, err
	}
	digest, err := digestProxy(proxy)
	if err != nil {
		_ = cleanup()
		return ModuleProof{}, "", nil, err
	}
	if err := makeProxyReadOnly(proxy); err != nil {
		_ = cleanup()
		return ModuleProof{}, "", nil, err
	}
	proof := ModuleProof{
		Schema: moduleProofSchema, BaseRevision: revision,
		CandidateSnapshotSHA256: snapshot.SHA256,
		ProductVersion:          candidateVersion, ProxySHA256: digest,
		Modules: identities, Network: "disabled", ChecksumDatabase: "disabled",
		Workspace: "off", State: "proxy_ready",
	}
	return proof, proxy, cleanup, nil
}

// removeProofWork restores only invocation-owned modes before confined cleanup.
func removeProofWork(work string) error {
	parent := filepath.Dir(work)
	if filepath.Base(parent) != "reference" ||
		!strings.HasPrefix(filepath.Base(work), ".module-proof.") {
		return errors.New("module_cleanup")
	}
	err := filepath.WalkDir(work, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o700)
		}
		if entry.Type().IsRegular() {
			return os.Chmod(path, 0o600)
		}
		return errors.New("module_cleanup")
	})
	if err != nil {
		return errors.New("module_cleanup")
	}
	if err := os.RemoveAll(work); err != nil {
		return errors.New("module_cleanup")
	}
	return nil
}

// RunModuleProof builds the proxy and verifies every command module standalone.
func RunModuleProof(root string) (ModuleProof, error) {
	proof, proxy, cleanup, err := BuildPrivateProxy(root)
	if err != nil {
		return ModuleProof{}, err
	}
	cleanupDone := false
	defer func() {
		if !cleanupDone {
			_ = cleanup()
		}
	}()
	work := filepath.Dir(proxy)
	revision := proof.BaseRevision
	snapshot, err := conformance.ProduceSnapshot(root, revision)
	if err != nil || snapshot.SHA256 != proof.CandidateSnapshotSHA256 {
		return ModuleProof{}, errors.New("module_candidate")
	}
	sourceRoot := filepath.Join(work, "source")
	if err := copyCandidateSnapshot(root, sourceRoot, snapshot); err != nil {
		return ModuleProof{}, err
	}
	if err := installProofGitMetadata(root, sourceRoot, revision); err != nil {
		return ModuleProof{}, err
	}
	allowedSums, err := committedModuleSumLines(root)
	if err != nil {
		return ModuleProof{}, err
	}
	for _, directory := range proofModules {
		moduleRoot := filepath.Join(sourceRoot, filepath.FromSlash(directory))
		graph, err := runStandaloneModule(
			moduleRoot, proxy,
			filepath.Join(work, "go-state", strings.ReplaceAll(directory, "/", "-")),
			allowedSums,
		)
		if err != nil {
			name := strings.NewReplacer("/", "_", "-", "_").Replace(directory)
			return ModuleProof{}, errors.New("module_" + name + "_" + err.Error())
		}
		proof.Checks = append(proof.Checks, ModuleCheck{
			Directory: directory, GraphSHA256: interop.SHA256(graph), State: "pass",
		})
	}
	current, err := conformance.ProduceSnapshot(root, revision)
	if err != nil || current.SHA256 != proof.CandidateSnapshotSHA256 {
		return ModuleProof{}, errors.New("module_candidate")
	}
	proof.State = "pass"
	content, err := canonicalModuleProof(proof)
	if err != nil {
		return ModuleProof{}, err
	}
	if err := writePrivateArtifact(root, moduleProofPath, content); err != nil {
		return ModuleProof{}, err
	}
	if err := cleanup(); err != nil {
		return ModuleProof{}, err
	}
	cleanupDone = true
	return proof, nil
}

// installProofGitMetadata creates a local-only exact-base inventory for repository tests.
func installProofGitMetadata(source, destination, revision string) error {
	bundle, err := os.CreateTemp(filepath.Dir(destination), ".candidate-base.*.bundle")
	if err != nil {
		return errors.New("module_git")
	}
	bundlePath := bundle.Name()
	if bundle.Close() != nil || os.Remove(bundlePath) != nil {
		return errors.New("module_git")
	}
	defer func() { _ = os.Remove(bundlePath) }()
	commands := []struct {
		directory string
		arguments []string
	}{
		{source, []string{"bundle", "create", bundlePath, "HEAD"}},
		{destination, []string{"init", "--quiet"}},
		{destination, []string{"fetch", "--quiet", bundlePath, revision}},
		{destination, []string{"update-ref", "refs/heads/candidate", "FETCH_HEAD"}},
		{destination, []string{"symbolic-ref", "HEAD", "refs/heads/candidate"}},
		{destination, []string{"read-tree", "HEAD"}},
	}
	for _, operation := range commands {
		command := exec.Command("git", operation.arguments...)
		command.Dir = operation.directory
		command.Env = []string{
			"HOME=" + filepath.Dir(destination),
			"LANG=C", "LC_ALL=C", "PATH=/usr/local/bin:/usr/bin:/bin",
			"GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
		}
		output, runErr := command.CombinedOutput()
		if runErr != nil || len(output) > 1<<20 {
			return errors.New("module_git")
		}
	}
	return nil
}

// LoadModuleProof validates one bounded candidate-bound proof.
func LoadModuleProof(content []byte) (ModuleProof, error) {
	if len(content) == 0 || len(content) > 1<<20 {
		return ModuleProof{}, errors.New("module_proof_size")
	}
	var proof ModuleProof
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return ModuleProof{}, errors.New("module_proof_json")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ModuleProof{}, errors.New("module_proof_json")
	}
	if proof.Schema != moduleProofSchema || proof.ProductVersion != candidateVersion ||
		proof.Network != "disabled" || proof.ChecksumDatabase != "disabled" ||
		proof.Workspace != "off" || proof.State != "pass" ||
		len(proof.Checks) != len(proofModules) || len(proof.Modules) < 2 {
		return ModuleProof{}, errors.New("module_proof_contract")
	}
	for index, check := range proof.Checks {
		if check.Directory != proofModules[index] || check.State != "pass" ||
			len(check.GraphSHA256) != 64 {
			return ModuleProof{}, errors.New("module_proof_contract")
		}
	}
	return proof, nil
}

// ReadCurrentModuleProof binds ignored proof bytes to the current candidate.
func ReadCurrentModuleProof(root string) (ModuleProof, error) {
	content, err := artifactpath.ReadFile(root, moduleProofPath, 1<<20)
	if err != nil {
		return ModuleProof{}, errors.New("module_proof_read")
	}
	return loadCurrentModuleProof(root, content)
}

// loadCurrentModuleProof validates one exact proof byte sequence against the current candidate.
func loadCurrentModuleProof(root string, content []byte) (ModuleProof, error) {
	proof, err := LoadModuleProof(content)
	if err != nil {
		return ModuleProof{}, err
	}
	snapshot, err := conformance.ProduceSnapshot(root, proof.BaseRevision)
	if err != nil || snapshot.SHA256 != proof.CandidateSnapshotSHA256 {
		return ModuleProof{}, errors.New("module_proof_candidate")
	}
	return proof, nil
}

// requiredModuleGraph derives the pruned fixed-test closure from committed metadata.
func requiredModuleGraph(root string, _ string, _ conformance.Snapshot) ([]module.Version, error) {
	sums, err := committedModuleSums(root)
	if err != nil {
		return nil, err
	}
	vendored, err := vendoredPackageModules(root)
	if err != nil {
		return nil, err
	}
	needed := make(map[string]module.Version)
	for path, version := range vendored {
		value := module.Version{Path: path, Version: version}
		needed[path+"@"+version] = value
	}
	for _, directory := range append(append([]string(nil), proofModules...), "lib") {
		content, err := artifactpath.ReadFile(
			root, filepath.ToSlash(filepath.Join(directory, "go.mod")), 1<<20,
		)
		if err != nil {
			return nil, errors.New("module_graph_mod")
		}
		file, err := modfile.Parse("go.mod", content, nil)
		if err != nil {
			return nil, errors.New("module_graph_mod")
		}
		for _, requirement := range file.Require {
			if requirement.Mod.Path != "github.com/croessner/dkim2" {
				needed[requirement.Mod.Path+"@"+requirement.Mod.Version] = requirement.Mod
			}
		}
	}
	cache := filepath.Join(os.Getenv("HOME"), "go", "pkg", "mod", "cache", "download")
	processed := make(map[string]bool)
	for {
		progress := false
		keys := make([]string, 0, len(needed))
		for key := range needed {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			if processed[key] {
				continue
			}
			value := needed[key]
			expected := sums[key+"/go.mod"]
			if expected == "" {
				if vendored[value.Path] == value.Version {
					return nil, errors.New("module_graph_sum")
				}
				processed[key] = true
				continue
			}
			content, err := cachedModuleFile(cache, value.Path, value.Version)
			if err != nil || goModHash(content) != expected {
				return nil, errors.New("module_graph_sum")
			}
			file, err := modfile.Parse("go.mod", content, nil)
			if err != nil {
				return nil, errors.New("module_graph_mod")
			}
			processed[key] = true
			for _, requirement := range file.Require {
				if requirement.Mod.Path == "github.com/croessner/dkim2" {
					continue
				}
				if sums[requirement.Mod.Path+"@"+requirement.Mod.Version+"/go.mod"] != "" ||
					vendored[requirement.Mod.Path] == requirement.Mod.Version {
					childKey := requirement.Mod.Path + "@" + requirement.Mod.Version
					if _, exists := needed[childKey]; !exists {
						needed[childKey] = requirement.Mod
						progress = true
					}
				}
			}
		}
		if !progress {
			break
		}
	}
	modules := make([]module.Version, 0, len(needed))
	for _, value := range needed {
		if value.Path == "" || value.Version == "" || module.Check(value.Path, value.Version) != nil {
			return nil, errors.New("module_graph_identity")
		}
		modules = append(modules, value)
	}
	slices.SortFunc(modules, func(left, right module.Version) int {
		return strings.Compare(left.Path+"@"+left.Version, right.Path+"@"+right.Version)
	})
	return modules, nil
}

// goModHash computes the standard h1 content hash for one module file.
func goModHash(content []byte) string {
	contentDigest := sha256.Sum256(content)
	line := fmt.Sprintf("%x  go.mod\n", contentDigest[:])
	digest := sha256.Sum256([]byte(line))
	return "h1:" + base64.StdEncoding.EncodeToString(digest[:])
}

// cachedModuleFile reads one exact escaped module file from the local cache.
func cachedModuleFile(cache, path, version string) ([]byte, error) {
	return moduleArtifactContent(cache, path, version, ".mod", 1<<20)
}

// moduleArtifactContent reads an exact cache artifact or the active local-only proxy.
func moduleArtifactContent(
	cache, path, version, extension string,
	limit int64,
) ([]byte, error) {
	escapedPath, err := module.EscapePath(path)
	if err != nil {
		return nil, errors.New("module_graph_identity")
	}
	escapedVersion, err := module.EscapeVersion(version)
	if err != nil {
		return nil, errors.New("module_graph_identity")
	}
	cachePath := filepath.Join(
		cache, filepath.FromSlash(escapedPath), "@v", escapedVersion+extension,
	)
	content, cacheErr := readStableRegular(cachePath, limit)
	if cacheErr == nil {
		return content, nil
	}
	proxyRoot, err := activeLocalProxyRoot()
	if err != nil {
		return nil, errors.New("module_cache_file")
	}
	relative := filepath.ToSlash(filepath.Join(
		filepath.FromSlash(escapedPath), "@v", escapedVersion+extension,
	))
	return artifactpath.ReadFile(
		proxyRoot, relative, limit,
	)
}

// activeLocalProxyRoot accepts only one absolute credential-free file proxy.
func activeLocalProxyRoot() (string, error) {
	configured := os.Getenv("GOPROXY")
	if configured == "" || strings.Contains(configured, ",") || strings.Contains(configured, "|") {
		return "", errors.New("module_proxy_source")
	}
	parsed, err := url.Parse(configured)
	if err != nil || parsed.Scheme != "file" || parsed.Host != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("module_proxy_source")
	}
	path, err := url.PathUnescape(parsed.Path)
	if err != nil || !filepath.IsAbs(path) {
		return "", errors.New("module_proxy_source")
	}
	path = filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(path)
	info, statErr := os.Lstat(path)
	if err != nil || statErr != nil || resolved != path || !info.IsDir() ||
		filepath.Base(path) != "proxy" ||
		!strings.HasPrefix(filepath.Base(filepath.Dir(path)), ".module-proof.") {
		return "", errors.New("module_proxy_source")
	}
	return path, nil
}

// writeProxyLists writes one sorted version list for each exact module path.
func writeProxyLists(proxy string, identities []ModuleIdentity) error {
	versions := make(map[string][]string)
	for _, identity := range identities {
		versions[identity.Path] = append(versions[identity.Path], identity.Version)
	}
	for path, values := range versions {
		slices.Sort(values)
		values = slices.Compact(values)
		directory, err := proxyVersionDirectory(proxy, path)
		if err != nil {
			return err
		}
		if err := os.WriteFile(
			filepath.Join(directory, "list"), []byte(strings.Join(values, "\n")+"\n"), 0o600,
		); err != nil {
			return errors.New("module_proxy_write")
		}
	}
	return nil
}

// populatePrivateProxy admits the candidate library and exact vendored closure.
func populatePrivateProxy(
	root string,
	proxy string,
	snapshot conformance.Snapshot,
	graphModules []module.Version,
) ([]ModuleIdentity, error) {
	sums, err := committedModuleSums(root)
	if err != nil {
		return nil, err
	}
	vendored, err := vendoredPackageModules(root)
	if err != nil {
		return nil, err
	}
	candidate, err := writeCandidateModule(root, proxy, snapshot)
	if err != nil {
		return nil, err
	}
	identities := []ModuleIdentity{candidate}
	cache := filepath.Join(os.Getenv("HOME"), "go", "pkg", "mod", "cache", "download")
	if configured := os.Getenv("GOMODCACHE"); configured != "" {
		cache = filepath.Join(configured, "cache", "download")
	}
	for _, dependency := range graphModules {
		vendoredVersion, hasVendoredPackages := vendored[dependency.Path]
		includeZip := sums[dependency.Path+"@"+dependency.Version] != ""
		if hasVendoredPackages && vendoredVersion == dependency.Version && !includeZip {
			return nil, errors.New("module_vendor_sum")
		}
		identity, err := copyDependencyModule(
			cache, proxy, dependency, sums, includeZip,
		)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	slices.SortFunc(identities, func(left, right ModuleIdentity) int {
		return strings.Compare(left.Path+"@"+left.Version, right.Path+"@"+right.Version)
	})
	if err := writeProxyLists(proxy, identities); err != nil {
		return nil, err
	}
	return identities, nil
}

// writeCandidateModule creates canonical proxy files only from candidate library bytes.
func writeCandidateModule(root, proxy string, snapshot conformance.Snapshot) (ModuleIdentity, error) {
	version := candidateVersion
	path := "github.com/croessner/dkim2"
	directory, err := proxyVersionDirectory(proxy, path)
	if err != nil {
		return ModuleIdentity{}, err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return ModuleIdentity{}, errors.New("module_proxy_write")
	}
	modContent, err := artifactpath.ReadFile(root, "lib/go.mod", 1<<20)
	if err != nil {
		return ModuleIdentity{}, errors.New("module_candidate_mod")
	}
	if err := os.WriteFile(filepath.Join(directory, version+".mod"), modContent, 0o600); err != nil {
		return ModuleIdentity{}, errors.New("module_proxy_write")
	}
	info := []byte(`{"Version":"v0.1.0-rc.1","Time":"1980-01-01T00:00:00Z"}` + "\n")
	if err := os.WriteFile(filepath.Join(directory, version+".info"), info, 0o600); err != nil {
		return ModuleIdentity{}, errors.New("module_proxy_write")
	}
	zipPath := filepath.Join(directory, version+".zip")
	if err := createCandidateZip(root, zipPath, path, version, snapshot); err != nil {
		return ModuleIdentity{}, err
	}
	hash, err := moduleZipHash(zipPath)
	if err != nil {
		return ModuleIdentity{}, err
	}
	return ModuleIdentity{Path: path, Version: version, Mode: "zip", H1: hash}, nil
}

// createCandidateZip renders one deterministic canonical module zip.
func createCandidateZip(root, destination, path, version string, snapshot conformance.Snapshot) error {
	if module.CheckPath(path) != nil || module.Check(path, version) != nil {
		return errors.New("module_candidate_identity")
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("module_proxy_write")
	}
	writer := zip.NewWriter(file)
	prefix := path + "@" + version + "/"
	count := 0
	for _, entry := range snapshot.Entries {
		if !strings.HasPrefix(entry.Path, "lib/") {
			continue
		}
		name := strings.TrimPrefix(entry.Path, "lib/")
		if !validModuleRelativePath(name) {
			_ = writer.Close()
			_ = file.Close()
			return errors.New("module_candidate_path")
		}
		header := &zip.FileHeader{Name: prefix + name, Method: zip.Deflate}
		header.Modified = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)
		switch entry.Mode {
		case "100755":
			header.SetMode(0o555)
		case "100644":
			header.SetMode(0o444)
		default:
			_ = writer.Close()
			_ = file.Close()
			return errors.New("module_candidate_mode")
		}
		target, err := writer.CreateHeader(header)
		if err != nil {
			_ = writer.Close()
			_ = file.Close()
			return errors.New("module_proxy_write")
		}
		source, err := artifactpath.OpenFile(root, entry.Path, maxModuleBytes)
		if err != nil {
			_ = writer.Close()
			_ = file.Close()
			return errors.New("module_candidate_read")
		}
		hasher := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(target, hasher), source)
		closeErr := source.Close()
		if copyErr != nil || closeErr != nil || written > maxModuleBytes ||
			fmt.Sprintf("%x", hasher.Sum(nil)) != entry.SHA256 {
			_ = writer.Close()
			_ = file.Close()
			return errors.New("module_candidate_unstable")
		}
		count++
	}
	if count == 0 || writer.Close() != nil || file.Close() != nil {
		return errors.New("module_proxy_write")
	}
	return nil
}

// validModuleRelativePath rejects escape, reserved, and noncanonical zip names.
func validModuleRelativePath(name string) bool {
	if name == "" || len(name) > 512 || strings.Contains(name, "\\") ||
		strings.HasPrefix(name, "/") || strings.Contains(name, "//") ||
		filepath.ToSlash(filepath.Clean(filepath.FromSlash(name))) != name {
		return false
	}
	for _, component := range strings.Split(name, "/") {
		lower := strings.ToLower(component)
		if component == "" || component == "." || component == ".." ||
			lower == ".git" || lower == "temp" || lower == ".artifacts" ||
			strings.HasPrefix(lower, ".git") {
			return false
		}
	}
	return true
}

// vendoredPackageModules maps modules that contribute packages to the checked tree.
func vendoredPackageModules(root string) (map[string]string, error) {
	content, err := artifactpath.ReadFile(root, "vendor/modules.txt", 4<<20)
	if err != nil {
		return nil, errors.New("module_vendor_read")
	}
	modules := make(map[string]string)
	var current module.Version
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[0] == "#" && strings.HasPrefix(fields[2], "v") {
			current = module.Version{Path: fields[1], Version: fields[2]}
			continue
		}
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") ||
			current.Path == "" || current.Path == "github.com/croessner/dkim2" {
			continue
		}
		if module.Check(current.Path, current.Version) != nil {
			return nil, errors.New("module_vendor_identity")
		}
		if existing := modules[current.Path]; existing != "" && existing != current.Version {
			return nil, errors.New("module_vendor_duplicate")
		}
		modules[current.Path] = current.Version
	}
	if scanner.Err() != nil || len(modules) == 0 {
		return nil, errors.New("module_vendor_read")
	}
	return modules, nil
}

// committedModuleSums returns the exact authenticated zip hashes in committed metadata.
func committedModuleSums(root string) (map[string]string, error) {
	paths := []string{"go.work.sum", "lib/go.sum", "cmd/dkim2d/go.sum", "cmd/dkim2-milter/go.sum", "cmd/dkim2ctl/go.sum", "tools/go.sum"}
	sums := make(map[string]string)
	for _, path := range paths {
		content, err := artifactpath.ReadFile(root, path, 8<<20)
		if err != nil {
			return nil, errors.New("module_sum_read")
		}
		scanner := bufio.NewScanner(bytes.NewReader(content))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) != 3 {
				continue
			}
			key := fields[0] + "@" + fields[1]
			if existing, exists := sums[key]; exists && existing != fields[2] {
				return nil, errors.New("module_sum_conflict")
			}
			sums[key] = fields[2]
		}
		if scanner.Err() != nil {
			return nil, errors.New("module_sum_read")
		}
	}
	return sums, nil
}

// committedModuleSumLines returns every exact authenticated line across workspace metadata.
func committedModuleSumLines(root string) (map[string]bool, error) {
	paths := []string{"go.work.sum", "lib/go.sum", "cmd/dkim2d/go.sum", "cmd/dkim2-milter/go.sum", "cmd/dkim2ctl/go.sum", "tools/go.sum"}
	lines := make(map[string]bool)
	for _, path := range paths {
		content, err := artifactpath.ReadFile(root, path, 8<<20)
		if err != nil {
			return nil, errors.New("module_sum_read")
		}
		scanner := bufio.NewScanner(bytes.NewReader(content))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) != 3 || !strings.HasPrefix(fields[2], "h1:") {
				return nil, errors.New("module_sum_format")
			}
			lines[scanner.Text()] = true
		}
		if scanner.Err() != nil {
			return nil, errors.New("module_sum_read")
		}
	}
	return lines, nil
}

// copyDependencyModule admits one cache archive only after sum authentication.
func copyDependencyModule(
	cache string,
	proxy string,
	dependency module.Version,
	sums map[string]string,
	includeZip bool,
) (ModuleIdentity, error) {
	escapedVersion, err := module.EscapeVersion(dependency.Version)
	if err != nil {
		return ModuleIdentity{}, errors.New("module_dependency_identity")
	}
	key := dependency.Path + "@" + dependency.Version
	hash := sums[key]
	mode := "zip"
	if !includeZip {
		hash = sums[key+"/go.mod"]
		mode = "go_mod_only"
	}
	if includeZip && !strings.HasPrefix(hash, "h1:") {
		return ModuleIdentity{}, errors.New("module_dependency_sum")
	}
	destination, err := proxyVersionDirectory(proxy, dependency.Path)
	if err != nil {
		return ModuleIdentity{}, err
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return ModuleIdentity{}, errors.New("module_proxy_write")
	}
	extensions := []string{".mod"}
	if mode == "zip" {
		extensions = append(extensions, ".zip")
	}
	for _, extension := range extensions {
		content, readErr := moduleArtifactContent(
			cache, dependency.Path, dependency.Version, extension, maxModuleBytes,
		)
		if readErr != nil || os.WriteFile(
			filepath.Join(destination, escapedVersion+extension), content, 0o600,
		) != nil {
			return ModuleIdentity{}, errors.New("module_dependency_read")
		}
	}
	if mode == "zip" {
		actual, hashErr := moduleZipHash(filepath.Join(destination, escapedVersion+".zip"))
		if hashErr != nil || actual != hash {
			return ModuleIdentity{}, errors.New("module_dependency_hash")
		}
	}
	if !strings.HasPrefix(hash, "h1:") {
		return ModuleIdentity{}, errors.New("module_dependency_sum")
	}
	info := []byte(fmt.Sprintf(`{"Version":%q,"Time":"1980-01-01T00:00:00Z"}`+"\n", dependency.Version))
	if err := os.WriteFile(filepath.Join(destination, escapedVersion+".info"), info, 0o600); err != nil {
		return ModuleIdentity{}, errors.New("module_proxy_write")
	}
	return ModuleIdentity{Path: dependency.Path, Version: dependency.Version, Mode: mode, H1: hash}, nil
}

// proxyVersionDirectory returns one escaped exact proxy path.
func proxyVersionDirectory(proxy, path string) (string, error) {
	escaped, err := module.EscapePath(path)
	if err != nil || filepath.IsAbs(escaped) || strings.Contains(escaped, "..") {
		return "", errors.New("module_proxy_path")
	}
	return filepath.Join(proxy, filepath.FromSlash(escaped), "@v"), nil
}

// readStableRegular reads one bounded regular non-link file and rechecks metadata.
func readStableRegular(path string, limit int64) ([]byte, error) {
	descriptor, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, errors.New("module_cache_file")
	}
	file := os.NewFile(uintptr(descriptor), filepath.Base(path))
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("module_cache_file")
	}
	defer func() { _ = file.Close() }()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > limit {
		return nil, errors.New("module_cache_file")
	}
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || !os.SameFile(before, after) ||
		int64(len(content)) != before.Size() || int64(len(content)) > limit ||
		!after.Mode().IsRegular() {
		return nil, errors.New("module_cache_unstable")
	}
	return content, nil
}

// moduleZipHash computes the canonical Go h1 digest for one module zip.
func moduleZipHash(path string) (string, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return "", errors.New("module_zip_read")
	}
	defer func() {
		_ = reader.Close()
	}()
	files := append([]*zip.File(nil), reader.File...)
	slices.SortFunc(files, func(left, right *zip.File) int {
		return strings.Compare(left.Name, right.Name)
	})
	summaryHasher := sha256.New()
	for _, file := range files {
		if file.FileInfo().IsDir() {
			continue
		}
		source, err := file.Open()
		if err != nil {
			return "", errors.New("module_zip_read")
		}
		contentHasher := sha256.New()
		size, copyErr := io.Copy(contentHasher, io.LimitReader(source, maxModuleBytes+1))
		closeErr := source.Close()
		if copyErr != nil || closeErr != nil || size > maxModuleBytes {
			return "", errors.New("module_zip_read")
		}
		if _, err := fmt.Fprintf(summaryHasher, "%x  %s\n", contentHasher.Sum(nil), file.Name); err != nil {
			return "", errors.New("module_zip_hash")
		}
	}
	return "h1:" + base64.StdEncoding.EncodeToString(summaryHasher.Sum(nil)), nil
}

// digestProxy hashes every exact proxy path and byte sequence deterministically.
func digestProxy(root string) (string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path != root && entry.Type()&os.ModeSymlink != 0 {
			return errors.New("module_proxy_link")
		}
		if entry.Type().IsRegular() {
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			paths = append(paths, filepath.ToSlash(relative))
		}
		return nil
	})
	if err != nil {
		return "", errors.New("module_proxy_walk")
	}
	slices.Sort(paths)
	hasher := sha256.New()
	for _, path := range paths {
		content, err := readStableRegular(filepath.Join(root, filepath.FromSlash(path)), maxModuleBytes)
		if err != nil {
			return "", err
		}
		if _, err := fmt.Fprintf(hasher, "%d:%s%d:", len(path), path, len(content)); err != nil {
			return "", errors.New("module_proxy_hash")
		}
		_, _ = hasher.Write(content)
	}
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

// makeProxyReadOnly removes write and execute authority from proxy files.
func makeProxyReadOnly(root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		if !entry.Type().IsRegular() || os.Chmod(path, 0o400) != nil {
			return errors.New("module_proxy_mode")
		}
		return nil
	})
	if err != nil {
		return errors.New("module_proxy_mode")
	}
	slices.Reverse(directories)
	for _, directory := range directories {
		if err := os.Chmod(directory, 0o500); err != nil {
			return errors.New("module_proxy_mode")
		}
	}
	return nil
}

// copyCandidateSnapshot materializes every durable candidate path for module tests.
func copyCandidateSnapshot(root, destination string, snapshot conformance.Snapshot) error {
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return errors.New("module_source_write")
	}
	for _, entry := range snapshot.Entries {
		if !validCandidateRelativePath(entry.Path) {
			return errors.New("module_source_path")
		}
		target := filepath.Join(destination, filepath.FromSlash(entry.Path))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return errors.New("module_source_write")
		}
		source, err := artifactpath.OpenFile(root, entry.Path, maxModuleBytes)
		if err != nil {
			return errors.New("module_source_read")
		}
		content, readErr := io.ReadAll(io.LimitReader(source, maxModuleBytes+1))
		closeErr := source.Close()
		if readErr != nil || closeErr != nil || int64(len(content)) > maxModuleBytes ||
			interop.SHA256(content) != entry.SHA256 {
			return errors.New("module_source_unstable")
		}
		mode := os.FileMode(0o600)
		if entry.Mode == "100755" {
			mode = 0o700
		}
		if err := os.WriteFile(target, content, mode); err != nil {
			return errors.New("module_source_write")
		}
	}
	return nil
}

// validCandidateRelativePath rejects only repository escape and ignored state roots.
func validCandidateRelativePath(name string) bool {
	if name == "" || len(name) > 4096 || strings.Contains(name, "\\") ||
		strings.HasPrefix(name, "/") ||
		filepath.ToSlash(filepath.Clean(filepath.FromSlash(name))) != name {
		return false
	}
	for _, component := range strings.Split(name, "/") {
		if component == "" || component == "." || component == ".." ||
			component == ".git" || component == "temp" || component == ".artifacts" {
			return false
		}
	}
	return true
}

// runStandaloneModule performs tidy readback, graph, test, vet, and build offline.
func runStandaloneModule(
	root string,
	proxy string,
	state string,
	allowedSums map[string]bool,
) ([]byte, error) {
	if err := os.MkdirAll(filepath.Join(state, "mod"), 0o700); err != nil ||
		os.MkdirAll(filepath.Join(state, "cache"), 0o700) != nil ||
		os.MkdirAll(filepath.Join(state, "home"), 0o700) != nil {
		return nil, errors.New("module_state")
	}
	temporaryRoot, err := os.MkdirTemp(os.TempDir(), "dkim2-module-proof.")
	if err != nil {
		return nil, errors.New("module_state")
	}
	defer func() {
		_ = os.RemoveAll(temporaryRoot)
	}()
	environment := []string{
		"HOME=" + filepath.Join(state, "home"),
		"TMPDIR=" + temporaryRoot,
		"LANG=C", "LC_ALL=C", "PATH=/usr/local/bin:/usr/bin:/bin",
		"GOENV=off", "GOTOOLCHAIN=local", "GOWORK=off",
		"GOPROXY=file://" + filepath.ToSlash(proxy), "GOSUMDB=off",
		"GONOSUMDB=*", "GONOPROXY=none", "GOPRIVATE=", "GOVCS=off",
		"GOMODCACHE=" + filepath.Join(state, "mod"),
		"GOCACHE=" + filepath.Join(state, "cache"),
		"GOFLAGS=-mod=readonly",
	}
	modPath := filepath.Join(root, "go.mod")
	sumPath := filepath.Join(root, "go.sum")
	originalMod, err := readStableRegular(modPath, 1<<20)
	if err != nil {
		return nil, errors.New("standalone_metadata")
	}
	originalSum, err := readStableRegular(sumPath, 8<<20)
	if err != nil {
		return nil, errors.New("standalone_metadata")
	}
	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = root
	tidy.Env = replaceEnvironment(environment, "GOFLAGS=-mod=mod")
	output, err := tidy.CombinedOutput()
	if err != nil || len(output) > 8<<20 {
		return nil, errors.New("standalone_tidy")
	}
	tidiedMod, err := readStableRegular(modPath, 1<<20)
	if err != nil || !bytes.Equal(originalMod, tidiedMod) {
		return nil, errors.New("standalone_tidy_mod")
	}
	tidiedSum, err := readStableRegular(sumPath, 8<<20)
	if err != nil || !moduleSumSubset(originalSum, tidiedSum, allowedSums) {
		return nil, errors.New("standalone_tidy_sum")
	}
	commands := [][]string{
		{"list", "-deps", "-f", `{{with .Module}}{{.Path}}@{{.Version}}{{end}}`, "./..."},
		{"test", "./..."},
		{"vet", "./..."},
		{"build", "./..."},
	}
	var graph []byte
	for _, arguments := range commands {
		command := exec.Command("go", arguments...)
		command.Dir = root
		command.Env = environment
		output, err := command.CombinedOutput()
		if err != nil || len(output) > 8<<20 {
			return nil, errors.New("standalone_" + arguments[0])
		}
		if arguments[0] == "list" {
			graph = append([]byte(nil), output...)
		}
	}
	if len(graph) == 0 {
		return nil, errors.New("module_graph")
	}
	return graph, nil
}

// replaceEnvironment returns one environment with an exact key replacement.
func replaceEnvironment(environment []string, replacement string) []string {
	key, _, _ := strings.Cut(replacement, "=")
	result := make([]string, 0, len(environment))
	for _, value := range environment {
		current, _, _ := strings.Cut(value, "=")
		if current != key {
			result = append(result, value)
		}
	}
	return append(result, replacement)
}

// moduleSumSubset proves standalone tidy adds or changes no authenticated sum.
func moduleSumSubset(original, tidied []byte, allowed map[string]bool) bool {
	originalLines := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(original))
	for scanner.Scan() {
		originalLines[scanner.Text()] = true
	}
	if scanner.Err() != nil {
		return false
	}
	scanner = bufio.NewScanner(bytes.NewReader(tidied))
	for scanner.Scan() {
		if !originalLines[scanner.Text()] && !allowed[scanner.Text()] {
			return false
		}
	}
	return scanner.Err() == nil
}

// canonicalModuleProof returns stable indented JSON with one trailing newline.
func canonicalModuleProof(proof ModuleProof) ([]byte, error) {
	content, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		return nil, errors.New("module_proof_json")
	}
	return append(content, '\n'), nil
}

// writePrivateArtifact installs one bounded ignored artifact with private mode.
func writePrivateArtifact(root, relative string, content []byte) error {
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return errors.New("module_artifact_write")
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".artifact.")
	if err != nil {
		return errors.New("module_artifact_write")
	}
	name := temporary.Name()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		_ = os.Remove(name)
		return errors.New("module_artifact_write")
	}
	_, writeErr := temporary.Write(content)
	closeErr := temporary.Close()
	if writeErr != nil || closeErr != nil || os.Rename(name, path) != nil {
		_ = os.Remove(name)
		return errors.New("module_artifact_write")
	}
	return nil
}
