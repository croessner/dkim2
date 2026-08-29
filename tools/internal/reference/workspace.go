//nolint:goconst // Exact workspace metadata and environment values form an auditable allowlist.
package reference

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/croessner/dkim2/tools/internal/conformance"
)

var workspaceMetadataPaths = []string{
	"go.work",
	"go.work.sum",
	"lib/go.mod",
	"lib/go.sum",
	"cmd/dkim2d/go.mod",
	"cmd/dkim2d/go.sum",
	"cmd/dkim2-milter/go.mod",
	"cmd/dkim2-milter/go.sum",
	"cmd/dkim2-exim/go.mod",
	"cmd/dkim2-exim/go.sum",
	"cmd/dkim2ctl/go.mod",
	"cmd/dkim2ctl/go.sum",
	"tools/go.mod",
	"tools/go.sum",
}

var vendorLFPaths = []string{
	"github.com/vmware-labs/yaml-jsonpath/LICENSE",
	"github.com/vmware-labs/yaml-jsonpath/NOTICE",
}

var vendorTrailingWhitespacePaths = []string{
	"github.com/go-openapi/jsonpointer/README.md",
	"github.com/go-sql-driver/mysql/LICENSE",
	"github.com/miekg/dns/LICENSE",
	"github.com/pelletier/go-toml/v2/README.md",
	"go.uber.org/zap/CHANGELOG.md",
}

// WriteVendorTree regenerates and installs the hardened vendor tree through
// the candidate-bound private proxy without ambient network or module state.
func WriteVendorTree(root string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return errors.New("vendor_root")
	}
	proof, proxy, cleanup, err := BuildPrivateProxy(root)
	if err != nil {
		return err
	}
	cleanupDone := false
	defer func() {
		if !cleanupDone {
			_ = cleanup()
		}
	}()
	snapshot, err := conformance.ProduceSnapshot(root, proof.BaseRevision)
	if err != nil || snapshot.SHA256 != proof.CandidateSnapshotSHA256 {
		return errors.New("vendor_candidate")
	}
	work := filepath.Dir(proxy)
	repository := filepath.Join(work, "vendor-workspace")
	if err := copyCandidateSnapshot(root, repository, snapshot); err != nil {
		return err
	}
	output := filepath.Join(work, "vendor-output")
	if err := runWorkspaceCommand(
		repository, proxy, filepath.Join(work, "vendor-state"),
		"work", "vendor", "-o", output,
	); err != nil {
		return err
	}
	if err := hardenVendorTree(output); err != nil {
		return err
	}
	if err := normalizeVendorLF(output); err != nil {
		return err
	}
	current, err := conformance.ProduceSnapshot(root, proof.BaseRevision)
	if err != nil || current.SHA256 != proof.CandidateSnapshotSHA256 {
		return errors.New("vendor_candidate")
	}
	if err := installVendorTree(root, output); err != nil {
		return err
	}
	if err := cleanup(); err != nil {
		return err
	}
	cleanupDone = true
	return nil
}

// CheckWorkspaceMetadata proves go work sync is stable through the private proxy.
func CheckWorkspaceMetadata(root string) error {
	proof, proxy, cleanup, err := BuildPrivateProxy(root)
	if err != nil {
		return err
	}
	defer func() { _ = cleanup() }()
	snapshot, err := conformance.ProduceSnapshot(root, proof.BaseRevision)
	if err != nil || snapshot.SHA256 != proof.CandidateSnapshotSHA256 {
		return errors.New("workspace_candidate")
	}
	repository := filepath.Join(filepath.Dir(proxy), "workspace")
	if err := copyCandidateSnapshot(root, repository, snapshot); err != nil {
		return err
	}
	if err := runWorkspaceCommand(repository, proxy, filepath.Join(filepath.Dir(proxy), "workspace-state"), "work", "sync"); err != nil {
		return err
	}
	for _, path := range workspaceMetadataPaths {
		current, err := readStableRegular(filepath.Join(root, filepath.FromSlash(path)), 8<<20)
		if err != nil {
			return errors.New("workspace_metadata")
		}
		generated, err := readStableRegular(filepath.Join(repository, filepath.FromSlash(path)), 8<<20)
		if err != nil || !bytes.Equal(current, generated) {
			return errors.New("workspace_stale")
		}
	}
	return nil
}

// CheckVendorTree proves workspace vendoring is reproducible through the private proxy.
func CheckVendorTree(root string) error {
	proof, proxy, cleanup, err := BuildPrivateProxy(root)
	if err != nil {
		return err
	}
	defer func() { _ = cleanup() }()
	snapshot, err := conformance.ProduceSnapshot(root, proof.BaseRevision)
	if err != nil || snapshot.SHA256 != proof.CandidateSnapshotSHA256 {
		return errors.New("vendor_candidate")
	}
	repository := filepath.Join(filepath.Dir(proxy), "vendor-workspace")
	if err := copyCandidateSnapshot(root, repository, snapshot); err != nil {
		return err
	}
	output := filepath.Join(filepath.Dir(proxy), "vendor-output")
	if err := runWorkspaceCommand(
		repository, proxy, filepath.Join(filepath.Dir(proxy), "vendor-state"),
		"work", "vendor", "-o", output,
	); err != nil {
		return err
	}
	if err := hardenVendorTree(output); err != nil {
		return err
	}
	if err := normalizeVendorLF(output); err != nil {
		return err
	}
	equal, err := equalRegularTrees(filepath.Join(root, "vendor"), output)
	if err != nil || !equal {
		return errors.New("vendor_stale")
	}
	return nil
}

// runWorkspaceCommand executes one closed Go workspace maintenance operation.
func runWorkspaceCommand(root, proxy, state string, arguments ...string) error {
	if len(arguments) < 2 || arguments[0] != "work" ||
		(arguments[1] != "sync" && arguments[1] != "vendor") {
		return errors.New("workspace_arguments")
	}
	for _, directory := range []string{
		filepath.Join(state, "home"),
		filepath.Join(state, "mod"),
		filepath.Join(state, "cache"),
		filepath.Join(state, "tmp"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return errors.New("workspace_state")
		}
	}
	command := exec.Command("go", arguments...)
	command.Dir = root
	command.Env = []string{
		"HOME=" + filepath.Join(state, "home"),
		"TMPDIR=" + filepath.Join(state, "tmp"),
		"LANG=C", "LC_ALL=C", "PATH=/usr/local/bin:/usr/bin:/bin",
		"GOENV=off", "GOTOOLCHAIN=local",
		"GOWORK=" + filepath.Join(root, "go.work"),
		"GOPROXY=file://" + filepath.ToSlash(proxy), "GOSUMDB=off",
		"GONOSUMDB=*", "GONOPROXY=none", "GOPRIVATE=", "GOVCS=off",
		"GOMODCACHE=" + filepath.Join(state, "mod"),
		"GOCACHE=" + filepath.Join(state, "cache"),
		"GOFLAGS=",
	}
	output, err := command.CombinedOutput()
	if err != nil || len(output) > 8<<20 {
		return errors.New("workspace_" + arguments[1])
	}
	return nil
}

// normalizeVendorLF applies the repository's exact upstream text exceptions.
func normalizeVendorLF(root string) error {
	for _, path := range vendorLFPaths {
		target := filepath.Join(root, filepath.FromSlash(path))
		content, err := readStableRegular(target, 4<<20)
		if err != nil {
			return errors.New("vendor_normalize")
		}
		content = bytes.ReplaceAll(content, []byte("\r"), nil)
		if err := os.WriteFile(target, content, 0o644); err != nil {
			return errors.New("vendor_normalize")
		}
	}
	for _, path := range vendorTrailingWhitespacePaths {
		target := filepath.Join(root, filepath.FromSlash(path))
		content, err := readStableRegular(target, 4<<20)
		if err != nil {
			return errors.New("vendor_normalize")
		}
		lines := bytes.Split(content, []byte("\n"))
		for index := range lines {
			lines[index] = bytes.TrimRight(lines[index], " \t")
		}
		if err := os.WriteFile(target, bytes.Join(lines, []byte("\n")), 0o644); err != nil {
			return errors.New("vendor_normalize")
		}
	}
	return nil
}

// installVendorTree swaps one generated tree into the repository while keeping
// the previous tree recoverable inside invocation-owned ignored state.
func installVendorTree(root, generated string) error {
	current := filepath.Join(root, "vendor")
	currentInfo, err := os.Lstat(current)
	if err != nil || !currentInfo.IsDir() || currentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("vendor_install")
	}
	generatedInfo, err := os.Lstat(generated)
	if err != nil || !generatedInfo.IsDir() || generatedInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("vendor_install")
	}
	previous := filepath.Join(filepath.Dir(generated), "vendor-previous")
	if _, err := os.Lstat(previous); !os.IsNotExist(err) {
		return errors.New("vendor_install")
	}
	if err := os.Rename(current, previous); err != nil {
		return errors.New("vendor_install")
	}
	if err := os.Rename(generated, current); err != nil {
		if restoreErr := os.Rename(previous, current); restoreErr != nil {
			return errors.New("vendor_restore")
		}
		return errors.New("vendor_install")
	}
	return nil
}

// equalRegularTrees compares exact regular-file names and bytes without following links.
func equalRegularTrees(left, right string) (bool, error) {
	leftPaths, err := regularTreePaths(left)
	if err != nil {
		return false, err
	}
	rightPaths, err := regularTreePaths(right)
	if err != nil || !slices.Equal(leftPaths, rightPaths) {
		return false, err
	}
	for _, path := range leftPaths {
		leftContent, err := readStableRegular(filepath.Join(left, filepath.FromSlash(path)), maxModuleBytes)
		if err != nil {
			return false, errors.New("vendor_compare")
		}
		rightContent, err := readStableRegular(filepath.Join(right, filepath.FromSlash(path)), maxModuleBytes)
		if err != nil || !bytes.Equal(leftContent, rightContent) {
			return false, err
		}
	}
	return true, nil
}

// regularTreePaths returns sorted confined regular-file paths.
func regularTreePaths(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || (!entry.IsDir() && !entry.Type().IsRegular()) {
			return errors.New("vendor_tree")
		}
		if entry.Type().IsRegular() {
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			relative = filepath.ToSlash(relative)
			if strings.HasPrefix(relative, "../") || strings.HasPrefix(relative, "/") {
				return errors.New("vendor_tree")
			}
			paths = append(paths, relative)
		}
		return nil
	})
	if err != nil {
		return nil, errors.New("vendor_tree")
	}
	slices.Sort(paths)
	return paths, nil
}
