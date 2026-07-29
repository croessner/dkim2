// Command buildmeta derives closed container build metadata from repository state.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/dkim2/tools/internal/artifactpath"
	"github.com/croessner/dkim2/tools/internal/conformance"
)

type buildMetadata struct {
	Schema          string `json:"schema"`
	Version         string `json:"version"`
	Revision        string `json:"revision"`
	SourceDateEpoch int64  `json:"source_date_epoch"`
	Created         string `json:"created"`
	Dirty           string `json:"dirty"`
	CandidateSHA256 string `json:"candidate_snapshot_sha256"`
}

// main emits metadata derived only from the exact local repository state.
func main() {
	var root string
	var materialize string
	flag.StringVar(&root, "root", "", "repository root")
	flag.StringVar(&materialize, "materialize", "", "private candidate context")
	flag.Parse()
	if flag.NArg() != 0 || root == "" {
		os.Exit(2)
	}
	metadata, err := deriveMetadata(root)
	if err != nil {
		fail()
	}
	if materialize != "" {
		revision, revisionErr := conformance.CurrentRevision(root)
		candidate, candidateErr := conformance.ProduceSnapshot(root, revision)
		if revisionErr != nil || candidateErr != nil ||
			candidate.SHA256 != metadata.CandidateSHA256 ||
			materializeCandidate(root, materialize, candidate) != nil {
			fail()
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(metadata); err != nil {
		fail()
	}
}

// materializeCandidate copies the exact descriptor-bound candidate into a private context.
func materializeCandidate(
	root string,
	destination string,
	candidate conformance.Snapshot,
) error {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return errors.New("metadata_context")
	}
	absoluteRoot, err = filepath.EvalSymlinks(absoluteRoot)
	if err != nil {
		return errors.New("metadata_context")
	}
	cleaned := filepath.Clean(destination)
	parts := strings.Split(cleaned, string(filepath.Separator))
	if filepath.IsAbs(destination) || len(parts) != 3 ||
		parts[0] != ".artifacts" || parts[2] != "context" ||
		(!strings.HasPrefix(parts[1], ".product-build-work.") &&
			!strings.HasPrefix(parts[1], ".image-build-work.")) {
		return errors.New("metadata_context")
	}
	absoluteDestination := filepath.Join(absoluteRoot, cleaned)
	info, err := os.Lstat(absoluteDestination)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("metadata_context")
	}
	evaluated, err := filepath.EvalSymlinks(absoluteDestination)
	if err != nil || evaluated != absoluteDestination {
		return errors.New("metadata_context")
	}
	destinationRoot, err := os.OpenRoot(absoluteDestination)
	if err != nil {
		return errors.New("metadata_context")
	}
	defer func() {
		_ = destinationRoot.Close()
	}()
	for _, entry := range candidate.Entries {
		if err := materializeEntry(absoluteRoot, destinationRoot, entry); err != nil {
			return err
		}
	}
	return nil
}

// materializeEntry copies and revalidates one candidate file through open descriptors.
func materializeEntry(
	root string,
	destination *os.Root,
	entry conformance.SnapshotEntry,
) error {
	source, err := artifactpath.OpenFile(root, entry.Path, 256<<20)
	if err != nil {
		return errors.New("metadata_context")
	}
	defer func() {
		_ = source.Close()
	}()
	before, err := artifactpath.SnapshotOpenFile(source, 256<<20)
	if err != nil || before.SHA256 != entry.SHA256 {
		return errors.New("metadata_context")
	}
	parent := filepath.Dir(filepath.FromSlash(entry.Path))
	if parent != "." {
		if err := destination.MkdirAll(parent, 0o700); err != nil {
			return errors.New("metadata_context")
		}
	}
	target, err := destination.OpenFile(
		filepath.FromSlash(entry.Path),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		return errors.New("metadata_context")
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(target, hasher), source)
	closeErr := target.Close()
	after, snapshotErr := artifactpath.SnapshotOpenFile(source, 256<<20)
	if copyErr != nil || closeErr != nil || snapshotErr != nil ||
		!reflect.DeepEqual(before, after) || written != before.Size ||
		fmt.Sprintf("%x", hasher.Sum(nil)) != entry.SHA256 {
		return errors.New("metadata_context")
	}
	mode := os.FileMode(0o400)
	if entry.Mode == "100755" {
		mode = 0o500
	} else if entry.Mode != "100644" {
		return errors.New("metadata_context")
	}
	if err := destination.Chmod(filepath.FromSlash(entry.Path), mode); err != nil {
		return errors.New("metadata_context")
	}
	return nil
}

// deriveMetadata binds revision, timestamp, version, and dirty state to Git.
func deriveMetadata(root string) (buildMetadata, error) {
	revision, err := conformance.CurrentRevision(root)
	if err != nil {
		return buildMetadata{}, errors.New("metadata_revision")
	}
	candidate, err := conformance.ProduceSnapshot(root, revision)
	if err != nil {
		return buildMetadata{}, errors.New("metadata_candidate")
	}
	epochText, err := gitOutput(root, "show", "-s", "--format=%ct", revision)
	if err != nil {
		return buildMetadata{}, errors.New("metadata_epoch")
	}
	epoch, err := strconv.ParseInt(epochText, 10, 64)
	if err != nil || epoch < 1 {
		return buildMetadata{}, errors.New("metadata_epoch")
	}
	tags, err := gitOutput(root, "tag", "--points-at", revision, "--sort=refname")
	if err != nil {
		return buildMetadata{}, errors.New("metadata_tags")
	}
	version, err := selectVersion(strings.Fields(tags))
	if err != nil {
		return buildMetadata{}, err
	}
	status, err := gitOutput(root, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return buildMetadata{}, errors.New("metadata_status")
	}
	dirty := "clean"
	if status != "" {
		dirty = "dirty"
	}
	return buildMetadata{
		Schema:          "dkim2-container-build-metadata-v1",
		Version:         version,
		Revision:        revision,
		SourceDateEpoch: epoch,
		Created:         time.Unix(epoch, 0).UTC().Format(time.RFC3339),
		Dirty:           dirty,
		CandidateSHA256: candidate.SHA256,
	}, nil
}

// selectVersion accepts at most one exact stable semantic-version tag.
func selectVersion(tags []string) (string, error) {
	version := "0.0.0-dev"
	found := false
	for _, tag := range tags {
		if !strings.HasPrefix(tag, "v") {
			continue
		}
		if !validReleaseVersion(tag) || found {
			return "", errors.New("metadata_version")
		}
		version = tag
		found = true
	}
	return version, nil
}

// validReleaseVersion accepts exactly vMAJOR.MINOR.PATCH with decimal fields.
func validReleaseVersion(value string) bool {
	if len(value) < 6 || value[0] != 'v' {
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

// gitOutput runs one closed Git command and returns bounded trimmed output.
func gitOutput(root string, arguments ...string) (string, error) {
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	command.Env = []string{
		"HOME=" + os.TempDir(),
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/bin:/bin",
	}
	content, err := command.Output()
	if err != nil || len(content) > 1<<20 {
		return "", errors.New("metadata_git")
	}
	return strings.TrimSpace(string(content)), nil
}

// fail emits one fixed content-free metadata failure.
func fail() {
	fmt.Fprintln(os.Stderr, "build metadata rejected")
	os.Exit(1)
}
