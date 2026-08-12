// Command dbguard owns exact offline Trivy database use and portable identity.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/croessner/dkim2/tools/internal/artifactpath"
	"github.com/croessner/dkim2/tools/internal/conformance"
	"github.com/croessner/dkim2/tools/internal/strictjson"
)

const (
	metadataPath             = ".artifacts/image-tools/trivy-cache/db/metadata.json"
	databasePath             = ".artifacts/image-tools/trivy-cache/db/trivy.db"
	trivyPath                = ".artifacts/image-tools/trivy"
	trivyIdentityPath        = ".artifacts/image-tools/trivy.identity.json"
	toolAllowlistPath        = "build/container/image-tools.json"
	maximumMetadataBytes     = int64(64 << 10)
	maximumDatabaseBytes     = int64(2 << 30)
	maximumScannerBytes      = int64(256 << 20)
	maximumScannerOutput     = int64(128 << 20)
	maximumScannerDiagnostic = int64(64 << 10)
	maximumLayoutBytes       = int64(1 << 30)
	maximumLayoutEntries     = 10_000
	maximumScanDuration      = 5 * time.Minute
	maximumClockSkew         = 5 * time.Minute
	maximumDatabaseAge       = 48 * time.Hour
)

type toolIdentity struct {
	Schema        string `json:"schema"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Asset         string `json:"asset"`
	ArchiveSHA256 string `json:"archive_sha256"`
	BinarySHA256  string `json:"binary_sha256"`
}

type toolAllowlist struct {
	Schema string `json:"schema"`
	Tools  []struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Platforms []struct {
			GOOS          string `json:"goos"`
			GOARCH        string `json:"goarch"`
			Asset         string `json:"asset"`
			ArchiveSHA256 string `json:"archive_sha256"`
			BinarySHA256  string `json:"binary_sha256"`
		} `json:"platforms"`
	} `json:"tools"`
}

type databaseMetadata struct {
	Version      int    `json:"Version"`
	NextUpdate   string `json:"NextUpdate"`
	UpdatedAt    string `json:"UpdatedAt"`
	DownloadedAt string `json:"DownloadedAt"`
}

type portableFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type databaseSnapshot struct {
	Schema                  string       `json:"schema"`
	CandidateSnapshotSHA256 string       `json:"candidate_snapshot_sha256"`
	ScanTime                string       `json:"scan_time"`
	Tool                    toolIdentity `json:"tool"`
	VulnerabilityDatabase   struct {
		SchemaVersion        int            `json:"schema_version"`
		NextUpdate           string         `json:"next_update"`
		UpdatedAt            string         `json:"updated_at"`
		DownloadedAt         string         `json:"downloaded_at"`
		MaximumDatabaseBytes int64          `json:"maximum_database_bytes"`
		Files                []portableFile `json:"files"`
	} `json:"vulnerability_database"`
}

type guardedDatabase struct {
	portable databaseSnapshot
	metadata artifactpath.FileSnapshot
	database artifactpath.FileSnapshot
}

type guardedFiles struct {
	metadataValue databaseMetadata
	metadata      artifactpath.FileSnapshot
	database      artifactpath.FileSnapshot
}

type boundedWriter struct {
	destination io.Writer
	remaining   int64
}

type scanSnapshot struct {
	rootPath string
}

// main inspects the database or executes one closed offline scan under the guard.
func main() {
	var root string
	var inspect bool
	var input string
	var output string
	var scanTimeValue string
	flag.StringVar(&root, "root", "", "repository root")
	flag.BoolVar(&inspect, "inspect", false, "emit the portable database identity")
	flag.StringVar(&input, "input", "", "confined OCI layout")
	flag.StringVar(&output, "output", "", "confined Trivy JSON output")
	flag.StringVar(&scanTimeValue, "scan-time", "", "shared canonical UTC scan time")
	flag.Parse()
	if flag.NArg() != 0 || root == "" ||
		(inspect && (input != "" || output != "")) ||
		(!inspect && (input == "" || output == "")) {
		os.Exit(2)
	}
	scanTime, err := parseScanTime(scanTimeValue, time.Now().UTC())
	if err != nil {
		fail()
	}
	var result databaseSnapshot
	if inspect {
		result, err = buildSnapshot(root, scanTime)
	} else {
		result, err = runGuardedScan(root, input, output, scanTime)
	}
	if err != nil {
		fail()
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fail()
	}
}

// buildSnapshot returns one portable projection after a stable descriptor capture.
func buildSnapshot(root string, scanTime time.Time) (databaseSnapshot, error) {
	captured, err := captureDatabase(root, scanTime)
	if err != nil {
		return databaseSnapshot{}, err
	}
	return captured.portable, nil
}

// runGuardedScan binds scanner input, output, environment, tool, and database.
func runGuardedScan(
	root string,
	input string,
	output string,
	scanTime time.Time,
) (databaseSnapshot, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return databaseSnapshot{}, errors.New("database_root")
	}
	inputRelative, inputWork, err := confinedWorkRelative(input, true)
	if err != nil {
		return databaseSnapshot{}, err
	}
	outputRelative, outputWork, err := confinedWorkRelative(output, false)
	if err != nil || inputWork != outputWork ||
		strings.HasPrefix(outputRelative, inputRelative+string(filepath.Separator)) {
		return databaseSnapshot{}, errors.New("database_path")
	}
	inputBefore, err := artifactpath.SnapshotTree(
		absoluteRoot,
		inputRelative,
		maximumLayoutEntries,
		maximumLayoutBytes,
	)
	if err != nil {
		return databaseSnapshot{}, errors.New("database_input")
	}
	outputFile, err := artifactpath.CreateFile(absoluteRoot, outputRelative)
	if err != nil {
		return databaseSnapshot{}, errors.New("database_output")
	}
	outputClosed := false
	defer func() {
		if !outputClosed {
			_ = outputFile.Close()
		}
	}()
	before, err := captureDatabase(absoluteRoot, scanTime)
	if err != nil {
		return databaseSnapshot{}, err
	}
	scanView, err := prepareScanSnapshot(
		absoluteRoot,
		inputWork,
		inputRelative,
		inputBefore,
		before,
	)
	if err != nil {
		return databaseSnapshot{}, err
	}
	defer scanView.close()
	scanContext, cancel := context.WithTimeout(context.Background(), maximumScanDuration)
	defer cancel()
	command := scannerCommand(
		scanContext,
		scanView,
		filepath.Join(absoluteRoot, inputWork),
	)
	command.Stdout = &boundedWriter{
		destination: outputFile,
		remaining:   maximumScannerOutput,
	}
	command.Stderr = &boundedWriter{
		destination: io.Discard,
		remaining:   maximumScannerDiagnostic,
	}
	if err := command.Run(); err != nil {
		return databaseSnapshot{}, errors.New("database_scan")
	}
	if err := outputFile.Sync(); err != nil {
		return databaseSnapshot{}, errors.New("database_output")
	}
	outputDescriptor, err := artifactpath.SnapshotOpenFile(
		outputFile,
		maximumScannerOutput,
	)
	if err != nil {
		return databaseSnapshot{}, errors.New("database_output")
	}
	if err := outputFile.Close(); err != nil {
		return databaseSnapshot{}, errors.New("database_output")
	}
	outputClosed = true
	outputPath, err := artifactpath.SnapshotFile(
		absoluteRoot,
		outputRelative,
		maximumScannerOutput,
	)
	if err != nil || !reflect.DeepEqual(outputDescriptor, outputPath) {
		return databaseSnapshot{}, errors.New("database_output")
	}
	after, err := captureDatabase(absoluteRoot, scanTime)
	if err != nil || !sameGuardedDatabase(before, after) {
		return databaseSnapshot{}, errors.New("database_changed")
	}
	inputAfter, err := artifactpath.SnapshotTree(
		absoluteRoot,
		inputRelative,
		maximumLayoutEntries,
		maximumLayoutBytes,
	)
	if err != nil || !reflect.DeepEqual(inputBefore, inputAfter) {
		return databaseSnapshot{}, errors.New("database_input_changed")
	}
	return before.portable, nil
}

// scannerCommand builds the fixed descriptor-bound invocation and clean environment.
func scannerCommand(ctx context.Context, snapshot *scanSnapshot, work string) *exec.Cmd {
	command := exec.CommandContext(
		ctx,
		filepath.Join(snapshot.rootPath, "trivy"),
		"image",
		"--cache-dir", filepath.Join(snapshot.rootPath, "cache"),
		"--cache-backend", "memory",
		"--skip-db-update",
		"--skip-version-check",
		"--disable-telemetry",
		"--offline-scan",
		"--no-progress",
		"--input", filepath.Join(snapshot.rootPath, "input"),
		"--format", "json",
		"--scanners", "vuln",
		"--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
		"--exit-code", "0",
	)
	command.Dir = work
	command.WaitDelay = 5 * time.Second
	command.Env = []string{
		"DOCKER_CONFIG=" + filepath.Join(snapshot.rootPath, "docker-config"),
		"HOME=" + work,
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/bin:/bin",
		"TMPDIR=" + work,
		"TZ=UTC",
	}
	return command
}

// prepareScanSnapshot binds every consumed executable, DB, and layout byte to FDs.
func prepareScanSnapshot(
	root string,
	work string,
	input string,
	inputInventory []artifactpath.TreeEntry,
	database guardedDatabase,
) (*scanSnapshot, error) {
	viewPath := filepath.Join(root, work, ".scanner-snapshot")
	if err := os.Mkdir(viewPath, 0o700); err != nil {
		return nil, errors.New("database_snapshot")
	}
	snapshot := &scanSnapshot{rootPath: viewPath}
	failSnapshot := func() (*scanSnapshot, error) {
		snapshot.close()
		return nil, errors.New("database_snapshot")
	}
	scanner, err := artifactpath.OpenFile(root, trivyPath, maximumScannerBytes)
	if err != nil {
		return failSnapshot()
	}
	scannerIdentity, err := artifactpath.SnapshotOpenFile(scanner, maximumScannerBytes)
	if err != nil || scannerIdentity.SHA256 != database.portable.Tool.BinarySHA256 {
		_ = scanner.Close()
		return failSnapshot()
	}
	if err := cloneSnapshotFile(
		root,
		scanner,
		filepath.Join(viewPath, "trivy"),
		scannerIdentity,
		maximumScannerBytes,
	); err != nil {
		_ = scanner.Close()
		return failSnapshot()
	}
	if err := scanner.Close(); err != nil {
		return failSnapshot()
	}
	if err := os.Chmod(filepath.Join(viewPath, "trivy"), 0o500); err != nil {
		return failSnapshot()
	}
	for _, directory := range []string{
		filepath.Join(viewPath, "input"),
		filepath.Join(viewPath, "cache"),
		filepath.Join(viewPath, "cache", "db"),
		filepath.Join(viewPath, "docker-config"),
	} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			return failSnapshot()
		}
	}
	if err := os.WriteFile(
		filepath.Join(viewPath, "docker-config", "config.json"),
		[]byte("{\"auths\":{}}\n"),
		0o400,
	); err != nil {
		return failSnapshot()
	}
	for _, entry := range inputInventory {
		target := filepath.Join(viewPath, "input")
		if entry.Path != "." {
			target = filepath.Join(target, entry.Path)
		}
		switch entry.Kind {
		case "directory":
			if entry.Path != "." {
				if err := os.Mkdir(target, 0o700); err != nil {
					return failSnapshot()
				}
			}
		case "file":
			source := filepath.Join(input, entry.Path)
			if err := addSnapshotFile(
				root,
				source,
				target,
				entry.Snapshot,
				maximumLayoutBytes,
			); err != nil {
				return failSnapshot()
			}
		default:
			return failSnapshot()
		}
	}
	if err := addSnapshotFile(
		root,
		metadataPath,
		filepath.Join(viewPath, "cache", "db", "metadata.json"),
		database.metadata,
		maximumMetadataBytes,
	); err != nil {
		return failSnapshot()
	}
	if err := addSnapshotFile(
		root,
		databasePath,
		filepath.Join(viewPath, "cache", "db", "trivy.db"),
		database.database,
		maximumDatabaseBytes,
	); err != nil {
		return failSnapshot()
	}
	if err := makeSnapshotReadOnly(viewPath); err != nil {
		return failSnapshot()
	}
	return snapshot, nil
}

// cloneSnapshotFile installs exact descriptor-bound bytes using filesystem CoW.
func cloneSnapshotFile(
	root string,
	source *os.File,
	target string,
	expected artifactpath.FileSnapshot,
	limit int64,
) error {
	if source == nil {
		return errors.New("database_snapshot")
	}
	if err := cloneFile(source, target); err != nil {
		return errors.New("database_snapshot")
	}
	relative, err := filepath.Rel(root, target)
	if err != nil {
		return errors.New("database_snapshot")
	}
	actual, err := artifactpath.SnapshotFile(root, relative, limit)
	if err != nil || actual.Size != expected.Size || actual.SHA256 != expected.SHA256 {
		return errors.New("database_snapshot")
	}
	return nil
}

// addSnapshotFile clones one descriptor-verified source into the exclusive view.
func addSnapshotFile(
	root string,
	source string,
	target string,
	expected artifactpath.FileSnapshot,
	limit int64,
) error {
	file, err := artifactpath.OpenFile(root, source, limit)
	if err != nil {
		return errors.New("database_snapshot")
	}
	actual, err := artifactpath.SnapshotOpenFile(file, limit)
	if err != nil || !reflect.DeepEqual(actual, expected) {
		_ = file.Close()
		return errors.New("database_snapshot")
	}
	if err := cloneSnapshotFile(root, file, target, expected, limit); err != nil {
		_ = file.Close()
		return errors.New("database_snapshot")
	}
	if err := file.Close(); err != nil {
		return errors.New("database_snapshot")
	}
	return os.Chmod(target, 0o400)
}

// makeSnapshotReadOnly removes write permission from the private view directories.
func makeSnapshotReadOnly(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o500)
		}
		return nil
	})
}

// close releases every inherited descriptor and removes the private scan view.
func (snapshot *scanSnapshot) close() {
	if snapshot == nil {
		return
	}
	if snapshot.rootPath != "" {
		_ = os.Chmod(snapshot.rootPath, 0o700)
		_ = filepath.WalkDir(
			snapshot.rootPath,
			func(path string, entry os.DirEntry, err error) error {
				if err == nil && entry.IsDir() {
					_ = os.Chmod(path, 0o700)
				}
				return nil
			},
		)
		_ = os.RemoveAll(snapshot.rootPath)
	}
}

// sameGuardedDatabase compares private and portable scanner database identity.
func sameGuardedDatabase(left guardedDatabase, right guardedDatabase) bool {
	return reflect.DeepEqual(left.metadata, right.metadata) &&
		reflect.DeepEqual(left.database, right.database) &&
		reflect.DeepEqual(left.portable, right.portable)
}

// guardDatabaseFiles is the focused test seam for private database stability.
func guardDatabaseFiles(root string, operation func() error) error {
	if operation == nil {
		return errors.New("database_operation")
	}
	before, err := captureDatabaseFiles(root)
	if err != nil {
		return err
	}
	if err := operation(); err != nil {
		return errors.New("database_operation")
	}
	after, err := captureDatabaseFiles(root)
	if err != nil || !reflect.DeepEqual(before, after) {
		return errors.New("database_changed")
	}
	return nil
}

// captureDatabase validates candidate stability around the large database hash.
func captureDatabase(root string, scanTime time.Time) (guardedDatabase, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return guardedDatabase{}, errors.New("database_root")
	}
	tool, err := loadTool(absoluteRoot)
	if err != nil {
		return guardedDatabase{}, err
	}
	candidateBefore, err := candidateIdentity(absoluteRoot)
	if err != nil {
		return guardedDatabase{}, err
	}
	files, err := captureDatabaseFiles(absoluteRoot)
	if err != nil {
		return guardedDatabase{}, err
	}
	if err := validateMetadataAt(files.metadataValue, scanTime); err != nil {
		return guardedDatabase{}, err
	}
	candidateAfter, err := candidateIdentity(absoluteRoot)
	if err != nil || candidateBefore != candidateAfter {
		return guardedDatabase{}, errors.New("database_candidate_changed")
	}
	portable := portableDatabaseSnapshot(candidateBefore, tool, files, scanTime)
	return guardedDatabase{
		portable: portable,
		metadata: files.metadata,
		database: files.database,
	}, nil
}

// portableDatabaseSnapshot projects only cross-host database release identity.
func portableDatabaseSnapshot(
	candidate string,
	tool toolIdentity,
	files guardedFiles,
	scanTime time.Time,
) databaseSnapshot {
	metadata := files.metadataValue
	portable := databaseSnapshot{
		Schema:                  "dkim2-trivy-database-inventory-v1",
		CandidateSnapshotSHA256: candidate,
		ScanTime:                scanTime.UTC().Format(time.RFC3339),
		Tool:                    tool,
	}
	portable.VulnerabilityDatabase.SchemaVersion = metadata.Version
	portable.VulnerabilityDatabase.NextUpdate = metadata.NextUpdate
	portable.VulnerabilityDatabase.UpdatedAt = metadata.UpdatedAt
	portable.VulnerabilityDatabase.DownloadedAt = metadata.DownloadedAt
	portable.VulnerabilityDatabase.MaximumDatabaseBytes = maximumDatabaseBytes
	portable.VulnerabilityDatabase.Files = []portableFile{
		{
			Path: "db/metadata.json",
			Size: files.metadata.Size, SHA256: files.metadata.SHA256,
		},
		{Path: "db/trivy.db", Size: files.database.Size, SHA256: files.database.SHA256},
	}
	return portable
}

// candidateIdentity produces one exact repository candidate identifier.
func candidateIdentity(root string) (string, error) {
	revision, err := conformance.CurrentRevision(root)
	if err != nil {
		return "", errors.New("database_candidate")
	}
	candidate, err := conformance.ProduceSnapshot(root, revision)
	if err != nil {
		return "", errors.New("database_candidate")
	}
	return candidate.SHA256, nil
}

// captureDatabaseFiles binds metadata before and after the database hash interval.
func captureDatabaseFiles(root string) (guardedFiles, error) {
	metadataContent, metadataBefore, err := captureMetadata(root)
	if err != nil {
		return guardedFiles{}, err
	}
	database, err := artifactpath.SnapshotFile(
		root,
		databasePath,
		maximumDatabaseBytes,
	)
	if err != nil {
		return guardedFiles{}, errors.New("database_content")
	}
	metadataAfterContent, metadataAfter, err := captureMetadata(root)
	if err != nil ||
		!reflect.DeepEqual(metadataBefore, metadataAfter) ||
		!reflect.DeepEqual(metadataContent, metadataAfterContent) {
		return guardedFiles{}, errors.New("database_metadata_changed")
	}
	metadata, err := parseMetadata(metadataContent)
	if err != nil {
		return guardedFiles{}, err
	}
	return guardedFiles{
		metadataValue: metadata,
		metadata:      metadataBefore,
		database:      database,
	}, nil
}

// captureMetadata returns stable metadata content and private descriptor identity.
func captureMetadata(root string) ([]byte, artifactpath.FileSnapshot, error) {
	content, err := artifactpath.ReadFile(root, metadataPath, maximumMetadataBytes)
	if err != nil {
		return nil, artifactpath.FileSnapshot{}, errors.New("database_metadata")
	}
	snapshot, err := artifactpath.SnapshotFile(root, metadataPath, maximumMetadataBytes)
	if err != nil {
		return nil, artifactpath.FileSnapshot{}, errors.New("database_metadata")
	}
	sum := sha256.Sum256(content)
	if snapshot.SHA256 != hex.EncodeToString(sum[:]) {
		return nil, artifactpath.FileSnapshot{}, errors.New("database_metadata_changed")
	}
	return content, snapshot, nil
}

// parseMetadata validates the closed Trivy database metadata contract.
func parseMetadata(content []byte) (databaseMetadata, error) {
	var metadata databaseMetadata
	if strictjson.Decode(content, &metadata, 8, 128) != nil ||
		metadata.Version != 2 {
		return databaseMetadata{}, errors.New("database_metadata")
	}
	updatedAt, updatedErr := time.Parse(time.RFC3339Nano, metadata.UpdatedAt)
	nextUpdate, nextErr := time.Parse(time.RFC3339Nano, metadata.NextUpdate)
	downloadedAt, downloadedErr := time.Parse(time.RFC3339Nano, metadata.DownloadedAt)
	if updatedErr != nil || nextErr != nil || downloadedErr != nil ||
		!nextUpdate.After(updatedAt) || downloadedAt.Before(updatedAt) {
		return databaseMetadata{}, errors.New("database_metadata")
	}
	return metadata, nil
}

// parseScanTime accepts one current whole-second UTC time controlled by the scan cycle.
func parseScanTime(value string, current time.Time) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, errors.New("database_time")
	}
	delta := current.UTC().Sub(parsed)
	if delta < -maximumClockSkew || delta > maximumClockSkew {
		return time.Time{}, errors.New("database_time")
	}
	return parsed, nil
}

// validateMetadataAt rejects expired, stale, or implausibly future database metadata.
func validateMetadataAt(metadata databaseMetadata, scanTime time.Time) error {
	updatedAt, updatedErr := time.Parse(time.RFC3339Nano, metadata.UpdatedAt)
	nextUpdate, nextErr := time.Parse(time.RFC3339Nano, metadata.NextUpdate)
	downloadedAt, downloadedErr := time.Parse(time.RFC3339Nano, metadata.DownloadedAt)
	if scanTime.IsZero() || updatedErr != nil || nextErr != nil || downloadedErr != nil {
		return errors.New("database_time")
	}
	now := scanTime.UTC()
	if updatedAt.After(now.Add(maximumClockSkew)) ||
		downloadedAt.After(now.Add(maximumClockSkew)) ||
		downloadedAt.Before(updatedAt) ||
		!downloadedAt.Before(nextUpdate) ||
		!nextUpdate.After(now) ||
		now.Sub(updatedAt) > maximumDatabaseAge {
		return errors.New("database_time")
	}
	return nil
}

// loadTool binds executable and identity bytes to the durable current-host allowlist.
func loadTool(root string) (toolIdentity, error) {
	identityContent, err := artifactpath.ReadFile(root, trivyIdentityPath, 16<<10)
	if err != nil {
		return toolIdentity{}, errors.New("database_tool")
	}
	var identity toolIdentity
	if strictjson.Decode(identityContent, &identity, 8, 128) != nil ||
		identity.Schema != "dkim2-image-tool-v1" ||
		identity.Name != "trivy" || identity.Version == "" ||
		len(identity.Version) > 32 {
		return toolIdentity{}, errors.New("database_tool")
	}
	allowlistContent, err := artifactpath.ReadFile(root, toolAllowlistPath, 64<<10)
	if err != nil {
		return toolIdentity{}, errors.New("database_tool")
	}
	var allowlist toolAllowlist
	if strictjson.Decode(allowlistContent, &allowlist, 16, 1024) != nil ||
		allowlist.Schema != "dkim2-image-tool-allowlist-v1" {
		return toolIdentity{}, errors.New("database_tool")
	}
	matches := 0
	for _, tool := range allowlist.Tools {
		if tool.Name != identity.Name || tool.Version != identity.Version {
			continue
		}
		for _, platform := range tool.Platforms {
			if platform.GOOS == runtime.GOOS && platform.GOARCH == runtime.GOARCH &&
				platform.Asset == identity.Asset &&
				platform.ArchiveSHA256 == identity.ArchiveSHA256 &&
				platform.BinarySHA256 == identity.BinarySHA256 {
				matches++
			}
		}
	}
	scanner, err := artifactpath.SnapshotFile(root, trivyPath, maximumScannerBytes)
	if err != nil || matches != 1 || scanner.SHA256 != identity.BinarySHA256 {
		return toolIdentity{}, errors.New("database_tool")
	}
	return identity, nil
}

// confinedWorkRelative applies a closed lexical work-tree policy.
func confinedWorkRelative(relative string, requireDirectory bool) (string, string, error) {
	if relative == "" || filepath.IsAbs(relative) ||
		strings.ContainsRune(relative, '\x00') {
		return "", "", errors.New("database_path")
	}
	cleaned := filepath.Clean(relative)
	parts := strings.Split(cleaned, string(filepath.Separator))
	if len(parts) < 3 || parts[0] != ".artifacts" ||
		!strings.HasPrefix(parts[1], ".image-evidence-work.") ||
		parts[1] == ".image-evidence-work." {
		return "", "", errors.New("database_path")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", "", errors.New("database_path")
		}
	}
	if !requireDirectory && len(parts) != 3 {
		return "", "", errors.New("database_path")
	}
	return cleaned, filepath.Join(parts[0], parts[1]), nil
}

// Write writes up to the fixed scanner-report limit without buffering content.
func (writer *boundedWriter) Write(content []byte) (int, error) {
	if writer == nil || writer.destination == nil || writer.remaining < 0 {
		return 0, errors.New("database_output")
	}
	if int64(len(content)) > writer.remaining {
		return 0, errors.New("database_output_limit")
	}
	written, err := writer.destination.Write(content)
	writer.remaining -= int64(written)
	return written, err
}

// fail emits one fixed content-free database failure.
func fail() {
	fmt.Fprintln(os.Stderr, "scanner database rejected")
	os.Exit(1)
}
