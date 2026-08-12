//nolint:goconst // Independent evidence negatives intentionally repeat exact artifact literals.
package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestWriteImageReleaseReportsUsesRepositoryRelativeArtifacts freezes safe path resolution.
func TestWriteImageReleaseReportsUsesRepositoryRelativeArtifacts(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, evidenceDirectory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	product := "dkim2d"
	paths := []string{
		"runtime-policy.json",
		"trivy-database.json",
		product + ".oci.json",
		product + ".provenance.json",
		product + ".amd64.sbom-binding.json",
		product + ".arm64.sbom-binding.json",
		product + ".amd64.trivy-binding.json",
		product + ".arm64.trivy-binding.json",
	}
	for _, name := range paths {
		if err := os.WriteFile(
			filepath.Join(directory, name),
			[]byte(name),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	revision := strings.Repeat("1", 40)
	candidate := strings.Repeat("2", 64)
	if err := writeImageReleaseReports(
		root,
		revision,
		candidate,
		[]string{product},
	); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(directory, product+".release.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report imageReleaseReport
	if err := json.Unmarshal(content, &report); err != nil {
		t.Fatal(err)
	}
	if report.Schema != "dkim2-image-release-report-v1" ||
		report.BaseRevision != revision ||
		report.CandidateSnapshotSHA256 != candidate ||
		report.Product != product ||
		report.State != "pass" ||
		len(report.SBOMBindings) != 2 ||
		len(report.VulnerabilityBindings) != 2 {
		t.Fatalf("unexpected release report: %#v", report)
	}
}

// TestLoadToolRejectsJointBinaryAndIdentitySubstitution freezes the durable allowlist authority.
func TestLoadToolRejectsJointBinaryAndIdentitySubstitution(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("tool allowlist supports release hosts only")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("tool allowlist supports release hosts only")
	}
	root := t.TempDir()
	for _, directory := range []string{
		filepath.Join(root, "build", "container"),
		filepath.Join(root, ".artifacts", "image-tools"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	binary := []byte("reviewed")
	binarySum := sha256.Sum256(binary)
	reviewedSHA := hex.EncodeToString(binarySum[:])
	allowlist := toolAllowlist{
		Schema: "dkim2-image-tool-allowlist-v1",
		Tools: []reviewedTool{
			{Name: "syft", Version: "1.46.0"},
			{Name: "trivy", Version: "0.72.0"},
		},
	}
	for toolIndex := range allowlist.Tools {
		for _, platform := range []reviewedToolPlatform{
			{GOOS: "darwin", GOARCH: "amd64"},
			{GOOS: "darwin", GOARCH: "arm64"},
			{GOOS: "linux", GOARCH: "amd64"},
			{GOOS: "linux", GOARCH: "arm64"},
		} {
			platform.Asset = allowlist.Tools[toolIndex].Name + "-" +
				platform.GOOS + "-" + platform.GOARCH + ".tar.gz"
			platform.ArchiveSHA256 = strings.Repeat("7", 64)
			platform.BinarySHA256 = strings.Repeat("8", 64)
			if toolIndex == 0 && platform.GOOS == runtime.GOOS &&
				platform.GOARCH == runtime.GOARCH {
				platform.BinarySHA256 = reviewedSHA
			}
			allowlist.Tools[toolIndex].Platforms = append(
				allowlist.Tools[toolIndex].Platforms,
				platform,
			)
		}
	}
	allowlistContent, err := json.Marshal(allowlist)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(root, toolAllowlistPath),
		allowlistContent,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	toolPath := filepath.Join(root, toolDirectory, "syft")
	if err := os.WriteFile(toolPath, binary, 0o500); err != nil {
		t.Fatal(err)
	}
	reviewed, err := loadReviewedTool(
		root,
		"syft",
		runtime.GOOS,
		runtime.GOARCH,
	)
	if err != nil {
		t.Fatal(err)
	}
	identity := toolIdentity{
		Schema:        "dkim2-image-tool-v1",
		Name:          "syft",
		Version:       reviewed.Version,
		Asset:         reviewed.Platform.Asset,
		ArchiveSHA256: reviewed.Platform.ArchiveSHA256,
		BinarySHA256:  reviewed.Platform.BinarySHA256,
	}
	writeToolIdentity(t, root, identity)
	if _, err := loadTool(root, "syft"); err != nil {
		t.Fatal(err)
	}
	substituted := []byte("substituted")
	substitutedSum := sha256.Sum256(substituted)
	if err := os.Chmod(toolPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(toolPath, substituted, 0o500); err != nil {
		t.Fatal(err)
	}
	identity.BinarySHA256 = hex.EncodeToString(substitutedSum[:])
	writeToolIdentity(t, root, identity)
	if _, err := loadTool(root, "syft"); err == nil {
		t.Fatal("joint binary and identity substitution was accepted")
	}
}

// TestLoadOCIReportRejectsClosedMetadataAndPlatformVersionDrift freezes report authority.
func TestLoadOCIReportRejectsClosedMetadataAndPlatformVersionDrift(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, evidenceDirectory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	revision := strings.Repeat("1", 40)
	report := testOCIReport(revision, "v1.2.3")
	writeReport := func() {
		t.Helper()
		content, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(directory, "dkim2d.oci.json"),
			content,
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	writeReport()
	if _, err := loadOCIReport(root, "dkim2d", revision); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOCIReport(root, "dkim2d", strings.Repeat("9", 40)); err == nil {
		t.Fatal("stale OCI report revision was accepted")
	}
	report.Platforms[0].Labels["unexpected"] = "value"
	writeReport()
	if _, err := loadOCIReport(root, "dkim2d", revision); err == nil {
		t.Fatal("extra OCI label was accepted")
	}
	report = testOCIReport(revision, "v1.2.3")
	report.Platforms[0].Files[1].Mode = 0o644
	writeReport()
	if _, err := loadOCIReport(root, "dkim2d", revision); err == nil {
		t.Fatal("writable public notice was accepted")
	}
	report = testOCIReport(revision, "v1.2.3")
	report.Platforms[1].Version = "v1.2.4"
	report.Platforms[1].Labels["org.opencontainers.image.version"] = "v1.2.4"
	writeReport()
	if _, err := loadOCIReport(root, "dkim2d", revision); err == nil {
		t.Fatal("platform version drift was accepted")
	}
}

// testOCIReport returns one exact normalized daemon report fixture.
func testOCIReport(revision string, version string) ociReport {
	created := "1970-01-01T00:00:00Z"
	report := ociReport{
		Schema:        "dkim2-oci-policy-v1",
		Product:       "dkim2d",
		SubjectDigest: "sha256:" + strings.Repeat("2", 64),
	}
	for index, architecture := range []string{"amd64", "arm64"} {
		digit := fmt.Sprintf("%x", index+3)
		labels := map[string]string{
			"org.opencontainers.image.source":        "https://github.com/croessner/dkim2",
			"org.opencontainers.image.revision":      revision,
			"org.opencontainers.image.version":       version,
			"org.opencontainers.image.created":       created,
			"org.opencontainers.image.vendor":        "DKIM2 reference implementation",
			"org.opencontainers.image.documentation": "https://github.com/croessner/dkim2/tree/main/docs/operator",
			"org.opencontainers.image.licenses":      "Apache-2.0",
			"org.opencontainers.image.title":         "dkim2d",
			"org.opencontainers.image.description":   "Loopback-only DKIM2 processing daemon",
		}
		report.Platforms = append(report.Platforms, ociPlatformReport{
			Platform:       "linux/" + architecture,
			ManifestDigest: "sha256:" + strings.Repeat(digit, 64),
			ConfigDigest:   "sha256:" + strings.Repeat(fmt.Sprintf("%x", index+5), 64),
			LayerDigest:    "sha256:" + strings.Repeat(fmt.Sprintf("%x", index+7), 64),
			DiffIDDigest:   "sha256:" + strings.Repeat(fmt.Sprintf("%x", index+9), 64),
			User:           "2000:2000",
			Entrypoint:     []string{"/usr/local/bin/dkim2d"},
			Labels:         labels,
			Created:        created,
			Revision:       revision,
			Version:        version,
			Healthcheck: &ociHealthcheck{
				Test:     []string{"CMD", "/usr/local/bin/dkim2d", "probe"},
				Interval: int64(10 * time.Second),
				Timeout:  int64(3 * time.Second),
				Retries:  3,
			},
			Files: []ociFileReport{
				{
					Path:     "/usr/local/bin/dkim2d",
					Mode:     0o555,
					Size:     1024,
					SHA256:   strings.Repeat("a", 64),
					Typeflag: tar.TypeReg,
					Build: binaryBuildInfo{
						GoVersion: "go1.26.5",
						Main: moduleBuildInfo{
							Path:    "github.com/croessner/dkim2/cmd/dkim2d",
							Version: "(devel)",
						},
						GOOS: "linux", GOARCH: architecture,
						CGO: "0", Trimpath: "true",
					},
				},
				{
					Path: "/usr/share/licenses/dkim2/THIRD_PARTY_NOTICES.txt",
					Mode: 0o444, Size: 4096, SHA256: strings.Repeat("b", 64),
					Typeflag: tar.TypeReg,
				},
				{
					Path: "/usr/share/licenses/dkim2/LICENSE",
					Mode: 0o444, Size: 1024, SHA256: strings.Repeat("c", 64),
					Typeflag: tar.TypeReg,
				},
			},
		})
	}
	return report
}

// TestValidateSBOMRejectsTamperStaleCandidateAndWrongTool freezes exact bindings.
func TestValidateSBOMRejectsTamperStaleCandidateAndWrongTool(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, evidenceDirectory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	subject := "sha256:" + strings.Repeat("a", 64)
	candidate := strings.Repeat("b", 64)
	binary := strings.Repeat("f", 64)
	version := "0.0.0-dev"
	build := binaryBuildInfo{
		GoVersion: "go1.26.5",
		Main: moduleBuildInfo{
			Path:    "github.com/croessner/dkim2/cmd/dkim2d",
			Version: "(devel)",
		},
		GOOS:     "linux",
		GOARCH:   "amd64",
		CGO:      "0",
		Trimpath: "true",
	}
	document := []byte(fmt.Sprintf(
		`{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"dkim2d@%s","documentNamespace":"https://github.com/croessner/dkim2/sbom/%s","creationInfo":{"created":"1970-01-01T00:00:00Z","creators":["Organization: Anchore, Inc","Tool: syft-1.46.0"],"licenseListVersion":"3.28"},"packages":[{"SPDXID":"SPDXRef-Root","name":"dkim2d@%s","versionInfo":"%s","licenseConcluded":"NOASSERTION","licenseDeclared":"NOASSERTION","downloadLocation":"NOASSERTION","filesAnalyzed":false,"copyrightText":"NOASSERTION","supplier":"NOASSERTION","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceLocator":"pkg:oci/dkim2d","referenceType":"purl"}]},{"SPDXID":"SPDXRef-Module","name":"github.com/croessner/dkim2/cmd/dkim2d","versionInfo":"UNKNOWN","licenseConcluded":"NOASSERTION","licenseDeclared":"NOASSERTION","downloadLocation":"NOASSERTION","filesAnalyzed":false,"copyrightText":"NOASSERTION","supplier":"NOASSERTION","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceLocator":"pkg:golang/github.com/croessner/dkim2/cmd/dkim2d","referenceType":"purl"}]},{"SPDXID":"SPDXRef-Stdlib","name":"stdlib","versionInfo":"go1.26.5","licenseConcluded":"NOASSERTION","licenseDeclared":"NOASSERTION","downloadLocation":"NOASSERTION","filesAnalyzed":false,"copyrightText":"NOASSERTION","supplier":"NOASSERTION","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceLocator":"pkg:golang/stdlib@go1.26.5","referenceType":"purl"}]}],"files":[{"SPDXID":"SPDXRef-Binary","fileName":"usr/local/bin/dkim2d","fileTypes":["APPLICATION","BINARY"],"checksums":[{"algorithm":"SHA256","checksumValue":"%s"}],"licenseConcluded":"NOASSERTION","licenseInfoInFiles":["NOASSERTION"],"copyrightText":"NOASSERTION","comment":""}],"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-Root"},{"spdxElementId":"SPDXRef-Root","relationshipType":"CONTAINS","relatedSpdxElement":"SPDXRef-Module"},{"spdxElementId":"SPDXRef-Root","relationshipType":"CONTAINS","relatedSpdxElement":"SPDXRef-Stdlib"},{"spdxElementId":"SPDXRef-Root","relationshipType":"CONTAINS","relatedSpdxElement":"SPDXRef-Binary"}]}`,
		subject,
		strings.TrimPrefix(subject, "sha256:"),
		subject,
		version,
		binary,
	))
	documentPath := filepath.Join(directory, "dkim2d.amd64.spdx.json")
	if err := os.WriteFile(documentPath, document, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(document)
	tool := testToolIdentity("syft", "1.46.0")
	writeSBOMBinding(t, directory, candidate, subject, hex.EncodeToString(sum[:]), tool)
	if err := validateSBOM(
		root, "dkim2d", "amd64", "linux/amd64", subject, binary,
		version, build, candidate, tool,
	); err != nil {
		t.Fatal(err)
	}
	if err := validateSBOM(
		root,
		"dkim2d",
		"amd64",
		"linux/amd64",
		subject,
		strings.Repeat("0", 64),
		version,
		build,
		candidate,
		tool,
	); err == nil {
		t.Fatal("unexpected binary inventory was accepted")
	}
	var unexpectedDocument spdxDocument
	if err := json.Unmarshal(document, &unexpectedDocument); err != nil {
		t.Fatal(err)
	}
	unexpectedDocument.Packages = append(unexpectedDocument.Packages, spdxPackage{
		SPDXID:           "SPDXRef-Unexpected",
		Name:             "example.invalid/unexpected",
		VersionInfo:      "v1.0.0",
		LicenseConcluded: "NOASSERTION",
		LicenseDeclared:  "NOASSERTION",
		DownloadLocation: "NOASSERTION",
		CopyrightText:    "NOASSERTION",
		Supplier:         "NOASSERTION",
		ExternalRefs: []spdxExternalReference{{
			ReferenceCategory: "PACKAGE-MANAGER",
			ReferenceLocator:  "pkg:golang/example.invalid/unexpected@v1.0.0",
			ReferenceType:     "purl",
		}},
	})
	unexpectedPackage, err := json.Marshal(unexpectedDocument)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(documentPath, unexpectedPackage, 0o600); err != nil {
		t.Fatal(err)
	}
	unexpectedSum := sha256.Sum256(unexpectedPackage)
	writeSBOMBinding(
		t,
		directory,
		candidate,
		subject,
		hex.EncodeToString(unexpectedSum[:]),
		tool,
	)
	if err := validateSBOM(
		root, "dkim2d", "amd64", "linux/amd64", subject, binary,
		version, build, candidate, tool,
	); err == nil {
		t.Fatal("unexpected package inventory was accepted")
	}
	if err := os.WriteFile(documentPath, document, 0o600); err != nil {
		t.Fatal(err)
	}
	writeSBOMBinding(t, directory, candidate, subject, strings.Repeat("c", 64), tool)
	if err := validateSBOM(
		root, "dkim2d", "amd64", "linux/amd64", subject, binary,
		version, build, candidate, tool,
	); err == nil {
		t.Fatal("tampered SBOM hash was accepted")
	}
	writeSBOMBinding(t, directory, strings.Repeat("d", 64), subject, hex.EncodeToString(sum[:]), tool)
	if err := validateSBOM(
		root, "dkim2d", "amd64", "linux/amd64", subject, binary,
		version, build, candidate, tool,
	); err == nil {
		t.Fatal("stale candidate was accepted")
	}
	wrongTool := tool
	wrongTool.BinarySHA256 = strings.Repeat("e", 64)
	writeSBOMBinding(t, directory, candidate, subject, hex.EncodeToString(sum[:]), wrongTool)
	if err := validateSBOM(
		root, "dkim2d", "amd64", "linux/amd64", subject, binary,
		version, build, candidate, tool,
	); err == nil {
		t.Fatal("wrong tool was accepted")
	}
}

// TestConsistentOCIVersionAcceptsReleaseAndRejectsPlatformDrift freezes SBOM version authority.
func TestConsistentOCIVersionAcceptsReleaseAndRejectsPlatformDrift(t *testing.T) {
	report := ociReport{Platforms: []ociPlatformReport{
		{Platform: "linux/amd64", Version: "v1.2.3"},
		{Platform: "linux/arm64", Version: "v1.2.3"},
	}}
	version, err := consistentOCIVersion(report)
	if err != nil || version != "v1.2.3" {
		t.Fatalf("release version rejected: version=%q err=%v", version, err)
	}
	report.Platforms[1].Version = "v1.2.4"
	if _, err := consistentOCIVersion(report); err == nil {
		t.Fatal("platform version drift was accepted")
	}
	report.Platforms[1].Version = "v01.2.3"
	if _, err := consistentOCIVersion(report); err == nil {
		t.Fatal("invalid platform version was accepted")
	}
}

// TestValidateProvenanceRejectsAuthorityAndWrongDescriptor freezes release separation.
func TestValidateProvenanceRejectsAuthorityAndWrongDescriptor(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, evidenceDirectory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	writeBuildInputPolicy(t, root)
	revision := strings.Repeat("1", 40)
	candidate := strings.Repeat("2", 64)
	report := ociReport{
		Schema:        "dkim2-oci-policy-v1",
		Product:       "dkim2d",
		SubjectDigest: "sha256:" + strings.Repeat("3", 64),
	}
	report.Platforms = append(report.Platforms,
		ociPlatformReport{Platform: "linux/amd64", ManifestDigest: "sha256:" + strings.Repeat("4", 64)},
		ociPlatformReport{Platform: "linux/arm64", ManifestDigest: "sha256:" + strings.Repeat("5", 64)},
	)
	writeProvenance(t, directory, revision, candidate, report, false, strings.Repeat("5", 64))
	if err := validateProvenance(root, "dkim2d", revision, candidate, report); err != nil {
		t.Fatal(err)
	}
	writeProvenance(t, directory, revision, candidate, report, true, strings.Repeat("5", 64))
	if err := validateProvenance(root, "dkim2d", revision, candidate, report); err == nil {
		t.Fatal("publication-authoritative local statement was accepted")
	}
	writeProvenance(t, directory, revision, candidate, report, false, strings.Repeat("6", 64))
	if err := validateProvenance(root, "dkim2d", revision, candidate, report); err == nil {
		t.Fatal("wrong platform subject was accepted")
	}
	writeProvenance(t, directory, revision, candidate, report, false, strings.Repeat("5", 64))
	provenancePath := filepath.Join(directory, "dkim2d.provenance.json")
	content, err := os.ReadFile(provenancePath)
	if err != nil {
		t.Fatal(err)
	}
	wrongBuilder := strings.Replace(
		string(content),
		"0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f",
		strings.Repeat("9", 64),
		1,
	)
	if err := os.WriteFile(provenancePath, []byte(wrongBuilder), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateProvenance(root, "dkim2d", revision, candidate, report); err == nil {
		t.Fatal("wrong BuildKit dependency was accepted")
	}
	wrongPlatforms := strings.Replace(
		string(content),
		`["linux/amd64","linux/arm64"]`,
		`["linux/arm64","linux/amd64"]`,
		1,
	)
	if err := os.WriteFile(provenancePath, []byte(wrongPlatforms), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateProvenance(root, "dkim2d", revision, candidate, report); err == nil {
		t.Fatal("wrong provenance platform order was accepted")
	}
}

// TestValidateTrivyDatabaseRejectsContentAndToolTamper freezes exact DB inventory binding.
func TestValidateTrivyDatabaseRejectsContentAndToolTamper(t *testing.T) {
	tool := testToolIdentity("trivy", "0.72.0")
	candidate := strings.Repeat("8", 64)
	current := time.Date(2026, 7, 28, 16, 0, 0, 0, time.UTC)
	valid := []byte(fmt.Sprintf(
		`{"schema":"dkim2-trivy-database-inventory-v1","candidate_snapshot_sha256":"%s","scan_time":"2026-07-28T16:00:00Z","tool":{"schema":"%s","name":"%s","version":"%s","asset":"%s","archive_sha256":"%s","binary_sha256":"%s"},"vulnerability_database":{"schema_version":2,"next_update":"2026-07-29T13:20:17Z","updated_at":"2026-07-28T13:20:17Z","downloaded_at":"2026-07-28T15:35:54Z","maximum_database_bytes":2147483648,"files":[{"path":"db/metadata.json","size":149,"sha256":"%s"},{"path":"db/trivy.db","size":1224044544,"sha256":"%s"}]}}`,
		candidate,
		tool.Schema,
		tool.Name,
		tool.Version,
		tool.Asset,
		tool.ArchiveSHA256,
		tool.BinarySHA256,
		strings.Repeat("9", 64),
		strings.Repeat("a", 64),
	))
	if _, err := validateTrivyDatabaseAt(valid, tool, candidate, current); err != nil {
		t.Fatal(err)
	}
	wrongTool := tool
	wrongTool.BinarySHA256 = strings.Repeat("b", 64)
	if _, err := validateTrivyDatabaseAt(valid, wrongTool, candidate, current); err == nil {
		t.Fatal("wrong database tool was accepted")
	}
	tampered := strings.Replace(
		string(valid),
		strings.Repeat("a", 64),
		"x"+strings.Repeat("a", 63),
		1,
	)
	if _, err := validateTrivyDatabaseAt(
		[]byte(tampered),
		tool,
		candidate,
		current,
	); err == nil {
		t.Fatal("tampered database content identity was accepted")
	}
	if _, err := validateTrivyDatabaseAt(
		valid,
		tool,
		strings.Repeat("7", 64),
		current,
	); err == nil {
		t.Fatal("wrong database candidate was accepted")
	}
	expired := strings.Replace(
		string(valid),
		"2026-07-29T13:20:17Z",
		"2026-07-28T16:00:00Z",
		1,
	)
	if _, err := validateTrivyDatabaseAt(
		[]byte(expired),
		tool,
		candidate,
		current,
	); err == nil {
		t.Fatal("expired database was accepted")
	}
}

// TestValidateVulnerabilityRejectsDatabaseInventoryTamper freezes report-to-database binding.
func TestValidateVulnerabilityRejectsDatabaseInventoryTamper(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, evidenceDirectory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	subject := "sha256:" + strings.Repeat("a", 64)
	candidate := strings.Repeat("b", 64)
	database := strings.Repeat("c", 64)
	tool := testToolIdentity("trivy", "0.72.0")
	databaseReport := trivyDatabaseReport{}
	databaseReport.ScanTime = "2026-07-28T16:00:00Z"
	databaseReport.VulnerabilityDB.SchemaVersion = 2
	databaseReport.VulnerabilityDB.UpdatedAt = "2026-07-28T13:20:17Z"
	databaseReport.VulnerabilityDB.NextUpdate = "2026-07-29T13:20:17Z"
	databaseReport.VulnerabilityDB.DownloadedAt = "2026-07-28T15:35:54Z"
	databaseReport.VulnerabilityDB.Files = []trivyDatabaseFile{
		{Path: "db/metadata.json", Size: 149, SHA256: strings.Repeat("d", 64)},
		{Path: "db/trivy.db", Size: 1224044544, SHA256: strings.Repeat("e", 64)},
	}
	report := []byte(fmt.Sprintf(
		`{"SchemaVersion":2,"CreatedAt":"1970-01-01T00:00:00Z","ArtifactName":"dkim2d@%s","ArtifactID":"%s","Results":[]}`,
		subject,
		subject,
	))
	if err := os.WriteFile(
		filepath.Join(directory, "dkim2d.amd64.trivy.json"),
		report,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	reportSum := sha256.Sum256(report)
	binding := []byte(fmt.Sprintf(
		`{"schema":"dkim2-image-vulnerability-binding-v1","candidate_snapshot_sha256":"%s","product":"dkim2d","platform":"linux/amd64","subject_digest":"%s","report":{"format":"trivy-json-0.72.0","sha256":"%s"},"database":{"inventory_sha256":"%s","content_sha256":"%s","metadata_sha256":"%s","scan_time":"2026-07-28T16:00:00Z","schema_version":2,"updated_at":"2026-07-28T13:20:17Z","next_update":"2026-07-29T13:20:17Z","downloaded_at":"2026-07-28T15:35:54Z"},"tool":{"schema":"%s","name":"%s","version":"%s","asset":"%s","archive_sha256":"%s","binary_sha256":"%s"}}`,
		candidate,
		subject,
		hex.EncodeToString(reportSum[:]),
		database,
		strings.Repeat("e", 64),
		strings.Repeat("d", 64),
		tool.Schema,
		tool.Name,
		tool.Version,
		tool.Asset,
		tool.ArchiveSHA256,
		tool.BinarySHA256,
	))
	if err := os.WriteFile(
		filepath.Join(directory, "dkim2d.amd64.trivy-binding.json"),
		binding,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := validateVulnerability(
		root,
		"dkim2d",
		"amd64",
		"linux/amd64",
		subject,
		candidate,
		database,
		databaseReport,
		tool,
	); err != nil {
		t.Fatal(err)
	}
	if err := validateVulnerability(
		root,
		"dkim2d",
		"amd64",
		"linux/amd64",
		subject,
		candidate,
		strings.Repeat("d", 64),
		databaseReport,
		tool,
	); err == nil {
		t.Fatal("wrong database inventory was accepted")
	}
	lowReport := []byte(fmt.Sprintf(
		`{"SchemaVersion":2,"CreatedAt":"1970-01-01T00:00:00Z","ArtifactName":"dkim2d@%s","ArtifactID":"%s","Results":[{"Vulnerabilities":[{"Severity":"LOW"}]}]}`,
		subject,
		subject,
	))
	if err := os.WriteFile(
		filepath.Join(directory, "dkim2d.amd64.trivy.json"),
		lowReport,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := validateVulnerability(
		root,
		"dkim2d",
		"amd64",
		"linux/amd64",
		subject,
		candidate,
		database,
		databaseReport,
		tool,
	); err == nil {
		t.Fatal("renamed low-severity finding was accepted")
	}
}

// TestValidateRuntimeEvidenceRejectsStaleSubjectsAndIncompleteLifecycle freezes runtime binding.
func TestValidateRuntimeEvidenceRejectsStaleSubjectsAndIncompleteLifecycle(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, evidenceDirectory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	candidate := strings.Repeat("a", 64)
	subjects := map[string]string{
		"dkim2d":       "sha256:" + strings.Repeat("b", 64),
		"dkim2-milter": "sha256:" + strings.Repeat("c", 64),
		"dkim2ctl":     "sha256:" + strings.Repeat("d", 64),
	}
	reports := make(map[string]ociReport, len(subjects))
	for product, subject := range subjects {
		reports[product] = ociReport{
			Product: product,
			Platforms: []ociPlatformReport{{
				Platform:       "linux/amd64",
				ManifestDigest: subject,
			}},
		}
	}
	writeRuntimeEvidence(t, directory, candidate, subjects, true)
	if err := validateRuntimeEvidence(root, candidate, reports); err != nil {
		t.Fatal(err)
	}
	stale := mapsClone(subjects)
	stale["dkim2ctl"] = "sha256:" + strings.Repeat("e", 64)
	writeRuntimeEvidence(t, directory, candidate, stale, true)
	if err := validateRuntimeEvidence(root, candidate, reports); err == nil {
		t.Fatal("stale runtime subject was accepted")
	}
	writeRuntimeEvidence(t, directory, candidate, subjects, false)
	if err := validateRuntimeEvidence(root, candidate, reports); err == nil {
		t.Fatal("incomplete lifecycle evidence was accepted")
	}
}

// testToolIdentity returns one fixed valid tool fixture.
func testToolIdentity(name string, version string) toolIdentity {
	return toolIdentity{
		Schema:        "dkim2-image-tool-v1",
		Name:          name,
		Version:       version,
		Asset:         name + ".tar.gz",
		ArchiveSHA256: strings.Repeat("7", 64),
		BinarySHA256:  strings.Repeat("8", 64),
	}
}

// writeToolIdentity writes one strict downloaded-tool identity fixture.
func writeToolIdentity(t *testing.T, root string, identity toolIdentity) {
	t.Helper()
	content, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(root, toolDirectory, identity.Name+".identity.json"),
		content,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

// mapsClone returns an independent string map for mutation-oriented tests.
func mapsClone(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

// writeRuntimeEvidence writes one candidate-bound runtime fixture.
func writeRuntimeEvidence(
	t *testing.T,
	directory string,
	candidate string,
	subjects map[string]string,
	complete bool,
) {
	t.Helper()
	content := fmt.Sprintf(
		`{"schema":"dkim2-image-runtime-evidence-v1","candidate_snapshot_sha256":"%s","platform":"linux/amd64","images":[{"product":"dkim2d","platform":"linux/amd64","subject_digest":"%s","user":"2000:2000","read_only":true,"cap_drop":["ALL"],"no_new_privileges":true},{"product":"dkim2-milter","platform":"linux/amd64","subject_digest":"%s","user":"2000:2000","read_only":true,"cap_drop":["ALL"],"no_new_privileges":true},{"product":"dkim2ctl","platform":"linux/amd64","subject_digest":"%s","user":"2000:2000","read_only":true,"cap_drop":["ALL"],"no_new_privileges":true}],"lifecycle":{"daemon_sigterm":true,"daemon_sigint":%t,"milter_sigterm":true,"milter_sigint":true,"restart":true,"writable_socket_volume":true}}`,
		candidate,
		subjects["dkim2d"],
		subjects["dkim2-milter"],
		subjects["dkim2ctl"],
		complete,
	)
	if err := os.WriteFile(
		filepath.Join(directory, "runtime-policy.json"),
		[]byte(content),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

// writeSBOMBinding writes one strict repository-owned binding fixture.
func writeSBOMBinding(
	t *testing.T,
	directory string,
	candidate string,
	subject string,
	hash string,
	tool toolIdentity,
) {
	t.Helper()
	content := fmt.Sprintf(
		`{"schema":"dkim2-image-sbom-binding-v1","candidate_snapshot_sha256":"%s","product":"dkim2d","platform":"linux/amd64","subject_digest":"%s","sbom":{"format":"SPDX-2.3","sha256":"%s"},"tool":{"schema":"%s","name":"%s","version":"%s","asset":"%s","archive_sha256":"%s","binary_sha256":"%s"}}`,
		candidate, subject, hash,
		tool.Schema, tool.Name, tool.Version, tool.Asset, tool.ArchiveSHA256, tool.BinarySHA256,
	)
	if err := os.WriteFile(
		filepath.Join(directory, "dkim2d.amd64.sbom-binding.json"),
		[]byte(content),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

// writeProvenance writes one closed local statement fixture.
func writeProvenance(
	t *testing.T,
	directory string,
	revision string,
	candidate string,
	report ociReport,
	authority bool,
	arm64Digest string,
) {
	t.Helper()
	content := fmt.Sprintf(
		`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"dkim2d","digest":{"sha256":"%s"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"buildType":"https://github.com/croessner/dkim2/container-build/v1","externalParameters":{"platforms":["linux/amd64","linux/arm64"]},"internalParameters":{"candidate_snapshot_sha256":"%s","evidence_class":"local-test","publication_authority":%t},"resolvedDependencies":[{"uri":"git+https://github.com/croessner/dkim2","digest":{"gitCommit":"%s"}},{"uri":"docker-image://docker.io/library/busybox","digest":{"sha256":"%s"}},{"uri":"docker-image://docker.io/library/golang","digest":{"sha256":"%s"}},{"uri":"docker-image://moby/buildkit","digest":{"sha256":"%s"}}]},"runDetails":{"builder":{"id":"local://dkim2/image-evidence"},"metadata":{"invocationId":"local-test"},"byproducts":[{"name":"linux/amd64","digest":{"sha256":"%s"}},{"name":"linux/arm64","digest":{"sha256":"%s"}}]}}}`,
		strings.TrimPrefix(report.SubjectDigest, "sha256:"),
		candidate,
		authority,
		revision,
		"9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028",
		"1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651",
		"0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f",
		strings.TrimPrefix(report.Platforms[0].ManifestDigest, "sha256:"),
		arm64Digest,
	)
	if err := os.WriteFile(
		filepath.Join(directory, "dkim2d.provenance.json"),
		[]byte(content),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

// writeBuildInputPolicy writes the central immutable build-input fixture.
func writeBuildInputPolicy(t *testing.T, root string) {
	t.Helper()
	directory := filepath.Join(root, "build", "container")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	content := `{"schema":"dkim2-container-build-inputs-v1","images":[{"name":"metadata-validator","uri":"docker-image://docker.io/library/busybox","reference":"busybox:1.37.0","digest":"9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028","purpose":"build-only metadata validation"},{"name":"go-builder","uri":"docker-image://docker.io/library/golang","reference":"golang:1.26.5-bookworm","digest":"1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651","purpose":"build-only Go compilation"},{"name":"buildkit","uri":"docker-image://moby/buildkit","reference":"moby/buildkit:buildx-stable-1","digest":"0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f","purpose":"isolated BuildKit executor"}]}`
	if err := os.WriteFile(
		filepath.Join(directory, "build-inputs.json"),
		[]byte(content),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}
