// Command imageevidence validates candidate-bound local image evidence.
//
//nolint:goconst // Evidence validators keep exact schema and platform literals near each check.
package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/croessner/dkim2/tools/internal/artifactpath"
	"github.com/croessner/dkim2/tools/internal/conformance"
	"github.com/croessner/dkim2/tools/internal/strictjson"
)

const (
	evidenceDirectory  = ".artifacts/image-evidence"
	toolDirectory      = ".artifacts/image-tools"
	toolAllowlistPath  = "build/container/image-tools.json"
	buildInputPath     = "build/container/build-inputs.json"
	maximumDBClockSkew = 5 * time.Minute
	maximumDBAge       = 48 * time.Hour
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
	Schema string         `json:"schema"`
	Tools  []reviewedTool `json:"tools"`
}

type reviewedTool struct {
	Name      string                 `json:"name"`
	Version   string                 `json:"version"`
	Platforms []reviewedToolPlatform `json:"platforms"`
}

type reviewedToolPlatform struct {
	GOOS          string `json:"goos"`
	GOARCH        string `json:"goarch"`
	Asset         string `json:"asset"`
	ArchiveSHA256 string `json:"archive_sha256"`
	BinarySHA256  string `json:"binary_sha256"`
}

type reviewedToolSelection struct {
	Version  string
	Platform reviewedToolPlatform
}

type buildInputPolicy struct {
	Schema string               `json:"schema"`
	Images []reviewedBuildImage `json:"images"`
}

type reviewedBuildImage struct {
	Name      string `json:"name"`
	URI       string `json:"uri"`
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
	Purpose   string `json:"purpose"`
}

type ociReport struct {
	Schema        string              `json:"schema"`
	Product       string              `json:"product"`
	SubjectDigest string              `json:"subject_digest"`
	Platforms     []ociPlatformReport `json:"platforms"`
}

type ociPlatformReport struct {
	Platform       string            `json:"platform"`
	ManifestDigest string            `json:"manifest_digest"`
	ConfigDigest   string            `json:"config_digest"`
	LayerDigest    string            `json:"layer_digest"`
	DiffIDDigest   string            `json:"diff_id_digest"`
	User           string            `json:"user"`
	Entrypoint     []string          `json:"entrypoint"`
	Labels         map[string]string `json:"labels"`
	Created        string            `json:"created"`
	Revision       string            `json:"revision"`
	Version        string            `json:"version"`
	Healthcheck    *ociHealthcheck   `json:"healthcheck,omitempty"`
	Files          []ociFileReport   `json:"files"`
}

type ociFileReport struct {
	Path     string          `json:"path"`
	Mode     int64           `json:"mode"`
	UID      int             `json:"uid"`
	GID      int             `json:"gid"`
	Size     int64           `json:"size"`
	SHA256   string          `json:"sha256"`
	Typeflag byte            `json:"typeflag"`
	Build    binaryBuildInfo `json:"build"`
}

type ociHealthcheck struct {
	Test          []string `json:"Test"`
	Interval      int64    `json:"Interval,omitempty"`
	Timeout       int64    `json:"Timeout,omitempty"`
	StartPeriod   int64    `json:"StartPeriod,omitempty"`
	StartInterval int64    `json:"StartInterval,omitempty"`
	Retries       int      `json:"Retries,omitempty"`
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

type artifactBinding struct {
	Format string `json:"format"`
	SHA256 string `json:"sha256"`
}

type sbomBinding struct {
	Schema                  string          `json:"schema"`
	CandidateSnapshotSHA256 string          `json:"candidate_snapshot_sha256"`
	Product                 string          `json:"product"`
	Platform                string          `json:"platform"`
	SubjectDigest           string          `json:"subject_digest"`
	SBOM                    artifactBinding `json:"sbom"`
	Tool                    toolIdentity    `json:"tool"`
}

type vulnerabilityBinding struct {
	Schema                  string          `json:"schema"`
	CandidateSnapshotSHA256 string          `json:"candidate_snapshot_sha256"`
	Product                 string          `json:"product"`
	Platform                string          `json:"platform"`
	SubjectDigest           string          `json:"subject_digest"`
	Report                  artifactBinding `json:"report"`
	Database                struct {
		InventorySHA256 string `json:"inventory_sha256"`
		ContentSHA256   string `json:"content_sha256"`
		MetadataSHA256  string `json:"metadata_sha256"`
		ScanTime        string `json:"scan_time"`
		SchemaVersion   int    `json:"schema_version"`
		UpdatedAt       string `json:"updated_at"`
		NextUpdate      string `json:"next_update"`
		DownloadedAt    string `json:"downloaded_at"`
	} `json:"database"`
	Tool toolIdentity `json:"tool"`
}

type provenanceStatement struct {
	Type    string `json:"_type"`
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string `json:"predicateType"`
	Predicate     struct {
		BuildDefinition struct {
			BuildType          string `json:"buildType"`
			ExternalParameters struct {
				Platforms []string `json:"platforms"`
			} `json:"externalParameters"`
			InternalParameters struct {
				CandidateSnapshotSHA256 string `json:"candidate_snapshot_sha256"`
				EvidenceClass           string `json:"evidence_class"`
				PublicationAuthority    bool   `json:"publication_authority"`
			} `json:"internalParameters"`
			ResolvedDependencies []struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"resolvedDependencies"`
		} `json:"buildDefinition"`
		RunDetails struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
			Metadata struct {
				InvocationID string `json:"invocationId"`
			} `json:"metadata"`
			Byproducts []struct {
				Name   string            `json:"name"`
				Digest map[string]string `json:"digest"`
			} `json:"byproducts"`
		} `json:"runDetails"`
	} `json:"predicate"`
}

type releaseArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type imageReleaseReport struct {
	Schema                  string            `json:"schema"`
	BaseRevision            string            `json:"base_revision"`
	CandidateSnapshotSHA256 string            `json:"candidate_snapshot_sha256"`
	Product                 string            `json:"product"`
	OCI                     releaseArtifact   `json:"oci"`
	Provenance              releaseArtifact   `json:"provenance"`
	RuntimePolicy           releaseArtifact   `json:"runtime_policy"`
	VulnerabilityDatabase   releaseArtifact   `json:"vulnerability_database"`
	SBOMBindings            []releaseArtifact `json:"sbom_bindings"`
	VulnerabilityBindings   []releaseArtifact `json:"vulnerability_bindings"`
	State                   string            `json:"state"`
}

type spdxDocument struct {
	SPDXVersion       string `json:"spdxVersion"`
	DataLicense       string `json:"dataLicense"`
	SPDXID            string `json:"SPDXID"`
	Name              string `json:"name"`
	DocumentNamespace string `json:"documentNamespace"`
	CreationInfo      struct {
		Created            string   `json:"created"`
		Creators           []string `json:"creators"`
		LicenseListVersion string   `json:"licenseListVersion"`
	} `json:"creationInfo"`
	Packages      []spdxPackage      `json:"packages"`
	Files         []spdxFile         `json:"files"`
	Relationships []spdxRelationship `json:"relationships"`
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxExternalReference struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceLocator  string `json:"referenceLocator"`
	ReferenceType     string `json:"referenceType"`
}

type spdxPackage struct {
	SPDXID                string                  `json:"SPDXID"`
	Name                  string                  `json:"name"`
	VersionInfo           string                  `json:"versionInfo"`
	LicenseConcluded      string                  `json:"licenseConcluded"`
	LicenseDeclared       string                  `json:"licenseDeclared"`
	DownloadLocation      string                  `json:"downloadLocation"`
	FilesAnalyzed         bool                    `json:"filesAnalyzed"`
	CopyrightText         string                  `json:"copyrightText"`
	Supplier              string                  `json:"supplier"`
	PrimaryPackagePurpose string                  `json:"primaryPackagePurpose,omitempty"`
	SourceInfo            string                  `json:"sourceInfo,omitempty"`
	Checksums             []spdxChecksum          `json:"checksums,omitempty"`
	ExternalRefs          []spdxExternalReference `json:"externalRefs"`
}

type spdxFile struct {
	SPDXID            string         `json:"SPDXID"`
	FileName          string         `json:"fileName"`
	FileTypes         []string       `json:"fileTypes"`
	Checksums         []spdxChecksum `json:"checksums"`
	LicenseConcluded  string         `json:"licenseConcluded"`
	LicenseInfoInFile []string       `json:"licenseInfoInFiles"`
	CopyrightText     string         `json:"copyrightText"`
	Comment           string         `json:"comment"`
}

type spdxRelationship struct {
	ElementID      string `json:"spdxElementId"`
	Relationship   string `json:"relationshipType"`
	RelatedElement string `json:"relatedSpdxElement"`
	Comment        string `json:"comment,omitempty"`
}

type trivyReport struct {
	SchemaVersion int    `json:"SchemaVersion"`
	CreatedAt     string `json:"CreatedAt"`
	ArtifactName  string `json:"ArtifactName"`
	ArtifactID    string `json:"ArtifactID"`
	Results       []struct {
		Vulnerabilities []struct {
			Severity string `json:"Severity"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

type trivyDatabaseReport struct {
	Schema                  string       `json:"schema"`
	CandidateSnapshotSHA256 string       `json:"candidate_snapshot_sha256"`
	ScanTime                string       `json:"scan_time"`
	Tool                    toolIdentity `json:"tool"`
	VulnerabilityDB         struct {
		SchemaVersion        int                 `json:"schema_version"`
		NextUpdate           string              `json:"next_update"`
		UpdatedAt            string              `json:"updated_at"`
		DownloadedAt         string              `json:"downloaded_at"`
		MaximumDatabaseBytes int64               `json:"maximum_database_bytes"`
		Files                []trivyDatabaseFile `json:"files"`
	} `json:"vulnerability_database"`
}

type trivyDatabaseFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type runtimeEvidence struct {
	Schema                  string `json:"schema"`
	CandidateSnapshotSHA256 string `json:"candidate_snapshot_sha256"`
	Platform                string `json:"platform"`
	Images                  []struct {
		Product       string   `json:"product"`
		Platform      string   `json:"platform"`
		SubjectDigest string   `json:"subject_digest"`
		User          string   `json:"user"`
		ReadOnly      bool     `json:"read_only"`
		CapDrop       []string `json:"cap_drop"`
		NoNewPrivs    bool     `json:"no_new_privileges"`
	} `json:"images"`
	Lifecycle struct {
		DaemonSIGTERM       bool `json:"daemon_sigterm"`
		DaemonSIGINT        bool `json:"daemon_sigint"`
		MilterSIGTERM       bool `json:"milter_sigterm"`
		MilterSIGINT        bool `json:"milter_sigint"`
		Restart             bool `json:"restart"`
		WritableSocketState bool `json:"writable_socket_volume"`
	} `json:"lifecycle"`
}

// main validates one unchanged candidate and every local evidence relationship.
func main() {
	root, versionProduct, err := parseInvocation()
	if err != nil {
		fail()
	}
	revision, err := conformance.CurrentRevision(root)
	if err != nil {
		fail()
	}
	if versionProduct != "" {
		report, loadErr := loadOCIReport(root, versionProduct, revision)
		version, versionErr := consistentOCIVersion(report)
		if loadErr != nil || versionErr != nil {
			fail()
		}
		fmt.Println(version)
		return
	}
	snapshot, err := conformance.ProduceSnapshot(root, revision)
	if err != nil {
		fail()
	}
	syft, err := loadTool(root, "syft")
	if err != nil {
		fail()
	}
	trivy, err := loadTool(root, "trivy")
	if err != nil {
		fail()
	}
	databasePath := filepath.Join(root, evidenceDirectory, "trivy-database.json")
	databaseContent, err := readSafeFile(root, databasePath, 1<<20)
	if err != nil {
		fail()
	}
	database, err := validateTrivyDatabase(databaseContent, trivy, snapshot.SHA256)
	if err != nil {
		fail()
	}
	databaseSum := sha256.Sum256(databaseContent)
	databaseSHA := hex.EncodeToString(databaseSum[:])
	products := []string{"dkim2d", "dkim2-milter", "dkim2ctl"}
	reports := make(map[string]ociReport, len(products))
	noticeSHA := ""
	for _, product := range products {
		report, err := loadOCIReport(root, product, revision)
		if err != nil {
			fail()
		}
		reports[product] = report
		if err := validateProvenance(root, product, revision, snapshot.SHA256, report); err != nil {
			fail()
		}
		for _, platform := range []string{"linux/amd64", "linux/arm64"} {
			platformEvidence, ok := platformReportFor(report, platform)
			if !ok {
				fail()
			}
			binary, notice, ok := validOCIInventory(
				platformEvidence.Files,
				product,
				platform,
			)
			if !ok || (noticeSHA != "" && notice.SHA256 != noticeSHA) {
				fail()
			}
			noticeSHA = notice.SHA256
			subject := platformEvidence.ManifestDigest
			architecture := strings.TrimPrefix(platform, "linux/")
			if err := validateSBOM(
				root,
				product,
				architecture,
				platform,
				subject,
				binary.SHA256,
				platformEvidence.Version,
				binary.Build,
				snapshot.SHA256,
				syft,
			); err != nil {
				fail()
			}
			if err := validateVulnerability(
				root,
				product,
				architecture,
				platform,
				subject,
				snapshot.SHA256,
				databaseSHA,
				database,
				trivy,
			); err != nil {
				fail()
			}
		}
	}
	if err := validateRuntimeEvidence(root, snapshot.SHA256, reports); err != nil {
		fail()
	}
	if err := scanPrivacy(root); err != nil {
		fail()
	}
	if err := writeImageReleaseReports(root, revision, snapshot.SHA256, products); err != nil {
		fail()
	}
	fmt.Println("image evidence verified")
}

// writeImageReleaseReports binds every validated product image, SBOM, provenance, and scan input.
func writeImageReleaseReports(
	root string,
	revision string,
	candidate string,
	products []string,
) error {
	runtimePath := filepath.Join(evidenceDirectory, "runtime-policy.json")
	runtimeSHA, err := fileSHA256(root, filepath.Join(root, runtimePath), 1<<20)
	if err != nil {
		return errors.New("release evidence")
	}
	databasePath := filepath.Join(evidenceDirectory, "trivy-database.json")
	databaseSHA, err := fileSHA256(root, filepath.Join(root, databasePath), 1<<20)
	if err != nil {
		return errors.New("release evidence")
	}
	for _, product := range products {
		report := imageReleaseReport{
			Schema:                  "dkim2-image-release-report-v1",
			BaseRevision:            revision,
			CandidateSnapshotSHA256: candidate,
			Product:                 product,
			RuntimePolicy: releaseArtifact{
				Path:   runtimePath,
				SHA256: runtimeSHA,
			},
			VulnerabilityDatabase: releaseArtifact{
				Path:   databasePath,
				SHA256: databaseSHA,
			},
			State: "pass",
		}
		for _, item := range []struct {
			target *releaseArtifact
			path   string
		}{
			{target: &report.OCI, path: filepath.Join(evidenceDirectory, product+".oci.json")},
			{
				target: &report.Provenance,
				path:   filepath.Join(evidenceDirectory, product+".provenance.json"),
			},
		} {
			digest, err := fileSHA256(root, filepath.Join(root, item.path), 64<<20)
			if err != nil {
				return errors.New("release evidence")
			}
			*item.target = releaseArtifact{Path: filepath.ToSlash(item.path), SHA256: digest}
		}
		for _, architecture := range []string{"amd64", "arm64"} {
			prefix := product + "." + architecture
			sbomPath := filepath.Join(evidenceDirectory, prefix+".sbom-binding.json")
			sbomSHA, err := fileSHA256(root, filepath.Join(root, sbomPath), 1<<20)
			if err != nil {
				return errors.New("release evidence")
			}
			report.SBOMBindings = append(report.SBOMBindings, releaseArtifact{
				Path: filepath.ToSlash(sbomPath), SHA256: sbomSHA,
			})
			vulnerabilityPath := filepath.Join(
				evidenceDirectory,
				prefix+".trivy-binding.json",
			)
			vulnerabilitySHA, err := fileSHA256(
				root,
				filepath.Join(root, vulnerabilityPath),
				1<<20,
			)
			if err != nil {
				return errors.New("release evidence")
			}
			report.VulnerabilityBindings = append(
				report.VulnerabilityBindings,
				releaseArtifact{
					Path:   filepath.ToSlash(vulnerabilityPath),
					SHA256: vulnerabilitySHA,
				},
			)
		}
		content, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return errors.New("release evidence")
		}
		content = append(content, '\n')
		target := filepath.Join(root, evidenceDirectory, product+".release.json")
		temporary, err := os.CreateTemp(filepath.Dir(target), ".release.")
		if err != nil {
			return errors.New("release evidence")
		}
		name := temporary.Name()
		if err := temporary.Chmod(0o600); err != nil {
			_ = temporary.Close()
			_ = os.Remove(name)
			return errors.New("release evidence")
		}
		_, writeErr := temporary.Write(content)
		closeErr := temporary.Close()
		if writeErr != nil || closeErr != nil || os.Rename(name, target) != nil {
			_ = os.Remove(name)
			return errors.New("release evidence")
		}
	}
	return nil
}

// validateTrivyDatabase verifies the exact scanner database inventory and tool binding.
func validateTrivyDatabase(
	content []byte,
	tool toolIdentity,
	candidate string,
) (trivyDatabaseReport, error) {
	return validateTrivyDatabaseAt(content, tool, candidate, time.Now().UTC())
}

// validateTrivyDatabaseAt verifies database identity and freshness at one testable clock.
func validateTrivyDatabaseAt(
	content []byte,
	tool toolIdentity,
	candidate string,
	current time.Time,
) (trivyDatabaseReport, error) {
	var report trivyDatabaseReport
	if strictjson.Decode(content, &report, 16, 512) != nil ||
		report.Schema != "dkim2-trivy-database-inventory-v1" ||
		report.CandidateSnapshotSHA256 != candidate ||
		!validSHA256(report.CandidateSnapshotSHA256) ||
		report.Tool != tool ||
		report.VulnerabilityDB.SchemaVersion != 2 ||
		report.VulnerabilityDB.MaximumDatabaseBytes != 2<<30 ||
		len(report.VulnerabilityDB.Files) != 2 {
		return trivyDatabaseReport{}, errors.New("database")
	}
	updatedAt, updatedErr := time.Parse(time.RFC3339Nano, report.VulnerabilityDB.UpdatedAt)
	nextUpdate, nextErr := time.Parse(time.RFC3339Nano, report.VulnerabilityDB.NextUpdate)
	downloadedAt, downloadedErr := time.Parse(
		time.RFC3339Nano,
		report.VulnerabilityDB.DownloadedAt,
	)
	scanTime, scanErr := time.Parse(time.RFC3339, report.ScanTime)
	if updatedErr != nil || nextErr != nil || downloadedErr != nil ||
		scanErr != nil || scanTime.UTC().Format(time.RFC3339) != report.ScanTime ||
		!nextUpdate.After(updatedAt) || downloadedAt.Before(updatedAt) ||
		!downloadedAt.Before(nextUpdate) ||
		updatedAt.After(scanTime.Add(maximumDBClockSkew)) ||
		downloadedAt.After(scanTime.Add(maximumDBClockSkew)) ||
		!nextUpdate.After(scanTime) ||
		scanTime.Sub(updatedAt) > maximumDBAge ||
		scanTime.After(current.UTC().Add(maximumDBClockSkew)) ||
		!nextUpdate.After(current.UTC()) ||
		current.UTC().Sub(updatedAt) > maximumDBAge {
		return trivyDatabaseReport{}, errors.New("database")
	}
	expectedFiles := []struct {
		path    string
		maxSize int64
	}{
		{path: "db/metadata.json", maxSize: 64 << 10},
		{path: "db/trivy.db", maxSize: 2 << 30},
	}
	for index, file := range report.VulnerabilityDB.Files {
		expected := expectedFiles[index]
		if file.Path != expected.path || file.Size <= 0 ||
			file.Size > expected.maxSize || !validSHA256(file.SHA256) {
			return trivyDatabaseReport{}, errors.New("database")
		}
	}
	return report, nil
}

// validateRuntimeEvidence binds tested policy and lifecycle facts to OCI subjects.
func validateRuntimeEvidence(
	root string,
	candidate string,
	reports map[string]ociReport,
) error {
	content, err := readSafeFile(
		root,
		filepath.Join(root, evidenceDirectory, "runtime-policy.json"),
		1<<20,
	)
	if err != nil {
		return err
	}
	var evidence runtimeEvidence
	if strictjson.Decode(content, &evidence, 16, 1024) != nil ||
		evidence.Schema != "dkim2-image-runtime-evidence-v1" ||
		evidence.CandidateSnapshotSHA256 != candidate ||
		(evidence.Platform != "linux/amd64" && evidence.Platform != "linux/arm64") ||
		len(evidence.Images) != len(reports) ||
		!evidence.Lifecycle.DaemonSIGTERM ||
		!evidence.Lifecycle.DaemonSIGINT ||
		!evidence.Lifecycle.MilterSIGTERM ||
		!evidence.Lifecycle.MilterSIGINT ||
		!evidence.Lifecycle.Restart ||
		!evidence.Lifecycle.WritableSocketState {
		return errors.New("runtime")
	}
	seen := make(map[string]struct{}, len(evidence.Images))
	for _, image := range evidence.Images {
		report, ok := reports[image.Product]
		if !ok || image.Platform != evidence.Platform ||
			image.User != "2000:2000" || !image.ReadOnly ||
			len(image.CapDrop) != 1 || image.CapDrop[0] != "ALL" ||
			!image.NoNewPrivs {
			return errors.New("runtime image")
		}
		subject, ok := manifestSubject(report, evidence.Platform)
		if !ok || image.SubjectDigest != subject {
			return errors.New("runtime subject")
		}
		if _, duplicate := seen[image.Product]; duplicate {
			return errors.New("runtime duplicate")
		}
		seen[image.Product] = struct{}{}
	}
	return nil
}

// parseInvocation accepts the closed verifier or OCI-version query surface.
func parseInvocation() (string, string, error) {
	var rawRoot string
	var versionProduct string
	switch {
	case len(os.Args) == 3 && os.Args[1] == "-root":
		rawRoot = os.Args[2]
	case len(os.Args) == 5 && os.Args[1] == "-root" &&
		os.Args[3] == "-oci-version" && validEvidenceProduct(os.Args[4]):
		rawRoot = os.Args[2]
		versionProduct = os.Args[4]
	default:
		return "", "", errors.New("arguments")
	}
	root, err := filepath.Abs(rawRoot)
	if err != nil {
		return "", "", err
	}
	evaluated, err := filepath.EvalSymlinks(root)
	if err != nil || evaluated != filepath.Clean(root) {
		return "", "", errors.New("root")
	}
	return root, versionProduct, nil
}

// validEvidenceProduct accepts one repository-owned container product.
func validEvidenceProduct(value string) bool {
	return value == "dkim2d" || value == "dkim2-milter" || value == "dkim2ctl"
}

// fail emits one fixed content-free evidence failure.
func fail() {
	fmt.Fprintln(os.Stderr, "image evidence rejected")
	os.Exit(1)
}

// loadTool verifies the downloaded archive identity and exact executable bytes.
func loadTool(root string, name string) (toolIdentity, error) {
	reviewed, err := loadReviewedTool(root, name, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return toolIdentity{}, err
	}
	identityPath := filepath.Join(root, toolDirectory, name+".identity.json")
	content, err := readSafeFile(root, identityPath, 16<<10)
	if err != nil {
		return toolIdentity{}, err
	}
	var identity toolIdentity
	if err := strictjson.Decode(content, &identity, 8, 128); err != nil ||
		identity.Schema != "dkim2-image-tool-v1" ||
		identity.Name != name || identity.Version != reviewed.Version ||
		!validSHA256(identity.ArchiveSHA256) || !validSHA256(identity.BinarySHA256) ||
		identity.Asset == "" || len(identity.Asset) > 128 ||
		identity.Asset != reviewed.Platform.Asset ||
		identity.ArchiveSHA256 != reviewed.Platform.ArchiveSHA256 ||
		identity.BinarySHA256 != reviewed.Platform.BinarySHA256 {
		return toolIdentity{}, errors.New("tool")
	}
	binarySHA, err := fileSHA256(root, filepath.Join(root, toolDirectory, name), 256<<20)
	if err != nil || binarySHA != identity.BinarySHA256 {
		return toolIdentity{}, errors.New("tool")
	}
	return identity, nil
}

// loadReviewedTool resolves one host-specific identity from the durable closed allowlist.
func loadReviewedTool(
	root string,
	name string,
	goos string,
	goarch string,
) (reviewedToolSelection, error) {
	content, err := readSafeFile(root, filepath.Join(root, toolAllowlistPath), 64<<10)
	if err != nil {
		return reviewedToolSelection{}, err
	}
	var allowlist toolAllowlist
	if strictjson.Decode(content, &allowlist, 16, 1024) != nil ||
		allowlist.Schema != "dkim2-image-tool-allowlist-v1" ||
		len(allowlist.Tools) != 2 {
		return reviewedToolSelection{}, errors.New("tool allowlist")
	}
	expectedTools := []string{"syft", "trivy"}
	expectedPlatforms := []struct {
		goos   string
		goarch string
	}{
		{goos: "darwin", goarch: "amd64"},
		{goos: "darwin", goarch: "arm64"},
		{goos: "linux", goarch: "amd64"},
		{goos: "linux", goarch: "arm64"},
	}
	var selected reviewedToolSelection
	found := false
	for toolIndex, tool := range allowlist.Tools {
		if tool.Name != expectedTools[toolIndex] || tool.Version == "" ||
			len(tool.Version) > 32 ||
			len(tool.Platforms) != len(expectedPlatforms) {
			return reviewedToolSelection{}, errors.New("tool allowlist")
		}
		for platformIndex, platform := range tool.Platforms {
			expectedPlatform := expectedPlatforms[platformIndex]
			if platform.GOOS != expectedPlatform.goos ||
				platform.GOARCH != expectedPlatform.goarch ||
				platform.Asset == "" || len(platform.Asset) > 128 ||
				!validSHA256(platform.ArchiveSHA256) ||
				!validSHA256(platform.BinarySHA256) {
				return reviewedToolSelection{}, errors.New("tool allowlist")
			}
			if tool.Name == name &&
				platform.GOOS == goos && platform.GOARCH == goarch {
				selected = reviewedToolSelection{
					Version:  tool.Version,
					Platform: platform,
				}
				found = true
			}
		}
	}
	if !found {
		return reviewedToolSelection{}, errors.New("tool allowlist")
	}
	return selected, nil
}

// loadOCIReport strictly decodes the repository-owned normalized OCI report.
func loadOCIReport(root string, product string, revision string) (ociReport, error) {
	content, err := readSafeFile(
		root,
		filepath.Join(root, evidenceDirectory, product+".oci.json"),
		1<<20,
	)
	if err != nil {
		return ociReport{}, err
	}
	var report ociReport
	if err := strictjson.Decode(content, &report, 32, 100_000); err != nil ||
		report.Schema != "dkim2-oci-policy-v1" || report.Product != product ||
		!validDigest(report.SubjectDigest) || len(report.Platforms) != 2 {
		return ociReport{}, errors.New("oci")
	}
	seen := make(map[string]struct{}, len(report.Platforms))
	descriptions := map[string]string{
		"dkim2d":       "Loopback-only DKIM2 processing daemon",
		"dkim2-milter": "Unix-socket DKIM2 Milter adapter",
		"dkim2ctl":     "Generated-client DKIM2 conformance utility",
	}
	for _, candidate := range report.Platforms {
		expectedLabels := map[string]string{
			"org.opencontainers.image.source":        "https://github.com/croessner/dkim2",
			"org.opencontainers.image.revision":      revision,
			"org.opencontainers.image.version":       candidate.Version,
			"org.opencontainers.image.created":       candidate.Created,
			"org.opencontainers.image.vendor":        "DKIM2 reference implementation",
			"org.opencontainers.image.documentation": "https://github.com/croessner/dkim2/tree/main/docs/operator",
			"org.opencontainers.image.licenses":      "Apache-2.0",
			"org.opencontainers.image.title":         product,
			"org.opencontainers.image.description":   descriptions[product],
		}
		if (candidate.Platform != "linux/amd64" && candidate.Platform != "linux/arm64") ||
			!validDigest(candidate.ManifestDigest) ||
			!validDigest(candidate.ConfigDigest) ||
			!validDigest(candidate.LayerDigest) ||
			!validDigest(candidate.DiffIDDigest) ||
			len(candidate.Files) != 3 ||
			candidate.Revision != revision ||
			!validContainerVersion(candidate.Version) ||
			!validExactRFC3339(candidate.Created) ||
			candidate.User != "2000:2000" ||
			!equalStrings(candidate.Entrypoint, []string{"/usr/local/bin/" + product}) ||
			!equalStringMaps(candidate.Labels, expectedLabels) ||
			!validOCIHealthcheck(candidate.Healthcheck, product) {
			return ociReport{}, errors.New("oci")
		}
		if _, _, ok := validOCIInventory(
			candidate.Files,
			product,
			candidate.Platform,
		); !ok {
			return ociReport{}, errors.New("oci")
		}
		if _, duplicate := seen[candidate.Platform]; duplicate {
			return ociReport{}, errors.New("oci")
		}
		seen[candidate.Platform] = struct{}{}
	}
	if _, err := consistentOCIVersion(report); err != nil {
		return ociReport{}, err
	}
	return report, nil
}

// consistentOCIVersion returns the one version shared by both validated platforms.
func consistentOCIVersion(report ociReport) (string, error) {
	if len(report.Platforms) != 2 {
		return "", errors.New("oci version")
	}
	var version string
	seen := make(map[string]bool, 2)
	for _, candidate := range report.Platforms {
		if (candidate.Platform != "linux/amd64" && candidate.Platform != "linux/arm64") ||
			seen[candidate.Platform] || !validContainerVersion(candidate.Version) {
			return "", errors.New("oci version")
		}
		seen[candidate.Platform] = true
		if version == "" {
			version = candidate.Version
			continue
		}
		if candidate.Version != version {
			return "", errors.New("oci version")
		}
	}
	if !seen["linux/amd64"] || !seen["linux/arm64"] {
		return "", errors.New("oci version")
	}
	return version, nil
}

// validOCIBinary verifies the exact binary and embedded build closure projection.
func validOCIBinary(
	file ociFileReport,
	product string,
	platform string,
) bool {
	parts := strings.Split(platform, "/")
	if len(parts) != 2 ||
		file.Path != "/usr/local/bin/"+product ||
		file.Mode != 0o555 || file.UID != 0 || file.GID != 0 ||
		file.Size <= 0 || file.Size > 100<<20 ||
		!validSHA256(file.SHA256) || file.Typeflag != tar.TypeReg ||
		file.Build.GoVersion != "go1.26.6" ||
		file.Build.Main.Path != "github.com/croessner/dkim2/cmd/"+product ||
		file.Build.Main.Version != "(devel)" || file.Build.Main.Sum != "" ||
		file.Build.GOOS != "linux" || file.Build.GOARCH != parts[1] ||
		file.Build.CGO != "0" || file.Build.Trimpath != "true" {
		return false
	}
	previous := ""
	for _, dependency := range file.Build.Deps {
		if dependency.Path == "" || dependency.Path <= previous ||
			dependency.Version == "" {
			return false
		}
		previous = dependency.Path
	}
	return true
}

// validOCINotice verifies the exact public license-notice projection.
func validOCINotice(file ociFileReport) bool {
	return file.Path == "/usr/share/licenses/dkim2/THIRD_PARTY_NOTICES.txt" &&
		file.Mode == 0o444 && file.UID == 0 && file.GID == 0 &&
		file.Size > 0 && file.Size <= 8<<20 &&
		validSHA256(file.SHA256) && file.Typeflag == tar.TypeReg &&
		file.Build.GoVersion == "" && file.Build.Main.Path == "" &&
		file.Build.Main.Version == "" && file.Build.Main.Sum == "" &&
		len(file.Build.Deps) == 0 && file.Build.GOOS == "" &&
		file.Build.GOARCH == "" && file.Build.CGO == "" &&
		file.Build.Trimpath == ""
}

// validOCIProjectLicense verifies the fixed project license projection.
func validOCIProjectLicense(file ociFileReport) bool {
	return file.Path == "/usr/share/licenses/dkim2/LICENSE" &&
		file.Mode == 0o444 && file.UID == 0 && file.GID == 0 &&
		file.Size > 0 && file.Size <= 32<<10 &&
		validSHA256(file.SHA256) && file.Typeflag == tar.TypeReg &&
		file.Build.GoVersion == "" && file.Build.Main.Path == "" &&
		file.Build.Main.Version == "" && file.Build.Main.Sum == "" &&
		len(file.Build.Deps) == 0 && file.Build.GOOS == "" &&
		file.Build.GOARCH == "" && file.Build.CGO == "" &&
		file.Build.Trimpath == ""
}

// validOCIInventory returns the uniquely validated binary and notice records.
func validOCIInventory(
	files []ociFileReport,
	product string,
	platform string,
) (ociFileReport, ociFileReport, bool) {
	if len(files) != 3 {
		return ociFileReport{}, ociFileReport{}, false
	}
	var binary ociFileReport
	var notice ociFileReport
	licenseFound := false
	binaryFound := false
	noticeFound := false
	for _, file := range files {
		switch {
		case validOCIBinary(file, product, platform):
			if binaryFound {
				return ociFileReport{}, ociFileReport{}, false
			}
			binary = file
			binaryFound = true
		case validOCINotice(file):
			if noticeFound {
				return ociFileReport{}, ociFileReport{}, false
			}
			notice = file
			noticeFound = true
		case validOCIProjectLicense(file):
			if licenseFound {
				return ociFileReport{}, ociFileReport{}, false
			}
			licenseFound = true
		default:
			return ociFileReport{}, ociFileReport{}, false
		}
	}
	return binary, notice, binaryFound && noticeFound && licenseFound
}

// validOCIHealthcheck verifies exact daemon-only probe behavior.
func validOCIHealthcheck(value *ociHealthcheck, product string) bool {
	if product != "dkim2d" {
		return value == nil
	}
	return value != nil &&
		equalStrings(
			value.Test,
			[]string{"CMD", "/usr/local/bin/dkim2d", "probe"},
		) &&
		value.Interval == int64(10*time.Second) &&
		value.Timeout == int64(3*time.Second) &&
		value.Retries == 3 &&
		value.StartPeriod == 0 &&
		value.StartInterval == 0
}

// validExactRFC3339 accepts one canonical whole-second UTC timestamp.
func validExactRFC3339(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.UTC().Format(time.RFC3339) == value
}

// validContainerVersion accepts development or one stable semantic version.
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

// equalStringMaps compares exact closed string maps.
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

// manifestSubject returns one exact platform manifest from a validated report.
func manifestSubject(report ociReport, platform string) (string, bool) {
	candidate, ok := platformReportFor(report, platform)
	if !ok {
		return "", false
	}
	return candidate.ManifestDigest, true
}

// platformReportFor returns one exact validated platform report.
func platformReportFor(report ociReport, platform string) (ociPlatformReport, bool) {
	for _, candidate := range report.Platforms {
		if candidate.Platform == platform && validDigest(candidate.ManifestDigest) {
			return candidate, true
		}
	}
	return ociPlatformReport{}, false
}

// validateSBOM binds strict normalized SPDX bytes to candidate, subject, and tool.
func validateSBOM(
	root string,
	product string,
	architecture string,
	platform string,
	subject string,
	binarySHA string,
	version string,
	build binaryBuildInfo,
	candidate string,
	tool toolIdentity,
) error {
	prefix := product + "." + architecture
	sbomPath := filepath.Join(root, evidenceDirectory, prefix+".spdx.json")
	sbomContent, err := readSafeFile(root, sbomPath, 64<<20)
	if err != nil {
		return errors.New("sbom")
	}
	var document spdxDocument
	if strictjson.Decode(sbomContent, &document, 128, 2_000_000) != nil ||
		document.SPDXVersion != "SPDX-2.3" || document.DataLicense != "CC0-1.0" ||
		document.SPDXID != "SPDXRef-DOCUMENT" ||
		document.Name != product+"@"+subject ||
		document.CreationInfo.Created != "1970-01-01T00:00:00Z" ||
		!equalStrings(
			document.CreationInfo.Creators,
			[]string{"Organization: Anchore, Inc", "Tool: syft-" + tool.Version},
		) ||
		document.CreationInfo.LicenseListVersion == "" ||
		document.DocumentNamespace !=
			"https://github.com/croessner/dkim2/sbom/"+strings.TrimPrefix(subject, "sha256:") ||
		!validSPDXInventory(document, product, subject, binarySHA, version, build) {
		return errors.New("sbom")
	}
	bindingContent, err := readSafeFile(
		root,
		filepath.Join(root, evidenceDirectory, prefix+".sbom-binding.json"),
		64<<10,
	)
	if err != nil {
		return err
	}
	var binding sbomBinding
	if strictjson.Decode(bindingContent, &binding, 16, 512) != nil ||
		binding.Schema != "dkim2-image-sbom-binding-v1" ||
		binding.CandidateSnapshotSHA256 != candidate ||
		binding.Product != product || binding.Platform != platform ||
		binding.SubjectDigest != subject || binding.SBOM.Format != "SPDX-2.3" ||
		binding.Tool != tool {
		return errors.New("sbom binding")
	}
	actual := sha256.Sum256(sbomContent)
	if binding.SBOM.SHA256 != hex.EncodeToString(actual[:]) {
		return errors.New("sbom hash")
	}
	return nil
}

// validSPDXInventory verifies the closed package, file, license, and relationship inventory.
//
//nolint:gocyclo // The closed SPDX matrix stays linear so every evidence field is visible.
func validSPDXInventory(
	document spdxDocument,
	product string,
	subject string,
	binarySHA string,
	version string,
	build binaryBuildInfo,
) bool {
	expectedPackages := expectedSPDXPackages(product, subject, version, build)
	if expectedPackages == nil || len(document.Packages) != len(expectedPackages) ||
		len(document.Files) != 1 || len(document.Relationships) == 0 ||
		len(document.Relationships) > 10_000 || !validSHA256(binarySHA) {
		return false
	}
	identifiers := map[string]struct{}{"SPDXRef-DOCUMENT": {}}
	rootID := ""
	seenPackages := make(map[string]bool, len(expectedPackages))
	for _, current := range document.Packages {
		if !strings.HasPrefix(current.SPDXID, "SPDXRef-") ||
			current.Name == "" || len(current.Name) > 512 ||
			current.VersionInfo == "" || len(current.VersionInfo) > 256 ||
			current.LicenseConcluded == "" || len(current.LicenseConcluded) > 256 ||
			current.LicenseDeclared == "" || len(current.LicenseDeclared) > 256 ||
			current.DownloadLocation != "NOASSERTION" || current.FilesAnalyzed ||
			current.CopyrightText == "" || current.Supplier == "" ||
			len(current.ExternalRefs) == 0 || len(current.ExternalRefs) > 32 {
			return false
		}
		expectedVersion, ok := expectedPackages[current.Name]
		if !ok || expectedVersion != current.VersionInfo || seenPackages[current.Name] {
			return false
		}
		seenPackages[current.Name] = true
		if _, duplicate := identifiers[current.SPDXID]; duplicate {
			return false
		}
		identifiers[current.SPDXID] = struct{}{}
		if current.Name == product+"@"+subject {
			rootID = current.SPDXID
		}
		for _, reference := range current.ExternalRefs {
			if reference.ReferenceCategory == "" ||
				reference.ReferenceType == "" ||
				reference.ReferenceLocator == "" ||
				len(reference.ReferenceLocator) > 4_096 {
				return false
			}
		}
	}
	file := document.Files[0]
	if !strings.HasPrefix(file.SPDXID, "SPDXRef-") ||
		file.FileName != "usr/local/bin/"+product ||
		!equalStrings(file.FileTypes, []string{"APPLICATION", "BINARY"}) ||
		file.LicenseConcluded == "" || len(file.LicenseInfoInFile) == 0 ||
		file.CopyrightText == "" || len(file.Comment) > 512 ||
		checksumFor(file.Checksums, "SHA256") != binarySHA {
		return false
	}
	if _, duplicate := identifiers[file.SPDXID]; duplicate {
		return false
	}
	identifiers[file.SPDXID] = struct{}{}
	describes := 0
	for _, relationship := range document.Relationships {
		if _, ok := identifiers[relationship.ElementID]; !ok {
			return false
		}
		if _, ok := identifiers[relationship.RelatedElement]; !ok {
			return false
		}
		switch relationship.Relationship {
		case "CONTAINS", "DEPENDENCY_OF", "DESCRIBES", "OTHER":
		default:
			return false
		}
		if relationship.Relationship == "DESCRIBES" &&
			relationship.ElementID == "SPDXRef-DOCUMENT" &&
			relationship.RelatedElement == rootID {
			describes++
		}
		if len(relationship.Comment) > 512 {
			return false
		}
	}
	return rootID != "" && describes == 1
}

// expectedSPDXPackages derives the exact SBOM closure from embedded build info.
func expectedSPDXPackages(
	product string,
	subject string,
	version string,
	build binaryBuildInfo,
) map[string]string {
	if build.GoVersion != "go1.26.6" ||
		build.Main.Path != "github.com/croessner/dkim2/cmd/"+product ||
		build.Main.Version != "(devel)" ||
		build.GOOS != "linux" ||
		(build.GOARCH != "amd64" && build.GOARCH != "arm64") ||
		build.CGO != "0" || build.Trimpath != "true" ||
		version == "" {
		return nil
	}
	result := map[string]string{
		product + "@" + subject: version,
		build.Main.Path:         "UNKNOWN",
		"stdlib":                build.GoVersion,
	}
	for _, dependency := range build.Deps {
		if dependency.Path == "" || dependency.Version == "" {
			return nil
		}
		dependencyVersion := dependency.Version
		if dependencyVersion == "(devel)" {
			dependencyVersion = "UNKNOWN"
		}
		if _, duplicate := result[dependency.Path]; duplicate {
			return nil
		}
		result[dependency.Path] = dependencyVersion
	}
	return result
}

// checksumFor returns one unique validated checksum for the requested algorithm.
func checksumFor(checksums []spdxChecksum, algorithm string) string {
	var result string
	for _, checksum := range checksums {
		if checksum.Algorithm != algorithm {
			continue
		}
		if result != "" || !validSHA256(checksum.ChecksumValue) {
			return ""
		}
		result = checksum.ChecksumValue
	}
	return result
}

// validateVulnerability binds a clean Trivy report to subject, DB, and tool.
func validateVulnerability(
	root string,
	product string,
	architecture string,
	platform string,
	subject string,
	candidate string,
	databaseSHA string,
	database trivyDatabaseReport,
	tool toolIdentity,
) error {
	if len(database.VulnerabilityDB.Files) != 2 {
		return errors.New("vulnerability database")
	}
	prefix := product + "." + architecture
	reportContent, err := readSafeFile(
		root,
		filepath.Join(root, evidenceDirectory, prefix+".trivy.json"),
		128<<20,
	)
	if err != nil || strictjson.Validate(reportContent, 128, 2_000_000) != nil {
		return errors.New("vulnerability")
	}
	var report trivyReport
	if json.Unmarshal(reportContent, &report) != nil ||
		report.SchemaVersion != 2 || report.CreatedAt != "1970-01-01T00:00:00Z" ||
		report.ArtifactName != product+"@"+subject || report.ArtifactID != subject {
		return errors.New("vulnerability")
	}
	for _, result := range report.Results {
		if len(result.Vulnerabilities) != 0 {
			return errors.New("vulnerability finding")
		}
	}
	bindingContent, err := readSafeFile(
		root,
		filepath.Join(root, evidenceDirectory, prefix+".trivy-binding.json"),
		64<<10,
	)
	if err != nil {
		return err
	}
	var binding vulnerabilityBinding
	if strictjson.Decode(bindingContent, &binding, 16, 512) != nil ||
		binding.Schema != "dkim2-image-vulnerability-binding-v1" ||
		binding.CandidateSnapshotSHA256 != candidate ||
		binding.Product != product || binding.Platform != platform ||
		binding.SubjectDigest != subject ||
		binding.Report.Format != "trivy-json-"+tool.Version ||
		binding.Database.InventorySHA256 != databaseSHA ||
		binding.Database.ContentSHA256 != database.VulnerabilityDB.Files[1].SHA256 ||
		binding.Database.MetadataSHA256 != database.VulnerabilityDB.Files[0].SHA256 ||
		binding.Database.ScanTime != database.ScanTime ||
		binding.Database.SchemaVersion != database.VulnerabilityDB.SchemaVersion ||
		binding.Database.UpdatedAt != database.VulnerabilityDB.UpdatedAt ||
		binding.Database.NextUpdate != database.VulnerabilityDB.NextUpdate ||
		binding.Database.DownloadedAt != database.VulnerabilityDB.DownloadedAt ||
		binding.Tool != tool {
		return errors.New("vulnerability binding")
	}
	actual := sha256.Sum256(reportContent)
	if binding.Report.SHA256 != hex.EncodeToString(actual[:]) {
		return errors.New("vulnerability hash")
	}
	return nil
}

// validateProvenance rejects publication authority and verifies SLSA descriptor binding.
func validateProvenance(
	root string,
	product string,
	revision string,
	candidate string,
	report ociReport,
) error {
	content, err := readSafeFile(
		root,
		filepath.Join(root, evidenceDirectory, product+".provenance.json"),
		1<<20,
	)
	if err != nil {
		return err
	}
	var statement provenanceStatement
	if strictjson.Decode(content, &statement, 32, 4096) != nil ||
		statement.Type != "https://in-toto.io/Statement/v1" ||
		statement.PredicateType != "https://slsa.dev/provenance/v1" ||
		len(statement.Subject) != 1 || statement.Subject[0].Name != product ||
		len(statement.Subject[0].Digest) != 1 ||
		statement.Subject[0].Digest["sha256"] != strings.TrimPrefix(report.SubjectDigest, "sha256:") ||
		statement.Predicate.BuildDefinition.BuildType !=
			"https://github.com/croessner/dkim2/container-build/v1" ||
		statement.Predicate.BuildDefinition.InternalParameters.CandidateSnapshotSHA256 != candidate ||
		statement.Predicate.BuildDefinition.InternalParameters.PublicationAuthority ||
		statement.Predicate.BuildDefinition.InternalParameters.EvidenceClass != "local-test" ||
		!equalStrings(
			statement.Predicate.BuildDefinition.ExternalParameters.Platforms,
			[]string{"linux/amd64", "linux/arm64"},
		) ||
		!validResolvedDependencies(
			root,
			statement.Predicate.BuildDefinition.ResolvedDependencies,
			revision,
		) ||
		len(statement.Predicate.RunDetails.Byproducts) != 2 {
		return errors.New("provenance")
	}
	if statement.Predicate.RunDetails.Builder.ID != "local://dkim2/image-evidence" ||
		statement.Predicate.RunDetails.Metadata.InvocationID != "local-test" {
		return errors.New("provenance invocation")
	}
	expectedPlatforms := []string{"linux/amd64", "linux/arm64"}
	for index, byproduct := range statement.Predicate.RunDetails.Byproducts {
		expectedPlatform := expectedPlatforms[index]
		subject, ok := manifestSubject(report, expectedPlatform)
		if !ok || byproduct.Name != expectedPlatform ||
			len(byproduct.Digest) != 1 ||
			byproduct.Digest["sha256"] != strings.TrimPrefix(subject, "sha256:") {
			return errors.New("provenance byproduct")
		}
	}
	return nil
}

// validResolvedDependencies verifies source and centrally reviewed build inputs.
func validResolvedDependencies(
	root string,
	dependencies []struct {
		URI    string            `json:"uri"`
		Digest map[string]string `json:"digest"`
	},
	revision string,
) bool {
	policy, err := loadBuildInputPolicy(root)
	if err != nil || len(dependencies) != len(policy.Images)+1 {
		return false
	}
	if dependencies[0].URI != "git+https://github.com/croessner/dkim2" ||
		len(dependencies[0].Digest) != 1 ||
		dependencies[0].Digest["gitCommit"] != revision {
		return false
	}
	for index, image := range policy.Images {
		dependency := dependencies[index+1]
		if dependency.URI != image.URI || len(dependency.Digest) != 1 ||
			dependency.Digest["sha256"] != image.Digest {
			return false
		}
	}
	return true
}

// loadBuildInputPolicy reads the bounded central build-input allowlist.
func loadBuildInputPolicy(root string) (buildInputPolicy, error) {
	content, err := readSafeFile(
		root,
		filepath.Join(root, buildInputPath),
		64<<10,
	)
	if err != nil {
		return buildInputPolicy{}, err
	}
	var policy buildInputPolicy
	if strictjson.Decode(content, &policy, 8, 256) != nil ||
		policy.Schema != "dkim2-container-build-inputs-v1" ||
		len(policy.Images) != 3 {
		return buildInputPolicy{}, errors.New("build input policy")
	}
	expected := []struct {
		name    string
		uri     string
		purpose string
	}{
		{
			name:    "metadata-validator",
			uri:     "docker-image://docker.io/library/busybox",
			purpose: "build-only metadata validation",
		},
		{
			name:    "go-builder",
			uri:     "docker-image://docker.io/library/golang",
			purpose: "build-only Go compilation",
		},
		{
			name:    "buildkit",
			uri:     "docker-image://moby/buildkit",
			purpose: "isolated BuildKit executor",
		},
	}
	for index, image := range policy.Images {
		current := expected[index]
		if image.Name != current.name || image.URI != current.uri ||
			image.Purpose != current.purpose || image.Reference == "" ||
			len(image.Reference) > 128 || !validSHA256(image.Digest) {
			return buildInputPolicy{}, errors.New("build input policy")
		}
	}
	return policy, nil
}

// scanPrivacy rejects local identity and protected marker classes in evidence.
func scanPrivacy(root string) error {
	names := []string{"trivy-database.json", "runtime-policy.json"}
	for _, product := range []string{"dkim2d", "dkim2-milter", "dkim2ctl"} {
		names = append(names, product+".oci.json", product+".provenance.json")
		for _, architecture := range []string{"amd64", "arm64"} {
			prefix := product + "." + architecture
			names = append(
				names,
				prefix+".spdx.json",
				prefix+".sbom-binding.json",
				prefix+".trivy.json",
				prefix+".trivy-binding.json",
			)
		}
	}
	for _, name := range names {
		content, err := readSafeFile(
			root,
			filepath.Join(root, evidenceDirectory, name),
			128<<20,
		)
		if err != nil {
			return err
		}
		for _, marker := range [][]byte{
			[]byte("/Users/"),
			[]byte("/home/"),
			[]byte("PRIVATE KEY"),
			[]byte("BEGIN RSA"),
			[]byte("Message-Instance:"),
			[]byte("X-DKIM2-Capability"),
		} {
			if strings.Contains(string(content), string(marker)) {
				return errors.New("privacy")
			}
		}
	}
	return nil
}

// readSafeFile reads one bounded owned one-link regular file.
func readSafeFile(root string, path string, limit int64) ([]byte, error) {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return nil, errors.New("file")
	}
	return artifactpath.ReadFile(root, relative, limit)
}

// fileSHA256 hashes one safe bounded file.
func fileSHA256(root string, path string, limit int64) (string, error) {
	content, err := readSafeFile(root, path, limit)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]), nil
}

// validDigest accepts one exact lowercase SHA-256 OCI digest.
func validDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validSHA256(strings.TrimPrefix(value, "sha256:"))
}

// validSHA256 accepts one exact lowercase SHA-256 hex value.
func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

// equalStrings compares exact ordered string slices.
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
