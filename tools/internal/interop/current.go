//nolint:goconst // Closed evidence vocabulary stays visible at each owning projection.
package interop

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/croessner/dkim2/tools/internal/artifactpath"
	"github.com/croessner/dkim2/tools/internal/conformance"
	"github.com/croessner/dkim2/tools/internal/strictjson"
)

const (
	currentEvidencePath   = ".artifacts/interop/discovery-evidence.json"
	currentComparisonPath = ".artifacts/interop/external-comparison.json"
	currentCutoffPath     = ".artifacts/interop/observation-cutoff.txt"
	maxProducerBytes      = int64(128 << 20)
	maxPeerOutputBytes    = 1 << 20
	peerRunnerImage       = "golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651"
)

var currentSourceFiles = map[string][]string{
	"github-dkim2-search": {
		".artifacts/interop/raw/github-search.json",
		".artifacts/interop/raw/search-candidates/darkglobe-project-darkglobe-suite-commit.json",
		".artifacts/interop/raw/search-candidates/darkglobe-project-darkglobe-suite-repo.json",
		".artifacts/interop/raw/search-candidates/dkim2wg-spec-commit.json",
		".artifacts/interop/raw/search-candidates/dkim2wg-spec-repo.json",
		".artifacts/interop/raw/search-candidates/EdgarOrtegaRamirez-mailauthlens-commit.json",
		".artifacts/interop/raw/search-candidates/EdgarOrtegaRamirez-mailauthlens-repo.json",
		".artifacts/interop/raw/search-candidates/turscar-dkim2play-commit.json",
		".artifacts/interop/raw/search-candidates/turscar-dkim2play-repo.json",
		".artifacts/interop/raw/search-candidates/darkglobe-source.tar.gz",
		".artifacts/interop/raw/search-candidates/dkim2play-source.tar.gz",
		".artifacts/interop/raw/search-candidates/mailauthlens-source.tar.gz",
		".artifacts/interop/raw/search-candidates/spec-source.tar.gz",
	},
	"github-dkim2wg-interop": {
		".artifacts/interop/raw/dkim2wg-repo.json",
		".artifacts/interop/raw/dkim2wg-commit.json",
		".artifacts/interop/raw/dkim2wg-source.tar.gz",
	},
	"github-dkim2wg-repositories": {
		".artifacts/interop/raw/dkim2wg-repos.json",
	},
	"github-stalwart-mail-auth": {
		".artifacts/interop/raw/stalwart-repo.json",
		".artifacts/interop/raw/stalwart-commit.json",
		".artifacts/interop/raw/stalwart-source.tar.gz",
	},
	"ietf-dkim-archive-index": {
		".artifacts/interop/raw/archive-index.html",
	},
	"ietf-dkim-interop-announcement": {
		".artifacts/interop/raw/announcement.html",
	},
	"ietf-dkim2-dns-04": {
		".artifacts/interop/raw/dns-04.txt",
	},
	"ietf-dkim2-spec-04": {
		".artifacts/interop/raw/spec-04.txt",
	},
	"turscar-dkim2": {
		".artifacts/interop/raw/turscar-repo.json",
		".artifacts/interop/raw/turscar-branch.json",
		".artifacts/interop/raw/turscar-source.tar.gz",
	},
}

type normalizedFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type boundedPeerOutput struct {
	content []byte
}

type currentPeer struct {
	id                   string
	archive              string
	sourceDirectory      string
	packagePath          string
	harness              string
	tests                string
	moduleCache          string
	expectedBuildSHA256  string
	expectedDependencyID string
}

type currentProducer struct {
	path   string
	digest string
}

// Write retains only bounded hostile peer output and fails closed on overflow.
func (o *boundedPeerOutput) Write(content []byte) (int, error) {
	if len(o.content) > maxPeerOutputBytes-len(content) {
		return 0, errors.New("comparison_output")
	}
	o.content = append(o.content, content...)
	return len(content), nil
}

// RunCurrent normalizes the exact reviewed acquisition and comparison run.
func RunCurrent(root string, now time.Time) error {
	registry, _, err := ReadRegistry(root)
	if err != nil {
		return err
	}
	catalog, err := ReadCandidateCatalog(root, registry)
	if err != nil {
		return err
	}
	if _, err := InspectCandidateArchives(root); err != nil {
		return err
	}
	revision, err := conformance.CurrentRevision(root)
	if err != nil {
		return errors.New("current_revision")
	}
	snapshot, err := conformance.ProduceSnapshot(root, revision)
	if err != nil {
		return errors.New("current_candidate")
	}
	cutoff, err := readCurrentCutoff(root, now)
	if err != nil {
		return err
	}
	registryDigest, err := RegistryDigest(root)
	if err != nil {
		return err
	}
	observations, err := normalizeCurrentSources(root, registry, cutoff)
	if err != nil {
		return err
	}
	producers, err := runCurrentPeers(root, catalog)
	if err != nil {
		return err
	}
	evidence := DiscoveryEvidence{
		Schema: EvidenceSchema, MessageDraft: MessageDraft, DNSDraft: DNSDraft,
		BaseRevision: revision, CandidateSnapshotSHA256: snapshot.SHA256,
		RegistrySHA256: registryDigest, ObservationCutoff: cutoff.Format(time.RFC3339),
		Sources: observations, Candidates: catalog.Candidates, Availability: "eligible_not_runnable",
	}
	if err := evidence.Validate(registry, now); err != nil {
		return err
	}
	evidenceBytes, err := CanonicalJSON(evidence)
	if err != nil {
		return err
	}
	comparison, err := buildCurrentComparison(root, evidence, evidenceBytes, producers)
	if err != nil {
		return err
	}
	if err := comparison.Validate(evidence); err != nil {
		return err
	}
	comparisonBytes, err := CanonicalJSON(comparison)
	if err != nil {
		return err
	}
	if err := writeCurrentArtifact(root, currentEvidencePath, evidenceBytes); err != nil {
		return err
	}
	return writeCurrentArtifact(root, currentComparisonPath, comparisonBytes)
}

// runCurrentPeers builds both reviewed parser harnesses from their exact source
// archives and executes the resulting binaries in separate netless containers.
func runCurrentPeers(root string, catalog CandidateCatalog) (map[string]currentProducer, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, errors.New("comparison_root")
	}
	dockerHost, err := currentDockerHost()
	if err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp(
		filepath.Join(absoluteRoot, ".artifacts", "interop"),
		".peer-run.",
	)
	if err != nil {
		return nil, errors.New("comparison_state")
	}
	defer func() { _ = os.RemoveAll(work) }()
	dockerConfig := filepath.Join(work, "docker-config")
	dockerHome := filepath.Join(work, "home")
	outputDirectory := filepath.Join(work, "output")
	for _, directory := range []string{dockerConfig, dockerHome, outputDirectory} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			return nil, errors.New("comparison_state")
		}
	}
	if err := os.Chmod(outputDirectory, 0o733); err != nil {
		return nil, errors.New("comparison_state")
	}
	if err := os.WriteFile(
		filepath.Join(dockerConfig, "config.json"),
		[]byte("{\"auths\":{}}\n"),
		0o600,
	); err != nil {
		return nil, errors.New("comparison_state")
	}
	mailauthlens := candidateByID(catalog.Candidates, "mailauthlens")
	turscar := candidateByID(catalog.Candidates, "turscar-dkim2")
	peers := []currentPeer{
		{
			id:                  "mailauthlens",
			archive:             ".artifacts/interop/raw/search-candidates/mailauthlens-source.tar.gz",
			sourceDirectory:     "mailauthlens-" + mailauthlens.Revision,
			packagePath:         "./internal/dkim2",
			harness:             "testdata/interop/harness/mailauthlens_overlap_test.go",
			tests:               "^(TestDNSKeyFWS|TestSignatureFWS|TestSignatureMixedCaseObservation)$",
			expectedBuildSHA256: mailauthlens.BuildSHA256,
		},
		{
			id:                   "turscar-dkim2",
			archive:              ".artifacts/interop/raw/turscar-source.tar.gz",
			sourceDirectory:      "dkim2",
			packagePath:          ".",
			harness:              "testdata/interop/harness/turscar_overlap_test.go",
			tests:                "^(TestSignatureFWS|TestSignatureMixedCase)$",
			moduleCache:          ".artifacts/interop/sandbox/turscar-gopath/pkg/mod",
			expectedBuildSHA256:  turscar.BuildSHA256,
			expectedDependencyID: turscar.DependencySHA256,
		},
	}
	producers := make(map[string]currentProducer, len(peers))
	for _, peer := range peers {
		producer, err := buildCurrentPeer(
			absoluteRoot,
			outputDirectory,
			dockerConfig,
			dockerHome,
			dockerHost,
			peer,
		)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		arguments := peerContainerArguments(producer.path, peer.tests)
		command := exec.CommandContext(ctx, "docker", arguments...)
		command.Env = peerDockerEnvironment(dockerConfig, dockerHome, dockerHost)
		output := &boundedPeerOutput{}
		command.Stdout = output
		command.Stderr = output
		runErr := command.Run()
		timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
		cancel()
		if runErr != nil || timedOut {
			return nil, errors.New("comparison_execution")
		}
		producers[peer.id] = producer
	}
	return producers, nil
}

// buildCurrentPeer compiles one tracked harness from the validated immutable
// archive using only a verified offline dependency cache.
func buildCurrentPeer(
	root string,
	outputDirectory string,
	dockerConfig string,
	dockerHome string,
	dockerHost string,
	peer currentPeer,
) (currentProducer, error) {
	archive := filepath.Join(filepath.Dir(outputDirectory), peer.id+".source.tar.gz")
	harness := filepath.Join(filepath.Dir(outputDirectory), peer.id+".harness_test.go")
	output := filepath.Join(outputDirectory, peer.id+".test")
	for _, path := range []string{archive, harness, output, peer.sourceDirectory} {
		if strings.ContainsAny(path, ",\r\n") {
			return currentProducer{}, errors.New("comparison_producer")
		}
	}
	for _, input := range []struct {
		source string
		target string
		limit  int64
	}{
		{source: peer.archive, target: archive, limit: maxProducerBytes},
		{source: peer.harness, target: harness, limit: maxRegistryBytes},
	} {
		if err := copyPeerInput(root, input.source, input.target, input.limit); err != nil {
			return currentProducer{}, errors.New("comparison_producer")
		}
	}
	arguments := peerBuildArguments(root, outputDirectory, archive, harness, peer)
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "docker", arguments...)
	command.Env = peerDockerEnvironment(dockerConfig, dockerHome, dockerHost)
	result := &boundedPeerOutput{}
	command.Stdout = result
	command.Stderr = result
	if err := command.Run(); err != nil || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return currentProducer{}, errors.New("comparison_build")
	}
	if err := os.Chmod(output, 0o555); err != nil {
		return currentProducer{}, errors.New("comparison_producer")
	}
	file, err := os.Open(output)
	if err != nil {
		return currentProducer{}, errors.New("comparison_producer")
	}
	snapshot, snapshotErr := artifactpath.SnapshotOpenFile(file, maxProducerBytes)
	binaryFile, binaryErr := elf.NewFile(file)
	if binaryErr == nil {
		binaryErr = validatePeerELF(binaryFile)
	}
	closeErr := file.Close()
	if snapshotErr != nil || binaryErr != nil || closeErr != nil || snapshot.Size == 0 {
		return currentProducer{}, errors.New("comparison_producer")
	}
	return currentProducer{path: output, digest: snapshot.SHA256}, nil
}

// validatePeerELF requires a static linux/amd64 executable for the closed runner.
func validatePeerELF(file *elf.File) error {
	if file.Machine != elf.EM_X86_64 || file.Type != elf.ET_EXEC {
		return errors.New("comparison_platform")
	}
	for _, program := range file.Progs {
		if program.Type == elf.PT_INTERP {
			return errors.New("comparison_platform")
		}
	}
	return nil
}

// copyPeerInput captures one stable regular input into invocation-owned storage.
func copyPeerInput(root string, source string, target string, limit int64) error {
	input, err := artifactpath.OpenFile(root, source, limit)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(output, io.LimitReader(input, limit+1))
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil || written == 0 || written > limit {
		return errors.New("comparison_input")
	}
	return os.Chmod(target, 0o444)
}

// peerBuildArguments returns the closed external build sandbox contract.
func peerBuildArguments(
	root string,
	outputDirectory string,
	archive string,
	harness string,
	peer currentPeer,
) []string {
	source := "/work/source/" + peer.sourceDirectory
	packageDirectory := source
	if peer.packagePath != "." {
		packageDirectory += "/" + strings.TrimPrefix(peer.packagePath, "./")
	}
	script := "mkdir -p /work/source && " +
		"tar -xzf /source.tar.gz -C /work/source && " +
		"cp /harness_test.go " + packageDirectory + "/dkim2_interop_test.go && " +
		"chmod -R a-w " + source + " && " +
		"cd " + source + " && " +
		`printf '%s  %s\n' "$EXPECTED_BUILD_SHA256" go.mod | sha256sum -c - && `
	if peer.expectedDependencyID != "" {
		script += `printf '%s  %s\n' "$EXPECTED_DEPENDENCY_SHA256" go.sum | sha256sum -c - && ` +
			"go mod verify && "
	}
	script += "go test -c -vet=off -o /output/" + peer.id + ".test " + peer.packagePath
	arguments := []string{
		"run", "--rm", "--pull", "never",
		"--network", "none",
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", "256",
		"--memory", "2g",
		"--cpus", "2",
		"--ulimit", "nofile=64:64",
		"--ulimit", "fsize=134217728:134217728",
		"--user", "65534:65534",
		"--tmpfs", "/work:rw,nosuid,nodev,size=512m",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=512m",
		"--env", "HOME=/tmp",
		"--env", "TMPDIR=/tmp",
		"--env", "GOPATH=/gopath",
		"--env", "GOMODCACHE=/gopath/pkg/mod",
		"--env", "GOCACHE=/tmp/go-build",
		"--env", "GOTOOLCHAIN=local",
		"--env", "GOPROXY=off",
		"--env", "GOSUMDB=off",
		"--env", "GOWORK=off",
		"--env", "GOENV=off",
		"--env", "CGO_ENABLED=0",
		"--env", "GOOS=linux",
		"--env", "GOARCH=amd64",
		"--env", "EXPECTED_BUILD_SHA256=" + peer.expectedBuildSHA256,
		"--env", "EXPECTED_DEPENDENCY_SHA256=" + peer.expectedDependencyID,
		"--mount", "type=bind,src=" + archive + ",dst=/source.tar.gz,readonly",
		"--mount", "type=bind,src=" + harness + ",dst=/harness_test.go,readonly",
		"--mount", "type=bind,src=" + outputDirectory + ",dst=/output",
	}
	if peer.moduleCache != "" {
		cache := filepath.Join(root, filepath.FromSlash(peer.moduleCache))
		arguments = append(
			arguments,
			"--mount", "type=bind,src="+cache+",dst=/gopath/pkg/mod,readonly",
		)
	} else {
		arguments = append(arguments, "--tmpfs", "/gopath:rw,noexec,nosuid,nodev,size=16m")
	}
	return append(
		arguments,
		"--entrypoint", "/bin/sh",
		peerRunnerImage,
		"-c", script,
	)
}

// peerDockerEnvironment isolates Docker credentials while preserving only the
// validated local daemon endpoint and deterministic process basics.
func peerDockerEnvironment(dockerConfig string, dockerHome string, dockerHost string) []string {
	return []string{
		"DOCKER_CONFIG=" + dockerConfig,
		"DOCKER_HOST=" + dockerHost,
		"HOME=" + dockerHome,
		"LANG=C", "LC_ALL=C", "PATH=/usr/local/bin:/usr/bin:/bin",
	}
}

// currentDockerHost resolves and validates the active local Docker Unix socket
// before peer execution switches to an invocation-owned credential directory.
func currentDockerHost() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		"docker",
		"context",
		"inspect",
		"--format",
		"{{json .Endpoints.docker.Host}}",
	)
	output := &boundedPeerOutput{}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", errors.New("comparison_runtime")
	}
	var host string
	if err := json.Unmarshal(output.content, &host); err != nil {
		return "", errors.New("comparison_runtime")
	}
	const unixPrefix = "unix://"
	if !strings.HasPrefix(host, unixPrefix) {
		return "", errors.New("comparison_runtime")
	}
	socketPath := strings.TrimPrefix(host, unixPrefix)
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath {
		return "", errors.New("comparison_runtime")
	}
	info, err := os.Lstat(socketPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return "", errors.New("comparison_runtime")
	}
	return host, nil
}

// peerContainerArguments returns the closed external execution sandbox contract.
func peerContainerArguments(binary string, tests string) []string {
	return []string{
		"run", "--rm", "--pull", "never",
		"--network", "none",
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", "32",
		"--memory", "256m",
		"--cpus", "1",
		"--ulimit", "nofile=64:64",
		"--ulimit", "fsize=16777216:16777216",
		"--user", "65534:65534",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
		"--env", "HOME=/tmp",
		"--env", "TMPDIR=/tmp",
		"--mount", "type=bind,src=" + binary + ",dst=/peer.test,readonly",
		"--entrypoint", "/peer.test",
		peerRunnerImage,
		"-test.run", tests,
		"-test.count=1",
	}
}

// CurrentEvidenceSet owns validated normalized evidence and the exact bytes that were checked.
type CurrentEvidenceSet struct {
	Discovery      DiscoveryEvidence
	Comparison     ComparisonReport
	DiscoveryJSON  []byte
	ComparisonJSON []byte
}

// LoadCurrentEvidenceSet validates candidate-bound evidence without rereading bytes for identity.
func LoadCurrentEvidenceSet(
	root string,
	now time.Time,
) (CurrentEvidenceSet, error) {
	registry, _, err := ReadRegistry(root)
	if err != nil {
		return CurrentEvidenceSet{}, err
	}
	evidenceBytes, err := artifactpath.ReadFile(root, currentEvidencePath, maxRegistryBytes)
	if err != nil {
		return CurrentEvidenceSet{}, errors.New("current_evidence")
	}
	var evidence DiscoveryEvidence
	if err := strictDecodeCurrent(evidenceBytes, &evidence); err != nil {
		return CurrentEvidenceSet{}, err
	}
	if err := evidence.Validate(registry, now); err != nil {
		return CurrentEvidenceSet{}, err
	}
	registryDigest, err := RegistryDigest(root)
	if err != nil || evidence.RegistrySHA256 != registryDigest {
		return CurrentEvidenceSet{}, errors.New("current_registry")
	}
	catalog, err := ReadCandidateCatalog(root, registry)
	if err != nil || !reflect.DeepEqual(evidence.Candidates, catalog.Candidates) {
		return CurrentEvidenceSet{}, errors.New("current_catalog")
	}
	comparisonBytes, err := artifactpath.ReadFile(root, currentComparisonPath, maxRegistryBytes)
	if err != nil {
		return CurrentEvidenceSet{}, errors.New("current_comparison")
	}
	var comparison ComparisonReport
	if err := strictDecodeCurrent(comparisonBytes, &comparison); err != nil {
		return CurrentEvidenceSet{}, err
	}
	if comparison.EvidenceSHA256 != SHA256(evidenceBytes) {
		return CurrentEvidenceSet{}, errors.New("current_comparison")
	}
	if err := comparison.Validate(evidence); err != nil {
		return CurrentEvidenceSet{}, err
	}
	revision, err := conformance.CurrentRevision(root)
	if err != nil || revision != evidence.BaseRevision {
		return CurrentEvidenceSet{}, errors.New("current_revision")
	}
	snapshot, err := conformance.ProduceSnapshot(root, revision)
	if err != nil || snapshot.SHA256 != evidence.CandidateSnapshotSHA256 {
		return CurrentEvidenceSet{}, errors.New("current_candidate")
	}
	return CurrentEvidenceSet{
		Discovery:      evidence,
		Comparison:     comparison,
		DiscoveryJSON:  evidenceBytes,
		ComparisonJSON: comparisonBytes,
	}, nil
}

// ReadCurrentEvidence validates candidate-bound ignored discovery and comparison evidence.
func ReadCurrentEvidence(
	root string,
	now time.Time,
) (DiscoveryEvidence, ComparisonReport, error) {
	current, err := LoadCurrentEvidenceSet(root, now)
	if err != nil {
		return DiscoveryEvidence{}, ComparisonReport{}, err
	}
	return current.Discovery, current.Comparison, nil
}

// strictDecodeCurrent decodes one closed current-evidence document.
func strictDecodeCurrent(content []byte, target any) error {
	if err := strictjson.Decode(content, target, maxJSONDepth, maxJSONTokens); err != nil {
		return errors.New("current_json")
	}
	return nil
}

// normalizeCurrentSources hashes raw bytes and a bounded content-free file inventory.
func normalizeCurrentSources(
	root string,
	registry Registry,
	cutoff time.Time,
) ([]SourceObservation, error) {
	observations := make([]SourceObservation, 0, len(registry.Sources))
	for _, source := range registry.Sources {
		paths, exists := currentSourceFiles[source.ID]
		if !exists || len(paths) == 0 {
			return nil, errors.New("current_source")
		}
		files := make([]normalizedFile, 0, len(paths))
		for _, path := range paths {
			file, err := artifactpath.OpenFile(
				root,
				path,
				registry.RetrievalPolicy.MaxResponseBytes,
			)
			if err != nil {
				return nil, errors.New("current_source")
			}
			info, statErr := file.Stat()
			snapshot, snapshotErr := artifactpath.SnapshotOpenFile(
				file,
				registry.RetrievalPolicy.MaxResponseBytes,
			)
			closeErr := file.Close()
			if statErr != nil || snapshotErr != nil || closeErr != nil {
				return nil, errors.New("current_source")
			}
			age := cutoff.Sub(info.ModTime().UTC())
			if age < -time.Minute || age > 2*time.Hour {
				return nil, errors.New("current_source_freshness")
			}
			files = append(files, normalizedFile{
				Path: filepath.Base(path), SHA256: snapshot.SHA256, Size: snapshot.Size,
			})
		}
		normalized, err := CanonicalJSON(files)
		if err != nil {
			return nil, err
		}
		observations = append(observations, SourceObservation{
			ID: source.ID, State: "observed", ResponseSHA256: files[0].SHA256,
			NormalizedSHA256: SHA256(normalized),
		})
	}
	return observations, nil
}

// buildCurrentComparison binds only exact reviewed parser overlap.
func buildCurrentComparison(
	root string,
	evidence DiscoveryEvidence,
	evidenceBytes []byte,
	producers map[string]currentProducer,
) (ComparisonReport, error) {
	fixture, err := artifactpath.SnapshotFile(
		root, "testdata/interop/fixtures/mailauthlens-overlap.json", maxRegistryBytes,
	)
	if err != nil {
		return ComparisonReport{}, errors.New("comparison_fixture")
	}
	localProducer, err := digestRepositoryFiles(root, []string{
		"lib/internal/keyresolver/record.go",
		"lib/internal/signature/parser.go",
	})
	if err != nil {
		return ComparisonReport{}, err
	}
	mailauthlens, mailauthlensExists := producers["mailauthlens"]
	turscar, turscarExists := producers["turscar-dkim2"]
	if !mailauthlensExists || !turscarExists ||
		mailauthlens.digest == "" || turscar.digest == "" {
		return ComparisonReport{}, errors.New("comparison_producer")
	}
	stalwart := candidateByID(evidence.Candidates, "stalwart-mail-auth")
	if stalwart.SourceSHA256 == "" {
		return ComparisonReport{}, errors.New("comparison_candidate")
	}
	cases := []ComparisonCase{
		{
			CandidateID: "mailauthlens", CaseID: "dns-key-fws", Operation: "dns-key-parse",
			ClaimClass: "draft_normative", FixtureSHA256: fixture.SHA256,
			LocalProducer: localProducer, ExternalProducer: mailauthlens.digest, State: "agreement",
		},
		{
			CandidateID: "mailauthlens", CaseID: "signature-fws", Operation: "signature-parse",
			ClaimClass: "draft_normative", FixtureSHA256: fixture.SHA256,
			LocalProducer: localProducer, ExternalProducer: mailauthlens.digest, State: "agreement",
		},
		{
			CandidateID: "mailauthlens", CaseID: "signature-mixed-case", Operation: "signature-parse",
			ClaimClass: "documented_interpretation", FixtureSHA256: fixture.SHA256,
			LocalProducer: localProducer, ExternalProducer: mailauthlens.digest, State: "unsupported",
			Limitation: "documented-interpretation-differs",
		},
		{
			CandidateID: "stalwart-mail-auth", CaseID: "signature-parse",
			Operation: "signature-parse", ClaimClass: "external_observation",
			FixtureSHA256: fixture.SHA256, LocalProducer: localProducer,
			ExternalProducer: stalwart.SourceSHA256, State: "not_runnable",
			Limitation: "no-immutable-cargo-lock",
		},
		{
			CandidateID: "turscar-dkim2", CaseID: "signature-fws", Operation: "signature-parse",
			ClaimClass: "draft_normative", FixtureSHA256: fixture.SHA256,
			LocalProducer: localProducer, ExternalProducer: turscar.digest, State: "agreement",
		},
		{
			CandidateID: "turscar-dkim2", CaseID: "signature-mixed-case", Operation: "signature-parse",
			ClaimClass: "documented_interpretation", FixtureSHA256: fixture.SHA256,
			LocalProducer: localProducer, ExternalProducer: turscar.digest, State: "agreement",
		},
	}
	return ComparisonReport{
		Schema: ComparisonSchema, MessageDraft: MessageDraft, DNSDraft: DNSDraft,
		BaseRevision:            evidence.BaseRevision,
		CandidateSnapshotSHA256: evidence.CandidateSnapshotSHA256,
		RegistrySHA256:          evidence.RegistrySHA256, EvidenceSHA256: SHA256(evidenceBytes),
		ObservationCutoff: evidence.ObservationCutoff, Cases: cases,
		Availability: "eligible_not_runnable",
	}, nil
}

// candidateByID returns one catalog candidate or its zero value.
func candidateByID(candidates []Candidate, id string) Candidate {
	for _, candidate := range candidates {
		if candidate.ID == id {
			return candidate
		}
	}
	return Candidate{}
}

// digestRepositoryFiles frames exact producer files before hashing them.
func digestRepositoryFiles(root string, paths []string) (string, error) {
	framed := make([]byte, 0)
	var size [8]byte
	for _, path := range paths {
		content, err := artifactpath.ReadFile(root, path, maxProducerBytes)
		if err != nil {
			return "", errors.New("comparison_local_producer")
		}
		binary.BigEndian.PutUint64(size[:], uint64(len(path)))
		framed = append(framed, size[:]...)
		framed = append(framed, path...)
		binary.BigEndian.PutUint64(size[:], uint64(len(content)))
		framed = append(framed, size[:]...)
		framed = append(framed, content...)
	}
	return SHA256(framed), nil
}

// readCurrentCutoff requires the exact acquisition-owned external observation clock.
func readCurrentCutoff(root string, now time.Time) (time.Time, error) {
	content, err := artifactpath.ReadFile(root, currentCutoffPath, 64)
	if err != nil {
		return time.Time{}, errors.New("current_cutoff")
	}
	cutoff, parseErr := time.Parse(time.RFC3339, string(content))
	if parseErr != nil || cutoff.After(now.Add(time.Minute)) {
		return time.Time{}, errors.New("current_cutoff")
	}
	return cutoff, nil
}

// writeCurrentArtifact atomically replaces one fixed ignored evidence file.
func writeCurrentArtifact(root, relative string, content []byte) error {
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return errors.New("current_write")
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, content, 0o600); err != nil {
		return errors.New("current_write")
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return errors.New("current_write")
	}
	return nil
}
