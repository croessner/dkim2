package tools_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testDevRevision = "1111111111111111111111111111111111111111"

// TestDevPublisherRejectsStaleThirdSubjectBeforeRegistryMutation proves that
// direct script execution cannot publish after late local-evidence rejection.
func TestDevPublisherRejectsStaleThirdSubjectBeforeRegistryMutation(t *testing.T) {
	t.Parallel()
	root, logPath := prepareDevPublisherFixture(t, "stale-third")
	runRejectedDevPublisher(t, root, logPath)
}

// TestDevPublisherRejectsThirdTagCollisionBeforeRegistryMutation proves that
// every destination tag is preflighted before the first registry export.
func TestDevPublisherRejectsThirdTagCollisionBeforeRegistryMutation(t *testing.T) {
	t.Parallel()
	root, logPath := prepareDevPublisherFixture(t, "collision-third")
	runRejectedDevPublisher(t, root, logPath)
}

// prepareDevPublisherFixture creates a closed fake repository and command
// surface that records any attempted registry export.
func prepareDevPublisherFixture(t *testing.T, scenario string) (string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("publisher contract requires POSIX shell behavior")
	}
	repositoryRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for _, directory := range []string{
		filepath.Join(root, "scripts"),
		filepath.Join(root, "tools"),
		filepath.Join(root, ".artifacts", "image-evidence"),
		filepath.Join(root, "fakebin"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	copyExecutable(t,
		filepath.Join(repositoryRoot, "scripts", "publish-dev-images.sh"),
		filepath.Join(root, "scripts", "publish-dev-images.sh"),
	)
	for _, name := range []string{
		"build-images.sh",
		"inspect-images.sh",
		"test-image-runtime.sh",
	} {
		writeExecutable(t, filepath.Join(root, "scripts", name), "#!/bin/sh\nexit 0\n")
	}
	writeExecutable(t, filepath.Join(root, "fakebin", "git"), fakeGitCommand)
	writeExecutable(t, filepath.Join(root, "fakebin", "go"), fakeGoCommand)
	writeExecutable(t, filepath.Join(root, "fakebin", "docker"), fakeDockerCommand)
	writeOCIReports(t, root, scenario == "stale-third")
	return root, filepath.Join(root, "docker.log")
}

// runRejectedDevPublisher requires policy rejection and proves that the fake
// registry exporter was never invoked.
func runRejectedDevPublisher(t *testing.T, root string, logPath string) {
	t.Helper()
	command := exec.Command("/bin/sh", "scripts/publish-dev-images.sh")
	command.Dir = root
	command.Env = append(os.Environ(),
		"DKIM2_DEV_PUBLISH_APPROVED=true",
		"DKIM2_DEV_REGISTRY=docker.roessner-net.de/mail",
		"DKIM2_TEST_DOCKER_LOG="+logPath,
		"PATH="+filepath.Join(root, "fakebin")+":"+os.Getenv("PATH"),
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("publisher unexpectedly succeeded: %s", output)
	}
	content, readErr := os.ReadFile(logPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
	if strings.Contains(string(content), "REGISTRY_EXPORT") {
		t.Fatalf("registry export occurred after rejected preflight: %s", content)
	}
}

// writeOCIReports writes the three minimal descriptor projections consumed by
// the publisher test double, optionally making only the final product stale.
func writeOCIReports(t *testing.T, root string, staleThird bool) {
	t.Helper()
	index := []byte(`{"schemaVersion":2,"manifests":[{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":{"os":"linux","architecture":"amd64"}},{"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","platform":{"os":"linux","architecture":"arm64"}}]}`)
	sum := sha256.Sum256(index)
	for _, product := range []string{"dkim2d", "dkim2-milter", "dkim2ctl"} {
		revision := testDevRevision
		if staleThird && product == "dkim2ctl" {
			revision = strings.Repeat("9", 40)
		}
		report := map[string]any{
			"subject_digest": "sha256:" + hex.EncodeToString(sum[:]),
			"platforms": []map[string]string{
				{
					"platform":        "linux/amd64",
					"manifest_digest": "sha256:" + strings.Repeat("a", 64),
					"revision":        revision,
				},
				{
					"platform":        "linux/arm64",
					"manifest_digest": "sha256:" + strings.Repeat("b", 64),
					"revision":        revision,
				},
			},
		}
		content, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, ".artifacts", "image-evidence", product+".oci.json")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// copyExecutable copies one repository script into the isolated fixture.
func copyExecutable(t *testing.T, source string, target string) {
	t.Helper()
	content, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, target, string(content))
}

// writeExecutable installs one private executable fixture.
func writeExecutable(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
}

const fakeGitCommand = `#!/bin/sh
set -eu
case "$1" in
  status) exit 0 ;;
  rev-parse) printf '%s\n' "` + testDevRevision + `" ;;
  *) exit 2 ;;
esac
`

const fakeGoCommand = `#!/bin/sh
set -eu
case "$*" in
  *"./cmd/safepath"*"-directory .artifacts"*)
    mkdir -p .artifacts
    ;;
  *"./cmd/buildmeta"*)
    materialize=
    previous=
    for argument in "$@"; do
      if test "$previous" = -materialize; then materialize=$argument; fi
      previous=$argument
    done
    if test -n "$materialize"; then
      mkdir -p "$materialize/build/container"
      printf '%s\n' '{"images":[{"name":"buildkit","reference":"example.invalid/buildkit","digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]}' >"$materialize/build/container/build-inputs.json"
      : >"$materialize/build/container/Dockerfile"
    fi
    printf '%s\n' '{"schema":"dkim2-container-build-metadata-v1","version":"0.0.0-dev","revision":"` + testDevRevision + `","source_date_epoch":1,"created":"1970-01-01T00:00:01Z","dirty":"clean","candidate_snapshot_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}'
    ;;
  *"./cmd/imageevidence"*"-oci-version"*)
    product=
    previous=
    for argument in "$@"; do
      if test "$previous" = -oci-version; then product=$argument; fi
      previous=$argument
    done
    jq -e --arg revision "` + testDevRevision + `" 'all(.platforms[]; .revision == $revision)' ".artifacts/image-evidence/$product.oci.json" >/dev/null
    printf '%s\n' 0.0.0-dev
    ;;
  *) exit 2 ;;
esac
`

const fakeDockerCommand = `#!/bin/sh
set -eu
case "$1 $2" in
  "context inspect")
    printf '%s\n' unix:///var/run/docker.sock
    ;;
  "buildx create"|"buildx inspect"|"buildx rm")
    exit 0
    ;;
  "buildx imagetools")
    target=
    for argument in "$@"; do target=$argument; done
    case "$target" in
      *dkim2ctl:*)
        printf '%s' '{"schemaVersion":2,"manifests":[]}'
        ;;
      *)
        printf '%s\n' "$target manifest unknown: not found" >&2
        exit 1
        ;;
    esac
    ;;
  "buildx build")
    printf '%s\n' REGISTRY_EXPORT >>"$DKIM2_TEST_DOCKER_LOG"
    exit 0
    ;;
  *) exit 2 ;;
esac
`
