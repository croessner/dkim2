package tools_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const composePolicyLimit = 1 << 20
const qualificationCapChown = "CHOWN"
const qualificationCapDACOverride = "DAC_OVERRIDE"
const qualificationCapFOwner = "FOWNER"

type qualificationCompose struct {
	Services map[string]qualificationService `yaml:"services"`
	Volumes  map[string]map[string]any       `yaml:"volumes"`
	Networks map[string]qualificationNetwork `yaml:"networks"`
}

type qualificationService struct {
	Build         qualificationBuild  `yaml:"build"`
	Platform      string              `yaml:"platform"`
	Command       []string            `yaml:"command"`
	User          string              `yaml:"user,omitempty"`
	ReadOnly      bool                `yaml:"read_only"`
	CapDrop       []string            `yaml:"cap_drop"`
	CapAdd        []string            `yaml:"cap_add,omitempty"`
	SecurityOpt   []string            `yaml:"security_opt,omitempty"`
	Tmpfs         []string            `yaml:"tmpfs"`
	Volumes       []string            `yaml:"volumes"`
	Networks      []string            `yaml:"networks,omitempty"`
	NetworkMode   string              `yaml:"network_mode,omitempty"`
	DNS           []string            `yaml:"dns,omitempty"`
	DependsOn     map[string]any      `yaml:"depends_on,omitempty"`
	Healthcheck   qualificationHealth `yaml:"healthcheck,omitempty"`
	PidsLimit     int                 `yaml:"pids_limit"`
	MemoryLimit   string              `yaml:"mem_limit"`
	CPUs          float64             `yaml:"cpus"`
	Ports         []string            `yaml:"ports,omitempty"`
	Privileged    bool                `yaml:"privileged,omitempty"`
	PID           string              `yaml:"pid,omitempty"`
	ExtraHosts    []string            `yaml:"extra_hosts,omitempty"`
	ContainerName string              `yaml:"container_name,omitempty"`
}

type qualificationBuild struct {
	Context    string            `yaml:"context"`
	Dockerfile string            `yaml:"dockerfile"`
	Target     string            `yaml:"target"`
	Pull       bool              `yaml:"pull"`
	Arguments  map[string]string `yaml:"args"`
}

type qualificationHealth struct {
	Test        []string `yaml:"test"`
	Interval    string   `yaml:"interval"`
	Timeout     string   `yaml:"timeout"`
	Retries     int      `yaml:"retries"`
	StartPeriod string   `yaml:"start_period"`
}

type qualificationNetwork struct {
	Internal bool `yaml:"internal"`
}

// TestPostfixQualificationComposePolicy freezes isolated least-authority topology.
func TestPostfixQualificationComposePolicy(t *testing.T) {
	compose := loadQualificationCompose(t)
	if len(compose.Services) != 3 ||
		len(compose.Volumes) != 3 ||
		len(compose.Networks) != 1 ||
		!compose.Networks["qualification"].Internal {
		t.Fatal("qualification topology escaped its closed inventory")
	}
	for name, service := range compose.Services {
		assertQualificationServicePolicy(t, name, service)
	}
	if compose.Services["daemon"].NetworkMode != "" ||
		compose.Services["stack"].NetworkMode != "service:daemon" ||
		len(compose.Services["stack"].Networks) != 0 ||
		!slicesContainExact(compose.Services["daemon"].DNS, "127.0.0.1") {
		t.Fatal("daemon loopback namespace policy was not explicit")
	}
	if !slicesContainExact(compose.Services["daemon"].Volumes, "daemon-jail:/jail") {
		t.Fatal("daemon protected chroot did not use one project-scoped local volume")
	}
	if !slicesContainExact(compose.Services["stack"].Volumes, "milter-jail:/milter-jail") {
		t.Fatal("Milter protected chroot did not use one project-scoped local volume")
	}
	if !exactStringSet(
		compose.Services["bootstrap"].CapAdd,
		[]string{qualificationCapChown, qualificationCapDACOverride, qualificationCapFOwner},
	) {
		t.Fatal("bootstrap capability allowlist was not exact")
	}
	if compose.Services["daemon"].User != "0:0" ||
		!exactStringSet(
			compose.Services["daemon"].CapAdd,
			[]string{
				qualificationCapChown, qualificationCapDACOverride,
				qualificationCapFOwner, "NET_BIND_SERVICE",
				"SETGID", "SETUID", "SYS_CHROOT",
			},
		) {
		t.Fatal("daemon chroot bootstrap authority was not exact")
	}
	assertQualificationStackCapabilities(t, compose.Services["stack"].CapAdd)
}

// assertQualificationServicePolicy checks one closed Compose service surface.
func assertQualificationServicePolicy(
	t *testing.T,
	name string,
	service qualificationService,
) {
	t.Helper()
	if service.Build.Context != "../../.." ||
		service.Build.Dockerfile != "contrib/qualification/postfix-milter/Dockerfile" ||
		service.Build.Target == "" ||
		service.Build.Pull ||
		service.Platform != "linux/amd64" ||
		len(service.Build.Arguments) != 3 ||
		!service.ReadOnly ||
		service.Privileged ||
		!exactStringSet(service.SecurityOpt, []string{"no-new-privileges:true"}) ||
		len(service.Ports) != 0 ||
		service.PID != "" ||
		len(service.ExtraHosts) != 0 ||
		service.ContainerName != "" ||
		service.PidsLimit < 1 ||
		service.MemoryLimit == "" ||
		service.CPUs <= 0 ||
		!slicesContainExact(service.CapDrop, "ALL") {
		t.Fatalf("service %s violated the static qualification policy", name)
	}
	for _, volume := range service.Volumes {
		if strings.Contains(volume, "/var/run/docker.sock") ||
			strings.HasPrefix(volume, "/") {
			t.Fatalf("service %s used a host or Docker-socket mount", name)
		}
	}
}

// assertQualificationStackCapabilities checks the explicit stack allowlist.
func assertQualificationStackCapabilities(t *testing.T, capabilities []string) {
	t.Helper()
	for _, capability := range capabilities {
		switch capability {
		case qualificationCapChown, qualificationCapDACOverride,
			qualificationCapFOwner, "KILL", "NET_BIND_SERVICE",
			"SETGID", "SETUID", "SYS_CHROOT":
		default:
			t.Fatalf("stack requested unapproved capability %q", capability)
		}
	}
}

// TestPostfixQualificationPinsBuildInputsAndCleanup freezes supply-chain and ownership rules.
func TestPostfixQualificationPinsBuildInputsAndCleanup(t *testing.T) {
	dockerfile := readQualificationFile(t, "Dockerfile", 1<<16)
	for _, identity := range []string{
		"golang@sha256:ae5a2316d12f3e78fd99177dad452e6ad4f240af2d71d57b480c3477f250fec6",
		"debian@sha256:4e401d95de7083948053197a9c3913343cd06b706bf15eb6a0c3ccd26f436a0e",
		"chrroessner/postfix@sha256:8ccda0e26bb241116c7df5e0fb2bcdbc6a77b409b085d87e7ad4d0c23b0c41fd",
	} {
		if !bytes.Contains(dockerfile, []byte(identity)) {
			t.Fatalf("Dockerfile omitted pinned identity %q", identity)
		}
	}
	for _, forbidden := range [][]byte{
		[]byte(":latest"), []byte("apt-get"), []byte("apk add"),
		[]byte("curl "), []byte("wget "),
	} {
		if bytes.Contains(dockerfile, forbidden) {
			t.Fatal("Dockerfile used a mutable or network package input")
		}
	}
	if !bytes.Contains(
		dockerfile,
		[]byte("COPY cmd/dkim2-exim/go.mod cmd/dkim2-exim/go.sum ./cmd/dkim2-exim/"),
	) {
		t.Fatal("Dockerfile omitted Exim module metadata required by go.work")
	}
	run := readQualificationFile(t, "run.sh", 1<<16)
	for _, required := range [][]byte{
		[]byte("project=dkim2-postfix-qualification"),
		[]byte("validate_output_root"),
		[]byte(`.artifacts/*/*`),
		[]byte(`test ! -L .artifacts`),
		[]byte(`test ! -L "$output_root"`),
		[]byte("down --volumes --remove-orphans"),
		[]byte("trap cleanup EXIT HUP INT TERM"),
		[]byte(`--project-name "$project"`),
		[]byte(`label=com.docker.compose.project=$project`),
		[]byte("prove_injected_failure_cleanup"),
		[]byte("run_bounded_exec"),
		[]byte(`docker exec "$container"`),
		[]byte(`.schema == "dkim2.candidate-snapshot.v1"`),
		[]byte(`(.sha256 | test("^[0-9a-f]{64}$"))`),
		[]byte("daemon-identity"),
		[]byte(`docker pull "$expected_digest"`),
		[]byte("producer_sha256: $producer"),
		[]byte(`cmp "$output_root/run-1/report.json" "$output_root/run-2/report.json"`),
	} {
		if !bytes.Contains(run, required) {
			t.Fatal("qualification runner omitted project-scoped repeatability evidence")
		}
	}
	runtime := readQualificationFile(t, filepath.Join("cmd", "qualify", "main.go"), 1<<20)
	for _, required := range [][]byte{
		[]byte(`syscall.Chroot(jail)`),
		[]byte(`Chroot:     milterJail`),
		[]byte(`syscall.Setgroups([]int{})`),
		[]byte(`syscall.Setgid(daemonUID)`),
		[]byte(`syscall.Setuid(daemonUID)`),
		[]byte(`err = emitIdentity([]string{"dkim2d"}, false)`),
		[]byte(`"milter_connect_timeout=2s"`),
		[]byte(`"milter_command_timeout=5s"`),
		[]byte(`"milter_content_timeout=5s"`),
		[]byte(`os.ReadFile("/proc/net/tcp6")`),
		[]byte(`context.WithTimeout(context.Background(), 10*time.Second)`),
		[]byte(`exec.CommandContext(`),
		[]byte(`block += "\n  dsn_domain: " + signingDomain`),
	} {
		if !bytes.Contains(runtime, required) {
			t.Fatal("daemon runtime omitted chroot or privilege-drop evidence")
		}
	}
	for _, forbidden := range [][]byte{
		[]byte("docker system prune"), []byte("docker volume prune"),
		[]byte("eval "), []byte("--privileged"), []byte("--network host"),
		[]byte("m18"),
	} {
		if bytes.Contains(run, forbidden) {
			t.Fatal("qualification runner contained a forbidden operation")
		}
	}
	composeInput := readQualificationFile(t, "compose.yaml", composePolicyLimit)
	if bytes.Contains(composeInput, []byte("m18")) {
		t.Fatal("qualification Compose file used a transient milestone name")
	}
	ignore := readQualificationFile(t, "Dockerfile.dockerignore", 1<<16)
	for _, required := range [][]byte{
		[]byte("**\n"), []byte("!lib/**"), []byte("!cmd/dkim2d/**"),
		[]byte("!cmd/dkim2-milter/**"),
		[]byte("!cmd/dkim2-exim/go.mod"),
		[]byte("!cmd/dkim2-exim/go.sum"),
		[]byte("!contrib/qualification/postfix-milter/cmd/qualify/main.go"),
	} {
		if !bytes.Contains(ignore, required) {
			t.Fatal("Docker build context was not closed to qualification inputs")
		}
	}
	productIgnore := readRepositoryFile(t, ".dockerignore", 1<<16)
	if bytes.Contains(productIgnore, []byte("!contrib/")) {
		t.Fatal("product image context admitted qualification inputs")
	}
}

// FuzzPostfixQualificationComposeDecoding exercises bounded strict YAML decoding.
func FuzzPostfixQualificationComposeDecoding(f *testing.F) {
	input, err := os.ReadFile(qualificationPath("compose.yaml"))
	if err == nil {
		f.Add(input)
	}
	f.Add([]byte("services: {}\n"))
	f.Fuzz(func(_ *testing.T, input []byte) {
		if len(input) > composePolicyLimit+1 {
			input = input[:composePolicyLimit+1]
		}
		_, _ = decodeQualificationCompose(input)
	})
}

// loadQualificationCompose reads and validates one bounded Compose document.
func loadQualificationCompose(t *testing.T) qualificationCompose {
	t.Helper()
	input := readQualificationFile(t, "compose.yaml", composePolicyLimit)
	compose, err := decodeQualificationCompose(input)
	if err != nil {
		t.Fatalf("qualification Compose decode failed: %v", err)
	}
	return compose
}

// decodeQualificationCompose rejects unknown, duplicate, trailing, and oversized YAML.
func decodeQualificationCompose(input []byte) (qualificationCompose, error) {
	if len(input) == 0 || len(input) > composePolicyLimit {
		return qualificationCompose{}, errors.New("compose_size")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(input))
	decoder.KnownFields(true)
	var compose qualificationCompose
	if err := decoder.Decode(&compose); err != nil {
		return qualificationCompose{}, errors.New("compose_yaml")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return qualificationCompose{}, errors.New("compose_trailing")
	}
	return compose, nil
}

// readQualificationFile reads one regular qualification artifact under a fixed bound.
func readQualificationFile(t *testing.T, name string, limit int64) []byte {
	t.Helper()
	return readBoundedRegularFile(t, qualificationPath(name), limit)
}

// readRepositoryFile reads one fixed repository-root artifact under a fixed bound.
func readRepositoryFile(t *testing.T, name string, limit int64) []byte {
	t.Helper()
	return readBoundedRegularFile(t, filepath.Join("..", name), limit)
}

// readBoundedRegularFile rejects nonregular and oversized static-policy inputs.
func readBoundedRegularFile(t *testing.T, path string, limit int64) []byte {
	t.Helper()
	state, err := os.Lstat(path)
	if err != nil || !state.Mode().IsRegular() || state.Size() < 1 || state.Size() > limit {
		t.Fatal("qualification policy input was not one bounded regular file")
	}
	input, err := os.ReadFile(path)
	if err != nil || int64(len(input)) != state.Size() {
		t.Fatal("qualification policy input read failed")
	}
	return input
}

// qualificationPath resolves one durable qualification artifact.
func qualificationPath(name string) string {
	return filepath.Join("..", "contrib", "qualification", "postfix-milter", name)
}

// slicesContainExact checks one closed scalar list.
func slicesContainExact(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// exactStringSet compares one small capability allowlist without order dependence.
func exactStringSet(values, wanted []string) bool {
	if len(values) != len(wanted) {
		return false
	}
	for _, value := range wanted {
		if !slicesContainExact(values, value) {
			return false
		}
	}
	return true
}
