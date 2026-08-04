package httpjson

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
)

// TestDKIM2ctlGeneratedClientAgainstProductionBoundary crosses the built
// dkim2ctl generated client and the production generated daemon boundary.
func TestDKIM2ctlGeneratedClientAgainstProductionBoundary(t *testing.T) {
	processSecret := bytes.Repeat([]byte{0xa5}, 32)
	signSecret := bytes.Repeat([]byte{0xb6}, 32)
	reviseSecret := bytes.Repeat([]byte{0xc7}, 32)
	address, boundaryFacts := startDKIM2ctlProductionBoundary(
		t,
		processSecret,
		signSecret,
		reviseSecret,
	)
	probe := probeDKIM2ctlProductionBoundary(t, address, signSecret)
	if !probe.Valid() {
		t.Fatalf(
			"production boundary probe failed: status=%d cache=%t nosniff=%t close=%t type=%t length_header=%t length_field=%t transfer=%t json=%t operation=%t actions=%d",
			probe.status,
			probe.cache,
			probe.nosniff,
			probe.close,
			probe.contentType,
			probe.contentLengthHeader,
			probe.contentLengthField,
			probe.noTransferEncoding,
			probe.json,
			probe.operation,
			probe.actions,
		)
	}

	repository := dkim2ctlRepositoryRoot(t)
	binary := filepath.Join(t.TempDir(), "dkim2ctl")
	subprocessEnvironment := dkim2ctlClosedEnvironment(t, repository)
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("locate Go toolchain")
	}
	build := exec.CommandContext(
		t.Context(),
		goBinary,
		"-C",
		filepath.Join(repository, "cmd", "dkim2ctl"),
		"build",
		"-o",
		binary,
		".",
	)
	build.Env = subprocessEnvironment
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf(
			"build dkim2ctl generated client: class=failed output_bytes=%d",
			len(output),
		)
	}

	protected := t.TempDir()
	processCapability := writeDKIM2ctlCapability(
		t,
		protected,
		"process-capability",
		processSecret,
	)
	signCapability := writeDKIM2ctlCapability(
		t,
		protected,
		"sign-capability",
		signSecret,
	)
	reviseCapability := writeDKIM2ctlCapability(
		t,
		protected,
		"revise-capability",
		reviseSecret,
	)
	fixtures := filepath.Join(
		repository,
		"cmd",
		"dkim2ctl",
		"testdata",
		"fixtures",
		dkim2.DraftIdentifier,
	)
	command := exec.CommandContext(
		t.Context(),
		binary,
		"--server-url",
		"http://"+address,
		"--timeout",
		"10s",
		"--capability-file",
		processCapability,
		"--sign-capability-file",
		signCapability,
		"--revise-capability-file",
		reviseCapability,
		"fixture",
		"run",
		filepath.Join(fixtures, "process-report.json"),
		filepath.Join(fixtures, "sign.json"),
		filepath.Join(fixtures, "revise.json"),
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	command.Env = subprocessEnvironment
	if err := command.Run(); err != nil {
		errorClass, status := dkim2ctlOutputFailureClass(stdout.Bytes())
		t.Fatalf(
			"run dkim2ctl against production boundary: class=%s status=%d stdout_bytes=%d stderr_bytes=%d process_calls=%d sign_calls=%d revise_calls=%d",
			errorClass,
			status,
			stdout.Len(),
			stderr.Len(),
			boundaryFacts.processCalls.Load(),
			boundaryFacts.signCalls.Load(),
			boundaryFacts.reviseCalls.Load(),
		)
	}
	if stderr.Len() != 0 || strings.Count(stdout.String(), "\n") != 5 {
		t.Fatalf(
			"dkim2ctl subprocess output shape: stdout_bytes=%d stderr_bytes=%d records=%d",
			stdout.Len(),
			stderr.Len(),
			strings.Count(stdout.String(), "\n"),
		)
	}
	for _, expected := range []string{
		`"operation":"process","outcome":"match"`,
		`"operation":"sign","outcome":"match"`,
		`"operation":"revise","outcome":"match"`,
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatal("dkim2ctl subprocess omitted a required operation record")
		}
	}
	for _, protectedValue := range [][]byte{
		processSecret,
		signSecret,
		reviseSecret,
	} {
		if strings.Contains(
			stdout.String()+stderr.String(),
			base64.RawURLEncoding.EncodeToString(protectedValue),
		) {
			t.Fatal("dkim2ctl subprocess exposed a protected capability")
		}
	}
}

// startDKIM2ctlProductionBoundary launches the production listener, generated
// server, capability filters, domain processor, and operation adapter.
func startDKIM2ctlProductionBoundary(
	t *testing.T,
	processSecret []byte,
	signSecret []byte,
	reviseSecret []byte,
) (string, *dkim2ctlBoundaryFacts) {
	t.Helper()
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("loopback listeners are unavailable in this test environment")
	}
	tracked, err := newTrackedListener(raw, nil)
	if err != nil {
		_ = raw.Close()
		t.Fatalf("construct tracked production listener: %v", err)
	}
	validator, err := NewRequestValidator()
	if err != nil {
		_ = tracked.Close()
		t.Fatalf("construct production request validator: %v", err)
	}
	facts := &dkim2ctlBoundaryFacts{}
	processor := newDKIM2ctlInboundProcessor(t, facts)
	readiness := &boundaryReadiness{}
	readiness.ready.Store(true)
	handler, err := NewHTTPBoundary(
		BoundaryConfig{
			Authority:       raw.Addr().String(),
			RequestDeadline: 10 * time.Second,
			MaxInFlight:     1,
			MaxWaiters:      1,
			AdmissionWait:   time.Second,
		},
		&boundaryCapabilityMatcher{value: bytes.Clone(processSecret)},
		readiness,
		processor,
		&boundaryFatalNotifier{},
		validator,
		&dkim2ctlOperationService{facts: facts},
		signMatcherDependency{
			capabilityMatcher: &boundaryCapabilityMatcher{
				value: bytes.Clone(signSecret),
			},
		},
		reviseMatcherDependency{
			capabilityMatcher: &boundaryCapabilityMatcher{
				value: bytes.Clone(reviseSecret),
			},
		},
	)
	if err != nil {
		_ = tracked.Close()
		t.Fatalf("construct production HTTP boundary: %v", err)
	}
	server := &http.Server{
		Handler:                      handler,
		ConnContext:                  tracked.ConnContext,
		ErrorLog:                     log.New(io.Discard, "", 0),
		DisableGeneralOptionsHandler: true,
		MaxHeaderBytes:               transportServerMaxHeaderBytes,
	}
	done := make(chan struct{})
	go func() {
		_ = server.Serve(tracked)
		close(done)
	}()
	t.Cleanup(func() {
		handler.Close()
		_ = server.Close()
		_ = tracked.Close()
		<-done
	})
	return raw.Addr().String(), facts
}

type dkim2ctlBoundaryFacts struct {
	processCalls atomic.Int32
	signCalls    atomic.Int32
	reviseCalls  atomic.Int32
}

type dkim2ctlProbeFacts struct {
	status              int
	actions             int
	cache               bool
	nosniff             bool
	close               bool
	contentType         bool
	contentLengthHeader bool
	contentLengthField  bool
	noTransferEncoding  bool
	json                bool
	operation           bool
}

// Valid reports whether the production boundary preserved every client-facing
// transport and generated-response invariant in the probe.
func (f dkim2ctlProbeFacts) Valid() bool {
	return f.status == http.StatusOK &&
		f.actions == 2 &&
		f.cache &&
		f.nosniff &&
		f.close &&
		f.contentType &&
		f.contentLengthHeader &&
		f.contentLengthField &&
		f.noTransferEncoding &&
		f.json &&
		f.operation
}

// probeDKIM2ctlProductionBoundary observes only closed transport and generated
// response facts from one authentic protected sign request.
func probeDKIM2ctlProductionBoundary(
	t *testing.T,
	address string,
	signSecret []byte,
) dkim2ctlProbeFacts {
	t.Helper()
	body := `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04",` +
		`"message":{"raw_rfc5322_base64":"U3ViamVjdDogdGVzdA0KDQpib2R5DQo=",` +
		`"fidelity":"raw_rfc5322"},"smtp":{"mail_from":"<sender@example.test>",` +
		`"rcpt_to":["<recipient@example.test>"]},"context":{"tenant":"tenant-a",` +
		`"domain":"example.test"}}`
	request, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"http://"+address+signPath,
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatal("construct production boundary probe")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(
		"X-DKIM2-Capability",
		base64.RawURLEncoding.EncodeToString(signSecret),
	)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableCompression: true,
			DisableKeepAlives:  true,
			ForceAttemptHTTP2:  false,
		},
	}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("execute production boundary probe")
	}
	if response.Body == nil {
		t.Fatal("production boundary probe omitted response body")
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil {
		t.Fatal("consume production boundary probe")
	}
	var generatedResponse struct {
		Operation string `json:"operation"`
		Result    string `json:"result"`
		Actions   []struct {
			Name string `json:"name"`
		} `json:"actions"`
	}
	jsonOK := json.Unmarshal(responseBody, &generatedResponse) == nil
	contentLength := response.Header.Get("Content-Length")
	return dkim2ctlProbeFacts{
		status:              response.StatusCode,
		actions:             len(generatedResponse.Actions),
		cache:               response.Header.Get("Cache-Control") == "no-store",
		nosniff:             response.Header.Get("X-Content-Type-Options") == testNoSniffValue,
		close:               response.Close,
		contentType:         response.Header.Get("Content-Type") == "application/json",
		contentLengthHeader: contentLength != "",
		contentLengthField:  response.ContentLength == int64(len(responseBody)),
		noTransferEncoding:  len(response.TransferEncoding) == 0,
		json:                jsonOK,
		operation: generatedResponse.Operation == string(app.OperationSign) &&
			generatedResponse.Result == string(app.OperationPass),
	}
}

type dkim2ctlGoldenCorpus struct {
	Draft       string `json:"draft"`
	RSAModulus  string `json:"rsa_modulus_base64"`
	RSAExponent int    `json:"rsa_exponent"`
}

type dkim2ctlGoldenProvider struct {
	key *rsa.PublicKey
}

// LookupPublicKey returns the frozen public key for authentic process handling.
func (p dkim2ctlGoldenProvider) LookupPublicKey(
	_ context.Context,
	query dkim2.PublicKeyQuery,
) (dkim2.PublicKeyResult, error) {
	if query.Algorithm() != dkim2.AlgorithmRSASHA256 {
		return dkim2.MissingPublicKey(query.Algorithm()), nil
	}
	return dkim2.FoundRSAPublicKey(p.key), nil
}

type dkim2ctlFirstSeenStore struct {
	facts *dkim2ctlBoundaryFacts
}

// CheckAndRemember returns the deterministic successful replay-store outcome.
func (s dkim2ctlFirstSeenStore) CheckAndRemember(
	context.Context,
	dkim2.ReplayKey,
	dkim2.ReplayRetention,
) (dkim2.ReplayCheck, error) {
	if s.facts != nil {
		s.facts.processCalls.Add(1)
	}
	return dkim2.ReplayCheckFirstSeen, nil
}

// newDKIM2ctlInboundProcessor constructs an authentic verifier, policy, and
// enabled replay use case from the frozen public golden vector key.
func newDKIM2ctlInboundProcessor(
	t *testing.T,
	facts *dkim2ctlBoundaryFacts,
) *app.InboundProcessor {
	t.Helper()
	repository := dkim2ctlRepositoryRoot(t)
	corpusBytes, err := os.ReadFile(filepath.Join(
		repository,
		"lib",
		"testdata",
		"vectors",
		dkim2.DraftIdentifier,
		"public-golden.json",
	))
	if err != nil {
		t.Fatalf("read frozen public golden corpus: %v", err)
	}
	var corpus dkim2ctlGoldenCorpus
	if err := json.Unmarshal(corpusBytes, &corpus); err != nil ||
		corpus.Draft != dkim2.DraftIdentifier {
		t.Fatal("decode frozen public golden corpus")
	}
	modulus, err := base64.StdEncoding.Strict().DecodeString(corpus.RSAModulus)
	if err != nil {
		t.Fatal("decode frozen public golden modulus")
	}
	verifier, err := dkim2.NewVerifier(
		dkim2ctlGoldenProvider{
			key: &rsa.PublicKey{
				N: new(big.Int).SetBytes(modulus),
				E: corpus.RSAExponent,
			},
		},
		dkim2.WithVerificationClock(
			func() time.Time { return time.Unix(1_700_000_000, 0) },
		),
	)
	if err != nil {
		t.Fatalf("construct authentic verifier: %v", err)
	}
	domain, err := app.NewDomainProcessor(verifier, config.PolicyStrict)
	if err != nil {
		t.Fatalf("construct production domain processor: %v", err)
	}
	deriver, err := dkim2.NewReplayDeriver(bytes.Repeat([]byte{0xd8}, 32), 1)
	if err != nil {
		t.Fatalf("construct replay deriver: %v", err)
	}
	replay, err := app.NewEnabledReplayCoordinator(
		deriver,
		dkim2ctlFirstSeenStore{facts: facts},
		dkim2.DefaultReplayRetention(),
	)
	if err != nil {
		t.Fatalf("construct enabled replay coordinator: %v", err)
	}
	processor, err := app.NewInboundProcessor(domain, replay)
	if err != nil {
		t.Fatalf("construct inbound processor: %v", err)
	}
	return processor
}

type dkim2ctlOperationService struct {
	facts *dkim2ctlBoundaryFacts
}

// Sign returns deterministic originator mutation and no-mutation plans.
func (s *dkim2ctlOperationService) Sign(
	_ context.Context,
	request app.OperationRequest,
) (app.SigningAssessment, error) {
	if s != nil && s.facts != nil {
		s.facts.signCalls.Add(1)
	}
	if request.Tenant() == "tenant-no-mutation" {
		result, err := app.NewOperationResult(
			app.OperationSign,
			app.OperationPass,
			app.OperationContinue,
			nil,
		)
		if err != nil {
			return app.SigningAssessment{}, err
		}
		return app.NewApplicableSigningAssessment(result)
	}
	result, err := newDKIM2ctlOperationResult(
		app.OperationSign,
		"Message-Instance:v=1; i=1; h=sha256:synthetic\r\n",
		"DKIM2-Signature:v=1; a=ed25519-sha256; d=example.test; s=test; b=synthetic\r\n",
	)
	if err != nil {
		return app.SigningAssessment{}, err
	}
	return app.NewApplicableSigningAssessment(result)
}

// Revise returns deterministic changed- and unchanged-content mutation plans.
func (s *dkim2ctlOperationService) Revise(
	_ context.Context,
	request app.OperationRequest,
) (app.OperationResult, error) {
	if s != nil && s.facts != nil {
		s.facts.reviseCalls.Add(1)
	}
	if request.Tenant() == "tenant-unchanged" {
		return newDKIM2ctlOperationResult(
			app.OperationRevise,
			"DKIM2-Signature:v=1; a=ed25519-sha256; d=example.test; s=test; b=unchanged\r\n",
		)
	}
	return newDKIM2ctlOperationResult(
		app.OperationRevise,
		"Message-Instance:v=1; i=2; h=sha256:synthetic\r\n",
		"DKIM2-Signature:v=1; a=ed25519-sha256; d=example.test; s=test; b=changed\r\n",
	)
}

// SignDeliveryStatus keeps the ordinary dkim2ctl integration fixture closed for DSN requests.
func (*dkim2ctlOperationService) SignDeliveryStatus(
	context.Context,
	app.DeliveryStatusRequest,
) (app.OperationResult, error) {
	return app.NewOperationResult(
		app.OperationDeliveryStatus, app.OperationPermerror, app.OperationReject, nil,
	)
}

// newDKIM2ctlOperationResult constructs one exact successful operation plan.
func newDKIM2ctlOperationResult(
	operation app.Operation,
	values ...string,
) (app.OperationResult, error) {
	fields := make([]app.CompletedField, len(values))
	for index := range values {
		field, err := app.NewCompletedField([]byte(values[index]))
		if err != nil {
			return app.OperationResult{}, err
		}
		fields[index] = field
	}
	return app.NewOperationResult(
		operation,
		app.OperationPass,
		app.OperationAccept,
		fields,
	)
}

// writeDKIM2ctlCapability creates one owner-only protected test capability.
func writeDKIM2ctlCapability(
	t *testing.T,
	directory string,
	name string,
	value []byte,
) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatalf("write protected test capability: %v", err)
	}
	return path
}

// dkim2ctlRepositoryRoot derives the workspace root from this test source.
func dkim2ctlRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("derive repository root")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "../../../.."))
}

// dkim2ctlClosedEnvironment returns the minimal subprocess environment used by
// both the Go build and the generated-client execution.
func dkim2ctlClosedEnvironment(t *testing.T, repository string) []string {
	t.Helper()
	environment := []string{
		"GOENV=off",
		"GOTOOLCHAIN=local",
		"GOWORK=" + filepath.Join(repository, "go.work"),
		"HOME=" + t.TempDir(),
		"TMPDIR=" + t.TempDir(),
		"GOCACHE=" + t.TempDir(),
	}
	switch runtime.GOOS {
	case "darwin":
		compiler, err := exec.LookPath("cc")
		if err != nil {
			t.Skip("portable C compiler is unavailable for Darwin ACL checks")
		}
		environment = append(
			environment,
			"CC="+compiler,
			"CGO_ENABLED=1",
		)
	case "linux":
		environment = append(environment, "CGO_ENABLED=0")
	default:
		t.Skip("protected capability loading is unsupported on this platform")
	}
	return environment
}

// dkim2ctlOutputFailureClass extracts only one closed class and status from a
// subprocess record without publishing any retained record content.
func dkim2ctlOutputFailureClass(output []byte) (string, int) {
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var record struct {
			ErrorClass *string `json:"error_class"`
			HTTPStatus *int    `json:"http_status"`
		}
		if json.Unmarshal(line, &record) != nil {
			return "invalid-record", 0
		}
		if record.ErrorClass == nil {
			continue
		}
		switch *record.ErrorClass {
		case "usage", "fixture", "capability", "transport", "contract",
			"mismatch", "internal":
		default:
			return "unknown", 0
		}
		if record.HTTPStatus == nil {
			return *record.ErrorClass, 0
		}
		return *record.ErrorClass, *record.HTTPStatus
	}
	return "missing-error", 0
}
