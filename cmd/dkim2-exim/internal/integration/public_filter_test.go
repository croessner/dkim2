//go:build linux || darwin

// Package integration exercises the public one-shot Exim filter executable.
package integration

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/evidence"
	generatedfixture "github.com/croessner/dkim2/cmd/dkim2-exim/internal/integration/generated"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/testsupport"
	"golang.org/x/sys/unix"
)

const publicFilterTimeout = 15 * time.Second
const publicTenant = "tenant"

var publicExecutablePath string

// TestMain builds the real executable once for public transport-filter tests.
func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", ".dkim2-exim-integration-")
	if err != nil {
		os.Exit(1)
	}
	publicExecutablePath = filepath.Join(directory, "dkim2-exim")
	command := exec.Command("go", "build", "-o", publicExecutablePath, "../..")
	if output, buildErr := command.CombinedOutput(); buildErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "integration executable build failed: %s\n", output)
		_ = os.RemoveAll(directory)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(directory)
	os.Exit(code)
}

// generatedDaemonService returns test-owned filter responses through generated DTOs.
type generatedDaemonService struct {
	sign   func(generatedfixture.SignRequest) generatedfixture.OperationResponse
	revise func(generatedfixture.ReviseRequest) generatedfixture.OperationResponse
}

// SignDeliveryStatus rejects DSN signing because this Exim fixture has no
// delivery-status evidence source or DSN capability.
func (*generatedDaemonService) SignDeliveryStatus(
	context.Context,
	generatedfixture.SignDeliveryStatusRequestObject,
) (generatedfixture.SignDeliveryStatusResponseObject, error) {
	return nil, errors.New("unexpected fixture operation")
}

// GetHealth rejects an operation outside the filter fixture.
func (*generatedDaemonService) GetHealth(
	context.Context,
	generatedfixture.GetHealthRequestObject,
) (generatedfixture.GetHealthResponseObject, error) {
	return nil, errors.New("unexpected fixture operation")
}

// HeadHealth rejects an operation outside the filter fixture.
func (*generatedDaemonService) HeadHealth(
	context.Context,
	generatedfixture.HeadHealthRequestObject,
) (generatedfixture.HeadHealthResponseObject, error) {
	return nil, errors.New("unexpected fixture operation")
}

// GetMetrics rejects an operation outside the filter fixture.
func (*generatedDaemonService) GetMetrics(
	context.Context,
	generatedfixture.GetMetricsRequestObject,
) (generatedfixture.GetMetricsResponseObject, error) {
	return nil, errors.New("unexpected fixture operation")
}

// GetReadiness rejects an operation outside the filter fixture.
func (*generatedDaemonService) GetReadiness(
	context.Context,
	generatedfixture.GetReadinessRequestObject,
) (generatedfixture.GetReadinessResponseObject, error) {
	return nil, errors.New("unexpected fixture operation")
}

// HeadReadiness rejects an operation outside the filter fixture.
func (*generatedDaemonService) HeadReadiness(
	context.Context,
	generatedfixture.HeadReadinessRequestObject,
) (generatedfixture.HeadReadinessResponseObject, error) {
	return nil, errors.New("unexpected fixture operation")
}

// ProcessMessage rejects an operation outside the filter fixture.
func (*generatedDaemonService) ProcessMessage(
	context.Context,
	generatedfixture.ProcessMessageRequestObject,
) (generatedfixture.ProcessMessageResponseObject, error) {
	return nil, errors.New("unexpected fixture operation")
}

// ReviseMessage returns one test-owned response through generated serialization.
func (s *generatedDaemonService) ReviseMessage(
	_ context.Context,
	request generatedfixture.ReviseMessageRequestObject,
) (generatedfixture.ReviseMessageResponseObject, error) {
	if s == nil || s.revise == nil || request.Body == nil {
		return nil, errors.New("unexpected fixture operation")
	}
	body := s.revise(*request.Body)
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, errors.New("fixture encoding failure")
	}
	return generatedfixture.ReviseMessage200JSONResponse{
		Body: body,
		Headers: generatedfixture.ReviseMessage200ResponseHeaders{
			ContentLength: strconv.Itoa(len(encoded) + 1),
		},
	}, nil
}

// SignMessage returns one test-owned response through generated serialization.
func (s *generatedDaemonService) SignMessage(
	_ context.Context,
	request generatedfixture.SignMessageRequestObject,
) (generatedfixture.SignMessageResponseObject, error) {
	if s == nil || s.sign == nil || request.Body == nil {
		return nil, errors.New("unexpected fixture operation")
	}
	body := s.sign(*request.Body)
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, errors.New("fixture encoding failure")
	}
	return generatedfixture.SignMessage200JSONResponse{
		Body: body,
		Headers: generatedfixture.SignMessage200ResponseHeaders{
			ContentLength: strconv.Itoa(len(encoded) + 1),
		},
	}, nil
}

// daemonFixture owns one generated loopback fixture.
type daemonFixture struct {
	endpoint string
	server   *http.Server
	listener net.Listener
}

// newGeneratedDaemonFixture starts the strict generated route and DTO boundary.
func newGeneratedDaemonFixture(
	t *testing.T,
	service *generatedDaemonService,
	calls *atomic.Int64,
) *daemonFixture {
	t.Helper()
	expectedCapability := base64.RawURLEncoding.EncodeToString(
		bytes.Repeat([]byte{0xa5}, 32),
	)
	middleware := func(
		next generatedfixture.StrictHandlerFunc,
		operationID string,
	) generatedfixture.StrictHandlerFunc {
		return func(
			ctx context.Context,
			writer http.ResponseWriter,
			request *http.Request,
			input any,
		) (any, error) {
			expectedPath := ""
			switch operationID {
			case "SignMessage":
				expectedPath = "/v1/sign"
			case "ReviseMessage":
				expectedPath = "/v1/revise"
			default:
				return nil, errors.New("invalid generated fixture operation")
			}
			if request.Method != http.MethodPost ||
				request.URL.Path != expectedPath ||
				request.Header.Get("X-DKIM2-Capability") != expectedCapability ||
				request.Header.Get("Authorization") != "" ||
				request.Header.Get("Cookie") != "" ||
				request.Header.Get("Accept") != "application/json" ||
				request.Header.Get("Cache-Control") != "no-store" ||
				request.Header.Get("User-Agent") != "dkim2-exim/1" {
				return nil, errors.New("invalid generated fixture request")
			}
			calls.Add(1)
			return next(ctx, writer, request, input)
		}
	}
	strict := generatedfixture.NewStrictHandler(
		service,
		[]generatedfixture.StrictMiddlewareFunc{middleware},
	)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("generated fixture listen failed")
	}
	server := &http.Server{
		Handler: generatedfixture.HandlerFromMux(
			strict,
			http.NewServeMux(),
		),
		ReadHeaderTimeout: time.Second,
	}
	fixture := &daemonFixture{
		endpoint: "http://" + listener.Addr().String(),
		server:   server,
		listener: listener,
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	return fixture
}

// TestPublicExecutableGeneratedSignFlow proves actual config, capability,
// generated HTTP, stdin/stdout pipes, and complete LF transformation.
func TestPublicExecutableGeneratedSignFlow(t *testing.T) {
	var calls atomic.Int64
	fixture := newGeneratedDaemonFixture(t, &generatedDaemonService{
		sign: func(request generatedfixture.SignRequest) generatedfixture.OperationResponse {
			sender, err := request.Smtp.MailFrom.Bytes()
			if err != nil || string(sender) != "<sender@example.test>" ||
				len(request.Smtp.RcptTo) != 1 {
				t.Error("generated fixture received incorrect outgoing authority")
			}
			clear(sender)
			return signedResponse()
		},
	}, &calls)
	configPath := writeSignConfig(t, fixture.endpoint)
	input := []byte("Subject: public\n\nbody")
	command := publicSignFilterCommand(t, configPath, input)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		exitCode := -1
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			exitCode = exitError.ExitCode()
		}
		t.Fatalf(
			"public filter sign invocation failed class=%d calls=%d stderr-bytes=%d",
			exitCode,
			calls.Load(),
			stderr.Len(),
		)
	}
	want := []byte(
		"Subject: public\n" +
			"Message-Instance: i=1; m=public\n" +
			"DKIM2-Signature: i=1; s=public\n\n" +
			"body\n",
	)
	if !bytes.Equal(stdout.Bytes(), want) || stderr.Len() != 0 ||
		calls.Load() != 1 {
		t.Fatal("public filter sign output or protocol purity changed")
	}
}

// TestPublicExecutableGeneratedReviseFlow proves the real executable loads
// authenticated incoming evidence while preserving distinct outgoing authority.
func TestPublicExecutableGeneratedReviseFlow(t *testing.T) {
	var calls atomic.Int64
	fixture := newGeneratedDaemonFixture(t, &generatedDaemonService{
		revise: func(request generatedfixture.ReviseRequest) generatedfixture.OperationResponse {
			incomingSender, incomingErr := request.IncomingSmtp.MailFrom.Bytes()
			outgoingSender, outgoingErr := request.Smtp.MailFrom.Bytes()
			var incomingRecipient, outgoingRecipient []byte
			if len(request.IncomingSmtp.RcptTo) == 1 {
				incomingRecipient, incomingErr = request.IncomingSmtp.RcptTo[0].Bytes()
			}
			if len(request.Smtp.RcptTo) == 1 {
				outgoingRecipient, outgoingErr = request.Smtp.RcptTo[0].Bytes()
			}
			defer clear(incomingSender)
			defer clear(outgoingSender)
			defer clear(incomingRecipient)
			defer clear(outgoingRecipient)
			if incomingErr != nil || outgoingErr != nil ||
				string(incomingSender) != "<incoming-marker@example.test>" ||
				string(outgoingSender) != "<outgoing-marker@example.test>" ||
				string(incomingRecipient) != "<incoming-recipient-marker@example.net>" ||
				string(outgoingRecipient) != "<outgoing-recipient-marker@example.net>" {
				t.Error("generated fixture conflated incoming and outgoing authority")
			}
			return revisedResponse()
		},
	}, &calls)
	configPath, locator := writeReviseConfig(t, fixture.endpoint)
	input := []byte("Subject: public revise\n\nbody")
	command := publicReviseFilterCommand(t, configPath, locator, input)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		exitCode := -1
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			exitCode = exitError.ExitCode()
		}
		t.Fatalf(
			"public filter revise invocation failed class=%d calls=%d stderr-bytes=%d",
			exitCode,
			calls.Load(),
			stderr.Len(),
		)
	}
	want := []byte(
		"Subject: public revise\n" +
			"DKIM2-Signature: i=2; s=public\n\n" +
			"body\n",
	)
	if !bytes.Equal(stdout.Bytes(), want) || stderr.Len() != 0 ||
		calls.Load() != 1 {
		t.Fatal("public filter revise output or protocol purity changed")
	}
}

// TestPublicExecutablePartialDisconnectIsDeterministic proves a real pipe
// disconnect after output begins is always nonzero and never reaches stderr.
func TestPublicExecutablePartialDisconnectIsDeterministic(t *testing.T) {
	var calls atomic.Int64
	fixture := newGeneratedDaemonFixture(t, &generatedDaemonService{
		sign: func(generatedfixture.SignRequest) generatedfixture.OperationResponse {
			response := signedResponse()
			response.Actions = generatedfixture.ActionPlan{}
			response.Disposition = generatedfixture.DispositionContinue
			return response
		},
	}, &calls)
	configPath := writeSignConfig(t, fixture.endpoint)
	input := append(
		[]byte("Subject: partial\n\n"),
		bytes.Repeat([]byte{'x'}, 4<<20)...,
	)
	input = append(input, '\n')
	const attempts = 10
	for range attempts {
		command := publicSignFilterCommand(t, configPath, input)
		var stderr bytes.Buffer
		command.Stderr = &stderr
		output, err := command.StdoutPipe()
		if err != nil {
			t.Fatal("public stdout pipe construction failed")
		}
		if err = command.Start(); err != nil {
			t.Fatal("public partial filter start failed")
		}
		var first [1]byte
		if _, err = io.ReadFull(output, first[:]); err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatalf(
				"public partial filter produced no output calls=%d stderr-bytes=%d",
				calls.Load(),
				stderr.Len(),
			)
		}
		if err = output.Close(); err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatal("public output disconnect failed")
		}
		if err = command.Wait(); err == nil {
			t.Fatal("public partial disconnect returned success")
		}
		if stderr.Len() != 0 {
			t.Fatal("public partial disconnect emitted diagnostics")
		}
	}
	if calls.Load() != attempts {
		t.Fatal("public partial disconnect retried or skipped daemon authority")
	}
}

// revisedResponse returns one exact generated revision action plan.
func revisedResponse() generatedfixture.OperationResponse {
	return generatedfixture.OperationResponse{
		Actions: generatedfixture.ActionPlan{
			{
				Type:  generatedfixture.AddHeader,
				Name:  generatedfixture.DKIM2Signature,
				Value: " i=2; s=public",
			},
		},
		ApiVersion:  generatedfixture.V1,
		Disposition: generatedfixture.DispositionAccept,
		Draft:       generatedfixture.DraftIetfDkimDkim2Spec05,
		Operation:   generatedfixture.Revise,
		Result:      generatedfixture.OperationResponseResultPass,
	}
}

// signedResponse returns one exact generated originator action plan.
func signedResponse() generatedfixture.OperationResponse {
	return generatedfixture.OperationResponse{
		Actions: generatedfixture.ActionPlan{
			{
				Type:  generatedfixture.AddHeader,
				Name:  generatedfixture.MessageInstance,
				Value: " i=1; m=public",
			},
			{
				Type:  generatedfixture.AddHeader,
				Name:  generatedfixture.DKIM2Signature,
				Value: " i=1; s=public",
			},
		},
		ApiVersion:  generatedfixture.V1,
		Disposition: generatedfixture.DispositionAccept,
		Draft:       generatedfixture.DraftIetfDkimDkim2Spec05,
		Operation:   generatedfixture.Sign,
		Result:      generatedfixture.OperationResponseResultPass,
	}
}

// writeSignConfig creates one exact protected mode-specific JSON document.
func writeSignConfig(t *testing.T, endpoint string) string {
	t.Helper()
	root := testsupport.TrustedTempDirectory(t)
	capabilityRoot := testsupport.TrustedTempDirectory(t)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal("public protected parent mode failed")
	}
	if err := os.Chmod(capabilityRoot, 0o700); err != nil {
		t.Fatal("public capability parent mode failed")
	}
	capabilityPath := filepath.Join(capabilityRoot, "sign.capability")
	capability := bytes.Repeat([]byte{0xa5}, 32)
	if err := os.WriteFile(capabilityPath, capability, 0o400); err != nil {
		t.Fatal("public capability creation failed")
	}
	clear(capability)
	encoded := fmt.Appendf(nil, "version: dkim2-exim-config-v1\ndaemon:\n  endpoint: %s\n  request_timeout: 10s\n  sign_capability_file: %s\nsigning:\n  tenant: %s\n  domain: example.test\n", endpoint, capabilityPath, publicTenant)
	configPath := filepath.Join(root, "sign.yaml")
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		clear(encoded)
		t.Fatal("public config creation failed")
	}
	clear(encoded)
	if err := os.Chmod(capabilityRoot, 0o500); err != nil {
		t.Fatal("public exact capability parent mode failed")
	}
	t.Cleanup(func() { _ = os.Chmod(capabilityRoot, 0o700) })
	return configPath
}

// writeReviseConfig creates protected revision config and authenticated evidence.
func writeReviseConfig(t *testing.T, endpoint string) (string, string) {
	t.Helper()
	configRoot := testsupport.TrustedTempDirectory(t)
	capabilityRoot := testsupport.TrustedTempDirectory(t)
	evidenceRoot := testsupport.TrustedTempDirectory(t)
	keyRoot := testsupport.TrustedTempDirectory(t)
	readinessRoot := testsupport.TrustedTempDirectory(t)
	for _, root := range []string{
		configRoot, capabilityRoot, evidenceRoot, keyRoot, readinessRoot,
	} {
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal("public protected revision parent mode failed")
		}
	}
	capabilityPath := filepath.Join(capabilityRoot, "revise.capability")
	capability := bytes.Repeat([]byte{0xa5}, evidence.KeyBytes)
	if err := os.WriteFile(capabilityPath, capability, 0o400); err != nil {
		t.Fatal("public revise capability creation failed")
	}
	clear(capability)
	if err := os.Chmod(capabilityRoot, 0o500); err != nil {
		t.Fatal("public revise capability parent protection failed")
	}
	t.Cleanup(func() { _ = os.Chmod(capabilityRoot, 0o700) })
	keyPath := filepath.Join(keyRoot, "evidence.key")
	key := bytes.Repeat([]byte{0x5a}, evidence.KeyBytes)
	if err := os.WriteFile(keyPath, key, 0o400); err != nil {
		clear(key)
		t.Fatal("public evidence key creation failed")
	}
	if err := os.Chmod(keyRoot, 0o500); err != nil {
		clear(key)
		t.Fatal("public evidence key parent protection failed")
	}
	t.Cleanup(func() { _ = os.Chmod(keyRoot, 0o700) })
	incoming, err := adapter.NewIncomingEvidence(
		[]byte("<incoming-marker@example.test>"),
		[][]byte{[]byte("<incoming-recipient-marker@example.net>")},
		adapter.SessionSMTP,
	)
	if err != nil {
		clear(key)
		t.Fatal("public incoming evidence construction failed")
	}
	record, err := evidence.NewRecord(
		time.Now().UTC(),
		evidence.MinimumRetention,
		incoming,
		bytes.NewReader(bytes.Repeat([]byte{0x7b}, evidence.LocatorBytes)),
	)
	if err != nil {
		clear(key)
		t.Fatal("public evidence record construction failed")
	}
	encodedRecord, err := record.Encode(key)
	if err != nil {
		clear(key)
		t.Fatal("public evidence record encoding failed")
	}
	recordPath := filepath.Join(evidenceRoot, record.Locator()+".ev1")
	recordBytes := len(encodedRecord)
	if err = os.WriteFile(recordPath, encodedRecord, 0o600); err != nil {
		clear(encodedRecord)
		t.Fatal("public evidence record creation failed")
	}
	clear(encodedRecord)
	readinessPath := filepath.Join(readinessRoot, "readiness")
	writeReadinessMarkerFixture(
		t,
		readinessPath,
		evidenceRoot,
		key,
		1,
		int64(recordBytes),
	)
	writerLock, lockErr := unix.Open(
		readinessRoot,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if lockErr != nil ||
		unix.Flock(writerLock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		clear(key)
		t.Fatal("public readiness writer lock failed")
	}
	t.Cleanup(func() {
		_ = unix.Flock(writerLock, unix.LOCK_UN)
		_ = unix.Close(writerLock)
	})
	clear(key)
	encodedConfig := fmt.Appendf(nil, "version: dkim2-exim-config-v1\ndaemon:\n  endpoint: %s\n  request_timeout: 10s\n  revise_capability_file: %s\nsigning:\n  tenant: %s\n  domain: example.test\nevidence:\n  enabled: true\n  root: %s\n  key_file: %s\n  readiness_file: %s\n", endpoint, capabilityPath, publicTenant, evidenceRoot, keyPath, readinessPath)
	configPath := filepath.Join(configRoot, "revise.yaml")
	if err = os.WriteFile(configPath, encodedConfig, 0o600); err != nil {
		clear(encodedConfig)
		t.Fatal("public revise config creation failed")
	}
	clear(encodedConfig)
	return configPath, record.Locator()
}

// writeReadinessMarkerFixture independently constructs one fixed clean marker.
func writeReadinessMarkerFixture(
	t *testing.T,
	path string,
	root string,
	key []byte,
	records uint64,
	recordBytes int64,
) {
	t.Helper()
	fingerprint := fixtureRootFingerprint(t, root)
	encoded := make([]byte, 112)
	copy(encoded[:4], "DXR1")
	encoded[4] = 1
	encoded[5] = 1
	binary.BigEndian.PutUint64(encoded[8:16], 1)
	for index, value := range []uint64{
		fingerprint[0],
		fingerprint[1],
		fingerprint[2],
		fingerprint[3],
		fingerprint[4],
		fingerprint[5],
		records,
		uint64(recordBytes),
	} {
		start := 16 + index*8
		binary.BigEndian.PutUint64(encoded[start:start+8], value)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("DKIM2-EXIM-READINESS-V1\x00"))
	_, _ = mac.Write(encoded[:80])
	sum := mac.Sum(nil)
	copy(encoded[80:], sum)
	clear(sum)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		clear(encoded)
		t.Fatal("public readiness marker creation failed")
	}
	clear(encoded)
}

// publicSignFilterCommand constructs one exact public sign command with a deadline.
func publicSignFilterCommand(
	t *testing.T,
	configPath string,
	input []byte,
) *exec.Cmd {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), publicFilterTimeout)
	t.Cleanup(cancel)
	command := exec.CommandContext(
		ctx,
		publicExecutablePath,
		"--config",
		configPath,
		"filter",
		"sign",
		"--",
		"<sender@example.test>",
		"<recipient@example.test>",
	)
	command.Stdin = bytes.NewReader(input)
	return command
}

// publicReviseFilterCommand constructs one exact public revise command with a deadline.
func publicReviseFilterCommand(
	t *testing.T,
	configPath string,
	locator string,
	input []byte,
) *exec.Cmd {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), publicFilterTimeout)
	t.Cleanup(cancel)
	command := exec.CommandContext(
		ctx,
		publicExecutablePath,
		"--config",
		configPath,
		"filter",
		"revise",
		"--",
		locator,
		"<outgoing-marker@example.test>",
		"<outgoing-recipient-marker@example.net>",
	)
	command.Stdin = bytes.NewReader(input)
	return command
}
