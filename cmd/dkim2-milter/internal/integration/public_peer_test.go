//go:build linux || darwin

// Package integration exercises the executable through its public Milter socket.
package integration

import (
	"bytes"
	"context"
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
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/daemon"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/daemon/generated"
	generatedfixture "github.com/croessner/dkim2/cmd/dkim2-milter/internal/integration/generated"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/testsupport"
)

const (
	peerAbort     byte = 'A'
	peerBody      byte = 'B'
	peerConnect   byte = 'C'
	peerEOM       byte = 'E'
	peerHelo      byte = 'H'
	peerHeader    byte = 'L'
	peerMail      byte = 'M'
	peerEOH       byte = 'N'
	peerNegotiate byte = 'O'
	peerQuit      byte = 'Q'
	peerRecipient byte = 'R'

	adapterAccept    byte = 'a'
	adapterContinue  byte = 'c'
	adapterAddHeader byte = 'h'
	adapterReplyCode byte = 'y'

	peerVersion6        uint32 = 6
	peerAddHeaders      uint32 = 0x00000001
	peerChangeHeaders   uint32 = 0x00000010
	peerNoUnknown       uint32 = 0x00000100
	peerNoData          uint32 = 0x00000200
	peerHeaderLeadSpace uint32 = 0x00100000

	publicTestTimeout        = 8 * time.Second
	publicStartupTimeout     = 20 * time.Second
	integrationFailOpen      = "fail_open"
	integrationTempfailReply = "451 4.7.1 DKIM2 service unavailable\x00"
	integrationModeInbound   = "inbound"
	integrationModeOrigin    = "originator"
)

var executablePath string

// TestMain builds the real executable once for the complete public-boundary suite.
func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", ".dkim2-milter-integration-")
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "integration executable directory failed")
		os.Exit(1)
	}
	executablePath = filepath.Join(directory, "dkim2-milter")
	command := exec.Command("go", "build", "-o", executablePath, "../..")
	if output, buildErr := command.CombinedOutput(); buildErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "integration executable build failed: %s\n", output)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(directory)
	os.Exit(code)
}

// protocolPeer is an MTA-side oracle with no production parser or state dependency.
type protocolPeer struct {
	connection net.Conn
}

// adapterFrame is one independently decoded adapter response.
type adapterFrame struct {
	command byte
	payload []byte
}

// TestExecutableInboundSuccess proves the real binary, generated contract, and public socket compose.
func TestExecutableInboundSuccess(t *testing.T) {
	fixture := newGeneratedDaemonFixture(t, &generatedDaemonService{
		process: func(body generatedfixture.ProcessRequest) generatedfixture.ProcessResponse {
			assertFixtureMessage(t, body.ApiVersion, body.Draft, body.Message, body.Smtp)
			return validFixtureProcessResponse()
		},
	})
	process := startExecutable(t, fixture.endpoint, integrationModeInbound, "tempfail", 2*time.Second)
	peer := dialPublicPeer(t, process.socket)
	defer peer.close()

	frames := peer.standardTransaction(t)
	if len(frames) != 1 || frames[0].command != adapterAccept ||
		len(frames[0].payload) != 0 {
		t.Fatalf("EOM responses = %#v", frames)
	}
	peer.send(t, peerQuit, nil)
	process.stop(t)
	assertPrivateOutputAbsent(t, process.log)
}

// TestExecutableSigningModeMatrix proves generated routing and ordered public actions.
func TestExecutableSigningModeMatrix(t *testing.T) {
	tests := []struct {
		name        string
		mode        string
		operation   generated.OperationResponseOperation
		actions     generated.ActionPlan
		wantHeaders []string
	}{
		{
			name: integrationModeOrigin, mode: integrationModeOrigin,
			operation: generated.Sign,
			actions: generated.ActionPlan{
				{Name: generated.MessageInstance, Type: generated.AddHeader, Value: "v=2; i=1"},
				{Name: generated.DKIM2Signature, Type: generated.AddHeader, Value: "v=2; s=1"},
			},
			wantHeaders: []string{"Message-Instance", "DKIM2-Signature"},
		},
		{
			name: "ordinary transit", mode: "ordinary_transit",
			operation: generated.Revise,
			actions: generated.ActionPlan{
				{Name: generated.DKIM2Signature, Type: generated.AddHeader, Value: "v=2; s=2"},
			},
			wantHeaders: []string{"DKIM2-Signature"},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			service := &generatedDaemonService{}
			switch testCase.operation {
			case generated.Sign:
				service.sign = func(body generatedfixture.SignRequest) generatedfixture.OperationResponse {
					assertFixtureMessage(t, body.ApiVersion, body.Draft, body.Message, body.Smtp)
					assertFixtureSigningContext(t, body.Context)
					return fixtureOperationResponse("sign", testCase.actions)
				}
			case generated.Revise:
				service.revise = func(body generatedfixture.ReviseRequest) generatedfixture.OperationResponse {
					assertFixtureMessage(t, body.ApiVersion, body.Draft, body.Message, body.Smtp)
					assertFixtureSigningContext(t, body.Context)
					return fixtureOperationResponse("revise", testCase.actions)
				}
			}
			fixture := newGeneratedDaemonFixture(t, service)
			process := startExecutable(
				t, fixture.endpoint, testCase.mode, "tempfail", 2*time.Second,
			)
			peer := dialPublicPeer(t, process.socket)
			frames := peer.standardTransaction(t)
			if len(frames) != len(testCase.wantHeaders)+1 {
				t.Fatalf("EOM frame count = %d", len(frames))
			}
			for index, wantName := range testCase.wantHeaders {
				name, value, ok := splitHeaderAction(frames[index].payload)
				if frames[index].command != adapterAddHeader || !ok ||
					name != wantName || value != testCase.actions[index].Value {
					t.Fatalf("action %d = %q %q %q", index, frames[index].command, name, value)
				}
			}
			terminal := frames[len(frames)-1]
			if terminal.command != adapterAccept || len(terminal.payload) != 0 {
				t.Fatalf("terminal response = %q %x", terminal.command, terminal.payload)
			}
			peer.send(t, peerQuit, nil)
			peer.close()
			process.stop(t)
			assertPrivateOutputAbsent(t, process.log)
		})
	}
}

// TestExecutableFailurePolicyMatrix proves fixed replies and the narrow fail-open scope.
func TestExecutableFailurePolicyMatrix(t *testing.T) {
	tests := []struct {
		name        string
		failure     string
		endpoint    func(*testing.T) string
		want        byte
		wantPayload string
	}{
		{
			name: "unavailable tempfails", failure: "tempfail",
			endpoint: unavailableEndpoint, want: adapterReplyCode,
			wantPayload: integrationTempfailReply,
		},
		{
			name: "pre-write unavailable fails open", failure: integrationFailOpen,
			endpoint: unavailableEndpoint, want: adapterAccept,
		},
		{
			name: "post-write timeout remains closed", failure: integrationFailOpen,
			endpoint: func(t *testing.T) string {
				return newDaemonFixture(t, func(http.ResponseWriter, *http.Request) {
					time.Sleep(500 * time.Millisecond)
				}).endpoint
			},
			want:        adapterReplyCode,
			wantPayload: integrationTempfailReply,
		},
		{
			name: "response overflow remains closed", failure: integrationFailOpen,
			endpoint: func(t *testing.T) string {
				return newDaemonFixture(t, func(writer http.ResponseWriter, _ *http.Request) {
					writer.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(writer, strings.Repeat("x", (4<<20)+1))
				}).endpoint
			},
			want:        adapterReplyCode,
			wantPayload: integrationTempfailReply,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			process := startExecutable(
				t, testCase.endpoint(t), integrationModeInbound, testCase.failure, 100*time.Millisecond,
			)
			peer := dialPublicPeer(t, process.socket)
			frames := peer.standardTransaction(t)
			if len(frames) != 1 || frames[0].command != testCase.want ||
				string(frames[0].payload) != testCase.wantPayload {
				t.Fatalf("failure response = %#v", frames)
			}
			peer.send(t, peerQuit, nil)
			peer.close()
			process.stop(t)
			assertPrivateOutputAbsent(t, process.log)
		})
	}
}

// TestExecutableDaemonRejectUsesExactFixedReply proves public 550 policy mapping.
func TestExecutableDaemonRejectUsesExactFixedReply(t *testing.T) {
	fixture := newGeneratedDaemonFixture(t, &generatedDaemonService{
		process: func(generatedfixture.ProcessRequest) generatedfixture.ProcessResponse {
			response := validFixtureProcessResponse()
			response.Disposition = generatedfixture.DispositionReject
			response.Verification.State = generatedfixture.FAIL
			response.Verification.PrimaryReason = generatedfixture.VerificationReasonMissingProtocol
			response.Verification.Checks[0].Reason = generatedfixture.VerificationReasonMissingProtocol
			response.Policy.Verdict = generatedfixture.PolicyResultVerdictReject
			response.Policy.PrimaryReason = generatedfixture.ProtocolFail
			response.Policy.Findings[0] = generatedfixture.PolicyFinding{
				Reason: generatedfixture.ProtocolFail, Severity: generatedfixture.Permanent,
			}
			response.Replay.Class = generatedfixture.NotChecked
			return response
		},
	})
	process := startExecutable(t, fixture.endpoint, integrationModeInbound, "tempfail", time.Second)
	peer := dialPublicPeer(t, process.socket)
	frames := peer.standardTransaction(t)
	if len(frames) != 1 || frames[0].command != adapterReplyCode ||
		string(frames[0].payload) != "550 5.7.1 DKIM2 policy rejection\x00" {
		t.Fatalf("daemon rejection response = %#v", frames)
	}
	peer.send(t, peerQuit, nil)
	peer.close()
	process.stop(t)
}

// TestExecutablePartialActionDisconnectRecovers proves bounded public write ambiguity.
func TestExecutablePartialActionDisconnectRecovers(t *testing.T) {
	var calls int
	var callsMu sync.Mutex
	fixture := newGeneratedDaemonFixture(t, &generatedDaemonService{
		sign: func(generatedfixture.SignRequest) generatedfixture.OperationResponse {
			callsMu.Lock()
			defer callsMu.Unlock()
			calls++
			if calls == 1 {
				return generatedfixture.OperationResponse{
					Actions: generatedfixture.ActionPlan{
						{
							Name:  generatedfixture.MessageInstance,
							Type:  generatedfixture.AddHeader,
							Value: strings.Repeat("m", 65_000),
						},
						{
							Name:  generatedfixture.DKIM2Signature,
							Type:  generatedfixture.AddHeader,
							Value: strings.Repeat("s", 65_000),
						},
					},
					ApiVersion:  generatedfixture.V1,
					Disposition: generatedfixture.DispositionAccept,
					Draft:       generatedfixture.DraftIetfDkimDkim2Spec04,
					Operation:   generatedfixture.Sign,
					Result:      generatedfixture.OperationResponseResultPass,
				}
			}
			return fixtureOperationResponse("sign", generated.ActionPlan{
				{Name: generated.MessageInstance, Type: generated.AddHeader, Value: "v=2; i=2"},
				{Name: generated.DKIM2Signature, Type: generated.AddHeader, Value: "v=2; s=2"},
			})
		},
	})
	process := startExecutable(t, fixture.endpoint, integrationModeOrigin, "fail_open", time.Second)
	first := dialPublicPeer(t, process.socket)
	if unixConnection, ok := first.connection.(*net.UnixConn); ok {
		_ = unixConnection.SetReadBuffer(1024)
	}
	first.negotiate(t)
	first.callback(t, peerConnect, []byte("mx.example.test\x00U"))
	first.callback(t, peerHelo, []byte("mx.example.test\x00"))
	first.sendMessageCallbacks(t)
	first.send(t, peerEOM, nil)
	command, prefix := first.receiveFramePrefix(t, 64)
	if command != adapterAddHeader ||
		!bytes.HasPrefix(prefix, []byte("Message-Instance\x00")) {
		t.Fatalf("first partial action = %q %q", command, prefix)
	}
	if unixConnection, ok := first.connection.(*net.UnixConn); ok {
		_ = unixConnection.CloseRead()
	}
	first.close()

	second := dialPublicPeer(t, process.socket)
	frames := second.standardTransaction(t)
	if len(frames) != 3 || frames[0].command != adapterAddHeader ||
		frames[1].command != adapterAddHeader || frames[2].command != adapterAccept {
		t.Fatalf("post-disconnect listener response = %#v", frames)
	}
	second.send(t, peerQuit, nil)
	second.close()
	process.stop(t)
	logged, err := os.ReadFile(process.log)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(logged, []byte(`"disposition":"close"`)) ||
		!bytes.Contains(logged, []byte(`"failure_class":"indeterminate"`)) {
		t.Fatalf("partial output lacked bounded indeterminate evidence: %q", logged)
	}
	callsMu.Lock()
	gotCalls := calls
	callsMu.Unlock()
	if gotCalls != 2 {
		t.Fatalf("daemon calls after public partial output = %d", gotCalls)
	}
}

// TestExecutableAbortReuseAndMalformedDisconnect proves public connection isolation.
func TestExecutableAbortReuseAndMalformedDisconnect(t *testing.T) {
	var calls int
	var callsMu sync.Mutex
	fixture := newGeneratedDaemonFixture(t, &generatedDaemonService{
		process: func(generatedfixture.ProcessRequest) generatedfixture.ProcessResponse {
			callsMu.Lock()
			calls++
			callsMu.Unlock()
			return validFixtureProcessResponse()
		},
	})
	process := startExecutable(t, fixture.endpoint, integrationModeInbound, "tempfail", time.Second)

	malformed := dialPublicPeer(t, process.socket)
	if _, err := malformed.connection.Write([]byte{0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err := malformed.connection.Read(one[:]); err == nil {
		t.Fatal("zero-length public frame did not terminate its connection")
	}
	malformed.close()

	peer := dialPublicPeer(t, process.socket)
	peer.negotiate(t)
	peer.callback(t, peerConnect, []byte("mx.example.test\x00U"))
	peer.callback(t, peerHelo, []byte("mx.example.test\x00"))
	peer.callback(t, peerMail, []byte("<aborted@example.test>\x00"))
	peer.callback(t, peerRecipient, []byte("<recipient@example.test>\x00"))
	peer.callback(t, peerHeader, []byte("Subject\x00 aborted\x00"))
	peer.send(t, peerAbort, nil)
	frames := peer.messageTransaction(t)
	if len(frames) != 1 || frames[0].command != adapterAccept {
		t.Fatalf("reused transaction response = %#v", frames)
	}
	peer.send(t, peerQuit, nil)
	peer.close()
	callsMu.Lock()
	gotCalls := calls
	callsMu.Unlock()
	if gotCalls != 1 {
		t.Fatalf("daemon calls after abort/reuse = %d", gotCalls)
	}
	process.stop(t)
}

// TestExecutableOverloadAndSlowDisconnect proves admission and shutdown backpressure.
func TestExecutableOverloadAndSlowDisconnect(t *testing.T) {
	fixture := newGeneratedDaemonFixture(t, &generatedDaemonService{
		process: func(generatedfixture.ProcessRequest) generatedfixture.ProcessResponse {
			return validFixtureProcessResponse()
		},
	})
	process := startExecutable(
		t, fixture.endpoint, integrationModeInbound, "tempfail", time.Second,
		"  max_connections: 1\n  max_in_flight_messages: 1\n",
	)
	slow := dialPublicPeer(t, process.socket)
	if _, err := slow.connection.Write([]byte{0, 0}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	overloaded := dialPublicPeer(t, process.socket)
	_, writeErr := overloaded.connection.Write([]byte{0, 0, 0, 1, peerQuit})
	if writeErr == nil {
		var response [1]byte
		if _, err := overloaded.connection.Read(response[:]); err == nil {
			t.Fatal("connection-limit peer was not closed")
		}
	} else if !errors.Is(writeErr, syscall.EPIPE) &&
		!errors.Is(writeErr, syscall.ECONNRESET) &&
		!errors.Is(writeErr, net.ErrClosed) {
		t.Fatalf("connection-limit rejection write = %v", writeErr)
	}
	overloaded.close()
	started := time.Now()
	process.stop(t)
	if time.Since(started) > 2*time.Second {
		t.Fatal("slow partial frame exceeded the configured shutdown bound")
	}
	slow.close()
}

// daemonFixture owns one canonical loopback HTTP server.
type daemonFixture struct {
	endpoint string
	server   *http.Server
	listener net.Listener
}

// generatedDaemonService implements the exact generated strict-server boundary.
type generatedDaemonService struct {
	process func(generatedfixture.ProcessRequest) generatedfixture.ProcessResponse
	sign    func(generatedfixture.SignRequest) generatedfixture.OperationResponse
	revise  func(generatedfixture.ReviseRequest) generatedfixture.OperationResponse
}

// GetHealth rejects an operation outside the fixture's Milter scope.
func (*generatedDaemonService) GetHealth(
	context.Context,
	generatedfixture.GetHealthRequestObject,
) (generatedfixture.GetHealthResponseObject, error) {
	return nil, errors.New("unexpected fixture operation")
}

// HeadHealth rejects an operation outside the fixture's Milter scope.
func (*generatedDaemonService) HeadHealth(
	context.Context,
	generatedfixture.HeadHealthRequestObject,
) (generatedfixture.HeadHealthResponseObject, error) {
	return nil, errors.New("unexpected fixture operation")
}

// GetMetrics rejects an operation outside the fixture's Milter scope.
func (*generatedDaemonService) GetMetrics(
	context.Context,
	generatedfixture.GetMetricsRequestObject,
) (generatedfixture.GetMetricsResponseObject, error) {
	return nil, errors.New("unexpected fixture operation")
}

// GetReadiness rejects an operation outside the fixture's Milter scope.
func (*generatedDaemonService) GetReadiness(
	context.Context,
	generatedfixture.GetReadinessRequestObject,
) (generatedfixture.GetReadinessResponseObject, error) {
	return nil, errors.New("unexpected fixture operation")
}

// HeadReadiness rejects an operation outside the fixture's Milter scope.
func (*generatedDaemonService) HeadReadiness(
	context.Context,
	generatedfixture.HeadReadinessRequestObject,
) (generatedfixture.HeadReadinessResponseObject, error) {
	return nil, errors.New("unexpected fixture operation")
}

// ProcessMessage returns one test-owned response through generated serialization.
func (s *generatedDaemonService) ProcessMessage(
	_ context.Context,
	request generatedfixture.ProcessMessageRequestObject,
) (generatedfixture.ProcessMessageResponseObject, error) {
	if s == nil || s.process == nil || request.Body == nil {
		return nil, errors.New("unexpected fixture operation")
	}
	body := s.process(*request.Body)
	return generatedfixture.ProcessMessage200JSONResponse{
		Body: body, Headers: generatedfixture.ProcessMessage200ResponseHeaders{
			ContentLength: strconv.Itoa(encodedFixtureLength(body)),
		},
	}, nil
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
	return generatedfixture.ReviseMessage200JSONResponse{
		Body: body, Headers: generatedfixture.ReviseMessage200ResponseHeaders{
			ContentLength: strconv.Itoa(encodedFixtureLength(body)),
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
	return generatedfixture.SignMessage200JSONResponse{
		Body: body, Headers: generatedfixture.SignMessage200ResponseHeaders{
			ContentLength: strconv.Itoa(encodedFixtureLength(body)),
		},
	}, nil
}

// encodedFixtureLength returns the generated JSON encoder's exact byte count.
func encodedFixtureLength(value any) int {
	encoded, err := json.Marshal(value)
	if err != nil {
		return 0
	}
	return len(encoded) + 1
}

// newGeneratedDaemonFixture installs the strict generated route and DTO boundary.
func newGeneratedDaemonFixture(
	t *testing.T,
	service *generatedDaemonService,
) *daemonFixture {
	t.Helper()
	if service == nil {
		t.Fatal("missing generated fixture service")
	}
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
			route := map[string]string{
				"ProcessMessage": "/v1/process",
				"ReviseMessage":  "/v1/revise",
				"SignMessage":    "/v1/sign",
			}[operationID]
			assertFixedDaemonRequest(t, request, route)
			return next(ctx, writer, request, input)
		}
	}
	strict := generatedfixture.NewStrictHandler(service, []generatedfixture.StrictMiddlewareFunc{
		middleware,
	})
	return startDaemonFixture(
		t,
		generatedfixture.HandlerFromMux(strict, http.NewServeMux()),
	)
}

// newDaemonFixture starts one loopback fixture using generated boundary DTOs.
func newDaemonFixture(t *testing.T, handler http.HandlerFunc) *daemonFixture {
	t.Helper()
	return startDaemonFixture(t, handler)
}

// startDaemonFixture starts one canonical loopback HTTP fixture.
func startDaemonFixture(t *testing.T, handler http.Handler) *daemonFixture {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: time.Second,
	}
	fixture := &daemonFixture{
		endpoint: "http://" + listener.Addr().String(),
		server:   server,
		listener: listener,
	}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	return fixture
}

// executableProcess owns one real adapter subprocess and its protected fixture tree.
type executableProcess struct {
	command *exec.Cmd
	socket  string
	log     string
}

// startExecutable builds and starts the real adapter against one fixture endpoint.
func startExecutable(
	t *testing.T,
	endpoint string,
	mode string,
	failure string,
	requestTimeout time.Duration,
	extraServer ...string,
) *executableProcess {
	t.Helper()
	root := testsupport.TrustedTempDirectory(t)

	socketPath := filepath.Join(root, "m.sock")
	capabilityParent := filepath.Join(root, "capability")
	if err := os.Mkdir(capabilityParent, 0o700); err != nil {
		t.Fatal(err)
	}
	capabilityPath := filepath.Join(capabilityParent, "token")
	capability := bytes.Repeat([]byte{0xa5}, 32)
	if err := os.WriteFile(capabilityPath, capability, 0o400); err != nil {
		t.Fatal(err)
	}
	clear(capability)
	if err := os.Chmod(capabilityParent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(capabilityParent, 0o700) })

	signing := ""
	if mode != integrationModeInbound {
		signing = "\nsigning:\n  tenant: tenant-a\n  domain: example.test"
	}
	document := fmt.Sprintf(`version: dkim2-milter-config-v1
server:
  socket: %s
  shutdown_timeout: 1s
%s
daemon:
  endpoint: %s
  capability_file: %s
  request_timeout: %s
mode: %s%s
failure:
  mode: %s
limits:
  message_bytes: 1048576
  header_bytes: 65536
  header_count: 100
  header_field_bytes: 8192
  recipient_count: 100
`, socketPath, strings.Join(extraServer, ""), endpoint, capabilityPath,
		requestTimeout, mode, signing, failure)
	configPath := filepath.Join(root, "milter.yaml")
	if err := os.WriteFile(configPath, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(configPath); err != nil {
		t.Fatalf("integration configuration failed preflight: %v", err)
	}
	capabilityOwner, err := daemon.LoadCapability(capabilityPath)
	if err != nil {
		t.Fatalf("integration capability failed preflight: %v", err)
	}
	if err := capabilityOwner.Close(); err != nil {
		t.Fatalf("integration capability cleanup failed: %v", err)
	}
	logPath := filepath.Join(root, "process.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executablePath, "serve", "--config", configPath)
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	process := &executableProcess{command: command, socket: socketPath, log: logPath}
	t.Cleanup(func() {
		if command.Process != nil && command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
		_ = logFile.Close()
	})
	waitForSocket(t, socketPath, command, logPath)
	return process
}

// waitForSocket waits for readiness evidence at the public path.
func waitForSocket(t *testing.T, path string, command *exec.Cmd, logPath string) {
	t.Helper()
	deadline := time.Now().Add(publicStartupTimeout)
	for time.Now().Before(deadline) {
		state, err := os.Lstat(path)
		if err == nil && state.Mode()&os.ModeSocket != 0 {
			return
		}
		if command.ProcessState != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	logged, _ := os.ReadFile(logPath)
	t.Fatalf("adapter socket was not ready; output=%q", logged)
}

// stop requests the executable's idempotent signal shutdown and verifies cleanup.
func (p *executableProcess) stop(t *testing.T) {
	t.Helper()
	if p == nil || p.command == nil || p.command.Process == nil {
		t.Fatal("missing executable process")
	}
	if err := p.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- p.command.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			logged, _ := os.ReadFile(p.log)
			t.Fatalf("adapter exit: %v output=%q", err, logged)
		}
	case <-time.After(publicTestTimeout):
		_ = p.command.Process.Kill()
		t.Fatal("adapter did not stop within its shutdown budget")
	}
	if _, err := os.Lstat(p.socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned socket remained after shutdown: %v", err)
	}
}

// dialPublicPeer connects the independent peer to the executable's owned socket.
func dialPublicPeer(t *testing.T, path string) *protocolPeer {
	t.Helper()
	connection, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.SetDeadline(time.Now().Add(publicTestTimeout)); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	return &protocolPeer{connection: connection}
}

// close closes the public peer connection.
func (p *protocolPeer) close() {
	if p != nil && p.connection != nil {
		_ = p.connection.Close()
	}
}

// negotiate proves the exact v6 capability handshake.
func (p *protocolPeer) negotiate(t *testing.T) {
	t.Helper()
	payload := make([]byte, 12)
	binary.BigEndian.PutUint32(payload[:4], peerVersion6)
	binary.BigEndian.PutUint32(payload[4:8], peerAddHeaders|peerChangeHeaders)
	binary.BigEndian.PutUint32(
		payload[8:],
		peerNoUnknown|peerNoData|peerHeaderLeadSpace,
	)
	p.send(t, peerNegotiate, payload)
	response := p.receive(t)
	if response.command != peerNegotiate || !bytes.Equal(response.payload, payload) {
		t.Fatalf("negotiation response = %q %x", response.command, response.payload)
	}
}

// callback sends one callback and requires the ordinary continue response.
func (p *protocolPeer) callback(t *testing.T, command byte, payload []byte) {
	t.Helper()
	p.send(t, command, payload)
	response := p.receive(t)
	if response.command != adapterContinue || len(response.payload) != 0 {
		t.Fatalf("callback %q response = %q %x", command, response.command, response.payload)
	}
}

// standardTransaction drives a complete message with independent byte expectations.
func (p *protocolPeer) standardTransaction(t *testing.T) []adapterFrame {
	t.Helper()
	p.negotiate(t)
	p.callback(t, peerConnect, []byte("mx.example.test\x00U"))
	p.callback(t, peerHelo, []byte("mx.example.test\x00"))
	return p.messageTransaction(t)
}

// messageTransaction drives one transaction after an established HELO state.
func (p *protocolPeer) messageTransaction(t *testing.T) []adapterFrame {
	t.Helper()
	p.sendMessageCallbacks(t)
	p.send(t, peerEOM, nil)
	var responses []adapterFrame
	for {
		response := p.receive(t)
		responses = append(responses, response)
		if response.command != adapterAddHeader {
			return responses
		}
	}
}

// sendMessageCallbacks sends a complete message without its EOM marker.
func (p *protocolPeer) sendMessageCallbacks(t *testing.T) {
	t.Helper()
	p.callback(t, peerMail, []byte("<sender@example.test>\x00"))
	p.callback(t, peerRecipient, []byte("<recipient@example.test>\x00"))
	p.callback(t, peerHeader, []byte("From\x00 sender@example.test\x00"))
	p.callback(t, peerHeader, []byte("Subject\x00 exact value\x00"))
	p.callback(t, peerEOH, nil)
	p.callback(t, peerBody, []byte("body\r\n"))
}

// unavailableEndpoint reserves and closes one canonical authority before startup.
func unavailableEndpoint(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return endpoint
}

// send writes one independently framed MTA command.
func (p *protocolPeer) send(t *testing.T, command byte, payload []byte) {
	t.Helper()
	frame := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)+1))
	frame[4] = command
	copy(frame[5:], payload)
	if _, err := p.connection.Write(frame); err != nil {
		t.Fatal(err)
	}
}

// receive validates one independently framed adapter response.
func (p *protocolPeer) receive(t *testing.T) adapterFrame {
	t.Helper()
	var lengthBytes [4]byte
	if _, err := io.ReadFull(p.connection, lengthBytes[:]); err != nil {
		t.Fatal(err)
	}
	length := binary.BigEndian.Uint32(lengthBytes[:])
	if length < 1 || length > 65536 {
		t.Fatalf("adapter frame length = %d", length)
	}
	data := make([]byte, int(length))
	if _, err := io.ReadFull(p.connection, data); err != nil {
		t.Fatal(err)
	}
	return adapterFrame{command: data[0], payload: bytes.Clone(data[1:])}
}

// receiveFramePrefix consumes only a bounded prefix before a forced peer disconnect.
func (p *protocolPeer) receiveFramePrefix(t *testing.T, maximum int) (byte, []byte) {
	t.Helper()
	if maximum < 1 || maximum > 1024 {
		t.Fatal("invalid response prefix bound")
	}
	var lengthBytes [4]byte
	if _, err := io.ReadFull(p.connection, lengthBytes[:]); err != nil {
		t.Fatal(err)
	}
	length := binary.BigEndian.Uint32(lengthBytes[:])
	if length <= uint32(maximum+1) || length > 65536 {
		t.Fatalf("adapter partial frame length = %d", length)
	}
	data := make([]byte, maximum+1)
	if _, err := io.ReadFull(p.connection, data); err != nil {
		t.Fatal(err)
	}
	return data[0], bytes.Clone(data[1:])
}

// assertFixtureMessage checks the exact generated-server message and SMTP projection.
func assertFixtureMessage(
	t *testing.T,
	api generatedfixture.APIVersion,
	draft generatedfixture.DraftVersion,
	message generatedfixture.MessageInput,
	smtp generatedfixture.SMTPInput,
) {
	t.Helper()
	rawValue, err := message.RawRfc5322Base64.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(string(rawValue))
	clear(rawValue)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	mailFrom, err := smtp.MailFrom.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(mailFrom)
	if api != generatedfixture.V1 ||
		draft != generatedfixture.DraftIetfDkimDkim2Spec04 ||
		message.Fidelity == nil ||
		*message.Fidelity != generatedfixture.MilterReconstructedCrlf ||
		!bytes.Equal(raw, []byte(
			"From: sender@example.test\r\nSubject: exact value\r\n\r\nbody\r\n",
		)) ||
		!bytes.Equal(mailFrom, []byte("<sender@example.test>")) ||
		len(smtp.RcptTo) != 1 {
		t.Fatal("generated message projection differed from independent callback oracle")
	}
	recipient, err := smtp.RcptTo[0].Bytes()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(recipient)
	if !bytes.Equal(recipient, []byte("<recipient@example.test>")) {
		t.Fatal("generated recipient projection differed from independent callback oracle")
	}
}

// assertFixtureSigningContext checks exact configured identity at the generated boundary.
func assertFixtureSigningContext(t *testing.T, value generatedfixture.SigningContext) {
	t.Helper()
	if value.Tenant != "tenant-a" || value.Domain != "example.test" {
		t.Error("generated signing context differed from fixed configuration")
	}
}

// fixtureOperationResponse converts test-owned expected actions into generated server DTOs.
func fixtureOperationResponse(
	operation string,
	actions generated.ActionPlan,
) generatedfixture.OperationResponse {
	fixtureActions := make(generatedfixture.ActionPlan, len(actions))
	for index := range actions {
		fixtureActions[index] = generatedfixture.AddHeaderAction{
			Name:  generatedfixture.AddHeaderActionName(actions[index].Name),
			Type:  generatedfixture.AddHeaderActionType(actions[index].Type),
			Value: actions[index].Value,
		}
	}
	return generatedfixture.OperationResponse{
		Actions: fixtureActions, ApiVersion: generatedfixture.V1,
		Disposition: generatedfixture.DispositionAccept,
		Draft:       generatedfixture.DraftIetfDkimDkim2Spec04,
		Operation:   generatedfixture.OperationResponseOperation(operation),
		Result:      generatedfixture.OperationResponseResultPass,
	}
}

// assertFixedDaemonRequest verifies credential scope and ambient-request exclusion.
func assertFixedDaemonRequest(t *testing.T, request *http.Request, route string) {
	t.Helper()
	wantCapability := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, 32))
	if request.Method != http.MethodPost || request.URL.Path != route ||
		request.URL.RawQuery != "" ||
		request.Header.Get("Content-Type") != "application/json" ||
		request.Header.Get("Accept") != "application/json" ||
		request.Header.Get("Cache-Control") != "no-store" ||
		request.Header.Get("User-Agent") != "dkim2-milter/1" ||
		request.Header.Get("X-DKIM2-Capability") != wantCapability ||
		request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
		t.Error("daemon request escaped the generated fixed capability contract")
	}
}

// validFixtureProcessResponse returns one complete generated accepting response.
func validFixtureProcessResponse() generatedfixture.ProcessResponse {
	return generatedfixture.ProcessResponse{
		Actions:     generatedfixture.ActionPlan{},
		ApiVersion:  generatedfixture.V1,
		Disposition: generatedfixture.DispositionAccept,
		Draft:       generatedfixture.DraftIetfDkimDkim2Spec04,
		Verification: generatedfixture.VerificationResult{
			Checks: []generatedfixture.VerificationCheck{{
				Class:  generatedfixture.VerificationCheckClassProtocol,
				Reason: generatedfixture.VerificationReasonNone,
			}},
			CustodyStructure: generatedfixture.VerificationResultCustodyStructureNotEvaluated,
			HistoricalContent: generatedfixture.
				VerificationResultHistoricalContentNotEvaluated,
			HistoricalSignatures: generatedfixture.
				VerificationResultHistoricalSignaturesNotEvaluated,
			PrimaryReason: generatedfixture.VerificationReasonNone,
			Scope:         generatedfixture.Current,
			SignatureSets: []generatedfixture.SignatureSetResult{},
			State:         generatedfixture.PASS,
		},
		Policy: generatedfixture.PolicyResult{
			DoNotExplode: generatedfixture.PolicyResultDoNotExplodeNotEvaluated,
			DoNotModify:  generatedfixture.PolicyResultDoNotModifyNotEvaluated,
			Feedback: generatedfixture.PolicyFeedback{
				HistoryCoverage: generatedfixture.PolicyFeedbackHistoryCoverageNotEvaluated,
			},
			Findings: []generatedfixture.PolicyFinding{{
				Reason: generatedfixture.ProtocolPass, Severity: generatedfixture.Info,
			}},
			Mode: generatedfixture.Strict, PrimaryReason: generatedfixture.ProtocolPass,
			Verdict: generatedfixture.PolicyResultVerdictAccept,
		},
		Replay: generatedfixture.ReplayResult{Class: generatedfixture.Disabled},
	}
}

// splitHeaderAction decodes one independent add-header response payload.
func splitHeaderAction(payload []byte) (string, string, bool) {
	first := bytes.IndexByte(payload, 0)
	if first < 1 || len(payload) < first+2 || payload[len(payload)-1] != 0 ||
		bytes.IndexByte(payload[first+1:len(payload)-1], 0) >= 0 {
		return "", "", false
	}
	return string(payload[:first]), string(payload[first+1 : len(payload)-1]), true
}

// containsPrivateMarker reports accidental identity or message disclosure.
func containsPrivateMarker(data []byte) bool {
	for _, marker := range []string{
		"sender@example.test", "recipient@example.test", "exact value", "body\r\n",
		"tenant-a", "example.test",
	} {
		if strings.Contains(string(data), marker) {
			return true
		}
	}
	return false
}

// assertPrivateOutputAbsent proves logs do not disclose message or signing identity.
func assertPrivateOutputAbsent(t *testing.T, path string) {
	t.Helper()
	logged, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if containsPrivateMarker(logged) {
		t.Fatalf("adapter output exposed private input: %q", logged)
	}
}
