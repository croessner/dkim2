package command

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/config"
)

const (
	testConfigPath = "/tmp/dkim2-milter.yaml"
	testStartCall  = "start"
	testDoneCall   = "done"
	testStopCall   = "stop"
)

// applicationFake records the explicit process lifecycle.
type applicationFake struct {
	mu         sync.Mutex
	calls      []string
	done       chan os.Signal
	startErr   error
	stopErr    error
	panicStart bool
	panicDone  bool
	panicStop  bool
	startLeft  time.Duration
	stopLeft   time.Duration
}

// Start records one bounded startup.
func (a *applicationFake) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, testStartCall)
	if a.panicStart {
		panic("private start marker")
	}
	if deadline, present := ctx.Deadline(); present {
		a.startLeft = time.Until(deadline)
	}
	return a.startErr
}

// TestRunServeStopsAmbiguousApplicationReturnedWithBuildError proves ownership.
func TestRunServeStopsAmbiguousApplicationReturnedWithBuildError(t *testing.T) {
	snapshot := commandSnapshot(t)
	application := &applicationFake{}
	err := runServe(
		context.Background(),
		testConfigPath,
		&bytes.Buffer{},
		commandDependencies{
			load: func(string) (config.Snapshot, error) { return snapshot, nil },
			build: func(config.Snapshot, io.Writer) (managedApplication, error) {
				return application, errors.New("private build error")
			},
			withTimeout: context.WithTimeout,
		},
	)
	if !errors.Is(err, errCommandRuntime) ||
		!equalStrings(application.callSnapshot(), []string{testStopCall}) {
		t.Fatalf("ambiguous build cleanup err=%v calls=%v", err, application.callSnapshot())
	}
}

// Done returns the deterministic test wait channel.
func (a *applicationFake) Done() <-chan os.Signal {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, testDoneCall)
	if a.panicDone {
		panic("private done marker")
	}
	return a.done
}

// Stop records one bounded shutdown.
func (a *applicationFake) Stop(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, testStopCall)
	if deadline, present := ctx.Deadline(); present {
		a.stopLeft = time.Until(deadline)
	}
	if a.panicStop {
		panic("private stop marker")
	}
	return a.stopErr
}

// callSnapshot returns an immutable copy of lifecycle calls.
func (a *applicationFake) callSnapshot() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.calls...)
}

// commandSnapshot loads one real validated config for orchestration tests.
func commandSnapshot(t *testing.T) config.Snapshot {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "milter.yaml")
	document := `version: dkim2-milter-config-v1
server:
  socket: /tmp/dkim2-milter.sock
  shutdown_timeout: 3s
daemon:
  endpoint: http://127.0.0.1:8080
  capability_file: /tmp/dkim2-milter.cap
mode: inbound
`
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// TestCommandHelpVersionAndShapeNeverBootstrap proves the public config-only surface.
func TestCommandHelpVersionAndShapeNeverBootstrap(t *testing.T) {
	marker := "private-cli-marker"
	tests := []struct {
		name       string
		args       []string
		wantExit   int
		wantOutput string
	}{
		{name: "help", args: []string{"--help"}, wantExit: 0, wantOutput: commandUsage},
		{name: "version", args: []string{"--version"}, wantExit: 0, wantOutput: "dkim2-milter development\n"},
		{name: "missing command", wantExit: 2, wantOutput: commandShapeDiagnostic},
		{name: "missing config", args: []string{serveCommandName}, wantExit: 2, wantOutput: commandShapeDiagnostic},
		{name: "secret flag", args: []string{serveCommandName, "--config", testConfigPath, "--capability", marker}, wantExit: 2, wantOutput: commandShapeDiagnostic},
		{name: "endpoint flag", args: []string{serveCommandName, "--config", testConfigPath, "--daemon-url", marker}, wantExit: 2, wantOutput: commandShapeDiagnostic},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			loads := 0
			exit := executeWithDependencies(
				test.args,
				&stdout,
				&stderr,
				commandDependencies{
					load: func(string) (config.Snapshot, error) {
						loads++
						return config.Snapshot{}, errors.New(marker)
					},
					build: func(config.Snapshot, io.Writer) (managedApplication, error) {
						t.Fatal("shape-only command reached Fx build")
						return nil, nil
					},
					withTimeout: context.WithTimeout,
				},
			)
			if exit != test.wantExit {
				t.Fatalf("exit = %d, want %d", exit, test.wantExit)
			}
			output := stdout.String() + stderr.String()
			if !strings.Contains(output, test.wantOutput) {
				t.Fatalf("output = %q, want %q", output, test.wantOutput)
			}
			if strings.Contains(output, marker) || loads != 0 {
				t.Fatal("shape-only output leaked input or bootstrapped runtime")
			}
		})
	}
}

// TestRunServeUsesFxLifecycleAndConfiguredBounds proves config-to-runtime orchestration.
func TestRunServeUsesFxLifecycleAndConfiguredBounds(t *testing.T) {
	snapshot := commandSnapshot(t)
	done := make(chan os.Signal)
	close(done)
	application := &applicationFake{done: done}
	loads := 0
	builds := 0
	err := runServe(
		context.Background(),
		testConfigPath,
		&bytes.Buffer{},
		commandDependencies{
			load: func(path string) (config.Snapshot, error) {
				loads++
				if path != testConfigPath {
					t.Fatal("unexpected config path")
				}
				return snapshot, nil
			},
			build: func(got config.Snapshot, _ io.Writer) (managedApplication, error) {
				builds++
				if got.Mode() != config.ModeInbound {
					t.Fatal("Fx build received a different snapshot")
				}
				return application, nil
			},
			withTimeout: context.WithTimeout,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if loads != 1 || builds != 1 ||
		!equalStrings(application.callSnapshot(), []string{testStartCall, testDoneCall, testStopCall}) {
		t.Fatalf("loads=%d builds=%d calls=%v", loads, builds, application.callSnapshot())
	}
	if application.startLeft <= 0 || application.startLeft > app.StartTimeout ||
		application.stopLeft <= 0 || application.stopLeft > snapshot.ShutdownTimeout() {
		t.Fatalf("start bound=%s stop bound=%s", application.startLeft, application.stopLeft)
	}
}

// TestRunServeContainsWaitAndStopPanics proves lifecycle seams cannot bypass cleanup.
func TestRunServeContainsWaitAndStopPanics(t *testing.T) {
	snapshot := commandSnapshot(t)
	for _, test := range []struct {
		name        string
		application *applicationFake
	}{
		{name: "start panic", application: &applicationFake{panicStart: true}},
		{name: "wait panic", application: &applicationFake{panicDone: true}},
		{name: "stop panic", application: &applicationFake{done: closedSignal(), panicStop: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := runServe(
				context.Background(),
				testConfigPath,
				&bytes.Buffer{},
				commandDependencies{
					load: func(string) (config.Snapshot, error) { return snapshot, nil },
					build: func(config.Snapshot, io.Writer) (managedApplication, error) {
						return test.application, nil
					},
					withTimeout: context.WithTimeout,
				},
			)
			if !errors.Is(err, errCommandRuntime) {
				t.Fatalf("runServe() error = %v", err)
			}
			if calls := test.application.callSnapshot(); len(calls) < 2 ||
				calls[0] != testStartCall || calls[len(calls)-1] != testStopCall {
				t.Fatalf("panic cleanup calls = %v", calls)
			}
		})
	}
}

// closedSignal returns one already-terminal process signal channel.
func closedSignal() chan os.Signal {
	done := make(chan os.Signal)
	close(done)
	return done
}

// equalStrings reports exact ordered equality without external dependencies.
func equalStrings(left, right []string) bool {
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
