package command

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
)

const (
	testStartCall  = "start"
	testWaitCall   = "wait"
	testStopCall   = "stop"
	testConfigFlag = "--config"
	testConfigPath = "/tmp/config.yaml"
)

// commandOwnerFake records command-side protected ownership.
type commandOwnerFake struct {
	mu           sync.Mutex
	closeCalls   int
	closeError   error
	stopLimit    time.Duration
	stopError    error
	panicOnClose bool
}

// Close records one command-side release without retaining protected values.
func (o *commandOwnerFake) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closeCalls++
	if o.panicOnClose {
		panic("protected marker")
	}
	return o.closeError
}

// stopTimeout returns the deterministic fake outer shutdown budget.
func (o *commandOwnerFake) stopTimeout() (time.Duration, error) {
	if o.stopError != nil {
		return 0, o.stopError
	}
	return o.stopLimit, nil
}

// closes returns the synchronized close count.
func (o *commandOwnerFake) closes() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.closeCalls
}

// commandApplicationFake records explicit application orchestration.
type commandApplicationFake struct {
	mu               sync.Mutex
	calls            []string
	startError       error
	stopError        error
	signal           applicationSignal
	closeWait        bool
	blockWait        bool
	blockStart       bool
	nilWait          bool
	panicWait        bool
	panicStop        bool
	startHasDeadline bool
	startRemaining   time.Duration
	startCallback    func()
	stopHasDeadline  bool
	stopRemaining    time.Duration
}

// Start records explicit application startup.
func (a *commandApplicationFake) Start(ctx context.Context) error {
	a.mu.Lock()
	a.calls = append(a.calls, testStartCall)
	deadline, present := ctx.Deadline()
	a.startHasDeadline = present
	if present {
		a.startRemaining = time.Until(deadline)
	}
	callback := a.startCallback
	block := a.blockStart
	startError := a.startError
	a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if callback != nil {
		callback()
	}
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	return startError
}

// Wait records explicit waiting and returns one deterministic signal.
func (a *commandApplicationFake) Wait() <-chan applicationSignal {
	a.mu.Lock()
	a.calls = append(a.calls, testWaitCall)
	panicWait := a.panicWait
	nilWait := a.nilWait
	a.mu.Unlock()
	if panicWait {
		panic("private wait marker")
	}
	if nilWait {
		return nil
	}
	wait := make(chan applicationSignal, 1)
	if a.blockWait {
		return wait
	}
	if !a.closeWait {
		wait <- a.signal
	}
	close(wait)
	return wait
}

// TestRunServeCancellationStopsWithTheCommandBound proves cancellation cannot strand Fx waiting.
func TestRunServeCancellationStopsWithTheCommandBound(t *testing.T) {
	t.Parallel()
	stopTimeout := 250 * time.Millisecond
	owner := &commandOwnerFake{stopLimit: stopTimeout}
	ctx, cancel := context.WithCancel(context.Background())
	application := &commandApplicationFake{blockWait: true, startCallback: cancel}
	err := runServe(
		ctx,
		testConfigPath,
		config.NewFlagValues("", false, "", false, "", false),
		commandDependencies{
			load: func(string, config.FlagValues) (bootstrapOwner, error) {
				return owner, nil
			},
			build: func(bootstrapOwner, time.Duration) (managedApplication, error) {
				return application, nil
			},
			withTimeout: context.WithTimeout,
		},
	)
	if !errors.Is(err, errCommandRuntime) {
		t.Fatal("canceled command did not return the stable runtime failure")
	}
	if owner.closes() != 0 {
		t.Fatal("canceled command reclaimed transferred ownership")
	}
	if got := application.callSnapshot(); !equalCalls(got, []string{testStartCall, testWaitCall, testStopCall}) {
		t.Fatalf("application calls = %v", got)
	}
	if !application.stopHasDeadline ||
		application.stopRemaining <= 0 ||
		application.stopRemaining > stopTimeout {
		t.Fatalf("stop deadline remaining = %s", application.stopRemaining)
	}
	if !application.startHasDeadline ||
		application.startRemaining < app.LifecycleStartTimeout-time.Second ||
		application.startRemaining > app.LifecycleStartTimeout {
		t.Fatalf("start deadline remaining = %s", application.startRemaining)
	}
}

// TestRunValidateLoadsAndReleasesProtectedState proves validation never builds the runtime.
func TestRunValidateLoadsAndReleasesProtectedState(t *testing.T) {
	t.Parallel()
	owner := &commandOwnerFake{}
	builds := 0
	deps := commandDependencies{
		load: func(path string, _ config.FlagValues) (bootstrapOwner, error) {
			if path != testConfigPath {
				t.Fatal("validation used an unexpected path")
			}
			return owner, nil
		},
		build: func(bootstrapOwner, time.Duration) (managedApplication, error) {
			builds++
			return nil, errCommandRuntime
		},
		withTimeout: context.WithTimeout,
	}
	if err := runValidate(testConfigPath, deps); err != nil {
		t.Fatal(err)
	}
	if owner.closes() != 1 || builds != 0 {
		t.Fatalf("validation closes=%d builds=%d", owner.closes(), builds)
	}
}

// TestRunValidateFailsClosed proves invalid paths, load failures, and close failures are rejected.
func TestRunValidateFailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		path       string
		owner      bootstrapOwner
		err        error
		loadPanic  bool
		wantCloses int
	}{
		{name: "relative path", path: "dkim2d.yaml", owner: &commandOwnerFake{}},
		{name: "load failure", path: testConfigPath, err: errCommandRuntime},
		{
			name: "ambiguous load", path: testConfigPath,
			owner: &commandOwnerFake{}, err: errCommandRuntime, wantCloses: 1,
		},
		{name: "load panic", path: testConfigPath, loadPanic: true},
		{
			name: "close failure", path: testConfigPath,
			owner: &commandOwnerFake{closeError: errCommandRuntime}, wantCloses: 1,
		},
		{
			name: "close panic", path: testConfigPath,
			owner: &commandOwnerFake{panicOnClose: true}, wantCloses: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deps := commandDependencies{
				load: func(string, config.FlagValues) (bootstrapOwner, error) {
					if test.loadPanic {
						panic("protected loader marker")
					}
					return test.owner, test.err
				},
			}
			if err := runValidate(test.path, deps); !errors.Is(err, errCommandRuntime) {
				t.Fatalf("runValidate() error = %v", err)
			}
			if owner, ok := test.owner.(*commandOwnerFake); ok &&
				owner.closes() != test.wantCloses {
				t.Fatalf("protected closes = %d, want %d", owner.closes(), test.wantCloses)
			}
		})
	}
}

// TestRunServeBoundsHostileStartWithTheExactContract proves the 115-second request is explicit.
func TestRunServeBoundsHostileStartWithTheExactContract(t *testing.T) {
	t.Parallel()
	owner := &commandOwnerFake{stopLimit: time.Second}
	application := &commandApplicationFake{blockStart: true}
	var requested time.Duration
	err := runServe(
		context.Background(),
		testConfigPath,
		config.NewFlagValues("", false, "", false, "", false),
		commandDependencies{
			load: func(string, config.FlagValues) (bootstrapOwner, error) {
				return owner, nil
			},
			build: func(bootstrapOwner, time.Duration) (managedApplication, error) {
				return application, nil
			},
			withTimeout: func(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
				requested = timeout
				return context.WithTimeout(parent, 10*time.Millisecond)
			},
		},
	)
	if !errors.Is(err, errCommandRuntime) {
		t.Fatal("hostile start did not return the stable runtime failure")
	}
	if requested != app.LifecycleStartTimeout {
		t.Fatalf("requested start timeout = %s, want %s", requested, app.LifecycleStartTimeout)
	}
	if owner.closes() != 1 {
		t.Fatalf("prebootstrap closes = %d, want 1", owner.closes())
	}
	if got := application.callSnapshot(); !equalCalls(got, []string{testStartCall}) {
		t.Fatalf("application calls = %v", got)
	}
}

// Stop records explicit application shutdown and its command-owned deadline.
func (a *commandApplicationFake) Stop(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, testStopCall)
	deadline, present := ctx.Deadline()
	a.stopHasDeadline = present
	if present {
		a.stopRemaining = time.Until(deadline)
	}
	if a.panicStop {
		panic("private stop marker")
	}
	return a.stopError
}

// callSnapshot returns one owned copy of the application call order.
func (a *commandApplicationFake) callSnapshot() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.calls...)
}

// commandHarness executes one fake command and returns stable output.
func commandHarness(
	t *testing.T,
	args []string,
	owner *commandOwnerFake,
	application *commandApplicationFake,
	loadError error,
	buildError error,
) (int, string, string, int, time.Duration) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	loadCalls := 0
	var builtTimeout time.Duration
	deps := commandDependencies{
		load: func(string, config.FlagValues) (bootstrapOwner, error) {
			loadCalls++
			if loadError != nil {
				return nil, loadError
			}
			return owner, nil
		},
		build: func(_ bootstrapOwner, timeout time.Duration) (managedApplication, error) {
			builtTimeout = timeout
			if buildError != nil {
				return nil, buildError
			}
			return application, nil
		},
		withTimeout: context.WithTimeout,
	}
	exit := executeWithDependencies(args, &stdout, &stderr, deps)
	return exit, stdout.String(), stderr.String(), loadCalls, builtTimeout
}

// TestCommandHelpAndShapeFreezeStableExits proves help and malformed input never bootstrap.
func TestCommandHelpAndShapeFreezeStableExits(t *testing.T) {
	t.Parallel()
	marker := "private-command-marker"
	tests := []struct {
		name       string
		args       []string
		wantExit   int
		wantStdout bool
		wantStderr string
	}{
		{name: "root help", args: []string{"--help"}, wantExit: 0, wantStdout: true},
		{name: "serve help", args: []string{serveCommandName, "--help"}, wantExit: 0, wantStdout: true},
		{name: "missing command", wantExit: 2, wantStderr: commandShapeDiagnostic},
		{name: "missing required config", args: []string{serveCommandName}, wantExit: 2, wantStderr: commandShapeDiagnostic},
		{name: "positional argument", args: []string{serveCommandName, testConfigFlag, testConfigPath, marker}, wantExit: 2, wantStderr: commandShapeDiagnostic},
		{name: "unknown flag", args: []string{serveCommandName, testConfigFlag, testConfigPath, "--" + marker}, wantExit: 2, wantStderr: commandShapeDiagnostic},
		{name: "completion command", args: []string{completionCommandName, marker}, wantExit: 2, wantStderr: commandShapeDiagnostic},
		{name: "hidden completion", args: []string{hiddenCompletionCommand, marker}, wantExit: 2, wantStderr: commandShapeDiagnostic},
		{name: "hidden completion no description", args: []string{hiddenNoDescCompletionCmd, marker}, wantExit: 2, wantStderr: commandShapeDiagnostic},
		{name: "help completion", args: []string{helpCommandName, completionCommandName, marker}, wantExit: 2, wantStderr: commandShapeDiagnostic},
		{name: "help hidden completion", args: []string{helpCommandName, hiddenCompletionCommand, marker}, wantExit: 2, wantStderr: commandShapeDiagnostic},
		{name: "help hidden completion no description", args: []string{helpCommandName, hiddenNoDescCompletionCmd, marker}, wantExit: 2, wantStderr: commandShapeDiagnostic},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			owner := &commandOwnerFake{stopLimit: time.Second}
			application := &commandApplicationFake{}
			exit, stdout, stderr, loads, _ := commandHarness(
				t,
				test.args,
				owner,
				application,
				nil,
				nil,
			)
			if exit != test.wantExit {
				t.Fatalf("exit = %d, want %d", exit, test.wantExit)
			}
			if test.wantStdout != strings.Contains(stdout, commandUsage) {
				t.Fatalf("stdout usage presence = %t, want %t", strings.Contains(stdout, commandUsage), test.wantStdout)
			}
			if test.wantStderr == "" {
				if stderr != "" {
					t.Fatalf("stderr = %q, want empty", stderr)
				}
			} else if !strings.HasPrefix(stderr, test.wantStderr) ||
				!strings.Contains(stderr, commandUsage) {
				t.Fatalf("stderr did not contain stable diagnostic and usage")
			}
			if strings.Contains(stdout, marker) || strings.Contains(stderr, marker) {
				t.Fatal("command output exposed an input-derived marker")
			}
			if loads != 0 || owner.closes() != 0 || len(application.callSnapshot()) != 0 {
				t.Fatal("help or malformed input reached runtime ownership")
			}
		})
	}
}

// TestCommandClosesOwnerReturnedAlongsideLoadError proves ambiguous load ownership fails closed.
func TestCommandClosesOwnerReturnedAlongsideLoadError(t *testing.T) {
	t.Parallel()
	owner := &commandOwnerFake{stopLimit: time.Second}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exit := executeWithDependencies(
		[]string{serveCommandName, testConfigFlag, testConfigPath},
		&stdout,
		&stderr,
		commandDependencies{
			load: func(string, config.FlagValues) (bootstrapOwner, error) {
				return owner, errors.New("private load marker")
			},
			build: func(bootstrapOwner, time.Duration) (managedApplication, error) {
				t.Fatal("ambiguous load ownership reached Fx build")
				return nil, nil
			},
			withTimeout: context.WithTimeout,
		},
	)
	if exit != 1 || stdout.String() != "" || stderr.String() != commandRuntimeDiagnostic {
		t.Fatalf("result = %d/%q/%q", exit, stdout.String(), stderr.String())
	}
	if owner.closes() != 1 {
		t.Fatalf("owner closes = %d, want 1", owner.closes())
	}
}

// TestCommandPreservesTransferWhenStartCancelPanics proves cancellation cannot reclaim ownership.
func TestCommandPreservesTransferWhenStartCancelPanics(t *testing.T) {
	t.Parallel()
	owner := &commandOwnerFake{stopLimit: time.Second}
	application := &commandApplicationFake{}
	timeoutCalls := 0
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exit := executeWithDependencies(
		[]string{serveCommandName, testConfigFlag, testConfigPath},
		&stdout,
		&stderr,
		commandDependencies{
			load: func(string, config.FlagValues) (bootstrapOwner, error) {
				return owner, nil
			},
			build: func(bootstrapOwner, time.Duration) (managedApplication, error) {
				return application, nil
			},
			withTimeout: func(
				parent context.Context,
				timeout time.Duration,
			) (context.Context, context.CancelFunc) {
				timeoutCalls++
				ctx, cancel := context.WithTimeout(parent, timeout)
				if timeoutCalls == 1 {
					return ctx, func() {
						cancel()
						panic("private cancel marker")
					}
				}
				return ctx, cancel
			},
		},
	)
	if exit != 1 || stdout.String() != "" || stderr.String() != commandRuntimeDiagnostic {
		t.Fatalf("result = %d/%q/%q", exit, stdout.String(), stderr.String())
	}
	if owner.closes() != 0 {
		t.Fatal("command reclaimed ownership after successful Start")
	}
	if got := application.callSnapshot(); !equalCalls(got, []string{testStartCall, testStopCall}) {
		t.Fatalf("application calls = %v, want start/stop", got)
	}
}

// TestCommandFailureOwnershipAndPrivacy proves every pre-transfer failure closes once.
func TestCommandFailureOwnershipAndPrivacy(t *testing.T) {
	t.Parallel()
	marker := "private-runtime-marker"
	tests := []struct {
		name       string
		args       []string
		loadError  error
		timeoutErr error
		buildError error
		startError error
		wantLoads  int
		wantCloses int
		wantCalls  []string
	}{
		{
			name: "relative path",
			args: []string{serveCommandName, testConfigFlag, marker},
		},
		{
			name:      "load failure",
			args:      []string{serveCommandName, testConfigFlag, "/tmp/" + marker},
			loadError: errors.New(marker),
			wantLoads: 1,
		},
		{
			name:       "timeout failure",
			args:       []string{serveCommandName, testConfigFlag, "/tmp/" + marker},
			timeoutErr: errors.New(marker),
			wantLoads:  1,
			wantCloses: 1,
		},
		{
			name:       "build failure",
			args:       []string{serveCommandName, testConfigFlag, "/tmp/" + marker},
			buildError: errors.New(marker),
			wantLoads:  1,
			wantCloses: 1,
		},
		{
			name:       "start failure",
			args:       []string{serveCommandName, testConfigFlag, "/tmp/" + marker},
			startError: errors.New(marker),
			wantLoads:  1,
			wantCloses: 1,
			wantCalls:  []string{testStartCall},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			owner := &commandOwnerFake{
				stopLimit: time.Second,
				stopError: test.timeoutErr,
			}
			application := &commandApplicationFake{startError: test.startError}
			exit, stdout, stderr, loads, _ := commandHarness(
				t,
				test.args,
				owner,
				application,
				test.loadError,
				test.buildError,
			)
			if exit != 1 {
				t.Fatalf("exit = %d, want 1", exit)
			}
			if stdout != "" || stderr != commandRuntimeDiagnostic {
				t.Fatalf("output was not the stable runtime diagnostic")
			}
			if strings.Contains(stdout, marker) || strings.Contains(stderr, marker) {
				t.Fatal("runtime output exposed an input-derived marker")
			}
			if loads != test.wantLoads || owner.closes() != test.wantCloses {
				t.Fatalf(
					"loads/closes = %d/%d, want %d/%d",
					loads,
					owner.closes(),
					test.wantLoads,
					test.wantCloses,
				)
			}
			if got := application.callSnapshot(); !equalCalls(got, test.wantCalls) {
				t.Fatalf("application calls = %v, want %v", got, test.wantCalls)
			}
		})
	}
}

// TestCommandSuccessfulTransferAndBoundedStop proves explicit orchestration and ownership transfer.
func TestCommandSuccessfulTransferAndBoundedStop(t *testing.T) {
	t.Parallel()
	stopTimeout := 250 * time.Millisecond
	owner := &commandOwnerFake{stopLimit: stopTimeout}
	application := &commandApplicationFake{}
	exit, stdout, stderr, loads, builtTimeout := commandHarness(
		t,
		[]string{
			serveCommandName,
			testConfigFlag, testConfigPath,
			"--listen", "127.0.0.1:9090",
			"--policy-mode", "strict",
			"--replay-backend", "disabled",
		},
		owner,
		application,
		nil,
		nil,
	)
	if exit != 0 || stdout != "" || stderr != "" {
		t.Fatalf("result = exit %d stdout %q stderr %q, want clean", exit, stdout, stderr)
	}
	if loads != 1 || builtTimeout != stopTimeout {
		t.Fatalf("loads/timeout = %d/%s, want 1/%s", loads, builtTimeout, stopTimeout)
	}
	if owner.closes() != 0 {
		t.Fatal("command closed protected material after successful lifecycle transfer")
	}
	if got := application.callSnapshot(); !equalCalls(got, []string{testStartCall, testWaitCall, testStopCall}) {
		t.Fatalf("application calls = %v", got)
	}
	if !application.stopHasDeadline ||
		application.stopRemaining <= 0 ||
		application.stopRemaining > stopTimeout {
		t.Fatalf("stop deadline remaining = %s", application.stopRemaining)
	}
	if !application.startHasDeadline ||
		application.startRemaining < app.LifecycleStartTimeout-time.Second ||
		application.startRemaining > app.LifecycleStartTimeout {
		t.Fatalf("start deadline remaining = %s", application.startRemaining)
	}
}

// TestCommandPropagatesDynamicStopBounds proves both validated endpoint budgets stay exact.
func TestCommandPropagatesDynamicStopBounds(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		shutdown time.Duration
		stop     time.Duration
	}{
		{shutdown: time.Second, stop: 51 * time.Second},
		{shutdown: 120 * time.Second, stop: 170 * time.Second},
	} {
		test := test
		t.Run(test.shutdown.String(), func(t *testing.T) {
			t.Parallel()
			stopTimeout, err := app.LifecycleStopTimeout(test.shutdown)
			if err != nil || stopTimeout != test.stop {
				t.Fatalf("derived stop timeout = %s, want %s", stopTimeout, test.stop)
			}
			owner := &commandOwnerFake{stopLimit: stopTimeout}
			application := &commandApplicationFake{}
			exit, _, stderr, _, builtTimeout := commandHarness(
				t,
				[]string{serveCommandName, testConfigFlag, testConfigPath},
				owner,
				application,
				nil,
				nil,
			)
			if exit != 0 || stderr != "" {
				t.Fatalf("exit/stderr = %d/%q", exit, stderr)
			}
			if builtTimeout != stopTimeout {
				t.Fatalf("Fx build timeout = %s, want %s", builtTimeout, stopTimeout)
			}
			if !application.stopHasDeadline ||
				application.stopRemaining < stopTimeout-time.Second ||
				application.stopRemaining > stopTimeout {
				t.Fatalf("command stop deadline remaining = %s", application.stopRemaining)
			}
		})
	}
}

// TestCommandFatalSignalAndStopFailureRemainExitOne proves shutdown never hides fatal state.
func TestCommandFatalSignalAndStopFailureRemainExitOne(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		signal    applicationSignal
		closeWait bool
		nilWait   bool
		panicWait bool
		panicStop bool
		stopError error
	}{
		{name: "fatal signal", signal: applicationSignal{Failed: true}},
		{name: "closed wait", closeWait: true},
		{name: "nil wait", nilWait: true},
		{name: "wait panic", panicWait: true},
		{name: "stop panic", panicStop: true},
		{name: "stop failure", stopError: errors.New("private-stop-marker")},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			owner := &commandOwnerFake{stopLimit: time.Second}
			application := &commandApplicationFake{
				signal:    test.signal,
				closeWait: test.closeWait,
				nilWait:   test.nilWait,
				panicWait: test.panicWait,
				panicStop: test.panicStop,
				stopError: test.stopError,
			}
			exit, stdout, stderr, _, _ := commandHarness(
				t,
				[]string{serveCommandName, testConfigFlag, testConfigPath},
				owner,
				application,
				nil,
				nil,
			)
			if exit != 1 || stdout != "" || stderr != commandRuntimeDiagnostic {
				t.Fatalf("fatal result = exit %d stdout %q stderr %q", exit, stdout, stderr)
			}
			if owner.closes() != 0 {
				t.Fatal("command reclaimed already transferred ownership")
			}
			if got := application.callSnapshot(); !equalCalls(got, []string{testStartCall, testWaitCall, testStopCall}) {
				t.Fatalf("application calls = %v", got)
			}
		})
	}
}

// TestCommandContainsDependencyPanic proves panic text never escapes command diagnostics.
func TestCommandContainsDependencyPanic(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	marker := "private-panic-marker"
	exit := executeWithDependencies(
		[]string{serveCommandName, testConfigFlag, testConfigPath},
		&stdout,
		&stderr,
		commandDependencies{
			load: func(string, config.FlagValues) (bootstrapOwner, error) {
				panic(marker)
			},
			build: func(bootstrapOwner, time.Duration) (managedApplication, error) {
				return nil, nil
			},
			withTimeout: context.WithTimeout,
		},
	)
	if exit != 1 {
		t.Fatalf("exit = %d, want 1", exit)
	}
	if stdout.String() != "" || stderr.String() != commandRuntimeDiagnostic {
		t.Fatalf("panic output was not stable")
	}
	if strings.Contains(stderr.String(), marker) {
		t.Fatal("panic marker escaped stable command output")
	}
}

// equalCalls compares deterministic application call sequences.
func equalCalls(got []string, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
