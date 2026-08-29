package valkey

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	dkim2 "github.com/croessner/dkim2"
	valkeygo "github.com/valkey-io/valkey-go"
)

const (
	syntheticReplyMarker       = "SYNTHETIC-PRIVATE-REPLY-MARKER"
	syntheticSecretMarker      = "0123456789ABCDEF0123456789ABCDEF"
	panicPointMessage          = "message"
	panicPointString           = "string"
	canonicalInt64OverflowText = "9223372036854775808"
	testPrimaryInternal        = "internal"
	testPrimaryMalformed       = "malformed"
	testPrimaryMismatch        = "mismatch"
	testPrimaryTransport       = "transport"
	testStateDegraded          = "degraded"
	testStateReady             = "ready"
	testNameEmpty              = "empty"
	testNameNonASCII           = "non ascii"
	testNameNil                = "nil"
	testNamePointer            = "pointer"
	testParentOwned            = "owned"
	testFormatDetailed         = "%+v"
	testFormatGoSyntax         = "%#v"
)

// fakeCommand records only bounded command properties needed by the adapter contract.
type fakeCommand struct {
	retryable bool
	panicRead bool
	onRead    func()
}

// IsRetryable reports the injected retry flag.
func (c fakeCommand) IsRetryable() bool {
	if c.onRead != nil {
		c.onRead()
	}
	if c.panicRead {
		panic("synthetic retryability panic")
	}
	return c.retryable
}

// typedNilCommand is a practical typed-nil command seam.
type typedNilCommand struct{}

// IsRetryable is never valid on a nil command receiver.
func (*typedNilCommand) IsRetryable() bool { return false }

// typedNilCommandClient is a practical typed-nil constructor dependency.
type typedNilCommandClient struct{}

// BuildSet is unreachable for a rejected typed-nil client.
func (*typedNilCommandClient) BuildSet(string, string, int64) command { return nil }

// Do is unreachable for a rejected typed-nil client.
func (*typedNilCommandClient) Do(context.Context, command) resultReader { return nil }

// fakeCommandClient captures one command build and dispatch without provider I/O.
type fakeCommandClient struct {
	mu            sync.Mutex
	buildCalls    int
	dispatchCalls int
	key           string
	marker        string
	milliseconds  int64
	command       command
	result        resultReader
	buildPanic    bool
	dispatchPanic bool
	onDispatch    func()
	onBuild       func()
}

// BuildSet captures the exact one-command input without retaining it beyond the test.
func (c *fakeCommandClient) BuildSet(key, marker string, milliseconds int64) command {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buildCalls++
	if c.onBuild != nil {
		c.onBuild()
	}
	if c.buildPanic {
		panic("synthetic build panic")
	}
	c.key = key
	c.marker = marker
	c.milliseconds = milliseconds
	return c.command
}

// Do records one dispatch and returns the injected bounded result.
func (c *fakeCommandClient) Do(context.Context, command) resultReader {
	c.mu.Lock()
	c.dispatchCalls++
	onDispatch := c.onDispatch
	result := c.result
	dispatchPanic := c.dispatchPanic
	c.mu.Unlock()
	if onDispatch != nil {
		onDispatch()
	}
	if dispatchPanic {
		panic("synthetic dispatch panic")
	}
	return result
}

// counts returns the captured build and dispatch counts.
func (c *fakeCommandClient) counts() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buildCalls, c.dispatchCalls
}

// fakeResult implements the exact package-private result-reader seam.
type fakeResult struct {
	nonValkeyErr error
	raw          string
	err          error
	message      valkeygo.ValkeyMessage
	messageErr   error

	nonValkeyCalls int
	stringCalls    int
	messageCalls   int
	panicAt        string
}

// hostileContext injects an impossible or panicking Err result at one preflight.
type hostileContext struct {
	calls  int
	failAt int
	err    error
	panic  bool
}

// Deadline reports no deadline for the synthetic hostile context.
func (*hostileContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done reports no asynchronous completion for the synthetic hostile context.
func (*hostileContext) Done() <-chan struct{} { return nil }

// Err returns or panics with the configured hostile state at one exact call.
func (c *hostileContext) Err() error {
	c.calls++
	if c.calls != c.failAt {
		return nil
	}
	if c.panic {
		panic("synthetic context panic")
	}
	return c.err
}

// Value returns no values for the synthetic hostile context.
func (*hostileContext) Value(any) any { return nil }

// deadlineCapabilityContext exposes one controlled context deadline capability.
type deadlineCapabilityContext struct {
	deadline time.Time
	present  bool
	panic    bool
}

// Deadline returns or panics with the configured synthetic deadline.
func (c *deadlineCapabilityContext) Deadline() (time.Time, bool) {
	if c.panic {
		panic("synthetic deadline panic")
	}
	return c.deadline, c.present
}

// Done reports no asynchronous completion for the synthetic deadline context.
func (*deadlineCapabilityContext) Done() <-chan struct{} { return nil }

// Err reports a live context so preflight must inspect the deadline capability.
func (*deadlineCapabilityContext) Err() error { return nil }

// Value returns no values for the synthetic deadline context.
func (*deadlineCapabilityContext) Value(any) any { return nil }

// NonValkeyError returns the injected non-authoritative failure.
func (r *fakeResult) NonValkeyError() error {
	r.nonValkeyCalls++
	if r.panicAt == "non_valkey" {
		panic("synthetic result panic")
	}
	return r.nonValkeyErr
}

// ToString returns one injected lossless value/error pair.
func (r *fakeResult) ToString() (string, error) {
	r.stringCalls++
	if r.panicAt == panicPointString {
		panic("synthetic result panic")
	}
	return r.raw, r.err
}

// ToMessage returns one injected response-type proof.
func (r *fakeResult) ToMessage() (valkeygo.ValkeyMessage, error) {
	r.messageCalls++
	if r.panicAt == panicPointMessage {
		panic("synthetic result panic")
	}
	return r.message, r.messageErr
}

// TestStoreBuildsAndDispatchesOneNonRetryableSet verifies protected command capture.
func TestStoreBuildsAndDispatchesOneNonRetryableSet(t *testing.T) {
	result := resultFromMessage(t, cachedMessage(t, '+', "OK"))
	client := &fakeCommandClient{command: fakeCommand{}, result: result}
	store := mustCommandStore(t, client)
	key := validReplayKey(t)
	retention, err := dkim2.NewReplayRetention(1500 * time.Millisecond)
	if err != nil {
		t.Fatal("retention construction failed")
	}

	check, err := store.CheckAndRemember(context.Background(), key, retention)
	if err != nil || check != dkim2.ReplayCheckFirstSeen {
		t.Fatalf("unexpected bounded result: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
	}
	builds, dispatches := client.counts()
	if builds != 1 || dispatches != 1 {
		t.Fatalf("command counts = (%d,%d), want (1,1)", builds, dispatches)
	}
	if client.marker != dkim2.ReplayStoredValue || client.milliseconds != 1500 {
		t.Fatal("command marker or retention differs from the frozen contract")
	}
	if client.key == "" || strings.Contains(client.key, syntheticSecretMarker) {
		t.Fatal("protected command key was absent or derived from a raw secret")
	}
	if state := store.State(); state != dkim2.ReplayStoreReady {
		t.Fatalf("state = %q, want ready", state)
	}
}

// TestCommandStoreRejectsNilClients verifies constructor-only valid client state.
func TestCommandStoreRejectsNilClients(t *testing.T) {
	for name, client := range map[string]commandClient{
		testNameNil: nil,
		"typed nil": (*typedNilCommandClient)(nil),
	} {
		t.Run(name, func(t *testing.T) {
			store, err := newCommandStore(client)
			if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorMisconfigured {
				t.Fatalf("constructor result: store-present=%t code=%q",
					store != nil, dkim2.ReplayErrorCodeOf(err))
			}
		})
	}
}

// TestStoreRejectsBeforeDispatch verifies exact preflight and command-construction boundaries.
func TestStoreRejectsBeforeDispatch(t *testing.T) {
	key := validReplayKey(t)
	retention := dkim2.DefaultReplayRetention()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, expire := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer expire()

	cases := []struct {
		name string
		ctx  context.Context
		key  dkim2.ReplayKey
		ret  dkim2.ReplayRetention
		code dkim2.ReplayErrorCode
	}{
		{name: "nil context", ctx: nil, key: key, ret: retention, code: dkim2.ReplayErrorInvalidRequest},
		{name: "cancelled", ctx: cancelled, key: key, ret: retention, code: dkim2.ReplayErrorCancelled},
		{name: syntheticDeadlineName, ctx: expired, key: key, ret: retention, code: dkim2.ReplayErrorDeadlineExceeded},
		{name: "zero key", ctx: context.Background(), ret: retention, code: dkim2.ReplayErrorInvalidRequest},
		{name: "zero retention", ctx: context.Background(), key: key, code: dkim2.ReplayErrorInvalidRequest},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			client := &fakeCommandClient{command: fakeCommand{}, result: resultFromMessage(t, cachedMessage(t, '+', "OK"))}
			store := mustCommandStore(t, client)
			check, err := store.CheckAndRemember(testCase.ctx, testCase.key, testCase.ret)
			if check != 0 || dkim2.ReplayErrorCodeOf(err) != testCase.code {
				t.Fatalf("bounded result: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
			}
			builds, dispatches := client.counts()
			if builds != 0 || dispatches != 0 {
				t.Fatalf("command counts = (%d,%d), want zero", builds, dispatches)
			}
			if store.State() != dkim2.ReplayStoreReady {
				t.Fatal("ordinary preflight refusal degraded the store")
			}
		})
	}

	for name, command := range map[string]command{
		"nil command":       nil,
		"typed nil command": (*typedNilCommand)(nil),
		"retryable command": fakeCommand{retryable: true},
		"retry flag panic":  fakeCommand{panicRead: true},
	} {
		t.Run(name, func(t *testing.T) {
			client := &fakeCommandClient{command: command}
			store := mustCommandStore(t, client)
			check, err := store.CheckAndRemember(context.Background(), key, retention)
			if check != 0 || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
				t.Fatalf("bounded result: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
			}
			_, dispatches := client.counts()
			if dispatches != 0 {
				t.Fatalf("dispatches = %d, want zero", dispatches)
			}
		})
	}

	t.Run("build panic", func(t *testing.T) {
		client := &fakeCommandClient{buildPanic: true}
		store := mustCommandStore(t, client)
		check, err := store.CheckAndRemember(context.Background(), key, retention)
		if check != 0 || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
			t.Fatalf("bounded result: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
		}
		_, dispatches := client.counts()
		if dispatches != 0 {
			t.Fatalf("dispatches = %d, want zero", dispatches)
		}
	})

	for _, boundary := range []string{"build", "retryability"} {
		t.Run("cancel during "+boundary, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			client := &fakeCommandClient{result: resultFromMessage(t, cachedMessage(t, '+', "OK"))}
			if boundary == "build" {
				client.onBuild = cancel
				client.command = fakeCommand{}
			} else {
				client.command = fakeCommand{onRead: cancel}
			}
			store := mustCommandStore(t, client)
			check, err := store.CheckAndRemember(ctx, key, retention)
			if check != 0 || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorCancelled ||
				!errors.Is(err, context.Canceled) {
				t.Fatalf("bounded result: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
			}
			_, dispatches := client.counts()
			if dispatches != 0 {
				t.Fatalf("dispatches = %d, want zero", dispatches)
			}
			if store.State() != dkim2.ReplayStoreReady {
				t.Fatal("ordinary final-preflight cancellation degraded the store")
			}
		})
	}

	t.Run("deadline at final preflight", func(t *testing.T) {
		ctx := &hostileContext{failAt: 5, err: context.DeadlineExceeded}
		client := &fakeCommandClient{
			command: fakeCommand{},
			result:  resultFromMessage(t, cachedMessage(t, '+', "OK")),
		}
		store := mustCommandStore(t, client)
		check, err := store.CheckAndRemember(ctx, key, retention)
		if check != 0 || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorDeadlineExceeded ||
			!errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("bounded result: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
		}
		builds, dispatches := client.counts()
		if builds != 1 || dispatches != 0 {
			t.Fatalf("command counts = (%d,%d), want (1,0)", builds, dispatches)
		}
		if store.State() != dkim2.ReplayStoreReady {
			t.Fatal("ordinary final-preflight deadline degraded the store")
		}
	})
}

// TestHostilePreflightPublishesStickyRestart verifies context contradictions degrade before dispatch.
func TestHostilePreflightPublishesStickyRestart(t *testing.T) {
	for _, failAt := range []int{1, 2, 5} {
		for _, panics := range []bool{false, true} {
			name := fmt.Sprintf("preflight_%d_panic_%t", failAt, panics)
			t.Run(name, func(t *testing.T) {
				client := &fakeCommandClient{
					command: fakeCommand{},
					result:  resultFromMessage(t, cachedMessage(t, '+', "OK")),
				}
				store := mustCommandStore(t, client)
				ctx := &hostileContext{
					failAt: failAt,
					err:    errors.New("synthetic impossible context state"),
					panic:  panics,
				}

				check, err := store.CheckAndRemember(ctx, validReplayKey(t), dkim2.DefaultReplayRetention())
				if check != 0 || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
					t.Fatalf("bounded result: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
				}
				builds, dispatches := client.counts()
				wantBuilds := 0
				if failAt >= 5 {
					wantBuilds = 1
				}
				if builds != wantBuilds || dispatches != 0 {
					t.Fatalf("command counts = (%d,%d), want (%d,0)", builds, dispatches, wantBuilds)
				}
				if got := store.strongestRecovery(); got != recoveryRestart {
					t.Fatalf("recovery class = %d, want restart", got)
				}
				if store.State() != dkim2.ReplayStoreDegraded {
					t.Fatal("hostile preflight did not publish degraded")
				}

				success, successErr := store.CheckAndRemember(
					context.Background(),
					validReplayKey(t),
					dkim2.DefaultReplayRetention(),
				)
				if successErr != nil || success != dkim2.ReplayCheckFirstSeen ||
					store.State() != dkim2.ReplayStoreDegraded {
					t.Fatalf("bounded recovery: check=%q code=%q state=%q",
						success, dkim2.ReplayErrorCodeOf(successErr), store.State())
				}
				assertPrivateFailure(t, err, store)
			})
		}
	}
}

// TestPreflightContainsHostileDeadlineCapabilities proves deadline inspection is bounded before dispatch.
func TestPreflightContainsHostileDeadlineCapabilities(t *testing.T) {
	t.Run("future deadline remains live", func(t *testing.T) {
		ctx := &deadlineCapabilityContext{
			deadline: time.Now().Add(time.Hour),
			present:  true,
		}
		if err := preflightContext(ctx); err != nil {
			t.Fatalf("future deadline code=%q", dkim2.ReplayErrorCodeOf(err))
		}
	})

	t.Run("elapsed deadline is terminal", func(t *testing.T) {
		ctx := &deadlineCapabilityContext{
			deadline: time.Now().Add(-time.Hour),
			present:  true,
		}
		err := preflightContext(ctx)
		if dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorDeadlineExceeded ||
			!errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("elapsed deadline code=%q", dkim2.ReplayErrorCodeOf(err))
		}
	})

	t.Run("deadline panic cannot dispatch", func(t *testing.T) {
		client := &fakeCommandClient{
			command: fakeCommand{},
			result:  resultFromMessage(t, cachedMessage(t, '+', "OK")),
		}
		store := mustCommandStore(t, client)
		check, err := store.CheckAndRemember(
			&deadlineCapabilityContext{panic: true},
			validReplayKey(t),
			dkim2.DefaultReplayRetention(),
		)
		if check != 0 || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
			t.Fatalf("deadline panic: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
		}
		builds, dispatches := client.counts()
		if builds != 0 || dispatches != 0 {
			t.Fatalf("command counts=(%d,%d), want (0,0)", builds, dispatches)
		}
		if store.State() != dkim2.ReplayStoreDegraded || store.strongestRecovery() != recoveryRestart {
			t.Fatalf("hostile deadline state=%q recovery=%d", store.State(), store.strongestRecovery())
		}
		assertPrivateFailure(t, err, store)
	})
}

// TestStoreMapsAuthoritativeResults verifies the exact closed result table.
func TestStoreMapsAuthoritativeResults(t *testing.T) {
	cases := []struct {
		name   string
		result resultReader
		check  dkim2.ReplayCheck
		code   dkim2.ReplayErrorCode
	}{
		{name: "ok", result: resultFromMessage(t, cachedMessage(t, '+', "OK")), check: dkim2.ReplayCheckFirstSeen},
		{name: "null", result: resultFromMessage(t, cachedMessage(t, '_', "")), check: dkim2.ReplayCheckReplayed},
		{name: "oom", result: resultFromMessage(t, cachedMessage(t, '-', serverKindOOM+" "+syntheticReplyMarker)), code: dkim2.ReplayErrorLimitExceeded},
		{name: "noauth", result: resultFromMessage(t, cachedMessage(t, '-', "NOAUTH "+syntheticReplyMarker)), code: dkim2.ReplayErrorUnavailable},
		{name: "wrongpass", result: resultFromMessage(t, cachedMessage(t, '-', "WRONGPASS "+syntheticReplyMarker)), code: dkim2.ReplayErrorUnavailable},
		{name: "noperm", result: resultFromMessage(t, cachedMessage(t, '-', "NOPERM "+syntheticReplyMarker)), code: dkim2.ReplayErrorUnavailable},
		{name: "readonly", result: resultFromMessage(t, cachedMessage(t, '-', "READONLY "+syntheticReplyMarker)), code: dkim2.ReplayErrorUnavailable},
		{name: "masterdown", result: resultFromMessage(t, cachedMessage(t, '-', "MASTERDOWN "+syntheticReplyMarker)), code: dkim2.ReplayErrorUnavailable},
		{name: "clusterdown", result: resultFromMessage(t, cachedMessage(t, '-', "CLUSTERDOWN "+syntheticReplyMarker)), code: dkim2.ReplayErrorUnavailable},
		{name: "loading", result: resultFromMessage(t, cachedMessage(t, '-', "LOADING "+syntheticReplyMarker)), code: dkim2.ReplayErrorUnavailable},
		{name: "misconf", result: resultFromMessage(t, cachedMessage(t, '-', "MISCONF "+syntheticReplyMarker)), code: dkim2.ReplayErrorUnavailable},
		{name: "noreplicas", result: resultFromMessage(t, cachedMessage(t, '-', "NOREPLICAS "+syntheticReplyMarker)), code: dkim2.ReplayErrorUnavailable},
		{name: "moved", result: resultFromMessage(t, cachedMessage(t, '-', "MOVED "+syntheticReplyMarker)), code: dkim2.ReplayErrorUnavailable},
		{name: "ask", result: resultFromMessage(t, cachedMessage(t, '-', "ASK "+syntheticReplyMarker)), code: dkim2.ReplayErrorUnavailable},
		{name: "tryagain", result: resultFromMessage(t, cachedMessage(t, '-', "TRYAGAIN "+syntheticReplyMarker)), code: dkim2.ReplayErrorUnavailable},
		{name: "busy", result: resultFromMessage(t, cachedMessage(t, '-', "BUSY "+syntheticReplyMarker)), code: dkim2.ReplayErrorUnavailable},
		{name: "err", result: resultFromMessage(t, cachedMessage(t, '-', "ERR OOM "+syntheticReplyMarker)), code: dkim2.ReplayErrorInconsistent},
		{name: auditUnknownToken, result: resultFromMessage(t, cachedMessage(t, '!', "FUTURE_KIND "+syntheticReplyMarker)), code: dkim2.ReplayErrorInconsistent},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			check, _, err := runOneCheck(t, testCase.result)
			if check != testCase.check {
				t.Fatalf("check = %q, want %q", check, testCase.check)
			}
			if testCase.code == "" {
				if err != nil {
					t.Fatalf("success returned code %q", dkim2.ReplayErrorCodeOf(err))
				}
			} else if dkim2.ReplayErrorCodeOf(err) != testCase.code {
				t.Fatalf("code = %q, want %q", dkim2.ReplayErrorCodeOf(err), testCase.code)
			}
			if err != nil && strings.Contains(err.Error(), syntheticReplyMarker) {
				t.Fatal("bounded error exposed server reply content")
			}
			wantMessages := 0
			if testCase.check == dkim2.ReplayCheckFirstSeen {
				wantMessages = 1
			}
			result := testCase.result.(*fakeResult)
			if result.nonValkeyCalls != 1 || result.stringCalls != 1 ||
				result.messageCalls != wantMessages {
				t.Fatalf("result calls = (%d,%d,%d), want (1,1,%d)",
					result.nonValkeyCalls, result.stringCalls, result.messageCalls, wantMessages)
			}
		})
	}
}

// TestStoreRejectsEveryUnexpectedReplyShape verifies exhaustive authoritative shape handling.
func TestStoreRejectsEveryUnexpectedReplyShape(t *testing.T) {
	frames := []struct {
		name    string
		prefix  byte
		payload string
	}{
		{name: "simple string", prefix: '+', payload: "PONG"},
		{name: "bulk ok", prefix: '$', payload: "OK"},
		{name: "bulk string", prefix: '$', payload: "value"},
		{name: "integer", prefix: ':', payload: ""},
		{name: "float ok", prefix: ',', payload: "OK"},
		{name: "boolean", prefix: '#', payload: ""},
		{name: "verbatim ok", prefix: '=', payload: "OK"},
		{name: "big number ok", prefix: '(', payload: "OK"},
		{name: "array", prefix: '*', payload: ""},
		{name: "set", prefix: '~', payload: ""},
		{name: "map", prefix: '%', payload: ""},
		{name: "push", prefix: '>', payload: "OK"},
	}
	for _, frame := range frames {
		t.Run(frame.name, func(t *testing.T) {
			result := resultFromMessage(t, cachedMessage(t, frame.prefix, frame.payload))
			check, _, err := runOneCheck(t, result)
			if check != 0 || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInconsistent {
				t.Fatalf("bounded result: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
			}
			wantMessages := 0
			if result.raw == "OK" && result.err == nil {
				wantMessages = 1
			}
			if result.nonValkeyCalls != 1 || result.stringCalls != 1 ||
				result.messageCalls != wantMessages {
				t.Fatalf("result calls = (%d,%d,%d), want (1,1,%d)",
					result.nonValkeyCalls, result.stringCalls, result.messageCalls, wantMessages)
			}
		})
	}
}

// TestOKCacheFrameContradictions verifies exact simple-string provenance and framing.
func TestOKCacheFrameContradictions(t *testing.T) {
	nonzeroTTL := cachedMessage(t, '+', "OK")
	ttlFrame := nonzeroTTL.CacheMarshal(make([]byte, 0, nonzeroTTL.CacheSize()))
	ttlFrame[0] = 1
	var nonzeroTTLMessage valkeygo.ValkeyMessage
	if err := nonzeroTTLMessage.CacheUnmarshalView(ttlFrame); err != nil {
		t.Fatal("nonzero TTL fixture construction failed")
	}
	cases := []struct {
		name    string
		message valkeygo.ValkeyMessage
		code    dkim2.ReplayErrorCode
	}{
		{name: "bulk ok", message: cachedMessage(t, '$', "OK"), code: dkim2.ReplayErrorInconsistent},
		{name: "nonzero ttl", message: nonzeroTTLMessage, code: dkim2.ReplayErrorInternalInvariant},
		{name: "wrong value", message: cachedMessage(t, '+', "NO"), code: dkim2.ReplayErrorInternalInvariant},
		{name: "wrong length", message: cachedMessage(t, '+', "O"), code: dkim2.ReplayErrorInternalInvariant},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			result := &fakeResult{raw: "OK", message: testCase.message}
			check, _, err := runOneCheck(t, result)
			if check != 0 || dkim2.ReplayErrorCodeOf(err) != testCase.code {
				t.Fatalf("bounded result: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
			}
			if result.nonValkeyCalls != 1 || result.stringCalls != 1 || result.messageCalls != 1 {
				t.Fatalf("result calls = (%d,%d,%d), want (1,1,1)",
					result.nonValkeyCalls, result.stringCalls, result.messageCalls)
			}
		})
	}
}

// TestStoreMapsUncertainPostDispatchFailures verifies uncertainty never unwraps caller context.
func TestStoreMapsUncertainPostDispatchFailures(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		result *fakeResult
		panic  bool
	}{
		{name: testPrimaryTransport, result: &fakeResult{nonValkeyErr: errors.New(syntheticReplyMarker)}},
		{name: "client close", result: &fakeResult{nonValkeyErr: valkeygo.ErrClosing}},
		{name: "cancel during call", result: &fakeResult{nonValkeyErr: context.Canceled}},
		{name: "deadline during call", result: &fakeResult{nonValkeyErr: context.DeadlineExceeded}},
		{name: "result panic", result: &fakeResult{panicAt: "non_valkey"}},
		{name: "dispatch panic", result: &fakeResult{}, panic: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			client := &fakeCommandClient{command: fakeCommand{}, result: testCase.result, dispatchPanic: testCase.panic}
			store := mustCommandStore(t, client)
			check, err := store.CheckAndRemember(context.Background(), validReplayKey(t), dkim2.DefaultReplayRetention())
			if check != 0 || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorIndeterminate {
				t.Fatalf("bounded result: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("post-dispatch uncertainty retained caller context identity")
			}
			if state := store.State(); state != dkim2.ReplayStoreDegraded {
				t.Fatalf("state = %q, want degraded", state)
			}
			_, dispatches := client.counts()
			if dispatches != 1 {
				t.Fatalf("dispatches = %d, want one", dispatches)
			}
			assertPrivateFailure(t, err, store)
		})
	}

	for _, panicPoint := range []string{panicPointString, panicPointMessage} {
		t.Run(panicPoint+" panic", func(t *testing.T) {
			result := &fakeResult{panicAt: panicPoint}
			if panicPoint == panicPointMessage {
				result.raw = "OK"
			}
			check, store, err := runOneCheck(t, result)
			if check != 0 || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorIndeterminate ||
				store.State() != dkim2.ReplayStoreDegraded {
				t.Fatalf("bounded result: check=%q code=%q state=%q",
					check, dkim2.ReplayErrorCodeOf(err), store.State())
			}
		})
	}
}

// TestStoreRejectsImpossibleResultSeams verifies nil results remain contract failures after one dispatch.
func TestStoreRejectsImpossibleResultSeams(t *testing.T) {
	for name, result := range map[string]resultReader{
		testNameNil: nil,
		"typed nil": (*fakeResult)(nil),
	} {
		t.Run(name, func(t *testing.T) {
			check, store, err := runOneCheck(t, result)
			if check != 0 || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant ||
				store.State() != dkim2.ReplayStoreDegraded {
				t.Fatalf("bounded result: check=%q code=%q state=%q",
					check, dkim2.ReplayErrorCodeOf(err), store.State())
			}
			assertPrivateFailure(t, err, store)
		})
	}
}

// TestStorePreservesAuthoritativeReplyAfterContextCancellation verifies no post-dispatch overwrite.
func TestStorePreservesAuthoritativeReplyAfterContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &fakeCommandClient{
		command:    fakeCommand{},
		result:     resultFromMessage(t, cachedMessage(t, '+', "OK")),
		onDispatch: cancel,
	}
	store := mustCommandStore(t, client)
	check, err := store.CheckAndRemember(ctx, validReplayKey(t), dkim2.DefaultReplayRetention())
	if err != nil || check != dkim2.ReplayCheckFirstSeen {
		t.Fatalf("bounded result: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
	}
}

// TestResultMappingCallOrderAndContradictions verifies the exact lossless projection contract.
func TestResultMappingCallOrderAndContradictions(t *testing.T) {
	okMessage := cachedMessage(t, '+', "OK")
	cases := []struct {
		name         string
		result       *fakeResult
		code         dkim2.ReplayErrorCode
		stringCalls  int
		messageCalls int
	}{
		{name: "non valkey stops", result: &fakeResult{nonValkeyErr: errors.New(syntheticReplyMarker)}, code: dkim2.ReplayErrorIndeterminate},
		{name: "nil error text", result: &fakeResult{raw: serverKindOOM + " " + syntheticReplyMarker}, code: dkim2.ReplayErrorInconsistent, stringCalls: 1},
		{name: "null nonempty", result: &fakeResult{raw: "x", err: valkeygo.Nil}, code: dkim2.ReplayErrorInternalInvariant, stringCalls: 1},
		{name: "arbitrary error", result: &fakeResult{raw: serverKindOOM + " " + syntheticReplyMarker, err: errors.New(serverKindOOM)}, code: dkim2.ReplayErrorInternalInvariant, stringCalls: 1},
		{name: "wrapped typed error", result: wrappedServerResult(t, serverKindOOM+" "+syntheticReplyMarker), code: dkim2.ReplayErrorInternalInvariant, stringCalls: 1},
		{name: "typed nil error", result: &fakeResult{raw: serverKindOOM, err: (*valkeygo.ValkeyError)(nil)}, code: dkim2.ReplayErrorInternalInvariant, stringCalls: 1},
		{name: "empty typed error", result: resultFromMessage(t, cachedMessage(t, '-', "")), code: dkim2.ReplayErrorInconsistent, stringCalls: 1},
		{name: "oversized", result: resultFromMessage(t, cachedMessage(t, '-', strings.Repeat("A", 4097))), code: dkim2.ReplayErrorInconsistent, stringCalls: 1},
		{name: "ok message error", result: &fakeResult{raw: "OK", message: okMessage, messageErr: errors.New(syntheticReplyMarker)}, code: dkim2.ReplayErrorInternalInvariant, stringCalls: 1, messageCalls: 1},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			check, _, err := runOneCheck(t, testCase.result)
			if check != 0 || dkim2.ReplayErrorCodeOf(err) != testCase.code {
				t.Fatalf("bounded result: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
			}
			if testCase.result.nonValkeyCalls != 1 ||
				testCase.result.stringCalls != testCase.stringCalls ||
				testCase.result.messageCalls != testCase.messageCalls {
				t.Fatalf("result calls = (%d,%d,%d), want (1,%d,%d)",
					testCase.result.nonValkeyCalls,
					testCase.result.stringCalls,
					testCase.result.messageCalls,
					testCase.stringCalls,
					testCase.messageCalls,
				)
			}
			assertPrivateFailure(t, err, nil)
		})
	}
}

// TestTypedNilValkeyErrorPublishesRestart verifies direct typed nil remains a sticky contradiction.
func TestTypedNilValkeyErrorPublishesRestart(t *testing.T) {
	result := &fakeResult{raw: serverKindOOM, err: (*valkeygo.ValkeyError)(nil)}
	check, store, err := runOneCheck(t, result)
	if check != 0 || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
		t.Fatalf("bounded result: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
	}
	if result.nonValkeyCalls != 1 || result.stringCalls != 1 || result.messageCalls != 0 {
		t.Fatalf("result calls = (%d,%d,%d), want (1,1,0)",
			result.nonValkeyCalls, result.stringCalls, result.messageCalls)
	}
	if got := store.strongestRecovery(); got != recoveryRestart ||
		store.State() != dkim2.ReplayStoreDegraded {
		t.Fatalf("recovery = %d state=%q, want restart/degraded", got, store.State())
	}
	assertPrivateFailure(t, err, store)
}

// TestLeadingErrorKindGrammarAndBounds verifies the exact bounded token extractor directly.
func TestLeadingErrorKindGrammarAndBounds(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		raw   string
		kind  string
		valid bool
	}{
		{name: testNameEmpty},
		{name: "one byte", raw: "A", kind: "A", valid: true},
		{name: "thirty two bytes", raw: strings.Repeat("A", 32), kind: strings.Repeat("A", 32), valid: true},
		{name: "thirty three bytes", raw: strings.Repeat("A", 33)},
		{name: "digit first", raw: "1OOM"},
		{name: "underscore first", raw: "_OOM"},
		{name: "lowercase first", raw: "oOM"},
		{name: "lowercase inside", raw: "OoM"},
		{name: "digit inside", raw: "OOM2", kind: "OOM2", valid: true},
		{name: "underscore and digit inside", raw: "OOM_KIND9", kind: "OOM_KIND9", valid: true},
		{name: "hyphen", raw: "OOM-X"},
		{name: "tab delimiter", raw: "OOM\tdetail"},
		{name: "nul delimiter", raw: "OOM\x00detail"},
		{name: "newline delimiter", raw: "OOM\ndetail"},
		{name: testNameNonASCII, raw: "OOMé"},
		{name: "missing delimiter", raw: "OOMdetail"},
		{name: "payload end", raw: serverKindOOM, kind: serverKindOOM, valid: true},
		{name: "ascii space", raw: serverKindOOM + " detail", kind: serverKindOOM, valid: true},
		{name: "prefix collision at end", raw: "OOMMORE", kind: "OOMMORE", valid: true},
		{name: "suffix not inspected", raw: serverKindOOM + " \t\x00" + syntheticReplyMarker, kind: serverKindOOM, valid: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			kind, valid := leadingErrorKind(testCase.raw)
			if kind != testCase.kind || valid != testCase.valid {
				t.Fatalf("leading kind = (%q,%t), want (%q,%t)",
					kind, valid, testCase.kind, testCase.valid)
			}
		})
	}
}

// TestPayloadEndOOMPublishesRevalidation verifies end-delimited OOM uses its exact recovery class.
func TestPayloadEndOOMPublishesRevalidation(t *testing.T) {
	result := resultFromMessage(t, cachedMessage(t, '-', serverKindOOM))
	check, store, err := runOneCheck(t, result)
	if check != 0 || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorLimitExceeded {
		t.Fatalf("bounded result: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
	}
	if got := store.strongestRecovery(); got != recoveryRevalidation ||
		store.State() != dkim2.ReplayStoreDegraded {
		t.Fatalf("recovery = %d state=%q, want revalidation/degraded", got, store.State())
	}
	assertPrivateFailure(t, err, store)
}

// TestErrorKindMappingAndPayloadBounds verifies exact kinds map without prefix matching.
func TestErrorKindMappingAndPayloadBounds(t *testing.T) {
	for _, testCase := range []struct {
		name string
		raw  string
		code dkim2.ReplayErrorCode
	}{
		{name: "prefix collision", raw: "OOMMORE detail", code: dkim2.ReplayErrorInconsistent},
		{name: "known payload end", raw: serverKindOOM, code: dkim2.ReplayErrorLimitExceeded},
		{name: "known exact", raw: serverKindOOM + " detail", code: dkim2.ReplayErrorLimitExceeded},
		{name: "busy suffix not inspected", raw: serverKindBUSY + " \t\x00" + syntheticReplyMarker, code: dkim2.ReplayErrorUnavailable},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			result := resultFromMessage(t, cachedMessage(t, '-', testCase.raw))
			check, _, err := runOneCheck(t, result)
			if check != 0 || dkim2.ReplayErrorCodeOf(err) != testCase.code {
				t.Fatalf("bounded result: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
			}
		})
	}

	t.Run("payload cap exact", func(t *testing.T) {
		raw := serverKindOOM + " " + strings.Repeat("x", 4096-len(serverKindOOM+" "))
		check, _, err := runOneCheck(t, resultFromMessage(t, cachedMessage(t, '-', raw)))
		if check != 0 || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorLimitExceeded {
			t.Fatalf("bounded result: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
		}
	})
	t.Run("payload cap plus one", func(t *testing.T) {
		raw := serverKindOOM + " " + strings.Repeat("x", 4097-len(serverKindOOM+" "))
		check, _, err := runOneCheck(t, resultFromMessage(t, cachedMessage(t, '-', raw)))
		if check != 0 || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInconsistent {
			t.Fatalf("bounded result: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
		}
	})
	for _, suffix := range []string{
		" ignored lowercase content",
		" OOMMORE",
		" \t\x00" + syntheticReplyMarker,
	} {
		t.Run("suffix not inspected", func(t *testing.T) {
			check, _, err := runOneCheck(t, resultFromMessage(t, cachedMessage(t, '-', serverKindOOM+suffix)))
			if check != 0 || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorLimitExceeded {
				t.Fatalf("bounded result: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
			}
		})
	}
}

// TestStateRecoveryClasses verifies transient success recovery and sticky degradation.
func TestStateRecoveryClasses(t *testing.T) {
	transient := &fakeCommandClient{
		command: fakeCommand{},
		result:  &fakeResult{nonValkeyErr: errors.New(syntheticReplyMarker)},
	}
	store := mustCommandStore(t, transient)
	key := validReplayKey(t)
	_, _ = store.CheckAndRemember(context.Background(), key, dkim2.DefaultReplayRetention())
	if store.State() != dkim2.ReplayStoreDegraded {
		t.Fatal("transient failure did not degrade")
	}
	transient.result = resultFromMessage(t, cachedMessage(t, '+', "OK"))
	if check, err := store.CheckAndRemember(context.Background(), key, dkim2.DefaultReplayRetention()); err != nil ||
		check != dkim2.ReplayCheckFirstSeen || store.State() != dkim2.ReplayStoreReady {
		t.Fatal("authoritative success did not recover transient degradation")
	}

	sticky := &fakeCommandClient{command: fakeCommand{}, result: resultFromMessage(t, cachedMessage(t, '-', serverKindOOM+" detail"))}
	stickyStore := mustCommandStore(t, sticky)
	_, _ = stickyStore.CheckAndRemember(context.Background(), key, dkim2.DefaultReplayRetention())
	sticky.result = resultFromMessage(t, cachedMessage(t, '+', "OK"))
	_, _ = stickyStore.CheckAndRemember(context.Background(), key, dkim2.DefaultReplayRetention())
	if stickyStore.State() != dkim2.ReplayStoreDegraded {
		t.Fatal("ordinary success cleared sticky degradation")
	}
}

// TestStateRecoveryClassMatrix verifies every frozen transient and sticky category.
func TestStateRecoveryClassMatrix(t *testing.T) {
	cases := []struct {
		kind       string
		recovering bool
		recovery   recoveryClass
	}{
		{kind: "MASTERDOWN", recovery: recoveryRevalidation},
		{kind: "CLUSTERDOWN", recovery: recoveryRevalidation},
		{kind: "LOADING", recovery: recoveryRevalidation},
		{kind: serverKindMOVED, recovery: recoveryRevalidation},
		{kind: serverKindASK, recovery: recoveryRevalidation},
		{kind: serverKindTRYAGAIN, recovering: true, recovery: recoveryTransient},
		{kind: serverKindBUSY, recovering: true, recovery: recoveryTransient},
		{kind: serverKindOOM, recovery: recoveryRevalidation},
		{kind: "NOAUTH", recovery: recoveryRestart},
		{kind: "WRONGPASS", recovery: recoveryRestart},
		{kind: "NOPERM", recovery: recoveryRevalidation},
		{kind: "READONLY", recovery: recoveryRevalidation},
		{kind: "MISCONF", recovery: recoveryRevalidation},
		{kind: "NOREPLICAS", recovery: recoveryRevalidation},
		{kind: "ERR", recovery: recoveryRestart},
		{kind: "FUTURE_KIND", recovery: recoveryRestart},
	}
	for _, testCase := range cases {
		t.Run(testCase.kind, func(t *testing.T) {
			client := &fakeCommandClient{
				command: fakeCommand{},
				result:  resultFromMessage(t, cachedMessage(t, '-', testCase.kind+" "+syntheticReplyMarker)),
			}
			store := mustCommandStore(t, client)
			key := validReplayKey(t)
			_, _ = store.CheckAndRemember(context.Background(), key, dkim2.DefaultReplayRetention())
			if store.State() != dkim2.ReplayStoreDegraded {
				t.Fatal("failure did not publish degraded")
			}
			if got := store.strongestRecovery(); got != testCase.recovery {
				t.Fatalf("recovery class = %d, want %d", got, testCase.recovery)
			}
			client.result = resultFromMessage(t, cachedMessage(t, '+', "OK"))
			check, err := store.CheckAndRemember(context.Background(), key, dkim2.DefaultReplayRetention())
			if err != nil || check != dkim2.ReplayCheckFirstSeen {
				t.Fatalf("success after degradation failed: check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
			}
			want := dkim2.ReplayStoreDegraded
			if testCase.recovering {
				want = dkim2.ReplayStoreReady
			}
			if store.State() != want {
				t.Fatalf("state = %q, want %q", store.State(), want)
			}
		})
	}
}

// TestRecoveryPublicationIsMonotonicUnderConcurrency verifies sticky classes cannot be lost.
func TestRecoveryPublicationIsMonotonicUnderConcurrency(t *testing.T) {
	store := mustCommandStore(t, &fakeCommandClient{})
	var wait sync.WaitGroup
	for index := range 128 {
		wait.Go(func() {
			switch index % 4 {
			case 0:
				store.publishSuccess()
			case 1:
				store.publishFailure(recoveryTransient)
			case 2:
				store.publishFailure(recoveryRevalidation)
			default:
				store.publishFailure(recoveryRestart)
			}
		})
	}
	wait.Wait()
	if got := store.strongestRecovery(); got != recoveryRestart {
		t.Fatalf("recovery class = %d, want restart", got)
	}
	if store.State() != dkim2.ReplayStoreDegraded {
		t.Fatal("monotonic restart publication did not remain degraded")
	}
}

// TestStateTerminalProjectionDominatesCapturedRecovery models close between atomic snapshots.
func TestStateTerminalProjectionDominatesCapturedRecovery(t *testing.T) {
	store := &Store{storeCore: &storeCore{gate: newAdmissionGate(1, 1)}}
	capturedRecovery := store.strongestRecovery()
	if _, err := store.gate.beginClose(); err != nil {
		t.Fatal(err)
	}
	if state := store.stateAfterRecovery(capturedRecovery); state != dkim2.ReplayStoreClosing {
		t.Fatalf("state=%q want=%q", state, dkim2.ReplayStoreClosing)
	}
	if !store.gate.publishClosed() {
		t.Fatal("close publication failed")
	}
	if state := store.stateAfterRecovery(capturedRecovery); state != dkim2.ReplayStoreClosed {
		t.Fatalf("state=%q want=%q", state, dkim2.ReplayStoreClosed)
	}
}

// TestRedirectRefusalsAreNeverRetried verifies one build and dispatch per returned refusal.
func TestRedirectRefusalsAreNeverRetried(t *testing.T) {
	for _, kind := range []string{serverKindMOVED, serverKindASK, serverKindTRYAGAIN, serverKindBUSY} {
		t.Run(kind, func(t *testing.T) {
			result := resultFromMessage(t, cachedMessage(t, '-', kind+" "+syntheticReplyMarker))
			client := &fakeCommandClient{command: fakeCommand{}, result: result}
			store := mustCommandStore(t, client)
			check, err := store.CheckAndRemember(
				context.Background(),
				validReplayKey(t),
				dkim2.DefaultReplayRetention(),
			)
			if check != 0 || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorUnavailable ||
				store.State() != dkim2.ReplayStoreDegraded {
				t.Fatalf("bounded result: check=%q code=%q state=%q",
					check, dkim2.ReplayErrorCodeOf(err), store.State())
			}
			builds, dispatches := client.counts()
			if builds != 1 || dispatches != 1 {
				t.Fatalf("command counts = (%d,%d), want (1,1)", builds, dispatches)
			}
		})
	}
}

// TestInvariantAndPanicDegradationIsSticky verifies ordinary success cannot certify recovery.
func TestInvariantAndPanicDegradationIsSticky(t *testing.T) {
	cases := []struct {
		name   string
		client *fakeCommandClient
	}{
		{name: "build panic", client: &fakeCommandClient{buildPanic: true}},
		{name: "retryability panic", client: &fakeCommandClient{command: fakeCommand{panicRead: true}}},
		{name: "dispatch panic", client: &fakeCommandClient{command: fakeCommand{}, dispatchPanic: true}},
		{name: "result panic", client: &fakeCommandClient{command: fakeCommand{}, result: &fakeResult{panicAt: panicPointString}}},
		{name: "impossible result", client: &fakeCommandClient{command: fakeCommand{}}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			store := mustCommandStore(t, testCase.client)
			key := validReplayKey(t)
			_, firstErr := store.CheckAndRemember(context.Background(), key, dkim2.DefaultReplayRetention())
			if firstErr == nil || store.State() != dkim2.ReplayStoreDegraded {
				t.Fatal("contract failure did not publish degraded")
			}
			if got := store.strongestRecovery(); got != recoveryRestart {
				t.Fatalf("recovery class = %d, want restart", got)
			}
			testCase.client.buildPanic = false
			testCase.client.dispatchPanic = false
			testCase.client.command = fakeCommand{}
			testCase.client.result = resultFromMessage(t, cachedMessage(t, '+', "OK"))
			check, err := store.CheckAndRemember(context.Background(), key, dkim2.DefaultReplayRetention())
			if err != nil || check != dkim2.ReplayCheckFirstSeen ||
				store.State() != dkim2.ReplayStoreDegraded {
				t.Fatalf("bounded recovery: check=%q code=%q state=%q",
					check, dkim2.ReplayErrorCodeOf(err), store.State())
			}
			if got := store.strongestRecovery(); got != recoveryRestart {
				t.Fatalf("recovery class after success = %d, want restart", got)
			}
			assertPrivateFailure(t, firstErr, store)
		})
	}
}

// TestNativeAdapterBuildsAndDispatchesExactCompletedCommand verifies the real v1.0.77 path.
func TestNativeAdapterBuildsAndDispatchesExactCompletedCommand(t *testing.T) {
	key := slotZeroStorageKey()
	client := &nativeClientProbe{}
	adapter := valkeyCommandClient{client: client}
	command := adapter.BuildSet(key, dkim2.ReplayStoredValue, 1234)
	native, ok := command.(nativeCommand)
	if !ok {
		t.Fatal("production adapter returned an unexpected command wrapper")
	}
	tokens := native.completed.Commands()
	if len(tokens) != 6 ||
		tokens[0] != "SET" ||
		tokens[1] != key ||
		tokens[2] != dkim2.ReplayStoredValue ||
		tokens[3] != "NX" ||
		tokens[4] != "PX" ||
		tokens[5] != "1234" {
		t.Fatal("production Completed tokens differ from the frozen SET contract")
	}
	if native.IsRetryable() {
		t.Fatal("production SET command is retryable")
	}

	ctx := context.WithValue(context.Background(), nativeProbeContextKey{}, "exact")
	result := adapter.Do(ctx, command)
	concrete, ok := result.(concreteResult)
	if !ok {
		t.Fatal("production adapter did not return a concrete result wrapper")
	}
	if concrete.result != client.result {
		t.Fatal("production adapter did not retain the exact native result")
	}
	if client.dispatches != 1 || client.ctx != ctx ||
		!reflect.DeepEqual(client.completed.Commands(), tokens) {
		t.Fatal("production adapter did not forward one exact context and command")
	}

	before := client.dispatches
	if _, ok := adapter.Do(ctx, fakeCommand{}).(impossibleResult); !ok {
		t.Fatal("wrong command type did not return an impossible result")
	}
	if client.dispatches != before {
		t.Fatal("wrong command type reached the native client")
	}
}

// nativeProbeContextKey provides an identity-bearing context value without a string key.
type nativeProbeContextKey struct{}

// nativeClientProbe records one native dispatch for the deliberately slot-zero test key.
type nativeClientProbe struct {
	dispatches int
	ctx        context.Context
	completed  valkeygo.Completed
	result     valkeygo.ValkeyResult
}

// B returns a builder whose initial zero slot accepts the slot-zero fixture.
func (*nativeClientProbe) B() valkeygo.Builder { return valkeygo.Builder{} }

// Do records and returns one exact native dispatch.
func (c *nativeClientProbe) Do(ctx context.Context, completed valkeygo.Completed) valkeygo.ValkeyResult {
	c.dispatches++
	c.ctx = ctx
	c.completed = completed
	return c.result
}

// runOneCheck executes one complete fake-provider operation.
func runOneCheck(t *testing.T, result resultReader) (dkim2.ReplayCheck, *Store, error) {
	t.Helper()
	client := &fakeCommandClient{command: fakeCommand{}, result: result}
	store := mustCommandStore(t, client)
	check, err := store.CheckAndRemember(context.Background(), validReplayKey(t), dkim2.DefaultReplayRetention())
	return check, store, err
}

// mustCommandStore constructs one valid fake command store.
func mustCommandStore(t *testing.T, client commandClient) *Store {
	t.Helper()
	store, err := newCommandStore(client)
	if err != nil {
		t.Fatalf("command store construction failed with code %q", dkim2.ReplayErrorCodeOf(err))
	}
	return store
}

// assertPrivateFailure verifies bounded formatting cannot reveal synthetic protected input.
func assertPrivateFailure(t *testing.T, err error, store *Store) {
	t.Helper()
	formatted := fmt.Sprintf("%v|%+v|%#v|%s", err, err, store, store)
	for _, marker := range []string{syntheticReplyMarker, syntheticSecretMarker} {
		if strings.Contains(formatted, marker) {
			t.Fatal("bounded failure formatting exposed protected input")
		}
	}
}

// resultFromMessage creates the same lossless projections as a concrete ValkeyResult.
func resultFromMessage(t *testing.T, message valkeygo.ValkeyMessage) *fakeResult {
	t.Helper()
	raw, err := message.ToString()
	return &fakeResult{raw: raw, err: err, message: message, messageErr: message.Error()}
}

// wrappedServerResult returns a deliberately non-authoritative wrapped typed server error.
func wrappedServerResult(t *testing.T, raw string) *fakeResult {
	t.Helper()
	result := resultFromMessage(t, cachedMessage(t, '-', raw))
	result.err = errors.Join(result.err, errors.New("wrapper"))
	return result
}

// cachedMessage constructs one pinned valkey-go cache-layout fixture.
func cachedMessage(t *testing.T, prefix byte, payload string) valkeygo.ValkeyMessage {
	t.Helper()
	frame := make([]byte, 16+len(payload))
	frame[7] = prefix
	binary.BigEndian.PutUint64(frame[8:16], uint64(len(payload)))
	copy(frame[16:], payload)
	var message valkeygo.ValkeyMessage
	if err := message.CacheUnmarshalView(frame); err != nil {
		t.Fatal("cache fixture construction failed")
	}
	return message
}

// validReplayKey derives one protected key only through authentic public verifier evidence.
func validReplayKey(t *testing.T) dkim2.ReplayKey {
	t.Helper()
	corpusBytes, err := os.ReadFile("../../../../../lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-06/public-golden.json")
	if err != nil {
		t.Fatal("public replay corpus read failed")
	}
	var corpus struct {
		RSAModulus  string `json:"rsa_modulus_base64"`
		RSAExponent int    `json:"rsa_exponent"`
		Vectors     map[string]struct {
			Raw     string   `json:"raw_base64"`
			Reverse string   `json:"reverse_path_base64"`
			Forward []string `json:"forward_paths_base64"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(corpusBytes, &corpus); err != nil {
		t.Fatal("public replay corpus decode failed")
	}
	modulus, err := base64.StdEncoding.DecodeString(corpus.RSAModulus)
	if err != nil {
		t.Fatal("public modulus decode failed")
	}
	fixture := corpus.Vectors["rsa_pass"]
	raw, err := base64.StdEncoding.DecodeString(fixture.Raw)
	if err != nil {
		t.Fatal("public raw message decode failed")
	}
	reverse, err := base64.StdEncoding.DecodeString(fixture.Reverse)
	if err != nil {
		t.Fatal("public reverse path decode failed")
	}
	forward := make([][]byte, len(fixture.Forward))
	for index, encoded := range fixture.Forward {
		forward[index], err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal("public forward path decode failed")
		}
	}
	key := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: corpus.RSAExponent}
	verifier, err := dkim2.NewVerifier(
		staticKeyProvider{key: key},
		dkim2.WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }),
	)
	if err != nil {
		t.Fatal("public verifier construction failed")
	}
	verified, err := verifier.Verify(context.Background(), dkim2.NewVerifyRequest(raw, reverse, forward))
	if err != nil || verified.State() != dkim2.ResultStatePASS {
		t.Fatal("public replay fixture did not verify")
	}
	identities, err := dkim2.ReplayIdentities(verified)
	if err != nil {
		t.Fatal("public replay identity projection failed")
	}
	identity, err := identities.Identity(0)
	if err != nil {
		t.Fatal("public replay identity selection failed")
	}
	deriver, err := dkim2.NewReplayDeriver([]byte(syntheticSecretMarker), 1)
	if err != nil {
		t.Fatal("public replay deriver construction failed")
	}
	defer func() {
		_ = deriver.Close(context.Background())
	}()
	derived, err := deriver.Derive(context.Background(), identity)
	if err != nil {
		t.Fatal("public replay key derivation failed")
	}
	return derived
}

// staticKeyProvider returns one frozen synthetic RSA public key.
type staticKeyProvider struct {
	key *rsa.PublicKey
}

// LookupPublicKey supplies one algorithm-bounded public key.
func (p staticKeyProvider) LookupPublicKey(_ context.Context, query dkim2.PublicKeyQuery) (dkim2.PublicKeyResult, error) {
	if query.Algorithm() != dkim2.AlgorithmRSASHA256 {
		return dkim2.MissingPublicKey(query.Algorithm()), nil
	}
	return dkim2.FoundRSAPublicKey(p.key), nil
}

// slotZeroStorageKey returns one exact-format string whose Redis cluster slot is zero.
func slotZeroStorageKey() string {
	const candidate = "dkim2:replay:v1:00000001:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABov"
	if len(candidate) != 68 || clusterSlot(candidate) != 0 {
		panic("slot-zero fixture invalid")
	}
	return candidate
}

// clusterSlot computes the standard Redis-compatible CRC16 slot for one test key.
func clusterSlot(key string) uint16 {
	var crc uint16
	for index := range len(key) {
		crc ^= uint16(key[index]) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc % 16384
}

// TestTestSeamsRemainNarrow prevents accidental provider-shaped surface growth.
func TestTestSeamsRemainNarrow(t *testing.T) {
	if got := reflect.TypeFor[commandClient]().NumMethod(); got != 2 {
		t.Fatalf("commandClient methods = %d, want 2", got)
	}
	if got := reflect.TypeFor[resultReader]().NumMethod(); got != 3 {
		t.Fatalf("resultReader methods = %d, want 3", got)
	}
}
