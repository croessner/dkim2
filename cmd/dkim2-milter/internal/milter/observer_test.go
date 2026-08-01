package milter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordedMessageObservation struct {
	mode, disposition, result, failure string
	failOpen                           bool
}

type recordingObserver struct {
	mu         sync.Mutex
	admissions []string
	callbacks  []string
	messages   []recordedMessageObservation
	actions    []string
	panicNow   bool
}

type blockingObserver struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type privateObserver struct{ marker string }

// RecordConnectionAdmission is an inert private formatting seam.
func (*privateObserver) RecordConnectionAdmission(string) {}

// RecordCallback is an inert private formatting seam.
func (*privateObserver) RecordCallback(string, string, string, time.Duration) {}

// RecordMessage is an inert private formatting seam.
func (*privateObserver) RecordMessage(
	string, string, string, string, time.Duration, uint64, uint64, bool,
) {
}

// RecordAction is an inert private formatting seam.
func (*privateObserver) RecordAction(string, string) {}

// block waits until the test releases the deliberately slow observer.
func (o *blockingObserver) block() {
	o.once.Do(func() { close(o.entered) })
	<-o.release
}

// RecordConnectionAdmission blocks at the injected latency seam.
func (o *blockingObserver) RecordConnectionAdmission(string) { o.block() }

// RecordCallback blocks at the injected latency seam.
func (o *blockingObserver) RecordCallback(string, string, string, time.Duration) { o.block() }

// RecordMessage blocks at the injected latency seam.
func (o *blockingObserver) RecordMessage(
	string, string, string, string, time.Duration, uint64, uint64, bool,
) {
	o.block()
}

// RecordAction blocks at the injected latency seam.
func (o *blockingObserver) RecordAction(string, string) { o.block() }

// RecordConnectionAdmission captures one closed admission value.
func (o *recordingObserver) RecordConnectionAdmission(value string) {
	if o.panicNow {
		panic("private observer marker")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.admissions = append(o.admissions, value)
}

// RecordCallback captures one closed callback tuple.
func (o *recordingObserver) RecordCallback(callback, state, result string, _ time.Duration) {
	if o.panicNow {
		panic("private observer marker")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.callbacks = append(o.callbacks, callback+"/"+state+"/"+result)
}

// RecordMessage captures one closed message tuple.
func (o *recordingObserver) RecordMessage(
	mode, disposition, result, failure string,
	_ time.Duration,
	_, _ uint64,
	failOpen bool,
) {
	if o.panicNow {
		panic("private observer marker")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.messages = append(o.messages, recordedMessageObservation{
		mode: mode, disposition: disposition, result: result,
		failure: failure, failOpen: failOpen,
	})
}

// RecordAction captures one closed action tuple.
func (o *recordingObserver) RecordAction(action, result string) {
	if o.panicNow {
		panic("private observer marker")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.actions = append(o.actions, action+"/"+result)
}

// TestObserverReceivesCompleteClosedEOMFacts proves the production observation boundary.
func TestObserverReceivesCompleteClosedEOMFacts(t *testing.T) {
	observer := &recordingObserver{}
	admission, err := NewAdmission(2, 2, testAdmissionBytes)
	if err != nil || admission.SetObserver(observer) != nil {
		t.Fatal("observed admission construction failed")
	}
	if err := admission.ActivateObserver(); err != nil {
		t.Fatal("observer activation failed")
	}
	t.Cleanup(func() {
		admission.Stop()
		_ = admission.CloseObserver()
	})
	handler := &testHandler{result: Result{
		Operation: operationSign,
		Result:    resultPass,
		Outcome:   DispositionAccept,
		Actions: []Action{
			{Kind: ActionAddHeader, Name: headerMessage, Value: testActionValue},
			{Kind: ActionAddHeader, Name: headerDKIM2, Value: testActionValue},
		},
	}}
	session, err := NewSession(handler, admission, Limits{
		MessageBytes: 1 << 16, HeaderBytes: 1 << 15,
		HeaderCount: 100, HeaderFieldBytes: 1024, RecipientCount: 100,
	}, time.Second, FailurePolicy{}, modeOriginator, "")
	if err != nil {
		t.Fatal("session construction failed")
	}
	input := appendPeerFrames(
		peerFrame(commandNegotiate, negotiationPayload()),
		peerFrame(commandConnect, []byte("mx\x00U")),
		peerFrame(commandHelo, []byte("helo\x00")),
		peerFrame(commandMail, []byte("<a@example.test>\x00")),
		peerFrame(commandRecipient, []byte("<b@example.test>\x00")),
		peerFrame(commandEOH, nil),
		peerFrame(commandEOM, nil),
		peerFrame(commandQuit, nil),
	)
	stream := &splitStream{reader: bytes.NewReader(input)}
	if err := session.Serve(context.Background(), stream); err != nil {
		t.Fatal("observed session failed")
	}
	if !waitForObservations(observer, 1, 1, 1) {
		t.Fatal("bounded observer did not deliver queued outcomes")
	}
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if len(observer.messages) != 1 ||
		observer.messages[0].mode != modeOriginator ||
		observer.messages[0].disposition != "accept" ||
		observer.messages[0].result != "success" ||
		observer.messages[0].failure != "none" ||
		observer.messages[0].failOpen ||
		!containsObservation(observer.callbacks, "eom/") ||
		!containsObservation(observer.actions, "add_header/success") ||
		!containsObservation(observer.actions, "accept/success") {
		t.Fatalf("incomplete closed observations: %#v %#v %#v",
			observer.messages, observer.callbacks, observer.actions)
	}
}

// TestObserverClassifiesNotApplicableMessagesAsSuccessfulContinuation proves
// normal inbound and originator no-ops never inflate operational failures.
func TestObserverClassifiesNotApplicableMessagesAsSuccessfulContinuation(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		mode      string
		operation string
		input     []byte
	}{
		{name: "unsigned inbound", mode: modeInbound, operation: operationProcess, input: completeTwoRecipientMessage()},
		{name: "absent originator profile", mode: modeOriginator, operation: operationSign, input: completeOriginatorMessage()},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			observer := &recordingObserver{}
			admission, err := NewAdmission(2, 2, testAdmissionBytes)
			if err != nil || admission.SetObserver(observer) != nil || admission.ActivateObserver() != nil {
				t.Fatal("observed admission construction failed")
			}
			t.Cleanup(func() {
				admission.Stop()
				_ = admission.CloseObserver()
			})
			handler := &testHandler{result: Result{
				Operation: testCase.operation, Result: resultNone, Outcome: DispositionContinue,
			}}
			session, err := NewSession(handler, admission, Limits{
				MessageBytes: 1 << 16, HeaderBytes: 1 << 15,
				HeaderCount: 100, HeaderFieldBytes: 1024, RecipientCount: 100,
			}, time.Second, FailurePolicy{}, testCase.mode, "")
			if err != nil {
				t.Fatal("session construction failed")
			}
			stream := &splitStream{reader: bytes.NewReader(testCase.input)}
			if err := session.Serve(context.Background(), stream); err != nil {
				t.Fatalf("Serve() error=%v", err)
			}
			if !waitForObservations(observer, 1, 1, 1) {
				t.Fatal("bounded observer did not deliver no-op outcome")
			}
			observer.mu.Lock()
			defer observer.mu.Unlock()
			if len(observer.messages) != 1 ||
				observer.messages[0].disposition != string(DispositionContinue) ||
				observer.messages[0].result != observationSuccess ||
				observer.messages[0].failure != observationNoFailure {
				t.Fatalf("no-op observation=%#v", observer.messages)
			}
		})
	}
}

// waitForObservations waits only in tests for the local asynchronous seam.
func waitForObservations(
	observer *recordingObserver,
	messages, callbacks, actions int,
) bool {
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		observer.mu.Lock()
		ready := len(observer.messages) >= messages &&
			len(observer.callbacks) >= callbacks &&
			len(observer.actions) >= actions
		observer.mu.Unlock()
		if ready {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

// TestObserverPanicCannotCrossMailBoundary proves telemetry is non-authoritative.
func TestObserverPanicCannotCrossMailBoundary(t *testing.T) {
	observer := &recordingObserver{panicNow: true}
	admission, err := NewAdmission(1, 1, testAdmissionBytes)
	if err != nil || admission.SetObserver(observer) != nil {
		t.Fatal("observed admission construction failed")
	}
	if err := admission.ActivateObserver(); err != nil {
		t.Fatal("observer activation failed")
	}
	release, admitted := admission.AdmitConnection()
	if !admitted {
		t.Fatal("observer panic changed admission result")
	}
	release()
	handler := &testHandler{err: &Error{Class: FailureUnavailable}}
	session, err := NewSession(handler, admission, Limits{
		MessageBytes: 1 << 16, HeaderBytes: 1 << 15,
		HeaderCount: 100, HeaderFieldBytes: 1024, RecipientCount: 100,
	}, time.Second, FailurePolicy{FailOpen: true}, modeInbound, "")
	if err != nil {
		t.Fatal("session construction failed")
	}
	if !session.startTransaction(0) {
		t.Fatal("message admission failed")
	}
	session.reverse = []byte("<a@example.test>")
	session.recipients = [][]byte{[]byte("<b@example.test>")}
	frames, err := session.endMessage(context.Background())
	if err != nil || len(frames) != 1 || frames[0][4] != replyAccept {
		t.Fatal("observer panic changed fail-open result")
	}
	session.finishMessageObservation()
	admission.Stop()
	if err := admission.CloseObserver(); err != nil {
		t.Fatal("observer close failed")
	}
}

// TestAdmissionObserverRejectsLateInstallation proves observer immutability after use.
func TestAdmissionObserverRejectsLateInstallation(t *testing.T) {
	admission, err := NewAdmission(1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	release, admitted := admission.AdmitConnection()
	if !admitted {
		t.Fatal("connection admission failed")
	}
	if err := admission.SetObserver(&recordingObserver{}); !errors.Is(
		err,
		&Error{Class: FailureContract},
	) {
		t.Fatal("late observer installation succeeded")
	}
	release()
}

// TestObserverLatencyCannotBlockAdmissionShutdown proves telemetry is non-authoritative.
func TestObserverLatencyCannotBlockAdmissionShutdown(t *testing.T) {
	observer := &blockingObserver{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	admission, err := NewAdmission(1, 1, 1)
	if err != nil || admission.SetObserver(observer) != nil ||
		admission.ActivateObserver() != nil {
		t.Fatal("blocking observer construction failed")
	}
	release, admitted := admission.AdmitConnection()
	if !admitted {
		t.Fatal("connection admission failed")
	}
	defer release()
	select {
	case <-observer.entered:
	case <-time.After(time.Second):
		t.Fatal("blocking observer was not invoked")
	}
	stopped := make(chan struct{})
	go func() {
		admission.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("observer latency blocked admission shutdown")
	}
	if err := admission.CloseObserver(); err != nil {
		t.Fatal("observer close failed")
	}
	waitContext, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	if err := admission.WaitObserver(waitContext); !errors.Is(
		err,
		&Error{Class: FailureInternal},
	) {
		cancel()
		t.Fatal("blocked observer did not respect the join budget")
	}
	cancel()
	close(observer.release)
	finalContext, finalCancel := context.WithTimeout(context.Background(), time.Second)
	defer finalCancel()
	if err := admission.WaitObserver(finalContext); err != nil {
		t.Fatal("released observer did not join")
	}
}

// TestAdmissionFormattingCannotTraverseObserver proves structural privacy.
func TestAdmissionFormattingCannotTraverseObserver(t *testing.T) {
	const marker = "toxic-private-observer-marker"
	admission, err := NewAdmission(1, 1, 1)
	if err != nil || admission.SetObserver(&privateObserver{marker: marker}) != nil {
		t.Fatal("private observer installation failed")
	}
	for _, value := range []string{
		fmt.Sprint(admission),
		fmt.Sprintf("%+v", admission),
		fmt.Sprintf("%#v", admission),
		fmt.Sprintf("%#v", struct{ Admission *Admission }{Admission: admission}),
	} {
		if strings.Contains(value, marker) {
			t.Fatal("admission formatting traversed the observer target")
		}
	}
	if output, marshalErr := json.Marshal(admission); marshalErr == nil ||
		strings.Contains(string(output), marker) {
		t.Fatal("admission serialization did not fail closed")
	}
	admission.Stop()
	if err := admission.CloseObserver(); err != nil {
		t.Fatal("private observer close failed")
	}
}

// containsObservation reports whether one closed record has the prefix.
func containsObservation(values []string, prefix string) bool {
	for _, value := range values {
		if len(value) >= len(prefix) && value[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
