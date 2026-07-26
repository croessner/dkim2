package httpjson

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestTrackedListenerEnforcesFixedConnectionCapAndRecoversTokens proves listener ownership.
func TestTrackedListenerEnforcesFixedConnectionCapAndRecoversTokens(t *testing.T) {
	raw := newTransportScriptedListener()
	listener, err := newTrackedListener(raw, nil)
	if err != nil {
		t.Fatalf("newTrackedListener() failed: %v", err)
	}
	accepted := make([]net.Conn, 0, testConnectionLimit)
	for index := 0; index < testConnectionLimit; index++ {
		rawConn := newTransportRecordingConn(nil)
		raw.enqueue(rawConn)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			t.Fatalf("Accept(%d) failed: %v", index, acceptErr)
		}
		accepted = append(accepted, connection)
	}
	if len(listener.tokens) != testConnectionLimit {
		t.Fatalf("active tokens = %d, want %d", len(listener.tokens), testConnectionLimit)
	}

	refused := newTransportRecordingConn(nil)
	raw.enqueue(refused)
	var backoffs atomic.Int32
	listener.waitRefusal = func(<-chan struct{}) bool {
		backoffs.Add(1)
		return false
	}
	if connection, acceptErr := listener.Accept(); connection != nil || !errors.Is(acceptErr, net.ErrClosed) {
		t.Fatalf("saturated Accept() = %v/%v", connection, acceptErr)
	}
	if refused.closeCalls.Load() != 1 || backoffs.Load() != 1 {
		t.Fatal("saturated socket was not closed before one bounded backoff")
	}

	if closeErr := accepted[0].Close(); closeErr != nil {
		t.Fatalf("tracked close failed: %v", closeErr)
	}
	if len(listener.tokens) != testConnectionLimit-1 {
		t.Fatal("ordinary connection close did not recover its token")
	}
	replacement := newTransportRecordingConn(nil)
	raw.enqueue(replacement)
	connection, acceptErr := listener.Accept()
	if acceptErr != nil || connection == nil {
		t.Fatalf("replacement Accept() = %v/%v", connection, acceptErr)
	}
	accepted[0] = connection
	for _, active := range accepted {
		_ = active.Close()
		_ = active.Close()
	}
	if len(listener.tokens) != 0 {
		t.Fatalf("final active tokens = %d, want zero", len(listener.tokens))
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("listener Close() failed: %v", err)
	}
}

// TestTransportRefusalBackoffIsExact freezes the spec-owned anti-spin delay.
func TestTransportRefusalBackoffIsExact(t *testing.T) {
	if transportRefusalBackoff != 10*time.Millisecond {
		t.Fatalf("refusal backoff = %s, want 10ms", transportRefusalBackoff)
	}
}

// TestTrackedListenerCloseInterruptsRefusalBackoff proves shutdown cannot wait for the fixed delay.
func TestTrackedListenerCloseInterruptsRefusalBackoff(t *testing.T) {
	raw := newTransportScriptedListener()
	listener, err := newTrackedListener(raw, nil)
	if err != nil {
		t.Fatalf("newTrackedListener() failed: %v", err)
	}
	for index := 0; index < testConnectionLimit; index++ {
		raw.enqueue(newTransportRecordingConn(nil))
		if _, acceptErr := listener.Accept(); acceptErr != nil {
			t.Fatalf("Accept(%d) failed: %v", index, acceptErr)
		}
	}
	raw.enqueue(newTransportRecordingConn(nil))
	started := make(chan struct{})
	listener.waitRefusal = func(closed <-chan struct{}) bool {
		close(started)
		<-closed
		return false
	}
	result := make(chan error, 1)
	go func() {
		_, acceptErr := listener.Accept()
		result <- acceptErr
	}()
	<-started
	if closeErr := listener.Close(); closeErr != nil {
		t.Fatalf("Close() failed: %v", closeErr)
	}
	select {
	case acceptErr := <-result:
		if !errors.Is(acceptErr, net.ErrClosed) {
			t.Fatalf("Accept() returned %v", acceptErr)
		}
	case <-time.After(time.Second):
		t.Fatal("listener close did not interrupt refusal backoff")
	}
}

// TestTrackedListenerNeverReturnsAConnectionAfterConcurrentClose proves lifecycle linearization.
func TestTrackedListenerNeverReturnsAConnectionAfterConcurrentClose(t *testing.T) {
	rawConn := newTransportRecordingConn(nil)
	raw := newTransportCloseRaceListener(rawConn)
	listener, err := newTrackedListener(raw, nil)
	if err != nil {
		t.Fatalf("newTrackedListener() failed: %v", err)
	}
	acceptResult := make(chan struct {
		connection net.Conn
		err        error
	}, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		acceptResult <- struct {
			connection net.Conn
			err        error
		}{connection: connection, err: acceptErr}
	}()
	<-raw.acceptStarted
	closeResult := make(chan error, 1)
	go func() { closeResult <- listener.Close() }()
	<-raw.closeObserved
	close(raw.allowAccept)
	if closeErr := <-closeResult; closeErr != nil {
		t.Fatalf("Close() failed: %v", closeErr)
	}
	result := <-acceptResult
	if result.connection != nil || !errors.Is(result.err, net.ErrClosed) {
		t.Fatalf("Accept() = %v/%v", result.connection, result.err)
	}
	if rawConn.closeCalls.Load() != 1 || len(listener.tokens) != 0 {
		t.Fatal("late accepted socket or cap token survived listener close")
	}
}

// TestTrackedListenerAcceptDiagnosticsAreContentFree proves net/http cannot log raw errors.
func TestTrackedListenerAcceptDiagnosticsAreContentFree(t *testing.T) {
	raw := &transportErrorListener{}
	listener, err := newTrackedListener(raw, nil)
	if err != nil {
		t.Fatalf("newTrackedListener() failed: %v", err)
	}
	var diagnostics bytes.Buffer
	server := &http.Server{
		ErrorLog: log.New(&diagnostics, "", 0),
	}
	serveErr := server.Serve(listener)
	if serveErr == nil || strings.Contains(serveErr.Error(), transportPrivateMarker) ||
		strings.Contains(diagnostics.String(), transportPrivateMarker) {
		t.Fatalf("Serve() diagnostics leaked raw error: %v / %q", serveErr, diagnostics.String())
	}
	if !strings.Contains(diagnostics.String(), transportControlErrorText) {
		t.Fatal("temporary accept retry did not retain its bounded classification")
	}
}

// TestTrackedConnCapturesNormalizesAndReplaysOneHead proves byte ownership across split reads.
func TestTrackedConnCapturesNormalizesAndReplaysOneHead(t *testing.T) {
	rawHead := "POST /v1/process HTTP/1.1\r\n" +
		"Host: 127.0.0.1:8080\r\n" +
		"Expect: ,100-continue,\r\n" +
		"Transfer-Encoding: ,chunked,,\r\n\r\n"
	body := "4\r\ntest\r\n0\r\n\r\n"
	raw := newTransportRecordingConn([][]byte{
		[]byte(rawHead[:23]),
		[]byte(rawHead[23:] + body[:3]),
		[]byte(body[3:]),
	})
	state := newTransportState(nil)
	var releases atomic.Int32
	connection := newTrackedConn(raw, state, func() { releases.Add(1) })
	state.connection.Store(connection)

	value, readErr := io.ReadAll(connection)
	if readErr != nil {
		t.Fatalf("ReadAll() failed: %v", readErr)
	}
	wantHead := "POST /v1/process HTTP/1.1\r\n" +
		"Host: 127.0.0.1:8080\r\n" +
		"X-Dk2E: ,100-continue,\r\n" +
		"Transfer-Encoding:chunked    \r\n\r\n"
	if string(value) != wantHead+body {
		t.Fatalf("replayed bytes differ:\n got %q\nwant %q", value, wantHead+body)
	}
	facts := state.Facts()
	if facts.expect != expectContinue || facts.framing != framingSingleChunked ||
		facts.hostCount != 1 || facts.hostValue != "127.0.0.1:8080" {
		t.Fatalf("captured facts = %#v", facts)
	}
	if releases.Load() != 0 {
		t.Fatal("read completion released connection ownership")
	}
	if closeErr := connection.Close(); closeErr != nil {
		t.Fatalf("Close() failed: %v", closeErr)
	}
	if releases.Load() != 1 {
		t.Fatal("connection close did not release exactly once")
	}
}

// TestTrackedConnEmitsTheOnlyRaw414ForIncompleteOverLimitTarget proves the pre-parser path.
func TestTrackedConnEmitsTheOnlyRaw414ForIncompleteOverLimitTarget(t *testing.T) {
	prefix := append([]byte("GET /"), bytes.Repeat([]byte{'x'}, testRequestHeadLimit-len("GET /"))...)
	raw := newTransportRecordingConn([][]byte{prefix})
	state := newTransportState(func() (string, bool) {
		return transportTestEpoch, true
	})
	var releases atomic.Int32
	connection := newTrackedConn(raw, state, func() { releases.Add(1) })
	state.connection.Store(connection)
	before := time.Now()
	output := make([]byte, 1)
	count, readErr := connection.Read(output)
	after := time.Now()
	if count != 0 || !errors.Is(readErr, io.EOF) {
		t.Fatalf("Read() = %d/%v, want 0/EOF", count, readErr)
	}
	want := "HTTP/1.1 414 URI Too Long\r\n" +
		"Cache-Control: no-store\r\n" +
		"X-Content-Type-Options: nosniff\r\n" +
		"Connection: close\r\n" +
		"Content-Length: 0\r\n" +
		"Date: Thu, 01 Jan 1970 00:00:00 GMT\r\n\r\n"
	if got := raw.writtenString(); got != want {
		t.Fatalf("raw 414 = %q, want %q", got, want)
	}
	deadline := raw.writeDeadline()
	if deadline.Before(before.Add(5*time.Second)) ||
		deadline.After(after.Add(5*time.Second)) {
		t.Fatalf("write deadline = %v outside fixed window", deadline)
	}
	if raw.closeCalls.Load() != 1 || releases.Load() != 1 || !state.ResponseTerminal() {
		t.Fatal("raw 414 did not terminate connection ownership exactly once")
	}
	if next, nextErr := connection.Read(output); next != 0 || !errors.Is(nextErr, net.ErrClosed) {
		t.Fatalf("terminal Read() = %d/%v", next, nextErr)
	}
}

// TestTrackedConnRaw414FailuresNeverPublishAPartialResponseTwice proves fixed-write safety.
func TestTrackedConnRaw414FailuresNeverPublishAPartialResponseTwice(t *testing.T) {
	prefix := append([]byte("POST /"), bytes.Repeat([]byte{'x'}, testRequestHeadLimit-len("POST /"))...)
	tests := []struct {
		name            string
		configure       func(*transportRecordingConn)
		wantWrittenByte bool
	}{
		{name: testDeadlineName, configure: func(conn *transportRecordingConn) { conn.writeDeadlineErr = errors.New(transportPrivateMarker) }},
		{name: "zero write", configure: func(conn *transportRecordingConn) { conn.zeroWrite = true }},
		{name: "partial error", wantWrittenByte: true, configure: func(conn *transportRecordingConn) {
			conn.maximumWrite = 7
			conn.writeErrAfter = 1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := newTransportRecordingConn([][]byte{prefix})
			test.configure(raw)
			state := newTransportState(nil)
			var releases atomic.Int32
			connection := newTrackedConn(raw, state, func() { releases.Add(1) })
			state.connection.Store(connection)
			count, readErr := connection.Read(make([]byte, 1))
			if count != 0 || readErr == nil || strings.Contains(readErr.Error(), transportPrivateMarker) {
				t.Fatalf("Read() = %d/%v", count, readErr)
			}
			if (len(raw.writtenString()) > 0) != test.wantWrittenByte {
				t.Fatal("raw write prefix outcome differs")
			}
			if raw.closeCalls.Load() != 1 || releases.Load() != 1 {
				t.Fatal("raw failure did not release exactly once")
			}
			if next, nextErr := connection.Read(make([]byte, 1)); next != 0 || !errors.Is(nextErr, net.ErrClosed) {
				t.Fatalf("terminal Read() = %d/%v", next, nextErr)
			}
		})
	}
}

// TestTrackedConnNeverUsesRaw414OutsideTheExactMethodBound proves Go-owned fallbacks.
func TestTrackedConnNeverUsesRaw414OutsideTheExactMethodBound(t *testing.T) {
	tests := []struct {
		name      string
		prefix    []byte
		firstRead int
	}{
		{name: "method byte 65", prefix: append(bytes.Repeat([]byte{'A'}, transportMethodInspectLimit+1), ' '), firstRead: 65},
		{name: "invalid method", prefix: []byte("GE(T "), firstRead: 3},
		{name: "lf before delimiter", prefix: []byte("GET /bad\n"), firstRead: 9},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prefix := append([]byte(nil), test.prefix...)
			prefix = append(prefix, bytes.Repeat([]byte{'x'}, testRequestHeadLimit-len(prefix))...)
			raw := newTransportRecordingConn([][]byte{prefix})
			state := newTransportState(nil)
			connection := newTrackedConn(raw, state, nil)
			state.connection.Store(connection)
			output := make([]byte, testRequestHeadLimit)
			count, readErr := connection.Read(output)
			if readErr != nil || count != test.firstRead {
				t.Fatalf("Read() = %d/%v", count, readErr)
			}
			replayed := append([]byte(nil), output[:count]...)
			remaining, remainingErr := io.ReadAll(connection)
			if remainingErr != nil {
				t.Fatalf("ReadAll() failed: %v", remainingErr)
			}
			replayed = append(replayed, remaining...)
			if !bytes.Equal(replayed, prefix) {
				t.Fatal("early-release path did not replay the original prefix exactly")
			}
			if raw.writtenString() != "" || raw.closeCalls.Load() != 0 {
				t.Fatal("non-raw case emitted a response or closed early")
			}
			_ = connection.Close()
		})
	}
}

// TestTrackedConnMethodOverflowReleasesOnlyByte65ThenNormalizesLaterFields proves segment safety.
func TestTrackedConnMethodOverflowReleasesOnlyByte65ThenNormalizesLaterFields(t *testing.T) {
	method := string(bytes.Repeat([]byte{'A'}, transportMethodInspectLimit+1))
	firstSegment := method + " /v1/process HTTP/1.1\r\n" +
		"Host: 127.0.0.1:8080\r\n" +
		testExpectContinueField +
		"Transfer-Encoding: ,chunked,"
	raw := newTransportRecordingConn([][]byte{
		[]byte(firstSegment),
		[]byte("\r\n\r\n"),
	})
	state := newTransportState(nil)
	connection := newTrackedConn(raw, state, nil)
	state.connection.Store(connection)
	output := make([]byte, len(firstSegment)+64)
	count, readErr := connection.Read(output)
	if readErr != nil || count != transportMethodInspectLimit+1 ||
		string(output[:count]) != method {
		t.Fatalf("first replay = %d/%v/%q", count, readErr, output[:count])
	}
	remaining, remainingErr := io.ReadAll(connection)
	if remainingErr != nil {
		t.Fatalf("remaining replay failed: %v", remainingErr)
	}
	wantRemaining := " /v1/process HTTP/1.1\r\n" +
		"Host: 127.0.0.1:8080\r\n" +
		"X-Dk2E: 100-continue\r\n" +
		"Transfer-Encoding:chunked   \r\n\r\n"
	if string(remaining) != wantRemaining {
		t.Fatalf("remaining replay = %q, want %q", remaining, wantRemaining)
	}
	facts := state.Facts()
	if facts.expect != expectContinue || facts.framing != framingSingleChunked {
		t.Fatalf("late facts = %#v", facts)
	}
	if raw.writtenString() != "" {
		t.Fatal("method overflow emitted a raw response")
	}
	_ = connection.Close()
}

// TestTrackedConnMethodOverflowByteAtATimeKeepsOneShotBoundary proves split-read stability.
func TestTrackedConnMethodOverflowByteAtATimeKeepsOneShotBoundary(t *testing.T) {
	request := string(bytes.Repeat([]byte{'B'}, transportMethodInspectLimit+1)) +
		" /healthz HTTP/1.1\nHost: local\nExpect: ,100-continue\n" +
		"Transfer-Encoding: ,chunked,\n\n"
	segments := make([][]byte, 0, len(request))
	for index := range []byte(request) {
		segments = append(segments, []byte{request[index]})
	}
	raw := newTransportRecordingConn(segments)
	state := newTransportState(nil)
	connection := newTrackedConn(raw, state, nil)
	state.connection.Store(connection)
	first := make([]byte, len(request))
	count, readErr := connection.Read(first)
	if readErr != nil || count != transportMethodInspectLimit+1 {
		t.Fatalf("first replay = %d/%v", count, readErr)
	}
	rest, restErr := io.ReadAll(connection)
	if restErr != nil {
		t.Fatalf("remaining replay failed: %v", restErr)
	}
	got := append(append([]byte(nil), first[:count]...), rest...)
	want := strings.Replace(request, "Expect:", "X-Dk2E:", 1)
	want = strings.Replace(want, "Transfer-Encoding: ,chunked,", "Transfer-Encoding:chunked   ", 1)
	if string(got) != want {
		t.Fatalf("byte-at-time replay differs:\n got %q\nwant %q", got, want)
	}
	_ = connection.Close()
}

// TestTrackedConnNormalizationIsIndependentOfCoalescedBodyTail proves non-growing replay.
func TestTrackedConnNormalizationIsIndependentOfCoalescedBodyTail(t *testing.T) {
	head := "POST /v1/process HTTP/1.1\r\nHost: local\r\n" +
		"Transfer-Encoding:\r\nTransfer-Encoding: chunked\r\n\r\n"
	body := strings.Repeat("b", testRequestHeadLimit)
	tests := []struct {
		name     string
		segments [][]byte
	}{
		{name: "coalesced", segments: [][]byte{[]byte(head + body)}},
		{name: "split", segments: [][]byte{[]byte(head), []byte(body)}},
	}
	var baseline []byte
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := newTransportRecordingConn(test.segments)
			state := newTransportState(nil)
			connection := newTrackedConn(raw, state, nil)
			state.connection.Store(connection)
			got, readErr := io.ReadAll(connection)
			if readErr != nil {
				t.Fatalf("ReadAll() failed: %v", readErr)
			}
			wantHead := "POST /v1/process HTTP/1.1\r\nHost: local\r\n" +
				"X-DKIM2-Framing-X:\r\nTransfer-Encoding:chunked \r\n\r\n"
			if string(got) != wantHead+body {
				t.Fatal("normalized head/body replay differs")
			}
			if state.Facts().framing != framingSingleChunked {
				t.Fatal("co-read body tail changed the framing class")
			}
			if baseline == nil {
				baseline = append([]byte(nil), got...)
			} else if !bytes.Equal(got, baseline) {
				t.Fatal("TCP segmentation changed normalized Go bytes")
			}
			_ = connection.Close()
		})
	}
}

// TestTrackedConnControlAndFormattingRemainBounded proves error and privacy surfaces.
func TestTrackedConnControlAndFormattingRemainBounded(t *testing.T) {
	raw := newTransportRecordingConn(nil)
	raw.readDeadlineErr = errors.New(transportPrivateMarker)
	state := newTransportState(func() (string, bool) { return transportPrivateMarker, true })
	connection := newTrackedConn(raw, state, nil)
	state.connection.Store(connection)
	if err := state.AdvanceReadDeadline(time.Now()); err == nil ||
		strings.Contains(err.Error(), transportPrivateMarker) {
		t.Fatal("raw deadline error escaped")
	}
	for _, value := range []any{connection, state, transportFacts{hostValue: transportPrivateMarker}} {
		for _, formatted := range []string{
			fmt.Sprint(value),
			fmt.Sprintf("%+v", value),
			fmt.Sprintf("%#v", value),
		} {
			if strings.Contains(formatted, transportPrivateMarker) {
				t.Fatal("transport formatting escaped private state")
			}
		}
	}
	_ = connection.Close()
}

// TestTrackedConnConcurrentCloseReleasesExactlyOnce proves close race ownership.
func TestTrackedConnConcurrentCloseReleasesExactlyOnce(t *testing.T) {
	raw := newTransportRecordingConn(nil)
	state := newTransportState(nil)
	var releases atomic.Int32
	connection := newTrackedConn(raw, state, func() { releases.Add(1) })
	state.connection.Store(connection)
	var group sync.WaitGroup
	for index := 0; index < 64; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_ = connection.Close()
			_ = state.Close()
		}()
	}
	group.Wait()
	if raw.closeCalls.Load() != 1 || releases.Load() != 1 {
		t.Fatal("concurrent close released raw connection or token more than once")
	}
}

// TestTrackedConnConcurrentCloseSuppressesBlockedReadReplay proves terminal scrub.
func TestTrackedConnConcurrentCloseSuppressesBlockedReadReplay(t *testing.T) {
	state := newTransportState(nil)
	state.publishFacts(transportFacts{hostCount: 1, hostValue: "private.example"})
	raw := newTransportBlockingConn([]byte("GET / HTTP/1.1\r\nHost: private.example"))
	var releases atomic.Int32
	connection := newTrackedConn(raw, state, func() { releases.Add(1) })
	state.connection.Store(connection)
	admission, _ := newProcessAdmission(1, 0, 0)
	lease, _ := admission.TryAcquire(context.Background())
	ledger, _ := newWorkingSetLedger(processWorkingSetUnitBytes)
	if err := ledger.Claim(workingSetFixedStorage, 1); err != nil {
		t.Fatal("working-set claim failed")
	}
	reservation, _ := newProcessReservation(lease, ledger)
	if !state.OwnProcessReservation(reservation) {
		t.Fatal("transport rejected process reservation")
	}
	reservation.HandlerDone()

	result := make(chan struct {
		count int
		err   error
	}, 1)
	go func() {
		output := make([]byte, 256)
		count, err := connection.Read(output)
		result <- struct {
			count int
			err   error
		}{count: count, err: err}
	}()
	select {
	case <-raw.blocked:
	case <-time.After(time.Second):
		t.Fatal("Read did not reach the blocked raw owner")
	}
	closeResult := make(chan error, 1)
	go func() { closeResult <- connection.Close() }()
	select {
	case <-raw.closeCalled:
	case <-time.After(time.Second):
		t.Fatal("Close did not terminate the raw owner")
	}
	if admission.Owned() != 1 || ledger.Snapshot().Live != 1 ||
		releases.Load() != 0 {
		t.Fatal("terminal ownership released before read-state scrub")
	}
	close(raw.unblock)
	select {
	case readResult := <-result:
		if readResult.count != 0 || !errors.Is(readResult.err, net.ErrClosed) {
			t.Fatalf("terminal Read() = %d/%v", readResult.count, readResult.err)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal Read remained blocked")
	}
	if err := <-closeResult; err != nil {
		t.Fatal("Close() failed")
	}
	if connection.captured != nil || connection.replayAt != 0 ||
		connection.pendingRead != nil || releases.Load() != 1 {
		t.Fatal("terminal connection retained replay or release ownership")
	}
	if facts := state.Facts(); facts.hostValue != "" {
		t.Fatal("terminal connection retained captured Host")
	}
	if _, _, ok := state.ConsumeHost(); ok {
		t.Fatal("terminal Host remained consumable")
	}
	if admission.Owned() != 0 || ledger.Snapshot().Live != 0 {
		t.Fatal("scrub completion retained process reservation")
	}
}

// TestTrackedConnDefersReservationUntilBlockedResponseScrub proves output ownership.
func TestTrackedConnDefersReservationUntilBlockedResponseScrub(t *testing.T) {
	state := newTransportState(nil)
	state.publishFacts(transportFacts{
		protoMajor: 1,
		protoMinor: 1,
		hostCount:  1,
		hostValue:  "private.example",
	})
	state.MarkHandlerEntered()
	raw := newTransportBlockingWriteConn()
	var releases atomic.Int32
	connection := newTrackedConn(raw, state, func() { releases.Add(1) })
	state.connection.Store(connection)
	admission, _ := newProcessAdmission(1, 0, 0)
	lease, _ := admission.TryAcquire(context.Background())
	ledger, _ := newWorkingSetLedger(processWorkingSetUnitBytes)
	if err := ledger.Claim(workingSetFixedStorage, 1); err != nil {
		t.Fatal("working-set claim failed")
	}
	reservation, _ := newProcessReservation(lease, ledger)
	if !state.OwnProcessReservation(reservation) {
		t.Fatal("transport rejected process reservation")
	}
	reservation.HandlerDone()

	partial := []byte("HTTP/1.1 500 Internal Server Error\r\nX-Test: retained")
	if count, err := connection.Write(partial); err != nil || count != len(partial) {
		t.Fatalf("partial response Write() = %d/%v", count, err)
	}
	writeResult := make(chan error, 1)
	go func() {
		_, err := connection.Write([]byte("\r\n\r\nbody"))
		writeResult <- err
	}()
	select {
	case <-raw.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("response filter did not reach blocked raw Write")
	}
	closeResult := make(chan error, 1)
	go func() { closeResult <- connection.Close() }()
	select {
	case <-raw.closeCalled:
	case <-time.After(time.Second):
		t.Fatal("Close did not terminate blocked response transport")
	}
	if admission.Owned() != 1 || ledger.Snapshot().Live != 1 ||
		releases.Load() != 0 {
		t.Fatal("response reservation released before blocked write scrub")
	}
	close(raw.allowWrite)
	if err := <-writeResult; !errors.Is(err, errResponseFilter) {
		t.Fatalf("terminal response Write() error = %v", err)
	}
	if err := <-closeResult; err != nil {
		t.Fatal("Close() failed")
	}
	if connection.response != nil || admission.Owned() != 0 ||
		ledger.Snapshot().Live != 0 || releases.Load() != 1 {
		t.Fatal("response scrub did not release exact terminal ownership")
	}
}

// TestTrackedConnResponseOutcomesReleaseAttachedReservation proves successful
// partial writes and zero-write failure use the same terminal ownership path.
func TestTrackedConnResponseOutcomesReleaseAttachedReservation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		configure func(*transportRecordingConn)
		wantError bool
	}{
		{
			name: "successful partial raw writes",
			configure: func(raw *transportRecordingConn) {
				raw.maximumWrite = 7
			},
		},
		{
			name: "zero raw write",
			configure: func(raw *transportRecordingConn) {
				raw.zeroWrite = true
			},
			wantError: true,
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			raw := newTransportRecordingConn(nil)
			testCase.configure(raw)
			state := newTransportState(nil)
			state.publishFacts(transportFacts{
				protoMajor: 1,
				protoMinor: 1,
				hostCount:  1,
			})
			state.MarkHandlerEntered()
			connection := newTrackedConn(raw, state, nil)
			state.connection.Store(connection)
			admission, _ := newProcessAdmission(1, 0, 0)
			lease, _ := admission.TryAcquire(context.Background())
			ledger, _ := newWorkingSetLedger(processWorkingSetUnitBytes)
			if err := ledger.Claim(workingSetFixedStorage, 1); err != nil {
				t.Fatal("working-set claim failed")
			}
			reservation, _ := newProcessReservation(lease, ledger)
			if !state.OwnProcessReservation(reservation) {
				t.Fatal("transport rejected process reservation")
			}
			reservation.HandlerDone()

			response := []byte(
				"HTTP/1.1 500 Internal Server Error\r\n" +
					"Content-Length: 4\r\n\r\nbody",
			)
			count, err := connection.Write(response)
			if count != len(response) || (err != nil) != testCase.wantError {
				t.Fatalf("Write() = %d/%v", count, err)
			}
			if !testCase.wantError {
				if admission.Owned() != 1 {
					t.Fatal("successful final write released before socket terminal")
				}
				if err := connection.Close(); err != nil {
					t.Fatal("Close() failed")
				}
			}
			if admission.Owned() != 0 || ledger.Snapshot().Live != 0 ||
				connection.response != nil {
				t.Fatal("terminal response outcome retained reservation or filter")
			}
		})
	}
}

type transportScriptedListener struct {
	connections chan net.Conn
	closed      chan struct{}
	closeOnce   sync.Once
}

type transportCloseRaceListener struct {
	connection    net.Conn
	acceptStarted chan struct{}
	allowAccept   chan struct{}
	closeObserved chan struct{}
	closeOnce     sync.Once
}

// newTransportCloseRaceListener constructs an Accept-success versus Close race.
func newTransportCloseRaceListener(connection net.Conn) *transportCloseRaceListener {
	return &transportCloseRaceListener{
		connection:    connection,
		acceptStarted: make(chan struct{}),
		allowAccept:   make(chan struct{}),
		closeObserved: make(chan struct{}),
	}
}

// Accept waits until Close has started, then returns one already-accepted socket.
func (l *transportCloseRaceListener) Accept() (net.Conn, error) {
	close(l.acceptStarted)
	<-l.allowAccept
	return l.connection, nil
}

// Close publishes lifecycle closure without changing the scripted Accept result.
func (l *transportCloseRaceListener) Close() error {
	l.closeOnce.Do(func() { close(l.closeObserved) })
	return nil
}

// Addr returns one constant test endpoint.
func (*transportCloseRaceListener) Addr() net.Addr {
	return transportTestAddr("close-race")
}

type transportErrorListener struct {
	calls atomic.Int32
}

// Accept returns one private temporary error followed by closure.
func (l *transportErrorListener) Accept() (net.Conn, error) {
	if l.calls.Add(1) == 1 {
		return nil, &transportPrivateNetError{}
	}
	return nil, net.ErrClosed
}

// Close satisfies net.Listener for the diagnostic fixture.
func (*transportErrorListener) Close() error { return nil }

// Addr returns one constant test endpoint.
func (*transportErrorListener) Addr() net.Addr {
	return transportTestAddr("error-listener")
}

type transportPrivateNetError struct{}

// Error returns one marker that must never reach diagnostics.
func (*transportPrivateNetError) Error() string { return transportPrivateMarker }

// Timeout reports no timeout.
func (*transportPrivateNetError) Timeout() bool { return false }

// Temporary requests net/http's bounded retry path.
func (*transportPrivateNetError) Temporary() bool { return true }

// newTransportScriptedListener constructs one deterministic accept queue.
func newTransportScriptedListener() *transportScriptedListener {
	return &transportScriptedListener{
		connections: make(chan net.Conn, testConnectionLimit+8),
		closed:      make(chan struct{}),
	}
}

// enqueue adds one accepted raw connection.
func (l *transportScriptedListener) enqueue(connection net.Conn) {
	l.connections <- connection
}

// Accept returns the next scripted connection or the close signal.
func (l *transportScriptedListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.connections:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// Close publishes listener closure exactly once.
func (l *transportScriptedListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

// Addr returns one constant test endpoint.
func (*transportScriptedListener) Addr() net.Addr {
	return transportTestAddr("listener")
}

type transportRecordingConn struct {
	mu sync.Mutex

	reads             [][]byte
	readIndex         int
	written           bytes.Buffer
	maximumWrite      int
	writeCalls        int
	writeErrAfter     int
	zeroWrite         bool
	readDeadlineErr   error
	writeDeadlineErr  error
	lastReadDeadline  time.Time
	lastWriteDeadline time.Time
	closeCalls        atomic.Int32
	closed            atomic.Bool
}

type transportBlockingConn struct {
	*transportRecordingConn
	first       []byte
	blocked     chan struct{}
	unblock     chan struct{}
	closeCalled chan struct{}
	blockOnce   sync.Once
	closeOnce   sync.Once
}

type transportBlockingWriteConn struct {
	*transportRecordingConn
	writeStarted chan struct{}
	closeCalled  chan struct{}
	allowWrite   chan struct{}
	writeOnce    sync.Once
	closeOnce    sync.Once
}

// newTransportBlockingWriteConn constructs one independently released write.
func newTransportBlockingWriteConn() *transportBlockingWriteConn {
	return &transportBlockingWriteConn{
		transportRecordingConn: newTransportRecordingConn(nil),
		writeStarted:           make(chan struct{}),
		closeCalled:            make(chan struct{}),
		allowWrite:             make(chan struct{}),
	}
}

// Write retains its input until the test permits one terminal failure.
func (c *transportBlockingWriteConn) Write([]byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeStarted) })
	<-c.allowWrite
	return 0, errors.New(transportPrivateMarker)
}

// Close publishes raw termination without releasing the blocked writer.
func (c *transportBlockingWriteConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeCalled)
		c.closed.Store(true)
		c.closeCalls.Add(1)
	})
	return nil
}

// newTransportBlockingConn constructs one partial-read then blocked raw owner.
func newTransportBlockingConn(first []byte) *transportBlockingConn {
	return &transportBlockingConn{
		transportRecordingConn: newTransportRecordingConn(nil),
		first:                  append([]byte(nil), first...),
		blocked:                make(chan struct{}),
		unblock:                make(chan struct{}),
		closeCalled:            make(chan struct{}),
	}
}

// Read returns one partial head, then waits for terminal Close.
func (c *transportBlockingConn) Read(output []byte) (int, error) {
	if len(c.first) != 0 {
		count := copy(output, c.first)
		c.first = c.first[count:]
		return count, nil
	}
	c.blockOnce.Do(func() { close(c.blocked) })
	<-c.unblock
	return 0, net.ErrClosed
}

// Close releases the blocked raw read exactly once.
func (c *transportBlockingConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeCalled)
		c.closed.Store(true)
		c.closeCalls.Add(1)
	})
	return nil
}

// newTransportRecordingConn constructs one deterministic raw connection.
func newTransportRecordingConn(reads [][]byte) *transportRecordingConn {
	return &transportRecordingConn{reads: reads}
}

// Read returns the next scripted raw segment.
func (c *transportRecordingConn) Read(output []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readIndex >= len(c.reads) {
		return 0, io.EOF
	}
	current := c.reads[c.readIndex]
	count := copy(output, current)
	if count == len(current) {
		c.readIndex++
	} else {
		c.reads[c.readIndex] = current[count:]
	}
	return count, nil
}

// Write records one bounded raw response segment.
func (c *transportRecordingConn) Write(input []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeCalls++
	if c.zeroWrite {
		return 0, nil
	}
	count := len(input)
	if c.maximumWrite > 0 && count > c.maximumWrite {
		count = c.maximumWrite
	}
	_, _ = c.written.Write(input[:count])
	if c.writeErrAfter > 0 && c.writeCalls >= c.writeErrAfter {
		return count, errors.New(transportPrivateMarker)
	}
	return count, nil
}

// Close records exact raw connection release.
func (c *transportRecordingConn) Close() error {
	c.closeCalls.Add(1)
	c.closed.Store(true)
	return nil
}

// LocalAddr returns one constant local endpoint.
func (*transportRecordingConn) LocalAddr() net.Addr {
	return transportTestAddr("local")
}

// RemoteAddr returns one constant remote endpoint.
func (*transportRecordingConn) RemoteAddr() net.Addr {
	return transportTestAddr("remote")
}

// SetDeadline records both raw deadline channels.
func (c *transportRecordingConn) SetDeadline(deadline time.Time) error {
	if err := c.SetReadDeadline(deadline); err != nil {
		return err
	}
	return c.SetWriteDeadline(deadline)
}

// SetReadDeadline records or rejects the raw read deadline.
func (c *transportRecordingConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastReadDeadline = deadline
	return c.readDeadlineErr
}

// SetWriteDeadline records or rejects the raw write deadline.
func (c *transportRecordingConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastWriteDeadline = deadline
	return c.writeDeadlineErr
}

// writtenString returns one synchronized output snapshot.
func (c *transportRecordingConn) writtenString() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written.String()
}

// writeDeadline returns the synchronized raw write deadline.
func (c *transportRecordingConn) writeDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastWriteDeadline
}

type transportTestAddr string

// Network returns one constant test network.
func (transportTestAddr) Network() string { return "transport-test" }

// String returns one constant content-free test address.
func (a transportTestAddr) String() string { return string(a) }
