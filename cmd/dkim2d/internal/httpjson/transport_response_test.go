package httpjson

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newResponseFilterFixture constructs one response filter with exact-close accounting.
func newResponseFilterFixture(
	dateProvider func() (string, bool),
) (*responseHeadFilter, *transportRecordingConn, *transportState, *atomic.Int32) {
	raw := newTransportRecordingConn(nil)
	state := newTransportState(dateProvider)
	releases := &atomic.Int32{}
	connection := newTrackedConn(raw, state, func() { releases.Add(1) })
	state.connection.Store(connection)
	filter := newResponseHeadFilter(raw, state, connection.terminate)
	return filter, raw, state, releases
}

// responseHeadAtSize builds one syntactically valid response head at an exact size.
func responseHeadAtSize(t *testing.T, size int, status string) []byte {
	t.Helper()
	prefix := []byte("HTTP/1.1 " + status + "\r\nX-Pad: ")
	suffix := []byte("\r\n\r\n")
	if size < len(prefix)+len(suffix) {
		t.Fatal("requested response head is too small")
	}
	return append(append(prefix, bytes.Repeat([]byte{'x'}, size-len(prefix)-len(suffix))...), suffix...)
}

// TestResponseHeadFilterEnforcesEachSectionCap proves exact and one-over boundaries.
func TestResponseHeadFilterEnforcesEachSectionCap(t *testing.T) {
	exact, raw, state, releases := newResponseFilterFixture(nil)
	head := responseHeadAtSize(t, testResponseHeadLimit, testStatusOK)
	if count, err := exact.Write(head); count != len(head) || err != nil {
		t.Fatalf("exact Write() = %d/%v", count, err)
	}
	if !strings.HasSuffix(raw.writtenString(), "Connection: close\r\n\r\n") {
		t.Fatal("exact-size response was not normalized")
	}
	if state.ResponseTerminal() || releases.Load() != 0 {
		t.Fatal("successful exact-size head became terminal")
	}

	over, overRaw, _, overReleases := newResponseFilterFixture(nil)
	tooLarge := responseHeadAtSize(t, testResponseHeadLimit+1, testStatusOK)
	if count, err := over.Write(tooLarge); count != len(tooLarge) || !errors.Is(err, errResponseFilter) {
		t.Fatalf("one-over Write() = %d/%v", count, err)
	}
	if overRaw.writtenString() != "" || overRaw.closeCalls.Load() != 1 || overReleases.Load() != 1 {
		t.Fatal("one-over response leaked bytes or retained ownership")
	}
	if count, err := over.Write([]byte("again")); count != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("terminal Write() = %d/%v", count, err)
	}
}

// TestResponseHeadFilterDoesNotChargeCoalescedBody proves the cap is section-local.
func TestResponseHeadFilterDoesNotChargeCoalescedBody(t *testing.T) {
	filter, raw, _, _ := newResponseFilterFixture(nil)
	head := []byte("HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n")
	body := bytes.Repeat([]byte{'b'}, 65_536)
	input := append(append([]byte(nil), head...), body...)
	if count, err := filter.Write(input); count != len(input) || err != nil {
		t.Fatalf("Write() = %d/%v", count, err)
	}
	if got := raw.writtenString(); !strings.HasSuffix(got, string(body)) {
		t.Fatal("coalesced body was truncated or counted as response head")
	}
}

// TestResponseHeadFilterNeverParsesCoalescedBodyDelimiters proves body byte opacity.
func TestResponseHeadFilterNeverParsesCoalescedBodyDelimiters(t *testing.T) {
	for _, body := range [][]byte{
		{'\n'},
		{'\r', 'x'},
		{0x00, 0xff, '\r', '\n', '\n'},
		bytes.Repeat([]byte{'\r'}, testResponseHeadLimit+1),
	} {
		filter, raw, state, _ := newResponseFilterFixture(nil)
		state.MarkHandlerEntered()
		head := []byte("HTTP/1.1 200 OK\r\n\r\n")
		input := append(append([]byte(nil), head...), body...)
		if count, err := filter.Write(input); count != len(input) || err != nil {
			t.Fatalf("body %x Write() = %d/%v", body[:min(len(body), 8)], count, err)
		}
		if got := []byte(raw.writtenString()); !bytes.HasSuffix(got, body) {
			t.Fatalf("body %x was changed or retained as head", body[:min(len(body), 8)])
		}
	}
}

// TestResponseHeadFilterResetsAfterBareContinue proves interim ownership and final limits.
func TestResponseHeadFilterResetsAfterBareContinue(t *testing.T) {
	filter, raw, state, releases := newResponseFilterFixture(nil)
	state.MarkHandlerEntered()
	interim := []byte("HTTP/1.1 100 Continue\r\n\r\n")
	if count, err := filter.Write(interim); count != len(interim) || err != nil {
		t.Fatalf("100 Write() = %d/%v", count, err)
	}
	if raw.writtenString() != string(interim) || releases.Load() != 0 || filter.Terminal() {
		t.Fatal("bare 100 changed bytes or released ownership")
	}
	final := responseHeadAtSize(t, testResponseHeadLimit, "599 Boundary")
	if count, err := filter.Write(final); count != len(final) || err != nil {
		t.Fatalf("final Write() = %d/%v", count, err)
	}

	invalid, invalidRaw, _, invalidReleases := newResponseFilterFixture(nil)
	if _, err := invalid.Write([]byte("HTTP/1.1 100 Continue\r\nX: y\r\n\r\n")); !errors.Is(err, errResponseFilter) {
		t.Fatalf("non-bare 100 error = %v", err)
	}
	if invalidRaw.writtenString() != "" || invalidReleases.Load() != 1 {
		t.Fatal("non-bare 100 escaped or retained ownership")
	}

	prehandler, prehandlerRaw, _, prehandlerReleases := newResponseFilterFixture(nil)
	if _, err := prehandler.Write(interim); !errors.Is(err, errResponseFilter) {
		t.Fatalf("pre-handler 100 error = %v", err)
	}
	if prehandlerRaw.writtenString() != "" || prehandlerReleases.Load() != 1 {
		t.Fatal("pre-handler 100 escaped or retained ownership")
	}
}

// TestResponseHeadFilterResetsCoalescedSectionCap proves each coalesced head owns its limit.
func TestResponseHeadFilterResetsCoalescedSectionCap(t *testing.T) {
	interim := []byte("HTTP/1.1 100 Continue\r\n\r\n")
	exact, exactRaw, exactState, _ := newResponseFilterFixture(nil)
	exactState.MarkHandlerEntered()
	final := responseHeadAtSize(t, testResponseHeadLimit, testStatusOK)
	input := append(append([]byte(nil), interim...), final...)
	if count, err := exact.Write(input); count != len(input) || err != nil {
		t.Fatalf("coalesced exact Write() = %d/%v", count, err)
	}
	if !strings.HasPrefix(exactRaw.writtenString(), string(interim)) ||
		!strings.HasSuffix(exactRaw.writtenString(), "Connection: close\r\n\r\n") {
		t.Fatal("coalesced exact sections were not both forwarded")
	}

	over, overRaw, overState, overReleases := newResponseFilterFixture(nil)
	overState.MarkHandlerEntered()
	overFinal := responseHeadAtSize(t, testResponseHeadLimit+1, testStatusOK)
	overInput := append(append([]byte(nil), interim...), overFinal...)
	if count, err := over.Write(overInput); count != len(overInput) || !errors.Is(err, errResponseFilter) {
		t.Fatalf("coalesced one-over Write() = %d/%v", count, err)
	}
	if overRaw.writtenString() != string(interim) || overReleases.Load() != 1 {
		t.Fatal("coalesced one-over leaked final prefix or retained ownership")
	}

	split, splitRaw, _, _ := newResponseFilterFixture(nil)
	splitPrefix := []byte("HTTP/1.1 204 No Content\r\nX: y\r\n\r")
	if count, err := split.Write(splitPrefix); count != len(splitPrefix) || err != nil {
		t.Fatalf("split prefix Write() = %d/%v", count, err)
	}
	if splitRaw.writtenString() != "" {
		t.Fatal("split terminator leaked an incomplete response head")
	}
	if count, err := split.Write([]byte("\n")); count != 1 || err != nil {
		t.Fatalf("split suffix Write() = %d/%v", count, err)
	}
	if !strings.HasSuffix(splitRaw.writtenString(), "Connection: close\r\n\r\n") {
		t.Fatal("split terminator did not complete the head")
	}

	splitContinue, splitContinueRaw, splitContinueState, _ := newResponseFilterFixture(nil)
	splitContinueState.MarkHandlerEntered()
	if _, err := splitContinue.Write([]byte("HTTP/1.1 100 Continue\r\n\r")); err != nil {
		t.Fatalf("split 100 prefix failed: %v", err)
	}
	if splitContinueRaw.writtenString() != "" {
		t.Fatal("split bare 100 leaked before its terminator")
	}
	if _, err := splitContinue.Write([]byte("\nHTTP/1.1 204 No Content\r\n\r\n")); err != nil {
		t.Fatalf("split 100 suffix/final failed: %v", err)
	}
	if !strings.HasPrefix(splitContinueRaw.writtenString(), string(interim)) {
		t.Fatal("split bare 100 was not forwarded exactly")
	}

	second, secondRaw, secondState, secondReleases := newResponseFilterFixture(nil)
	secondState.MarkHandlerEntered()
	secondInput := append(append([]byte(nil), interim...), interim...)
	if _, err := second.Write(secondInput); !errors.Is(err, errResponseFilter) {
		t.Fatalf("second 100 error = %v", err)
	}
	if secondRaw.writtenString() != string(interim) || secondReleases.Load() != 1 {
		t.Fatal("second 100 escaped or retained ownership")
	}
}

// TestResponseHeadFilterRejectsUnexpectedInformationalAndStatus600 proves status bounds.
func TestResponseHeadFilterRejectsUnexpectedInformationalAndStatus600(t *testing.T) {
	for _, head := range []string{
		"HTTP/1.1 101 Switching Protocols\r\n\r\n",
		"HTTP/1.1 199 Unexpected\r\n\r\n",
		"HTTP/1.1 600 Invalid\r\n\r\n",
	} {
		filter, raw, _, releases := newResponseFilterFixture(nil)
		if count, err := filter.Write([]byte(head)); count != len(head) || !errors.Is(err, errResponseFilter) {
			t.Fatalf("%q Write() = %d/%v", head, count, err)
		}
		if raw.writtenString() != "" || releases.Load() != 1 {
			t.Fatalf("%q escaped or retained ownership", head)
		}
	}
}

// TestResponseHeadFilterAppliesDateAndConnectionPolicy proves transform order and omission.
func TestResponseHeadFilterAppliesDateAndConnectionPolicy(t *testing.T) {
	tests := []struct {
		name     string
		provider func() (string, bool)
		head     string
		want     string
	}{
		{
			name: "inject",
			provider: func() (string, bool) {
				return transportTestEpoch, true
			},
			head: "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n",
			want: "HTTP/1.1 200 OK\r\nDate: Thu, 01 Jan 1970 00:00:00 GMT\r\nConnection: close\r\n\r\n",
		},
		{
			name: "preserve existing",
			provider: func() (string, bool) {
				return "Fri, 02 Jan 1970 00:00:00 GMT", true
			},
			head: "HTTP/1.1 304 Not Modified\r\ndAtE: Thu, 01 Jan 1970 00:00:00 GMT\r\nConnection: x\r\nConnection: y\r\n\r\n",
			want: "HTTP/1.1 304 Not Modified\r\ndAtE: Thu, 01 Jan 1970 00:00:00 GMT\r\nConnection: close\r\n\r\n",
		},
		{
			name: testUnavailableName,
			provider: func() (string, bool) {
				return "not-a-date", true
			},
			head: "HTTP/1.0 404 Not Found\r\n\r\n",
			want: "HTTP/1.0 404 Not Found\r\nConnection: close\r\n\r\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filter, raw, _, _ := newResponseFilterFixture(test.provider)
			if _, err := filter.Write([]byte(test.head)); err != nil {
				t.Fatalf("Write() failed: %v", err)
			}
			if got := raw.writtenString(); got != test.want {
				t.Fatalf("output = %q, want %q", got, test.want)
			}
		})
	}
}

// TestResponseHeadFilterRepairsEveryHTTP10FinalClass proves unconditional close normalization.
func TestResponseHeadFilterRepairsEveryHTTP10FinalClass(t *testing.T) {
	for _, status := range []string{
		testStatusOK, "204 No Content", "304 Not Modified", testBadRequestReason,
		"431 Request Header Fields Too Large", "500 Internal Server Error",
	} {
		filter, raw, _, _ := newResponseFilterFixture(func() (string, bool) {
			return transportTestEpoch, true
		})
		input := "HTTP/1.0 " + status + "\r\nConnection: keep-alive\r\n\r\n"
		if _, err := filter.Write([]byte(input)); err != nil {
			t.Fatalf("%s Write() failed: %v", status, err)
		}
		output := raw.writtenString()
		if strings.Count(output, "Connection: close\r\n") != 1 ||
			strings.Contains(output, "keep-alive") {
			t.Fatalf("%s Connection repair = %q", status, output)
		}
		wantDate := status[0] >= '2' && status[0] <= '4'
		if strings.Contains(output, "Date: ") != wantDate {
			t.Fatalf("%s Date presence differs: %q", status, output)
		}
	}
}

// TestResponseHeadFilterRewritesOnlyGuardedPrehandlerFraming501 proves effective-status policy.
func TestResponseHeadFilterRewritesOnlyGuardedPrehandlerFraming501(t *testing.T) {
	filter, raw, state, _ := newResponseFilterFixture(func() (string, bool) {
		return transportTestEpoch, true
	})
	state.publishFacts(transportFacts{framing: framingBad, protoMajor: 1, protoMinor: 1})
	input := "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n"
	if _, err := filter.Write([]byte(input)); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}
	if got := raw.writtenString(); got != "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nDate: Thu, 01 Jan 1970 00:00:00 GMT\r\nConnection: close\r\n\r\n" {
		t.Fatalf("rewritten output = %q", got)
	}

	owned, ownedRaw, ownedState, _ := newResponseFilterFixture(nil)
	ownedState.publishFacts(transportFacts{framing: framingBad, protoMajor: 1, protoMinor: 1})
	ownedState.MarkHandlerEntered()
	if _, err := owned.Write([]byte(input)); err != nil {
		t.Fatalf("handler-owned Write() failed: %v", err)
	}
	if !strings.HasPrefix(ownedRaw.writtenString(), testHTTP11NotImplementedLine) {
		t.Fatal("handler-owned 501 was rewritten")
	}
}

// TestResponseHeadFilterAddsDateToDirectGoClientErrors proves pre-handler repair.
func TestResponseHeadFilterAddsDateToDirectGoClientErrors(t *testing.T) {
	for _, status := range []string{testBadRequestReason, "431 Request Header Fields Too Large"} {
		filter, raw, _, _ := newResponseFilterFixture(func() (string, bool) {
			return transportTestEpoch, true
		})
		if _, err := filter.Write([]byte("HTTP/1.1 " + status + "\r\nContent-Length: 0\r\n\r\n")); err != nil {
			t.Fatalf("%s Write() failed: %v", status, err)
		}
		if !strings.Contains(raw.writtenString(), "Date: Thu, 01 Jan 1970 00:00:00 GMT\r\n") {
			t.Fatalf("%s did not receive Date", status)
		}
	}
}

// TestResponseHeadFilterSuppressesExactHEADBody proves byte-discard semantics.
func TestResponseHeadFilterSuppressesExactHEADBody(t *testing.T) {
	filter, raw, state, _ := newResponseFilterFixture(nil)
	state.publishFacts(transportFacts{exactHEAD: true})
	input := []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest")
	if count, err := filter.Write(input); count != len(input) || err != nil {
		t.Fatalf("coalesced Write() = %d/%v", count, err)
	}
	if strings.Contains(raw.writtenString(), "test") {
		t.Fatal("coalesced HEAD body escaped")
	}
	if count, err := filter.Write([]byte("later")); count != 5 || err != nil {
		t.Fatalf("later body Write() = %d/%v", count, err)
	}
	if strings.Contains(raw.writtenString(), "later") {
		t.Fatal("later HEAD body escaped")
	}
}

// TestResponseHeadFilterTerminalWriteFailuresAreConstantAndExactOnce proves failure containment.
func TestResponseHeadFilterTerminalWriteFailuresAreConstantAndExactOnce(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*transportRecordingConn)
	}{
		{name: testZeroName, configure: func(conn *transportRecordingConn) { conn.zeroWrite = true }},
		{name: "partial error", configure: func(conn *transportRecordingConn) {
			conn.maximumWrite = 7
			conn.writeErrAfter = 1
		}},
		{name: testDeadlineName, configure: func(conn *transportRecordingConn) {
			conn.writeDeadlineErr = errors.New(transportPrivateMarker)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filter, raw, _, releases := newResponseFilterFixture(nil)
			test.configure(raw)
			input := []byte("HTTP/1.1 200 OK\r\n\r\n")
			count, err := filter.Write(input)
			if count != len(input) || !errors.Is(err, errResponseFilter) ||
				strings.Contains(err.Error(), transportPrivateMarker) {
				t.Fatalf("Write() = %d/%v", count, err)
			}
			if raw.closeCalls.Load() != 1 || releases.Load() != 1 {
				t.Fatal("terminal failure did not close/release exactly once")
			}
			if count, err = filter.Write(input); count != 0 || !errors.Is(err, net.ErrClosed) {
				t.Fatalf("later Write() = %d/%v", count, err)
			}
		})
	}
}

// TestResponseHeadFilterRetriesSuccessfulPartialWritesAndPassesLaterBody proves write-all.
func TestResponseHeadFilterRetriesSuccessfulPartialWritesAndPassesLaterBody(t *testing.T) {
	filter, raw, state, _ := newResponseFilterFixture(nil)
	state.MarkHandlerEntered()
	raw.maximumWrite = 3
	head := []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
	if count, err := filter.Write(head); count != len(head) || err != nil {
		t.Fatalf("head Write() = %d/%v", count, err)
	}
	if count, err := filter.Write([]byte("test")); count != 4 || err != nil {
		t.Fatalf("body Write() = %d/%v", count, err)
	}
	if !strings.HasSuffix(raw.writtenString(), "\r\n\r\ntest") {
		t.Fatal("successful partial writes changed final bytes")
	}
}

// TestResponseHeadFilterRejectsMalformedProducedHeads proves invariant fail-closed behavior.
func TestResponseHeadFilterRejectsMalformedProducedHeads(t *testing.T) {
	for _, head := range []string{
		"HTTP/1.1 200 OK\nX: y\n\n",
		"HTTP/1.1 200 OK\r\nBad Field: y\r\n\r\n",
		"HTTP/2.0 200 OK\r\n\r\n",
		"HTTP/1.1 xxx Bad\r\n\r\n",
		"HTTP/1.1 099 Bad\r\n\r\n",
	} {
		filter, raw, _, releases := newResponseFilterFixture(nil)
		if count, err := filter.Write([]byte(head)); count != len(head) || !errors.Is(err, errResponseFilter) {
			t.Fatalf("%q Write() = %d/%v", head, count, err)
		}
		if raw.writtenString() != "" || releases.Load() != 1 {
			t.Fatalf("%q escaped or retained ownership", head)
		}
	}
}

// TestResponseHeadFilterExternalCloseIsImmediatelyTerminal proves shared-close visibility.
func TestResponseHeadFilterExternalCloseIsImmediatelyTerminal(t *testing.T) {
	filter, raw, state, releases := newResponseFilterFixture(nil)
	if count, err := filter.Write([]byte("HTTP/1.1 200")); count != 12 || err != nil {
		t.Fatalf("partial Write() = %d/%v", count, err)
	}
	if err := state.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	if count, err := filter.Write([]byte(" OK\r\n\r\n")); count != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("post-close Write() = %d/%v", count, err)
	}
	if raw.writtenString() != "" || raw.closeCalls.Load() != 1 || releases.Load() != 1 {
		t.Fatal("external close leaked partial head or duplicated release")
	}
}

// TestResponseHeadFilterConcurrentPartialWritesAndCloseDoNotDeadlock proves lock ordering.
func TestResponseHeadFilterConcurrentPartialWritesAndCloseDoNotDeadlock(t *testing.T) {
	filter, raw, state, releases := newResponseFilterFixture(nil)
	var group sync.WaitGroup
	for range 32 {
		group.Go(func() {
			_, _ = filter.Write([]byte("HTTP/1.1 200"))
		})
	}
	group.Go(func() {
		_ = state.Close()
	})
	done := make(chan struct{})
	go func() {
		group.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("concurrent write/close deadlocked")
	}
	if raw.closeCalls.Load() != 1 || releases.Load() != 1 {
		t.Fatal("concurrent close did not release exactly once")
	}
}

// TestResponseHeadFilterConcurrentContinueFinalAndShutdownReleasesOnce proves full race ownership.
func TestResponseHeadFilterConcurrentContinueFinalAndShutdownReleasesOnce(t *testing.T) {
	filter, raw, state, releases := newResponseFilterFixture(nil)
	state.MarkHandlerEntered()
	var group sync.WaitGroup
	for _, input := range [][]byte{
		[]byte("HTTP/1.1 100 Continue\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
	} {
		group.Go(func() {
			_, _ = filter.Write(input)
		})
	}
	group.Go(func() {
		_ = state.Close()
	})
	group.Wait()
	if raw.closeCalls.Load() != 1 || releases.Load() != 1 || !filter.Terminal() {
		t.Fatal("continue/final/shutdown race did not terminate exactly once")
	}
}
