package httpjson

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	transportPrivateMarker = "PRIVATE-TRANSPORT-MARKER"
	transportTestAbsent    = "absent"
	transportTestEmpty     = "empty"
	transportTestMalformed = "malformed"
	transportTestEpoch     = "Thu, 01 Jan 1970 00:00:00 GMT"
)

// TestPrepareTransportHeadClassifiesExpect proves the complete combined Expect grammar.
func TestPrepareTransportHeadClassifiesExpect(t *testing.T) {
	tests := []struct {
		name      string
		fields    string
		want      expectClass
		obsFold   bool
		rewritten int
	}{
		{name: transportTestAbsent, want: expectNone},
		{name: transportTestEmpty, fields: "Expect:\r\n", want: expectNone, rewritten: 1},
		{name: "empty list", fields: "Expect: ,,\r\n", want: expectNone, rewritten: 1},
		{name: "continue", fields: testExpectContinueField, want: expectContinue, rewritten: 1},
		{name: "case insensitive repeated", fields: "Expect: 100-Continue,\r\nExpect: ,100-CONTINUE\r\n", want: expectContinue, rewritten: 2},
		{name: "extension", fields: "Expect: private-extension\r\n", want: expectUnsupported, rewritten: 1},
		{name: "extension value", fields: "Expect: private-extension=\"value\\\\\\\"tail\";a=b\r\n", want: expectUnsupported, rewritten: 1},
		{name: testMixedName, fields: "Expect: 100-continue, private-extension\r\n", want: expectUnsupported, rewritten: 1},
		{name: "parameterized continue", fields: "Expect: 100-continue=x;level=1\r\n", want: expectUnsupported, rewritten: 1},
		{name: testEmptyParametersName, fields: "Expect: extension=x;; ;a=b;\r\n", want: expectUnsupported, rewritten: 1},
		{name: "missing expectation value", fields: "Expect: extension=\r\n", want: expectMalformed, rewritten: 1},
		{name: "ows before expectation equals", fields: "Expect: extension =x\r\n", want: expectMalformed, rewritten: 1},
		{name: "ows after expectation equals", fields: "Expect: extension= x\r\n", want: expectMalformed, rewritten: 1},
		{name: "ows before parameter equals", fields: "Expect: extension=x;a =b\r\n", want: expectMalformed, rewritten: 1},
		{name: "ows after parameter equals", fields: "Expect: extension=x;a= b\r\n", want: expectMalformed, rewritten: 1},
		{name: "continue parameter without value", fields: "Expect: 100-continue;level=1\r\n", want: expectMalformed, rewritten: 1},
		{name: "malformed token", fields: "Expect: bad member\r\n", want: expectMalformed, rewritten: 1},
		{name: "malformed quote", fields: "Expect: extension=\"unterminated\r\n", want: expectMalformed, rewritten: 1},
		{name: "malformed pair", fields: "Expect: extension=\"tail\\\r\n", want: expectMalformed, rewritten: 1},
		{name: testObsFoldName, fields: "Expect: 100-continue\r\n value\r\n", want: expectMalformed, obsFold: true, rewritten: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			head := transportHeadFixture("POST /v1/process HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n" + test.fields + "\r\n")
			facts, normalized := prepareTransportHead(head)
			if facts.expect != test.want || facts.expectObsFold != test.obsFold {
				t.Fatalf("Expect facts = %d/%t, want %d/%t", facts.expect, facts.expectObsFold, test.want, test.obsFold)
			}
			if count := bytes.Count(normalized, []byte("X-Dk2E:")); count != test.rewritten {
				t.Fatalf("neutralized Expect count = %d, want %d", count, test.rewritten)
			}
			if bytes.Contains(bytes.ToLower(normalized), []byte("\r\nexpect:")) {
				t.Fatal("an active Expect field survived normalization")
			}
		})
	}
}

// TestPrepareTransportHeadClassifiesFraming proves the complete transfer-coding matrix.
func TestPrepareTransportHeadClassifiesFraming(t *testing.T) {
	tests := []struct {
		name       string
		fields     string
		want       framingClass
		conflict   bool
		normalized string
	}{
		{name: transportTestAbsent, want: framingAbsent},
		{name: "exact chunked", fields: testChunkedField, want: framingSingleChunked, normalized: testChunkedField},
		{name: "case chunked", fields: "TRANSFER-ENCODING: CHUNKED\r\n", want: framingSingleChunked, normalized: "TRANSFER-ENCODING: CHUNKED\r\n"},
		{name: "empty normalized chunked", fields: "Transfer-Encoding: , chunked,,\r\n", want: framingSingleChunked, normalized: "Transfer-Encoding:chunked     \r\n"},
		{name: "multiple normalized chunked", fields: "Transfer-Encoding: ,\r\nTransfer-Encoding: chunked,\r\n", want: framingSingleChunked, normalized: "X-DKIM2-Framing-X: ,\r\nTransfer-Encoding:chunked  \r\n"},
		{name: "unsupported final chunked", fields: testGzipThenChunkedField, want: framingUnsupportedFinalChunked},
		{name: "unsupported final parameters", fields: "Transfer-Encoding: gzip;level=\"1\", chunked\r\n", want: framingUnsupportedFinalChunked},
		{name: "transfer parameter bws", fields: "Transfer-Encoding: gzip ; level = \"1\" , chunked\r\n", want: framingUnsupportedFinalChunked},
		{name: "transfer parameter missing equals", fields: "Transfer-Encoding: gzip;level, chunked\r\n", want: framingBad},
		{name: "transfer parameter empty value", fields: "Transfer-Encoding: gzip;level=, chunked\r\n", want: framingBad},
		{name: "transfer parameter empty element", fields: "Transfer-Encoding: gzip;;level=1, chunked\r\n", want: framingBad},
		{name: "nonfinal chunked", fields: testChunkedThenGzipField, want: framingBad},
		{name: "unsupported without chunked", fields: testGzipField, want: framingBad},
		{name: "repeated chunked", fields: testRepeatedChunkedField, want: framingBad},
		{name: "parameterized chunked", fields: "Transfer-Encoding: chunked;x=1\r\n", want: framingBad},
		{name: testOnlyEmptyName, fields: "Transfer-Encoding: ,,\r\n", want: framingBad},
		{name: transportTestMalformed, fields: "Transfer-Encoding: gzip=\"unterminated\r\n", want: framingBad},
		{name: testObsFoldName, fields: "Transfer-Encoding: chunked\r\n value\r\n", want: framingBad},
		{name: "content length conflict", fields: testChunkedWithLengthFields, want: framingBad, conflict: true},
		{name: "different content lengths", fields: "Content-Length: 1\r\nContent-Length: 2\r\n", want: framingAbsent, conflict: true},
		{name: "equal content lengths", fields: "Content-Length: 01\r\nContent-Length: 01\r\n", want: framingAbsent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			head := transportHeadFixture("POST /v1/process HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n" + test.fields + "\r\n")
			facts, normalized := prepareTransportHead(head)
			if facts.framing != test.want || facts.contentLengthConflict != test.conflict {
				t.Fatalf("framing facts = %d/%t, want %d/%t", facts.framing, facts.contentLengthConflict, test.want, test.conflict)
			}
			if test.normalized != "" && !bytes.Contains(normalized, []byte(test.normalized)) {
				t.Fatalf("normalized head does not contain %q:\n%s", test.normalized, normalized)
			}
		})
	}
}

// TestPrepareTransportHeadSupportsLFAndMixedTermination proves Go-compatible lines cannot bypass facts.
func TestPrepareTransportHeadSupportsLFAndMixedTermination(t *testing.T) {
	tests := []struct {
		name string
		head string
		want string
	}{
		{
			name: "lf only",
			head: "POST /v1/process HTTP/1.1\nHost: 127.0.0.1:8080\n" +
				"Expect: 100-continue\nTransfer-Encoding: ,chunked,\n\n",
			want: "POST /v1/process HTTP/1.1\nHost: 127.0.0.1:8080\n" +
				"X-Dk2E: 100-continue\nTransfer-Encoding:chunked   \n\n",
		},
		{
			name: testMixedName,
			head: "POST /v1/process HTTP/1.1\r\nHost: 127.0.0.1:8080\n" +
				"Expect: 100-continue\r\nTransfer-Encoding: ,chunked,\n\r\n",
			want: "POST /v1/process HTTP/1.1\r\nHost: 127.0.0.1:8080\n" +
				"X-Dk2E: 100-continue\r\nTransfer-Encoding:chunked   \n\r\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			head := transportHeadFixture(test.head)
			facts, normalized := prepareTransportHead(head)
			if facts.expect != expectContinue || facts.framing != framingSingleChunked ||
				facts.protoMajor != 1 || facts.protoMinor != 1 || facts.hostCount != 1 {
				t.Fatalf("facts = %#v", facts)
			}
			if string(normalized) != test.want {
				t.Fatalf("normalized head = %q, want %q", normalized, test.want)
			}
		})
	}
}

// TestPrepareTransportHeadPublishesOnlyBoundedFacts proves request-line and Host metadata.
func TestPrepareTransportHeadPublishesOnlyBoundedFacts(t *testing.T) {
	head := transportHeadFixture("HEAD /healthz?" + strings.Repeat("x", transportRequestTargetLimit) +
		" HTTP/1.9\r\nHost: " + transportPrivateMarker + "\r\nHost: alternate\r\n\r\n")
	facts, normalized := prepareTransportHead(head)
	if !facts.exactHEAD || facts.protoMajor != 1 || facts.protoMinor != 9 ||
		facts.hostCount != 2 || facts.hostValue != transportPrivateMarker ||
		!facts.requestTargetOverLimit {
		t.Fatalf("unexpected transport facts: %#v", facts)
	}
	if !bytes.Equal(head, normalized) {
		t.Fatal("ordinary head bytes changed")
	}
}

// TestTransportFactsAndStateFormattingRemainContentFree proves private facts do not escape.
func TestTransportFactsAndStateFormattingRemainContentFree(t *testing.T) {
	facts := transportFacts{hostValue: transportPrivateMarker}
	state := newTransportState(func() (string, bool) {
		return transportPrivateMarker, true
	})
	state.publishFacts(facts)
	values := map[string]any{
		"facts":         facts,
		"facts-pointer": &facts,
		"state":         state,
		"nested":        struct{ Value any }{Value: state},
		"map":           map[string]any{"value": facts},
	}
	for name, value := range values {
		t.Run(name, func(t *testing.T) {
			for _, formatted := range []string{
				fmt.Sprint(value),
				fmt.Sprintf("%+v", value),
				fmt.Sprintf("%#v", value),
			} {
				if strings.Contains(formatted, transportPrivateMarker) {
					t.Fatal("formatting exposed a private transport value")
				}
			}
			if encoded, err := json.Marshal(value); err == nil || encoded != nil {
				t.Fatal("transport state unexpectedly marshaled")
			}
		})
	}
}

// TestTransportStateValidDateRequiresCanonicalIMFFixdate proves exact Date validation.
func TestTransportStateValidDateRequiresCanonicalIMFFixdate(t *testing.T) {
	tests := []struct {
		name  string
		value string
		ok    bool
		want  string
	}{
		{name: "epoch", value: transportTestEpoch, ok: true, want: transportTestEpoch},
		{name: "upper year", value: "Fri, 31 Dec 9999 23:59:59 GMT", ok: true, want: "Fri, 31 Dec 9999 23:59:59 GMT"},
		{name: "rfc850 rejected", value: "Thursday, 01-Jan-70 00:00:00 GMT", ok: true},
		{name: "wrong weekday rejected", value: "Fri, 01 Jan 1970 00:00:00 GMT", ok: true},
		{name: "utc spelling rejected", value: "Thu, 01 Jan 1970 00:00:00 UTC", ok: true},
		{name: testUnavailableName, value: transportTestEpoch},
		{name: transportTestEmpty, ok: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := newTransportState(func() (string, bool) { return test.value, test.ok })
			got, valid := state.ValidDate()
			if valid != (test.want != "") || got != test.want {
				t.Fatalf("ValidDate() = %q/%t, want %q/%t", got, valid, test.want, test.want != "")
			}
		})
	}
	t.Run("panic", func(t *testing.T) {
		state := newTransportState(func() (string, bool) { panic(transportPrivateMarker) })
		if value, ok := state.ValidDate(); ok || value != "" {
			t.Fatal("panicking Date provider escaped")
		}
	})
}

// TestTransportContextPublishesOnlyTheOwnedState proves unforgeable context transport.
func TestTransportContextPublishesOnlyTheOwnedState(t *testing.T) {
	state := newTransportState(nil)
	conn := &trackedConn{state: state}
	ctx := transportConnContext(context.Background(), conn)
	got, ok := transportStateFromContext(ctx)
	if !ok || got != state {
		t.Fatal("ConnContext did not publish the exact transport state")
	}
	if _, ok := transportStateFromContext(context.Background()); ok {
		t.Fatal("empty context forged transport state")
	}
	var nilContext context.Context
	if _, ok := transportStateFromContext(nilContext); ok {
		t.Fatal("nil context forged transport state")
	}
	state.MarkHandlerEntered()
	if !state.HandlerEntered() {
		t.Fatal("handler-entered fact was not monotonic")
	}
}

// TestTransportStateValidDateMatchesHTTPTimeFormat guards the standard dependency.
func TestTransportStateValidDateMatchesHTTPTimeFormat(t *testing.T) {
	value := time.Unix(1_800_000_000, 0).UTC().Format(http.TimeFormat)
	state := newTransportState(func() (string, bool) { return value, true })
	if got, ok := state.ValidDate(); !ok || got != value {
		t.Fatal("canonical IMF-fixdate was rejected")
	}
}

// TestInspectTransportHeadUsesConstantListAndHostStorage proves fixed-capture accounting.
func TestInspectTransportHeadUsesConstantListAndHostStorage(t *testing.T) {
	tests := []struct {
		name string
		head []byte
	}{
		{
			name: "maximum empty expect members",
			head: transportHeadFixture("POST /v1/process HTTP/1.1\r\nHost: local\r\nExpect: " +
				strings.Repeat(",", testRequestHeadLimit-80) + "\r\n\r\n"),
		},
		{
			name: "maximum transfer members",
			head: transportHeadFixture("POST /v1/process HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: " +
				strings.Repeat("gzip=x,", (testRequestHeadLimit-100)/7) + "chunked\r\n\r\n"),
		},
		{
			name: "maximum host",
			head: transportHeadFixture("GET /healthz HTTP/1.1\r\nHost: " +
				strings.Repeat("h", testRequestHeadLimit-45) + "\r\n\r\n"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if allocations := testing.AllocsPerRun(100, func() {
				view := inspectTransportHead(test.head)
				if view.facts.hostCount == -1 {
					t.Fatal("impossible facts")
				}
			}); allocations != 0 {
				t.Fatalf("inspectTransportHead allocations = %f, want zero", allocations)
			}
		})
	}
}

// TestPrepareTransportHeadClonesOnlyBoundedHostAndReleasesToxicCapture proves liveness.
func TestPrepareTransportHeadClonesOnlyBoundedHostAndReleasesToxicCapture(t *testing.T) {
	head := transportHeadFixture("POST /v1/process HTTP/1.1\r\nHost: " +
		transportPrivateMarker + "\r\nExpect: toxic-expect-value\r\n" +
		"X-DKIM2-Capability: toxic-capability-value\r\n\r\n")
	facts, normalized := prepareTransportHead(head)
	clear(normalized)
	if facts.hostValue != transportPrivateMarker || facts.hostCount != 1 {
		t.Fatal("bounded Host clone did not survive capture cleanup")
	}
	for _, formatted := range []string{
		fmt.Sprint(facts),
		fmt.Sprintf("%+v", facts),
		fmt.Sprintf("%#v", facts),
	} {
		if strings.Contains(formatted, "toxic-") ||
			strings.Contains(formatted, transportPrivateMarker) {
			t.Fatal("cleaned captured metadata escaped through facts")
		}
	}
	exactValue := strings.Repeat("h", testHostFactLimit)
	exactHead := transportHeadFixture(
		"GET /healthz HTTP/1.1\r\nHost: " + exactValue + "\r\n\r\n",
	)
	exactFacts, exactNormalized := prepareTransportHead(exactHead)
	clear(exactNormalized)
	if exactFacts.hostCount != 1 || exactFacts.hostValue != exactValue {
		t.Fatal("exact-limit Host was not retained independently of the capture")
	}
	exactState := newTransportState(nil)
	exactState.publishFacts(exactFacts)
	consumed, count, ok := exactState.ConsumeHost()
	if !ok || count != 1 || consumed != exactValue ||
		exactState.Facts().hostValue != "" {
		t.Fatal("exact-limit Host was not consumed and scrubbed exactly once")
	}
	overLimit := transportHeadFixture("GET /healthz HTTP/1.1\r\nHost: " +
		strings.Repeat("h", testHostFactLimit+1) + "\r\n\r\n")
	overFacts, _ := prepareTransportHead(overLimit)
	if overFacts.hostCount != 1 || overFacts.hostValue != "" {
		t.Fatal("over-limit Host was retained instead of becoming a mismatch sentinel")
	}
	overState := newTransportState(nil)
	overState.publishFacts(overFacts)
	consumed, count, ok = overState.ConsumeHost()
	if !ok || count != 1 || consumed != "" ||
		overState.Facts().hostValue != "" {
		t.Fatal("over-limit Host sentinel was not consumed without retained value")
	}
}

// TestTransportStateConsumesAndScrubsHostExactlyOnce proves the authority handoff lifetime.
func TestTransportStateConsumesAndScrubsHostExactlyOnce(t *testing.T) {
	state := newTransportState(nil)
	state.publishFacts(transportFacts{hostCount: 1, hostValue: transportPrivateMarker})
	value, count, ok := state.ConsumeHost()
	if !ok || value != transportPrivateMarker || count != 1 {
		t.Fatalf("ConsumeHost() = %q/%d/%t", value, count, ok)
	}
	if facts := state.Facts(); facts.hostValue != "" || facts.hostCount != 1 {
		t.Fatalf("facts after consume = %#v", facts)
	}
	if value, count, ok = state.ConsumeHost(); ok || value != "" || count != 0 {
		t.Fatalf("second ConsumeHost() = %q/%d/%t", value, count, ok)
	}
}

// TestPrepareTransportHeadNormalizesFramingWithoutGrowth proves the frozen wire rewrite.
func TestPrepareTransportHeadNormalizesFramingWithoutGrowth(t *testing.T) {
	tests := []struct {
		name   string
		fields string
		want   string
	}{
		{
			name:   "chunked first",
			fields: "Transfer-Encoding: ,chunked,\r\nTransfer-Encoding: ,\r\n",
			want:   "Transfer-Encoding:chunked   \r\nX-DKIM2-Framing-X: ,\r\n",
		},
		{
			name:   "chunked middle",
			fields: "Transfer-Encoding:\r\nTRANSFER-ENCODING: ,CHUNKED,\r\nTransfer-Encoding: ,\r\n",
			want:   "X-DKIM2-Framing-X:\r\nTransfer-Encoding:chunked   \r\nX-DKIM2-Framing-X: ,\r\n",
		},
		{
			name:   "chunked last LF",
			fields: "Transfer-Encoding:\nTransfer-Encoding: ,\nTRANSFER-ENCODING: ,ChUnKeD,\n",
			want:   "X-DKIM2-Framing-X:\nX-DKIM2-Framing-X: ,\nTransfer-Encoding:chunked   \n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prefix := "POST /v1/process HTTP/1.1\r\nHost: local\r\n"
			if strings.Contains(test.fields, "\n") && !strings.Contains(test.fields, "\r\n") {
				prefix = "POST /v1/process HTTP/1.1\nHost: local\n"
			}
			terminator := "\r\n"
			if strings.Contains(test.fields, "\n") && !strings.Contains(test.fields, "\r\n") {
				terminator = "\n"
			}
			body := "BODY-TAIL"
			input := []byte(prefix + test.fields + terminator + body)
			headEnd := len(input) - len(body)
			facts, normalized, normalizedEnd := prepareTransportHeadPrefix(input, headEnd)
			if facts.framing != framingSingleChunked {
				t.Fatalf("framing = %d", facts.framing)
			}
			if normalizedEnd != headEnd || len(normalized) != len(input) {
				t.Fatalf("normalization changed lengths: %d/%d and %d/%d", normalizedEnd, headEnd, len(normalized), len(input))
			}
			if got := string(normalized); got != prefix+test.want+terminator+body {
				t.Fatalf("normalized bytes = %q", got)
			}
		})
	}
}

// TestNormalizeSingleChunkedAllocatesNoStorage proves full-capture in-place rewriting.
func TestNormalizeSingleChunkedAllocatesNoStorage(t *testing.T) {
	head := []byte("POST /v1/process HTTP/1.1\r\nHost: local\r\n" +
		"Transfer-Encoding:\r\nTransfer-Encoding: ,chunked,\r\n\r\n")
	headEnd := len(head)
	original := make([]byte, testRequestHeadLimit)
	copy(original, head)
	for index := headEnd; index < len(original); index++ {
		original[index] = 'b'
	}
	view := inspectTransportHead(original[:headEnd])
	if view.facts.framing != framingSingleChunked ||
		view.chunkedFraming.lineStart == 0 {
		t.Fatal("fixture did not select a non-first semantic chunked occurrence")
	}
	working := make([]byte, len(original))
	allocations := testing.AllocsPerRun(100, func() {
		copy(working, original)
		normalized, normalizedEnd, ok := normalizeSingleChunked(
			working,
			headEnd,
			view.framingCount,
			view.chunkedFraming,
		)
		if !ok || normalizedEnd != headEnd || len(normalized) != len(original) {
			panic("normalization changed the fixed capture")
		}
	})
	if allocations != 0 {
		t.Fatalf("normalizeSingleChunked allocations = %f, want zero", allocations)
	}
	if !bytes.Equal(working[headEnd:], original[headEnd:]) {
		t.Fatal("normalization changed the coalesced body tail")
	}
}

// transportHeadFixture creates the production-sized shared capture backing.
func transportHeadFixture(value string) []byte {
	head := make([]byte, len(value), testRequestHeadLimit)
	copy(head, value)
	return head
}
