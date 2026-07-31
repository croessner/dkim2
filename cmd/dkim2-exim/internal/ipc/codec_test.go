package ipc

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

type trapReader struct {
	data     *bytes.Reader
	maximum  int
	consumed int
}

// allowFixtureBuild admits only test-controlled build IDs at this package boundary.
func allowFixtureBuild(value []byte) bool { return len(value) == BuildIDBytes }

// Read rejects any byte consumed beyond the configured compatibility prefix.
func (r *trapReader) Read(output []byte) (int, error) {
	if r.consumed >= r.maximum {
		return 0, errors.New("mail data read before build admission")
	}
	if len(output) > r.maximum-r.consumed {
		output = output[:r.maximum-r.consumed]
	}
	count, err := r.data.Read(output)
	r.consumed += count
	return count, err
}

// validRequestFixture returns one minimal independently assembled request model.
func validRequestFixture() Request {
	return Request{
		buildID:          []byte(strings.Repeat("a", BuildIDBytes)),
		source:           SourceLocalScanObserved,
		session:          SessionSMTP,
		peer:             []byte("192.0.2.1"),
		peerPort:         25,
		helo:             []byte("mail.example"),
		receivedProtocol: []byte("esmtp"),
		mailFrom:         []byte("<sender@example>"),
		recipients:       [][]byte{[]byte("<recipient@example>")},
		headers:          [][]byte{[]byte("Subject: fixture\n")},
		body:             []byte("body\n"),
	}
}

// maximumRequestFixture returns a request at every aggregate wire maximum.
func maximumRequestFixture() Request {
	headers := make([][]byte, MaxHeaders)
	remaining := MaxHeaderAggregateBytes
	for index := range headers {
		length := remaining / (len(headers) - index)
		headers[index] = bytes.Repeat([]byte{'h'}, length)
		headers[index][length-1] = '\n'
		remaining -= length
	}
	recipients := make([][]byte, MaxRecipients)
	for index := range recipients {
		recipients[index] = bytes.Repeat([]byte{'r'}, MaxEnvelopeBytes)
	}
	return Request{
		buildID:          bytes.Repeat([]byte{'a'}, BuildIDBytes),
		source:           SourceLocalScanObserved,
		session:          SessionSMTP,
		peer:             bytes.Repeat([]byte{'p'}, MaxPeerBytes),
		peerPort:         65_535,
		helo:             bytes.Repeat([]byte{'h'}, MaxHELOBytes),
		receivedProtocol: bytes.Repeat([]byte{'s'}, MaxReceivedProtocolBytes),
		mailFrom:         bytes.Repeat([]byte{'m'}, MaxEnvelopeBytes),
		recipients:       recipients,
		headers:          headers,
		body: bytes.Repeat(
			[]byte{0}, MaxMessageBytes-MaxHeaderAggregateBytes-1,
		),
	}
}

// handBuiltRequestFrame assembles a fixture without using the production encoder.
func handBuiltRequestFrame(request Request) []byte {
	payload := &bytes.Buffer{}
	_ = binary.Write(payload, binary.BigEndian, uint16(len(request.buildID)))
	payload.WriteByte(byte(request.source))
	payload.WriteByte(byte(request.session))
	_ = binary.Write(payload, binary.BigEndian, uint16(len(request.recipients)))
	_ = binary.Write(payload, binary.BigEndian, uint16(len(request.headers)))
	_ = binary.Write(payload, binary.BigEndian, uint16(len(request.peer)))
	_ = binary.Write(payload, binary.BigEndian, request.peerPort)
	_ = binary.Write(payload, binary.BigEndian, uint16(len(request.helo)))
	_ = binary.Write(payload, binary.BigEndian, uint16(len(request.receivedProtocol)))
	_ = binary.Write(payload, binary.BigEndian, uint16(len(request.mailFrom)))
	payload.Write(request.buildID)
	payload.Write(request.peer)
	payload.Write(request.helo)
	payload.Write(request.receivedProtocol)
	payload.Write(request.mailFrom)
	for _, recipient := range request.recipients {
		_ = binary.Write(payload, binary.BigEndian, uint16(len(recipient)))
		payload.Write(recipient)
	}
	for _, header := range request.headers {
		_ = binary.Write(payload, binary.BigEndian, uint32(len(header)))
		payload.Write(header)
	}
	_ = binary.Write(payload, binary.BigEndian, uint32(len(request.body)))
	payload.Write(request.body)

	output := make([]byte, FrameHeaderBytes+payload.Len())
	copy(output, "DXI1")
	output[4] = Version
	output[5] = RequestKind
	binary.BigEndian.PutUint32(output[8:12], uint32(payload.Len()))
	copy(output[FrameHeaderBytes:], payload.Bytes())
	return output
}

// TestRequestMatchesIndependentWireOracle proves the canonical byte layout.
func TestRequestMatchesIndependentWireOracle(t *testing.T) {
	request := validRequestFixture()
	expected := handBuiltRequestFrame(request)
	actual, err := EncodeRequest(request)
	if err != nil {
		t.Fatal("valid request failed")
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("request encoder drifted from independent wire oracle")
	}
	decoded, err := DecodeRequest(expected, allowFixtureBuild)
	if err != nil {
		t.Fatal("independently assembled request failed")
	}
	if !bytes.Equal(decoded.body, request.body) ||
		!bytes.Equal(decoded.headers[0], request.headers[0]) {
		t.Fatal("independent wire oracle decoded incorrectly")
	}
}

// TestRequestRoundTripAndAliasing proves canonical framing and immutable copies.
func TestRequestRoundTripAndAliasing(t *testing.T) {
	request := validRequestFixture()
	frame, err := EncodeRequest(request)
	if err != nil {
		t.Fatal("valid request failed")
	}
	decoded, err := DecodeRequest(frame, allowFixtureBuild)
	if err != nil {
		t.Fatal("canonical request failed")
	}
	frame[len(frame)-1] ^= 1
	request.body[0] ^= 1
	if string(decoded.body) != "body\n" {
		t.Fatal("decoded request aliases caller storage")
	}
}

// TestRequestStreamingRejectsBuildBeforeMailRead proves early compatibility admission.
func TestRequestStreamingRejectsBuildBeforeMailRead(t *testing.T) {
	frame, err := EncodeRequest(validRequestFixture())
	if err != nil {
		t.Fatal("fixture encoding failed")
	}
	reader := &trapReader{
		data: bytes.NewReader(frame), maximum: FrameHeaderBytes + 18 + BuildIDBytes,
	}
	if _, err = DecodeRequestStream(reader, func([]byte) bool { return false }); err == nil {
		t.Fatal("disallowed build accepted")
	}
	if reader.consumed != reader.maximum {
		t.Fatal("stream decoder read mail bytes before build admission")
	}
}

// TestRequestStreamingRequiresEOFAfterDeclaredFrame proves a stream cannot
// carry a second frame or hidden trailing mail after an otherwise valid request.
func TestRequestStreamingRequiresEOFAfterDeclaredFrame(t *testing.T) {
	frame, err := EncodeRequest(validRequestFixture())
	if err != nil {
		t.Fatal("fixture encoding failed")
	}
	frame = append(frame, 'x')
	if _, decodeErr := DecodeRequestStream(bytes.NewReader(frame), func([]byte) bool { return true }); decodeErr == nil {
		t.Fatal("trailing stream byte accepted")
	}
}

// TestRequestRejectsDeclaredBodyBeyondRemainingFrame proves a malicious body
// length cannot cause allocation before the bounded frame has enough bytes.
func TestRequestRejectsDeclaredBodyBeyondRemainingFrame(t *testing.T) {
	request := validRequestFixture()
	frame, err := EncodeRequest(request)
	if err != nil {
		t.Fatal("fixture encoding failed")
	}
	bodyLengthOffset := len(frame) - len(request.body) - 4
	binary.BigEndian.PutUint32(frame[bodyLengthOffset:bodyLengthOffset+4], MaxMessageBytes)
	if _, decodeErr := DecodeRequest(frame, allowFixtureBuild); decodeErr == nil {
		t.Fatal("body length beyond declared frame accepted")
	}
}

// TestRequestRejectsHeaderAggregateBeforeNextAllocation proves the decoder
// stops after the length that crosses the aggregate cap, before value bytes.
func TestRequestRejectsHeaderAggregateBeforeNextAllocation(t *testing.T) {
	request := validRequestFixture()
	request.headers = make([][]byte, 17)
	for index := range request.headers {
		request.headers[index] = bytes.Repeat([]byte{'h'}, MaxHeaderFieldBytes)
	}
	frame := handBuiltRequestFrame(request)
	nextValueOffset := FrameHeaderBytes + 18 + BuildIDBytes +
		len(request.peer) + len(request.helo) + len(request.receivedProtocol) +
		len(request.mailFrom)
	for _, recipient := range request.recipients {
		nextValueOffset += 2 + len(recipient)
	}
	nextValueOffset += 16*(4+MaxHeaderFieldBytes) + 4
	reader := &trapReader{
		data: bytes.NewReader(frame), maximum: nextValueOffset + 1,
	}
	if _, err := DecodeRequestStream(reader, func([]byte) bool { return true }); err == nil {
		t.Fatal("header aggregate above the cap accepted")
	}
	if reader.consumed != nextValueOffset {
		t.Fatal("decoder read header bytes after aggregate limit became known")
	}
}

// TestRequestRejectsCombinedHeaderBodyLimitBeforeBodyRead proves the
// reconstructed-message bound is enforced before body allocation or reading.
func TestRequestRejectsCombinedHeaderBodyLimitBeforeBodyRead(t *testing.T) {
	request := validRequestFixture()
	request.headers = make([][]byte, 16)
	for index := range request.headers {
		request.headers[index] = bytes.Repeat([]byte{'h'}, MaxHeaderFieldBytes)
		request.headers[index][MaxHeaderFieldBytes-1] = '\n'
	}
	request.body = make([]byte, MaxMessageBytes-MaxHeaderAggregateBytes)
	frame := handBuiltRequestFrame(request)
	bodyOffset := FrameHeaderBytes + 18 + BuildIDBytes +
		len(request.peer) + len(request.helo) + len(request.receivedProtocol) +
		len(request.mailFrom)
	for _, recipient := range request.recipients {
		bodyOffset += 2 + len(recipient)
	}
	for _, header := range request.headers {
		bodyOffset += 4 + len(header)
	}
	bodyOffset += 4
	reader := &trapReader{data: bytes.NewReader(frame), maximum: bodyOffset}
	if _, err := DecodeRequestStream(reader, allowFixtureBuild); err == nil {
		t.Fatal("combined header and body limit accepted")
	}
	if reader.consumed != bodyOffset {
		t.Fatal("decoder read body bytes after combined limit became known")
	}
}

// TestRequestRejectsFrameAndSemanticDrift proves closed versioned decoding.
func TestRequestRejectsFrameAndSemanticDrift(t *testing.T) {
	request := validRequestFixture()
	frame, err := EncodeRequest(request)
	if err != nil {
		t.Fatal("fixture encoding failed")
	}
	cases := [][]byte{
		frame[:len(frame)-1],
		append(append([]byte(nil), frame...), 0),
		append([]byte("BAD!"), frame[4:]...),
	}
	version := append([]byte(nil), frame...)
	version[4] = 2
	cases = append(cases, version)
	reserved := append([]byte(nil), frame...)
	reserved[6] = 1
	cases = append(cases, reserved)
	oversized := make([]byte, FrameHeaderBytes)
	copy(oversized, "DXI1")
	oversized[4], oversized[5] = Version, RequestKind
	binary.BigEndian.PutUint32(oversized[8:], RequestPayloadBytes+1)
	cases = append(cases, oversized)
	for index, input := range cases {
		if _, decodeErr := DecodeRequest(input, allowFixtureBuild); decodeErr == nil {
			t.Fatalf("invalid frame class %d accepted", index)
		}
	}
}

// TestRequestExactSemanticLimit proves exact success and one-over rejection.
func TestRequestExactSemanticLimit(t *testing.T) {
	request := maximumRequestFixture()
	frame, err := EncodeRequest(request)
	if err != nil {
		t.Fatal("exact request payload and semantic limits failed")
	}
	if len(frame) != RequestFrameBytes ||
		binary.BigEndian.Uint32(frame[8:12]) != RequestPayloadBytes {
		t.Fatal("exact request frame cap oracle mismatch")
	}
	first := request.headers[0]
	request.headers[0] = make([]byte, len(first)+1)
	copy(request.headers[0], first)
	request.headers[0][len(first)-1] = 'h'
	request.headers[0][len(request.headers[0])-1] = '\n'
	if _, err := EncodeRequest(request); err == nil {
		t.Fatal("one-over reconstructed message limit accepted")
	}
	if _, err := framePayloadForTest(RequestKind, RequestPayloadBytes+1); err == nil {
		t.Fatal("one-over request payload accepted")
	}
}

// TestResponseAdmissionMatrix proves decision/reason/action coherence.
func TestResponseAdmissionMatrix(t *testing.T) {
	valid := []Response{
		{decision: DecisionAccept, reason: ReasonNone},
		{
			decision: DecisionAccept, reason: ReasonNone,
			removals: []uint16{3, 1}, addName: AddAuthenticationResults,
			addValue: []byte("mx.example; dkim2=pass"),
		},
		{decision: DecisionReject, reason: ReasonPolicyReject},
		{decision: DecisionTempfail, reason: ReasonTimeout},
	}
	for index, response := range valid {
		frame, err := EncodeResponse(response, []uint16{1, 3}, 3)
		if err != nil {
			t.Fatalf("valid response class %d failed", index)
		}
		if _, err = DecodeResponse(frame, []uint16{1, 3}, 3); err != nil {
			t.Fatalf("canonical response class %d failed", index)
		}
	}
	invalid := []Response{
		{decision: DecisionAccept, reason: ReasonTimeout},
		{decision: DecisionReject, reason: ReasonNone},
		{decision: DecisionTempfail, reason: ReasonPolicyReject},
		{decision: DecisionReject, reason: ReasonPolicyReject, locator: bytes.Repeat([]byte{'a'}, 32)},
		{decision: DecisionAccept, reason: ReasonNone, removals: []uint16{1, 2}},
		{decision: DecisionAccept, reason: ReasonNone, removals: []uint16{1, 1}},
		{decision: DecisionAccept, reason: ReasonNone, addName: AddAuthenticationResults},
	}
	for index, response := range invalid {
		if err := ValidateResponse(response, []uint16{1, 3}, 3); err == nil {
			t.Fatalf("invalid response class %d accepted", index)
		}
	}
}

// TestResponseRequiresExactEligibleSetAndCanonicalLocator proves closed mutation evidence.
func TestResponseRequiresExactEligibleSetAndCanonicalLocator(t *testing.T) {
	locator := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x7a}, 24))
	response := Response{
		decision: DecisionAccept,
		reason:   ReasonNone,
		removals: []uint16{3, 1},
		locator:  []byte(locator),
	}
	if err := ValidateResponse(response, []uint16{1, 3}, 4); err != nil {
		t.Fatal("exact eligible removal and locator failed")
	}
	response.removals = []uint16{2}
	if err := ValidateResponse(response, []uint16{1, 3}, 4); err == nil {
		t.Fatal("ineligible removal occurrence accepted")
	}
	response.removals = nil
	for _, invalid := range []string{
		locator + "=", strings.Repeat("+", 32), strings.Repeat("/", 32),
		strings.Repeat("A", 31) + "!",
	} {
		response.locator = []byte(invalid)
		if err := ValidateResponse(response, []uint16{1, 3}, 4); err == nil {
			t.Fatal("noncanonical evidence locator accepted")
		}
	}
}

// TestResponseExactFrameLimit proves the response cap formula independently.
func TestResponseExactFrameLimit(t *testing.T) {
	eligible := make([]uint16, MaxHeaders)
	removals := make([]uint16, MaxHeaders)
	for index := range eligible {
		eligible[index] = uint16(index + 1)
		removals[index] = uint16(MaxHeaders - index)
	}
	response := Response{
		decision: DecisionAccept,
		reason:   ReasonNone,
		removals: removals,
		addName:  AddAuthenticationResults,
		addValue: bytes.Repeat([]byte{'a'}, MaxAddValueBytes),
		locator: []byte(
			base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 24)),
		),
	}
	frame, err := EncodeResponse(response, eligible, MaxHeaders)
	if err != nil {
		t.Fatal("exact response payload limit failed")
	}
	if len(frame) != ResponseFrameBytes ||
		binary.BigEndian.Uint32(frame[8:12]) != ResponsePayloadBytes {
		t.Fatal("exact response frame cap oracle mismatch")
	}
}

// TestRequestGrammarSeparatesHeadersScalarsAndBody proves binary-safe boundaries.
func TestRequestGrammarSeparatesHeadersScalarsAndBody(t *testing.T) {
	request := validRequestFixture()
	request.body = []byte{0, '\r', '\n'}
	if _, err := EncodeRequest(request); err != nil {
		t.Fatal("binary-safe body failed")
	}
	for _, scalar := range [][]byte{[]byte("bad\n"), []byte("bad\r"), []byte{'b', 0}} {
		mutated := request
		mutated.mailFrom = scalar
		if _, err := EncodeRequest(mutated); err == nil {
			t.Fatal("illegal scalar accepted")
		}
	}
	for _, header := range [][]byte{
		[]byte("X: bad\r\n"), []byte{'X', ':', 0, '\n'},
		[]byte("X: first\nY: second\n"), []byte("X: missing"),
	} {
		mutated := request
		mutated.headers = [][]byte{header}
		if _, err := EncodeRequest(mutated); err == nil {
			t.Fatal("illegal observed header accepted")
		}
	}
}

// TestWireErrorsRedactRejectedInput proves toxic bytes never enter diagnostics.
func TestWireErrorsRedactRejectedInput(t *testing.T) {
	marker := "toxic-private-marker"
	_, err := DecodeRequest([]byte(marker), allowFixtureBuild)
	if err == nil || strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), marker) {
		t.Fatal("wire error exposed rejected input")
	}
	var typed *WireError
	if !errors.As(err, &typed) {
		t.Fatal("wire failure is not typed")
	}
}

// TestWireFailureClassesAreClosed proves external classification without input.
func TestWireFailureClassesAreClosed(t *testing.T) {
	resourceRequest := validRequestFixture()
	resourceRequest.body = make([]byte, MaxMessageBytes+1)
	invalidRequest := validRequestFixture()
	invalidRequest.buildID = []byte("invalid")
	cases := []struct {
		err   error
		class FailureClass
	}{
		{func() error {
			_, err := DecodeRequest([]byte("bad"), allowFixtureBuild)
			return err
		}(), FailureInvalidFrame},
		{func() error {
			_, err := NewRequest(
				resourceRequest.buildID, resourceRequest.source, resourceRequest.session,
				resourceRequest.peer, resourceRequest.peerPort, resourceRequest.helo,
				resourceRequest.receivedProtocol, resourceRequest.mailFrom,
				resourceRequest.recipients, resourceRequest.headers, resourceRequest.body,
			)
			return err
		}(), FailureResourceLimit},
		{func() error {
			_, err := NewRequest(
				invalidRequest.buildID, invalidRequest.source, invalidRequest.session,
				invalidRequest.peer, invalidRequest.peerPort, invalidRequest.helo,
				invalidRequest.receivedProtocol, invalidRequest.mailFrom,
				invalidRequest.recipients, invalidRequest.headers, invalidRequest.body,
			)
			return err
		}(), FailureInvalidRequest},
		{ValidateResponse(
			Response{decision: DecisionAccept, reason: ReasonTimeout}, nil, 0,
		), FailureInvalidResponse},
	}
	for index, current := range cases {
		var typed *WireError
		if !errors.As(current.err, &typed) || typed.Class() != current.class {
			t.Fatalf("failure class %d was not externally classifiable", index)
		}
	}
	var zero *WireError
	if zero.Class() != FailureUnknown {
		t.Fatal("nil wire error has a nonzero class")
	}
}

// TestStreamingVectorLimitsUseResourceClass proves wire and constructor cap
// rejections keep one stable class for the service decision mapper.
func TestStreamingVectorLimitsUseResourceClass(t *testing.T) {
	request := validRequestFixture()
	request.headers = [][]byte{bytes.Repeat([]byte{'h'}, MaxHeaderFieldBytes+1)}
	request.headers[0][MaxHeaderFieldBytes] = '\n'
	_, err := DecodeRequest(handBuiltRequestFrame(request), allowFixtureBuild)
	var typed *WireError
	if !errors.As(err, &typed) || typed.Class() != FailureResourceLimit {
		t.Fatal("oversized streamed header did not retain the resource class")
	}
}

// TestConstructorsValidateBeforeCopying proves rejected borrowed input does not
// trigger a mail-sized copy or an unbounded eligibility map.
func TestConstructorsValidateBeforeCopying(t *testing.T) {
	request := validRequestFixture()
	request.body = make([]byte, MaxMessageBytes+1)
	requestResult := testing.Benchmark(func(b *testing.B) {
		for b.Loop() {
			_, _ = NewRequest(
				request.buildID, request.source, request.session,
				request.peer, request.peerPort, request.helo,
				request.receivedProtocol, request.mailFrom,
				request.recipients, request.headers, request.body,
			)
		}
	})
	if requestResult.AllocedBytesPerOp() > 4_096 {
		t.Fatal("invalid request was copied before validation")
	}

	eligible := make([]uint16, MaxHeaders+1)
	responseResult := testing.Benchmark(func(b *testing.B) {
		for b.Loop() {
			_, _ = NewResponse(
				DecisionAccept, ReasonNone, nil, AddNone, nil, nil,
				eligible, MaxHeaders,
			)
		}
	})
	if responseResult.AllocedBytesPerOp() > 4_096 {
		t.Fatal("unbounded eligibility map was allocated before validation")
	}
}

// TestFailedOwnedAdmissionZeroizesEvidence proves decoder-owned temporary data
// is erased before an invalid request or response is discarded.
func TestFailedOwnedAdmissionZeroizesEvidence(t *testing.T) {
	request := validRequestFixture()
	requestBacking := [][]byte{
		request.buildID, request.peer, request.helo, request.receivedProtocol,
		request.mailFrom, request.recipients[0], request.headers[0], request.body,
	}
	request.buildID[0] = 'z'
	if _, err := admitOwnedRequest(request); err == nil {
		t.Fatal("invalid owned request admitted")
	}
	for _, value := range requestBacking {
		if !allZero(value) {
			t.Fatal("failed request admission retained evidence")
		}
	}

	response := Response{
		decision: DecisionReject,
		reason:   ReasonPolicyReject,
		removals: []uint16{1},
		addName:  AddAuthenticationResults,
		addValue: []byte("toxic-action"),
		locator:  bytes.Repeat([]byte{'a'}, EvidenceLocatorBytes),
	}
	removals := response.removals
	addValue := response.addValue
	locator := response.locator
	if _, err := admitOwnedResponse(response, []uint16{1}, 1); err == nil {
		t.Fatal("invalid owned response admitted")
	}
	if removals[0] != 0 || !allZero(addValue) || !allZero(locator) {
		t.Fatal("failed response admission retained evidence")
	}
}

// TestWireTypesRejectAllDiagnosticSerialization proves formatting, JSON, and
// text paths cannot reveal protected data, including zero values.
func TestWireTypesRejectAllDiagnosticSerialization(t *testing.T) {
	marker := "toxic-private-marker"
	request := validRequestFixture()
	request.body = []byte(marker)
	response := Response{
		decision: DecisionAccept,
		reason:   ReasonNone,
		addName:  AddAuthenticationResults,
		addValue: []byte(marker),
	}
	for _, value := range []any{request, response, Request{}, Response{}} {
		rendered := fmt.Sprintf("%v|%+v|%#v|%s|%q", value, value, value, value, value)
		if strings.Contains(rendered, marker) {
			t.Fatal("formatting exposed protected wire data")
		}
		if encoded, err := json.Marshal(value); err == nil || len(encoded) != 0 ||
			strings.Contains(fmt.Sprint(err), marker) {
			t.Fatal("JSON serialization did not fail closed")
		}
		textValue, ok := value.(interface{ MarshalText() ([]byte, error) })
		if !ok {
			t.Fatal("wire type does not implement text marshaling guard")
		}
		if encoded, err := textValue.MarshalText(); err == nil || len(encoded) != 0 ||
			strings.Contains(fmt.Sprint(err), marker) {
			t.Fatal("text serialization did not fail closed")
		}
	}
	wire := wireError(errInvalidRequest)
	rendered := fmt.Sprintf("%v|%+v|%#v|%s|%q", wire, wire, wire, wire, wire)
	if strings.Contains(rendered, marker) {
		t.Fatal("wire error formatting exposed protected data")
	}
	for _, value := range []any{wire, WireError{}} {
		if encoded, err := json.Marshal(value); err == nil || len(encoded) != 0 {
			t.Fatal("wire error JSON serialization did not fail closed")
		}
		textValue, ok := value.(interface{ MarshalText() ([]byte, error) })
		if !ok {
			t.Fatal("wire error does not implement text marshaling guard")
		}
		if encoded, err := textValue.MarshalText(); err == nil || len(encoded) != 0 {
			t.Fatal("wire error text serialization did not fail closed")
		}
	}
}

// framePayloadForTest delegates only cap admission to the production framer.
func framePayloadForTest(kind uint8, length int) ([]byte, error) {
	return frame(kind, make([]byte, length))
}

// allZero reports whether an owned byte buffer was erased.
func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

// FuzzRequestCodec exercises bounded request framing.
func FuzzRequestCodec(f *testing.F) {
	seed, err := EncodeRequest(validRequestFixture())
	if err != nil {
		f.Fatal("seed encoding failed")
	}
	f.Add(seed)
	f.Add([]byte("DXI1"))
	f.Fuzz(func(t *testing.T, data []byte) {
		request, decodeErr := DecodeRequest(data, allowFixtureBuild)
		if decodeErr != nil {
			return
		}
		frame, encodeErr := EncodeRequest(request)
		if encodeErr != nil {
			t.Fatal("decoded request failed re-encoding")
		}
		if !bytes.Equal(frame, data) {
			t.Fatal("request encoding is noncanonical")
		}
	})
}

// FuzzResponseCodec exercises bounded response framing and admission.
func FuzzResponseCodec(f *testing.F) {
	seed, err := EncodeResponse(
		Response{decision: DecisionAccept, reason: ReasonNone}, []uint16{1, 2, 3, 4}, 4,
	)
	if err != nil {
		f.Fatal("seed encoding failed")
	}
	f.Add(seed, uint16(4))
	f.Add([]byte("DXI1"), uint16(0))
	f.Fuzz(func(t *testing.T, data []byte, eligible uint16) {
		if eligible > MaxHeaders {
			eligible = MaxHeaders
		}
		eligibleValues := make([]uint16, eligible)
		for index := range eligibleValues {
			eligibleValues[index] = uint16(index + 1)
		}
		response, decodeErr := DecodeResponse(data, eligibleValues, eligible)
		if decodeErr != nil {
			return
		}
		frame, encodeErr := EncodeResponse(response, eligibleValues, eligible)
		if encodeErr != nil {
			t.Fatal("decoded response failed re-encoding")
		}
		if !bytes.Equal(frame, data) {
			t.Fatal("response encoding is noncanonical")
		}
	})
}

var _ io.Reader = (*trapReader)(nil)
