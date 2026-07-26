package httpjson

import (
	"bytes"
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	transportRequestHeadLimit     = 69_632
	transportServerMaxHeaderBytes = 65_536
	transportMethodInspectLimit   = 64
	transportRequestTargetLimit   = 8_192
	transportHostFactLimit        = 64
	transportPrehandlerTimeout    = 5 * time.Second
	transportRedacted             = "dkim2-http-transport"
	transportMarshalErrorText     = "dkim2 HTTP transport serialization is forbidden"
	transportControlErrorText     = "dkim2 HTTP transport control failed"
)

var errTransportControl = errors.New(transportControlErrorText)

type expectClass uint8

const (
	expectNone expectClass = iota
	expectContinue
	expectUnsupported
	expectMalformed
)

type framingClass uint8

const (
	framingAbsent framingClass = iota
	framingSingleChunked
	framingUnsupportedFinalChunked
	framingBad
)

type transportReadTerminalClass uint8

const (
	transportReadTerminalNone transportReadTerminalClass = iota
	transportReadTerminalEOF
	transportReadTerminalTimeout
	transportReadTerminalDisconnect
	transportReadTerminalOther
)

type transportFacts struct {
	exactHEAD              bool
	protoMajor             int
	protoMinor             int
	hostCount              int
	hostValue              string
	requestTargetOverLimit bool
	expect                 expectClass
	expectObsFold          bool
	framing                framingClass
	contentLengthPresent   bool
	contentLengthConflict  bool
}

// String returns a content-free transport-facts representation.
func (transportFacts) String() string { return transportRedacted }

// GoString returns a content-free Go-syntax transport-facts representation.
func (transportFacts) GoString() string { return transportRedacted }

// Format prevents formatting verbs from traversing captured Host metadata.
func (transportFacts) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, transportRedacted)
}

// MarshalJSON rejects serialization of private transport facts.
func (transportFacts) MarshalJSON() ([]byte, error) {
	return nil, errors.New(transportMarshalErrorText)
}

// MarshalText rejects diagnostic serialization of private transport facts.
func (transportFacts) MarshalText() ([]byte, error) {
	return nil, errors.New(transportMarshalErrorText)
}

type transportState struct {
	facts          atomic.Pointer[transportFacts]
	hostMu         sync.Mutex
	hostConsumed   bool
	handlerEntered atomic.Bool
	responseDone   atomic.Bool
	readTerminal   atomic.Uint32
	connection     atomic.Pointer[trackedConn]
	dateProvider   func() (string, bool)

	reservationMu sync.Mutex
	reservation   *processReservation
	transportDone bool
}

// newTransportState constructs one private per-connection transport authority.
func newTransportState(dateProvider func() (string, bool)) *transportState {
	return &transportState{dateProvider: dateProvider}
}

// publishFacts makes one immutable first-head classification visible.
func (s *transportState) publishFacts(facts transportFacts) {
	if s == nil {
		return
	}
	s.hostMu.Lock()
	defer s.hostMu.Unlock()
	snapshot := facts
	if s.hostConsumed {
		snapshot.hostValue = ""
	}
	s.facts.CompareAndSwap(nil, &snapshot)
}

// Facts returns one immutable copy of the captured first-head facts.
func (s *transportState) Facts() transportFacts {
	if s == nil {
		return transportFacts{}
	}
	s.hostMu.Lock()
	defer s.hostMu.Unlock()
	facts := s.facts.Load()
	if facts == nil {
		return transportFacts{}
	}
	return *facts
}

// ConsumeHost returns and scrubs the one owned Host fact exactly once.
func (s *transportState) ConsumeHost() (value string, count int, ok bool) {
	if s == nil {
		return "", 0, false
	}
	s.hostMu.Lock()
	defer s.hostMu.Unlock()
	if s.hostConsumed {
		return "", 0, false
	}
	facts := s.facts.Load()
	if facts == nil {
		return "", 0, false
	}
	s.hostConsumed = true
	snapshot := *facts
	value, count = snapshot.hostValue, snapshot.hostCount
	snapshot.hostValue = ""
	s.facts.Store(&snapshot)
	return value, count, true
}

// MarkHandlerEntered publishes that application-controlled response handling began.
func (s *transportState) MarkHandlerEntered() {
	if s != nil {
		s.handlerEntered.Store(true)
	}
}

// HandlerEntered reports whether the application handler crossed its response boundary.
func (s *transportState) HandlerEntered() bool {
	return s != nil && s.handlerEntered.Load()
}

// AdvanceReadDeadline narrows the exact tracked connection's read deadline.
func (s *transportState) AdvanceReadDeadline(deadline time.Time) error {
	connection := s.trackedConnection()
	if connection == nil {
		return errTransportControl
	}
	if err := connection.SetReadDeadline(deadline); err != nil {
		return errTransportControl
	}
	return nil
}

// PreparePrehandlerWrite applies the fixed raw-response write deadline.
func (s *transportState) PreparePrehandlerWrite() error {
	connection := s.trackedConnection()
	if connection == nil {
		return errTransportControl
	}
	if err := connection.SetWriteDeadline(time.Now().Add(transportPrehandlerTimeout)); err != nil {
		return errTransportControl
	}
	return nil
}

// Close terminates the exact tracked connection through its once-owned path.
func (s *transportState) Close() error {
	connection := s.trackedConnection()
	if connection == nil {
		return errTransportControl
	}
	return connection.Close()
}

// OwnProcessReservation transfers one admitted request to the exact tracked
// connection before any body or informational response work begins.
func (s *transportState) OwnProcessReservation(reservation *processReservation) bool {
	if s == nil || reservation == nil {
		return false
	}
	s.reservationMu.Lock()
	if s.reservation != nil {
		s.reservationMu.Unlock()
		return false
	}
	transportDone := s.transportDone
	if !transportDone {
		s.reservation = reservation
	}
	s.reservationMu.Unlock()
	if transportDone {
		reservation.TransportDone()
	}
	return true
}

// finishTransportOwnership records that response/socket ownership is terminal.
func (s *transportState) finishTransportOwnership() {
	if s == nil {
		return
	}
	s.reservationMu.Lock()
	s.transportDone = true
	reservation := s.reservation
	s.reservation = nil
	s.reservationMu.Unlock()
	if reservation != nil {
		reservation.TransportDone()
	}
}

// scrubPrivateFacts removes the only request-derived transport fact retained
// after the connection becomes terminal.
func (s *transportState) scrubPrivateFacts() {
	if s == nil {
		return
	}
	s.hostMu.Lock()
	defer s.hostMu.Unlock()
	s.hostConsumed = true
	facts := s.facts.Load()
	if facts == nil {
		return
	}
	snapshot := *facts
	snapshot.hostValue = ""
	s.facts.Store(&snapshot)
}

// ResponseTerminal reports the monotonic response-filter terminal state.
func (s *transportState) ResponseTerminal() bool {
	return s != nil && s.responseDone.Load()
}

// ReadTerminal returns the first content-free raw read terminal class.
func (s *transportState) ReadTerminal() transportReadTerminalClass {
	if s == nil {
		return transportReadTerminalNone
	}
	return transportReadTerminalClass(s.readTerminal.Load())
}

// publishReadTerminal records only the first terminal raw read classification.
func (s *transportState) publishReadTerminal(class transportReadTerminalClass) {
	if s == nil || class == transportReadTerminalNone {
		return
	}
	s.readTerminal.CompareAndSwap(
		uint32(transportReadTerminalNone),
		uint32(class),
	)
}

// markResponseTerminal publishes terminal response ownership for the filter.
func (s *transportState) markResponseTerminal() {
	if s != nil {
		s.responseDone.Store(true)
	}
}

// ValidDate returns only one canonical IMF-fixdate from the injected provider.
func (s *transportState) ValidDate() (value string, valid bool) {
	if s == nil || s.dateProvider == nil {
		return "", false
	}
	defer func() {
		if recover() != nil {
			value = ""
			valid = false
		}
	}()
	value, valid = s.dateProvider()
	if !valid || !validHTTPDate(value) {
		return "", false
	}
	return value, true
}

// validHTTPDate accepts only one canonical IMF-fixdate in the supported epoch.
func validHTTPDate(value string) bool {
	if value == "" {
		return false
	}
	parsed, err := http.ParseTime(value)
	if err != nil {
		return false
	}
	parsed = parsed.UTC()
	if parsed.Year() < 1970 || parsed.Year() > 9999 ||
		parsed.Nanosecond() != 0 || parsed.Format(http.TimeFormat) != value {
		return false
	}
	return true
}

// trackedConnection returns the exact connection authority without exposing it.
func (s *transportState) trackedConnection() *trackedConn {
	if s == nil {
		return nil
	}
	return s.connection.Load()
}

// String returns a content-free transport-state representation.
func (*transportState) String() string { return transportRedacted }

// GoString returns a content-free Go-syntax transport-state representation.
func (*transportState) GoString() string { return transportRedacted }

// Format prevents formatting verbs from traversing retained transport dependencies.
func (*transportState) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, transportRedacted)
}

// MarshalJSON rejects serialization of retained transport dependencies.
func (*transportState) MarshalJSON() ([]byte, error) {
	return nil, errors.New(transportMarshalErrorText)
}

// MarshalText rejects diagnostic serialization of retained transport dependencies.
func (*transportState) MarshalText() ([]byte, error) {
	return nil, errors.New(transportMarshalErrorText)
}

var (
	_ fmt.Stringer           = transportFacts{}
	_ fmt.GoStringer         = transportFacts{}
	_ json.Marshaler         = transportFacts{}
	_ encoding.TextMarshaler = transportFacts{}
	_ fmt.Stringer           = (*transportState)(nil)
	_ fmt.GoStringer         = (*transportState)(nil)
	_ json.Marshaler         = (*transportState)(nil)
	_ encoding.TextMarshaler = (*transportState)(nil)
)

type transportContextKey struct{}

// transportConnContext installs only state owned by an accepted tracked connection.
func transportConnContext(ctx context.Context, connection net.Conn) context.Context {
	if ctx == nil {
		return nil
	}
	tracked, ok := connection.(*trackedConn)
	if !ok || tracked == nil || tracked.state == nil {
		return ctx
	}
	return context.WithValue(ctx, transportContextKey{}, tracked.state)
}

// transportStateFromContext returns the private per-connection state when present.
func transportStateFromContext(ctx context.Context) (*transportState, bool) {
	if ctx == nil {
		return nil, false
	}
	state, ok := ctx.Value(transportContextKey{}).(*transportState)
	return state, ok && state != nil
}

type transportHeaderOccurrence struct {
	lineStart  int
	lineEnd    int
	nameStart  int
	nameEnd    int
	valueStart int
	valueEnd   int
}

type transportHeadView struct {
	facts           transportFacts
	expectCount     int
	framingCount    int
	chunkedFraming  transportHeaderOccurrence
	lengthCount     int
	firstLengthFrom int
	firstLengthTo   int
	hostFrom        int
	hostTo          int
	headerEnd       int
	parseValid      bool
}

// prepareTransportHead classifies and narrowly normalizes one complete first head.
func prepareTransportHead(head []byte) (transportFacts, []byte) {
	facts, normalized, _ := prepareTransportHeadPrefix(head, len(head))
	return facts, normalized
}

// prepareTransportHeadPrefix classifies a head prefix and preserves any captured body tail.
func prepareTransportHeadPrefix(
	captured []byte,
	headEnd int,
) (transportFacts, []byte, int) {
	if headEnd < 0 || headEnd > len(captured) {
		return transportFacts{}, captured, headEnd
	}
	view := inspectTransportHead(captured[:headEnd])
	rewriteTransportFieldNames(captured[:headEnd], []byte("Expect"), []byte("X-Dk2E"), 0)
	if view.facts.framing != framingSingleChunked ||
		transportFramingIsGoCompatible(captured, view.framingCount, view.chunkedFraming) {
		bindTransportHostValue(&view, captured, 0, 0)
		return view.facts, captured, headEnd
	}
	normalized, normalizedEnd, ok := normalizeSingleChunked(
		captured,
		headEnd,
		view.framingCount,
		view.chunkedFraming,
	)
	if !ok {
		view.facts.framing = framingBad
		bindTransportHostValue(&view, captured, 0, 0)
		return view.facts, captured, headEnd
	}
	bindTransportHostValue(&view, normalized, 0, 0)
	return view.facts, normalized, normalizedEnd
}

// inspectTransportHead performs one bounded request-line and field scan.
func inspectTransportHead(head []byte) transportHeadView {
	view := transportHeadView{
		facts: transportFacts{
			expect:  expectNone,
			framing: framingAbsent,
		},
		headerEnd: len(head),
	}
	_, lineEnd, next, complete := nextTransportLine(head, 0)
	if !complete {
		inspectTransportRequestLine(head, &view.facts)
		return view
	}
	inspectTransportRequestLine(head[:lineEnd], &view.facts)
	position := next
	var previousKind byte
	for position <= len(head) {
		lineStart, currentEnd, nextLine, lineComplete := nextTransportLine(head, position)
		if !lineComplete {
			break
		}
		if currentEnd == lineStart {
			view.parseValid = true
			view.headerEnd = nextLine
			break
		}
		line := head[lineStart:currentEnd]
		if line[0] == ' ' || line[0] == '\t' {
			switch previousKind {
			case 'e':
				view.facts.expectObsFold = true
				view.facts.expect = expectMalformed
			case 't':
				view.facts.framing = framingBad
			}
			position = nextLine
			continue
		}
		previousKind = 0
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			position = nextLine
			continue
		}
		name := line[:colon]
		valueStart := lineStart + colon + 1
		switch {
		case bytes.EqualFold(name, []byte("Host")):
			view.facts.hostCount++
			if view.facts.hostCount == 1 {
				view.hostFrom, view.hostTo = trimTransportOWSBounds(
					head,
					valueStart,
					currentEnd,
				)
			}
			previousKind = 'h'
		case bytes.EqualFold(name, []byte("Expect")):
			view.expectCount++
			previousKind = 'e'
		case bytes.EqualFold(name, []byte("Transfer-Encoding")):
			view.framingCount++
			previousKind = 't'
		case bytes.EqualFold(name, []byte("Content-Length")):
			view.lengthCount++
			view.facts.contentLengthPresent = true
			from, to := trimTransportOWSBounds(head, valueStart, currentEnd)
			if view.lengthCount == 1 {
				view.firstLengthFrom, view.firstLengthTo = from, to
			} else if !bytes.Equal(
				head[view.firstLengthFrom:view.firstLengthTo],
				head[from:to],
			) {
				view.facts.contentLengthConflict = true
			}
			previousKind = 'l'
		}
		position = nextLine
	}
	classifyTransportExpect(head, &view)
	classifyTransportFraming(head, &view)
	classifyTransportLengths(&view)
	return view
}

// inspectTransportRequestLine extracts only bounded immutable request-line facts.
func inspectTransportRequestLine(line []byte, facts *transportFacts) {
	firstSP := bytes.IndexByte(line, ' ')
	if firstSP < 0 {
		return
	}
	secondRelative := bytes.IndexByte(line[firstSP+1:], ' ')
	if secondRelative < 0 {
		return
	}
	secondSP := firstSP + 1 + secondRelative
	method := line[:firstSP]
	target := line[firstSP+1 : secondSP]
	version := line[secondSP+1:]
	facts.exactHEAD = bytes.Equal(method, []byte("HEAD"))
	facts.requestTargetOverLimit = len(target) > transportRequestTargetLimit
	facts.protoMajor, facts.protoMinor = parseTransportVersion(version)
}

// parseTransportVersion recognizes only one complete HTTP version token.
func parseTransportVersion(version []byte) (int, int) {
	if !bytes.HasPrefix(version, []byte("HTTP/")) {
		return 0, 0
	}
	version = version[len("HTTP/"):]
	dot := bytes.IndexByte(version, '.')
	if dot <= 0 || dot == len(version)-1 ||
		bytes.IndexByte(version[dot+1:], '.') >= 0 {
		return 0, 0
	}
	major, majorOK := parseTransportDecimal(version[:dot])
	minor, minorOK := parseTransportDecimal(version[dot+1:])
	if !majorOK || !minorOK {
		return 0, 0
	}
	return major, minor
}

// classifyTransportExpect reduces every field occurrence to one closed class.
func classifyTransportExpect(head []byte, view *transportHeadView) {
	if view.facts.expectObsFold {
		view.facts.expect = expectMalformed
		return
	}
	seenContinue := false
	seenUnsupported := false
	valid := walkTransportField(head, []byte("Expect"), func(occurrence transportHeaderOccurrence) bool {
		return walkTransportList(
			head[occurrence.valueStart:occurrence.valueEnd],
			func(item []byte) bool {
				name, parameterized, validItem := parseExpectationItem(item)
				if !validItem {
					return false
				}
				if len(name) == 0 {
					return true
				}
				if bytes.EqualFold(name, []byte("100-continue")) && !parameterized {
					seenContinue = true
				} else {
					seenUnsupported = true
				}
				return true
			})
	})
	if !valid {
		view.facts.expect = expectMalformed
		return
	}
	switch {
	case seenUnsupported:
		view.facts.expect = expectUnsupported
	case seenContinue:
		view.facts.expect = expectContinue
	default:
		view.facts.expect = expectNone
	}
}

// classifyTransportFraming reduces Transfer-Encoding to the four frozen classes.
func classifyTransportFraming(head []byte, view *transportHeadView) {
	if view.framingCount == 0 {
		view.facts.framing = framingAbsent
		return
	}
	if view.facts.framing == framingBad {
		return
	}
	codingCount := 0
	chunkedCount := 0
	lastChunked := false
	valid := walkTransportField(head, []byte("Transfer-Encoding"), func(occurrence transportHeaderOccurrence) bool {
		return walkTransportList(
			head[occurrence.valueStart:occurrence.valueEnd],
			func(item []byte) bool {
				name, parameterized, validItem := parseTransferCodingItem(item)
				if !validItem {
					return false
				}
				if len(name) != 0 {
					codingCount++
					lastChunked = bytes.EqualFold(name, []byte("chunked"))
					if lastChunked {
						chunkedCount++
						if parameterized {
							return false
						}
						view.chunkedFraming = occurrence
					}
				}
				return true
			})
	})
	if !valid {
		view.facts.framing = framingBad
		return
	}
	if codingCount == 0 {
		view.facts.framing = framingBad
		return
	}
	if chunkedCount != 1 {
		view.facts.framing = framingBad
		return
	}
	if !lastChunked {
		view.facts.framing = framingBad
		return
	}
	if codingCount == 1 {
		view.facts.framing = framingSingleChunked
		return
	}
	view.facts.framing = framingUnsupportedFinalChunked
}

// classifyTransportLengths records only ambiguity required by the outer gate.
func classifyTransportLengths(view *transportHeadView) {
	if view.framingCount > 0 && view.lengthCount > 0 {
		view.facts.contentLengthConflict = true
		view.facts.framing = framingBad
	}
}

// walkTransportList visits comma members without allocating per supplied member.
func walkTransportList(value []byte, visit func([]byte) bool) bool {
	start := 0
	quoted := false
	escaped := false
	for index, current := range value {
		if escaped {
			if !validQuotedPairOctet(current) {
				return false
			}
			escaped = false
			continue
		}
		if quoted {
			switch current {
			case '\\':
				escaped = true
			case '"':
				quoted = false
			case '\r', '\n':
				return false
			default:
				if !validQuotedTextOctet(current) {
					return false
				}
			}
			continue
		}
		switch current {
		case '"':
			quoted = true
		case ',':
			if !visit(bytes.Trim(value[start:index], " \t")) {
				return false
			}
			start = index + 1
		case '\r', '\n':
			return false
		}
	}
	if quoted || escaped {
		return false
	}
	return visit(bytes.Trim(value[start:], " \t"))
}

// parseExpectationItem validates the RFC expectation and parameter grammar.
func parseExpectationItem(item []byte) ([]byte, bool, bool) {
	if len(item) == 0 {
		return nil, false, true
	}
	position := consumeTransportToken(item, 0)
	if position == 0 {
		return nil, false, false
	}
	name := item[:position]
	parameterized := false
	hasExpectationValue := false
	if position < len(item) && item[position] == '=' {
		parameterized = true
		hasExpectationValue = true
		position++
		next, valid := consumeTransportValue(item, position)
		if !valid {
			return nil, false, false
		}
		position = next
	}
	for position < len(item) {
		position = skipTransportOWS(item, position)
		if position == len(item) {
			break
		}
		if !hasExpectationValue {
			return nil, false, false
		}
		if item[position] != ';' {
			return nil, false, false
		}
		parameterized = true
		position = skipTransportOWS(item, position+1)
		if position == len(item) || item[position] == ';' {
			continue
		}
		next := consumeTransportToken(item, position)
		if next == position {
			return nil, false, false
		}
		position = next
		if position >= len(item) || item[position] != '=' {
			return nil, false, false
		}
		position++
		next, valid := consumeTransportValue(item, position)
		if !valid {
			return nil, false, false
		}
		position = next
	}
	return name, parameterized, true
}

// parseTransferCodingItem validates one transfer-coding and mandatory parameters.
func parseTransferCodingItem(item []byte) ([]byte, bool, bool) {
	if len(item) == 0 {
		return nil, false, true
	}
	position := consumeTransportToken(item, 0)
	if position == 0 {
		return nil, false, false
	}
	name := item[:position]
	parameterized := false
	for position < len(item) {
		position = skipTransportOWS(item, position)
		if position == len(item) {
			break
		}
		if item[position] != ';' {
			return nil, false, false
		}
		parameterized = true
		position = skipTransportOWS(item, position+1)
		next := consumeTransportToken(item, position)
		if next == position {
			return nil, false, false
		}
		position = skipTransportOWS(item, next)
		if position >= len(item) || item[position] != '=' {
			return nil, false, false
		}
		position = skipTransportOWS(item, position+1)
		next, valid := consumeTransportValue(item, position)
		if !valid {
			return nil, false, false
		}
		position = next
	}
	return name, parameterized, true
}

// consumeTransportValue validates one token or quoted-string value.
func consumeTransportValue(value []byte, position int) (int, bool) {
	if position >= len(value) {
		return position, false
	}
	if value[position] != '"' {
		end := consumeTransportToken(value, position)
		return end, end > position
	}
	position++
	for position < len(value) {
		current := value[position]
		switch current {
		case '"':
			return position + 1, true
		case '\\':
			position++
			if position >= len(value) || !validQuotedPairOctet(value[position]) {
				return position, false
			}
		default:
			if !validQuotedTextOctet(current) {
				return position, false
			}
		}
		position++
	}
	return position, false
}

// consumeTransportToken returns the first byte outside RFC tchar.
func consumeTransportToken(value []byte, position int) int {
	for position < len(value) && isTransportTchar(value[position]) {
		position++
	}
	return position
}

// skipTransportOWS skips only RFC optional SP and HTAB.
func skipTransportOWS(value []byte, position int) int {
	for position < len(value) && (value[position] == ' ' || value[position] == '\t') {
		position++
	}
	return position
}

// isTransportTchar recognizes the RFC 9110 token alphabet.
func isTransportTchar(value byte) bool {
	if value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' ||
		value >= 'a' && value <= 'z' {
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", rune(value))
}

// validQuotedTextOctet recognizes qdtext without obs-fold interpretation.
func validQuotedTextOctet(value byte) bool {
	return value == '\t' || value == ' ' || value == '!' ||
		value >= '#' && value <= '[' || value >= ']' && value <= '~' ||
		value >= 0x80
}

// validQuotedPairOctet recognizes quoted-pair payload octets.
func validQuotedPairOctet(value byte) bool {
	return value == '\t' || value == ' ' || value >= '!' && value <= '~' || value >= 0x80
}

// transportFramingIsGoCompatible recognizes Go's one accepted field shape.
func transportFramingIsGoCompatible(
	head []byte,
	count int,
	first transportHeaderOccurrence,
) bool {
	if count != 1 {
		return false
	}
	value := bytes.Trim(head[first.valueStart:first.valueEnd], " \t")
	return bytes.EqualFold(value, []byte("chunked"))
}

// normalizeSingleChunked rewrites one accepted framing shape without changing its length.
func normalizeSingleChunked(
	captured []byte,
	headEnd int,
	count int,
	selected transportHeaderOccurrence,
) ([]byte, int, bool) {
	const canonical = "Transfer-Encoding:chunked"
	if count == 0 ||
		selected.lineStart < 0 ||
		selected.lineEnd > headEnd ||
		selected.lineEnd-selected.lineStart < len(canonical) {
		return captured, headEnd, false
	}
	if !rewriteTransportFramingNames(captured[:headEnd], selected) {
		return captured, headEnd, false
	}
	for index := selected.lineStart; index < selected.lineEnd; index++ {
		captured[index] = ' '
	}
	copy(captured[selected.lineStart:], canonical)
	return captured, headEnd, true
}

// rewriteTransportFramingNames makes every non-selected framing occurrence inert.
func rewriteTransportFramingNames(head []byte, selected transportHeaderOccurrence) bool {
	return walkTransportField(
		head,
		[]byte("Transfer-Encoding"),
		func(occurrence transportHeaderOccurrence) bool {
			if occurrence.lineStart != selected.lineStart {
				copy(head[occurrence.nameStart:occurrence.nameEnd], []byte("X-DKIM2-Framing-X"))
			}
			return true
		},
	)
}

// walkTransportField visits each exact field occurrence with constant parser state.
func walkTransportField(
	head []byte,
	name []byte,
	visit func(transportHeaderOccurrence) bool,
) bool {
	_, _, position, complete := nextTransportLine(head, 0)
	if !complete {
		return true
	}
	for position <= len(head) {
		lineStart, lineEnd, next, lineComplete := nextTransportLine(head, position)
		if !lineComplete || lineStart == lineEnd {
			return true
		}
		line := head[lineStart:lineEnd]
		if line[0] != ' ' && line[0] != '\t' {
			colon := bytes.IndexByte(line, ':')
			if colon > 0 && bytes.EqualFold(line[:colon], name) {
				if !visit(transportHeaderOccurrence{
					lineStart:  lineStart,
					lineEnd:    lineEnd,
					nameStart:  lineStart,
					nameEnd:    lineStart + colon,
					valueStart: lineStart + colon + 1,
					valueEnd:   lineEnd,
				}) {
					return false
				}
			}
		}
		position = next
	}
	return true
}

// rewriteTransportFieldNames performs a constant-space second-pass inert rewrite.
func rewriteTransportFieldNames(
	head []byte,
	name []byte,
	replacement []byte,
	skip int,
) bool {
	if len(name) != len(replacement) {
		return false
	}
	index := 0
	return walkTransportField(head, name, func(occurrence transportHeaderOccurrence) bool {
		if index >= skip {
			copy(head[occurrence.nameStart:occurrence.nameEnd], replacement)
		}
		index++
		return true
	})
}

// trimTransportOWSBounds returns a zero-copy SP/HTAB-trimmed span.
func trimTransportOWSBounds(value []byte, from, to int) (int, int) {
	for from < to && (value[from] == ' ' || value[from] == '\t') {
		from++
	}
	for to > from && (value[to-1] == ' ' || value[to-1] == '\t') {
		to--
	}
	return from, to
}

// bindTransportHostValue clones only a bounded authority sufficient for exact local matching.
func bindTransportHostValue(
	view *transportHeadView,
	captured []byte,
	delta int,
	shiftAfter int,
) {
	if view == nil || view.facts.hostCount == 0 {
		return
	}
	from, to := view.hostFrom, view.hostTo
	if shiftAfter > 0 && from >= shiftAfter {
		from += delta
		to += delta
	}
	if from < 0 || to < from || to > len(captured) || from == to {
		view.facts.hostValue = ""
		return
	}
	if to-from > transportHostFactLimit {
		view.facts.hostValue = ""
		return
	}
	view.facts.hostValue = string(captured[from:to])
}

// parseTransportDecimal parses one bounded nonnegative HTTP version component.
func parseTransportDecimal(value []byte) (int, bool) {
	const maximum = 1<<31 - 1
	result := 0
	for _, current := range value {
		if current < '0' || current > '9' {
			return 0, false
		}
		digit := int(current - '0')
		if result > (maximum-digit)/10 {
			return 0, false
		}
		result = result*10 + digit
	}
	return result, len(value) > 0
}

// nextTransportLine returns one Go-compatible LF-terminated line and strips one CR.
func nextTransportLine(value []byte, start int) (int, int, int, bool) {
	if start < 0 || start > len(value) {
		return start, start, start, false
	}
	relativeLF := bytes.IndexByte(value[start:], '\n')
	if relativeLF < 0 {
		return start, len(value), len(value), false
	}
	lf := start + relativeLF
	end := lf
	if end > start && value[end-1] == '\r' {
		end--
	}
	return start, end, lf + 1, true
}
