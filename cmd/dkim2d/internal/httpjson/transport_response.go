package httpjson

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const maxResponseHeadBytes = 16_384

var errResponseFilter = errors.New("http response filter failure")

// responseHeadFilter bounds and normalizes net/http output before it reaches a client.
type responseHeadFilter struct {
	writer    net.Conn
	transport *transportState
	terminate func()

	writeMu       sync.Mutex
	head          []byte
	finalHead     bool
	suppressBody  bool
	informational bool
	terminal      atomic.Bool
	terminateOnce sync.Once
}

// newResponseHeadFilter constructs one connection-local final-response boundary.
func newResponseHeadFilter(
	writer net.Conn,
	transport *transportState,
	terminate func(),
) *responseHeadFilter {
	return &responseHeadFilter{
		writer: writer, transport: transport, terminate: terminate,
		head: make([]byte, 0, maxResponseHeadBytes),
	}
}

// Terminal reports whether output is irrecoverably closed.
func (f *responseHeadFilter) Terminal() bool {
	return f == nil || f.transport == nil ||
		f.terminal.Load() || f.transport.ResponseTerminal()
}

// Scrub erases buffered response bytes and transport references after all
// in-flight writes have returned.
func (f *responseHeadFilter) Scrub() {
	if f == nil {
		return
	}
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	clear(f.head)
	f.head = nil
	f.writer = nil
	f.transport = nil
	f.terminate = nil
	f.finalHead = false
	f.suppressBody = false
	f.informational = false
	f.terminal.Store(true)
}

// Write transforms complete response heads and forwards or suppresses later bytes.
func (f *responseHeadFilter) Write(input []byte) (int, error) {
	if f == nil || f.writer == nil || f.transport == nil || f.Terminal() {
		return 0, net.ErrClosed
	}
	f.writeMu.Lock()
	defer func() {
		f.writeMu.Unlock()
		if f.Terminal() {
			f.terminateOnce.Do(func() {
				if f.terminate != nil {
					f.terminate()
				}
			})
		}
	}()
	if f.Terminal() {
		return 0, net.ErrClosed
	}
	return f.writeLocked(input)
}

// writeLocked filters one response fragment while holding the connection write lock.
func (f *responseHeadFilter) writeLocked(input []byte) (int, error) {
	if f.suppressBody {
		return len(input), nil
	}
	if f.finalHead {
		if err := f.writeAll(input); err != nil {
			f.fail()
			return len(input), errResponseFilter
		}
		return len(input), nil
	}

	pending := input
	for {
		previousLength := len(f.head)
		available := maxResponseHeadBytes - previousLength
		sectionTake, complete := responseSectionAppendLength(f.head, pending)
		take := min(len(pending), available)
		if complete {
			if sectionTake > available {
				f.fail()
				return len(input), errResponseFilter
			}
			take = sectionTake
		}
		f.head = append(f.head, pending[:take]...)
		if !validResponseHeadPrefix(f.head) {
			f.fail()
			return len(input), errResponseFilter
		}
		if !complete {
			if take < len(pending) || len(f.head) == maxResponseHeadBytes {
				f.fail()
				return len(input), errResponseFilter
			}
			return len(input), nil
		}
		pending = pending[sectionTake:]
		head := f.head
		status, informational, ok := parseResponseHead(head)
		if !ok {
			f.fail()
			return len(input), errResponseFilter
		}
		if informational {
			if !f.transport.HandlerEntered() || f.informational || status != 100 ||
				!bytes.Equal(head, []byte("HTTP/1.1 100 Continue\r\n\r\n")) {
				f.fail()
				return len(input), errResponseFilter
			}
			if err := f.writeAll(head); err != nil {
				f.fail()
				return len(input), errResponseFilter
			}
			f.informational = true
			f.head = f.head[:0]
			if len(pending) == 0 {
				return len(input), nil
			}
			continue
		}

		transformed, ok := f.transformFinalHead(head, status)
		if !ok {
			f.fail()
			return len(input), errResponseFilter
		}
		if !f.transport.HandlerEntered() {
			if err := f.transport.PreparePrehandlerWrite(); err != nil {
				f.fail()
				return len(input), errResponseFilter
			}
		}
		if err := f.writeAll(transformed); err != nil {
			f.fail()
			return len(input), errResponseFilter
		}
		f.finalHead = true
		f.head = f.head[:0]
		if f.transport.Facts().exactHEAD {
			f.suppressBody = true
			return len(input), nil
		}
		if err := f.writeAll(pending); err != nil {
			f.fail()
			return len(input), errResponseFilter
		}
		return len(input), nil
	}
}

// responseSectionAppendLength finds the first delimiter without copying body bytes.
func responseSectionAppendLength(head, pending []byte) (int, bool) {
	start := max(0, len(head)-3)
	total := len(head) + len(pending)
	for index := start; index+4 <= total; index++ {
		if responseVirtualByte(head, pending, index) == '\r' &&
			responseVirtualByte(head, pending, index+1) == '\n' &&
			responseVirtualByte(head, pending, index+2) == '\r' &&
			responseVirtualByte(head, pending, index+3) == '\n' {
			return index + 4 - len(head), true
		}
	}
	return 0, false
}

// responseVirtualByte reads one byte across the retained-head and pending boundary.
func responseVirtualByte(head, pending []byte, index int) byte {
	if index < len(head) {
		return head[index]
	}
	return pending[index-len(head)]
}

// validResponseHeadPrefix rejects known bare or malformed line delimiters incrementally.
func validResponseHeadPrefix(head []byte) bool {
	for index, value := range head {
		switch value {
		case '\n':
			if index == 0 || head[index-1] != '\r' {
				return false
			}
		case '\r':
			if index+1 < len(head) && head[index+1] != '\n' {
				return false
			}
		}
	}
	return true
}

// transformFinalHead applies effective-status, Date, and Connection policy in order.
func (f *responseHeadFilter) transformFinalHead(head []byte, status int) ([]byte, bool) {
	lines := bytes.Split(head[:len(head)-4], []byte("\r\n"))
	if len(lines) == 0 {
		return nil, false
	}
	facts := f.transport.Facts()
	effectiveStatus := status
	if !f.transport.HandlerEntered() &&
		facts.framing == framingBad &&
		facts.protoMajor == 1 && facts.protoMinor >= 1 &&
		status == 501 {
		lines[0] = []byte("HTTP/1.1 400 Bad Request")
		effectiveStatus = 400
	}

	hasDate := false
	filtered := make([][]byte, 0, len(lines)+2)
	filtered = append(filtered, lines[0])
	for _, line := range lines[1:] {
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || !validHTTPFieldName(line[:colon]) {
			return nil, false
		}
		name := string(line[:colon])
		if strings.EqualFold(name, "Connection") {
			continue
		}
		if strings.EqualFold(name, "Date") {
			hasDate = true
		}
		filtered = append(filtered, line)
	}
	if effectiveStatus >= 200 && effectiveStatus <= 499 && !hasDate {
		if date, ok := f.transport.ValidDate(); ok {
			filtered = append(filtered, []byte("Date: "+date))
		}
	}
	filtered = append(filtered, []byte("Connection: close"))
	return append(bytes.Join(filtered, []byte("\r\n")), []byte("\r\n\r\n")...), true
}

// parseResponseHead validates one Go-produced response head and returns its status class.
func parseResponseHead(head []byte) (status int, informational bool, ok bool) {
	if len(head) < len("HTTP/1.0 000\r\n\r\n") ||
		!bytes.HasSuffix(head, []byte("\r\n\r\n")) ||
		bytes.Contains(bytes.ReplaceAll(head, []byte("\r\n"), nil), []byte{'\n'}) {
		return 0, false, false
	}
	lines := bytes.Split(head[:len(head)-4], []byte("\r\n"))
	parts := bytes.SplitN(lines[0], []byte{' '}, 3)
	if len(parts) < 2 ||
		(!bytes.Equal(parts[0], []byte("HTTP/1.0")) && !bytes.Equal(parts[0], []byte("HTTP/1.1"))) ||
		len(parts[1]) != 3 {
		return 0, false, false
	}
	status, err := strconv.Atoi(string(parts[1]))
	if err != nil || status < 100 || status > 599 {
		return 0, false, false
	}
	for _, line := range lines[1:] {
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || !validHTTPFieldName(line[:colon]) {
			return 0, false, false
		}
	}
	return status, status >= 100 && status <= 199, true
}

// validHTTPFieldName validates the token grammar emitted by net/http.
func validHTTPFieldName(name []byte) bool {
	if len(name) == 0 {
		return false
	}
	for _, value := range name {
		if !httpTokenByte(value) {
			return false
		}
	}
	return true
}

// httpTokenByte reports whether one byte belongs to RFC 9110 tchar.
func httpTokenByte(value byte) bool {
	switch {
	case value >= '0' && value <= '9',
		value >= 'A' && value <= 'Z',
		value >= 'a' && value <= 'z':
		return true
	}
	return bytes.ContainsRune([]byte("!#$%&'*+-.^_`|~"), rune(value))
}

// writeAll forwards every byte or returns a constant terminal classification.
func (f *responseHeadFilter) writeAll(value []byte) error {
	for len(value) > 0 {
		written, err := f.writer.Write(value)
		if written > 0 {
			value = value[written:]
		}
		if err != nil || written == 0 {
			return errResponseFilter
		}
	}
	return nil
}

// fail marks output terminal; the caller closes only after releasing the write mutex.
func (f *responseHeadFilter) fail() {
	f.terminal.Store(true)
	f.transport.markResponseTerminal()
}
