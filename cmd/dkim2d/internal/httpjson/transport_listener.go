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
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

const (
	transportConnectionLimit = 128
	transportRefusalBackoff  = 10 * time.Millisecond
	transportReadErrorText   = "dkim2 HTTP transport read failed"
)

var errTransportRead = &transportReadError{}

type transportReadError struct {
	timeout bool
}

// Error returns a constant content-free transport read diagnostic.
func (*transportReadError) Error() string { return transportReadErrorText }

// Timeout reports whether the underlying operation exhausted its deadline.
func (e *transportReadError) Timeout() bool { return e != nil && e.timeout }

// Temporary reports no retryable transport condition.
func (*transportReadError) Temporary() bool { return false }

type transportAcceptError struct {
	temporary bool
}

type transportTemporary interface {
	Temporary() bool
}

type transportListenerOwner struct {
	tag byte
}

const (
	transportContextUnbound uint32 = iota
	transportContextBound
	transportContextClosed
)

// Error returns a constant content-free accept diagnostic.
func (*transportAcceptError) Error() string { return transportControlErrorText }

// Timeout reports no accept timeout detail.
func (*transportAcceptError) Timeout() bool { return false }

// Temporary preserves only net/http's bounded accept retry decision.
func (e *transportAcceptError) Temporary() bool {
	return e != nil && e.temporary
}

type trackedListener struct {
	raw          net.Listener
	dateProvider func() (string, bool)
	owner        *transportListenerOwner
	tokens       chan struct{}
	closed       chan struct{}
	closeOnce    sync.Once
	closeErr     error
	waitRefusal  func(<-chan struct{}) bool
	lifecycleMu  sync.RWMutex
	isClosed     bool
}

// newTrackedListener constructs the fixed-cap connection containment boundary.
func newTrackedListener(
	listener net.Listener,
	dateProvider func() (string, bool),
) (*trackedListener, error) {
	if nilInterfaceValue(listener) {
		return nil, errTransportControl
	}
	return &trackedListener{
		raw:          listener,
		dateProvider: dateProvider,
		owner:        &transportListenerOwner{tag: 1},
		tokens:       make(chan struct{}, transportConnectionLimit),
		closed:       make(chan struct{}),
		waitRefusal:  waitTransportRefusal,
	}, nil
}

// Accept returns one tracked connection or refuses excess sockets with bounded backoff.
func (l *trackedListener) Accept() (net.Conn, error) {
	if l == nil || nilInterfaceValue(l.raw) {
		return nil, net.ErrClosed
	}
	for {
		select {
		case <-l.closed:
			return nil, net.ErrClosed
		default:
		}
		raw, err := l.raw.Accept()
		if err != nil {
			return nil, l.classifyAcceptError(err)
		}
		l.lifecycleMu.RLock()
		if l.isClosed {
			l.lifecycleMu.RUnlock()
			_ = raw.Close()
			return nil, net.ErrClosed
		}
		select {
		case l.tokens <- struct{}{}:
			state := newTransportState(l.dateProvider)
			connection := newTrackedConn(raw, state, func() {
				select {
				case <-l.tokens:
				default:
				}
			})
			connection.owner = l.owner
			state.connection.Store(connection)
			l.lifecycleMu.RUnlock()
			return connection, nil
		default:
			_ = raw.Close()
		}
		l.lifecycleMu.RUnlock()
		if !l.waitRefusal(l.closed) {
			return nil, net.ErrClosed
		}
	}
}

// Close interrupts accept/backoff and closes the underlying listener exactly once.
func (l *trackedListener) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		l.lifecycleMu.Lock()
		defer l.lifecycleMu.Unlock()
		l.isClosed = true
		close(l.closed)
		if !nilInterfaceValue(l.raw) {
			if err := l.raw.Close(); err != nil {
				l.closeErr = errTransportControl
			}
		}
	})
	return l.closeErr
}

// classifyAcceptError preserves only closure and temporary retry semantics.
func (l *trackedListener) classifyAcceptError(err error) error {
	if err == nil {
		return nil
	}
	select {
	case <-l.closed:
		return net.ErrClosed
	default:
	}
	if errors.Is(err, net.ErrClosed) {
		return net.ErrClosed
	}
	var temporaryError transportTemporary
	if errors.As(err, &temporaryError) {
		return &transportAcceptError{temporary: temporaryError.Temporary()}
	}
	return &transportAcceptError{}
}

// Addr returns the underlying listener address without retaining another copy.
func (l *trackedListener) Addr() net.Addr {
	if l == nil || nilInterfaceValue(l.raw) {
		return nil
	}
	return l.raw.Addr()
}

// ConnContext installs the private state owned by a tracked accepted connection.
func (*trackedListener) ConnContext(ctx context.Context, connection net.Conn) context.Context {
	return transportConnContext(ctx, connection)
}

// String returns a content-free listener representation.
func (*trackedListener) String() string { return transportRedacted }

// GoString returns a content-free Go-syntax listener representation.
func (*trackedListener) GoString() string { return transportRedacted }

// Format prevents formatting verbs from traversing the underlying listener.
func (*trackedListener) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, transportRedacted)
}

// MarshalJSON rejects serialization of retained listener state.
func (*trackedListener) MarshalJSON() ([]byte, error) {
	return nil, errors.New(transportMarshalErrorText)
}

// MarshalText rejects diagnostic serialization of retained listener state.
func (*trackedListener) MarshalText() ([]byte, error) {
	return nil, errors.New(transportMarshalErrorText)
}

// waitTransportRefusal applies the fixed refusal delay and remains shutdown-interruptible.
func waitTransportRefusal(closed <-chan struct{}) bool {
	timer := time.NewTimer(transportRefusalBackoff)
	defer timer.Stop()
	select {
	case <-closed:
		return false
	case <-timer.C:
		return true
	}
}

type trackedConn struct {
	raw     net.Conn
	state   *transportState
	owner   *transportListenerOwner
	release func()

	closeOnce   sync.Once
	releaseOnce sync.Once
	closeErr    error

	readMu      sync.Mutex
	captured    []byte
	replayAt    int
	headDone    bool
	prefixFreed bool
	replayLimit int
	pendingRead error

	responseOnce sync.Once
	responseMu   sync.Mutex
	response     *responseHeadFilter

	contextState atomic.Uint32
}

// newTrackedConn constructs one exact-close connection and shared head buffer.
func newTrackedConn(raw net.Conn, state *transportState, release func()) *trackedConn {
	return &trackedConn{
		raw:      raw,
		state:    state,
		release:  release,
		captured: make([]byte, 0, transportRequestHeadLimit),
	}
}

// Read captures, classifies, and replays the first request head byte-for-byte.
func (c *trackedConn) Read(output []byte) (int, error) {
	if c == nil || nilInterfaceValue(c.raw) {
		return 0, net.ErrClosed
	}
	if c.state == nil || c.state.ResponseTerminal() {
		return 0, net.ErrClosed
	}
	if len(output) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.state.ResponseTerminal() {
		c.scrubReadStateLocked()
		return 0, net.ErrClosed
	}
	if count, ok := c.replayCaptured(output); ok {
		return count, nil
	}
	if err := c.captureRequestHeadLocked(); err != nil {
		return 0, err
	}
	if count, ok := c.replayCaptured(output); ok {
		return count, nil
	}
	if c.pendingRead != nil {
		readErr := c.pendingRead
		c.pendingRead = nil
		return 0, readErr
	}
	count, readErr := c.raw.Read(output)
	if c.state.ResponseTerminal() {
		c.scrubReadStateLocked()
		return 0, net.ErrClosed
	}
	if readErr != nil {
		return count, c.classifyReadError(readErr)
	}
	if count == 0 {
		c.state.publishReadTerminal(transportReadTerminalOther)
		return 0, errTransportRead
	}
	return count, nil
}

// captureRequestHeadLocked retains transport facts until replay can safely begin.
func (c *trackedConn) captureRequestHeadLocked() error {
	for !c.headDone {
		if !c.prefixFreed {
			if replayLimit, release := transportEarlyReplayLimit(c.captured); release {
				c.prefixFreed = true
				c.replayLimit = replayLimit
				return nil
			}
		}
		if headEnd := transportHeadTerminator(c.captured); headEnd >= 0 {
			facts, normalized, _ := prepareTransportHeadPrefix(c.captured, headEnd)
			c.captured = normalized
			c.state.publishFacts(facts)
			c.headDone = true
			return nil
		}
		if len(c.captured) == cap(c.captured) {
			if rawTransportTargetOverflow(c.captured) {
				return c.emitRawTargetTooLong()
			}
			c.publishPartialHead()
			c.headDone = true
			return nil
		}
		originalLength := len(c.captured)
		readCeiling := cap(c.captured)
		c.captured = c.captured[:readCeiling]
		count, readErr := c.raw.Read(c.captured[originalLength:])
		if c.state.ResponseTerminal() {
			c.scrubReadStateLocked()
			return net.ErrClosed
		}
		if count < 0 || count > readCeiling-originalLength {
			c.captured = c.captured[:originalLength]
			c.terminateReadLocked()
			return errTransportRead
		}
		c.captured = c.captured[:originalLength+count]
		if count == 0 && readErr == nil {
			c.state.publishReadTerminal(transportReadTerminalOther)
			c.terminateReadLocked()
			return errTransportRead
		}
		if len(c.captured) == cap(c.captured) &&
			rawTransportTargetOverflow(c.captured) {
			return c.emitRawTargetTooLong()
		}
		if !c.prefixFreed {
			if replayLimit, release := transportEarlyReplayLimit(c.captured); release {
				c.prefixFreed = true
				c.replayLimit = replayLimit
				return nil
			}
		}
		if headEnd := transportHeadTerminator(c.captured); headEnd >= 0 {
			facts, normalized, _ := prepareTransportHeadPrefix(c.captured, headEnd)
			c.captured = normalized
			c.state.publishFacts(facts)
			c.headDone = true
		}
		if readErr != nil {
			c.pendingRead = c.classifyReadError(readErr)
			if !c.headDone {
				c.publishPartialHead()
				c.headDone = true
			}
		}
	}
	return nil
}

// replayCaptured returns already inspected bytes without forcing another raw read.
func (c *trackedConn) replayCaptured(output []byte) (int, bool) {
	replayEnd := len(c.captured)
	if !c.headDone && c.prefixFreed && c.replayLimit < replayEnd {
		replayEnd = c.replayLimit
	}
	if c.replayAt >= replayEnd {
		return 0, false
	}
	count := copy(output, c.captured[c.replayAt:replayEnd])
	c.replayAt += count
	if c.headDone && c.replayAt == len(c.captured) {
		clear(c.captured)
		c.captured = nil
		c.replayAt = 0
	}
	return count, true
}

// publishPartialHead retains only request-line facts before Go's limit/error path.
func (c *trackedConn) publishPartialHead() {
	facts := transportFacts{expect: expectNone, framing: framingAbsent}
	_, lineEnd, _, complete := nextTransportLine(c.captured, 0)
	if !complete {
		inspectTransportRequestLine(c.captured, &facts)
	} else {
		inspectTransportRequestLine(c.captured[:lineEnd], &facts)
	}
	c.state.publishFacts(facts)
}

// Write delegates all server output to the connection-local response filter.
func (c *trackedConn) Write(input []byte) (int, error) {
	if c == nil || nilInterfaceValue(c.raw) || c.state == nil {
		return 0, net.ErrClosed
	}
	if c.state.ResponseTerminal() {
		return 0, net.ErrClosed
	}
	c.responseMu.Lock()
	if c.state.ResponseTerminal() {
		c.responseMu.Unlock()
		return 0, net.ErrClosed
	}
	c.responseOnce.Do(func() {
		c.response = newResponseHeadFilter(c.raw, c.state, func() {
			c.state.markResponseTerminal()
			c.terminateRaw()
		})
	})
	count, err := c.response.Write(input)
	terminal := c.response.Terminal()
	if terminal {
		c.state.markResponseTerminal()
	}
	c.responseMu.Unlock()
	if terminal {
		c.terminate()
	}
	return count, err
}

// Close terminates the raw connection and cap ownership exactly once.
func (c *trackedConn) Close() error {
	if c == nil {
		return nil
	}
	c.terminate()
	return c.closeErr
}

// terminate closes the raw connection without recursing through the response filter.
func (c *trackedConn) terminate() {
	c.terminateRaw()
	c.readMu.Lock()
	c.scrubReadStateLocked()
	c.readMu.Unlock()
	c.responseMu.Lock()
	if c.response != nil {
		c.response.Scrub()
		c.response = nil
	}
	c.responseMu.Unlock()
	c.finishTerminalOwnership()
}

// terminateReadLocked closes and scrubs while Read already owns readMu.
func (c *trackedConn) terminateReadLocked() {
	c.terminateRaw()
	c.scrubReadStateLocked()
	c.responseMu.Lock()
	if c.response != nil {
		c.response.Scrub()
		c.response = nil
	}
	c.responseMu.Unlock()
	c.finishTerminalOwnership()
}

// terminateRaw closes the socket and publishes terminal ownership exactly once.
func (c *trackedConn) terminateRaw() {
	c.closeOnce.Do(func() {
		defer func() {
			if recover() != nil {
				c.closeErr = errTransportControl
			}
		}()
		c.contextState.Store(transportContextClosed)
		if c.state != nil {
			c.state.markResponseTerminal()
		}
		if !nilInterfaceValue(c.raw) {
			if err := c.raw.Close(); err != nil {
				c.closeErr = errTransportControl
			}
		}
	})
}

// finishTerminalOwnership releases process and connection reservations only
// after captured request bytes and private facts are unreachable.
func (c *trackedConn) finishTerminalOwnership() {
	if c.state != nil {
		c.state.finishTransportOwnership()
	}
	c.releaseOnce.Do(func() {
		if c.release != nil {
			c.release()
		}
	})
}

// scrubReadStateLocked erases captured request bytes and bounded replay state.
func (c *trackedConn) scrubReadStateLocked() {
	clear(c.captured)
	c.captured = nil
	c.replayAt = 0
	c.headDone = true
	c.prefixFreed = false
	c.replayLimit = 0
	c.pendingRead = nil
	if c.state != nil {
		c.state.scrubPrivateFacts()
	}
}

// LocalAddr returns the raw local endpoint required by net/http.
func (c *trackedConn) LocalAddr() net.Addr {
	if c == nil || nilInterfaceValue(c.raw) {
		return nil
	}
	return c.raw.LocalAddr()
}

// RemoteAddr returns the raw remote endpoint required by net/http.
func (c *trackedConn) RemoteAddr() net.Addr {
	if c == nil || nilInterfaceValue(c.raw) {
		return nil
	}
	return c.raw.RemoteAddr()
}

// SetDeadline delegates a bounded whole-connection deadline.
func (c *trackedConn) SetDeadline(deadline time.Time) error {
	if c == nil || nilInterfaceValue(c.raw) {
		return net.ErrClosed
	}
	if err := c.raw.SetDeadline(deadline); err != nil {
		return errTransportControl
	}
	return nil
}

// SetReadDeadline delegates a bounded read deadline.
func (c *trackedConn) SetReadDeadline(deadline time.Time) error {
	if c == nil || nilInterfaceValue(c.raw) {
		return net.ErrClosed
	}
	if err := c.raw.SetReadDeadline(deadline); err != nil {
		return errTransportControl
	}
	return nil
}

// SetWriteDeadline delegates a bounded write deadline.
func (c *trackedConn) SetWriteDeadline(deadline time.Time) error {
	if c == nil || nilInterfaceValue(c.raw) {
		return net.ErrClosed
	}
	if err := c.raw.SetWriteDeadline(deadline); err != nil {
		return errTransportControl
	}
	return nil
}

// String returns a content-free connection representation.
func (*trackedConn) String() string { return transportRedacted }

// GoString returns a content-free Go-syntax connection representation.
func (*trackedConn) GoString() string { return transportRedacted }

// Format prevents formatting verbs from traversing raw connection state.
func (*trackedConn) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, transportRedacted)
}

// MarshalJSON rejects serialization of retained connection state.
func (*trackedConn) MarshalJSON() ([]byte, error) {
	return nil, errors.New(transportMarshalErrorText)
}

// MarshalText rejects diagnostic serialization of retained connection state.
func (*trackedConn) MarshalText() ([]byte, error) {
	return nil, errors.New(transportMarshalErrorText)
}

// emitRawTargetTooLong writes the sole pre-parser fixed response and terminates.
func (c *trackedConn) emitRawTargetTooLong() error {
	if c.state == nil || c.state.PreparePrehandlerWrite() != nil {
		c.terminateReadLocked()
		return errTransportRead
	}
	response := []byte("HTTP/1.1 414 URI Too Long\r\n" +
		"Cache-Control: no-store\r\n" +
		"X-Content-Type-Options: nosniff\r\n" +
		"Connection: close\r\n" +
		"Content-Length: 0\r\n")
	if date, ok := c.state.ValidDate(); ok {
		response = append(response, "Date: "...)
		response = append(response, date...)
		response = append(response, "\r\n"...)
	}
	response = append(response, "\r\n"...)
	writeErr := writeTransportAll(c.raw, response)
	c.terminateReadLocked()
	if writeErr != nil {
		return errTransportRead
	}
	return io.EOF
}

// writeTransportAll writes one fixed response without retrying a failed prefix.
func writeTransportAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		count, err := writer.Write(value)
		if count > 0 {
			value = value[count:]
		}
		if err != nil || count == 0 {
			return errTransportControl
		}
	}
	return nil
}

// rawTransportTargetOverflow selects only the incomplete request-line raw 414 path.
func rawTransportTargetOverflow(prefix []byte) bool {
	firstSP := bytes.IndexByte(prefix, ' ')
	if firstSP <= 0 || firstSP > transportMethodInspectLimit {
		return false
	}
	for _, value := range prefix[:firstSP] {
		if !isTransportTchar(value) {
			return false
		}
	}
	remaining := prefix[firstSP+1:]
	if bytes.IndexByte(remaining, ' ') >= 0 || bytes.IndexByte(remaining, '\n') >= 0 {
		return false
	}
	return len(remaining) > transportRequestTargetLimit &&
		len(prefix) == transportRequestHeadLimit
}

// transportHeadTerminator returns the exclusive first-head boundary.
func transportHeadTerminator(value []byte) int {
	_, _, position, complete := nextTransportLine(value, 0)
	if !complete {
		return -1
	}
	for position <= len(value) {
		start, end, next, lineComplete := nextTransportLine(value, position)
		if !lineComplete {
			return -1
		}
		if start == end {
			return next
		}
		position = next
	}
	return -1
}

// boundedTransportReadError preserves only timeout classification.
func (c *trackedConn) classifyReadError(err error) error {
	if err == nil {
		return nil
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		c.state.publishReadTerminal(transportReadTerminalTimeout)
		return &transportReadError{timeout: true}
	}
	if errors.Is(err, io.EOF) {
		c.state.publishReadTerminal(transportReadTerminalEOF)
		return io.EOF
	}
	if errors.Is(err, net.ErrClosed) {
		c.state.publishReadTerminal(transportReadTerminalDisconnect)
		return net.ErrClosed
	}
	c.state.publishReadTerminal(transportReadTerminalOther)
	return errTransportRead
}

// transportEarlyReplayLimit returns the exact one-shot prefilter release boundary.
func transportEarlyReplayLimit(prefix []byte) (int, bool) {
	firstSP := -1
	for index, value := range prefix {
		if value == '\n' {
			return index + 1, true
		}
		if firstSP < 0 {
			if value == ' ' {
				if index == 0 {
					return 1, true
				}
				firstSP = index
				continue
			}
			if !isTransportTchar(value) {
				return index + 1, true
			}
			if index+1 > transportMethodInspectLimit {
				return transportMethodInspectLimit + 1, true
			}
			continue
		}
		if value == ' ' {
			return 0, false
		}
	}
	return 0, false
}

// nilInterfaceValue rejects direct and typed-nil interface dependencies.
func nilInterfaceValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var (
	_ net.Error              = (*transportReadError)(nil)
	_ net.Error              = (*transportAcceptError)(nil)
	_ net.Listener           = (*trackedListener)(nil)
	_ net.Conn               = (*trackedConn)(nil)
	_ fmt.Stringer           = (*trackedListener)(nil)
	_ fmt.GoStringer         = (*trackedListener)(nil)
	_ json.Marshaler         = (*trackedListener)(nil)
	_ encoding.TextMarshaler = (*trackedListener)(nil)
	_ fmt.Stringer           = (*trackedConn)(nil)
	_ fmt.GoStringer         = (*trackedConn)(nil)
	_ json.Marshaler         = (*trackedConn)(nil)
	_ encoding.TextMarshaler = (*trackedConn)(nil)
)
