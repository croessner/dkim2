package valkey

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	dkim2 "github.com/croessner/dkim2"
)

// TestAuditRequestEncodingFreezesTheClosedInventory proves every exact wire token.
func TestAuditRequestEncodingFreezesTheClosedInventory(t *testing.T) {
	tests := []struct {
		request auditRequest
		want    string
	}{
		{
			request: auditRequest{command: auditCommandAuth, arguments: [][]byte{[]byte("auditor"), []byte("protected")}},
			want:    "*3\r\n$4\r\nAUTH\r\n$7\r\nauditor\r\n$9\r\nprotected\r\n",
		},
		{request: auditRequest{command: auditCommandRole}, want: "*1\r\n$4\r\nROLE\r\n"},
		{
			request: auditRequest{command: auditCommandConfigGet},
			want: "*9\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$11\r\nappendfsync\r\n" +
				"$10\r\nappendonly\r\n$9\r\nmaxmemory\r\n$16\r\nmaxmemory-policy\r\n" +
				"$20\r\nmin-replicas-max-lag\r\n$21\r\nmin-replicas-to-write\r\n$4\r\nsave\r\n",
		},
		{request: auditRequest{command: auditCommandInfoMemory}, want: "*2\r\n$4\r\nINFO\r\n$6\r\nmemory\r\n"},
		{request: auditRequest{command: auditCommandInfoPersistence}, want: "*2\r\n$4\r\nINFO\r\n$11\r\npersistence\r\n"},
		{request: auditRequest{command: auditCommandInfoReplication}, want: "*2\r\n$4\r\nINFO\r\n$11\r\nreplication\r\n"},
		{request: auditRequest{command: auditCommandInfoCluster}, want: "*2\r\n$4\r\nINFO\r\n$7\r\ncluster\r\n"},
		{
			request: auditRequest{command: auditCommandACLGetUser, arguments: [][]byte{[]byte("application")}},
			want:    "*3\r\n$3\r\nACL\r\n$7\r\nGETUSER\r\n$11\r\napplication\r\n",
		},
		{
			request: auditRequest{command: auditCommandACLDryRunPing, arguments: [][]byte{[]byte("application")}},
			want:    "*4\r\n$3\r\nACL\r\n$6\r\nDRYRUN\r\n$11\r\napplication\r\n$4\r\nPING\r\n",
		},
		{
			request: auditRequest{command: auditCommandACLDryRunInNamespaceSet, arguments: [][]byte{[]byte("application")}},
			want: "*9\r\n$3\r\nACL\r\n$6\r\nDRYRUN\r\n$11\r\napplication\r\n$3\r\nSET\r\n" +
				"$17\r\ndkim2:replay:v1:a\r\n$2\r\nv1\r\n$2\r\nNX\r\n$2\r\nPX\r\n$4\r\n1000\r\n",
		},
		{
			request: auditRequest{command: auditCommandACLDryRunOutOfNamespaceSet, arguments: [][]byte{[]byte("application")}},
			want: "*9\r\n$3\r\nACL\r\n$6\r\nDRYRUN\r\n$11\r\napplication\r\n$3\r\nSET\r\n" +
				"$22\r\noutside:dkim2-replay-a\r\n$2\r\nv1\r\n$2\r\nNX\r\n$2\r\nPX\r\n$4\r\n1000\r\n",
		},
	}
	for _, testCase := range tests {
		encoded, err := encodeAuditRequest(testCase.request)
		if err != nil {
			t.Fatalf("command %s failed: %v", testCase.request.command, err)
		}
		if !bytes.Equal(encoded, []byte(testCase.want)) {
			t.Fatalf("command %s wire encoding changed", testCase.request.command)
		}
		clear(encoded)
	}
}

// TestAuditWireRejectsCommandTwelveBeforeTransport proves the hard inventory cap.
func TestAuditWireRejectsCommandTwelveBeforeTransport(t *testing.T) {
	connection := newScriptedAuditConn(bytes.Repeat([]byte("+OK\r\n"), auditCommandCount))
	wire := &tlsSecurityAuditWire{connection: connection}
	for index := 0; index < auditCommandCount; index++ {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
		value, err := wire.roundTrip(ctx, auditRequest{command: auditCommandRole})
		cancel()
		if err != nil {
			t.Fatalf("command %d failed: %v", index+1, err)
		}
		value.clear()
	}
	writesBefore, deadlinesBefore := connection.counts()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
	_, err := wire.roundTrip(ctx, auditRequest{command: auditCommandRole})
	cancel()
	if dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
		t.Fatalf("command twelve code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	writesAfter, deadlinesAfter := connection.counts()
	if writesAfter != writesBefore || deadlinesAfter != deadlinesBefore {
		t.Fatal("command twelve reached the transport")
	}
}

// TestAuditWireClearsDecoderBytesOnEveryFailure proves local protected-buffer ownership.
func TestAuditWireClearsDecoderBytesOnEveryFailure(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*scriptedAuditConn)
		want      dkim2.ReplayErrorCode
	}{
		{name: "deadline error", configure: func(c *scriptedAuditConn) { c.deadlineErr = errors.New("deadline") }, want: dkim2.ReplayErrorUnavailable},
		{name: "deadline panic", configure: func(c *scriptedAuditConn) { c.deadlinePanic = true }, want: dkim2.ReplayErrorInternalInvariant},
		{name: "write error", configure: func(c *scriptedAuditConn) { c.writeErr = errors.New("write") }, want: dkim2.ReplayErrorUnavailable},
		{name: "write panic", configure: func(c *scriptedAuditConn) { c.writePanic = true }, want: dkim2.ReplayErrorInternalInvariant},
		{name: "mid-control transport error", configure: func(c *scriptedAuditConn) { c.readErrAt = 3 }, want: dkim2.ReplayErrorUnavailable},
		{name: "mid-bulk transport error", configure: func(c *scriptedAuditConn) { c.readErrAt = 5 }, want: dkim2.ReplayErrorUnavailable},
		{name: "read panic", configure: func(c *scriptedAuditConn) { c.readPanicAt = 3 }, want: dkim2.ReplayErrorInternalInvariant},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			connection := newScriptedAuditConn([]byte("$9\r\nprotected\r\n"))
			testCase.configure(connection)
			wire := &tlsSecurityAuditWire{connection: connection}
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
			_, err := wire.roundTrip(ctx, auditRequest{command: auditCommandRole})
			cancel()
			if dkim2.ReplayErrorCodeOf(err) != testCase.want {
				t.Fatalf("code=%q want=%q", dkim2.ReplayErrorCodeOf(err), testCase.want)
			}
			if !connection.readDestinationsCleared() {
				t.Fatal("decoder-owned bytes survived failure")
			}
		})
	}
}

// TestAuditWireTransfersSuccessfulDecoderOwnership proves caller-controlled erasure.
func TestAuditWireTransfersSuccessfulDecoderOwnership(t *testing.T) {
	connection := newScriptedAuditConn([]byte("$9\r\nprotected\r\n"))
	wire := &tlsSecurityAuditWire{connection: connection}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
	value, err := wire.roundTrip(ctx, auditRequest{command: auditCommandRole})
	cancel()
	if err != nil || value.owner == nil || value.owner.bufferCleared() {
		t.Fatal("successful reply did not retain decoder ownership")
	}
	owner := value.owner
	value.clear()
	if !owner.bufferCleared() || !connection.readDestinationsCleared() {
		t.Fatal("successful reply cleanup did not erase decoder bytes")
	}
}

type scriptedAuditConn struct {
	mu            sync.Mutex
	reader        *bytes.Reader
	writes        bytes.Buffer
	destinations  [][]byte
	readCalls     int
	writeCalls    int
	deadlineCalls int
	readErrAt     int
	readPanicAt   int
	writeErr      error
	writePanic    bool
	deadlineErr   error
	deadlinePanic bool
}

// newScriptedAuditConn constructs one deterministic private-wire transport.
func newScriptedAuditConn(reply []byte) *scriptedAuditConn {
	return &scriptedAuditConn{reader: bytes.NewReader(reply)}
}

// Read supplies one scripted reply and retains destination aliases for erasure proof.
func (c *scriptedAuditConn) Read(destination []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readCalls++
	c.destinations = append(c.destinations, destination)
	if c.readPanicAt == c.readCalls {
		panic("synthetic read panic")
	}
	if c.readErrAt == c.readCalls {
		return 0, errors.New("synthetic read error")
	}
	return c.reader.Read(destination)
}

// Write records one exact request or injects a transport failure.
func (c *scriptedAuditConn) Write(value []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeCalls++
	if c.writePanic {
		panic("synthetic write panic")
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.writes.Write(value)
}

// Close is a deterministic successful transport cleanup.
func (*scriptedAuditConn) Close() error { return nil }

// LocalAddr returns one non-sensitive synthetic address.
func (*scriptedAuditConn) LocalAddr() net.Addr { return scriptedAuditAddr("local") }

// RemoteAddr returns one non-sensitive synthetic address.
func (*scriptedAuditConn) RemoteAddr() net.Addr { return scriptedAuditAddr("remote") }

// SetDeadline records the exact combined deadline operation.
func (c *scriptedAuditConn) SetDeadline(time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadlineCalls++
	if c.deadlinePanic {
		panic("synthetic deadline panic")
	}
	return c.deadlineErr
}

// SetReadDeadline is not used by the combined-deadline wire.
func (*scriptedAuditConn) SetReadDeadline(time.Time) error { return io.ErrClosedPipe }

// SetWriteDeadline is not used by the combined-deadline wire.
func (*scriptedAuditConn) SetWriteDeadline(time.Time) error { return io.ErrClosedPipe }

// counts returns exact write and deadline call counts.
func (c *scriptedAuditConn) counts() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeCalls, c.deadlineCalls
}

// readDestinationsCleared proves every decoder destination alias is zero.
func (c *scriptedAuditConn) readDestinationsCleared() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, destination := range c.destinations {
		for _, value := range destination {
			if value != 0 {
				return false
			}
		}
	}
	return true
}

type scriptedAuditAddr string

// Network returns the synthetic address family.
func (scriptedAuditAddr) Network() string { return "synthetic" }

// String returns a bounded synthetic address.
func (a scriptedAuditAddr) String() string { return string(a) }
