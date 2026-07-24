package valkey

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"sync"

	dkim2 "github.com/croessner/dkim2"
)

// tlsSecurityAuditWire owns one direct sequential TLS RESP2 connection.
type tlsSecurityAuditWire struct {
	connection net.Conn
	mu         sync.Mutex
	commands   int
}

// newTLSSecurityAuditWire connects and immediately publishes immutable authority.
func newTLSSecurityAuditWire(
	ctx context.Context,
	config auditAuthority,
	publish func(auditWire),
) error {
	if err := preflightContext(ctx); err != nil {
		return err
	}
	tlsConfig, err := safeTLSConfig(config)
	if err != nil || tlsConfig == nil || tlsConfig.RootCAs == nil {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{
			Timeout:   config.dialTimeout,
			KeepAlive: config.tcpKeepAlive,
		},
		Config: tlsConfig,
	}
	connection, err := dialer.DialContext(ctx, "tcp", config.endpoint)
	if connection != nil {
		publish(&tlsSecurityAuditWire{connection: connection})
	}
	if err != nil {
		return boundedFactoryError(ctx, err)
	}
	return nil
}

// safeTLSConfig contains impossible validated trust-state panics.
func safeTLSConfig(config auditAuthority) (tlsConfig *tls.Config, resultErr error) {
	defer func() {
		if recover() != nil {
			tlsConfig = nil
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	return config.tlsConfig(), nil
}

// roundTrip writes one closed command and reads exactly one bounded RESP2 reply.
func (w *tlsSecurityAuditWire) roundTrip(
	ctx context.Context,
	request auditRequest,
) (value resp2Value, resultErr error) {
	var decoder *resp2Decoder
	defer func() {
		if recover() != nil {
			value.clear()
			if decoder != nil {
				decoder.clear()
			}
			value = resp2Value{}
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
			return
		}
		if resultErr != nil && decoder != nil {
			decoder.clear()
		}
	}()
	if w == nil {
		return resp2Value{}, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.commands >= auditCommandCount {
		return resp2Value{}, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	if err := preflightContext(ctx); err != nil {
		return resp2Value{}, err
	}
	if nilInterface(w.connection) {
		return resp2Value{}, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	deadline, present := ctx.Deadline()
	if !present || deadline.IsZero() {
		return resp2Value{}, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	if err := w.connection.SetDeadline(deadline); err != nil {
		return resp2Value{}, dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
	}
	command, err := encodeAuditRequest(request)
	if err != nil {
		return resp2Value{}, err
	}
	defer clear(command)
	w.commands++
	if err := writeAll(w.connection, command); err != nil {
		if callerErr := preflightContext(ctx); callerErr != nil {
			return resp2Value{}, callerErr
		}
		return resp2Value{}, dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
	}
	decoder = newRESP2Decoder(w.connection)
	value, err = decoder.decode()
	if err != nil {
		decoder.clear()
		if callerErr := preflightContext(ctx); callerErr != nil {
			return resp2Value{}, callerErr
		}
		return resp2Value{}, err
	}
	return value, nil
}

// Close closes the ephemeral auditor connection.
func (w *tlsSecurityAuditWire) Close() error {
	if w == nil || nilInterface(w.connection) {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	return w.connection.Close()
}

// encodeAuditRequest serializes only one member of the frozen command inventory.
func encodeAuditRequest(request auditRequest) ([]byte, error) {
	tokens, err := auditRequestTokens(request)
	if err != nil {
		return nil, err
	}
	size := len("*\r\n") + len(strconv.Itoa(len(tokens)))
	for _, token := range tokens {
		size += len("$\r\n\r\n") + len(strconv.Itoa(len(token))) + len(token)
	}
	if size > maximumAuditReplyBytes {
		return nil, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	encoded := make([]byte, 0, size)
	encoded = append(encoded, '*')
	encoded = strconv.AppendInt(encoded, int64(len(tokens)), 10)
	encoded = append(encoded, '\r', '\n')
	for _, token := range tokens {
		encoded = append(encoded, '$')
		encoded = strconv.AppendInt(encoded, int64(len(token)), 10)
		encoded = append(encoded, '\r', '\n')
		encoded = append(encoded, token...)
		encoded = append(encoded, '\r', '\n')
	}
	return encoded, nil
}

// auditRequestTokens maps one closed enum and exact argument arity to wire tokens.
func auditRequestTokens(request auditRequest) ([][]byte, error) {
	argument := func(index int) []byte { return request.arguments[index] }
	switch request.command {
	case auditCommandAuth:
		if len(request.arguments) == 2 {
			return [][]byte{[]byte("AUTH"), argument(0), argument(1)}, nil
		}
	case auditCommandRole:
		if len(request.arguments) == 0 {
			return [][]byte{[]byte("ROLE")}, nil
		}
	case auditCommandConfigGet:
		if len(request.arguments) == 0 {
			return byteTokens(
				"CONFIG", "GET", "appendfsync", "appendonly", "maxmemory",
				"maxmemory-policy", "min-replicas-max-lag",
				"min-replicas-to-write", "save",
			), nil
		}
	case auditCommandInfoMemory:
		if len(request.arguments) == 0 {
			return byteTokens("INFO", "memory"), nil
		}
	case auditCommandInfoPersistence:
		if len(request.arguments) == 0 {
			return byteTokens("INFO", "persistence"), nil
		}
	case auditCommandInfoReplication:
		if len(request.arguments) == 0 {
			return byteTokens("INFO", "replication"), nil
		}
	case auditCommandInfoCluster:
		if len(request.arguments) == 0 {
			return byteTokens("INFO", "cluster"), nil
		}
	case auditCommandACLGetUser:
		if len(request.arguments) == 1 {
			return [][]byte{[]byte("ACL"), []byte("GETUSER"), argument(0)}, nil
		}
	case auditCommandACLDryRunPing:
		if len(request.arguments) == 1 {
			return [][]byte{[]byte("ACL"), []byte("DRYRUN"), argument(0), []byte("PING")}, nil
		}
	case auditCommandACLDryRunInNamespaceSet:
		if len(request.arguments) == 1 {
			return [][]byte{
				[]byte("ACL"), []byte("DRYRUN"), argument(0), []byte("SET"),
				[]byte("dkim2:replay:v1:a"), []byte("v1"), []byte("NX"),
				[]byte("PX"), []byte("1000"),
			}, nil
		}
	case auditCommandACLDryRunOutOfNamespaceSet:
		if len(request.arguments) == 1 {
			return [][]byte{
				[]byte("ACL"), []byte("DRYRUN"), argument(0), []byte("SET"),
				[]byte("outside:dkim2-replay-a"), []byte("v1"), []byte("NX"),
				[]byte("PX"), []byte("1000"),
			}, nil
		}
	}
	return nil, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
}

// byteTokens converts non-secret static tokens without generic command input.
func byteTokens(tokens ...string) [][]byte {
	values := make([][]byte, len(tokens))
	for index := range tokens {
		values[index] = []byte(tokens[index])
	}
	return values
}

// writeAll writes one complete command without pipelining or retry.
func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}
