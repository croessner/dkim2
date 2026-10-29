package redisstore

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // EVALSHA digests are SHA-1 by protocol definition.
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	dkim2 "github.com/croessner/dkim2"
)

// respServer is a minimal in-process RESP2 server for the exact commands the
// real go-redis client sends on behalf of the store. It lets tests drive the
// pinned go-redis retry loop with precise connection faults.
type respServer struct {
	mu   sync.Mutex
	data map[string]string
	// dropAfterSet makes the next N SET commands commit and then close the
	// connection without a reply, which go-redis observes as EOF.
	dropAfterSet int
	// dropAfterScript makes the next N script executions apply and then
	// close the connection without a reply.
	dropAfterScript int
	// rejectMaxClients makes the next N SET commands answer the
	// connection-limit rejection without executing.
	rejectMaxClients int
	// scripts holds the SHA-1 digests loaded through EVAL.
	scripts map[string]bool
	// failDials makes every dial after the first N successful ones fail.
	allowDials int
	dials      int
	sets       int
	evalShas   int
	evals      int
	listener   net.Listener
}

// newRESPServer starts one empty loopback server permitting unlimited dials.
func newRESPServer(t *testing.T) *respServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("loopback listener unavailable")
	}
	server := &respServer{data: map[string]string{}, scripts: map[string]bool{}, allowDials: -1, listener: listener}
	t.Cleanup(func() { _ = listener.Close() })
	go server.acceptLoop()
	return server
}

// dial opens one loopback connection to the in-process listener or reports
// a synthetic dial failure.
func (s *respServer) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	s.mu.Lock()
	if s.allowDials >= 0 && s.dials >= s.allowDials {
		s.mu.Unlock()
		return nil, &net.OpError{Op: caseDial, Net: "tcp", Err: errors.New("synthetic refusal")}
	}
	s.dials++
	address := s.listener.Addr().String()
	s.mu.Unlock()
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}

// acceptLoop serves every accepted loopback connection until the listener closes.
func (s *respServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.serve(conn)
	}
}

// serve answers commands on one connection until it closes.
func (s *respServer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	for {
		args, err := readRESPCommand(reader)
		if err != nil {
			return
		}
		reply, drop := s.handle(args)
		if drop {
			return
		}
		if _, err := io.WriteString(conn, reply); err != nil {
			return
		}
	}
}

// handle applies one command and reports whether the reply must be lost.
func (s *respServer) handle(args []string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch strings.ToLower(args[0]) {
	case "hello":
		return "-ERR unknown command 'hello'\r\n", false
	case "ping":
		return "+PONG\r\n", false
	case "info":
		if len(args) > 1 && args[1] == "memory" {
			return bulk("# Memory\r\nmaxmemory_policy:noeviction\r\n"), false
		}
		return bulk("# Server\r\nredis_version:7.2.4\r\n"), false
	case "evalsha":
		s.evalShas++
		if !s.scripts[strings.ToLower(args[1])] {
			return "-NOSCRIPT No matching script. Please use EVAL.\r\n", false
		}
		return s.runTakeoverLocked(args)
	case "eval":
		s.evals++
		digest := sha1.Sum([]byte(args[1])) //nolint:gosec // EVALSHA digests are SHA-1 by protocol definition.
		s.scripts[hex.EncodeToString(digest[:])] = true
		return s.runTakeoverLocked(args)
	case commandSet:
		s.sets++
		if s.rejectMaxClients > 0 {
			s.rejectMaxClients--
			return "-ERR max number of clients reached\r\n", false
		}
		key, value, mode := args[1], args[2], strings.ToLower(args[3])
		previous, present := s.data[key]
		if mode == "nx" && !present || mode == "xx" && present {
			s.data[key] = value
		}
		if s.dropAfterSet > 0 {
			s.dropAfterSet--
			return "", true
		}
		if !present {
			return "$-1\r\n", false
		}
		return bulk(previous), false
	default:
		return "-ERR unsupported\r\n", false
	}
}

// runTakeoverLocked models the single lease takeover script the store sends:
// EVAL(SHA) <script> 1 key expected replacement ms. It replaces the record
// only when it holds the expected value and returns the value it found.
func (s *respServer) runTakeoverLocked(args []string) (string, bool) {
	if len(args) != 7 || args[2] != "1" {
		return "-ERR unsupported script call\r\n", false
	}
	key, expected, replacement := args[3], args[4], args[5]
	current, present := s.data[key]
	if present && current == expected {
		s.data[key] = replacement
	}
	if s.dropAfterScript > 0 {
		s.dropAfterScript--
		return "", true
	}
	if !present {
		return "$-1\r\n", false
	}
	return bulk(current), false
}

// bulk renders one RESP bulk string.
func bulk(value string) string {
	return "$" + strconv.Itoa(len(value)) + "\r\n" + value + "\r\n"
}

// readRESPCommand reads one RESP array of bulk strings.
func readRESPCommand(reader *bufio.Reader) ([]string, error) {
	header, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(header, "*") {
		return nil, errors.New("not an array")
	}
	count, err := strconv.Atoi(strings.TrimSpace(header[1:]))
	if err != nil || count < 1 || count > 16 {
		return nil, errors.New("bad count")
	}
	args := make([]string, 0, count)
	for range count {
		length, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(length, "$") {
			return nil, errors.New("not a bulk string")
		}
		size, err := strconv.Atoi(strings.TrimSpace(length[1:]))
		if err != nil || size < 0 || size > 4096 {
			return nil, errors.New("bad size")
		}
		payload := make([]byte, size+2)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, err
		}
		args = append(args, string(payload[:size]))
	}
	return args, nil
}

// newRealClientStore builds one store over the production go-redis client
// options with the in-process transport.
func newRealClientStore(t *testing.T, server *respServer) *Store {
	t.Helper()
	config := testConfig()
	config.Protocol = 2
	config.MaxAttempts = 3
	config.MinRetryBackoff = time.Millisecond
	config.MaxRetryBackoff = 2 * time.Millisecond
	config.MinIdleConnections = 0
	deps := fakeDependencies(nil)
	deps.newBackend = func(validated validatedConfig, vault *credentialVault, material *constructionMaterial) backend {
		return newProductionBackend(validated, vault, material.config, material.sentinelPassword, server.dial)
	}
	store, err := newStoreWithDependencies(context.Background(), config, Secrets{}, deps)
	if err != nil {
		t.Fatalf("construct real-client store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	return store
}

// TestRealClientRetryAfterLostReplyIsFirstSeen is the end-to-end reproducer
// of the root cause: go-redis retries a SET whose first attempt committed but
// whose reply was lost. The nonce-bearing value lets the retried attempt
// recognize its own commit, so the result is first seen, never replayed.
func TestRealClientRetryAfterLostReplyIsFirstSeen(t *testing.T) {
	server := newRESPServer(t)
	store := newRealClientStore(t, server)
	server.mu.Lock()
	server.dropAfterSet = 1
	server.mu.Unlock()
	key, _ := testReplayKey(t, false)
	check, err := store.CheckAndRemember(context.Background(), key, testRetention(t))
	if err != nil || check != dkim2.ReplayCheckFirstSeen {
		t.Fatalf("retried check=%v err=%v, want first_seen", check, err)
	}
	server.mu.Lock()
	sets := server.sets
	server.mu.Unlock()
	if sets != 2 {
		t.Fatalf("SET attempts=%d, want 2 (one lost reply and one retry)", sets)
	}
	check, err = store.CheckAndRemember(context.Background(), key, testRetention(t))
	if err != nil || check != dkim2.ReplayCheckReplayed {
		t.Fatalf("later check=%v err=%v, want replayed", check, err)
	}
}

// TestRealClientEOFThenDialErrorIsIndeterminate proves that go-redis hiding
// the possibly committed first attempt behind a final dial error still
// yields indeterminate, never unavailable.
func TestRealClientEOFThenDialErrorIsIndeterminate(t *testing.T) {
	server := newRESPServer(t)
	store := newRealClientStore(t, server)
	server.mu.Lock()
	server.dropAfterSet = 1
	server.allowDials = server.dials
	server.mu.Unlock()
	key, _ := testReplayKey(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := store.CheckAndRemember(ctx, key, testRetention(t))
	requireCode(t, err, dkim2.ReplayErrorIndeterminate)
	if store.facts.strongest() != recoveryTransient {
		t.Fatalf("recovery=%d, want transient", store.facts.strongest())
	}
}

// lockedServer applies one mutation to the in-process server state.
func (s *respServer) lockedServer(apply func(*respServer)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	apply(s)
}

// TestRealClientMaxClientsRetryRecovers proves go-redis retries the
// connection-limit rejection and a later attempt completes authoritatively.
func TestRealClientMaxClientsRetryRecovers(t *testing.T) {
	server := newRESPServer(t)
	store := newRealClientStore(t, server)
	server.lockedServer(func(s *respServer) { s.rejectMaxClients = 1 })
	key, _ := testReplayKey(t, false)
	check, err := store.CheckAndRemember(context.Background(), key, testRetention(t))
	if err != nil || check != dkim2.ReplayCheckFirstSeen || !store.AuthorityReady() {
		t.Fatalf("check=%v err=%v ready=%t, want first_seen and ready", check, err, store.AuthorityReady())
	}
}

// TestRealClientMaxClientsExhaustionIsTransient proves exhausted
// connection-limit rejections fail closed as indeterminate with only the
// transient fact, and a successful probe restores readiness.
func TestRealClientMaxClientsExhaustionIsTransient(t *testing.T) {
	server := newRESPServer(t)
	store := newRealClientStore(t, server)
	server.lockedServer(func(s *respServer) { s.rejectMaxClients = 3 })
	key, _ := testReplayKey(t, false)
	_, err := store.CheckAndRemember(context.Background(), key, testRetention(t))
	requireCode(t, err, dkim2.ReplayErrorIndeterminate)
	if store.facts.strongest() != recoveryTransient {
		t.Fatalf("recovery=%d, want transient", store.facts.strongest())
	}
	if err := store.Probe(context.Background()); err != nil || !store.AuthorityReady() {
		t.Fatalf("probe err=%v did not restore readiness", err)
	}
}

// TestRealClientCommitAfterLostReplyIsCommitted proves a commit whose first
// attempt applied but lost its reply observes committed on the go-redis
// retry and stays committed.
func TestRealClientCommitAfterLostReplyIsCommitted(t *testing.T) {
	server := newRESPServer(t)
	store := newRealClientStore(t, server)
	key, storage := testReplayKey(t, true)
	server.lockedServer(func(s *respServer) {
		s.data[storage] = pendingValue(time.Minute, foreignNonce)
		s.dropAfterSet = 1
	})
	commit, err := store.CommitPropagation(context.Background(), key)
	if err != nil || commit != dkim2.ReplayPropagationCommitted {
		t.Fatalf("retried commit=%v err=%v, want committed", commit, err)
	}
	server.lockedServer(func(s *respServer) {
		if s.sets != 2 || s.data[storage] != dkim2.ReplayPropagationCommittedValue {
			t.Fatalf("SET attempts=%d stored committed=%t", s.sets, s.data[storage] == dkim2.ReplayPropagationCommittedValue)
		}
	})
}

// TestRealClientReserveAfterLostReplyIsReserved proves a reservation whose
// insert applied but lost its reply recognizes its own pending value on the
// go-redis retry.
func TestRealClientReserveAfterLostReplyIsReserved(t *testing.T) {
	server := newRESPServer(t)
	store := newRealClientStore(t, server)
	key, _ := testReplayKey(t, true)
	server.lockedServer(func(s *respServer) { s.dropAfterSet = 1 })
	reservation, err := store.ReservePropagation(context.Background(), key, testRetention(t), testLease(t))
	if err != nil || reservation != dkim2.ReplayPropagationReserved {
		t.Fatalf("retried reservation=%v err=%v, want reserved", reservation, err)
	}
	server.lockedServer(func(s *respServer) {
		if s.sets != 2 {
			t.Fatalf("SET attempts=%d, want 2", s.sets)
		}
	})
}

// TestRealClientTakeoverAfterLostReplyIsReserved proves an expired-lease
// takeover whose script applied but lost its reply recognizes its own
// replacement on the go-redis retry, through EVALSHA and through the
// NOSCRIPT-to-EVAL fallback.
func TestRealClientTakeoverAfterLostReplyIsReserved(t *testing.T) {
	for _, test := range []struct {
		name     string
		loaded   bool
		evalShas int
		evals    int
	}{
		{name: "evalsha", loaded: true, evalShas: 2, evals: 0},
		{name: "eval fallback", loaded: false, evalShas: 1, evals: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newRESPServer(t)
			store := newRealClientStore(t, server)
			key, storage := testReplayKey(t, true)
			server.lockedServer(func(s *respServer) {
				s.data[storage] = pendingValue(-time.Second, foreignNonce)
				s.dropAfterScript = 1
				if test.loaded {
					s.scripts[strings.ToLower(store.script.Hash())] = true
				}
			})
			reservation, err := store.ReservePropagation(context.Background(), key, testRetention(t), testLease(t))
			if err != nil || reservation != dkim2.ReplayPropagationReserved {
				t.Fatalf("retried takeover=%v err=%v, want reserved", reservation, err)
			}
			server.lockedServer(func(s *respServer) {
				if s.evalShas != test.evalShas || s.evals != test.evals {
					t.Fatalf("EVALSHA=%d EVAL=%d, want %d/%d", s.evalShas, s.evals, test.evalShas, test.evals)
				}
				if s.data[storage] == pendingValue(-time.Second, foreignNonce) {
					t.Fatal("takeover did not replace the expired foreign lease")
				}
			})
		})
	}
}
