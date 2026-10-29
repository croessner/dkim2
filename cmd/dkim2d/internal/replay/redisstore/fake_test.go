package redisstore

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	dkim2 "github.com/croessner/dkim2"
	"github.com/redis/go-redis/v9"
)

// testNonceBytes yields deterministic synthetic nonces for one test.
var testNonceBytes = []byte{
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
}

const (
	testSentinelMaster  = "mymaster"
	testSentinelAddress = "10.0.0.1:26379"
	testClusterAddress  = "10.0.0.1:7000"
	testServerName      = "redis.internal"
	testUsername        = "application"
	ownerInsert         = "insertIfAbsentCommand"
	ownerCommit         = "commitIfPresentCommand"
	caseEOF             = "eof"
	caseDial            = "dial"
	caseCommitted       = "committed"
	commandSet          = "set"
	commandGet          = "get"
)

const (
	firstTestValue = "v2:1011121314151617"
	foreignV2Value = "v2:ffffffffffffffff"
	testKeyPrefix  = "test:"
)

// testNow is the fixed wall clock used for lease stamping.
var testNow = time.UnixMilli(1_700_000_000_000).UTC()

// fakeBackend is an in-memory model of the exact commands the store issues.
// It applies SET NX/XX GET semantics and the takeover script, and lets tests
// inject replies, errors, retries, and panics without a network.
type fakeBackend struct {
	mu sync.Mutex
	// data is the modeled keyspace without TTL simulation.
	data map[string]string
	// doArgs records every pinned argument vector.
	doArgs [][]any
	// evalShaCalls and evalCalls count script dispatch forms.
	evalShaCalls int
	evalCalls    int
	// lostReplies makes the next N writes commit and then lose their reply,
	// modeling a go-redis internal retry that observes the first commit.
	lostReplies int
	// noScript makes the next EVALSHA report NOSCRIPT without executing.
	noScript bool
	// reply overrides the modeled reply of every write when non-nil.
	reply func(args []any) *redis.Cmd
	// scriptReply overrides the modeled script reply when non-nil.
	scriptReply func(keys []string, args []any) *redis.Cmd
	// pingErr is returned by every probe or startup PING.
	pingErr error
	// pingPanic makes the probe PING panic.
	pingPanic bool
	// primaries are the INFO replies startup checks inspect.
	primaries []fakePrimary
	// closeCalls and closeErr model client release.
	closeCalls int
	closeErr   error
	// panicOnDo makes the write dispatch panic after being recorded.
	panicOnDo bool
}

// fakePrimary returns fixed INFO sections or one error.
type fakePrimary struct {
	server string
	memory string
	err    error
}

// Info returns one fixed INFO section.
func (p fakePrimary) Info(_ context.Context, sections ...string) *redis.StringCmd {
	if p.err != nil {
		return redis.NewStringResult("", p.err)
	}
	if len(sections) == 1 && sections[0] == "memory" {
		return redis.NewStringResult(p.memory, nil)
	}
	return redis.NewStringResult(p.server, nil)
}

// healthyPrimary is one Redis 7.2 primary with noeviction.
func healthyPrimary() fakePrimary {
	return fakePrimary{
		server: "# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n",
		memory: "# Memory\r\nmaxmemory_policy:noeviction\r\n",
	}
}

// newFakeBackend returns one healthy single-primary fake.
func newFakeBackend() *fakeBackend {
	return &fakeBackend{data: map[string]string{}, primaries: []fakePrimary{healthyPrimary()}}
}

// Do models one pinned SET argument vector.
func (f *fakeBackend) Do(_ context.Context, args ...any) *redis.Cmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.doArgs = append(f.doArgs, append([]any(nil), args...))
	if f.panicOnDo {
		panic("synthetic dispatch panic")
	}
	if f.reply != nil {
		return f.reply(args)
	}
	reply := f.applySetLocked(args)
	if f.lostReplies > 0 {
		f.lostReplies--
		reply = f.applySetLocked(args)
	}
	return reply
}

// applySetLocked applies SET key value (NX|XX) GET (PX ms|KEEPTTL).
func (f *fakeBackend) applySetLocked(args []any) *redis.Cmd {
	key, _ := args[1].(string)
	value, _ := args[2].(string)
	mode, _ := args[3].(string)
	previous, present := f.data[key]
	switch {
	case mode == "nx" && !present, mode == "xx" && present:
		f.data[key] = value
	}
	if !present {
		return redis.NewCmdResult(nil, redis.Nil)
	}
	return redis.NewCmdResult(previous, nil)
}

// EvalSha models the takeover script, or NOSCRIPT once when requested.
func (f *fakeBackend) EvalSha(_ context.Context, _ string, keys []string, args ...any) *redis.Cmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evalShaCalls++
	if f.noScript {
		f.noScript = false
		return redis.NewCmdResult(nil, redis.ErrNoScript)
	}
	return f.runScriptLocked(keys, args)
}

// Eval models the takeover script source execution.
func (f *fakeBackend) Eval(_ context.Context, _ string, keys []string, args ...any) *redis.Cmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evalCalls++
	return f.runScriptLocked(keys, args)
}

// runScriptLocked applies the compare-and-set and returns the found value.
func (f *fakeBackend) runScriptLocked(keys []string, args []any) *redis.Cmd {
	if f.scriptReply != nil {
		return f.scriptReply(keys, args)
	}
	expected, _ := args[0].(string)
	replacement, _ := args[1].(string)
	current, present := f.data[keys[0]]
	if present && current == expected {
		f.data[keys[0]] = replacement
	}
	if !present {
		return redis.NewCmdResult(nil, redis.Nil)
	}
	return redis.NewCmdResult(current, nil)
}

// EvalRO is never used by the store.
func (f *fakeBackend) EvalRO(context.Context, string, []string, ...any) *redis.Cmd {
	panic("EvalRO is not part of the replay command set")
}

// EvalShaRO is never used by the store.
func (f *fakeBackend) EvalShaRO(context.Context, string, []string, ...any) *redis.Cmd {
	panic("EvalShaRO is not part of the replay command set")
}

// ScriptExists is never used by the store.
func (f *fakeBackend) ScriptExists(context.Context, ...string) *redis.BoolSliceCmd {
	panic("ScriptExists is not part of the replay command set")
}

// ScriptLoad is never used by the store.
func (f *fakeBackend) ScriptLoad(context.Context, string) *redis.StringCmd {
	panic("ScriptLoad is not part of the replay command set")
}

// pingPrimaries returns the configured probe result.
func (f *fakeBackend) pingPrimaries(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pingPanic {
		panic("synthetic ping panic")
	}
	return f.pingErr
}

// eachPrimary inspects every configured fake primary in order.
func (f *fakeBackend) eachPrimary(ctx context.Context, inspect func(context.Context, infoClient) error) error {
	f.mu.Lock()
	primaries := append([]fakePrimary(nil), f.primaries...)
	f.mu.Unlock()
	for _, primary := range primaries {
		if err := inspect(ctx, primary); err != nil {
			return err
		}
	}
	return nil
}

// Close records one release.
func (f *fakeBackend) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCalls++
	return f.closeErr
}

// stored returns one modeled value.
func (f *fakeBackend) stored(key string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	value, ok := f.data[key]
	return value, ok
}

// setStored seeds one modeled value.
func (f *fakeBackend) setStored(key, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[key] = value
}

// lastArgs returns the most recent pinned argument vector.
func (f *fakeBackend) lastArgs() []any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.doArgs) == 0 {
		return nil
	}
	return f.doArgs[len(f.doArgs)-1]
}

// testConfig returns one valid plaintext standalone configuration.
func testConfig() Config {
	config := DefaultConfig("127.0.0.1:6379")
	config.TLS = TLSConfig{}
	config.KeyPrefix = testKeyPrefix
	return config
}

// newTestStore constructs one store over fake with deterministic nonces.
func newTestStore(t testing.TB, fake *fakeBackend, mutate ...func(*Config)) *Store {
	t.Helper()
	config := testConfig()
	for _, apply := range mutate {
		apply(&config)
	}
	store, err := newStoreWithDependencies(context.Background(), config, Secrets{}, fakeDependencies(fake))
	if err != nil {
		t.Fatalf("construct store: %v", err)
	}
	return store
}

// fakeDependencies binds one fake backend and deterministic seams.
func fakeDependencies(fake backend) dependencies {
	return dependencies{
		newBackend:  func(validatedConfig, *credentialVault, *constructionMaterial) backend { return fake },
		nonceSource: bytes.NewReader(append([]byte(nil), testNonceBytes...)),
		wallClock:   func() time.Time { return testNow },
	}
}

// testReplayKey derives one first-seen or propagation key from authentic
// public verifier evidence and returns it with its prefixed storage key.
func testReplayKey(t testing.TB, propagation bool) (dkim2.ReplayKey, string) {
	t.Helper()
	derive := (*dkim2.ReplayDeriver).Derive
	if propagation {
		derive = (*dkim2.ReplayDeriver).DerivePropagation
	}
	key := deriveVerifiedReplayKey(t, derive)
	var storage string
	if err := dkim2.UseReplayStorageKey(key, func(storageKey string) error {
		storage = testKeyPrefix + storageKey
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return key, storage
}

// testRetention returns one valid retention.
func testRetention(t testing.TB) dkim2.ReplayRetention {
	t.Helper()
	retention, err := dkim2.NewReplayRetention(1500 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	return retention
}

// testLease returns one valid lease.
func testLease(t testing.TB) dkim2.ReplayLease {
	t.Helper()
	lease, err := dkim2.NewReplayLease(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

// pendingValue renders one nonce-bearing pending value at an offset from testNow.
func pendingValue(offset time.Duration, nonce string) string {
	return "pending:" + strconv.FormatInt(testNow.Add(offset).UnixMilli(), 10) + ":" + nonce
}

// requireCode asserts one exact replay error code.
func requireCode(t testing.TB, err error, want dkim2.ReplayErrorCode) {
	t.Helper()
	if got := dkim2.ReplayErrorCodeOf(err); got != want || !dkim2.IsReplayError(err) {
		t.Fatalf("error code=%q direct=%t, want %q", got, dkim2.IsReplayError(err), want)
	}
}

// syntheticNetworkError is one non-server transport failure.
var syntheticNetworkError = io.ErrUnexpectedEOF

// syntheticServerError returns one server error reply of the given text.
func syntheticServerError(text string) error {
	return redisServerError(text)
}

// redisServerError is one test-local server error that satisfies redis.Error.
type redisServerError string

// Error returns the raw synthetic server text.
func (e redisServerError) Error() string { return string(e) }

// RedisError marks the value as a server error reply.
func (redisServerError) RedisError() {}

var _ redis.Error = redisServerError("")

// errSynthetic is one plain non-server failure.
var errSynthetic = errors.New("synthetic failure")

// deriveVerifiedReplayKey verifies the public RSA fixture and derives one
// replay key from its first identity with the supplied deriver method.
func deriveVerifiedReplayKey(
	t testing.TB,
	derive func(*dkim2.ReplayDeriver, context.Context, dkim2.ReplayIdentity) (dkim2.ReplayKey, error),
) dkim2.ReplayKey {
	t.Helper()
	return deriveReplayKeyWithSecret(t, derive, verifiedTestIdentity(t), "redisstore synthetic secret")
}

// verifiedTestIdentity verifies the public RSA fixture and returns its first
// authentic replay identity.
func verifiedTestIdentity(t testing.TB) dkim2.ReplayIdentity {
	t.Helper()
	corpusBytes, err := os.ReadFile("../../../../../lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-08/public-golden.json")
	if err != nil {
		t.Fatal("public replay corpus read failed")
	}
	var corpus struct {
		RSAModulus  string `json:"rsa_modulus_base64"`
		RSAExponent int    `json:"rsa_exponent"`
		Vectors     map[string]struct {
			Raw     string   `json:"raw_base64"`
			Reverse string   `json:"reverse_path_base64"`
			Forward []string `json:"forward_paths_base64"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(corpusBytes, &corpus); err != nil {
		t.Fatal("public replay corpus decode failed")
	}
	modulus, err := base64.StdEncoding.DecodeString(corpus.RSAModulus)
	if err != nil {
		t.Fatal("public modulus decode failed")
	}
	fixture := corpus.Vectors["rsa_pass"]
	raw, rawErr := base64.StdEncoding.DecodeString(fixture.Raw)
	reverse, reverseErr := base64.StdEncoding.DecodeString(fixture.Reverse)
	if rawErr != nil || reverseErr != nil {
		t.Fatal("public message decode failed")
	}
	forward := make([][]byte, len(fixture.Forward))
	for index, encoded := range fixture.Forward {
		if forward[index], err = base64.StdEncoding.DecodeString(encoded); err != nil {
			t.Fatal("public forward path decode failed")
		}
	}
	verifier, err := dkim2.NewVerifier(
		staticKeyProvider{key: &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: corpus.RSAExponent}},
		dkim2.WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }),
	)
	if err != nil {
		t.Fatal("public verifier construction failed")
	}
	verified, err := verifier.Verify(context.Background(), dkim2.NewVerifyRequest(raw, reverse, forward))
	if err != nil || verified.State() != dkim2.ResultStatePASS {
		t.Fatal("public replay fixture did not verify")
	}
	identities, err := dkim2.ReplayIdentities(verified)
	if err != nil {
		t.Fatal("public replay identity projection failed")
	}
	identity, err := identities.Identity(0)
	if err != nil {
		t.Fatal("public replay identity selection failed")
	}
	return identity
}

// deriveReplayKeyWithSecret derives one key for identity under a synthetic
// secret label; distinct labels yield distinct keys, and so distinct cluster
// slots, for the same authentic identity.
func deriveReplayKeyWithSecret(
	t testing.TB,
	derive func(*dkim2.ReplayDeriver, context.Context, dkim2.ReplayIdentity) (dkim2.ReplayKey, error),
	identity dkim2.ReplayIdentity,
	label string,
) dkim2.ReplayKey {
	t.Helper()
	secret := sha256.Sum256([]byte(label))
	deriver, err := dkim2.NewReplayDeriver(secret[:], 1)
	if err != nil {
		t.Fatal("public replay deriver construction failed")
	}
	defer func() { _ = deriver.Close(context.Background()) }()
	derived, err := derive(deriver, context.Background(), identity)
	if err != nil {
		t.Fatal("public replay key derivation failed")
	}
	return derived
}

// staticKeyProvider returns one frozen synthetic RSA public key.
type staticKeyProvider struct {
	key *rsa.PublicKey
}

// LookupPublicKey supplies one algorithm-bounded public key.
func (p staticKeyProvider) LookupPublicKey(_ context.Context, query dkim2.PublicKeyQuery) (dkim2.PublicKeyResult, error) {
	if query.Algorithm() != dkim2.AlgorithmRSASHA256 {
		return dkim2.MissingPublicKey(query.Algorithm()), nil
	}
	return dkim2.FoundRSAPublicKey(p.key), nil
}

// reflectMethodCount returns the method-set size of one interface type.
func reflectMethodCount[T any]() int {
	return reflect.TypeFor[T]().NumMethod()
}
