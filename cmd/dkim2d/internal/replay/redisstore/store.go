// Package redisstore implements the daemon-owned Redis-compatible replay-store
// provider for standalone, Sentinel, and cluster deployments.
//
// Every write embeds a per-operation random nonce in the value it stores, so
// a write that go-redis retries after a lost reply recognizes its own earlier
// commit instead of reporting a foreign record. Outcomes that cannot be proven
// fail closed as indeterminate.
package redisstore

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	dkim2 "github.com/croessner/dkim2"
	"github.com/redis/go-redis/v9"
)

const storeRedactedText = "redis_replay_store"

// storeRedaction owns value-safe privacy methods without copying Store synchronization state.
type storeRedaction struct{}

// String returns one content-free provider representation.
func (storeRedaction) String() string { return storeRedactedText }

// GoString returns one content-free provider representation.
func (storeRedaction) GoString() string { return storeRedactedText }

// Format prevents formatting verbs from exposing client or result state.
func (storeRedaction) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, storeRedactedText)
}

// MarshalText rejects serialization of provider state.
func (storeRedaction) MarshalText() ([]byte, error) {
	return nil, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
}

// MarshalJSON rejects serialization of provider state.
func (storeRedaction) MarshalJSON() ([]byte, error) {
	return nil, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
}

// Store applies the storage-neutral replay contract through one shared private core.
type Store struct {
	storeRedaction
	*storeCore
}

// storeCore owns all mutable state so copied public Store values share one lifecycle.
type storeCore struct {
	client           backend
	script           *redis.Script
	facts            recoveryFacts
	gate             *admissionGate
	nonceSource      io.Reader
	wallClock        func() time.Time
	keyPrefix        string
	singleAttempt    bool
	minimumRetention time.Duration
	maximumRetention time.Duration
	healthTimeout    time.Duration
	healthThreshold  uint32
	probeFailures    atomic.Uint32
	vault            *credentialVault
	closeOnce        sync.Once
	closeMu          sync.Mutex
	closeErr         error
}

// dependencies contains package-private deterministic construction seams.
type dependencies struct {
	newBackend  func(validatedConfig, *credentialVault, *constructionMaterial) backend
	nonceSource io.Reader
	wallClock   func() time.Time
}

// NewStore validates config and secrets, constructs the go-redis client, and
// runs the startup checks (PING, version floor, eviction policy on every
// primary) before returning. A returned store has passed every check and is
// ready; on any failure the client is closed and no store is returned.
func NewStore(ctx context.Context, config Config, secrets Secrets) (*Store, error) {
	return newStoreWithDependencies(ctx, config, secrets, dependencies{
		newBackend: func(validated validatedConfig, vault *credentialVault, material *constructionMaterial) backend {
			return newProductionBackend(validated, vault, material.config, material.sentinelPassword, nil)
		},
	})
}

// constructionMaterial carries the transport material that exists only during
// client construction; the Sentinel password copy is cleared afterwards.
type constructionMaterial struct {
	config           *tls.Config
	sentinelPassword []byte
}

// newStoreWithDependencies provides deterministic package-private construction tests.
func newStoreWithDependencies(
	ctx context.Context,
	config Config,
	secrets Secrets,
	deps dependencies,
) (store *Store, resultErr error) {
	if err := preflightContext(ctx); err != nil {
		return nil, err
	}
	validated, err := validateConfig(config)
	if err != nil {
		return nil, err
	}
	if err := validateSentinelPassword(validated, secrets.SentinelPassword); err != nil {
		return nil, err
	}
	tlsConfig, err := buildTLSConfig(validated.tls, secrets)
	if err != nil {
		return nil, err
	}
	vault, err := newCredentialVault(validated.username, secrets.Password)
	if err != nil {
		return nil, err
	}
	if deps.newBackend == nil {
		vault.clear()
		return nil, misconfigured()
	}
	material := &constructionMaterial{config: tlsConfig, sentinelPassword: append([]byte(nil), secrets.SentinelPassword...)}
	client, err := callBackendFactory(deps.newBackend, validated, vault, material)
	clear(material.sentinelPassword)
	if err != nil {
		vault.clear()
		return nil, err
	}
	store = &Store{storeCore: &storeCore{
		client:           client,
		script:           redis.NewScript(leaseTakeoverScriptSource),
		gate:             newAdmissionGate(validated.limits.MaxInFlight, validated.limits.MaxAdmissionWaiters),
		nonceSource:      deps.nonceSource,
		wallClock:        deps.wallClock,
		keyPrefix:        validated.keyPrefix,
		singleAttempt:    validated.singleAttempt(),
		minimumRetention: validated.minimumRetention,
		maximumRetention: validated.maximumRetention,
		healthTimeout:    validated.health.Timeout,
		healthThreshold:  uint32(validated.health.FailureThreshold), //nolint:gosec // Validated to 1..10.
		vault:            vault,
	}}
	if err := runStartupChecks(ctx, client, validated.requireNoEviction); err != nil {
		if closeErr := store.release(); closeErr != nil &&
			dkim2.ReplayErrorCodeOf(closeErr) == dkim2.ReplayErrorInternalInvariant {
			return nil, closeErr
		}
		return nil, err
	}
	return store, nil
}

// callBackendFactory contains client-construction panics and typed-nil results.
func callBackendFactory(
	factory func(validatedConfig, *credentialVault, *constructionMaterial) backend,
	config validatedConfig,
	vault *credentialVault,
	material *constructionMaterial,
) (client backend, resultErr error) {
	defer func() {
		if recover() != nil {
			if !nilInterface(client) {
				_ = closeBackend(client)
			}
			client = nil
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	client = factory(config, vault, material)
	if nilInterface(client) {
		return nil, misconfigured()
	}
	return client, nil
}

// CheckAndRemember atomically inserts one nonce-bearing first-seen value with
// SET NX GET PX after strict preflight. A nil previous value or the store's
// own value from an earlier attempt of the same operation is first seen; any
// other valid first-seen value is replayed.
func (s *Store) CheckAndRemember(
	ctx context.Context,
	key dkim2.ReplayKey,
	retention dkim2.ReplayRetention,
) (dkim2.ReplayCheck, error) {
	if err := s.admitOperation(ctx); err != nil {
		return 0, err
	}
	if !s.retentionAllowed(retention) {
		return 0, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
	}
	nonce, err := s.newNonce()
	if err != nil {
		return 0, err
	}
	own, err := dkim2.ReplayFirstSeenValue(nonce)
	if err != nil {
		s.publishFailure(recoveryRestart)
		return 0, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	command, finish, err := s.buildKeyedCommand(ctx, key, func(storageKey string) pinnedCommand {
		return insertIfAbsentCommand(storageKey, own, retention.Milliseconds())
	})
	if err != nil {
		return 0, err
	}
	defer finish()
	if err := preflightContext(ctx); err != nil {
		s.publishPreflightFailure(err)
		return 0, err
	}
	outcome := s.dispatch(ctx, func(ctx context.Context) *redis.Cmd { return command.run(ctx, s.client) })
	if outcome.err != nil {
		s.publishFailure(outcome.recovery)
		return 0, outcome.err
	}
	if !outcome.present || outcome.previous == own {
		s.publishSuccess()
		return dkim2.ReplayCheckFirstSeen, nil
	}
	if _, _, ok := dkim2.ParseReplayFirstSeenValue(outcome.previous); !ok {
		s.publishFailure(recoveryRestart)
		return 0, dkim2.NewReplayError(dkim2.ReplayErrorInconsistent)
	}
	s.publishSuccess()
	return dkim2.ReplayCheckReplayed, nil
}

// admitOperation applies the shared preflight and lifecycle refusals.
func (s *Store) admitOperation(ctx context.Context) error {
	if err := preflightContext(ctx); err != nil {
		s.publishPreflightFailure(err)
		return err
	}
	if s == nil || s.storeCore == nil {
		return dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
	}
	switch s.lifecycleState() {
	case lifecycleClosing, lifecycleClosed:
		return dkim2.NewReplayError(dkim2.ReplayErrorClosed)
	case lifecycleReady:
		return nil
	default:
		s.publishFailure(recoveryRestart)
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
}

// retentionAllowed reports whether one retention is valid and inside the configured bounds.
func (s *Store) retentionAllowed(retention dkim2.ReplayRetention) bool {
	if !retention.Valid() {
		return false
	}
	duration := time.Duration(retention.Milliseconds()) * time.Millisecond
	return duration >= s.minimumRetention && duration <= s.maximumRetention
}

// newNonce draws one per-operation write nonce; a failing source is an
// internal invariant and makes the store restart-degraded.
func (s *Store) newNonce() (nonce dkim2.ReplayNonce, resultErr error) {
	defer func() {
		if recover() != nil {
			nonce = dkim2.ReplayNonce{}
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
			s.publishFailure(recoveryRestart)
		}
	}()
	nonce, err := dkim2.NewReplayNonce(s.nonceSource)
	if err != nil {
		s.publishFailure(recoveryRestart)
		return dkim2.ReplayNonce{}, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	return nonce, nil
}

// buildKeyedCommand admits one operation and builds its first command under
// the protected-key seam with the configured key prefix; it contains
// pre-dispatch callback and builder panics.
func (s *Store) buildKeyedCommand(
	ctx context.Context,
	key dkim2.ReplayKey,
	build func(storageKey string) pinnedCommand,
) (command pinnedCommand, finish func(), resultErr error) {
	defer func() {
		if recover() != nil {
			if finish != nil {
				finish()
			}
			command = pinnedCommand{}
			finish = nil
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
			s.publishFailure(recoveryRestart)
		}
	}()
	if err := dkim2.UseReplayStorageKey(key, func(storageKey string) error {
		var err error
		finish, err = s.gate.admit(ctx)
		if err != nil {
			return err
		}
		if nilInterface(s.client) || build == nil {
			return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
		command = build(s.keyPrefix + storageKey)
		if len(command.args) == 0 {
			return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
		return nil
	}); err != nil {
		if finish != nil {
			finish()
		}
		if dkim2.ReplayErrorCodeOf(err) == dkim2.ReplayErrorInternalInvariant {
			s.publishFailure(recoveryRestart)
		}
		return pinnedCommand{}, nil, err
	}
	if finish == nil {
		s.publishFailure(recoveryRestart)
		return pinnedCommand{}, nil, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	return command, finish, nil
}

// dispatch owns the post-boundary panic and uncertainty mapping of one write.
// A panic after dispatch may follow a commit and is therefore indeterminate.
func (s *Store) dispatch(ctx context.Context, send func(context.Context) *redis.Cmd) (outcome valueOutcome) {
	defer func() {
		if recover() != nil {
			outcome = valueFailure(dkim2.ReplayErrorIndeterminate, recoveryRestart)
		}
	}()
	return mapValueReply(send(ctx), s.singleAttempt)
}

// publishPreflightFailure records only hostile context contradictions as restart-sticky.
func (s *Store) publishPreflightFailure(err error) {
	if dkim2.ReplayErrorCodeOf(err) == dkim2.ReplayErrorInternalInvariant {
		s.publishFailure(recoveryRestart)
	}
}

// publishFailure records the observed recovery requirement.
func (s *Store) publishFailure(class recoveryClass) {
	if s == nil || s.storeCore == nil {
		return
	}
	s.facts.add(class)
}

// publishSuccess clears only transient degradation after authoritative completion.
func (s *Store) publishSuccess() {
	if s == nil || s.storeCore == nil {
		return
	}
	s.facts.clearTransient()
}

// State returns one bounded lock-free provider state.
func (s *Store) State() dkim2.ReplayStoreState {
	if s == nil || s.storeCore == nil || s.gate == nil {
		return dkim2.ReplayStoreDegraded
	}
	recovery := s.facts.strongest()
	switch s.gate.stateValue() {
	case lifecycleClosing:
		return dkim2.ReplayStoreClosing
	case lifecycleClosed:
		return dkim2.ReplayStoreClosed
	case lifecycleReady:
	default:
		return dkim2.ReplayStoreDegraded
	}
	if recovery != recoveryNone {
		return dkim2.ReplayStoreDegraded
	}
	return dkim2.ReplayStoreReady
}

// AuthorityReady reports ready lifecycle without any recovery fact. It
// performs no datastore I/O; startup checks already passed in NewStore and
// the health probe maintains the transient fact.
func (s *Store) AuthorityReady() bool {
	return s != nil && s.storeCore != nil && s.gate != nil &&
		s.lifecycleState() == lifecycleReady &&
		s.facts.strongest() == recoveryNone
}

// lifecycleState returns one bounded internal lifecycle snapshot.
func (s *Store) lifecycleState() lifecycleState {
	if s == nil || s.storeCore == nil || s.gate == nil {
		return 0
	}
	return s.gate.stateValue()
}

// Close publishes terminal state, drains admitted work, and closes ownership once.
func (s *Store) Close(ctx context.Context) error {
	if err := preflightContext(ctx); err != nil {
		return err
	}
	if s == nil || s.storeCore == nil || s.gate == nil {
		return misconfigured()
	}
	drained, err := s.gate.beginClose()
	if err != nil {
		return err
	}
	if err := waitAdmissionDrain(ctx, drained); err != nil {
		return err
	}
	if !s.gate.publishClosed() {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	return s.release()
}

// release closes the owned client and clears credentials exactly once.
func (s *Store) release() error {
	s.closeOnce.Do(func() {
		s.closeMu.Lock()
		defer s.closeMu.Unlock()
		if !nilInterface(s.client) {
			s.closeErr = closeBackend(s.client)
		}
		s.client = nil
		s.vault.clear()
	})
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closeErr
}

// closeBackend contains client cleanup panics and raw errors.
func closeBackend(client backend) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	if err := client.Close(); err != nil {
		return dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
	}
	return nil
}

var _ dkim2.ManagedReplayStore = (*Store)(nil)
