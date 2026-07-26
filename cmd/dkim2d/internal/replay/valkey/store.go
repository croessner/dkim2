// Package valkey implements the daemon-owned Valkey replay-store provider.
package valkey

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	dkim2 "github.com/croessner/dkim2"
	valkeygo "github.com/valkey-io/valkey-go"
)

const (
	maximumReplyBytes = 4 * 1024
	maximumKindBytes  = 32
	okCacheFrameBytes = 18
)

const storeRedactedText = "valkey_replay_store"

const (
	serverKindASK      = "ASK"
	serverKindMOVED    = "MOVED"
	serverKindOOM      = "OOM"
	serverKindTRYAGAIN = "TRYAGAIN"
	serverKindBUSY     = "BUSY"
)

// command is one completed replay write whose retryability is inspectable.
type command interface {
	IsRetryable() bool
}

// commandClient owns command construction and one dispatch operation.
type commandClient interface {
	BuildSet(string, string, int64) command
	Do(context.Context, command) resultReader
}

// resultReader exposes only the lossless bounded projections needed for mapping.
type resultReader interface {
	NonValkeyError() error
	ToString() (string, error)
	ToMessage() (valkeygo.ValkeyMessage, error)
}

// nativeClient is the exact subset of valkey.Client used by the command adapter.
type nativeClient interface {
	B() valkeygo.Builder
	Do(context.Context, valkeygo.Completed) valkeygo.ValkeyResult
}

// nativeCommand retains one concrete non-retryable completed command until dispatch.
type nativeCommand struct {
	completed valkeygo.Completed
}

// IsRetryable delegates to the pinned client command flag.
func (c nativeCommand) IsRetryable() bool { return c.completed.IsRetryable() }

// valkeyCommandClient adapts the pinned concrete client to the narrow store seam.
type valkeyCommandClient struct {
	client nativeClient
}

// BuildSet constructs exactly one ordinary SET key v1 NX PX milliseconds command.
func (c valkeyCommandClient) BuildSet(key, marker string, milliseconds int64) command {
	return nativeCommand{
		completed: c.client.B().
			Set().
			Key(key).
			Value(marker).
			Nx().
			PxMilliseconds(milliseconds).
			Build(),
	}
}

// Do dispatches only the concrete command produced by BuildSet.
func (c valkeyCommandClient) Do(ctx context.Context, candidate command) resultReader {
	completed, ok := candidate.(nativeCommand)
	if !ok {
		return impossibleResult{}
	}
	return concreteResult{result: c.client.Do(ctx, completed.completed)}
}

// concreteResult delegates to one non-pointer valkey.ValkeyResult value.
type concreteResult struct {
	result valkeygo.ValkeyResult
}

// NonValkeyError returns only the concrete client's transport or client failure.
func (r concreteResult) NonValkeyError() error { return r.result.NonValkeyError() }

// ToString returns the concrete result's original lossless scalar value and error.
func (r concreteResult) ToString() (string, error) { return r.result.ToString() }

// ToMessage returns the concrete result message for the exact OK type proof.
func (r concreteResult) ToMessage() (valkeygo.ValkeyMessage, error) {
	return r.result.ToMessage()
}

// impossibleResult represents a local adapter contradiction without raw detail.
type impossibleResult struct{}

// NonValkeyError keeps the contradiction out of transport classification.
func (impossibleResult) NonValkeyError() error { return nil }

// ToString returns an impossible direct error without protected detail.
func (impossibleResult) ToString() (string, error) {
	return "", dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
}

// ToMessage never supplies a message for an impossible adapter result.
func (impossibleResult) ToMessage() (valkeygo.ValkeyMessage, error) {
	return valkeygo.ValkeyMessage{}, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
}

// recoveryClass identifies how one degraded provider may return to ready.
type recoveryClass uint32

const (
	recoveryNone recoveryClass = iota
	recoveryTransient
	recoveryRevalidation
	recoveryRestart
)

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
	client              commandClient
	facts               recoveryFacts
	gate                *admissionGate
	securityEnforced    bool
	evidence            evidenceState
	clock               *serializedSecurityClock
	authority           *auditAuthority
	applicationUsername *string
	attestation         *OperatorAttestation
	auditWireFactory    auditWireFactory
	revalidation        atomic.Bool
	ownedClient         ownedApplicationClient
	closeOnce           sync.Once
	closeMu             sync.Mutex
	closeErr            error
}

// CheckAndRemember issues exactly one non-retryable SET NX PX after strict preflight.
func (s *Store) CheckAndRemember(
	ctx context.Context,
	key dkim2.ReplayKey,
	retention dkim2.ReplayRetention,
) (check dkim2.ReplayCheck, resultErr error) {
	if err := preflightContext(ctx); err != nil {
		s.publishPreflightFailure(err)
		return 0, err
	}
	if s == nil || s.storeCore == nil {
		return 0, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
	}
	switch s.lifecycleState() {
	case lifecycleClosing, lifecycleClosed:
		return 0, dkim2.NewReplayError(dkim2.ReplayErrorClosed)
	case lifecycleReady:
	default:
		s.publishFailure(recoveryRestart)
		return 0, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	if !retention.Valid() {
		return 0, dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
	}

	completed, finish, err := s.buildCommand(ctx, key, retention)
	if err != nil {
		if dkim2.ReplayErrorCodeOf(err) == dkim2.ReplayErrorInternalInvariant {
			s.publishFailure(recoveryRestart)
		}
		return 0, err
	}
	if finish == nil {
		s.publishFailure(recoveryRestart)
		return 0, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	defer finish()
	if err := preflightContext(ctx); err != nil {
		s.publishPreflightFailure(err)
		return 0, err
	}

	outcome := s.dispatch(ctx, completed)
	if outcome.err == nil {
		s.publishSuccess()
		return outcome.check, nil
	}
	s.publishFailure(outcome.recovery)
	return 0, outcome.err
}

// buildCommand contains pre-dispatch callback and client-builder panics.
func (s *Store) buildCommand(
	ctx context.Context,
	key dkim2.ReplayKey,
	retention dkim2.ReplayRetention,
) (completed command, finish func(), resultErr error) {
	defer func() {
		if recover() != nil {
			if finish != nil {
				finish()
			}
			completed = nil
			finish = nil
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	if s == nil || s.storeCore == nil {
		return nil, nil, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	if err := dkim2.UseReplayStorageKey(key, func(storageKey string) error {
		if evidenceErr := s.requireFreshSecurityEvidence(); evidenceErr != nil {
			return evidenceErr
		}
		var err error
		finish, err = s.gate.admit(ctx)
		if err != nil {
			return err
		}
		if evidenceErr := s.requireFreshSecurityEvidence(); evidenceErr != nil {
			return evidenceErr
		}
		if nilInterface(s.client) {
			return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
		completed = s.client.BuildSet(storageKey, dkim2.ReplayStoredValue, retention.Milliseconds())
		if nilInterface(completed) || completed.IsRetryable() {
			return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
		return nil
	}); err != nil {
		if finish != nil {
			finish()
		}
		return nil, nil, err
	}
	return completed, finish, nil
}

// requireFreshSecurityEvidence enforces the exact live-audit freshness boundary.
func (s *Store) requireFreshSecurityEvidence() error {
	if !s.securityEnforced {
		return nil
	}
	var fresh bool
	err := s.clock.withSample(func(now time.Time) error {
		var observeErr error
		fresh, observeErr = s.evidence.observeSample(now)
		if observeErr == nil && !fresh {
			s.publishStaleEvidenceFailure()
		}
		return observeErr
	})
	if err != nil {
		s.publishFailure(recoveryRestart)
		return err
	}
	if !fresh {
		return dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
	}
	return nil
}

// publishPreflightFailure records only hostile context contradictions as restart-sticky.
func (s *Store) publishPreflightFailure(err error) {
	if s != nil && s.storeCore != nil &&
		dkim2.ReplayErrorCodeOf(err) == dkim2.ReplayErrorInternalInvariant {
		s.publishFailure(recoveryRestart)
	}
}

// mappingOutcome keeps one closed result/error/recovery triple coherent.
type mappingOutcome struct {
	check    dkim2.ReplayCheck
	recovery recoveryClass
	err      error
}

// dispatch owns the post-boundary panic and uncertainty mapping.
func (s *Store) dispatch(ctx context.Context, completed command) (outcome mappingOutcome) {
	defer func() {
		if recover() != nil {
			outcome = replayFailure(dkim2.ReplayErrorIndeterminate, recoveryRestart)
		}
	}()

	result := s.client.Do(ctx, completed)
	if nilInterface(result) {
		return replayFailure(dkim2.ReplayErrorInternalInvariant, recoveryRestart)
	}
	return mapResult(result)
}

// mapResult applies the exact ordered lossless Valkey result mapping.
func mapResult(result resultReader) mappingOutcome {
	if result.NonValkeyError() != nil {
		return replayFailure(dkim2.ReplayErrorIndeterminate, recoveryTransient)
	}

	raw, err := result.ToString()
	if len(raw) > maximumReplyBytes {
		return replayFailure(dkim2.ReplayErrorInconsistent, recoveryRestart)
	}
	if err == nil {
		if raw != "OK" {
			return replayFailure(dkim2.ReplayErrorInconsistent, recoveryRestart)
		}
		return mapOK(result)
	}
	if valkeygo.IsValkeyNil(err) {
		if raw != "" {
			return replayFailure(dkim2.ReplayErrorInternalInvariant, recoveryRestart)
		}
		return replaySuccess(dkim2.ReplayCheckReplayed)
	}

	serverError, direct := err.(*valkeygo.ValkeyError)
	if !direct || serverError == nil {
		if valkeygo.IsParseErr(err) {
			return replayFailure(dkim2.ReplayErrorInconsistent, recoveryRestart)
		}
		return replayFailure(dkim2.ReplayErrorInternalInvariant, recoveryRestart)
	}
	kind, valid := leadingErrorKind(raw)
	if !valid {
		return replayFailure(dkim2.ReplayErrorInconsistent, recoveryRestart)
	}
	return mapServerKind(kind)
}

// mapOK proves exact simple-string OK with the pinned v1.0.76 cache frame.
func mapOK(result resultReader) mappingOutcome {
	message, err := result.ToMessage()
	if err != nil {
		return replayFailure(dkim2.ReplayErrorInternalInvariant, recoveryRestart)
	}
	if !message.IsString() {
		return replayFailure(dkim2.ReplayErrorInconsistent, recoveryRestart)
	}
	if message.CacheSize() != okCacheFrameBytes {
		return replayFailure(dkim2.ReplayErrorInternalInvariant, recoveryRestart)
	}
	frame := message.CacheMarshal(make([]byte, 0, okCacheFrameBytes))
	if len(frame) != okCacheFrameBytes {
		return replayFailure(dkim2.ReplayErrorInternalInvariant, recoveryRestart)
	}
	for _, value := range frame[:7] {
		if value != 0 {
			return replayFailure(dkim2.ReplayErrorInternalInvariant, recoveryRestart)
		}
	}
	if binary.BigEndian.Uint64(frame[8:16]) != 2 ||
		frame[16] != 'O' ||
		frame[17] != 'K' {
		return replayFailure(dkim2.ReplayErrorInternalInvariant, recoveryRestart)
	}
	switch frame[7] {
	case '+':
		return replaySuccess(dkim2.ReplayCheckFirstSeen)
	case '$':
		return replayFailure(dkim2.ReplayErrorInconsistent, recoveryRestart)
	default:
		return replayFailure(dkim2.ReplayErrorInternalInvariant, recoveryRestart)
	}
}

// leadingErrorKind extracts one exact bounded ASCII server-error token.
func leadingErrorKind(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	end := len(raw)
	if index := indexASCIIByte(raw, ' '); index >= 0 {
		end = index
	}
	if end < 1 || end > maximumKindBytes {
		return "", false
	}
	for index := range end {
		value := raw[index]
		if index == 0 {
			if value < 'A' || value > 'Z' {
				return "", false
			}
			continue
		}
		if (value < 'A' || value > 'Z') &&
			(value < '0' || value > '9') &&
			value != '_' {
			return "", false
		}
	}
	if end < len(raw) && raw[end] != ' ' {
		return "", false
	}
	return raw[:end], true
}

// indexASCIIByte locates one byte without classifying any reply suffix.
func indexASCIIByte(value string, target byte) int {
	for index := range len(value) {
		if value[index] == target {
			return index
		}
	}
	return -1
}

// mapServerKind maps one extracted kind without inspecting its suffix.
func mapServerKind(kind string) mappingOutcome {
	switch kind {
	case serverKindOOM:
		return replayFailure(dkim2.ReplayErrorLimitExceeded, recoveryRevalidation)
	case "NOAUTH", "WRONGPASS":
		return replayFailure(dkim2.ReplayErrorUnavailable, recoveryRestart)
	case "NOPERM", "READONLY", "MISCONF", "NOREPLICAS",
		"MASTERDOWN", "CLUSTERDOWN", "LOADING", serverKindMOVED, serverKindASK:
		return replayFailure(dkim2.ReplayErrorUnavailable, recoveryRevalidation)
	case serverKindTRYAGAIN, serverKindBUSY:
		return replayFailure(dkim2.ReplayErrorUnavailable, recoveryTransient)
	default:
		return replayFailure(dkim2.ReplayErrorInconsistent, recoveryRestart)
	}
}

// replaySuccess constructs one authoritative successful mapping.
func replaySuccess(check dkim2.ReplayCheck) mappingOutcome {
	return mappingOutcome{check: check}
}

// replayFailure constructs one zero-result bounded failure mapping.
func replayFailure(code dkim2.ReplayErrorCode, recovery recoveryClass) mappingOutcome {
	return mappingOutcome{
		recovery: recovery,
		err:      dkim2.NewReplayError(code),
	}
}

// publishFailure monotonically records the strongest observed recovery requirement.
func (s *Store) publishFailure(class recoveryClass) {
	if s == nil || s.storeCore == nil {
		return
	}
	s.facts.add(class)
}

// publishStaleEvidenceFailure records audit freshness loss without drift versioning.
func (s *Store) publishStaleEvidenceFailure() {
	if s == nil || s.storeCore == nil {
		return
	}
	s.facts.addStaleEvidence()
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
	recovery := s.strongestRecovery()
	return s.stateAfterRecovery(recovery)
}

// AuthorityReady reports fresh undegraded provider authority without datastore I/O.
func (s *Store) AuthorityReady() bool {
	if s == nil || s.storeCore == nil || s.gate == nil ||
		!s.securityEnforced || s.clock == nil ||
		s.lifecycleState() != lifecycleReady {
		return false
	}
	fresh := false
	err := s.clock.withSample(func(now time.Time) error {
		var observeErr error
		fresh, observeErr = s.evidence.observeSample(now)
		if observeErr == nil && !fresh {
			s.publishStaleEvidenceFailure()
		}
		return observeErr
	})
	if err != nil {
		s.publishFailure(recoveryRestart)
		return false
	}
	if !fresh ||
		s.lifecycleState() != lifecycleReady ||
		s.strongestRecovery() != recoveryNone {
		return false
	}
	return s.lifecycleState() == lifecycleReady &&
		s.strongestRecovery() == recoveryNone
}

// stateAfterRecovery rechecks terminal lifecycle after the recovery snapshot.
func (s *Store) stateAfterRecovery(recovery recoveryClass) dkim2.ReplayStoreState {
	switch s.gate.stateValue() {
	case lifecycleClosing:
		return dkim2.ReplayStoreClosing
	case lifecycleClosed:
		return dkim2.ReplayStoreClosed
	case lifecycleReady:
	default:
		return dkim2.ReplayStoreDegraded
	}
	switch recovery {
	case recoveryNone:
		return dkim2.ReplayStoreReady
	case recoveryTransient, recoveryRevalidation, recoveryRestart:
		return dkim2.ReplayStoreDegraded
	default:
		return dkim2.ReplayStoreDegraded
	}
}

// lifecycleState returns one bounded internal lifecycle snapshot.
func (s *Store) lifecycleState() lifecycleState {
	if s == nil || s.storeCore == nil || s.gate == nil {
		return 0
	}
	return s.gate.stateValue()
}

// strongestRecovery projects independent facts into the closed recovery class.
func (s *Store) strongestRecovery() recoveryClass {
	if s == nil || s.storeCore == nil {
		return recoveryRestart
	}
	bits := s.facts.load()
	switch {
	case bits&recoveryRestartBit != 0:
		return recoveryRestart
	case bits&(recoveryRevalidationBit|recoveryStaleEvidenceBit) != 0:
		return recoveryRevalidation
	case bits&recoveryTransientBit != 0:
		return recoveryTransient
	default:
		return recoveryNone
	}
}

// preflightContext maps context state before command construction or dispatch.
func preflightContext(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	if nilInterface(ctx) {
		return dkim2.NewReplayError(dkim2.ReplayErrorInvalidRequest)
	}
	switch ctx.Err() {
	case nil:
		deadline, present := ctx.Deadline()
		if present && !time.Now().Before(deadline) {
			return dkim2.NewReplayError(dkim2.ReplayErrorDeadlineExceeded)
		}
		return nil
	case context.Canceled:
		return dkim2.NewReplayError(dkim2.ReplayErrorCancelled)
	case context.DeadlineExceeded:
		return dkim2.NewReplayError(dkim2.ReplayErrorDeadlineExceeded)
	default:
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
}

// nilInterface reports nil-interface and typed-nil values without invoking them.
func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
