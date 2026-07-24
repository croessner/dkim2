package valkey

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	dkim2 "github.com/croessner/dkim2"
)

const (
	syntheticAuditUsername       = "audit_user"
	syntheticAuditPassword       = "audit-password"
	syntheticApplicationUsername = "application_user"
	syntheticPasswordHash        = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	syntheticDeadlineName        = "deadline"
	syntheticReplicaIP           = "127.0.0.2"
)

// auditReply injects one bounded wire result into the private security auditor.
type auditReply struct {
	value resp2Value
	err   error
}

// fakeAuditWire records the closed command inventory without retaining raw replies.
type fakeAuditWire struct {
	mu            sync.Mutex
	replies       []auditReply
	requests      []auditRequest
	aliases       []auditRequest
	deadlines     []time.Duration
	closeCalls    int
	closeErr      error
	closePanic    bool
	roundTripHook func(int)
}

// roundTrip returns the next injected reply and records only the closed request.
func (w *fakeAuditWire) roundTrip(ctx context.Context, request auditRequest) (resp2Value, error) {
	w.mu.Lock()
	index := len(w.requests)
	w.requests = append(w.requests, cloneAuditRequest(request))
	w.aliases = append(w.aliases, request)
	if deadline, ok := ctx.Deadline(); ok {
		w.deadlines = append(w.deadlines, time.Until(deadline))
	} else {
		w.deadlines = append(w.deadlines, 0)
	}
	hook := w.roundTripHook
	if index >= len(w.replies) {
		w.mu.Unlock()
		return resp2Value{}, errors.New("synthetic exhausted audit reply")
	}
	reply := w.replies[index]
	w.mu.Unlock()
	if hook != nil {
		hook(index)
	}
	return reply.value, reply.err
}

// protectedBuffersCleared proves the runner erased request and reply aliases.
func (w *fakeAuditWire) protectedBuffersCleared() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.aliases) == 0 || len(w.aliases[0].arguments) != 2 {
		return false
	}
	for _, request := range w.aliases {
		for _, argument := range request.arguments {
			for _, value := range argument {
				if value != 0 {
					return false
				}
			}
		}
	}
	for _, reply := range w.replies {
		if !auditValueBytesCleared(reply.value) {
			return false
		}
	}
	return true
}

// auditValueBytesCleared checks every scalar alias recursively.
func auditValueBytesCleared(value resp2Value) bool {
	for _, character := range value.bytes {
		if character != 0 {
			return false
		}
	}
	for _, child := range value.values {
		if !auditValueBytesCleared(child) {
			return false
		}
	}
	return true
}

// Close records exact auditor cleanup and injects bounded cleanup behavior.
func (w *fakeAuditWire) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closeCalls++
	if w.closePanic {
		panic("synthetic auditor close panic")
	}
	return w.closeErr
}

// snapshot returns stable copies of the fake's bounded observations.
func (w *fakeAuditWire) snapshot() ([]auditRequest, []time.Duration, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	requests := make([]auditRequest, len(w.requests))
	for index := range w.requests {
		requests[index] = cloneAuditRequest(w.requests[index])
	}
	return requests, append([]time.Duration(nil), w.deadlines...), w.closeCalls
}

// cloneAuditRequest prevents later credential clearing from changing the test observation.
func cloneAuditRequest(request auditRequest) auditRequest {
	cloned := request
	cloned.arguments = make([][]byte, len(request.arguments))
	for index := range request.arguments {
		cloned.arguments[index] = append([]byte(nil), request.arguments[index]...)
	}
	return cloned
}

// TestSecurityAuditorUsesExactSequentialInventory verifies the frozen eleven-command plan.
func TestSecurityAuditorUsesExactSequentialInventory(t *testing.T) {
	wire := &fakeAuditWire{replies: validAuditReplies()}
	err := runSecurityAudit(
		context.Background(),
		wire,
		validAuditCredentials(),
		validSecurityAuditPolicy(),
		auditPhaseConstruction,
	)
	if err != nil {
		t.Fatalf("security audit failed with code %q", dkim2.ReplayErrorCodeOf(err))
	}

	requests, deadlines, closeCalls := wire.snapshot()
	wantCommands := []auditCommand{
		auditCommandAuth,
		auditCommandRole,
		auditCommandConfigGet,
		auditCommandInfoMemory,
		auditCommandInfoPersistence,
		auditCommandInfoReplication,
		auditCommandInfoCluster,
		auditCommandACLGetUser,
		auditCommandACLDryRunPing,
		auditCommandACLDryRunInNamespaceSet,
		auditCommandACLDryRunOutOfNamespaceSet,
	}
	if len(requests) != len(wantCommands) {
		t.Fatalf("command count = %d, want %d", len(requests), len(wantCommands))
	}
	for index, want := range wantCommands {
		if requests[index].command != want {
			t.Fatalf("command %d = %q, want %q", index+1, requests[index].command, want)
		}
		if deadlines[index] <= 0 || deadlines[index] > 2*time.Second {
			t.Fatalf("command %d deadline = %s, want (0,2s]", index+1, deadlines[index])
		}
	}
	if closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", closeCalls)
	}
	assertAuditArguments(t, requests)
	if !wire.protectedBuffersCleared() {
		t.Fatal("auditor request or reply aliases retained protected bytes")
	}
}

// TestSecurityAuditorAcceptsAttestationProjection verifies the managed policy bridge.
func TestSecurityAuditorAcceptsAttestationProjection(t *testing.T) {
	policy := securityAuditPolicyFrom(mustOperatorAttestation(t), syntheticApplicationUsername)
	snapshot := auditSnapshot{}
	for index, reply := range validAuditReplies() {
		command := auditCommand(index + 1)
		if validation := validateAuditReply(command, reply.value, policy, &snapshot); validation != auditAccepted {
			t.Fatalf("command %d validation = %d, want accepted; policy=%q/%q/%q/%d/%d snapshot=%+v",
				index+1,
				validation,
				policy.persistenceMode,
				policy.appendFsyncPolicy,
				policy.saveSchedule,
				policy.minReplicasToWrite,
				policy.minReplicasMaxLagSeconds,
				snapshot,
			)
		}
	}
	if snapshot.roleReplicas != snapshot.connectedReplicas {
		t.Fatal("valid attestation projection disagrees across probes")
	}
}

// TestSecurityAuditorStopsAuthenticationFailure verifies AUTH is command one and fail-closed.
func TestSecurityAuditorStopsAuthenticationFailure(t *testing.T) {
	wire := &fakeAuditWire{replies: []auditReply{{
		value: errorAuditValue("WRONGPASS synthetic protected suffix"),
	}}}
	err := runSecurityAudit(
		context.Background(),
		wire,
		validAuditCredentials(),
		validSecurityAuditPolicy(),
		auditPhaseConstruction,
	)
	requests, _, closeCalls := wire.snapshot()
	if dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorMisconfigured {
		t.Fatalf("error code = %q, want misconfigured", dkim2.ReplayErrorCodeOf(err))
	}
	if len(requests) != 1 || requests[0].command != auditCommandAuth || closeCalls != 1 {
		t.Fatalf("authentication boundary = (%d,%q,%d), want one AUTH and one close",
			len(requests), requests[0].command, closeCalls)
	}
	if strings.Contains(err.Error(), "synthetic") || strings.Contains(fmt.Sprintf("%+v", err), "synthetic") {
		t.Fatal("bounded error disclosed an auditor error suffix")
	}
}

// TestSecurityAuditorMapsPolicyMismatchByPhase verifies construction/runtime recovery taxonomy.
func TestSecurityAuditorMapsPolicyMismatchByPhase(t *testing.T) {
	tests := []struct {
		name  string
		index int
		value resp2Value
	}{
		{"non-primary role", 1, slaveRoleAuditValue()},
		{"evicting memory policy", 2, configAuditValue("allkeys-lru", "67108864", "1", "10", "60 1", "no", "no")},
		{"insufficient headroom", 3, memoryInfoAuditValue("used_memory:66060289\r\n")},
		{"unhealthy rdb", 4, persistenceInfoAuditValue("rdb_last_bgsave_status:err\r\naof_enabled:0\r\naof_last_write_status:ok\r\naof_last_bgrewrite_status:ok\r\n")},
		{"replication role drift", 5, replicationInfoAuditValue("role:slave\r\nconnected_slaves:1\r\nslave0:ip=127.0.0.2,port=6379,state=online,offset=40,lag=1,type=replica\r\n")},
		{"cluster enabled", 6, clusterInfoAuditValue("cluster_enabled:1\r\n")},
		{"acl command excess", 7, aclAuditValue("-@all +ping +set +get", "~dkim2:replay:v1:*", "", "db=0", canonicalFlags(), []resp2Value{}, []string{syntheticPasswordHash})},
		{"required ping denied", 8, bulkAuditValue("denied")},
		{"required set denied", 9, bulkAuditValue("denied")},
		{"outside set permitted", 10, simpleAuditValue("OK")},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			for _, phaseCase := range []struct {
				phase auditPhase
				code  dkim2.ReplayErrorCode
			}{
				{auditPhaseConstruction, dkim2.ReplayErrorMisconfigured},
				{auditPhaseRuntime, dkim2.ReplayErrorUnavailable},
			} {
				replies := validAuditReplies()
				replies[testCase.index].value = cloneRESP2Value(testCase.value)
				wire := &fakeAuditWire{replies: replies}
				err := runSecurityAudit(
					context.Background(),
					wire,
					validAuditCredentials(),
					validSecurityAuditPolicy(),
					phaseCase.phase,
				)
				if dkim2.ReplayErrorCodeOf(err) != phaseCase.code {
					t.Fatalf("phase %q code = %q, want %q",
						phaseCase.phase, dkim2.ReplayErrorCodeOf(err), phaseCase.code)
				}
				_, _, closeCalls := wire.snapshot()
				if closeCalls != 1 {
					t.Fatalf("close calls = %d, want 1", closeCalls)
				}
			}
		})
	}
}

// TestSecurityAuditorRejectsMalformedAuthoritativeShapes verifies restart-only wire contradictions.
func TestSecurityAuditorRejectsMalformedAuthoritativeShapes(t *testing.T) {
	tests := []struct {
		name  string
		index int
		value resp2Value
	}{
		{"auth bulk OK", 0, bulkAuditValue("OK")},
		{"unknown role", 1, arrayAuditValue(bulkAuditValue("future"))},
		{"config wrong type", 2, arrayAuditValue(integerAuditValue(14))},
		{"memory duplicate", 3, memoryInfoAuditValue("used_memory:1\r\nused_memory:1\r\n")},
		{"persistence missing", 4, persistenceInfoAuditValue("rdb_last_bgsave_status:ok\r\n")},
		{"replication malformed", 5, replicationInfoAuditValue("role:master\r\nconnected_slaves:01\r\n")},
		{"cluster duplicate", 6, clusterInfoAuditValue("cluster_enabled:0\r\ncluster_enabled:0\r\n")},
		{"acl duplicate field", 7, duplicateACLFieldAuditValue()},
		{"ping null", 8, nullBulkAuditValue()},
		{"set array", 9, arrayAuditValue()},
		{"outside denial empty", 10, bulkAuditValue("")},
		{"unknown error kind", 0, errorAuditValue("FUTURE synthetic suffix")},
		{"malformed error kind", 0, errorAuditValue("wrongpass synthetic suffix")},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			replies := validAuditReplies()
			replies[testCase.index].value = cloneRESP2Value(testCase.value)
			wire := &fakeAuditWire{replies: replies}
			err := runSecurityAudit(
				context.Background(),
				wire,
				validAuditCredentials(),
				validSecurityAuditPolicy(),
				auditPhaseRuntime,
			)
			if dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInconsistent {
				t.Fatalf("error code = %q, want inconsistent", dkim2.ReplayErrorCodeOf(err))
			}
			_, _, closeCalls := wire.snapshot()
			if closeCalls != 1 {
				t.Fatalf("close calls = %d, want 1", closeCalls)
			}
		})
	}
}

// TestSecurityAuditorCleanupPrecedence verifies exact close-error and close-panic dominance.
func TestSecurityAuditorCleanupPrecedence(t *testing.T) {
	closeMarker := errors.New("synthetic close detail")
	tests := []struct {
		name       string
		mutate     func(*fakeAuditWire)
		context    func() context.Context
		want       dkim2.ReplayErrorCode
		closePanic bool
	}{
		{
			name: "success close error",
			mutate: func(w *fakeAuditWire) {
				w.closeErr = closeMarker
			},
			context: func() context.Context { return context.Background() },
			want:    dkim2.ReplayErrorUnavailable,
		},
		{
			name: "malformed reply retains inconsistent",
			mutate: func(w *fakeAuditWire) {
				w.replies[1].value = arrayAuditValue()
				w.closeErr = closeMarker
			},
			context: func() context.Context { return context.Background() },
			want:    dkim2.ReplayErrorInconsistent,
		},
		{
			name: "transport retains unavailable",
			mutate: func(w *fakeAuditWire) {
				w.replies[1].err = errors.New("synthetic transport detail")
				w.closeErr = closeMarker
			},
			context: func() context.Context { return context.Background() },
			want:    dkim2.ReplayErrorUnavailable,
		},
		{
			name: "caller cancellation retains cancellation",
			mutate: func(w *fakeAuditWire) {
				w.closeErr = closeMarker
			},
			context: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			want: dkim2.ReplayErrorCancelled,
		},
		{
			name: "close panic dominates success",
			mutate: func(w *fakeAuditWire) {
				w.closePanic = true
			},
			context: func() context.Context { return context.Background() },
			want:    dkim2.ReplayErrorInternalInvariant,
		},
		{
			name: "close panic dominates malformed",
			mutate: func(w *fakeAuditWire) {
				w.replies[1].value = arrayAuditValue()
				w.closePanic = true
			},
			context: func() context.Context { return context.Background() },
			want:    dkim2.ReplayErrorInternalInvariant,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			wire := &fakeAuditWire{replies: validAuditReplies()}
			testCase.mutate(wire)
			err := runSecurityAudit(
				testCase.context(),
				wire,
				validAuditCredentials(),
				validSecurityAuditPolicy(),
				auditPhaseConstruction,
			)
			if dkim2.ReplayErrorCodeOf(err) != testCase.want {
				t.Fatalf("error code = %q, want %q", dkim2.ReplayErrorCodeOf(err), testCase.want)
			}
			if err != nil && (strings.Contains(err.Error(), "synthetic") ||
				strings.Contains(fmt.Sprintf("%+v", err), "synthetic")) {
				t.Fatal("bounded error disclosed raw cleanup or transport detail")
			}
			_, _, closeCalls := wire.snapshot()
			if closeCalls != 1 {
				t.Fatalf("close calls = %d, want 1", closeCalls)
			}
		})
	}
}

// TestSecurityAuditorCallerContextPrecedesInternalTimeout verifies exact caller identity.
func TestSecurityAuditorCallerContextPrecedesInternalTimeout(t *testing.T) {
	for _, testCase := range []struct {
		name string
		ctx  func() context.Context
		code dkim2.ReplayErrorCode
	}{
		{
			name: "cancelled",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			code: dkim2.ReplayErrorCancelled,
		},
		{
			name: syntheticDeadlineName,
			ctx: func() context.Context {
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				cancel()
				return ctx
			},
			code: dkim2.ReplayErrorDeadlineExceeded,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			wire := &fakeAuditWire{replies: validAuditReplies()}
			err := runSecurityAudit(
				testCase.ctx(),
				wire,
				validAuditCredentials(),
				validSecurityAuditPolicy(),
				auditPhaseConstruction,
			)
			if dkim2.ReplayErrorCodeOf(err) != testCase.code {
				t.Fatalf("error code = %q, want %q", dkim2.ReplayErrorCodeOf(err), testCase.code)
			}
			requests, _, closeCalls := wire.snapshot()
			if len(requests) != 0 || closeCalls != 1 {
				t.Fatalf("preflight calls = (%d commands,%d closes), want (0,1)", len(requests), closeCalls)
			}
		})
	}
}

// TestSecurityAuditorClearsReplyWhenValidatorPanics verifies scoped cleanup precedence.
func TestSecurityAuditorClearsReplyWhenValidatorPanics(t *testing.T) {
	value := masterRoleAuditValue()
	alias := value.values[0].bytes
	panicked := false
	func() {
		defer func() {
			panicked = recover() != nil
		}()
		_ = validateAndClearAuditReply(
			&value,
			true,
			auditCommandRole,
			validSecurityAuditPolicy(),
			nil,
		)
	}()
	if !panicked {
		t.Fatal("hostile nil snapshot did not panic at the validator seam")
	}
	for _, character := range alias {
		if character != 0 {
			t.Fatal("validator panic retained reply bytes")
		}
	}
}

// TestSecurityAuditorSequentialChurnIsPolicyMismatch verifies cross-probe disagreement is not malformed wire state.
func TestSecurityAuditorSequentialChurnIsPolicyMismatch(t *testing.T) {
	for _, phaseCase := range []struct {
		phase auditPhase
		code  dkim2.ReplayErrorCode
	}{
		{auditPhaseConstruction, dkim2.ReplayErrorMisconfigured},
		{auditPhaseRuntime, dkim2.ReplayErrorUnavailable},
	} {
		replies := validAuditReplies()
		replies[5].value = replicationInfoAuditValue(
			"role:master\r\nconnected_slaves:0\r\n",
		)
		wire := &fakeAuditWire{replies: replies}
		err := runSecurityAudit(
			context.Background(),
			wire,
			validAuditCredentials(),
			validSecurityAuditPolicy(),
			phaseCase.phase,
		)
		if dkim2.ReplayErrorCodeOf(err) != phaseCase.code {
			t.Fatalf("phase %q code = %q, want %q",
				phaseCase.phase, dkim2.ReplayErrorCodeOf(err), phaseCase.code)
		}
	}
}

// TestSecurityAuditorACLPolicyAndMalformedMatrix freezes policy versus wire-shape recovery.
func TestSecurityAuditorACLPolicyAndMalformedMatrix(t *testing.T) {
	policyCases := []struct {
		name  string
		value resp2Value
	}{
		{"disabled", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0", []resp2Value{bulkAuditValue("off"), bulkAuditValue("sanitize-payload")}, nil, []string{syntheticPasswordHash})},
		{"nopass", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0", []resp2Value{bulkAuditValue("on"), bulkAuditValue("nopass"), bulkAuditValue("sanitize-payload")}, nil, []string{syntheticPasswordHash})},
		{"skip sanitize", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0", []resp2Value{bulkAuditValue("on"), bulkAuditValue("skip-sanitize-payload")}, nil, []string{syntheticPasswordHash})},
		{"no password", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0", canonicalFlags(), nil, nil)},
		{"two passwords", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0", canonicalFlags(), nil, []string{syntheticPasswordHash, strings.Repeat("b", 64)})},
		{"grant reordered", aclAuditValue("-@all +set +ping", "~dkim2:replay:v1:*", "", "db=0", canonicalFlags(), nil, []string{syntheticPasswordHash})},
		{"category grant", aclAuditValue("-@all +@write +ping +set", "~dkim2:replay:v1:*", "", "db=0", canonicalFlags(), nil, []string{syntheticPasswordHash})},
		{"bare parent command", aclAuditValue("-@all +ping +set +client", "~dkim2:replay:v1:*", "", "db=0", canonicalFlags(), nil, []string{syntheticPasswordHash})},
		{"different key", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:* ~other:*", "", "db=0", canonicalFlags(), nil, []string{syntheticPasswordHash})},
		{"channel pattern", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "&channel", "db=0", canonicalFlags(), nil, []string{syntheticPasswordHash})},
		{"all databases", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "alldbs", canonicalFlags(), nil, []string{syntheticPasswordHash})},
		{"no database", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "", canonicalFlags(), nil, []string{syntheticPasswordHash})},
		{"different database", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=1", canonicalFlags(), nil, []string{syntheticPasswordHash})},
		{"multiple databases", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0,1", canonicalFlags(), nil, []string{syntheticPasswordHash})},
		{"selector", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0", canonicalFlags(), []resp2Value{selectorAuditValue()}, []string{syntheticPasswordHash})},
	}
	for _, testCase := range policyCases {
		t.Run("policy/"+testCase.name, func(t *testing.T) {
			assertAuditValueCode(t, 7, testCase.value, auditPhaseConstruction, dkim2.ReplayErrorMisconfigured)
			assertAuditValueCode(t, 7, testCase.value, auditPhaseRuntime, dkim2.ReplayErrorUnavailable)
		})
	}

	malformedCases := []struct {
		name  string
		value resp2Value
	}{
		{"short password hash", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0", canonicalFlags(), nil, []string{"aa"})},
		{"uppercase password hash", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0", canonicalFlags(), nil, []string{strings.Repeat("A", 64)})},
		{"unknown flag", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0", []resp2Value{bulkAuditValue("on"), bulkAuditValue("sanitize-payload"), bulkAuditValue("allkeys")}, nil, []string{syntheticPasswordHash})},
		{"duplicate state flag", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0", []resp2Value{bulkAuditValue("on"), bulkAuditValue("on"), bulkAuditValue("sanitize-payload")}, nil, []string{syntheticPasswordHash})},
		{"mutual state flags", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0", []resp2Value{bulkAuditValue("on"), bulkAuditValue("off"), bulkAuditValue("sanitize-payload")}, nil, []string{syntheticPasswordHash})},
		{"duplicate sanitize flag", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0", []resp2Value{bulkAuditValue("on"), bulkAuditValue("sanitize-payload"), bulkAuditValue("sanitize-payload")}, nil, []string{syntheticPasswordHash})},
		{"mutual sanitize flags", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0", []resp2Value{bulkAuditValue("on"), bulkAuditValue("sanitize-payload"), bulkAuditValue("skip-sanitize-payload")}, nil, []string{syntheticPasswordHash})},
		{"duplicate nopass", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0", []resp2Value{bulkAuditValue("on"), bulkAuditValue("sanitize-payload"), bulkAuditValue("nopass"), bulkAuditValue("nopass")}, nil, []string{syntheticPasswordHash})},
		{"resetdbs", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "resetdbs", canonicalFlags(), nil, []string{syntheticPasswordHash})},
		{"empty db id", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=", canonicalFlags(), nil, []string{syntheticPasswordHash})},
		{"signed db id", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=+0", canonicalFlags(), nil, []string{syntheticPasswordHash})},
		{"leading zero db id", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=01", canonicalFlags(), nil, []string{syntheticPasswordHash})},
		{"duplicate db id", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0,0", canonicalFlags(), nil, []string{syntheticPasswordHash})},
		{"case drift", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "DB=0", canonicalFlags(), nil, []string{syntheticPasswordHash})},
		{"wrong scalar type", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0", canonicalFlags(), nil, []string{syntheticPasswordHash})},
		{"malformed selector", aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0", canonicalFlags(), []resp2Value{arrayAuditValue()}, []string{syntheticPasswordHash})},
	}
	malformedCases[len(malformedCases)-2].value.values[11] = integerAuditValue(0)
	for _, testCase := range malformedCases {
		t.Run("malformed/"+testCase.name, func(t *testing.T) {
			direct := cloneRESP2Value(testCase.value)
			if validation := validateAuditReply(
				auditCommandACLGetUser,
				direct,
				validSecurityAuditPolicy(),
				&auditSnapshot{},
			); validation != auditMalformed {
				t.Fatalf("direct ACL validation = %d, want malformed", validation)
			}
			assertAuditValueCode(t, 7, testCase.value, auditPhaseRuntime, dkim2.ReplayErrorInconsistent)
		})
	}
}

// TestSecurityAuditorInfoPolicyAndForwardCompatibility verifies in-place INFO distinctions.
func TestSecurityAuditorInfoPolicyAndForwardCompatibility(t *testing.T) {
	assertAuditValueCode(
		t,
		3,
		memoryInfoAuditValue("used_memory:67108865\r\n"),
		auditPhaseConstruction,
		dkim2.ReplayErrorMisconfigured,
	)
	replies := validAuditReplies()
	replies[5].value = replicationInfoAuditValue(
		"role:master\r\nconnected_slaves:1\r\nslave_repl_offset:42\r\nslave_repl_offset:43\r\n" +
			"slave0:ip=127.0.0.2,port=6379,state=online,offset=40,lag=1,type=replica\r\n",
	)
	wire := &fakeAuditWire{replies: replies}
	if err := runSecurityAudit(
		context.Background(),
		wire,
		validAuditCredentials(),
		validSecurityAuditPolicy(),
		auditPhaseConstruction,
	); err != nil {
		t.Fatalf("valid unknown INFO field failed with code %q", dkim2.ReplayErrorCodeOf(err))
	}
	assertAuditValueCode(
		t,
		5,
		replicationInfoAuditValue(
			"role:master\r\nconnected_slaves:1\r\n"+
				"slave0:ip=127.0.0.2,port=6379,state=ON LINE,offset=40,lag=1,type=replica\r\n",
		),
		auditPhaseRuntime,
		dkim2.ReplayErrorInconsistent,
	)
	for _, state := range []string{
		"wait_bgsave", "bg_transfer", "send_bulk", "online", "rdb_transmitted",
	} {
		for _, replicaType := range []string{"rdb-channel", "main-channel", "replica"} {
			replies := validAuditReplies()
			replies[5].value = replicationInfoAuditValue(
				"role:master\r\nconnected_slaves:1\r\n" +
					"slave0:ip=127.0.0.2,port=6379,state=" + state +
					",offset=40,lag=1,type=" + replicaType + "\r\n",
			)
			wire := &fakeAuditWire{replies: replies}
			if err := runSecurityAudit(
				context.Background(),
				wire,
				validAuditCredentials(),
				validSecurityAuditPolicy(),
				auditPhaseConstruction,
			); err != nil {
				t.Fatalf("state/type %q/%q failed with code %q",
					state, replicaType, dkim2.ReplayErrorCodeOf(err))
			}
		}
	}
	for _, replica := range []string{
		"ip=127.0.0.2,port=6379,state=online,offset=40,lag=1",
		"ip=127.0.0.2,port=6379,state=online,offset=40,lag=1,type=future",
		"ip=127.0.0.2,port=6379,state=future,offset=40,lag=1,type=replica",
		"ip=127.0.0.2,port=6379,state=online,offset=40,lag=1,type=replica,extra=x",
	} {
		assertAuditValueCode(
			t,
			5,
			replicationInfoAuditValue("role:master\r\nconnected_slaves:1\r\nslave0:"+replica+"\r\n"),
			auditPhaseRuntime,
			dkim2.ReplayErrorInconsistent,
		)
	}
}

// TestSecurityAuditorINFOSectionGrammar verifies exact section-scoped required fields.
func TestSecurityAuditorINFOSectionGrammar(t *testing.T) {
	accepted := infoAuditValue(
		"# Other_Section-1\r\nused_memory:1\r\n" +
			"# Memory\r\nUnknown.Field-1:\r\nused_memory:16777216\r\n" +
			"# Other\r\nused_memory:2\r\nused_memory:3\r\n",
	)
	assertAuditValueSuccess(t, 3, accepted)

	for _, payload := range []string{
		"used_memory:16777216\r\n# Memory\r\n",
		"# Memory\r\nused_memory:16777216\r\n# Memory\r\n",
		"# Other\r\nused_memory:16777216\r\n",
		"# Other\r\nused_memory:16777216\r\n# Memory\r\n",
		"#\r\nused_memory:16777216\r\n",
		"# \r\nused_memory:16777216\r\n",
		"# Bad Section\r\nused_memory:16777216\r\n",
		"# Memory!\r\nused_memory:16777216\r\n",
		"# Memory\r\nbad field:1\r\nused_memory:16777216\r\n",
		"# Memory\r\n:1\r\nused_memory:16777216\r\n",
	} {
		assertAuditValueCode(
			t,
			3,
			infoAuditValue(payload),
			auditPhaseRuntime,
			dkim2.ReplayErrorInconsistent,
		)
	}
}

// TestSecurityAuditorROLEBoundaries freezes master/sentinel count and official shape handling.
func TestSecurityAuditorROLEBoundaries(t *testing.T) {
	fourReplicas := []resp2Value{
		roleReplicaAuditValue(syntheticReplicaIP),
		roleReplicaAuditValue("127.0.0.3"),
		roleReplicaAuditValue("127.0.0.4"),
		roleReplicaAuditValue("127.0.0.5"),
	}
	assertAuditValueCode(
		t,
		1,
		arrayAuditValue(bulkAuditValue("master"), integerAuditValue(1), arrayAuditValue(fourReplicas...)),
		auditPhaseConstruction,
		dkim2.ReplayErrorMisconfigured,
	)

	for _, count := range []int{16, 17} {
		names := make([]resp2Value, count)
		for index := range names {
			names[index] = bulkAuditValue(fmt.Sprintf("master-%02d", index))
		}
		assertAuditValueCode(
			t,
			1,
			arrayAuditValue(bulkAuditValue("sentinel"), arrayAuditValue(names...)),
			auditPhaseRuntime,
			dkim2.ReplayErrorUnavailable,
		)
	}
	assertAuditValueCode(
		t,
		1,
		arrayAuditValue(
			bulkAuditValue("slave"),
			bulkAuditValue("not-an-ip"),
			integerAuditValue(6379),
			bulkAuditValue("connected"),
			integerAuditValue(1),
		),
		auditPhaseRuntime,
		dkim2.ReplayErrorUnavailable,
	)
}

// TestSecurityAuditorKnownErrorTokensMapToPolicyMismatch verifies the closed error-kind table.
func TestSecurityAuditorKnownErrorTokensMapToPolicyMismatch(t *testing.T) {
	for _, kind := range []string{
		serverKindNOAUTH, serverKindWRONGPASS, serverKindNOPERM, serverKindERR,
		serverKindREADONLY, serverKindMASTERDOWN, serverKindCLUSTERDOWN,
		serverKindLOADING, serverKindMISCONF, serverKindNOREPLICAS,
		serverKindMOVED, serverKindASK, serverKindTRYAGAIN, serverKindOOM,
	} {
		t.Run(kind, func(t *testing.T) {
			assertAuditValueCode(
				t,
				4,
				errorAuditValue(kind+" synthetic protected suffix"),
				auditPhaseConstruction,
				dkim2.ReplayErrorMisconfigured,
			)
		})
	}
	assertAuditValueCode(
		t,
		0,
		errorAuditValue(serverKindBUSY+" synthetic protected suffix"),
		auditPhaseConstruction,
		dkim2.ReplayErrorInconsistent,
	)
	for replyIndex := 1; replyIndex < auditCommandCount; replyIndex++ {
		assertAuditValueCode(
			t,
			replyIndex,
			errorAuditValue(serverKindBUSY+" synthetic protected suffix"),
			auditPhaseConstruction,
			dkim2.ReplayErrorMisconfigured,
		)
	}
}

// TestSecurityAuditorSignedSourceShapes verifies source-exact CONFIG and replica bounds.
func TestSecurityAuditorSignedSourceShapes(t *testing.T) {
	for _, config := range []resp2Value{
		configAuditValue("noeviction", "67108864", "2147483647", "30", "60 1", "no", "no"),
		configAuditValue("noeviction", "67108864", "0", "2147483647", "60 1", "no", "no"),
		configAuditValue("noeviction", "67108864", "0", "30", "60 0", "no", "no"),
		configAuditValue("noeviction", "67108864", "0", "30", "60 -2147483648", "no", "no"),
		configAuditValue("noeviction", "67108864", "0", "30", "9223372036854775807 1", "no", "no"),
		configAuditValue("noeviction", "67108864", "0", "30", "60 2147483647", "no", "no"),
	} {
		assertAuditValueCode(t, 2, config, auditPhaseConstruction, dkim2.ReplayErrorMisconfigured)
	}
	for _, config := range []resp2Value{
		configAuditValue("noeviction", "67108864", "2147483648", "30", "60 1", "no", "no"),
		configAuditValue("noeviction", "67108864", "0", "2147483648", "60 1", "no", "no"),
		configAuditValue("noeviction", "67108864", "0", "30", "60 -2147483649", "no", "no"),
		configAuditValue("noeviction", "67108864", "0", "30", "9223372036854775808 1", "no", "no"),
	} {
		assertAuditValueCode(t, 2, config, auditPhaseRuntime, dkim2.ReplayErrorInconsistent)
	}

	assertAuditValueCode(
		t,
		5,
		replicationInfoAuditValue(
			"role:master\r\nconnected_slaves:65536\r\n"+
				"slave0:ip=127.0.0.2,port=6379,state=online,offset=40,lag=1,type=replica\r\n",
		),
		auditPhaseRuntime,
		dkim2.ReplayErrorInconsistent,
	)
	fourLines := "role:master\r\nconnected_slaves:4\r\n" +
		"slave0:ip=127.0.0.2,port=6379,state=online,offset=40,lag=1,type=replica\r\n" +
		"slave1:ip=127.0.0.3,port=6379,state=online,offset=40,lag=1,type=replica\r\n" +
		"slave2:ip=127.0.0.4,port=6379,state=online,offset=40,lag=1,type=replica\r\n" +
		"slave3:ip=127.0.0.5,port=6379,state=online,offset=40,lag=1,type=replica\r\n"
	assertAuditValueCode(
		t,
		5,
		replicationInfoAuditValue(fourLines),
		auditPhaseConstruction,
		dkim2.ReplayErrorMisconfigured,
	)
	for index, metadata := range []string{
		"ip=mail.example,port=6379,state=online,offset=40,lag=1,type=replica",
		"ip=127.0.0.2,port=0,state=online,offset=40,lag=1,type=replica",
		"ip=127.0.0.2,port=-1,state=online,offset=40,lag=1,type=replica",
		"ip=127.0.0.2,port=6379,state=online,offset=-1,lag=1,type=replica",
		"ip=127.0.0.2,port=6379,state=online,offset=40,lag=-1,type=replica",
	} {
		t.Run(fmt.Sprintf("metadata_%d", index), func(t *testing.T) {
			assertAuditValueCode(
				t,
				5,
				replicationInfoAuditValue("role:master\r\nconnected_slaves:1\r\nslave0:"+metadata+"\r\n"),
				auditPhaseRuntime,
				dkim2.ReplayErrorUnavailable,
			)
		})
	}
}

// TestSecurityAuditorSignedReplicaBounds distinguishes source-valid extrema from overflow.
func TestSecurityAuditorSignedReplicaBounds(t *testing.T) {
	policy := validSecurityAuditPolicy()
	policy.minReplicasToWrite = 1
	for _, testCase := range []struct {
		name     string
		metadata string
	}{
		{
			name:     "port minimum",
			metadata: "ip=127.0.0.2,port=-2147483648,state=online,offset=40,lag=1,type=replica",
		},
		{
			name:     "port maximum",
			metadata: "ip=127.0.0.2,port=2147483647,state=online,offset=40,lag=1,type=replica",
		},
		{
			name:     "offset minimum",
			metadata: "ip=127.0.0.2,port=6379,state=online,offset=-9223372036854775808,lag=1,type=replica",
		},
		{
			name:     "offset maximum",
			metadata: "ip=127.0.0.2,port=6379,state=wait_bgsave,offset=9223372036854775807,lag=1,type=replica",
		},
		{
			name:     "lag minimum",
			metadata: "ip=127.0.0.2,port=6379,state=online,offset=40,lag=-9223372036854775808,type=replica",
		},
		{
			name:     "lag maximum",
			metadata: "ip=127.0.0.2,port=6379,state=online,offset=40,lag=9223372036854775807,type=replica",
		},
	} {
		t.Run("info valid/"+testCase.name, func(t *testing.T) {
			value := replicationInfoAuditValue(
				"role:master\r\nconnected_slaves:1\r\nslave0:" + testCase.metadata + "\r\n",
			)
			if validation := validateReplicationInfo(
				value,
				policy,
				&auditSnapshot{roleReplicas: 1},
			); validation != auditPolicyMismatch {
				t.Fatalf("validation = %d, want policy mismatch", validation)
			}
		})
	}
	for _, testCase := range []struct {
		name     string
		metadata string
	}{
		{
			name:     "port overflow",
			metadata: "ip=127.0.0.2,port=2147483648,state=online,offset=40,lag=1,type=replica",
		},
		{
			name:     "port underflow",
			metadata: "ip=127.0.0.2,port=-2147483649,state=online,offset=40,lag=1,type=replica",
		},
		{
			name:     "offset overflow",
			metadata: "ip=127.0.0.2,port=6379,state=online,offset=9223372036854775808,lag=1,type=replica",
		},
		{
			name:     "offset underflow",
			metadata: "ip=127.0.0.2,port=6379,state=online,offset=-9223372036854775809,lag=1,type=replica",
		},
		{
			name:     "lag overflow",
			metadata: "ip=127.0.0.2,port=6379,state=online,offset=40,lag=9223372036854775808,type=replica",
		},
		{
			name:     "lag underflow",
			metadata: "ip=127.0.0.2,port=6379,state=online,offset=40,lag=-9223372036854775809,type=replica",
		},
	} {
		t.Run("info malformed/"+testCase.name, func(t *testing.T) {
			value := replicationInfoAuditValue(
				"role:master\r\nconnected_slaves:1\r\nslave0:" + testCase.metadata + "\r\n",
			)
			if validation := validateReplicationInfo(
				value,
				policy,
				&auditSnapshot{roleReplicas: 1},
			); validation != auditMalformed {
				t.Fatalf("validation = %d, want malformed", validation)
			}
		})
	}

	for _, testCase := range []struct {
		name   string
		port   string
		offset string
		ip     string
	}{
		{name: "port minimum", port: "-2147483648", offset: "40", ip: syntheticReplicaIP},
		{name: "port maximum", port: "2147483647", offset: "40", ip: syntheticReplicaIP},
		{name: "offset minimum", port: "6379", offset: "-9223372036854775808", ip: syntheticReplicaIP},
		{name: "offset maximum", port: "6379", offset: "9223372036854775807", ip: "mail.example"},
	} {
		t.Run("role valid/"+testCase.name, func(t *testing.T) {
			value := masterRoleWithReplica(testCase.ip, testCase.port, testCase.offset)
			if validation := validateRole(value, &auditSnapshot{}); validation != auditPolicyMismatch {
				t.Fatalf("validation = %d, want policy mismatch", validation)
			}
		})
	}
	for _, testCase := range []struct {
		name   string
		port   string
		offset string
	}{
		{name: "port overflow", port: "2147483648", offset: "40"},
		{name: "port underflow", port: "-2147483649", offset: "40"},
		{name: "offset overflow", port: "6379", offset: canonicalInt64OverflowText},
		{name: "offset underflow", port: "6379", offset: "-9223372036854775809"},
	} {
		t.Run("role malformed/"+testCase.name, func(t *testing.T) {
			value := masterRoleWithReplica(syntheticReplicaIP, testCase.port, testCase.offset)
			if validation := validateRole(value, &auditSnapshot{}); validation != auditMalformed {
				t.Fatalf("validation = %d, want malformed", validation)
			}
		})
	}
}

// TestSecurityAuditorSourceExactROLEShapes verifies structural versus health classification.
func TestSecurityAuditorSourceExactROLEShapes(t *testing.T) {
	for _, replica := range []resp2Value{
		arrayAuditValue(bulkAuditValue(""), bulkAuditValue("6379"), bulkAuditValue("40")),
		arrayAuditValue(bulkAuditValue("mail.example"), bulkAuditValue("6379"), bulkAuditValue("40")),
		arrayAuditValue(bulkAuditValue(syntheticReplicaIP), bulkAuditValue("0"), bulkAuditValue("40")),
		arrayAuditValue(bulkAuditValue(syntheticReplicaIP), bulkAuditValue("-1"), bulkAuditValue("40")),
		arrayAuditValue(bulkAuditValue(syntheticReplicaIP), bulkAuditValue("2147483647"), bulkAuditValue("40")),
		arrayAuditValue(bulkAuditValue(syntheticReplicaIP), bulkAuditValue("6379"), bulkAuditValue("-1")),
	} {
		assertAuditValueCode(
			t,
			1,
			arrayAuditValue(bulkAuditValue("master"), integerAuditValue(1), arrayAuditValue(replica)),
			auditPhaseConstruction,
			dkim2.ReplayErrorMisconfigured,
		)
	}
	assertAuditValueCode(
		t,
		1,
		arrayAuditValue(
			bulkAuditValue("slave"),
			bulkAuditValue(""),
			integerAuditValue(0),
			bulkAuditValue(auditUnknownToken),
			integerAuditValue(-1),
		),
		auditPhaseRuntime,
		dkim2.ReplayErrorUnavailable,
	)
	for _, replica := range []resp2Value{
		arrayAuditValue(bulkAuditValue(strings.Repeat("x", 256)), bulkAuditValue("6379"), bulkAuditValue("40")),
		arrayAuditValue(bulkAuditValue(syntheticReplicaIP), bulkAuditValue("2147483648"), bulkAuditValue("40")),
		arrayAuditValue(bulkAuditValue(syntheticReplicaIP), bulkAuditValue("6379"), bulkAuditValue(canonicalInt64OverflowText)),
	} {
		assertAuditValueCode(
			t,
			1,
			arrayAuditValue(bulkAuditValue("master"), integerAuditValue(1), arrayAuditValue(replica)),
			auditPhaseRuntime,
			dkim2.ReplayErrorInconsistent,
		)
	}
	assertAuditValueCode(
		t,
		1,
		arrayAuditValue(bulkAuditValue("sentinel"), arrayAuditValue(bulkAuditValue(""))),
		auditPhaseRuntime,
		dkim2.ReplayErrorUnavailable,
	)
}

// TestSecurityAuditorACLSourceEnvelopes verifies tagged descriptor and pattern grammars.
func TestSecurityAuditorACLSourceEnvelopes(t *testing.T) {
	for _, descriptor := range []string{
		"-@all", "+@all", "-@all \tquoted\"\\@=,", "-@all +ping +set +get",
	} {
		assertAuditValueCode(
			t,
			7,
			aclAuditValue(descriptor, "~dkim2:replay:v1:*", "", "db=0", canonicalFlags(), nil, []string{syntheticPasswordHash}),
			auditPhaseConstruction,
			dkim2.ReplayErrorMisconfigured,
		)
	}
	for _, descriptor := range []string{"-@all\x00+x", "-@all +PING", "-@everything", "-@allx", "-@all "} {
		assertAuditValueCode(
			t,
			7,
			aclAuditValue(descriptor, "~dkim2:replay:v1:*", "", "db=0", canonicalFlags(), nil, []string{syntheticPasswordHash}),
			auditPhaseRuntime,
			dkim2.ReplayErrorInconsistent,
		)
	}
	for _, key := range []string{"~", "%R~", "%W~"} {
		assertAuditValueCode(
			t,
			7,
			aclAuditValue("-@all +ping +set", key, "", "db=0", canonicalFlags(), nil, []string{syntheticPasswordHash}),
			auditPhaseRuntime,
			dkim2.ReplayErrorUnavailable,
		)
	}
	assertAuditValueCode(
		t,
		7,
		aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "&", "db=0", canonicalFlags(), nil, []string{syntheticPasswordHash}),
		auditPhaseConstruction,
		dkim2.ReplayErrorMisconfigured,
	)
	for _, key := range []string{"~bad\tvalue", "~bad\x00value", "%X~bad"} {
		assertAuditValueCode(
			t,
			7,
			aclAuditValue("-@all +ping +set", key, "", "db=0", canonicalFlags(), nil, []string{syntheticPasswordHash}),
			auditPhaseRuntime,
			dkim2.ReplayErrorInconsistent,
		)
	}
	for _, key := range []string{"~same %R~same", "%R~same %W~same"} {
		assertAuditValueCode(
			t,
			7,
			aclAuditValue("-@all +ping +set", key, "", "db=0", canonicalFlags(), nil, []string{syntheticPasswordHash}),
			auditPhaseRuntime,
			dkim2.ReplayErrorInconsistent,
		)
	}
	assertAuditValueCode(
		t,
		7,
		aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "&* &other", "db=0", canonicalFlags(), nil, []string{syntheticPasswordHash}),
		auditPhaseRuntime,
		dkim2.ReplayErrorInconsistent,
	)
	for _, value := range []resp2Value{
		aclAuditValue("-@all +ping +set", "~* ~other", "", "db=0", canonicalFlags(), nil, []string{syntheticPasswordHash}),
		aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "&*", "db=0", canonicalFlags(), nil, []string{syntheticPasswordHash}),
	} {
		assertAuditValueCode(
			t,
			7,
			value,
			auditPhaseConstruction,
			dkim2.ReplayErrorMisconfigured,
		)
	}
	for _, whitespace := range []byte{'\t', '\n', '\v', '\f', '\r'} {
		assertAuditValueCode(
			t,
			7,
			aclAuditValue(
				"-@all +ping "+string(whitespace)+"+set",
				"~dkim2:replay:v1:*",
				"",
				"db=0",
				canonicalFlags(),
				nil,
				[]string{syntheticPasswordHash},
			),
			auditPhaseConstruction,
			dkim2.ReplayErrorMisconfigured,
		)
		for _, patterns := range []struct {
			keys     string
			channels string
		}{
			{keys: "~bad" + string(whitespace) + "value"},
			{keys: "~dkim2:replay:v1:*", channels: "&bad" + string(whitespace) + "value"},
		} {
			assertAuditValueCode(
				t,
				7,
				aclAuditValue(
					"-@all +ping +set",
					patterns.keys,
					patterns.channels,
					"db=0",
					canonicalFlags(),
					nil,
					[]string{syntheticPasswordHash},
				),
				auditPhaseRuntime,
				dkim2.ReplayErrorInconsistent,
			)
		}
	}
	assertAuditValueCode(
		t,
		7,
		aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=2147483647", canonicalFlags(), nil, []string{syntheticPasswordHash}),
		auditPhaseRuntime,
		dkim2.ReplayErrorUnavailable,
	)
	assertAuditValueCode(
		t,
		7,
		aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=2147483648", canonicalFlags(), nil, []string{syntheticPasswordHash}),
		auditPhaseRuntime,
		dkim2.ReplayErrorInconsistent,
	)
}

// TestSecurityAuditorNestedSelectorSourceShapes verifies exact nested selector pairs and grammars.
func TestSecurityAuditorNestedSelectorSourceShapes(t *testing.T) {
	for _, selectors := range [][]resp2Value{
		{selectorAuditValue()},
		{selectorAuditValue(), selectorAuditValue()},
	} {
		value := aclAuditValue(
			"-@all +ping +set",
			"~dkim2:replay:v1:*",
			"",
			"db=0",
			canonicalFlags(),
			selectors,
			[]string{syntheticPasswordHash},
		)
		if validation := validateACLGetUser(value); validation != auditPolicyMismatch {
			t.Fatalf("valid selector count %d validation = %d, want policy mismatch",
				len(selectors), validation)
		}
	}

	valid := selectorAuditValue()
	malformed := []struct {
		name  string
		value resp2Value
	}{
		{name: "selector scalar", value: bulkAuditValue("commands")},
		{name: "missing pair", value: arrayAuditValue(valid.values[:6]...)},
		{name: "extra pair", value: arrayAuditValue(append(cloneRESP2Values(valid.values), bulkAuditValue("future"), bulkAuditValue("value"))...)},
		{name: "commands value grammar", value: selectorAuditValueWith("allcommands", "~other:*", "", "db=0")},
		{name: "keys value grammar", value: selectorAuditValueWith("-@all +get", "other:*", "", "db=0")},
		{name: "channels value grammar", value: selectorAuditValueWith("-@all +get", "~other:*", "channel", "db=0")},
		{name: "databases value grammar", value: selectorAuditValueWith("-@all +get", "~other:*", "", "db=01")},
	}
	reordered := cloneRESP2Value(valid)
	reordered.values[0], reordered.values[2] = reordered.values[2], reordered.values[0]
	malformed = append(malformed, struct {
		name  string
		value resp2Value
	}{name: "reordered names", value: reordered})
	duplicate := cloneRESP2Value(valid)
	duplicate.values[2] = bulkAuditValue("commands")
	malformed = append(malformed, struct {
		name  string
		value resp2Value
	}{name: "duplicate name", value: duplicate})
	unknown := cloneRESP2Value(valid)
	unknown.values[6] = bulkAuditValue("future")
	malformed = append(malformed, struct {
		name  string
		value resp2Value
	}{name: "unknown name", value: unknown})
	wrongKeyType := cloneRESP2Value(valid)
	wrongKeyType.values[0] = integerAuditValue(0)
	malformed = append(malformed, struct {
		name  string
		value resp2Value
	}{name: "wrong key type", value: wrongKeyType})
	wrongValueType := cloneRESP2Value(valid)
	wrongValueType.values[1] = arrayAuditValue()
	malformed = append(malformed, struct {
		name  string
		value resp2Value
	}{name: "wrong value type", value: wrongValueType})

	for _, testCase := range malformed {
		t.Run(testCase.name, func(t *testing.T) {
			value := aclAuditValue(
				"-@all +ping +set",
				"~dkim2:replay:v1:*",
				"",
				"db=0",
				canonicalFlags(),
				[]resp2Value{testCase.value},
				[]string{syntheticPasswordHash},
			)
			if validation := validateACLGetUser(value); validation != auditMalformed {
				t.Fatalf("validation = %d, want malformed", validation)
			}
			assertAuditValueCode(
				t,
				7,
				value,
				auditPhaseRuntime,
				dkim2.ReplayErrorInconsistent,
			)
		})
	}
}

// TestSecurityAuditorPrivacyBoundary rejects immutable reply copies and unowned render storage.
func TestSecurityAuditorPrivacyBoundary(t *testing.T) {
	source, err := os.ReadFile("auditor.go")
	if err != nil {
		t.Fatalf("read auditor source: %v", err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "auditor.go", source, 0)
	if err != nil {
		t.Fatalf("parse auditor source: %v", err)
	}

	renderUsesCallerStorage := false
	canonicalClearsRenderBuffer := false
	ast.Inspect(file, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.CallExpr:
			if identifier, ok := value.Fun.(*ast.Ident); ok && identifier.Name == panicPointString {
				t.Error("auditor source converts protected bytes to immutable string")
			}
		case *ast.MapType:
			if identifier, ok := value.Key.(*ast.Ident); ok && identifier.Name == "string" {
				t.Error("auditor source retains protected fields in a string-keyed map")
			}
		case *ast.FuncDecl:
			switch value.Name.Name {
			case "renderCanonicalIPv6":
				renderUsesCallerStorage = len(value.Type.Params.List) == 2 &&
					len(value.Type.Params.List[0].Names) == 1 &&
					value.Type.Params.List[0].Names[0].Name == "output"
			case "canonicalIP":
				ast.Inspect(value.Body, func(statement ast.Node) bool {
					call, ok := statement.(*ast.CallExpr)
					if !ok {
						return true
					}
					identifier, ok := call.Fun.(*ast.Ident)
					if !ok || identifier.Name != "clear" || len(call.Args) != 1 {
						return true
					}
					slice, ok := call.Args[0].(*ast.SliceExpr)
					if !ok {
						return true
					}
					buffer, ok := slice.X.(*ast.Ident)
					if ok && buffer.Name == "renderBuffer" {
						canonicalClearsRenderBuffer = true
					}
					return true
				})
			}
		}
		return true
	})
	for _, imported := range file.Imports {
		if imported.Path.Value == `"strconv"` || imported.Path.Value == `"unsafe"` {
			t.Errorf("auditor source imports privacy-unsafe parser %s", imported.Path.Value)
		}
	}
	if !renderUsesCallerStorage {
		t.Error("IPv6 renderer does not use caller-owned output storage")
	}
	if !canonicalClearsRenderBuffer {
		t.Error("canonical IP validation does not clear derived render bytes")
	}
}

// TestSecurityAuditorCanonicalIPGrammar verifies byte-native canonical address validation.
func TestSecurityAuditorCanonicalIPGrammar(t *testing.T) {
	for _, value := range []string{
		"0.0.0.0",
		"127.0.0.1",
		"255.255.255.255",
		"::",
		"::1",
		"2001:db8::",
		"2001:db8::1",
		"2001:db8:0:1::1",
		"::ffff:192.0.2.1",
	} {
		if !canonicalIP([]byte(value)) {
			t.Errorf("canonicalIP(%q) = false, want true", value)
		}
	}
	for _, value := range []string{
		"",
		"01.2.3.4",
		"256.2.3.4",
		"127.0.0.1.",
		"2001:0db8::1",
		"2001:DB8::1",
		"2001:db8:::1",
		"2001:db8:0:1:0:0:0:1",
		"0:0:0:0:0:0:0:1",
		"::ffff:c000:201",
	} {
		if canonicalIP([]byte(value)) {
			t.Errorf("canonicalIP(%q) = true, want false", value)
		}
	}
}

// assertAuditValueCode replaces one successful reply and checks the closed result code.
func assertAuditValueCode(
	t *testing.T,
	replyIndex int,
	value resp2Value,
	phase auditPhase,
	want dkim2.ReplayErrorCode,
) {
	t.Helper()
	replies := validAuditReplies()
	replies[replyIndex].value = cloneRESP2Value(value)
	wire := &fakeAuditWire{replies: replies}
	err := runSecurityAudit(
		context.Background(),
		wire,
		validAuditCredentials(),
		validSecurityAuditPolicy(),
		phase,
	)
	if dkim2.ReplayErrorCodeOf(err) != want {
		t.Fatalf("error code = %q, want %q", dkim2.ReplayErrorCodeOf(err), want)
	}
	_, _, closeCalls := wire.snapshot()
	if closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", closeCalls)
	}
}

// assertAuditValueSuccess replaces one reply and requires a complete successful audit.
func assertAuditValueSuccess(t *testing.T, replyIndex int, value resp2Value) {
	t.Helper()
	replies := validAuditReplies()
	replies[replyIndex].value = cloneRESP2Value(value)
	wire := &fakeAuditWire{replies: replies}
	if err := runSecurityAudit(
		context.Background(),
		wire,
		validAuditCredentials(),
		validSecurityAuditPolicy(),
		auditPhaseConstruction,
	); err != nil {
		t.Fatalf("audit failed with code %q", dkim2.ReplayErrorCodeOf(err))
	}
}

// cloneRESP2Value gives each destructive audit one independently clearable reply tree.
func cloneRESP2Value(value resp2Value) resp2Value {
	cloned := value
	cloned.bytes = append([]byte(nil), value.bytes...)
	cloned.values = make([]resp2Value, len(value.values))
	for index := range value.values {
		cloned.values[index] = cloneRESP2Value(value.values[index])
	}
	return cloned
}

// assertAuditArguments verifies only bounded command-specific values cross the wire seam.
func assertAuditArguments(t *testing.T, requests []auditRequest) {
	t.Helper()
	for index, request := range requests {
		switch request.command {
		case auditCommandAuth:
			assertByteArguments(t, index, request.arguments,
				syntheticAuditUsername, syntheticAuditPassword)
		case auditCommandACLGetUser,
			auditCommandACLDryRunPing,
			auditCommandACLDryRunInNamespaceSet,
			auditCommandACLDryRunOutOfNamespaceSet:
			assertByteArguments(t, index, request.arguments, syntheticApplicationUsername)
		default:
			assertByteArguments(t, index, request.arguments)
		}
	}
}

// assertByteArguments compares one closed request's bounded byte arguments.
func assertByteArguments(t *testing.T, commandIndex int, got [][]byte, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("command %d argument count = %d, want %d", commandIndex+1, len(got), len(want))
	}
	for index := range want {
		if string(got[index]) != want[index] {
			t.Fatalf("command %d argument %d differs from the frozen request",
				commandIndex+1, index+1)
		}
	}
}

// validAuditCredentials returns bounded synthetic credentials for hermetic tests.
func validAuditCredentials() auditCredentials {
	return auditCredentials{
		username: syntheticAuditUsername,
		password: []byte(syntheticAuditPassword),
	}
}

// validSecurityAuditPolicy returns one exact RDB/replication/ACL proof policy.
func validSecurityAuditPolicy() securityAuditPolicy {
	return securityAuditPolicy{
		applicationUsername:      syntheticApplicationUsername,
		persistenceMode:          auditPersistenceRDB,
		appendFsyncPolicy:        auditAppendFsyncInactive,
		saveSchedule:             "60 1",
		minReplicasToWrite:       0,
		minReplicasMaxLagSeconds: 30,
	}
}

// validAuditReplies builds the exact successful reply sequence.
func validAuditReplies() []auditReply {
	return []auditReply{
		{value: simpleAuditValue("OK")},
		{value: masterRoleAuditValue()},
		{value: configAuditValue("noeviction", "67108864", "0", "30", "60 1", "no", "no")},
		{value: memoryInfoAuditValue("used_memory:16777216\r\n")},
		{value: persistenceInfoAuditValue("rdb_last_bgsave_status:ok\r\naof_enabled:0\r\naof_last_write_status:ok\r\naof_last_bgrewrite_status:ok\r\n")},
		{value: replicationInfoAuditValue("role:master\r\nconnected_slaves:1\r\nslave0:ip=127.0.0.2,port=6379,state=online,offset=40,lag=1,type=replica\r\n")},
		{value: clusterInfoAuditValue("cluster_enabled:0\r\n")},
		{value: aclAuditValue("-@all +ping +set", "~dkim2:replay:v1:*", "", "db=0", canonicalFlags(), []resp2Value{}, []string{syntheticPasswordHash})},
		{value: simpleAuditValue("OK")},
		{value: simpleAuditValue("OK")},
		{value: bulkAuditValue("denied")},
	}
}

// masterRoleAuditValue returns one exact healthy master ROLE shape.
func masterRoleAuditValue() resp2Value {
	replica := roleReplicaAuditValue(syntheticReplicaIP)
	return arrayAuditValue(
		bulkAuditValue("master"),
		integerAuditValue(42),
		arrayAuditValue(replica),
	)
}

// roleReplicaAuditValue returns one exact ROLE master replica triple.
func roleReplicaAuditValue(ip string) resp2Value {
	return arrayAuditValue(
		bulkAuditValue(ip),
		bulkAuditValue("6379"),
		bulkAuditValue("40"),
	)
}

// masterRoleWithReplica returns one master ROLE reply with caller-selected bulk bounds.
func masterRoleWithReplica(ip, port, offset string) resp2Value {
	return arrayAuditValue(
		bulkAuditValue("master"),
		integerAuditValue(42),
		arrayAuditValue(
			arrayAuditValue(
				bulkAuditValue(ip),
				bulkAuditValue(port),
				bulkAuditValue(offset),
			),
		),
	)
}

// slaveRoleAuditValue returns one well-formed unsupported ROLE slave shape.
func slaveRoleAuditValue() resp2Value {
	return arrayAuditValue(
		bulkAuditValue("slave"),
		bulkAuditValue("127.0.0.1"),
		integerAuditValue(6379),
		bulkAuditValue("connected"),
		integerAuditValue(42),
	)
}

// configAuditValue returns one exact ordered CONFIG GET response.
func configAuditValue(policy, maxMemory, minReplicas, maxLag, save, appendOnly, appendFsync string) resp2Value {
	return arrayAuditValue(
		bulkAuditValue("appendfsync"), bulkAuditValue(appendFsync),
		bulkAuditValue("appendonly"), bulkAuditValue(appendOnly),
		bulkAuditValue("maxmemory"), bulkAuditValue(maxMemory),
		bulkAuditValue("maxmemory-policy"), bulkAuditValue(policy),
		bulkAuditValue("min-replicas-max-lag"), bulkAuditValue(maxLag),
		bulkAuditValue("min-replicas-to-write"), bulkAuditValue(minReplicas),
		bulkAuditValue("save"), bulkAuditValue(save),
	)
}

// aclAuditValue returns one duplicate-preserving seven-pair ACL GETUSER reply.
func aclAuditValue(
	commands string,
	keys string,
	channels string,
	databases string,
	flags []resp2Value,
	selectors []resp2Value,
	passwords []string,
) resp2Value {
	passwordValues := make([]resp2Value, len(passwords))
	for index := range passwords {
		passwordValues[index] = bulkAuditValue(passwords[index])
	}
	return arrayAuditValue(
		bulkAuditValue("flags"), arrayAuditValue(flags...),
		bulkAuditValue("passwords"), arrayAuditValue(passwordValues...),
		bulkAuditValue("commands"), bulkAuditValue(commands),
		bulkAuditValue("keys"), bulkAuditValue(keys),
		bulkAuditValue("channels"), bulkAuditValue(channels),
		bulkAuditValue("databases"), bulkAuditValue(databases),
		bulkAuditValue("selectors"), arrayAuditValue(selectors...),
	)
}

// duplicateACLFieldAuditValue returns an exact-length reply with one duplicate key.
func duplicateACLFieldAuditValue() resp2Value {
	value := aclAuditValue(
		"-@all +ping +set",
		"~dkim2:replay:v1:*",
		"",
		"db=0",
		canonicalFlags(),
		nil,
		[]string{syntheticPasswordHash},
	)
	value.values[12] = bulkAuditValue("flags")
	return value
}

// canonicalFlags returns the exact canonical application-principal flag set.
func canonicalFlags() []resp2Value {
	return []resp2Value{bulkAuditValue("on"), bulkAuditValue("sanitize-payload")}
}

// selectorAuditValue returns one exact official nonempty selector shape.
func selectorAuditValue() resp2Value {
	return selectorAuditValueWith("-@all +get", "~other:*", "", "db=0")
}

// selectorAuditValueWith returns one ordered selector with caller-selected values.
func selectorAuditValueWith(commands, keys, channels, databases string) resp2Value {
	return arrayAuditValue(
		bulkAuditValue("commands"), bulkAuditValue(commands),
		bulkAuditValue("keys"), bulkAuditValue(keys),
		bulkAuditValue("channels"), bulkAuditValue(channels),
		bulkAuditValue("databases"), bulkAuditValue(databases),
	)
}

// cloneRESP2Values gives structural selector mutations an independent backing slice.
func cloneRESP2Values(values []resp2Value) []resp2Value {
	cloned := make([]resp2Value, len(values))
	for index := range values {
		cloned[index] = cloneRESP2Value(values[index])
	}
	return cloned
}

// simpleAuditValue returns one RESP2 simple string test value.
func simpleAuditValue(value string) resp2Value {
	return resp2Value{kind: resp2SimpleString, bytes: []byte(value)}
}

// errorAuditValue returns one RESP2 error test value.
func errorAuditValue(value string) resp2Value {
	return resp2Value{kind: resp2Error, bytes: []byte(value)}
}

// integerAuditValue returns one RESP2 integer test value.
func integerAuditValue(value int64) resp2Value {
	return resp2Value{kind: resp2Integer, integer: value}
}

// bulkAuditValue returns one RESP2 bulk string test value.
func bulkAuditValue(value string) resp2Value {
	return resp2Value{kind: resp2BulkString, bytes: []byte(value)}
}

// infoAuditValue returns one raw bounded INFO bulk payload.
func infoAuditValue(value string) resp2Value {
	return bulkAuditValue(value)
}

// sectionedInfoAuditValue returns one exact requested INFO section.
func sectionedInfoAuditValue(section, value string) resp2Value {
	return infoAuditValue("# " + section + "\r\n" + value)
}

// memoryInfoAuditValue returns one exact Memory INFO payload.
func memoryInfoAuditValue(value string) resp2Value {
	return sectionedInfoAuditValue("Memory", value)
}

// persistenceInfoAuditValue returns one exact Persistence INFO payload.
func persistenceInfoAuditValue(value string) resp2Value {
	return sectionedInfoAuditValue("Persistence", value)
}

// replicationInfoAuditValue returns one exact Replication INFO payload.
func replicationInfoAuditValue(value string) resp2Value {
	return sectionedInfoAuditValue("Replication", value)
}

// clusterInfoAuditValue returns one exact Cluster INFO payload.
func clusterInfoAuditValue(value string) resp2Value {
	return sectionedInfoAuditValue("Cluster", value)
}

// nullBulkAuditValue returns the official null-bulk singleton.
func nullBulkAuditValue() resp2Value {
	return resp2Value{kind: resp2NullBulk}
}

// arrayAuditValue returns one ordered duplicate-preserving RESP2 array.
func arrayAuditValue(values ...resp2Value) resp2Value {
	return resp2Value{kind: resp2Array, values: values}
}
