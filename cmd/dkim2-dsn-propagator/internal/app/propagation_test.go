package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/daemon"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/lmtp"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/observability"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/reinject"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/testsupport"
)

const (
	propagateRoute = "/v1/dsn/propagate"
	commitRoute    = "/v1/dsn/propagate/commit"
	capabilityName = "X-DKIM2-DSN-Propagate-Capability"
	testToken      = "coordinate-token-0001"
	keyAPIVersion  = "api_version"
	keyDraft       = "draft"
	keyProjection  = "delivery_status"
	keyPropagation = "propagation"
	valueDraft     = "draft-ietf-dkim-dkim2-spec-06"
	testNextHop    = "<previous@hop.example>"
)

// capabilityFixture creates one protected capability file with exact policy.
func capabilityFixture(t *testing.T) string {
	t.Helper()
	root := testsupport.TrustedTempDirectory(t)
	directory := filepath.Join(root, "protected")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal("capability directory failed")
	}
	path := filepath.Join(directory, "propagate.key")
	value := make([]byte, 32)
	for index := range value {
		value[index] = byte(index + 1)
	}
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal("capability file failed")
	}
	if err := os.Chmod(directory, 0o500); err != nil {
		t.Fatal("capability directory mode failed")
	}
	t.Cleanup(func() { _ = os.Chmod(directory, 0o700) })
	return path
}

// daemonScript is one scripted daemon answer for a matrix row.
type daemonScript struct {
	propagateStatus int
	propagateBody   map[string]any
	commitStatus    int
	commitBody      map[string]any

	mu      sync.Mutex
	commits int
}

// commitCount returns the number of observed commit calls.
func (s *daemonScript) commitCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commits
}

// startDaemon serves the scripted propagation answers on a loopback origin.
func startDaemon(t *testing.T, script *daemonScript) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(propagateRoute, func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get(capabilityName) == "" {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		writeJSON(writer, script.propagateStatus, script.propagateBody)
	})
	mux.HandleFunc(commitRoute, func(writer http.ResponseWriter, request *http.Request) {
		script.mu.Lock()
		script.commits++
		script.mu.Unlock()
		if request.Header.Get(capabilityName) == "" {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		writeJSON(writer, script.commitStatus, script.commitBody)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL
}

// writeJSON emits one bounded JSON answer with the declared status.
func writeJSON(writer http.ResponseWriter, status int, body map[string]any) {
	if status == 0 {
		status = http.StatusOK
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if body == nil {
		return
	}
	_ = json.NewEncoder(writer).Encode(body)
}

// projection returns one closed received-DSN projection with the given cause.
func projection(propagation string) map[string]any {
	return map[string]any{
		"structure": "valid", "embedded": "verified", "local_hop": "local",
		"outer_alignment": "aligned", "recipient_linkage": "linked",
		keyPropagation: propagation,
	}
}

// propagateBody builds one coherent propagation answer.
func propagateBody(result, disposition string, extra map[string]any) map[string]any {
	body := map[string]any{
		keyAPIVersion: "v1",
		keyDraft:      valueDraft,
		"operation":   "delivery_status_propagation",
		"result":      result,
		"disposition": disposition,
		"replay":      map[string]any{"class": "first_seen"},
	}
	for key, value := range extra {
		body[key] = value
	}
	return body
}

// acceptOutput builds the propagation member of an accepted answer.
func acceptOutput(smtputf8, eightBitMIME bool) map[string]any {
	return map[string]any{
		"next_hop_recipient":      testNextHop,
		"smtputf8_required":       smtputf8,
		"eight_bit_mime_required": eightBitMIME,
		"commit_token":            testToken,
		"raw_rfc5322_base64":      base64.StdEncoding.EncodeToString([]byte("Subject: dsn\r\n\r\n")),
	}
}

// commitBody builds the committed answer of the commit operation.
func commitBody() map[string]any {
	return map[string]any{
		keyAPIVersion: "v1",
		keyDraft:      valueDraft,
		"state":       "committed",
	}
}

// recordingReinjector records one attempt and answers a scripted error.
type recordingReinjector struct {
	mu       sync.Mutex
	err      error
	attempts int
	last     reinject.Message
}

// Send copies the submitted request, because the transaction erases the
// protected payload as soon as it completes.
func (r *recordingReinjector) Send(_ context.Context, message reinject.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts++
	copied := message
	copied.Bytes = append([]byte(nil), message.Bytes...)
	r.last = copied
	return r.err
}

// observed returns the attempt count and the last submitted message.
func (r *recordingReinjector) observed() (int, reinject.Message) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.attempts, r.last
}

// recordingTelemetry records the closed observation vocabulary only.
type recordingTelemetry struct {
	mu           sync.Mutex
	transactions []string
	replies      []string
	reinjections []string
	commits      []string
}

// RecordTransaction records one closed transaction outcome and reply class.
func (r *recordingTelemetry) RecordTransaction(outcome, reply string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.transactions = append(r.transactions, outcome)
	r.replies = append(r.replies, reply)
}

// RecordReinjection records one closed re-injection outcome.
func (r *recordingTelemetry) RecordReinjection(outcome string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reinjections = append(r.reinjections, outcome)
}

// RecordCommit records one closed commit outcome.
func (r *recordingTelemetry) RecordCommit(outcome string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commits = append(r.commits, outcome)
}

// snapshot returns copies of every recorded closed observation.
func (r *recordingTelemetry) snapshot() ([]string, []string, []string, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.transactions...),
		append([]string(nil), r.replies...),
		append([]string(nil), r.reinjections...),
		append([]string(nil), r.commits...)
}

// buildHandler assembles one complete transaction owner over a scripted daemon.
func buildHandler(
	t *testing.T,
	script *daemonScript,
	reinjector reinjectionClient,
	telemetry transactionTelemetry,
	reply config.PermanentFailureReply,
) *propagationHandler {
	t.Helper()
	origin := startDaemon(t, script)
	capability, err := daemon.LoadCapability(capabilityFixture(t))
	if err != nil {
		t.Fatal("capability load failed")
	}
	t.Cleanup(func() { _ = capability.Close() })
	client, err := daemon.NewClient(
		origin, capability, "tenant-a", "mta.example",
		2*time.Second, 2*time.Second, 1<<20,
	)
	if err != nil {
		t.Fatal("daemon client construction failed")
	}
	t.Cleanup(func() { _ = client.Close() })
	handler, err := newPropagationHandler(client, reinjector, telemetry, reply)
	if err != nil {
		t.Fatal("handler construction failed")
	}
	return handler
}

// testDelivery returns one bounded received notification.
func testDelivery() lmtp.Delivery {
	return lmtp.Delivery{
		ForwardPath: "<bounce+abc@local.example>",
		Bytes:       []byte("Subject: received dsn\r\n\r\n"),
	}
}

// TestFailClosedMatrix proves every daemon outcome maps to its exact reply.
func TestFailClosedMatrix(t *testing.T) {
	tests := map[string]struct {
		body       map[string]any
		status     int
		policy     config.PermanentFailureReply
		reply      lmtp.Reply
		outcome    string
		replyClass string
	}{
		"verification failure": {
			body:   propagateBody("fail", "reject", map[string]any{keyProjection: projection("eligible")}),
			policy: config.PermanentFailureReject,
			reply:  lmtp.ReplyRejected, outcome: observability.OutcomeRejected,
			replyClass: observability.ReplyRejected,
		},
		"verification failure discarded by policy": {
			body:   propagateBody("fail", "reject", map[string]any{keyProjection: projection("eligible")}),
			policy: config.PermanentFailureDiscard,
			reply:  lmtp.ReplyAccepted, outcome: observability.OutcomeRejected,
			replyClass: observability.ReplyAccepted,
		},
		"temporary failure": {
			body:   propagateBody("temperror", "tempfail", nil),
			policy: config.PermanentFailureReject,
			reply:  lmtp.ReplyDeferredPolicy, outcome: observability.OutcomeDeferred,
			replyClass: observability.ReplyDeferred,
		},
		"terminal origin": {
			body:       propagateBody("pass", "discard", map[string]any{keyProjection: projection("terminal_origin")}),
			policy:     config.PermanentFailureReject,
			reply:      lmtp.ReplyAccepted,
			outcome:    observability.OutcomeDiscardedTerminalOrigin,
			replyClass: observability.ReplyAccepted,
		},
		"not a failure report": {
			body:       propagateBody("pass", "discard", map[string]any{keyProjection: projection("not_failure")}),
			policy:     config.PermanentFailureReject,
			reply:      lmtp.ReplyAccepted,
			outcome:    observability.OutcomeDiscardedNotFailure,
			replyClass: observability.ReplyAccepted,
		},
		"null previous sender": {
			body: propagateBody("pass", "discard", map[string]any{
				keyProjection: projection("forbidden_null_previous_sender"),
			}),
			policy:     config.PermanentFailureReject,
			reply:      lmtp.ReplyAccepted,
			outcome:    observability.OutcomeDiscardedNullPreviousSender,
			replyClass: observability.ReplyAccepted,
		},
		"unsupported chain": {
			body:       propagateBody("pass", "discard", map[string]any{keyProjection: projection("unsupported_chain")}),
			policy:     config.PermanentFailureReject,
			reply:      lmtp.ReplyAccepted,
			outcome:    observability.OutcomeDiscardedUnsupportedChain,
			replyClass: observability.ReplyAccepted,
		},
		"not reconstructable": {
			body: propagateBody("permerror", "discard", map[string]any{
				keyProjection:         projection("not_reconstructable"),
				"propagation_failure": "not_reconstructable",
			}),
			policy:     config.PermanentFailureReject,
			reply:      lmtp.ReplyAccepted,
			outcome:    observability.OutcomeDiscardedNotReconstructable,
			replyClass: observability.ReplyAccepted,
		},
		"unprovisioned domain": {
			body: propagateBody("permerror", "discard", map[string]any{
				keyProjection:         projection("eligible"),
				"propagation_failure": "unprovisioned_domain",
			}),
			policy:     config.PermanentFailureReject,
			reply:      lmtp.ReplyAccepted,
			outcome:    observability.OutcomeDiscardedUnprovisionedDomain,
			replyClass: observability.ReplyAccepted,
		},
		"already committed coordinate": {
			body: map[string]any{
				keyAPIVersion: "v1", keyDraft: valueDraft,
				"operation": "delivery_status_propagation",
				"result":    "pass", "disposition": "discard",
				"replay":      map[string]any{"class": "replayed"},
				keyProjection: projection("eligible"),
			},
			policy:     config.PermanentFailureReject,
			reply:      lmtp.ReplyAccepted,
			outcome:    observability.OutcomeDiscardedCommitted,
			replyClass: observability.ReplyAccepted,
		},
		"incoherent result and disposition": {
			body:       propagateBody("pass", "reject", nil),
			policy:     config.PermanentFailureReject,
			reply:      lmtp.ReplyDeferredPolicy,
			outcome:    observability.OutcomeContractFailure,
			replyClass: observability.ReplyDeferred,
		},
		"accept without propagation member": {
			body:       propagateBody("pass", "accept", nil),
			policy:     config.PermanentFailureReject,
			reply:      lmtp.ReplyDeferredPolicy,
			outcome:    observability.OutcomeContractFailure,
			replyClass: observability.ReplyDeferred,
		},
		"discard without a closed cause": {
			body:       propagateBody("pass", "discard", map[string]any{keyProjection: projection("eligible")}),
			policy:     config.PermanentFailureReject,
			reply:      lmtp.ReplyDeferredPolicy,
			outcome:    observability.OutcomeContractFailure,
			replyClass: observability.ReplyDeferred,
		},
		"daemon refuses the capability": {
			status:     http.StatusForbidden,
			policy:     config.PermanentFailureReject,
			reply:      lmtp.ReplyDeferredPolicy,
			outcome:    observability.OutcomeContractFailure,
			replyClass: observability.ReplyDeferred,
		},
		"daemon is unavailable": {
			status:     http.StatusServiceUnavailable,
			policy:     config.PermanentFailureReject,
			reply:      lmtp.ReplyDeferredPolicy,
			outcome:    observability.OutcomeContractFailure,
			replyClass: observability.ReplyDeferred,
		},
	}
	for name, testCase := range tests {
		script := &daemonScript{
			propagateStatus: testCase.status,
			propagateBody:   testCase.body,
			commitBody:      commitBody(),
		}
		reinjector := &recordingReinjector{}
		telemetry := &recordingTelemetry{}
		handler := buildHandler(t, script, reinjector, telemetry, testCase.policy)
		reply := handler.Handle(context.Background(), testDelivery())
		if reply != testCase.reply {
			t.Fatalf("%s: reply %d want %d", name, reply, testCase.reply)
		}
		attempts, _ := reinjector.observed()
		if attempts != 0 {
			t.Fatalf("%s: a non-accept answer was re-injected", name)
		}
		if script.commitCount() != 0 {
			t.Fatalf("%s: a non-accept answer was committed", name)
		}
		outcomes, replies, _, _ := telemetry.snapshot()
		if len(outcomes) != 1 || outcomes[0] != testCase.outcome {
			t.Fatalf("%s: outcomes %v want %q", name, outcomes, testCase.outcome)
		}
		if len(replies) != 1 || replies[0] != testCase.replyClass {
			t.Fatalf("%s: reply classes %v", name, replies)
		}
	}
}

// TestAcceptedTransactionAcknowledgesOnlyAfterCommit proves the ordering rule.
func TestAcceptedTransactionAcknowledgesOnlyAfterCommit(t *testing.T) {
	script := &daemonScript{
		propagateBody: propagateBody("pass", "accept", map[string]any{
			keyProjection:  projection("eligible"),
			keyPropagation: acceptOutput(true, true),
		}),
		commitBody: commitBody(),
	}
	reinjector := &recordingReinjector{}
	telemetry := &recordingTelemetry{}
	handler := buildHandler(t, script, reinjector, telemetry, config.PermanentFailureReject)
	if reply := handler.Handle(context.Background(), testDelivery()); reply != lmtp.ReplyAccepted {
		t.Fatalf("accepted transaction returned %d", reply)
	}
	attempts, message := reinjector.observed()
	if attempts != 1 || message.ForwardPath != testNextHop ||
		!message.SMTPUTF8Required || !message.EightBitMIMERequired {
		t.Fatalf("re-injection request was not the daemon's own: %+v", message)
	}
	if string(message.Bytes) != "Subject: dsn\r\n\r\n" {
		t.Fatalf("re-injected bytes were altered: %q", string(message.Bytes))
	}
	if script.commitCount() != 1 {
		t.Fatalf("commit calls: %d", script.commitCount())
	}
	outcomes, replies, reinjections, commits := telemetry.snapshot()
	if len(outcomes) != 1 || outcomes[0] != observability.OutcomeAccepted ||
		replies[0] != observability.ReplyAccepted ||
		len(reinjections) != 1 || reinjections[0] != observability.ReinjectionAccepted ||
		len(commits) != 1 || commits[0] != observability.CommitCommitted {
		t.Fatalf("observations %v %v %v %v", outcomes, replies, reinjections, commits)
	}
}

// TestReinjectionFailuresNeverAcknowledge proves nothing is acknowledged
// before the listener's own 250.
func TestReinjectionFailuresNeverAcknowledge(t *testing.T) {
	tests := map[string]struct {
		err         error
		outcome     string
		reinjection string
	}{
		"refused":              {&reinject.Error{Outcome: reinject.OutcomeFailed}, observability.OutcomeDeferred, observability.ReinjectionFailed},
		"deferred":             {&reinject.Error{Outcome: reinject.OutcomeDeferred}, observability.OutcomeDeferred, observability.ReinjectionDeferred},
		"smtputf8 unavailable": {&reinject.Error{Outcome: reinject.OutcomeSMTPUTF8Unavailable}, observability.OutcomeDeferred, observability.ReinjectionSMTPUTF8Unavailable},
	}
	for name, testCase := range tests {
		script := &daemonScript{
			propagateBody: propagateBody("pass", "accept", map[string]any{
				keyProjection:  projection("eligible"),
				keyPropagation: acceptOutput(false, false),
			}),
			commitBody: commitBody(),
		}
		reinjector := &recordingReinjector{err: testCase.err}
		telemetry := &recordingTelemetry{}
		handler := buildHandler(t, script, reinjector, telemetry, config.PermanentFailureReject)
		reply := handler.Handle(context.Background(), testDelivery())
		if reply != lmtp.ReplyDeferredTransport {
			t.Fatalf("%s: reply %d", name, reply)
		}
		if script.commitCount() != 0 {
			t.Fatalf("%s: a failed re-injection was committed", name)
		}
		outcomes, _, reinjections, commits := telemetry.snapshot()
		if outcomes[0] != testCase.outcome || reinjections[0] != testCase.reinjection ||
			len(commits) != 0 {
			t.Fatalf("%s: observations %v %v %v", name, outcomes, reinjections, commits)
		}
	}
}

// TestCommitFailureDefers proves an unresolved coordinate is never acknowledged.
func TestCommitFailureDefers(t *testing.T) {
	for name, status := range map[string]int{
		"conflict":    http.StatusConflict,
		"unavailable": http.StatusServiceUnavailable,
	} {
		script := &daemonScript{
			propagateBody: propagateBody("pass", "accept", map[string]any{
				keyProjection:  projection("eligible"),
				keyPropagation: acceptOutput(false, false),
			}),
			commitStatus: status,
		}
		reinjector := &recordingReinjector{}
		telemetry := &recordingTelemetry{}
		handler := buildHandler(t, script, reinjector, telemetry, config.PermanentFailureReject)
		if reply := handler.Handle(context.Background(), testDelivery()); reply != lmtp.ReplyDeferredTransport {
			t.Fatalf("%s: commit failure returned %d", name, reply)
		}
		outcomes, _, reinjections, commits := telemetry.snapshot()
		if outcomes[0] != observability.OutcomeDeferred ||
			reinjections[0] != observability.ReinjectionAccepted ||
			len(commits) != 1 || commits[0] != observability.CommitDeferred {
			t.Fatalf("%s: observations %v %v %v", name, outcomes, reinjections, commits)
		}
	}
}

// TestHandlerConstructionRejectsIncompleteGraph proves fail-closed composition.
func TestHandlerConstructionRejectsIncompleteGraph(t *testing.T) {
	reinjector := &recordingReinjector{}
	telemetry := &recordingTelemetry{}
	if _, err := newPropagationHandler(nil, reinjector, telemetry, config.PermanentFailureReject); err == nil {
		t.Fatal("handler without a daemon client accepted")
	}
	if _, err := newPropagationHandler(nil, nil, nil, "fail_open"); err == nil {
		t.Fatal("handler with an unknown policy accepted")
	}
}

// TestHandlerRedaction proves the handler never renders its dependencies.
func TestHandlerRedaction(t *testing.T) {
	script := &daemonScript{propagateBody: propagateBody("temperror", "tempfail", nil)}
	handler := buildHandler(
		t, script, &recordingReinjector{}, &recordingTelemetry{},
		config.PermanentFailureReject,
	)
	rendered := handler.String() + handler.GoString()
	if strings.Contains(rendered, "tenant") || strings.Contains(rendered, "127.0.0.1") {
		t.Fatalf("handler leaked state: %q", rendered)
	}
	if _, err := handler.MarshalJSON(); err == nil {
		t.Fatal("handler serialization was permitted")
	}
}
