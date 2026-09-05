package httpjson

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/propagationtest"
)

const (
	propagateRouteTenant      = "tenant-a"
	propagateRouteOtherTenant = "tenant-b"
	propagateRouteLease       = 2 * time.Minute
	propagateRouteRetention   = 10 * time.Minute
	propagateRouteJSON        = "application/json"
	propagateRouteResultPass  = "pass"
	propagateRouteFidelity    = "lmtp_delivered_crlf"
)

// propagateRouteAuthority binds the test-kit authority to the app seam.
type propagateRouteAuthority struct{ *propagationtest.Authority }

// Acquire records the acquisition and returns the kit as the lease.
func (a propagateRouteAuthority) Acquire(ctx context.Context) (app.SigningLease, error) {
	if err := a.Open(ctx); err != nil {
		return nil, err
	}
	return a.Authority, nil
}

// propagateRouteClock is one settable clock shared by the store and the service.
type propagateRouteClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now returns the current instant.
func (c *propagateRouteClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the instant forward.
func (c *propagateRouteClock) Advance(delta time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(delta)
}

// propagateRouteHarness is one production HTTP boundary over the real
// inbound processor, composed like the daemon with the library
// authenticator over the shared replay store, and the real propagation
// service. Because the process route is replay-aware, every process call in
// one test uses a distinct notification unless a replay is the point.
type propagateRouteHarness struct {
	address         string
	corpus          *propagationtest.Corpus
	provider        *propagationtest.Provider
	authority       *propagationtest.Authority
	clock           *propagateRouteClock
	processSecret   []byte
	signSecret      []byte
	reviseSecret    []byte
	dsnSignSecret   []byte
	propagateSecret []byte
}

// startPropagateRouteHarness composes and serves the boundary on loopback.
func startPropagateRouteHarness(t *testing.T) *propagateRouteHarness {
	t.Helper()
	corpus := propagationtest.Load(t)
	provider := corpus.Provider(t)
	key := propagationtest.NewSigningKey(t, propagationtest.LocalDomain)
	provider.Publish(key)
	authority := propagationtest.NewAuthority().AddProfile(propagateRouteTenant, key)
	clock := &propagateRouteClock{now: corpus.Clock()}
	verifier := corpus.Verifier(t, provider)
	store, err := dkim2.NewReplayMemoryStore(dkim2.ReplayMemoryConfig{
		Limits: dkim2.ReplayLimits{MaxEntries: 64, MaxWaiters: 16, PruneBudget: 8, MaxInFlight: 16, MaxAdmissionWaiters: 16},
		Clock:  dkim2.ReplayClockFunc(clock.Now),
	})
	if err != nil {
		t.Fatalf("memory store: %v", err)
	}
	deriver, err := dkim2.NewReplayDeriver(bytes.Repeat([]byte{0x3c}, 32), 3)
	if err != nil {
		t.Fatalf("deriver: %v", err)
	}
	retention, err := dkim2.NewReplayRetention(propagateRouteRetention)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := dkim2.NewReplayLease(propagateRouteLease)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := dkim2.NewAuthenticator(verifier, store, deriver, retention)
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	domain, err := app.NewDomainProcessor(verifier, config.PolicyStrict, authenticator)
	if err != nil {
		t.Fatalf("domain processor: %v", err)
	}
	authorities, err := app.NewLocalAuthorityRegistry(propagateRouteAuthority{authority}, clock.Now)
	if err != nil {
		t.Fatalf("authority registry: %v", err)
	}
	binding, err := app.NewReceivedDSNBinding(verifier, authorities, "")
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	if err := domain.BindReceivedDSN(binding); err != nil {
		t.Fatalf("bind: %v", err)
	}
	replay, err := app.NewEnabledReplayCoordinator(deriver, store, retention)
	if err != nil {
		t.Fatalf("replay coordinator: %v", err)
	}
	processor, err := app.NewInboundProcessor(domain, replay)
	if err != nil {
		t.Fatalf("inbound processor: %v", err)
	}
	propagationReplay, err := app.NewPropagationReplayCoordinator(deriver, store, retention, lease)
	if err != nil {
		t.Fatalf("propagation replay: %v", err)
	}
	service, err := app.NewPropagationCoordinator(app.PropagationDependencies{
		Verifier: verifier, Evaluator: verifier, PublicKeys: provider,
		Authority: propagateRouteAuthority{authority}, Authorities: authorities,
		Policy: config.SigningFlagPolicyConfig{},
		Replay: propagationReplay, TokenRetention: propagateRouteRetention, Clock: clock.Now,
	})
	if err != nil {
		t.Fatalf("propagation service: %v", err)
	}
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("loopback listeners are unavailable in this test environment")
	}
	tracked, err := newTrackedListener(raw, nil)
	if err != nil {
		_ = raw.Close()
		t.Fatalf("tracked listener: %v", err)
	}
	validator, err := NewRequestValidator()
	if err != nil {
		_ = tracked.Close()
		t.Fatalf("validator: %v", err)
	}
	readiness := &boundaryReadiness{}
	readiness.ready.Store(true)
	processSecret := bytes.Repeat([]byte{0x11}, 32)
	propagateSecret := bytes.Repeat([]byte{0x22}, 32)
	signSecret := bytes.Repeat([]byte{0x33}, 32)
	reviseSecret := bytes.Repeat([]byte{0x44}, 32)
	dsnSignSecret := bytes.Repeat([]byte{0x55}, 32)
	handler, err := NewHTTPBoundary(
		BoundaryConfig{
			Authority:       raw.Addr().String(),
			RequestDeadline: 10 * time.Second,
			MaxInFlight:     2,
			MaxWaiters:      16,
			AdmissionWait:   time.Second,
		},
		&boundaryCapabilityMatcher{value: bytes.Clone(processSecret)},
		readiness,
		processor,
		&boundaryFatalNotifier{},
		validator,
		service,
		&dkim2ctlOperationService{},
		propagateMatcherDependency{capabilityMatcher: &boundaryCapabilityMatcher{value: bytes.Clone(propagateSecret)}},
		signMatcherDependency{capabilityMatcher: &boundaryCapabilityMatcher{value: bytes.Clone(signSecret)}},
		reviseMatcherDependency{capabilityMatcher: &boundaryCapabilityMatcher{value: bytes.Clone(reviseSecret)}},
		dsnSignMatcherDependency{capabilityMatcher: &boundaryCapabilityMatcher{value: bytes.Clone(dsnSignSecret)}},
	)
	if err != nil {
		_ = tracked.Close()
		t.Fatalf("HTTP boundary: %v", err)
	}
	server := &http.Server{
		Handler:                      handler,
		ConnContext:                  tracked.ConnContext,
		ErrorLog:                     log.New(io.Discard, "", 0),
		DisableGeneralOptionsHandler: true,
		MaxHeaderBytes:               transportServerMaxHeaderBytes,
	}
	done := make(chan struct{})
	go func() {
		_ = server.Serve(tracked)
		close(done)
	}()
	t.Cleanup(func() {
		handler.Close()
		_ = server.Close()
		_ = tracked.Close()
		<-done
	})
	return &propagateRouteHarness{
		address: raw.Addr().String(), corpus: corpus, provider: provider, authority: authority,
		clock: clock, processSecret: processSecret, signSecret: signSecret,
		reviseSecret: reviseSecret, dsnSignSecret: dsnSignSecret, propagateSecret: propagateSecret,
	}
}

// propagateBody renders one propagation request document for a corpus case.
func (h *propagateRouteHarness) propagateBody(t *testing.T, name, tenant string) string {
	t.Helper()
	testCase := h.corpus.Case(t, name)
	document := map[string]any{
		testKeyAPIVersion: "v1",
		testDraftName:     dkim2.DraftIdentifier,
		testKeyMessage: map[string]any{
			testKeyRawMessage: base64.StdEncoding.EncodeToString(testCase.RawMessage(t)),
			testKeyFidelity:   propagateRouteFidelity,
		},
		"outer_smtp": map[string]any{
			testKeyMailFrom: "<>",
			testKeyRcptTo:   []string{string(testCase.ForwardPath(t))},
			"smtputf8":      false,
		},
		testKeyContext: map[string]any{testKeyTenant: tenant, "reporting_mta": propagationtest.ReportingMTA},
	}
	return marshalRouteDocument(t, document)
}

// marshalRouteDocument renders one request document without HTML escaping,
// so that SMTP paths keep their literal angle brackets and tests can mutate
// them by exact substring.
func marshalRouteDocument(t *testing.T, document map[string]any) string {
	t.Helper()
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(buffer.String())
}

// processBody renders one process request document for a corpus case.
func (h *propagateRouteHarness) processBody(t *testing.T, name, tenant string) string {
	t.Helper()
	testCase := h.corpus.Case(t, name)
	document := map[string]any{
		testKeyAPIVersion: "v1",
		testDraftName:     dkim2.DraftIdentifier,
		testKeyMessage: map[string]any{
			testKeyRawMessage: base64.StdEncoding.EncodeToString(testCase.RawMessage(t)),
			testKeyFidelity:   propagateRouteFidelity,
		},
		testKeySMTP: map[string]any{testKeyMailFrom: "<>", testKeyRcptTo: []string{string(testCase.ForwardPath(t))}},
	}
	if tenant != "" {
		document[testKeyContext] = map[string]any{testKeyTenant: tenant}
	}
	return marshalRouteDocument(t, document)
}

// commitBody renders one commit request document.
func commitBody(token string) string {
	return `{"api_version":"v1","draft":"` + dkim2.DraftIdentifier + `","commit_token":"` + token + `"}`
}

// post issues one JSON request with the capability header and decodes the reply.
func (h *propagateRouteHarness) post(t *testing.T, path, header string, secret []byte, body string) (int, map[string]any) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+h.address+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", propagateRouteJSON)
	if header != "" {
		request.Header.Set(header, base64.RawURLEncoding.EncodeToString(secret))
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, DisableCompression: true}}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request %s: %v", path, err)
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	decoded := map[string]any{}
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &decoded); err != nil {
			t.Fatalf("decode %s response: %v", path, err)
		}
	}
	return response.StatusCode, decoded
}

// propagate posts one propagation request under the propagation capability.
func (h *propagateRouteHarness) propagate(t *testing.T, name, tenant string) (int, map[string]any) {
	t.Helper()
	return h.post(t, dsnPropagatePath, dsnPropagateCapabilityHeader, h.propagateSecret, h.propagateBody(t, name, tenant))
}

// commit posts one commit request under the propagation capability.
func (h *propagateRouteHarness) commit(t *testing.T, token string) (int, map[string]any) {
	t.Helper()
	return h.post(t, dsnPropagateCommitPath, dsnPropagateCapabilityHeader, h.propagateSecret, commitBody(token))
}

// requirePropagation asserts the status and the closed result and disposition pair.
func requirePropagation(t *testing.T, status int, body map[string]any, result, disposition string) {
	t.Helper()
	if status != http.StatusOK || body["result"] != result || body["disposition"] != disposition ||
		body["operation"] != "delivery_status_propagation" {
		t.Fatalf("status=%d result=%v disposition=%v operation=%v body=%v, want 200 %s/%s", status, body["result"], body["disposition"], body["operation"], body, result, disposition)
	}
	if _, present := body["delivery_status"].(map[string]any); !present {
		t.Fatal("propagation response lacks delivery_status")
	}
	if body["propagation_failure"] != nil && result != "permerror" {
		t.Fatalf("propagation_failure %v outside permerror", body["propagation_failure"])
	}
	if _, present := body["propagation"]; present != (disposition == testDispositionAccept) {
		t.Fatalf("propagation member present=%t for disposition %s", present, disposition)
	}
}

// outputToken extracts the commit token of an accepted response.
func outputToken(t *testing.T, body map[string]any) string {
	t.Helper()
	output, ok := body["propagation"].(map[string]any)
	if !ok {
		t.Fatal("accepted response lacks propagation output")
	}
	token, _ := output["commit_token"].(string)
	if !app.ValidPropagationCommitToken(token) {
		t.Fatalf("commit token %q is outside the contract grammar", token)
	}
	return token
}

// TestPropagateRouteAcceptsEligibleNotificationAndCommits proves the accept
// path over the production boundary: the signed output, the coordinate-bound
// token, the idempotent commit, and the discard of a committed coordinate.
func TestPropagateRouteAcceptsEligibleNotificationAndCommits(t *testing.T) {
	harness := startPropagateRouteHarness(t)
	status, body := harness.propagate(t, propagationtest.CaseRunOfOne, propagateRouteTenant)
	requirePropagation(t, status, body, propagateRouteResultPass, testDispositionAccept)
	output := body["propagation"].(map[string]any)
	testCase := harness.corpus.Case(t, propagationtest.CaseRunOfOne)
	if output["next_hop_recipient"] != string(testCase.ExpectedNextHop(t)) || output["smtputf8_required"] != false {
		t.Fatalf("output next_hop=%v smtputf8=%v", output["next_hop_recipient"], output["smtputf8_required"])
	}
	raw, err := base64.StdEncoding.DecodeString(output["raw_rfc5322_base64"].(string))
	if err != nil || !bytes.Contains(raw, []byte("DKIM2-Signature:")) || !bytes.Contains(raw, []byte("multipart/report")) {
		t.Fatal("accepted response does not carry the signed notification")
	}
	projection := body["delivery_status"].(map[string]any)
	if projection["local_hop"] != testLocalHopLocal || projection["propagation"] != "eligible" {
		t.Fatalf("delivery_status = %v", projection)
	}
	token := outputToken(t, body)
	status, body = harness.commit(t, token)
	if status != http.StatusOK || body["state"] != testStateCommitted {
		t.Fatalf("commit status=%d body=%v", status, body)
	}
	status, body = harness.commit(t, token)
	if status != http.StatusOK || body["state"] != testStateCommitted {
		t.Fatalf("second commit status=%d body=%v", status, body)
	}
	status, body = harness.propagate(t, propagationtest.CaseRunOfOne, propagateRouteTenant)
	requirePropagation(t, status, body, propagateRouteResultPass, "discard")
	if replay := body["replay"].(map[string]any); replay["class"] != "replayed" {
		t.Fatalf("committed coordinate replay = %v", replay)
	}
	if harness.authority.Signs.Load() != 1 {
		t.Fatalf("signs = %d, want 1", harness.authority.Signs.Load())
	}
}

// TestPropagateRouteTwoPhaseReplay proves the pending lease over HTTP: a
// preceding process call does not block the first propagation, a live
// lease is tempfail, an expired lease re-serves with a fresh token, the
// superseded token still commits, and the committed coordinate is discarded.
func TestPropagateRouteTwoPhaseReplay(t *testing.T) {
	harness := startPropagateRouteHarness(t)
	status, body := harness.post(t, processPath, localCapabilityHeader, harness.processSecret, harness.processBody(t, propagationtest.CaseRunOfOne, propagateRouteTenant))
	if status != http.StatusOK || body["disposition"] != testDispositionAccept {
		t.Fatalf("process status=%d disposition=%v", status, body["disposition"])
	}
	if projection, ok := body["delivery_status"].(map[string]any); !ok || projection["local_hop"] != testLocalHopLocal {
		t.Fatalf("process delivery_status = %v", body["delivery_status"])
	}
	status, body = harness.propagate(t, propagationtest.CaseRunOfOne, propagateRouteTenant)
	requirePropagation(t, status, body, propagateRouteResultPass, testDispositionAccept)
	first := outputToken(t, body)
	status, body = harness.propagate(t, propagationtest.CaseRunOfOne, propagateRouteTenant)
	requirePropagation(t, status, body, "temperror", "tempfail")
	if replay := body["replay"].(map[string]any); replay["class"] != "indeterminate" {
		t.Fatalf("live lease replay = %v", replay)
	}
	harness.clock.Advance(propagateRouteLease + time.Second)
	status, body = harness.propagate(t, propagationtest.CaseRunOfOne, propagateRouteTenant)
	requirePropagation(t, status, body, propagateRouteResultPass, testDispositionAccept)
	if second := outputToken(t, body); second == "" {
		t.Fatal("re-served attempt issued no token")
	}
	status, body = harness.commit(t, first)
	if status != http.StatusOK || body["state"] != testStateCommitted {
		t.Fatalf("superseded token commit status=%d body=%v", status, body)
	}
	status, body = harness.propagate(t, propagationtest.CaseRunOfOne, propagateRouteTenant)
	requirePropagation(t, status, body, propagateRouteResultPass, "discard")
	if harness.authority.Signs.Load() != 2 {
		t.Fatalf("signs = %d, want 2", harness.authority.Signs.Load())
	}
}

// TestPropagateRouteConcurrentRequestsYieldOneAccept proves N concurrent
// HTTP copies of one notification obtain exactly one accept.
func TestPropagateRouteConcurrentRequestsYieldOneAccept(t *testing.T) {
	harness := startPropagateRouteHarness(t)
	const copies = 6
	dispositions := make([]string, copies)
	var wait sync.WaitGroup
	for index := range copies {
		wait.Add(1)
		go func() {
			defer wait.Done()
			status, body := harness.propagate(t, propagationtest.CaseRunOfOne, propagateRouteTenant)
			if status == http.StatusOK {
				dispositions[index], _ = body["disposition"].(string)
			}
		}()
	}
	wait.Wait()
	accepts, deferrals := 0, 0
	for _, disposition := range dispositions {
		switch disposition {
		case testDispositionAccept:
			accepts++
		case "tempfail":
			deferrals++
		default:
			t.Fatalf("unexpected concurrent disposition %q", disposition)
		}
	}
	if accepts != 1 || deferrals != copies-1 || harness.authority.Signs.Load() != 1 {
		t.Fatalf("accepts=%d deferrals=%d signs=%d", accepts, deferrals, harness.authority.Signs.Load())
	}
}

// TestPropagateCommitUnresolvedTokensAnswer409 proves unknown and expired
// tokens answer 409 with the contracted error code, a malformed token is a
// contract failure, and a committed coordinate keeps answering 200.
func TestPropagateCommitUnresolvedTokensAnswer409(t *testing.T) {
	harness := startPropagateRouteHarness(t)
	status, body := harness.commit(t, strings.Repeat("A", 43))
	if status != http.StatusConflict {
		t.Fatalf("unknown token status = %d body=%v, want 409", status, body)
	}
	if body["code"] != "propagation_commit_unresolved" || body["category"] != "request" {
		t.Fatalf("unknown token body = %v", body)
	}
	if status, _ := harness.commit(t, "short"); status != http.StatusBadRequest {
		t.Fatalf("malformed token status = %d, want 400", status)
	}
	status, body = harness.propagate(t, propagationtest.CaseRunOfOne, propagateRouteTenant)
	requirePropagation(t, status, body, propagateRouteResultPass, testDispositionAccept)
	token := outputToken(t, body)
	harness.clock.Advance(propagateRouteRetention + time.Second)
	if status, _ := harness.commit(t, token); status != http.StatusConflict {
		t.Fatalf("expired token status = %d, want 409", status)
	}
	status, body = harness.propagate(t, propagationtest.CaseRunOfOne, propagateRouteTenant)
	requirePropagation(t, status, body, propagateRouteResultPass, testDispositionAccept)
	fresh := outputToken(t, body)
	if status, body := harness.commit(t, fresh); status != http.StatusOK || body["state"] != testStateCommitted {
		t.Fatalf("fresh token commit status=%d body=%v", status, body)
	}
	if status, body := harness.commit(t, fresh); status != http.StatusOK || body["state"] != testStateCommitted {
		t.Fatalf("committed coordinate commit status=%d body=%v", status, body)
	}
}

// TestPropagateRouteRefusalsNeverReachTheSigner proves the refused matrix
// rows over HTTP and that no refused request reaches a private key: a
// foreign tenant is not_local and rejected, an unprovisioned local domain is
// permerror with its failure class, a datasource outage is tempfail, and
// invalid documents are contract failures.
func TestPropagateRouteRefusalsNeverReachTheSigner(t *testing.T) {
	harness := startPropagateRouteHarness(t)
	forward := propagationtest.NewSigningKey(t, propagationtest.ForwardDomain)
	harness.provider.Publish(forward)
	harness.authority.AddLocal(propagateRouteTenant, propagationtest.ForwardDomain)
	status, body := harness.propagate(t, propagationtest.CaseRunOfOne, propagateRouteOtherTenant)
	requirePropagation(t, status, body, "fail", "reject")
	if projection := body["delivery_status"].(map[string]any); projection["local_hop"] != "not_local" {
		t.Fatalf("foreign tenant projection = %v", projection)
	}
	status, body = harness.propagate(t, propagationtest.CaseNextDomainRun, propagateRouteTenant)
	requirePropagation(t, status, body, "permerror", "discard")
	if body["propagation_failure"] != "unprovisioned_domain" {
		t.Fatalf("propagation_failure = %v", body["propagation_failure"])
	}
	status, body = harness.propagate(t, propagationtest.CasePreviousHopUnverified, propagateRouteTenant)
	requirePropagation(t, status, body, "permerror", "discard")
	if body["propagation_failure"] != "not_reconstructable" {
		t.Fatalf("propagation_failure = %v", body["propagation_failure"])
	}
	status, body = harness.propagate(t, propagationtest.CaseNullPreviousSender, propagateRouteTenant)
	requirePropagation(t, status, body, propagateRouteResultPass, "discard")
	harness.authority.SetOutage(true)
	status, body = harness.propagate(t, propagationtest.CaseRunOfOne, propagateRouteTenant)
	harness.authority.SetOutage(false)
	requirePropagation(t, status, body, "temperror", "tempfail")
	if projection := body["delivery_status"].(map[string]any); projection["local_hop"] != "temperror" {
		t.Fatalf("outage projection = %v", projection)
	}
	valid := harness.propagateBody(t, propagationtest.CaseRunOfOne, propagateRouteTenant)
	for name, document := range map[string]string{
		"non-null reverse path": strings.Replace(valid, `"mail_from":"<>"`, `"mail_from":"<x@local.example>"`, 1),
		"unsupported fidelity":  strings.Replace(valid, `"fidelity":"lmtp_delivered_crlf"`, `"fidelity":"milter_reconstructed_crlf"`, 1),
		"missing tenant":        strings.Replace(valid, `"tenant":"`+propagateRouteTenant+`"`, `"tenant":""`, 1),
		"two recipients":        strings.Replace(valid, `"rcpt_to":["`, `"rcpt_to":["<a@local.example>","`, 1),
	} {
		if status, _ := harness.post(t, dsnPropagatePath, dsnPropagateCapabilityHeader, harness.propagateSecret, document); status != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", name, status)
		}
	}
	if harness.authority.Signs.Load() != 0 {
		t.Fatalf("refused requests reached the private key %d times", harness.authority.Signs.Load())
	}
}

// TestPropagateRouteCapabilityIsolation proves the propagation capability
// opens only its two routes and that the process capability never opens them.
func TestPropagateRouteCapabilityIsolation(t *testing.T) {
	harness := startPropagateRouteHarness(t)
	body := harness.propagateBody(t, propagationtest.CaseRunOfOne, propagateRouteTenant)
	if status, _ := harness.post(t, dsnPropagatePath, localCapabilityHeader, harness.processSecret, body); status != http.StatusForbidden {
		t.Fatalf("process capability on propagate route status = %d, want 403", status)
	}
	if status, _ := harness.post(t, dsnPropagatePath, dsnPropagateCapabilityHeader, harness.processSecret, body); status != http.StatusForbidden {
		t.Fatalf("wrong secret on propagate route status = %d, want 403", status)
	}
	if status, _ := harness.post(t, dsnPropagateCommitPath, localCapabilityHeader, harness.processSecret, commitBody(strings.Repeat("A", 43))); status != http.StatusForbidden {
		t.Fatalf("process capability on commit route status = %d, want 403", status)
	}
	process := harness.processBody(t, propagationtest.CaseRunOfOne, propagateRouteTenant)
	if status, _ := harness.post(t, processPath, dsnPropagateCapabilityHeader, harness.propagateSecret, process); status != http.StatusForbidden {
		t.Fatalf("propagation capability on process route status = %d, want 403", status)
	}
	if status, _ := harness.post(t, dsnPropagatePath, "", nil, body); status != http.StatusForbidden {
		t.Fatalf("no capability on propagate route status = %d, want 403", status)
	}
	for name, credential := range map[string]struct {
		header string
		secret []byte
	}{
		"sign capability":         {header: localCapabilityHeader, secret: harness.signSecret},
		"revise capability":       {header: localCapabilityHeader, secret: harness.reviseSecret},
		"delivery-status sign":    {header: dsnSignCapabilityHeader, secret: harness.dsnSignSecret},
		"propagation secret only": {header: dsnSignCapabilityHeader, secret: harness.propagateSecret},
	} {
		if status, _ := harness.post(t, dsnPropagatePath, credential.header, credential.secret, body); status != http.StatusForbidden {
			t.Fatalf("%s on propagate route status = %d, want 403", name, status)
		}
		if status, _ := harness.post(t, dsnPropagateCommitPath, credential.header, credential.secret,
			commitBody(strings.Repeat("A", 43))); status != http.StatusForbidden {
			t.Fatalf("%s on commit route status = %d, want 403", name, status)
		}
	}
	for _, path := range []string{signPath, revisePath, dsnSignPath} {
		if status, _ := harness.post(t, path, dsnPropagateCapabilityHeader, harness.propagateSecret, body); status != http.StatusForbidden {
			t.Fatalf("propagation capability on %s status = %d, want 403", path, status)
		}
	}
	if harness.authority.Signs.Load() != 0 {
		t.Fatal("capability refusal reached the private key")
	}
}

// unsignedDeliveryStatusReport renders one syntactically well-formed RFC 6522
// delivery-status notification that carries no DKIM2 field family at all.
func unsignedDeliveryStatusReport() []byte {
	return []byte("From: <postmaster@foreign.example>\r\n" +
		"To: <bounce@local.example>\r\n" +
		"Subject: Undelivered Mail Returned to Sender\r\n" +
		"Auto-Submitted: auto-replied\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=\"b0\"\r\n" +
		"\r\n" +
		"--b0\r\n" +
		"Content-Type: text/plain; charset=us-ascii\r\n\r\n" +
		"Delivery failed.\r\n" +
		"--b0\r\n" +
		"Content-Type: message/delivery-status\r\n\r\n" +
		"Reporting-MTA: dns; foreign.example\r\n\r\n" +
		"Final-Recipient: rfc822; someone@destination.example\r\n" +
		"Action: failed\r\n" +
		"Status: 5.1.1\r\n" +
		"--b0\r\n" +
		"Content-Type: message/rfc822\r\n\r\n" +
		"From: <sender@origin.example>\r\n" +
		"To: <someone@destination.example>\r\n" +
		"Subject: original\r\n\r\n" +
		"body\r\n" +
		"--b0--\r\n")
}

// TestPropagateRouteRejectsNotApplicableNotification is the reproducer for
// the not-applicable row: a null-sender delivery-status report that carries
// no DKIM2 field family is nothing this route can propagate and nothing it
// may accept on a socket reserved for our own return-path addresses. It must
// be a permanent fail/reject, not a temporary defer, and it must omit the
// projection instead of claiming a malformed structure the evaluation never
// assessed.
func TestPropagateRouteRejectsNotApplicableNotification(t *testing.T) {
	harness := startPropagateRouteHarness(t)
	document := marshalRouteDocument(t, map[string]any{
		testKeyAPIVersion: "v1",
		testDraftName:     dkim2.DraftIdentifier,
		testKeyMessage: map[string]any{
			testKeyRawMessage: base64.StdEncoding.EncodeToString(unsignedDeliveryStatusReport()),
			testKeyFidelity:   propagateRouteFidelity,
		},
		"outer_smtp": map[string]any{
			testKeyMailFrom: "<>",
			testKeyRcptTo:   []string{"<bounce@local.example>"},
			"smtputf8":      false,
		},
		testKeyContext: map[string]any{testKeyTenant: propagateRouteTenant, "reporting_mta": propagationtest.ReportingMTA},
	})
	status, body := harness.post(t, dsnPropagatePath, dsnPropagateCapabilityHeader, harness.propagateSecret, document)
	if status != http.StatusOK || body["result"] != "fail" || body["disposition"] != "reject" {
		t.Fatalf("status=%d result=%v disposition=%v body=%v, want 200 fail/reject", status, body["result"], body["disposition"], body)
	}
	if _, present := body["delivery_status"]; present {
		t.Fatalf("an unevaluated notification carried a projection: %v", body["delivery_status"])
	}
	if _, present := body["propagation"]; present {
		t.Fatal("a rejected notification carried propagation output")
	}
	if replay := body["replay"].(map[string]any); replay["class"] != "not_checked" {
		t.Fatalf("a refused notification touched the replay gate: %v", replay)
	}
	if harness.authority.Signs.Load() != 0 {
		t.Fatal("a not-applicable notification reached the private key")
	}
}

// TestProcessRouteClassifiesDuplicateContentType is the reproducer for the
// classification gate: a notification whose top-level Content-Type is
// duplicated must still reach the library evaluation, which is the single
// authority that refuses the duplicate as a malformed structure. Selecting
// one Content-Type field in the gate let a second field hide the notification
// from the evaluation entirely, and the daemon then answered a plain accept
// for a structure it had never assessed. The notification must never be
// silently accepted.
//
// The evaluation is complete even though it stopped: every member after
// structure carries not_evaluated, so the daemon projects the malformed
// structure and the strict policy row rejects the notification.
func TestProcessRouteClassifiesDuplicateContentType(t *testing.T) {
	harness := startPropagateRouteHarness(t)
	testCase := harness.corpus.Case(t, propagationtest.CaseRunOfOne)
	raw := testCase.RawMessage(t)
	index := bytes.Index(raw, []byte("\r\n\r\n"))
	if index < 0 {
		t.Fatal("the corpus notification has no top-level header block")
	}
	duplicated := append(append([]byte(nil), raw[:index]...),
		append([]byte("\r\nContent-Type: text/plain"), raw[index:]...)...)
	document := marshalRouteDocument(t, map[string]any{
		testKeyAPIVersion: "v1",
		testDraftName:     dkim2.DraftIdentifier,
		testKeyMessage: map[string]any{
			testKeyRawMessage: base64.StdEncoding.EncodeToString(duplicated),
			testKeyFidelity:   propagateRouteFidelity,
		},
		testKeySMTP:    map[string]any{testKeyMailFrom: "<>", testKeyRcptTo: []string{string(testCase.ForwardPath(t))}},
		testKeyContext: map[string]any{testKeyTenant: propagateRouteTenant},
	})
	status, body := harness.post(t, processPath, localCapabilityHeader, harness.processSecret, document)
	if status != http.StatusOK {
		t.Fatalf("duplicated Content-Type status = %d, want 200", status)
	}
	if body["disposition"] != testDispositionReject {
		t.Fatalf("a duplicated Content-Type was not rejected: %v", body)
	}
	projection, ok := body["delivery_status"].(map[string]any)
	if !ok {
		t.Fatalf("a refused structure produced no projection: %v", body)
	}
	if projection["structure"] != testStructureMalformed || projection["embedded"] != testValueNotEvaluated {
		t.Fatalf("duplicated Content-Type projection = %v", projection)
	}
	for _, member := range []string{"local_hop", "outer_alignment", "recipient_linkage", "propagation"} {
		if projection[member] != testValueNotEvaluated {
			t.Fatalf("member %s after a stopped structure = %v", member, projection[member])
		}
	}
}

// TestProcessRouteProjectsDeliveryStatus proves the process route emits the
// projection with tenant precedence, keeps it absent for a non-DSN message,
// records the received-DSN policy finding, maps a datasource outage to a
// temporary local hop with a tempfail disposition, and reports a repeated
// notification as a replay under the outer policy. Each first-seen call uses
// its own notification because the route shares the daemon's replay store.
func TestProcessRouteProjectsDeliveryStatus(t *testing.T) {
	harness := startPropagateRouteHarness(t)
	status, body := harness.post(t, processPath, localCapabilityHeader, harness.processSecret, harness.processBody(t, propagationtest.CaseNullPreviousSender, ""))
	if status != http.StatusOK {
		t.Fatalf("process without tenant status = %d", status)
	}
	projection, ok := body["delivery_status"].(map[string]any)
	if !ok || projection["local_hop"] != "not_evaluated" || projection["propagation"] != "not_evaluated" || projection["structure"] != "valid" {
		t.Fatalf("no-tenant projection = %v", body["delivery_status"])
	}
	status, body = harness.post(t, processPath, localCapabilityHeader, harness.processSecret, harness.processBody(t, propagationtest.CaseRunOfOne, propagateRouteTenant))
	if status != http.StatusOK || body["disposition"] != testDispositionAccept {
		t.Fatalf("process with tenant status=%d disposition=%v body=%v", status, body["disposition"], body)
	}
	projection = body["delivery_status"].(map[string]any)
	if projection["local_hop"] != testLocalHopLocal || projection["propagation"] != "eligible" || projection["recipient_linkage"] != "linked" {
		t.Fatalf("tenant projection = %v", projection)
	}
	policy := body["policy"].(map[string]any)
	findings, _ := policy["findings"].([]any)
	if len(findings) == 0 {
		t.Fatalf("policy findings absent: %v", policy)
	}
	if last := findings[len(findings)-1].(map[string]any); last["reason"] != "received_dsn_linked" {
		t.Fatalf("last policy finding = %v", last)
	}
	harness.authority.SetOutage(true)
	status, body = harness.post(t, processPath, localCapabilityHeader, harness.processSecret, harness.processBody(t, propagationtest.CaseSMTPUTF8Header, propagateRouteTenant))
	harness.authority.SetOutage(false)
	if status != http.StatusOK || body["disposition"] != "tempfail" {
		t.Fatalf("outage status=%d disposition=%v", status, body["disposition"])
	}
	if projection = body["delivery_status"].(map[string]any); projection["local_hop"] != "temperror" {
		t.Fatalf("outage projection = %v", projection)
	}
	status, body = harness.post(t, processPath, localCapabilityHeader, harness.processSecret, harness.processBody(t, propagationtest.CaseRunOfOne, propagateRouteTenant))
	if status != http.StatusOK || body["disposition"] != "reject" {
		t.Fatalf("replayed status=%d disposition=%v", status, body["disposition"])
	}
	if replay := body["replay"].(map[string]any); replay["class"] != "replayed" {
		t.Fatalf("replayed notification replay = %v", replay)
	}
	if projection = body["delivery_status"].(map[string]any); projection["local_hop"] != testLocalHopLocal {
		t.Fatalf("replayed projection = %v", projection)
	}
	process := harness.processBody(t, propagationtest.CaseNextDomainRun, propagateRouteTenant)
	process = strings.Replace(process, `"mail_from":"<>"`, `"mail_from":"<bounce@destination.example>"`, 1)
	status, body = harness.post(t, processPath, localCapabilityHeader, harness.processSecret, process)
	if status != http.StatusOK {
		t.Fatalf("non-null sender status = %d", status)
	}
	if _, present := body["delivery_status"]; present {
		t.Fatal("non-null sender carried a delivery-status projection")
	}
	if status, _ := harness.post(t, processPath, localCapabilityHeader, harness.processSecret, strings.Replace(process, `"tenant":"`+propagateRouteTenant+`"`, `"tenant":"bad tenant!"`, 1)); status != http.StatusBadRequest {
		t.Fatalf("invalid tenant status = %d, want 400", status)
	}
}

// TestDeliveryStatusProjectionMappingIsTotal proves the projection mapper is
// total over the library's closed received-DSN vocabularies: every value the
// evaluation can report has a generated counterpart, so no library value can
// reach the wire as an internal contract failure. Each member is enumerated
// against a fixed valid remainder, which is exactly how the mapper treats
// them.
func TestDeliveryStatusProjectionMappingIsTotal(t *testing.T) {
	t.Parallel()

	structures := []dkim2.ReceivedDSNStructure{
		dkim2.ReceivedDSNStructureValid, dkim2.ReceivedDSNStructureMalformed,
		dkim2.ReceivedDSNStructureLimitExceeded,
	}
	embeddeds := []dkim2.ReceivedDSNEmbedded{
		dkim2.ReceivedDSNEmbeddedVerified, dkim2.ReceivedDSNEmbeddedVerifiedHeadersOnly,
		dkim2.ReceivedDSNEmbeddedUnverified, dkim2.ReceivedDSNEmbeddedTemperror,
		dkim2.ReceivedDSNEmbeddedAbsent, dkim2.ReceivedDSNEmbeddedNotEvaluated,
	}
	localHops := []dkim2.ReceivedDSNLocalHop{
		dkim2.ReceivedDSNLocalHopLocal, dkim2.ReceivedDSNLocalHopNotLocal,
		dkim2.ReceivedDSNLocalHopMismatch, dkim2.ReceivedDSNLocalHopTemperror,
		dkim2.ReceivedDSNLocalHopNotEvaluated,
	}
	alignments := []dkim2.ReceivedDSNOuterAlignment{
		dkim2.ReceivedDSNOuterAlignmentAligned, dkim2.ReceivedDSNOuterAlignmentMisaligned,
		dkim2.ReceivedDSNOuterAlignmentNotEvaluated,
	}
	linkages := []dkim2.ReceivedDSNRecipientLinkage{
		dkim2.ReceivedDSNRecipientLinkageLinked, dkim2.ReceivedDSNRecipientLinkageUnlinked,
		dkim2.ReceivedDSNRecipientLinkageNotEvaluated,
	}
	propagations := []dkim2.ReceivedDSNPropagation{
		dkim2.ReceivedDSNPropagationNotApplicable, dkim2.ReceivedDSNPropagationEligible,
		dkim2.ReceivedDSNPropagationTerminalOrigin, dkim2.ReceivedDSNPropagationNotFailure,
		dkim2.ReceivedDSNPropagationForbiddenNullPreviousSender,
		dkim2.ReceivedDSNPropagationUnsupportedChain,
		dkim2.ReceivedDSNPropagationNotReconstructable,
		dkim2.ReceivedDSNPropagationNotEvaluated,
	}
	assert := func(t *testing.T, projection app.DeliveryStatusProjection, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("closed projection refused: %v", err)
		}
		mapped, mapErr := mapDeliveryStatusProjection(projection)
		if mapErr != nil {
			t.Fatalf("mapper refused a closed library projection: %v", mapErr)
		}
		if !validDeliveryStatusProjection(mapped) {
			t.Fatal("the mapper produced a projection the wire validator refuses")
		}
	}
	for _, value := range structures {
		projection, err := app.NewClosedDeliveryStatusProjection(value,
			dkim2.ReceivedDSNEmbeddedVerified, dkim2.ReceivedDSNLocalHopLocal,
			dkim2.ReceivedDSNOuterAlignmentAligned, dkim2.ReceivedDSNRecipientLinkageLinked,
			dkim2.ReceivedDSNPropagationEligible)
		assert(t, projection, err)
	}
	for _, value := range embeddeds {
		projection, err := app.NewClosedDeliveryStatusProjection(dkim2.ReceivedDSNStructureValid,
			value, dkim2.ReceivedDSNLocalHopLocal, dkim2.ReceivedDSNOuterAlignmentAligned,
			dkim2.ReceivedDSNRecipientLinkageLinked, dkim2.ReceivedDSNPropagationEligible)
		assert(t, projection, err)
	}
	for _, value := range localHops {
		projection, err := app.NewClosedDeliveryStatusProjection(dkim2.ReceivedDSNStructureValid,
			dkim2.ReceivedDSNEmbeddedVerified, value, dkim2.ReceivedDSNOuterAlignmentAligned,
			dkim2.ReceivedDSNRecipientLinkageLinked, dkim2.ReceivedDSNPropagationEligible)
		assert(t, projection, err)
	}
	for _, value := range alignments {
		projection, err := app.NewClosedDeliveryStatusProjection(dkim2.ReceivedDSNStructureValid,
			dkim2.ReceivedDSNEmbeddedVerified, dkim2.ReceivedDSNLocalHopLocal, value,
			dkim2.ReceivedDSNRecipientLinkageLinked, dkim2.ReceivedDSNPropagationEligible)
		assert(t, projection, err)
	}
	for _, value := range linkages {
		projection, err := app.NewClosedDeliveryStatusProjection(dkim2.ReceivedDSNStructureValid,
			dkim2.ReceivedDSNEmbeddedVerified, dkim2.ReceivedDSNLocalHopLocal,
			dkim2.ReceivedDSNOuterAlignmentAligned, value, dkim2.ReceivedDSNPropagationEligible)
		assert(t, projection, err)
	}
	for _, value := range propagations {
		projection, err := app.NewClosedDeliveryStatusProjection(dkim2.ReceivedDSNStructureValid,
			dkim2.ReceivedDSNEmbeddedVerified, dkim2.ReceivedDSNLocalHopLocal,
			dkim2.ReceivedDSNOuterAlignmentAligned, dkim2.ReceivedDSNRecipientLinkageLinked, value)
		assert(t, projection, err)
	}
	stopped, err := app.NewClosedDeliveryStatusProjection(dkim2.ReceivedDSNStructureMalformed,
		dkim2.ReceivedDSNEmbeddedNotEvaluated, dkim2.ReceivedDSNLocalHopNotEvaluated,
		dkim2.ReceivedDSNOuterAlignmentNotEvaluated, dkim2.ReceivedDSNRecipientLinkageNotEvaluated,
		dkim2.ReceivedDSNPropagationNotEvaluated)
	assert(t, stopped, err)
	if _, err := app.NewClosedDeliveryStatusProjection("forged", dkim2.ReceivedDSNEmbeddedVerified,
		dkim2.ReceivedDSNLocalHopLocal, dkim2.ReceivedDSNOuterAlignmentAligned,
		dkim2.ReceivedDSNRecipientLinkageLinked, dkim2.ReceivedDSNPropagationEligible); err == nil {
		t.Fatal("a member outside the closed vocabulary was sealed into a projection")
	}
}
