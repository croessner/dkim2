package daemon

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/daemon/generated"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/daemon/wire"
)

const (
	fixedUserAgent      = "dkim2-dsn-propagator/1"
	daemonScheme        = "http"
	cacheControlNoStore = "no-store"
	redactedClient      = "dkim2_dsn_propagator_daemon_client{redacted}"
	maxResponseBytes    = 64 << 20
	maxNextHopBytes     = 256
	nullReversePath     = "<>"
)

// Disposition is the closed daemon decision for one received notification.
type Disposition uint8

const (
	// DispositionAccept requires re-injection and commit before acknowledgement.
	DispositionAccept Disposition = iota + 1
	// DispositionReject is a verification failure or a misrouted notification.
	DispositionReject
	// DispositionDiscard is a valid notification that must not be propagated.
	DispositionDiscard
	// DispositionTempfail requires the MTA to retry the delivery later.
	DispositionTempfail
)

// DiscardReason is the closed observable cause of one discard disposition.
type DiscardReason string

const (
	// DiscardTerminalOrigin marks a notification whose chain reached the origin.
	DiscardTerminalOrigin DiscardReason = "terminal_origin"
	// DiscardNotFailure marks a delivered or delayed report.
	DiscardNotFailure DiscardReason = "not_failure"
	// DiscardNullPreviousSender marks a forbidden null previous sender.
	DiscardNullPreviousSender DiscardReason = "null_previous_sender"
	// DiscardUnsupportedChain marks a chain this implementation cannot descend.
	DiscardUnsupportedChain DiscardReason = "unsupported_chain"
	// DiscardNotReconstructable marks a permanently unrebuildable notification.
	DiscardNotReconstructable DiscardReason = "not_reconstructable"
	// DiscardUnprovisionedDomain marks a local domain without a signing profile.
	DiscardUnprovisionedDomain DiscardReason = "unprovisioned_domain"
	// DiscardCommitted marks an already committed propagation coordinate.
	DiscardCommitted DiscardReason = "committed"
)

// Result is one bounded validated propagation decision.
//
// It never renders its protected members through formatting or serialization.
type Result struct {
	state *resultState
}

// resultState holds the protected propagation payload behind the opaque result.
type resultState struct {
	disposition          Disposition
	discardReason        DiscardReason
	nextHopRecipient     string
	smtputf8Required     bool
	eightBitMIMERequired bool
	message              []byte
	commitToken          wire.ProtectedString
	hasToken             bool
}

// Disposition returns the closed daemon decision.
func (r Result) Disposition() Disposition {
	if r.state == nil {
		return 0
	}
	return r.state.disposition
}

// DiscardReason returns the closed cause of a discard disposition.
func (r Result) DiscardReason() DiscardReason {
	if r.state == nil {
		return ""
	}
	return r.state.discardReason
}

// NextHopRecipient returns the exact previous-hop forward path.
func (r Result) NextHopRecipient() string {
	if r.state == nil {
		return ""
	}
	return r.state.nextHopRecipient
}

// SMTPUTF8Required reports whether re-injection must negotiate SMTPUTF8.
func (r Result) SMTPUTF8Required() bool {
	return r.state != nil && r.state.smtputf8Required
}

// EightBitMIMERequired reports whether re-injection must negotiate 8BITMIME.
func (r Result) EightBitMIMERequired() bool {
	return r.state != nil && r.state.eightBitMIMERequired
}

// Message returns the signed notification bytes owned by this result.
func (r Result) Message() []byte {
	if r.state == nil {
		return nil
	}
	return r.state.message
}

// Clear erases the protected propagation payload of a completed transaction.
func (r Result) Clear() {
	if r.state == nil {
		return
	}
	clear(r.state.message)
	r.state.message = nil
	r.state.nextHopRecipient = ""
	r.state.commitToken = wire.ProtectedString{}
	r.state.hasToken = false
}

// String returns a content-free result diagnostic.
func (Result) String() string { return redactedClient }

// GoString returns a content-free result representation.
func (r Result) GoString() string { return r.String() }

// Format prevents formatting from traversing the protected payload.
func (r Result) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// MarshalJSON rejects result serialization.
func (Result) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects result text serialization.
func (Result) MarshalText() ([]byte, error) { return nil, &Error{} }

// String returns a content-free private result-state diagnostic.
func (resultState) String() string { return redactedClient }

// GoString returns a content-free private result-state representation.
func (r resultState) GoString() string { return r.String() }

// Format prevents nested formatting from traversing protected payload members.
func (r resultState) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// MarshalJSON rejects private result-state serialization.
func (resultState) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects private result-state text serialization.
func (resultState) MarshalText() ([]byte, error) { return nil, &Error{} }

// Client calls exactly the two propagation operations of one daemon origin.
type Client struct {
	state *clientState
}

// clientState keeps copied holders opaque through one private guard.
type clientState struct {
	guard *clientGuard
}

// clientGuard owns the transport, capability, and request identity.
type clientGuard struct {
	client         *generated.ClientWithResponses
	transport      *http.Transport
	capability     *Capability
	mu             *sync.RWMutex
	closed         bool
	tenant         string
	reportingMTA   string
	requestTimeout time.Duration
	commitTimeout  time.Duration
	messageBytes   int64
}

// NewClient constructs a generated-client boundary with a confined transport.
func NewClient(
	origin string,
	capability *Capability,
	tenant string,
	reportingMTA string,
	requestTimeout time.Duration,
	commitTimeout time.Duration,
	messageBytes int64,
) (*Client, error) {
	if capability == nil || tenant == "" || reportingMTA == "" ||
		requestTimeout <= 0 || commitTimeout <= 0 || messageBytes <= 0 ||
		!strings.HasPrefix(origin, daemonScheme+"://") {
		return nil, &Error{}
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != daemonScheme || parsed.Host == "" {
		return nil, &Error{}
	}
	if err := capability.bindRequestTargets(origin); err != nil {
		return nil, &Error{}
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DisableCompression:     true,
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    4,
		MaxConnsPerHost:        8,
		IdleConnTimeout:        30 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		DialContext:            exactDialer(parsed.Host),
	}
	httpClient := &http.Client{
		Transport:     responseLimitTransport{next: transport, max: maxResponseBytes},
		CheckRedirect: rejectRedirect,
	}
	client, err := generated.NewClientWithResponses(
		origin,
		generated.WithHTTPClient(httpClient),
		generated.WithRequestEditorFn(editFixedRequest),
		generated.WithRequestEditorFn(capability.EditRequest),
	)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, &Error{}
	}
	return &Client{state: &clientState{guard: &clientGuard{
		client: client, transport: transport, capability: capability,
		mu: &sync.RWMutex{}, tenant: tenant, reportingMTA: reportingMTA,
		requestTimeout: requestTimeout, commitTimeout: commitTimeout,
		messageBytes: messageBytes,
	}}}, nil
}

// privateState returns the retained client guard only within this package.
func (c *Client) privateState() *clientGuard {
	if c == nil || c.state == nil {
		return nil
	}
	return c.state.guard
}

// Propagate submits one received notification and validates the daemon answer.
//
// Every ambiguous, incoherent, or out-of-contract answer fails closed, because
// the adapter must never re-inject bytes it cannot prove the daemon produced.
func (c *Client) Propagate(
	ctx context.Context,
	message []byte,
	forwardPath string,
	smtputf8 bool,
) (Result, error) {
	guard := c.privateState()
	if guard == nil || ctx == nil || len(message) == 0 ||
		int64(len(message)) > guard.messageBytes || forwardPath == "" ||
		len(forwardPath) > maxNextHopBytes {
		return Result{}, &Error{}
	}
	guard.mu.RLock()
	defer guard.mu.RUnlock()
	if guard.closed || guard.client == nil {
		return Result{}, &Error{}
	}
	rawMessage, err := wire.NewProtectedString(
		base64.StdEncoding.EncodeToString(message),
	)
	if err != nil {
		return Result{}, &Error{}
	}
	mailFrom, err := wire.NewProtectedString(nullReversePath)
	if err != nil {
		return Result{}, &Error{}
	}
	rcptTo, err := wire.NewProtectedString(forwardPath)
	if err != nil {
		return Result{}, &Error{}
	}
	callContext, cancel := context.WithTimeout(ctx, guard.requestTimeout)
	defer cancel()
	response, err := guard.client.PropagateDeliveryStatusWithResponse(
		callContext,
		generated.PropagateDeliveryStatusJSONRequestBody{
			ApiVersion: generated.V1,
			Draft:      generated.DraftIetfDkimDkim2Spec06,
			Message: generated.PropagationMessageInput{
				Fidelity:         generated.PropagationFidelityLMTPDeliveredCRLF,
				RawRfc5322Base64: rawMessage,
			},
			OuterSmtp: generated.PropagationSMTPInput{
				MailFrom: mailFrom,
				RcptTo:   []wire.ProtectedString{rcptTo},
				Smtputf8: smtputf8,
			},
			Context: generated.PropagationContext{
				Tenant:       guard.tenant,
				ReportingMta: guard.reportingMTA,
			},
		},
	)
	if err != nil || response == nil {
		return Result{}, &Error{}
	}
	return guard.mapPropagationResponse(response)
}

// mapPropagationResponse validates one bounded propagation answer.
func (guard *clientGuard) mapPropagationResponse(
	response *generated.PropagateDeliveryStatusResponse,
) (Result, error) {
	if response.HTTPResponse == nil ||
		response.HTTPResponse.StatusCode != http.StatusOK ||
		response.JSON200 == nil {
		return Result{}, &Error{}
	}
	body := response.JSON200
	if body.ApiVersion != generated.V1 ||
		body.Draft != generated.DraftIetfDkimDkim2Spec06 ||
		body.Operation != generated.PropagationOperationDeliveryStatusPropagation ||
		!body.Result.Valid() || !body.Disposition.Valid() ||
		!body.Replay.Class.Valid() {
		return Result{}, &Error{}
	}
	if !coherentOutcome(body.Result, body.Disposition) {
		return Result{}, &Error{}
	}
	switch body.Disposition {
	case generated.PropagationDispositionAccept:
		return guard.mapAccept(body)
	case generated.PropagationDispositionReject:
		if body.Propagation != nil || body.PropagationFailure != nil {
			return Result{}, &Error{}
		}
		return Result{state: &resultState{disposition: DispositionReject}}, nil
	case generated.PropagationDispositionTempfail:
		if body.Propagation != nil || body.PropagationFailure != nil {
			return Result{}, &Error{}
		}
		return Result{state: &resultState{disposition: DispositionTempfail}}, nil
	case generated.PropagationDispositionDiscard:
		reason, ok := discardReason(body)
		if !ok {
			return Result{}, &Error{}
		}
		return Result{state: &resultState{
			disposition: DispositionDiscard, discardReason: reason,
		}}, nil
	default:
		return Result{}, &Error{}
	}
}

// mapAccept validates and copies the protected propagation payload.
func (guard *clientGuard) mapAccept(
	body *generated.DSNPropagateResponse,
) (Result, error) {
	if body.Propagation == nil || body.PropagationFailure != nil {
		return Result{}, &Error{}
	}
	output := body.Propagation
	nextHop, err := output.NextHopRecipient.Bytes()
	if err != nil || !validForwardPath(string(nextHop)) {
		return Result{}, &Error{}
	}
	encoded, err := output.RawRfc5322Base64.Bytes()
	if err != nil {
		return Result{}, &Error{}
	}
	message, err := base64.StdEncoding.DecodeString(string(encoded))
	clear(encoded)
	if err != nil || len(message) == 0 || int64(len(message)) > guard.messageBytes {
		clear(message)
		return Result{}, &Error{}
	}
	token, err := output.CommitToken.Bytes()
	if err != nil || !validCommitToken(string(token)) {
		clear(message)
		return Result{}, &Error{}
	}
	clear(token)
	return Result{state: &resultState{
		disposition:          DispositionAccept,
		nextHopRecipient:     string(nextHop),
		smtputf8Required:     output.Smtputf8Required,
		eightBitMIMERequired: output.EightBitMimeRequired,
		message:              message,
		commitToken:          output.CommitToken,
		hasToken:             true,
	}}, nil
}

// coherentOutcome enforces this operation's own result and disposition rule.
func coherentOutcome(
	result generated.DSNPropagateResponseResult,
	disposition generated.PropagationDisposition,
) bool {
	switch result {
	case generated.PropagationResultPass:
		return disposition == generated.PropagationDispositionAccept ||
			disposition == generated.PropagationDispositionDiscard
	case generated.PropagationResultPermerror:
		return disposition == generated.PropagationDispositionDiscard
	case generated.PropagationResultFail:
		return disposition == generated.PropagationDispositionReject
	case generated.PropagationResultTemperror:
		return disposition == generated.PropagationDispositionTempfail
	default:
		return false
	}
}

// discardReason selects the closed observable cause of one discard answer.
//
// A permanent failure reason wins over every projection value, an already
// committed coordinate is recognized next, and only the closed projection
// causes remain. Anything else is out of contract and fails closed.
func discardReason(body *generated.DSNPropagateResponse) (DiscardReason, bool) {
	if body.Propagation != nil {
		return "", false
	}
	if body.PropagationFailure != nil {
		if body.Result != generated.PropagationResultPermerror {
			return "", false
		}
		switch *body.PropagationFailure {
		case generated.PropagationFailureNotReconstructable:
			return DiscardNotReconstructable, true
		case generated.PropagationFailureUnprovisionedDomain:
			return DiscardUnprovisionedDomain, true
		default:
			return "", false
		}
	}
	if body.Result != generated.PropagationResultPass {
		return "", false
	}
	if body.Replay.Class == generated.Replayed {
		return DiscardCommitted, true
	}
	if body.DeliveryStatus == nil {
		return "", false
	}
	switch body.DeliveryStatus.Propagation {
	case generated.DeliveryStatusPropagationTerminalOrigin:
		return DiscardTerminalOrigin, true
	case generated.DeliveryStatusPropagationNotFailure:
		return DiscardNotFailure, true
	case generated.DeliveryStatusPropagationForbiddenNullPreviousSender:
		return DiscardNullPreviousSender, true
	case generated.DeliveryStatusPropagationUnsupportedChain:
		return DiscardUnsupportedChain, true
	default:
		return "", false
	}
}

// validForwardPath accepts one bounded angle-addressed non-null forward path.
func validForwardPath(value string) bool {
	if len(value) < 3 || len(value) > maxNextHopBytes ||
		value[0] != '<' || value[len(value)-1] != '>' {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] == 0x7f {
			return false
		}
	}
	return !strings.ContainsAny(value[1:len(value)-1], "<>")
}

// validCommitToken accepts the contract's opaque bounded token grammar.
func validCommitToken(value string) bool {
	if len(value) < 16 || len(value) > 512 {
		return false
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' ||
			char >= '0' && char <= '9' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

// Commit moves one reserved coordinate to committed after successful
// re-injection. Any non-200 answer, including 409, fails closed.
func (c *Client) Commit(ctx context.Context, result Result) error {
	guard := c.privateState()
	if guard == nil || ctx == nil || result.state == nil ||
		result.state.disposition != DispositionAccept || !result.state.hasToken {
		return &Error{}
	}
	guard.mu.RLock()
	defer guard.mu.RUnlock()
	if guard.closed || guard.client == nil {
		return &Error{}
	}
	callContext, cancel := context.WithTimeout(ctx, guard.commitTimeout)
	defer cancel()
	response, err := guard.client.CommitDeliveryStatusPropagationWithResponse(
		callContext,
		generated.CommitDeliveryStatusPropagationJSONRequestBody{
			ApiVersion:  generated.V1,
			Draft:       generated.DraftIetfDkimDkim2Spec06,
			CommitToken: result.state.commitToken,
		},
	)
	if err != nil || response == nil || response.HTTPResponse == nil ||
		response.HTTPResponse.StatusCode != http.StatusOK || response.JSON200 == nil {
		return &Error{}
	}
	body := response.JSON200
	if body.ApiVersion != generated.V1 ||
		body.Draft != generated.DraftIetfDkimDkim2Spec06 ||
		body.State != generated.PropagationStateCommitted {
		return &Error{}
	}
	return nil
}

// Close prevents new operations and releases pooled daemon connections.
func (c *Client) Close() error {
	guard := c.privateState()
	if guard == nil {
		return nil
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.closed {
		return nil
	}
	guard.closed = true
	if guard.transport != nil {
		guard.transport.CloseIdleConnections()
	}
	guard.client = nil
	guard.transport = nil
	guard.capability = nil
	guard.tenant = ""
	guard.reportingMTA = ""
	return nil
}

// String returns a content-free client diagnostic.
func (Client) String() string { return redactedClient }

// GoString returns a content-free client representation.
func (c Client) GoString() string { return c.String() }

// Format prevents formatting from traversing tenant and reporting identity.
func (c Client) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, c.String())
}

// MarshalJSON rejects client serialization.
func (Client) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects client text serialization.
func (Client) MarshalText() ([]byte, error) { return nil, &Error{} }

// String returns a content-free private client-state diagnostic.
func (clientState) String() string { return redactedClient }

// GoString returns a content-free private client-state representation.
func (state clientState) GoString() string { return state.String() }

// Format prevents copied private state from traversing into the guard.
func (state clientState) Format(output fmt.State, _ rune) {
	_, _ = io.WriteString(output, state.String())
}

// MarshalJSON rejects private client-state serialization.
func (clientState) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects private client-state text serialization.
func (clientState) MarshalText() ([]byte, error) { return nil, &Error{} }

// String returns a content-free private client-guard diagnostic.
func (clientGuard) String() string { return redactedClient }

// GoString returns a content-free private client-guard representation.
func (guard clientGuard) GoString() string { return guard.String() }

// Format prevents guard dereferencing from traversing live transport state.
func (guard clientGuard) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, guard.String())
}

// MarshalJSON rejects private client-guard serialization.
func (clientGuard) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// MarshalText rejects private client-guard text serialization.
func (clientGuard) MarshalText() ([]byte, error) { return nil, &Error{} }

// exactDialer rejects any generated-client authority drift.
func exactDialer(authority string) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		if network != "tcp" || address != authority {
			return nil, &Error{}
		}
		return dialer.DialContext(ctx, network, address)
	}
}

// editFixedRequest installs only constant transport metadata.
func editFixedRequest(_ context.Context, request *http.Request) error {
	if request == nil || request.URL == nil || request.Header == nil ||
		request.URL.Scheme != daemonScheme || request.URL.User != nil {
		return &Error{}
	}
	request.Header.Set("User-Agent", fixedUserAgent)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", cacheControlNoStore)
	request.Close = false
	return nil
}

// rejectRedirect forbids all redirect following.
func rejectRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

// responseLimitTransport caps each daemon response before generated decoding.
type responseLimitTransport struct {
	next http.RoundTripper
	max  int64
}

// RoundTrip caps one response body before generated decoding.
func (t responseLimitTransport) RoundTrip(
	request *http.Request,
) (response *http.Response, resultErr error) {
	defer func() {
		if recover() != nil {
			if response != nil && response.Body != nil {
				_ = response.Body.Close()
			}
			response = nil
			resultErr = &Error{}
		}
	}()
	if t.next == nil || t.max < 1 {
		return nil, &Error{}
	}
	response, err := t.next.RoundTrip(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, err
	}
	if response == nil || response.Body == nil {
		return nil, &Error{}
	}
	response.Body = &limitedResponseBody{
		reader: io.LimitReader(response.Body, t.max+1),
		body:   response.Body,
		remain: t.max,
	}
	return response, nil
}

// limitedResponseBody enforces one absolute response byte cap.
type limitedResponseBody struct {
	reader io.Reader
	body   io.ReadCloser
	remain int64
}

// Read rejects the first byte beyond the operation response cap.
func (b *limitedResponseBody) Read(output []byte) (count int, resultErr error) {
	defer func() {
		if recover() != nil {
			count = 0
			resultErr = &Error{}
		}
	}()
	if b == nil || b.reader == nil || b.remain < 0 {
		return 0, &Error{}
	}
	if b.remain == 0 {
		var probe [1]byte
		count, err := b.reader.Read(probe[:])
		if count != 0 || err == nil {
			return 0, &Error{}
		}
		return 0, err
	}
	if int64(len(output)) > b.remain {
		output = output[:b.remain]
	}
	count, err := b.reader.Read(output)
	b.remain -= int64(count)
	return count, err
}

// Close releases the underlying response stream.
func (b *limitedResponseBody) Close() (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &Error{}
		}
	}()
	if b == nil || b.body == nil {
		return nil
	}
	return b.body.Close()
}

var _ http.RoundTripper = responseLimitTransport{}
