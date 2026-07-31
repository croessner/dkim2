package daemon

import (
	"context"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/daemon/generated"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/ipc"
)

const (
	authenticationResultsHeader = "Authentication-Results"
	contentTypeHeader           = "Content-Type"
	jsonMediaType               = "application/json"
	transportDialOperation      = "dial"
)

// ProcessClient is the generated OpenAPI process operation used by inbound IPC.
type ProcessClient interface {
	ProcessMessage(context.Context, generated.ProcessMessageJSONRequestBody, ...generated.RequestEditorFn) (*http.Response, error)
}

// EvidencePublisher persists accepted receive-time revision authority.
type EvidencePublisher interface {
	PublishIncoming(context.Context, adapter.IncomingEvidence) (string, error)
}

// FailOpenWarning records the mandatory bounded operator-visible warning.
type FailOpenWarning interface {
	RecordFailOpenContext(context.Context) error
}

// InboundFailureMode selects the closed inbound daemon-availability policy.
type InboundFailureMode uint8

const (
	// InboundTempfail keeps every daemon failure closed.
	InboundTempfail InboundFailureMode = iota
	// InboundFailOpen allows only proven pre-response availability failures.
	InboundFailOpen
)

// Processor maps admitted Exim evidence through the generated process client.
type Processor struct {
	client            ProcessClient
	authservID        string
	evidencePublisher EvidencePublisher
	failureMode       InboundFailureMode
	failOpenWarning   FailOpenWarning
}

// NewProcessor validates the narrow generated-client authority for process calls.
func NewProcessor(client ProcessClient, authservID string) (*Processor, error) {
	return NewProcessorWithEvidence(client, authservID, nil)
}

// NewProcessorWithEvidence enables immutable evidence publication on acceptance.
func NewProcessorWithEvidence(
	client ProcessClient,
	authservID string,
	publisher EvidencePublisher,
) (*Processor, error) {
	return NewProcessorWithPolicy(
		client, authservID, publisher, InboundTempfail, nil,
	)
}

// NewProcessorWithPolicy binds the exact reached-service inbound failure policy.
func NewProcessorWithPolicy(
	client ProcessClient,
	authservID string,
	publisher EvidencePublisher,
	failureMode InboundFailureMode,
	warning FailOpenWarning,
) (*Processor, error) {
	if client == nil || authservID != "" && !validAdministrativeDomain(authservID) ||
		failureMode > InboundFailOpen ||
		failureMode == InboundFailOpen && (authservID == "" || warning == nil) {
		return nil, adapter.NewError(adapter.FailureContract)
	}
	return &Processor{
		client: client, authservID: authservID, evidencePublisher: publisher,
		failureMode: failureMode, failOpenWarning: warning,
	}, nil
}

// Process makes exactly one generated POST /v1/process call and closes its result.
func (p *Processor) Process(ctx context.Context, input adapter.LocalScanRequest) (ipc.Response, error) {
	if p == nil || p.client == nil || ctx == nil {
		return ipc.Response{}, adapter.NewError(adapter.FailureContract)
	}
	request, err := MapProcessRequest(input, p.authservID)
	if err != nil {
		return ipc.Response{}, err
	}
	response, err := p.client.ProcessMessage(ctx, request)
	if err != nil {
		return p.handleProcessFailure(ctx, input, response, err)
	}
	body, err := readProcessResponse(response)
	if err != nil {
		return ipc.Response{}, err
	}
	plan, err := AdmitProcessJSON(body, p.authservID)
	clear(body)
	if err != nil {
		return ipc.Response{}, err
	}
	headers := input.Headers()
	defer clearHeaders(headers)
	removals := adapter.LocalAuthenticationResultOccurrences(headers, p.authservID)
	locator, err := p.publishAcceptedEvidence(ctx, plan, input)
	if err != nil {
		return ipc.Response{}, err
	}
	return responseFromPlan(plan, removals, uint16(len(headers)), locator)
}

// handleProcessFailure applies only the reached-service pre-response allowlist.
func (p *Processor) handleProcessFailure(
	ctx context.Context,
	input adapter.LocalScanRequest,
	response *http.Response,
	processErr error,
) (ipc.Response, error) {
	if response != nil {
		if response.Body != nil {
			_ = response.Body.Close()
		}
		return ipc.Response{}, adapter.NewError(adapter.FailureContract)
	}
	classified := classifyProcessError(ctx, processErr)
	if p.failureMode != InboundFailOpen ||
		!preResponseAvailabilityFailure(processErr) {
		return ipc.Response{}, classified
	}
	headers := input.Headers()
	defer clearHeaders(headers)
	if len(adapter.LocalAuthenticationResultOccurrences(headers, p.authservID)) != 0 {
		return ipc.Response{}, adapter.NewError(adapter.FailureUnavailable)
	}
	locator, err := p.publishFailOpenEvidence(ctx, input)
	if err != nil {
		return ipc.Response{}, err
	}
	if !recordFailOpenWarning(ctx, p.failOpenWarning) {
		clear(locator)
		return ipc.Response{}, adapter.NewError(adapter.FailureUnavailable)
	}
	responseValue, err := ipc.NewResponse(
		ipc.DecisionAccept,
		ipc.ReasonNone,
		nil,
		ipc.AddNone,
		nil,
		locator,
		nil,
		uint16(len(headers)),
	)
	clear(locator)
	return responseValue, err
}

// publishFailOpenEvidence persists required authority before fail-open acceptance.
func (p *Processor) publishFailOpenEvidence(
	ctx context.Context,
	input adapter.LocalScanRequest,
) ([]byte, error) {
	if p.evidencePublisher == nil {
		return nil, nil
	}
	mailFrom := input.MailFrom()
	recipients := input.Recipients()
	defer clearSMTP(mailFrom, recipients)
	incoming, err := adapter.NewIncomingEvidence(mailFrom, recipients, input.Session())
	if err != nil {
		return nil, adapter.NewError(adapter.FailureContract)
	}
	locator, err := p.evidencePublisher.PublishIncoming(ctx, incoming)
	if err != nil || !validEvidenceLocator(locator) {
		return nil, adapter.NewError(adapter.FailureResource)
	}
	return []byte(locator), nil
}

// preResponseAvailabilityFailure allows only dial failure or deadline expiry.
func preResponseAvailabilityFailure(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var operationError *net.OpError
	return errors.As(err, &operationError) &&
		operationError.Op == transportDialOperation
}

// recordFailOpenWarning contains mandatory warning sink failure and panic.
func recordFailOpenWarning(ctx context.Context, warning FailOpenWarning) (recorded bool) {
	if warning == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			recorded = false
		}
	}()
	return warning.RecordFailOpenContext(ctx) == nil
}

// publishAcceptedEvidence persists exact receive-time authority before acceptance.
func (p *Processor) publishAcceptedEvidence(
	ctx context.Context,
	plan adapter.Plan,
	input adapter.LocalScanRequest,
) ([]byte, error) {
	if p.evidencePublisher == nil {
		return nil, nil
	}
	if plan.Disposition() != adapter.DispositionAccept &&
		plan.Disposition() != adapter.DispositionContinue {
		return nil, nil
	}
	mailFrom := input.MailFrom()
	recipients := input.Recipients()
	defer clearSMTP(mailFrom, recipients)
	incoming, err := adapter.NewIncomingEvidence(mailFrom, recipients, input.Session())
	if err != nil {
		return nil, adapter.NewError(adapter.FailureContract)
	}
	locator, err := p.evidencePublisher.PublishIncoming(ctx, incoming)
	if err != nil || !validEvidenceLocator(locator) {
		return nil, adapter.NewError(adapter.FailureResource)
	}
	return []byte(locator), nil
}

// classifyProcessError keeps transport and cancellation causes content-free.
func classifyProcessError(ctx context.Context, err error) error {
	if errors.Is(err, context.DeadlineExceeded) ||
		ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return adapter.NewError(adapter.FailureTimeout)
	}
	return adapter.NewError(adapter.FailureUnavailable)
}

// readProcessResponse admits only one bounded successful generated JSON response.
func readProcessResponse(response *http.Response) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, adapter.NewError(adapter.FailureContract)
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get(contentTypeHeader))
	if response.StatusCode != http.StatusOK || mediaErr != nil ||
		mediaType != jsonMediaType {
		_ = response.Body.Close()
		return nil, adapter.NewError(adapter.FailureContract)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		clear(body)
		return nil, adapter.NewError(adapter.FailureUnavailable)
	}
	if len(body) == 0 || len(body) > maxResponseBytes {
		clear(body)
		return nil, adapter.NewError(adapter.FailureResource)
	}
	return body, nil
}

// responseFromPlan translates the complete admitted inbound plan to DXI1.
func responseFromPlan(
	plan adapter.Plan,
	removals []uint16,
	headerCount uint16,
	locator []byte,
) (ipc.Response, error) {
	if plan.Operation() != adapter.OperationProcess {
		return ipc.Response{}, adapter.NewError(adapter.FailureContract)
	}
	decision := ipc.DecisionAccept
	reason := ipc.ReasonNone
	addName := ipc.AddNone
	var addValue []byte
	switch plan.Disposition() {
	case adapter.DispositionAccept:
		actions := plan.Actions()
		if len(actions) == 1 && actions[0].Name() == authenticationResultsHeader {
			addName = ipc.AddAuthenticationResults
			addValue = []byte(actions[0].Value())
		} else if len(actions) != 0 {
			return ipc.Response{}, adapter.NewError(adapter.FailureContract)
		}
	case adapter.DispositionContinue:
		removals = nil
	case adapter.DispositionReject:
		decision, reason, removals = ipc.DecisionReject, ipc.ReasonPolicyReject, nil
	case adapter.DispositionTempfail:
		decision, reason, removals = ipc.DecisionTempfail, ipc.ReasonServiceUnavailable, nil
	default:
		return ipc.Response{}, adapter.NewError(adapter.FailureContract)
	}
	response, err := ipc.NewResponse(
		decision, reason, removals, addName, addValue, locator, removals, headerCount,
	)
	clear(addValue)
	clear(locator)
	return response, err
}

// validEvidenceLocator accepts exactly one canonical unpadded base64url locator.
func validEvidenceLocator(locator string) bool {
	if len(locator) != ipc.EvidenceLocatorBytes {
		return false
	}
	for _, current := range []byte(locator) {
		if current >= 'A' && current <= 'Z' || current >= 'a' && current <= 'z' ||
			current >= '0' && current <= '9' || current == '-' || current == '_' {
			continue
		}
		return false
	}
	return true
}

// clearHeaders erases temporary immutable accessor copies after response mapping.
func clearHeaders(headers [][]byte) {
	for index := range headers {
		clear(headers[index])
	}
}
