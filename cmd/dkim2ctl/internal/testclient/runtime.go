package testclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/testclient/generated"
)

const (
	statusBodyLimit     = 4 * 1024
	processBodyLimit    = 1024 * 1024
	durationUnder100    = "under_100ms"
	durationUnder1S     = "under_1s"
	durationUnder10S    = "under_10s"
	durationAtLeast     = "at_least_10s"
	memberActions       = "actions"
	memberAPIVersion    = "api_version"
	memberCategory      = "category"
	memberCode          = "code"
	memberDisposition   = "disposition"
	memberDraft         = "draft"
	memberOperation     = "operation"
	memberResult        = "result"
	memberStatus        = "status"
	headerCacheControl  = "Cache-Control"
	headerConnection    = "Connection"
	headerContentLength = "Content-Length"
	headerContentType   = "Content-Type"
)

// Operation is the closed generated-client operation vocabulary.
type Operation string

const (
	// OperationHealth identifies the generated liveness call.
	OperationHealth Operation = "health"
	// OperationReadiness identifies the generated readiness call.
	OperationReadiness Operation = "readiness"
	// OperationProcess identifies the generated inbound process call.
	OperationProcess Operation = "process"
	// OperationSign identifies the generated originator-signing call.
	OperationSign Operation = "sign"
	// OperationRevise identifies the generated ordinary-transit revision call.
	OperationRevise Operation = "revise"
	// OperationDSNSign identifies the dedicated delivery-status signing call.
	OperationDSNSign Operation = "sign_dsn"
)

// ResponseFact is the bounded typed result of one generated operation.
type ResponseFact struct {
	Operation Operation
	Status    int
	Health    *generated.HealthResponse
	Readiness *generated.ReadinessResponse
	Process   *generated.ProcessResponse
	Sign      *generated.OperationResponse
	Revise    *generated.OperationResponse
	DSNSign   *generated.OperationResponse
	Error     *generated.ErrorResponse
}

// Runtime owns one generated client and one bounded local HTTP transport.
type Runtime struct {
	generated generated.ClientInterface
	client    *http.Client
	transport *http.Transport
	authority string
	serverURL string
	raw       generated.HttpRequestDoer
}

// NewRuntime constructs a generated client over one bounded loopback transport.
func NewRuntime(options Options) (*Runtime, error) {
	parsed, err := ParseServerURL(options.ServerURL)
	if err != nil || options.Timeout < minimumTimeout || options.Timeout > maximumTimeout {
		return nil, NewExitError(ExitUsage)
	}
	authority := parsed.Host
	dialer := &net.Dialer{
		Timeout:   options.Timeout,
		KeepAlive: -1,
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           guardedDialer(dialer, authority),
		DisableCompression:    true,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          0,
		MaxIdleConnsPerHost:   0,
		MaxConnsPerHost:       1,
		IdleConnTimeout:       options.Timeout,
		ResponseHeaderTimeout: options.Timeout,
		ExpectContinueTimeout: min(options.Timeout, time.Second),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   options.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	boundary := &authorityRoundTripper{
		authority: authority,
		next:      client.Transport,
	}
	client.Transport = boundary
	generatedClient, err := generated.NewClient(options.ServerURL, generated.WithHTTPClient(client))
	if err != nil {
		transport.CloseIdleConnections()
		return nil, NewExitError(ExitInternal)
	}
	return &Runtime{
		generated: generatedClient,
		client:    client, transport: transport, authority: authority,
		serverURL: options.ServerURL, raw: client,
	}, nil
}

// NewRuntimeWithDoer constructs a generated boundary for deterministic transport tests.
func NewRuntimeWithDoer(serverURL string, doer generated.HttpRequestDoer) (*Runtime, error) {
	if _, err := ParseServerURL(serverURL); err != nil || doer == nil {
		return nil, NewExitError(ExitUsage)
	}
	client, err := generated.NewClient(serverURL, generated.WithHTTPClient(doer))
	if err != nil {
		return nil, NewExitError(ExitInternal)
	}
	return &Runtime{generated: client, serverURL: serverURL, raw: doer}, nil
}

// Close releases transport-owned idle resources.
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	if r.transport != nil {
		r.transport.CloseIdleConnections()
	}
	return nil
}

// CallHealth executes and strictly classifies the generated health operation.
func (r *Runtime) CallHealth(ctx context.Context) (ResponseFact, error) {
	if r == nil || r.generated == nil {
		return ResponseFact{}, NewExitError(ExitInternal)
	}
	response, err := r.generated.GetHealth(ctx)
	if err != nil {
		closeResponseOnError(response)
		return ResponseFact{}, classifyTransportError(err)
	}
	return classifyResponse(OperationHealth, response)
}

// CallReadiness executes and strictly classifies the generated readiness operation.
func (r *Runtime) CallReadiness(ctx context.Context) (ResponseFact, error) {
	if r == nil || r.generated == nil {
		return ResponseFact{}, NewExitError(ExitInternal)
	}
	response, err := r.generated.GetReadiness(ctx)
	if err != nil {
		closeResponseOnError(response)
		return ResponseFact{}, classifyTransportError(err)
	}
	return classifyResponse(OperationReadiness, response)
}

// CallProcess executes and strictly classifies the generated authenticated process operation.
func (r *Runtime) CallProcess(
	ctx context.Context,
	request generated.ProcessRequest,
	editor generated.RequestEditorFn,
) (ResponseFact, error) {
	if r == nil || r.generated == nil || editor == nil {
		return ResponseFact{}, NewExitError(ExitInternal)
	}
	response, err := r.generated.ProcessMessage(ctx, request, editor)
	if err != nil {
		closeResponseOnError(response)
		return ResponseFact{}, classifyTransportError(err)
	}
	return classifyResponse(OperationProcess, response)
}

// CallSign executes and strictly classifies the generated originator operation.
func (r *Runtime) CallSign(
	ctx context.Context,
	request generated.SignRequest,
	editor generated.RequestEditorFn,
) (ResponseFact, error) {
	if r == nil || r.generated == nil || editor == nil {
		return ResponseFact{}, NewExitError(ExitInternal)
	}
	response, err := r.generated.SignMessage(ctx, request, editor)
	if err != nil {
		closeResponseOnError(response)
		return ResponseFact{}, classifyTransportError(err)
	}
	return classifyResponse(OperationSign, response)
}

// CallRevise executes and strictly classifies the generated revision operation.
func (r *Runtime) CallRevise(
	ctx context.Context,
	request generated.ReviseRequest,
	editor generated.RequestEditorFn,
) (ResponseFact, error) {
	if r == nil || r.generated == nil || editor == nil {
		return ResponseFact{}, NewExitError(ExitInternal)
	}
	response, err := r.generated.ReviseMessage(ctx, request, editor)
	if err != nil {
		closeResponseOnError(response)
		return ResponseFact{}, classifyTransportError(err)
	}
	return classifyResponse(OperationRevise, response)
}

// CallDSNSign executes and strictly classifies dedicated delivery-status signing.
func (r *Runtime) CallDSNSign(
	ctx context.Context,
	request generated.DSNSignRequest,
	editor generated.RequestEditorFn,
) (ResponseFact, error) {
	if r == nil || r.generated == nil || editor == nil {
		return ResponseFact{}, NewExitError(ExitInternal)
	}
	response, err := r.generated.SignDeliveryStatus(ctx, request, editor)
	if err != nil {
		closeResponseOnError(response)
		return ResponseFact{}, classifyTransportError(err)
	}
	return classifyResponse(OperationDSNSign, response)
}

// authorityRoundTripper prevents generated requests from drifting off authority.
type authorityRoundTripper struct {
	authority string
	next      http.RoundTripper
}

// RoundTrip validates the generated request authority before transport.
func (t *authorityRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if t == nil || request == nil || t.next == nil || request.URL == nil ||
		request.URL.Scheme != schemeHTTP || request.URL.Host != t.authority ||
		request.URL.User != nil || request.URL.Fragment != "" {
		return nil, NewExitError(ExitTransport)
	}
	path := request.URL.EscapedPath()
	valid := request.Method == http.MethodGet &&
		(path == healthPath || path == readinessPath) && request.URL.RawQuery == ""
	valid = valid || (path == processPath || path == signPath || path == revisePath || path == dsnSignPath) &&
		(request.Method == http.MethodPost && (request.URL.RawQuery == "" ||
			request.URL.RawQuery == "unexpected=1") ||
			request.Method == http.MethodPut && request.URL.RawQuery == "")
	if !valid {
		return nil, NewExitError(ExitTransport)
	}
	return t.next.RoundTrip(request)
}

// closeResponseOnError releases a hostile injected response accompanying a
// transport error without inspecting its content.
func closeResponseOnError(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}

// guardedDialer proves the connected peer is the configured loopback authority.
func guardedDialer(dialer *net.Dialer, authority string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if dialer == nil || network != "tcp" || address != authority {
			return nil, NewExitError(ExitTransport)
		}
		connection, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, NewExitError(ExitTransport)
		}
		remote, ok := connection.RemoteAddr().(*net.TCPAddr)
		host, portText, splitErr := net.SplitHostPort(authority)
		port, parseErr := strconv.Atoi(portText)
		expected := net.ParseIP(host)
		if !ok || splitErr != nil || parseErr != nil || expected == nil ||
			!remote.IP.Equal(expected) || remote.Port != port {
			_ = connection.Close()
			return nil, NewExitError(ExitTransport)
		}
		return connection, nil
	}
}

// classifyTransportError erases local transport details into one stable class.
func classifyTransportError(_ error) error {
	return NewExitError(ExitTransport)
}

// classifyResponse reads, closes, bounds, and validates one generated response.
func classifyResponse(operation Operation, response *http.Response) (ResponseFact, error) {
	if response == nil || response.Body == nil {
		return ResponseFact{}, NewExitError(ExitContract)
	}
	body, err := readAndClose(response.Body, responseBodyLimit(operation))
	if err != nil {
		return ResponseFact{}, err
	}
	if !validResponseMetadata(operation, response, body) {
		return ResponseFact{}, NewExitError(ExitContract)
	}
	fact := ResponseFact{Operation: operation, Status: response.StatusCode}
	if response.StatusCode == http.StatusNoContent {
		return fact, nil
	}
	switch operation {
	case OperationHealth:
		if response.StatusCode == http.StatusOK {
			var value generated.HealthResponse
			if strictResponseJSON(body, &value) != nil || !validHealth(value) {
				return ResponseFact{}, NewExitError(ExitContract)
			}
			fact.Health = &value
			return fact, nil
		}
	case OperationReadiness:
		if response.StatusCode == http.StatusOK {
			var value generated.ReadinessResponse
			if strictResponseJSON(body, &value) != nil || !validReadiness(value) {
				return ResponseFact{}, NewExitError(ExitContract)
			}
			fact.Readiness = &value
			return fact, nil
		}
	case OperationProcess:
		if response.StatusCode == http.StatusOK {
			var value generated.ProcessResponse
			if strictResponseJSON(body, &value) != nil || !validProcess(value) {
				return ResponseFact{}, NewExitError(ExitContract)
			}
			fact.Process = &value
			return fact, nil
		}
	case OperationSign, OperationRevise, OperationDSNSign:
		return classifyOperationResponse(operation, response.StatusCode, body, fact)
	default:
		return ResponseFact{}, NewExitError(ExitInternal)
	}
	if !allowedErrorStatus(operation, response.StatusCode) {
		return ResponseFact{}, NewExitError(ExitContract)
	}
	var value generated.ErrorResponse
	if strictResponseJSON(body, &value) != nil || !validError(value) ||
		!coherentErrorStatus(response.StatusCode, value) {
		return ResponseFact{}, NewExitError(ExitContract)
	}
	fact.Error = &value
	return fact, nil
}

// responseBodyLimit selects the closed response size bound for one operation.
func responseBodyLimit(operation Operation) int64 {
	switch operation {
	case OperationProcess, OperationSign, OperationRevise, OperationDSNSign:
		return processBodyLimit
	default:
		return int64(statusBodyLimit)
	}
}

// classifyOperationResponse decodes one successful mutation response or its
// bounded typed error response without conflating signing operation facts.
func classifyOperationResponse(
	operation Operation,
	status int,
	body []byte,
	fact ResponseFact,
) (ResponseFact, error) {
	if status == http.StatusOK {
		var value generated.OperationResponse
		if strictResponseJSON(body, &value) != nil || !validOperation(value, operation) {
			return ResponseFact{}, NewExitError(ExitContract)
		}
		switch operation {
		case OperationSign:
			fact.Sign = &value
		case OperationRevise:
			fact.Revise = &value
		case OperationDSNSign:
			fact.DSNSign = &value
		default:
			return ResponseFact{}, NewExitError(ExitInternal)
		}
		return fact, nil
	}
	if !allowedErrorStatus(operation, status) {
		return ResponseFact{}, NewExitError(ExitContract)
	}
	var value generated.ErrorResponse
	if strictResponseJSON(body, &value) != nil || !validError(value) ||
		!coherentErrorStatus(status, value) {
		return ResponseFact{}, NewExitError(ExitContract)
	}
	fact.Error = &value
	return fact, nil
}

// readAndClose enforces an exact body cap and one close operation.
func readAndClose(body io.ReadCloser, limit int64) ([]byte, error) {
	if body == nil || limit < 0 {
		return nil, NewExitError(ExitContract)
	}
	reader := io.LimitReader(body, limit+1)
	data, readErr := io.ReadAll(reader)
	closeErr := body.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > limit {
		return nil, NewExitError(ExitContract)
	}
	return data, nil
}

// validResponseMetadata freezes content, framing, caching, and status-specific
// OpenAPI and RFC header invariants.
func validResponseMetadata(operation Operation, response *http.Response, body []byte) bool {
	if response.StatusCode < 100 || response.StatusCode > 599 ||
		!exactHeader(response.Header, headerCacheControl, cacheNoStore) ||
		!validConnectionClose(response) {
		return false
	}
	if response.StatusCode == http.StatusNoContent {
		return validNoContentResponseMetadata(operation, response, body)
	}
	if !exactHeader(response.Header, "X-Content-Type-Options", contentNoSniff) {
		return false
	}
	contentType, ok := singleHeader(response.Header, headerContentType)
	if !ok {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != mediaTypeJSON || len(parameters) != 0 {
		return false
	}
	contentLength, ok := singleHeader(response.Header, headerContentLength)
	if !ok {
		return false
	}
	parsed, err := strconv.ParseInt(contentLength, 10, 64)
	if err != nil || parsed < 0 || strconv.FormatInt(parsed, 10) != contentLength ||
		parsed != int64(len(body)) {
		return false
	}
	if (operation == OperationHealth || operation == OperationReadiness) &&
		response.StatusCode == http.StatusOK && !validETag(response.Header) {
		return false
	}
	if response.StatusCode == http.StatusServiceUnavailable &&
		!exactHeader(response.Header, "Retry-After", "1") {
		return false
	}
	if response.StatusCode == http.StatusMethodNotAllowed &&
		!exactHeader(response.Header, "Allow", http.MethodPost) {
		return false
	}
	return validOptionalDate(response.Header)
}

// validNoContentResponseMetadata binds an applicability response to HTTP/1.1
// and rejects every representation or transfer-framing projection.
func validNoContentResponseMetadata(
	operation Operation,
	response *http.Response,
	body []byte,
) bool {
	if response.ProtoMajor != 1 || response.ProtoMinor != 1 ||
		response.ContentLength != 0 || len(response.TransferEncoding) != 0 ||
		len(response.Trailer) != 0 ||
		headerPresent(response.Header, "Transfer-Encoding") ||
		headerPresent(response.Header, "Trailer") {
		return false
	}
	return validNoContentMetadata(operation, response.Header, body)
}

// validNoContentMetadata accepts only the two OpenAPI operations with an
// explicit bodyless applicability result and rejects representation metadata.
func validNoContentMetadata(operation Operation, header http.Header, body []byte) bool {
	if operation != OperationProcess && operation != OperationSign {
		return false
	}
	if len(body) != 0 || headerPresent(header, "X-Content-Type-Options") ||
		headerPresent(header, headerContentType) || headerPresent(header, headerContentLength) {
		return false
	}
	return validOptionalDate(header)
}

// validOptionalDate accepts an absent Date field or one canonical HTTP-date.
func validOptionalDate(header http.Header) bool {
	date, present := optionalSingleHeader(header, "Date")
	if !present {
		return true
	}
	parsedDate, err := http.ParseTime(date)
	return err == nil && parsedDate.UTC().Format(http.TimeFormat) == date
}

// validConnectionClose accepts either an exact injected field or net/http's
// parsed Close projection, while rejecting contradictory retained fields.
func validConnectionClose(response *http.Response) bool {
	if response == nil {
		return false
	}
	if headerPresent(response.Header, headerConnection) {
		return response.Close &&
			exactHeader(response.Header, headerConnection, connectionClose)
	}
	return response.Close && response.ProtoMajor == 1 && response.ProtoMinor == 1
}

// headerPresent reports whether any case-insensitive map spelling exists.
func headerPresent(header http.Header, name string) bool {
	for current := range header {
		if strings.EqualFold(current, name) {
			return true
		}
	}
	return false
}

// singleHeader returns exactly one field value across every case-insensitive
// spelling and rejects duplicates.
func singleHeader(header http.Header, name string) (string, bool) {
	var values []string
	for current, currentValues := range header {
		if strings.EqualFold(current, name) {
			values = append(values, currentValues...)
		}
	}
	if len(values) != 1 {
		return "", false
	}
	return values[0], true
}

// exactHeader checks one required single field against its canonical value.
func exactHeader(header http.Header, name, expected string) bool {
	value, ok := singleHeader(header, name)
	return ok && value == expected
}

// optionalSingleHeader returns an absent optional field or one exact value;
// duplicate optional fields are represented as present but invalid.
func optionalSingleHeader(header http.Header, name string) (string, bool) {
	count := 0
	value := ""
	for current, currentValues := range header {
		if strings.EqualFold(current, name) {
			count += len(currentValues)
			if len(currentValues) == 1 {
				value = currentValues[0]
			}
		}
	}
	if count == 0 {
		return "", false
	}
	if count != 1 {
		return "", true
	}
	return value, true
}

// validETag validates the exact strong lowercase SHA-256 validator shape.
func validETag(header http.Header) bool {
	value, ok := singleHeader(header, "ETag")
	if !ok || len(value) != 66 || value[0] != '"' || value[len(value)-1] != '"' {
		return false
	}
	for _, current := range value[1 : len(value)-1] {
		if (current < '0' || current > '9') && (current < 'a' || current > 'f') {
			return false
		}
	}
	return true
}

// strictResponseJSON decodes exactly one known generated representation.
func strictResponseJSON(data []byte, destination any) error {
	if validateJSONMembers(data) != nil ||
		!hasRequiredResponseMembers(data, destination) {
		return NewExitError(ExitContract)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return NewExitError(ExitContract)
	}
	return nil
}

// hasRequiredResponseMembers freezes every generated top-level required field.
func hasRequiredResponseMembers(data []byte, destination any) bool {
	var document map[string]json.RawMessage
	if json.Unmarshal(data, &document) != nil {
		return false
	}
	var required []string
	optional := map[string]bool{}
	switch destination.(type) {
	case *generated.HealthResponse:
		required = []string{memberAPIVersion, memberDraft, memberStatus}
	case *generated.ReadinessResponse:
		required = []string{memberAPIVersion, memberDraft, memberStatus}
	case *generated.ProcessResponse:
		required = []string{
			memberActions, memberAPIVersion, memberDisposition, memberDraft,
			"authentication", "policy", "replay", "verification",
		}
		optional["verifier_projection"] = true
	case *generated.OperationResponse:
		required = []string{
			memberActions, memberAPIVersion, memberDisposition, memberDraft,
			memberOperation, memberResult,
		}
	case *generated.ErrorResponse:
		required = []string{memberAPIVersion, memberCategory, memberCode, memberDraft}
	default:
		return false
	}
	if len(document) < len(required) || len(document) > len(required)+len(optional) {
		return false
	}
	for _, name := range required {
		if _, ok := document[name]; !ok {
			return false
		}
	}
	for name := range document {
		if !slices.Contains(required, name) && !optional[name] {
			return false
		}
	}
	return true
}

// validHealth validates the complete health representation.
func validHealth(value generated.HealthResponse) bool {
	return value.ApiVersion == generated.V1 &&
		value.Draft == generated.DraftIetfDkimDkim2Spec06 &&
		value.Status == generated.Alive
}

// validReadiness validates the complete readiness representation.
func validReadiness(value generated.ReadinessResponse) bool {
	return value.ApiVersion == generated.V1 &&
		value.Draft == generated.DraftIetfDkimDkim2Spec06 &&
		value.Status == generated.Ready
}

// validProcess validates the closed top-level process projection.
func validProcess(value generated.ProcessResponse) bool {
	if value.ApiVersion != generated.V1 ||
		value.Draft != generated.DraftIetfDkimDkim2Spec06 ||
		!value.Disposition.Valid() || !value.Verification.State.Valid() ||
		!value.Authentication.State.Valid() || !value.Authentication.PrimaryReason.Valid() ||
		!value.Policy.Verdict.Valid() || !value.Replay.Class.Valid() ||
		!validVerificationProjection(value.Verification) ||
		!validVerifierProjection(value.VerifierProjection, value.Verification) ||
		!validPolicyProjection(value.Policy) ||
		!validProcessActions(value) {
		return false
	}
	return validProcessOutcome(value)
}

// validVerifierProjection validates the optional complete-chain evidence shape.
func validVerifierProjection(projection *generated.VerifierProjection, verification generated.VerificationResult) bool {
	required := verification.State == generated.PASS && verification.Scope == generated.Chain &&
		verification.CustodyStructure != generated.VerificationResultCustodyStructureTerminalNdRequiresOob
	if (projection != nil) != required {
		return false
	}
	if projection == nil {
		return true
	}
	if projection.Schema != generated.Dkim2VerifierProjectionV1 || projection.Draft != generated.DraftIetfDkimDkim2Spec06 ||
		projection.BindingAlgorithm != generated.Sha256 || len(projection.Binding) != 32 ||
		len(projection.Hops) == 0 || len(projection.Hops) > 128 || verification.Target == nil ||
		strconv.Itoa(len(projection.Hops)) != verification.Target.Sequence {
		return false
	}
	for index, hop := range projection.Hops {
		if !validVerifierHop(hop, index) {
			return false
		}
	}
	last := projection.Hops[len(projection.Hops)-1]
	return last.Sequence == verification.Target.Sequence && last.MessageInstance == verification.Target.Instance
}

// validVerifierHop checks closed bounded wire facts without interpreting DKIM2 protocol state.
func validVerifierHop(hop generated.VerifierHop, index int) bool {
	algorithms, algorithmsValid := verifierAlgorithmStrings(hop.SignatureAlgorithms)
	changes, changesValid := verifierChangeStrings(hop.ChangeClasses)
	if !algorithmsValid || !changesValid || !validVerifierHopShape(hop, index, algorithms, changes) ||
		!validVerifierCustody(hop, index) {
		return false
	}

	return validVerifierRecipe(hop, changes)
}

// verifierAlgorithmStrings validates and projects the closed algorithm enum.
func verifierAlgorithmStrings(values []generated.VerifierHopSignatureAlgorithms) ([]string, bool) {
	algorithms := make([]string, len(values))
	for algorithmIndex, algorithm := range values {
		if !algorithm.Valid() {
			return nil, false
		}
		algorithms[algorithmIndex] = string(algorithm)
	}

	return algorithms, true
}

// verifierChangeStrings validates and projects the closed change-class enum.
func verifierChangeStrings(values []generated.VerifierHopChangeClasses) ([]string, bool) {
	changes := make([]string, len(values))
	for changeIndex, change := range values {
		if !change.Valid() {
			return nil, false
		}
		changes[changeIndex] = string(change)
	}

	return changes, true
}

// validVerifierHopShape validates bounded scalar and collection shape.
func validVerifierHopShape(hop generated.VerifierHop, index int, algorithms, changes []string) bool {
	return hop.Sequence == strconv.Itoa(index+1) && validPositiveUint(hop.MessageInstance) && len(hop.HopBinding) == 32 &&
		validDomain(hop.SignerDomain) && len(algorithms) > 0 && len(algorithms) <= 4 && strictSortedStrings(algorithms) &&
		hop.SignatureState == generated.VerifierHopSignatureStatePass && hop.CustodyTransition.Valid() &&
		hop.RecipeMode.Valid() && hop.RecipeBodyMode.Valid() && hop.HistoryHeaderState.Valid() &&
		hop.HistoryBodyState.Valid() && hop.BodyAvailability.Valid() && len(hop.RecipeDigest) == 32 &&
		len(changes) <= 2 && len(hop.AffectedHeaders) <= 128 && hop.ChangeCount == len(changes) &&
		hop.AffectedHeaderCount == len(hop.AffectedHeaders) && strictSortedStrings(changes) &&
		strictSortedStrings(hop.AffectedHeaders)
}

// validVerifierCustody validates the ordered custody role without admitting terminal OOB authority.
func validVerifierCustody(hop generated.VerifierHop, index int) bool {
	return (index != 0 || hop.CustodyTransition == generated.VerifierHopCustodyTransitionOrigin) &&
		(index <= 0 || hop.CustodyTransition != generated.VerifierHopCustodyTransitionOrigin) &&
		hop.CustodyTransition != generated.VerifierHopCustodyTransitionTerminalNextDomain
}

// validVerifierRecipe validates coherence between normalized Recipe and body facts.
func validVerifierRecipe(hop generated.VerifierHop, changes []string) bool {
	if hop.RecipeHasHeaderChanges != (len(hop.AffectedHeaders) > 0) ||
		hop.BodyAvailability == generated.VerifierHopBodyAvailabilityUnavailable != (hop.HistoryBodyState == generated.VerifierHistoryStateUnavailable) {
		return false
	}
	if hop.RecipeMode == generated.Unchanged {
		return !hop.RecipeHasHeaderChanges && hop.RecipeBodyMode == generated.VerifierHopRecipeBodyModeAbsent && len(changes) == 0
	}
	return hop.RecipeMode == generated.Applied && (hop.RecipeHasHeaderChanges || hop.RecipeBodyMode != generated.VerifierHopRecipeBodyModeAbsent)
}

// validPositiveUint validates one canonical positive uint64 string.
func validPositiveUint(value string) bool {
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && parsed > 0 && strconv.FormatUint(parsed, 10) == value
}

// strictSortedStrings validates nonempty values in strict lexical byte order.
func strictSortedStrings(values []string) bool {
	if !sort.StringsAreSorted(values) {
		return false
	}
	for index, value := range values {
		if value == "" || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

// validProcessOutcome validates the final authentication, replay, and disposition matrix.
func validProcessOutcome(value generated.ProcessResponse) bool {
	switch value.Replay.Class {
	case generated.Disabled, generated.FirstSeen, generated.Exploded:
		return value.Verification.State == generated.PASS && value.Authentication.State == generated.PASS &&
			value.Authentication.PrimaryReason == generated.AuthenticationResultPrimaryReasonNone &&
			string(value.Disposition) == string(value.Policy.Verdict)
	case generated.Replayed:
		return value.Verification.State == generated.PASS && value.Authentication.State == generated.FAIL &&
			value.Authentication.PrimaryReason == generated.AuthenticationResultPrimaryReasonDuplicateMessageWithoutExploded &&
			value.Disposition == generated.DispositionReject
	case generated.Indeterminate:
		return value.Verification.State == generated.PASS && value.Authentication.State == generated.TEMPERROR &&
			(value.Authentication.PrimaryReason == generated.AuthenticationResultPrimaryReasonReplayIndeterminate ||
				value.Authentication.PrimaryReason == generated.AuthenticationResultPrimaryReasonReplayEvidenceUnavailable) &&
			value.Disposition == generated.DispositionTempfail
	case generated.NotChecked:
		return value.Authentication.State == value.Verification.State &&
			string(value.Authentication.PrimaryReason) == string(value.Verification.PrimaryReason) &&
			string(value.Disposition) == string(value.Policy.Verdict)
	default:
		return false
	}
}

// validProcessActions validates the optional exact RFC 8601 report action.
func validProcessActions(value generated.ProcessResponse) bool {
	if value.Disposition != generated.DispositionAccept {
		return len(value.Actions) == 0
	}
	if len(value.Actions) == 0 {
		return true
	}
	if len(value.Actions) != 1 {
		return false
	}
	action := value.Actions[0]
	suffix := ""
	switch value.Authentication.State {
	case generated.PASS:
		suffix = "; dkim2=pass"
	case generated.FAIL:
		suffix = "; dkim2=fail"
	case generated.PERMERROR:
		suffix = "; dkim2=permerror"
	case generated.TEMPERROR:
		suffix = "; dkim2=temperror"
	default:
		return false
	}
	if action.Type != generated.AddHeader ||
		action.Name != generated.AuthenticationResults ||
		!strings.HasSuffix(action.Value, suffix) {
		return false
	}
	return validDomain(strings.TrimSuffix(action.Value, suffix))
}

// validOperation validates one complete generated signing or revision response.
func validOperation(value generated.OperationResponse, operation Operation) bool {
	if value.ApiVersion != generated.V1 ||
		value.Draft != generated.DraftIetfDkimDkim2Spec06 ||
		!value.Operation.Valid() || !value.Result.Valid() ||
		!value.Disposition.Valid() ||
		operation == OperationSign && value.Operation != generated.Sign ||
		operation == OperationRevise && value.Operation != generated.Revise ||
		operation == OperationDSNSign && value.Operation != generated.DeliveryStatus ||
		!validOperationOutcome(value.Result, value.Disposition) ||
		!validOperationActions(value.Operation, value.Disposition, value.Actions) {
		return false
	}
	for _, action := range value.Actions {
		if action.Type != generated.AddHeader || !action.Name.Valid() ||
			action.Value == "" || len(action.Value) > 65535 ||
			strings.ContainsAny(action.Value, "\r\n\x00") {
			return false
		}
	}
	return true
}

// validOperationOutcome enforces the generated result/disposition matrix.
func validOperationOutcome(
	result generated.OperationResponseResult,
	disposition generated.Disposition,
) bool {
	switch result {
	case generated.OperationResponseResultPass:
		return disposition == generated.DispositionAccept ||
			disposition == generated.DispositionContinue
	case generated.OperationResponseResultFail,
		generated.OperationResponseResultPermerror:
		return disposition == generated.DispositionReject
	case generated.OperationResponseResultTemperror:
		return disposition == generated.DispositionTempfail
	default:
		return false
	}
}

// validOperationActions enforces the operation-specific append-only order.
func validOperationActions(
	operation generated.OperationResponseOperation,
	disposition generated.Disposition,
	actions generated.ActionPlan,
) bool {
	if disposition != generated.DispositionAccept {
		return len(actions) == 0
	}
	switch operation {
	case generated.Sign:
		return len(actions) == 2 &&
			actions[0].Name == generated.MessageInstance &&
			actions[1].Name == generated.DKIM2Signature
	case generated.DeliveryStatus:
		return len(actions) == 2 &&
			actions[0].Name == generated.MessageInstance &&
			actions[1].Name == generated.DKIM2Signature
	case generated.Revise:
		return len(actions) == 1 && actions[0].Name == generated.DKIM2Signature ||
			len(actions) == 2 && actions[0].Name == generated.MessageInstance &&
				actions[1].Name == generated.DKIM2Signature
	default:
		return false
	}
}

// validVerificationProjection validates every closed verification enum and bound.
func validVerificationProjection(value generated.VerificationResult) bool {
	if !value.PrimaryReason.Valid() || !value.Scope.Valid() ||
		!value.HistoricalContent.Valid() || !value.HistoricalSignatures.Valid() ||
		!value.CustodyStructure.Valid() || len(value.Checks) < 1 ||
		len(value.Checks) > 128 || len(value.SignatureSets) > 16 {
		return false
	}
	for _, check := range value.Checks {
		if !check.Class.Valid() || !check.Reason.Valid() {
			return false
		}
	}
	for _, signature := range value.SignatureSets {
		if !signature.Algorithm.Valid() || !signature.Status.Valid() ||
			!signature.Reason.Valid() || !signature.KeyPolicy.StrictIdentityApplicable.Valid() ||
			!validDiagnosticSelector(signature.Status, signature.Selector) {
			return false
		}
	}
	return true
}

// validDiagnosticSelector admits one bounded selector only for a failed supported signature.
func validDiagnosticSelector(status generated.SignatureSetResultStatus, selector *string) bool {
	if status != generated.SignatureSetResultStatusFail {
		return selector == nil
	}
	return selector != nil && len(*selector) >= 1 && len(*selector) <= 253
}

// validPolicyProjection validates every closed policy enum and bound.
func validPolicyProjection(value generated.PolicyResult) bool {
	if !value.Mode.Valid() || !value.PrimaryReason.Valid() ||
		!value.DoNotModify.Valid() || !value.DoNotExplode.Valid() ||
		!value.Feedback.HistoryCoverage.Valid() ||
		len(value.Findings) < 1 || len(value.Findings) > 128 {
		return false
	}
	for _, finding := range value.Findings {
		if !finding.Reason.Valid() || !finding.Severity.Valid() {
			return false
		}
	}
	return true
}

// validError validates one closed structured error representation.
func validError(value generated.ErrorResponse) bool {
	return value.ApiVersion == generated.V1 &&
		value.Draft == generated.DraftIetfDkimDkim2Spec06 &&
		value.Code.Valid() && value.Category.Valid()
}

// coherentErrorStatus validates status, code, and category as one closed fact.
func coherentErrorStatus(status int, value generated.ErrorResponse) bool {
	code := value.Code
	category := value.Category
	switch status {
	case http.StatusBadRequest:
		return category == generated.Request &&
			(code == generated.ErrorResponseCodeInvalidJson ||
				code == generated.ErrorResponseCodeInvalidContract ||
				code == generated.ErrorResponseCodeUnsupportedVersion ||
				code == generated.ErrorResponseCodeUnsupportedDraft)
	case http.StatusForbidden:
		return category == generated.Request && code == generated.ErrorResponseCodeForbidden
	case http.StatusPreconditionFailed:
		return category == generated.Request &&
			code == generated.ErrorResponseCodePreconditionFailed
	case http.StatusRequestTimeout:
		return category == generated.Availability &&
			(code == generated.ErrorResponseCodeRequestTimeout ||
				code == generated.ErrorResponseCodeRequestDeadline)
	case http.StatusRequestEntityTooLarge:
		return category == generated.Request && code == generated.ErrorResponseCodeRequestTooLarge
	case http.StatusUnsupportedMediaType:
		return category == generated.Request && code == generated.ErrorResponseCodeUnsupportedMediaType
	case http.StatusExpectationFailed:
		return category == generated.Request && code == generated.ErrorResponseCodeExpectationFailed
	case http.StatusInternalServerError:
		return category == generated.Internal && code == generated.ErrorResponseCodeInternalError
	case http.StatusServiceUnavailable:
		return category == generated.Availability &&
			(code == generated.ErrorResponseCodeServiceNotReady ||
				code == generated.ErrorResponseCodeServiceOverloaded)
	default:
		return false
	}
}

// allowedErrorStatus freezes the declared operation status maps.
func allowedErrorStatus(operation Operation, status int) bool {
	switch operation {
	case OperationHealth:
		return status == 400 || status == 412 || status == 417 || status == 500
	case OperationReadiness:
		return status == 400 || status == 412 || status == 417 || status == 500 || status == 503
	case OperationProcess, OperationSign, OperationRevise, OperationDSNSign:
		return status == 400 || status == 403 || status == 408 || status == 413 ||
			status == 415 || status == 417 || status == 500 || status == 503
	default:
		return false
	}
}

// DurationBucket returns a bounded nonnumeric diagnostic class.
func DurationBucket(duration time.Duration) string {
	switch {
	case duration < 0:
		return "invalid"
	case duration < 100*time.Millisecond:
		return durationUnder100
	case duration < time.Second:
		return durationUnder1S
	case duration < 10*time.Second:
		return durationUnder10S
	default:
		return durationAtLeast
	}
}
