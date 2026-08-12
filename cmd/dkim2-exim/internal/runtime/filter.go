package runtime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	eximconfig "github.com/croessner/dkim2/cmd/dkim2-exim/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/daemon"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/daemon/generated"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/evidence"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/filter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/securefile"
)

const (
	capabilityBytes  = 32
	capabilityHeader = "X-DKIM2-Capability"
	fixedUserAgent   = "dkim2-exim/1"
	signRoute        = "/v1/sign"
	reviseRoute      = "/v1/revise"
)

// filterRuntime owns one one-shot generated client and its protected resources.
type filterRuntime struct {
	config     Config
	limits     filter.Limits
	processor  *daemon.FilterProcessor
	loader     *evidence.IncomingLoader
	reader     *evidence.Reader
	transport  *http.Transport
	capability *operationCapability
	sink       resultSink
	sinkID     securefile.Identity
}

// resultSink accepts bounded, non-authoritative filter result records.
type resultSink interface {
	Write([]byte) error
	Close() error
}

const wholeFilterTimeout = 10 * time.Second

// operationCapability owns one exact route-bound 32-byte capability.
type operationCapability struct {
	value  [capabilityBytes]byte
	target string
}

// String keeps route capability diagnostics content-free.
func (operationCapability) String() string { return "dkim2_exim_capability{redacted}" }

// GoString keeps route capability Go diagnostics content-free.
func (c operationCapability) GoString() string { return c.String() }

// Format prevents formatting from traversing route capability bytes.
func (c operationCapability) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, c.String())
}

// MarshalJSON rejects serialization of route capability bytes.
func (operationCapability) MarshalJSON() ([]byte, error) { return nil, errRuntime }

// MarshalText rejects textual serialization of route capability bytes.
func (operationCapability) MarshalText() ([]byte, error) { return nil, errRuntime }

// String keeps one-shot runtime diagnostics content-free.
func (filterRuntime) String() string { return "dkim2_exim_filter_runtime{redacted}" }

// GoString keeps one-shot runtime Go diagnostics content-free.
func (r filterRuntime) GoString() string { return r.String() }

// Format prevents formatting from traversing protected one-shot state.
func (r filterRuntime) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// MarshalJSON rejects serialization of protected one-shot state.
func (filterRuntime) MarshalJSON() ([]byte, error) { return nil, errRuntime }

// MarshalText rejects textual serialization of protected one-shot state.
func (filterRuntime) MarshalText() ([]byte, error) { return nil, errRuntime }

// RunFilter loads one protected operation runtime and executes it silently.
func RunFilter(
	ctx context.Context,
	configPath string,
	operation adapter.FilterOperation,
	arguments []string,
	input io.Reader,
	output io.Writer,
) (status int) {
	status = filter.ExitDefer
	if ctx == nil {
		return status
	}
	wholeContext, cancelWhole := context.WithTimeout(ctx, wholeFilterTimeout)
	defer cancelWhole()
	defer func() {
		if recover() != nil {
			status = filter.ExitDefer
		}
	}()
	instance, err := openSnapshotFilterRuntime(configPath, operation)
	if err != nil {
		return filter.ExitDefer
	}
	defer instance.closeSafely()
	defer instance.emitResultSafely(operation, &status)
	requestContext, cancel := filterRequestContext(wholeContext, instance.config.Timeout)
	defer cancel()
	releaseIO := interruptOwnedIO(requestContext, input, output)
	defer releaseIO()
	return filter.Execute(requestContext, filter.RunConfig{
		Operation: operation,
		Arguments: arguments,
		Input:     input,
		Output:    output,
		Loader:    instance.loader,
		Processor: instance.processor,
		TempDir:   os.TempDir(),
		Limits:    instance.limits,
	})
}

// filterRequestContext bounds configured authority by the remaining whole-process budget.
func filterRequestContext(parent context.Context, configured time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, configured)
}

// closeSafely releases runtime resources without changing the authoritative result.
func (r *filterRuntime) closeSafely() {
	defer func() { _ = recover() }()
	r.close()
}

// emitResultSafely contains all non-authoritative sink failures and panics.
func (r *filterRuntime) emitResultSafely(operation adapter.FilterOperation, status *int) {
	defer func() { _ = recover() }()
	if status != nil {
		r.emitResult(operation, *status)
	}
}

// interruptOwnedIO closes only production file descriptors on child cancellation.
func interruptOwnedIO(ctx context.Context, input io.Reader, output io.Writer) func() {
	inputFile, inputOwned := input.(*os.File)
	outputFile, outputOwned := output.(*os.File)
	if ctx == nil || !inputOwned && !outputOwned {
		return func() {}
	}
	done := make(chan struct{})
	joined := make(chan struct{})
	var once sync.Once
	var closeOnce sync.Once
	closeOwned := func() {
		closeOnce.Do(func() {
			if inputOwned {
				_ = inputFile.Close()
			}
			if outputOwned && outputFile != inputFile {
				_ = outputFile.Close()
			}
		})
	}
	go func() {
		defer close(joined)
		select {
		case <-ctx.Done():
			closeOwned()
		case <-done:
		}
	}()
	return func() {
		if ctx.Err() != nil {
			closeOwned()
		}
		once.Do(func() { close(done) })
		<-joined
	}
}

// openSnapshotFilterRuntime constructs the one-shot filter from the sole YAML snapshot owner.
func openSnapshotFilterRuntime(configPath string, operation adapter.FilterOperation) (*filterRuntime, error) {
	configOperation := eximconfig.OperationSign
	route := signRoute
	if operation == adapter.FilterRevise {
		configOperation, route = eximconfig.OperationRevise, reviseRoute
	}
	if operation != adapter.FilterSign && operation != adapter.FilterRevise {
		return nil, errRuntime
	}
	snapshot, err := eximconfig.LoadForOperation(configPath, configOperation)
	if err != nil || snapshot.ForOperation(configOperation) != nil {
		return nil, errRuntime
	}
	capabilityValue, identity, err := securefile.ReadCapability(snapshot.CapabilityPath(configOperation))
	if err != nil || protectedIdentitiesAlias(snapshot.ConfigIdentity(), identity) {
		Clear(capabilityValue)
		return nil, errRuntime
	}
	capability := &operationCapability{target: snapshot.Endpoint() + route}
	copy(capability.value[:], capabilityValue)
	Clear(capabilityValue)
	var sink *unixgramSink
	var sinkIdentity securefile.Identity
	_, destination := snapshot.Logging()
	if after, ok := strings.CutPrefix(destination, "unixgram:"); ok {
		sink, sinkIdentity, err = openUnixgramSink(after)
		if err != nil || protectedIdentitiesAlias(snapshot.ConfigIdentity(), sinkIdentity) ||
			protectedIdentitiesAlias(identity, sinkIdentity) {
			if sink != nil {
				_ = sink.Close()
			}
			sink = nil
		}
	}
	transport, client, err := newFilterClient(
		Config{Endpoint: snapshot.Endpoint(), Timeout: snapshot.DaemonTimeout()},
		capability,
	)
	if err != nil {
		if sink != nil {
			_ = sink.Close()
		}
		capability.close()
		return nil, errRuntime
	}
	tenant, domain := snapshot.SigningContext()
	messageBytes, headerBytes, headerCount, headerFieldBytes, _ := snapshot.Limits()
	limits := filter.Limits{
		MessageBytes: int(messageBytes), HeaderBytes: int(headerBytes),
		HeaderCount: headerCount, HeaderFieldBytes: int(headerFieldBytes),
	}
	processor, err := daemon.NewFilterProcessor(client, tenant, domain)
	if err != nil {
		transport.CloseIdleConnections()
		capability.close()
		if sink != nil {
			_ = sink.Close()
		}
		return nil, errRuntime
	}
	instance := &filterRuntime{
		config: Config{Endpoint: snapshot.Endpoint(), Timeout: snapshot.DaemonTimeout()},
		limits: limits, processor: processor, transport: transport, capability: capability,
		sink: sink, sinkID: sinkIdentity,
	}
	if operation == adapter.FilterRevise {
		enabled, root, key, _, _, _ := snapshot.Evidence()
		if !enabled {
			instance.close()
			return nil, errRuntime
		}
		reader, readerErr := evidence.NewReader(
			root, key, snapshot.EvidenceReadinessPath(), time.Now,
		)
		if readerErr != nil ||
			reader.ConflictsProtectedIdentity(snapshot.ConfigIdentity()) ||
			reader.ConflictsProtectedIdentity(identity) ||
			sink != nil && reader.ConflictsProtectedIdentity(sinkIdentity) {
			if reader != nil {
				_ = reader.Close()
			}
			instance.close()
			return nil, errRuntime
		}
		loader, loaderErr := evidence.NewIncomingLoader(reader)
		if loaderErr != nil {
			_ = reader.Close()
			instance.close()
			return nil, errRuntime
		}
		instance.reader, instance.loader = reader, loader
	}
	return instance, nil
}

// emitResult writes one bounded non-authoritative filter result datagram.
func (r *filterRuntime) emitResult(operation adapter.FilterOperation, status int) {
	if r == nil || r.sink == nil {
		return
	}
	name := "sign"
	if operation == adapter.FilterRevise {
		name = "revise"
	}
	result := "failure"
	if status == filter.ExitSuccess {
		result = "success"
	}
	value, err := json.Marshal(struct {
		Level     string `json:"level"`
		Event     string `json:"event"`
		Hook      string `json:"hook"`
		Operation string `json:"operation"`
		Result    string `json:"result"`
	}{
		Level: "INFO", Event: "exim_adapter", Hook: "transport_filter",
		Operation: name, Result: result,
	})
	if err != nil {
		return
	}
	value = append(value, '\n')
	_ = r.sink.Write(value)
	clear(value)
}

// protectedIdentitiesAlias rejects a shared child or final protected parent.
func protectedIdentitiesAlias(left securefile.Identity, right securefile.Identity) bool {
	return left.Equal(right) || left.SameParent(right)
}

// newFilterClient constructs one proxy-free exact-loopback generated client.
func newFilterClient(config Config, capability *operationCapability) (*http.Transport, *generated.Client, error) {
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || config.Validate() != nil || capability == nil {
		return nil, nil, errRuntime
	}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
		MaxConnsPerHost: 1, MaxResponseHeaderBytes: 64 << 10,
		DialContext: exactDialer(parsed.Host, config.Timeout),
	}
	httpClient := &http.Client{
		Transport: transport, Timeout: config.Timeout, CheckRedirect: rejectRedirect,
	}
	client, err := generated.NewClient(
		config.Endpoint,
		generated.WithHTTPClient(httpClient),
		generated.WithRequestEditorFn(editFixedRequest),
		generated.WithRequestEditorFn(capability.editRequest),
	)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, errRuntime
	}
	return transport, client, nil
}

// NewProcessClient constructs one strict generated process client and its release function.
func NewProcessClient(endpoint string, timeout time.Duration, capabilityValue []byte) (*generated.Client, func(), error) {
	if len(capabilityValue) != capabilityBytes {
		return nil, nil, errRuntime
	}
	capability := &operationCapability{target: endpoint + "/v1/process"}
	copy(capability.value[:], capabilityValue)
	transport, client, err := newFilterClient(Config{Endpoint: endpoint, Timeout: timeout}, capability)
	if err != nil {
		capability.close()
		return nil, nil, errRuntime
	}
	return client, func() {
		transport.CloseIdleConnections()
		capability.close()
	}, nil
}

// exactDialer rejects DNS, proxy, redirect, and cross-authority dialing.
func exactDialer(authority string, timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if ctx == nil || network != "tcp" || address != authority {
			return nil, errRuntime
		}
		return dialer.DialContext(ctx, network, address)
	}
}

// rejectRedirect prevents capability forwarding to another request target.
func rejectRedirect(*http.Request, []*http.Request) error { return errRuntime }

// editFixedRequest adds only the bounded generated-client protocol headers.
func editFixedRequest(ctx context.Context, request *http.Request) error {
	if ctx == nil || ctx.Err() != nil || request == nil || request.Header == nil ||
		request.Method != http.MethodPost || request.URL == nil ||
		request.URL.User != nil || request.URL.RawQuery != "" ||
		request.URL.Fragment != "" || request.Body == nil ||
		request.ContentLength <= 0 || len(request.TransferEncoding) != 0 ||
		len(request.Header) != 1 ||
		!exactHeader(request.Header, "Content-Type", "application/json") {
		return errRuntime
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("User-Agent", fixedUserAgent)
	return nil
}

// editRequest adds the capability only to its exact generated route.
func (c *operationCapability) editRequest(ctx context.Context, request *http.Request) error {
	if c == nil || !c.valid() || ctx == nil || ctx.Err() != nil ||
		request == nil || request.URL == nil || request.URL.String() != c.target ||
		len(request.Header) != 4 ||
		!exactHeader(request.Header, "Content-Type", "application/json") ||
		!exactHeader(request.Header, "Accept", "application/json") ||
		!exactHeader(request.Header, "Cache-Control", "no-store") ||
		!exactHeader(request.Header, "User-Agent", fixedUserAgent) ||
		request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" ||
		request.Header.Get(capabilityHeader) != "" {
		return errRuntime
	}
	request.Header.Set(capabilityHeader, base64.RawURLEncoding.EncodeToString(c.value[:]))
	return nil
}

// valid reports whether a capability remains nonzero and route-bound.
func (c *operationCapability) valid() bool {
	if c == nil || c.target == "" {
		return false
	}
	var nonzero byte
	for _, current := range c.value {
		nonzero |= current
	}
	return nonzero != 0
}

// close clears one protected capability and its request target.
func (c *operationCapability) close() {
	if c == nil {
		return
	}
	clear(c.value[:])
	c.target = ""
}

// exactHeader accepts one canonical single-valued HTTP field.
func exactHeader(header http.Header, name, value string) bool {
	values, present := header[http.CanonicalHeaderKey(name)]
	return present && len(values) == 1 && values[0] == value
}

// close releases every one-shot protected or pooled runtime resource.
func (r *filterRuntime) close() {
	if r == nil {
		return
	}
	if r.reader != nil {
		_ = r.reader.Close()
		r.reader = nil
	}
	if r.transport != nil {
		r.transport.CloseIdleConnections()
		r.transport = nil
	}
	if r.capability != nil {
		r.capability.close()
		r.capability = nil
	}
	if r.sink != nil {
		_ = r.sink.Close()
		r.sink = nil
	}
	r.processor = nil
	r.loader = nil
}
