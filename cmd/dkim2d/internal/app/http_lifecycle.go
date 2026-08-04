package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/observability"
)

const httpAssemblyInputRedacted = "dkim2d_http_assembly_input"

// FatalNotifier publishes one content-free instance-fatal transition.
type FatalNotifier interface {
	NotifyFatal()
}

// ServeReturnObserver synchronously classifies one transport Serve termination.
type ServeReturnObserver interface {
	NotifyServeReturn()
}

// ActivationAuthority authorizes the one HTTP registration-gate transition.
type ActivationAuthority interface {
	AllowHTTPActivation() bool
}

// HTTPFactory performs pure transport assembly without acquiring a listener.
type HTTPFactory interface {
	Assemble(HTTPAssemblyInput) (HTTPAssembly, error)
}

// HTTPAssembly owns validated transport composition before listener acquisition.
type HTTPAssembly interface {
	Bind(context.Context) (HTTPRuntime, error)
}

// HTTPRuntime owns one bound listener, handler gate, server, and serve operation.
type HTTPRuntime interface {
	Activate() error
	RejectNewRequests()
	Serve() error
	ServeStarted() <-chan struct{}
	Serving() bool
	CloseListener() error
	Shutdown(context.Context) error
	HandlersQuiescent() bool
	ForceClose(context.Context) error
	WaitHandlers(context.Context) error
}

// HTTPAssemblyInput carries only opaque app-owned dependencies into the transport adapter.
type HTTPAssemblyInput struct {
	snapshot          config.Snapshot
	capability        config.ProcessCapability
	signCapability    config.SignCapability
	reviseCapability  config.ReviseCapability
	dsnSignCapability config.DSNSignCapability
	processor         *InboundProcessor
	operation         OperationService
	readiness         *Readiness
	fatal             FatalNotifier
	serveReturn       ServeReturnObserver
	activation        ActivationAuthority
	baseContext       context.Context
	telemetry         *observability.Runtime
}

// newHTTPAssemblyInput validates one pure transport-construction input.
func newHTTPAssemblyInput(
	baseContext context.Context,
	preparation *config.RuntimePreparation,
	processor *InboundProcessor,
	readiness *Readiness,
	fatal FatalNotifier,
	serveReturn ServeReturnObserver,
	activation ActivationAuthority,
) (HTTPAssemblyInput, error) {
	if preparation == nil {
		return HTTPAssemblyInput{}, &LifecycleError{}
	}
	input := HTTPAssemblyInput{
		snapshot:    preparation.Snapshot(),
		capability:  preparation.ProcessCapability(),
		processor:   processor,
		readiness:   readiness,
		fatal:       fatal,
		serveReturn: serveReturn,
		activation:  activation,
		baseContext: baseContext,
	}
	if !input.baseValid() {
		return HTTPAssemblyInput{}, &LifecycleError{}
	}
	return input, nil
}

// Valid reports whether every structurally provable assembly dependency is present.
func (i HTTPAssemblyInput) Valid() bool {
	if !i.baseValid() {
		return false
	}
	enabled := i.snapshot.Signing().Enabled()
	return enabled == !nilInterface(i.operation)
}

// baseValid reports the transport dependencies that exist before optional
// signing-service composition.
func (i HTTPAssemblyInput) baseValid() bool {
	return i.snapshot.Valid() && i.processor != nil && i.readiness != nil &&
		!nilInterface(i.fatal) && !nilInterface(i.serveReturn) &&
		!nilInterface(i.activation) && !nilInterface(i.baseContext)
}

// Snapshot returns the immutable daemon configuration.
func (i HTTPAssemblyInput) Snapshot() config.Snapshot { return i.snapshot }

// ProcessCapability returns the opaque prepared capability handle.
func (i HTTPAssemblyInput) ProcessCapability() config.ProcessCapability {
	return i.capability
}

// SignCapability returns the opaque prepared originator capability handle.
func (i HTTPAssemblyInput) SignCapability() config.SignCapability {
	return i.signCapability
}

// ReviseCapability returns the opaque prepared revision capability handle.
func (i HTTPAssemblyInput) ReviseCapability() config.ReviseCapability {
	return i.reviseCapability
}

// DSNSignCapability returns the opaque prepared delivery-status capability handle.
func (i HTTPAssemblyInput) DSNSignCapability() config.DSNSignCapability {
	return i.dsnSignCapability
}

// OperationService returns the optional concrete signing application service.
func (i HTTPAssemblyInput) OperationService() OperationService { return i.operation }

// Processor returns the immutable inbound application service.
func (i HTTPAssemblyInput) Processor() *InboundProcessor { return i.processor }

// Readiness returns the instance-owned no-I/O readiness source.
func (i HTTPAssemblyInput) Readiness() *Readiness { return i.readiness }

// FatalNotifier returns the instance-owned shutdown arbiter.
func (i HTTPAssemblyInput) FatalNotifier() FatalNotifier { return i.fatal }

// ServeReturnObserver returns the synchronous transport-exit arbiter.
func (i HTTPAssemblyInput) ServeReturnObserver() ServeReturnObserver { return i.serveReturn }

// ActivationAuthority returns the one app-owned gate authorization source.
func (i HTTPAssemblyInput) ActivationAuthority() ActivationAuthority { return i.activation }

// BaseContext returns the daemon-owned parent for request contexts.
func (i HTTPAssemblyInput) BaseContext() context.Context { return i.baseContext }

// Observability returns the optional instance-owned telemetry runtime.
func (i HTTPAssemblyInput) Observability() *observability.Runtime { return i.telemetry }

// withObservability binds the already acquired telemetry owner to transport assembly.
func (i HTTPAssemblyInput) withObservability(runtime *observability.Runtime) HTTPAssemblyInput {
	i.telemetry = runtime
	return i
}

// withOperation binds the same-generation signing service and capabilities.
func (i HTTPAssemblyInput) withOperation(
	service OperationService,
	sign config.SignCapability,
	revise config.ReviseCapability,
	dsnSign config.DSNSignCapability,
) HTTPAssemblyInput {
	i.operation = service
	i.signCapability = sign
	i.reviseCapability = revise
	i.dsnSignCapability = dsnSign
	return i
}

// String returns a constant content-free assembly-input representation.
func (HTTPAssemblyInput) String() string { return httpAssemblyInputRedacted }

// GoString returns a constant content-free assembly-input representation.
func (HTTPAssemblyInput) GoString() string { return httpAssemblyInputRedacted }

// Format prevents formatting verbs from traversing assembly dependencies.
func (HTTPAssemblyInput) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, httpAssemblyInputRedacted)
}

// MarshalJSON rejects serialization of live assembly dependencies.
func (HTTPAssemblyInput) MarshalJSON() ([]byte, error) {
	return nil, &LifecycleError{}
}

// MarshalText rejects text serialization of live assembly dependencies.
func (HTTPAssemblyInput) MarshalText() ([]byte, error) {
	return nil, &LifecycleError{}
}

var _ fmt.Formatter = HTTPAssemblyInput{}
var _ json.Marshaler = HTTPAssemblyInput{}
