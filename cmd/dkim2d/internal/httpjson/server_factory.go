package httpjson

import (
	"context"
	"encoding"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/observability"
)

const serverRuntimeRedacted = "dkim2d_http_server_runtime"

type serverListenFunc func(network, address string) (net.Listener, error)

// ServerFactory performs pure HTTP transport assembly.
type ServerFactory struct {
	listen serverListenFunc
}

// NewServerFactory constructs the production HTTP transport factory without
// acquiring any runtime resource.
func NewServerFactory() *ServerFactory {
	return &ServerFactory{listen: net.Listen}
}

// Assemble validates one immutable app snapshot and constructs its pure HTTP
// transport graph without opening a listener.
func (f *ServerFactory) Assemble(input app.HTTPAssemblyInput) (app.HTTPAssembly, error) {
	if f == nil || f.listen == nil || !input.Valid() {
		return nil, &serverRuntimeError{}
	}
	server := input.Snapshot().Server()
	return newServerAssembly(
		input.BaseContext(),
		serverSettings{
			authority:         server.Listen(),
			readHeaderTimeout: server.ReadHeaderTimeout(),
			readTimeout:       server.ReadTimeout(),
			writeTimeout:      server.WriteTimeout(),
			requestDeadline:   server.RequestDeadline(),
			shutdownTimeout:   server.ShutdownTimeout(),
			maxInFlight:       int(server.MaxInFlight()),
			maxWaiters:        int(server.MaxWaiters()),
			admissionWait:     server.AdmissionWait(),
		},
		input.ProcessCapability(),
		input.Readiness(),
		input.Processor(),
		input.FatalNotifier(),
		input.ActivationAuthority(),
		input.ServeReturnObserver(),
		f.listen,
		input.Observability(),
	)
}

type serverSettings struct {
	authority         string
	readHeaderTimeout time.Duration
	readTimeout       time.Duration
	writeTimeout      time.Duration
	requestDeadline   time.Duration
	shutdownTimeout   time.Duration
	maxInFlight       int
	maxWaiters        int
	admissionWait     time.Duration
}

// valid reports whether the copied server snapshot retains every exact
// cross-field and resource bound enforced by configuration.
func (s serverSettings) valid() bool {
	return validServerAuthority(s.authority) &&
		s.readHeaderTimeout >= time.Second &&
		s.readHeaderTimeout <= 30*time.Second &&
		s.readTimeout >= time.Second &&
		s.readTimeout <= 120*time.Second &&
		s.requestDeadline >= time.Second &&
		s.requestDeadline <= 120*time.Second &&
		s.writeTimeout >= time.Second &&
		s.writeTimeout <= 180*time.Second &&
		s.shutdownTimeout >= time.Second &&
		s.shutdownTimeout <= 120*time.Second &&
		s.admissionWait >= 0 &&
		s.admissionWait <= time.Second &&
		s.maxInFlight >= 1 &&
		s.maxInFlight <= maxProcessInFlight &&
		s.maxWaiters >= 0 &&
		s.maxWaiters <= maxProcessWaiters &&
		s.readHeaderTimeout <= s.readTimeout &&
		s.readTimeout <= s.requestDeadline &&
		s.writeTimeout >= s.requestDeadline+time.Second
}

type serverAssembly struct {
	settings    serverSettings
	boundary    *HTTPBoundary
	gate        *HandlerRegistrationGate
	serveReturn app.ServeReturnObserver
	baseContext context.Context
	listen      serverListenFunc
	bindStarted atomic.Bool
}

// newServerAssembly constructs the full handler graph without acquiring a
// listener or performing external I/O.
func newServerAssembly(
	baseContext context.Context,
	settings serverSettings,
	matcher capabilityMatcher,
	readiness readinessSource,
	processor inboundProcessService,
	fatal FatalNotifier,
	activation activationAuthority,
	serveReturn app.ServeReturnObserver,
	listen serverListenFunc,
	telemetry ...*observability.Runtime,
) (assembly *serverAssembly, resultErr error) {
	defer func() {
		if recover() != nil {
			assembly = nil
			resultErr = &serverRuntimeError{}
		}
	}()
	if !settings.valid() || nilInterfaceValue(matcher) ||
		nilInterfaceValue(readiness) || nilInterfaceValue(processor) ||
		nilInterfaceValue(fatal) || nilInterfaceValue(activation) ||
		nilInterfaceValue(serveReturn) ||
		nilInterfaceValue(baseContext) ||
		listen == nil {
		return nil, &serverRuntimeError{}
	}
	validator, err := NewRequestValidator()
	if err != nil {
		return nil, &serverRuntimeError{}
	}
	boundary, err := NewHTTPBoundary(
		BoundaryConfig{
			Authority:       settings.authority,
			RequestDeadline: settings.requestDeadline,
			MaxInFlight:     settings.maxInFlight,
			MaxWaiters:      settings.maxWaiters,
			AdmissionWait:   settings.admissionWait,
		},
		matcher,
		readiness,
		processor,
		fatal,
		validator,
		firstTelemetryRuntime(telemetry),
	)
	if err != nil {
		return nil, &serverRuntimeError{}
	}
	gate, err := newHandlerRegistrationGate(boundary, activation, fatal)
	if err != nil {
		return nil, &serverRuntimeError{}
	}
	return &serverAssembly{
		settings:    settings,
		boundary:    boundary,
		gate:        gate,
		serveReturn: serveReturn,
		baseContext: baseContext,
		listen:      listen,
	}, nil
}

// firstTelemetryRuntime returns the sole optional instance runtime.
func firstTelemetryRuntime(values []*observability.Runtime) *observability.Runtime {
	if len(values) != 1 {
		return nil
	}
	return values[0]
}

// Bind performs the assembly's only listener acquisition and transfers exact
// ownership into one runtime.
func (a *serverAssembly) Bind(ctx context.Context) (runtime app.HTTPRuntime, resultErr error) {
	defer func() {
		if recover() != nil {
			runtime = nil
			resultErr = &serverRuntimeError{}
		}
	}()
	if a == nil || !a.settings.valid() || a.boundary == nil || a.gate == nil ||
		nilInterfaceValue(a.baseContext) || a.listen == nil ||
		nilInterfaceValue(ctx) || ctx.Err() != nil ||
		!a.bindStarted.CompareAndSwap(false, true) {
		return nil, &serverRuntimeError{}
	}
	raw, err := a.listen("tcp", a.settings.authority)
	if err != nil || nilInterfaceValue(raw) {
		closeRawServerListener(raw)
		return nil, &serverRuntimeError{}
	}
	owned := false
	defer func() {
		if !owned {
			closeRawServerListener(raw)
		}
	}()
	if ctx.Err() != nil || !serverListenerMatches(raw, a.settings.authority) {
		return nil, &serverRuntimeError{}
	}
	listener, err := NewServerListener(raw, currentHTTPDate)
	if err != nil || listener == nil {
		return nil, &serverRuntimeError{}
	}
	bound, err := newServerRuntime(
		a.baseContext,
		a.settings,
		a.boundary,
		a.gate,
		listener,
		a.serveReturn,
	)
	if err != nil {
		return nil, &serverRuntimeError{}
	}
	if ctx.Err() != nil {
		return nil, &serverRuntimeError{}
	}
	owned = true
	return bound, nil
}

// validServerAuthority accepts only one canonical numeric loopback TCP
// authority with a nonzero decimal port.
func validServerAuthority(authority string) bool {
	host, portText, err := net.SplitHostPort(authority)
	if err != nil || host == "" || portText == "" {
		return false
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsLoopback() || address.Is4In6() ||
		address.Zone() != "" ||
		address.String() != host {
		return false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	return err == nil && port != 0 &&
		strconv.FormatUint(port, 10) == portText &&
		net.JoinHostPort(host, portText) == authority
}

// serverListenerMatches verifies that acquisition returned the exact requested
// canonical TCP authority.
func serverListenerMatches(listener net.Listener, authority string) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	if nilInterfaceValue(listener) {
		return false
	}
	address := listener.Addr()
	return !nilInterfaceValue(address) &&
		address.Network() == "tcp" &&
		address.String() == authority
}

// closeRawServerListener contains arbitrary close behavior while relinquishing
// one failed acquisition.
func closeRawServerListener(listener net.Listener) {
	if nilInterfaceValue(listener) {
		return
	}
	defer func() {
		_ = recover()
	}()
	_ = listener.Close()
}

// currentHTTPDate returns one canonical IMF-fixdate without retaining clock
// state or subsecond precision.
func currentHTTPDate() (string, bool) {
	return time.Now().UTC().Truncate(time.Second).Format(http.TimeFormat), true
}

// String returns a constant content-free factory representation.
func (*ServerFactory) String() string { return serverRuntimeRedacted }

// GoString returns a constant content-free factory representation.
func (*ServerFactory) GoString() string { return serverRuntimeRedacted }

// Format prevents formatting verbs from traversing factory dependencies.
func (*ServerFactory) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, serverRuntimeRedacted)
}

// MarshalJSON rejects serialization of factory dependencies.
func (*ServerFactory) MarshalJSON() ([]byte, error) {
	return nil, &serverRuntimeError{}
}

// MarshalText rejects text serialization of factory dependencies.
func (*ServerFactory) MarshalText() ([]byte, error) {
	return nil, &serverRuntimeError{}
}

// String returns a constant content-free assembly representation.
func (*serverAssembly) String() string { return serverRuntimeRedacted }

// GoString returns a constant content-free assembly representation.
func (*serverAssembly) GoString() string { return serverRuntimeRedacted }

// Format prevents formatting verbs from traversing assembly dependencies.
func (*serverAssembly) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, serverRuntimeRedacted)
}

// MarshalJSON rejects serialization of assembly dependencies.
func (*serverAssembly) MarshalJSON() ([]byte, error) {
	return nil, &serverRuntimeError{}
}

// MarshalText rejects text serialization of assembly dependencies.
func (*serverAssembly) MarshalText() ([]byte, error) {
	return nil, &serverRuntimeError{}
}

var (
	_ app.HTTPFactory        = (*ServerFactory)(nil)
	_ app.HTTPAssembly       = (*serverAssembly)(nil)
	_ fmt.Formatter          = (*ServerFactory)(nil)
	_ fmt.Formatter          = (*serverAssembly)(nil)
	_ json.Marshaler         = (*ServerFactory)(nil)
	_ json.Marshaler         = (*serverAssembly)(nil)
	_ encoding.TextMarshaler = (*ServerFactory)(nil)
	_ encoding.TextMarshaler = (*serverAssembly)(nil)
)
