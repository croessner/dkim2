// Package app owns Fx composition and the adapter process lifecycle.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/daemon"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/observability"
	"go.uber.org/fx"
)

const (
	// StartTimeout bounds Fx startup independently of request deadlines.
	StartTimeout = 15 * time.Second
)

var errApplication = errors.New("dkim2-dsn-propagator application failure")

const redactedCapabilityOwner = "dkim2_dsn_propagator_capability_owner{redacted}"

// protectedCapability is the narrow credential ownership boundary.
type protectedCapability interface {
	Close() error
}

// capabilityLoader loads one exact protected capability.
type capabilityLoader func(string) (protectedCapability, error)

// capabilityOwner defers protected loading until Fx starts and clears it on stop.
type capabilityOwner struct {
	state *capabilityOwnerState
}

// capabilityOwnerState keeps copied holders opaque through one private guard.
type capabilityOwnerState struct {
	guard *capabilityOwnerGuard
}

// capabilityOwnerGuard owns the path, loader, and live credential.
type capabilityOwnerGuard struct {
	mu         *sync.Mutex
	path       string
	load       capabilityLoader
	capability protectedCapability
}

// newCapabilityOwner constructs one unstarted protected owner.
func newCapabilityOwner(snapshot config.Snapshot, load capabilityLoader) (*capabilityOwner, error) {
	if load == nil || snapshot.CapabilityFile() == "" {
		return nil, errApplication
	}
	return &capabilityOwner{state: &capabilityOwnerState{guard: &capabilityOwnerGuard{
		mu: &sync.Mutex{}, path: snapshot.CapabilityFile(), load: load,
	},
	}}, nil
}

// Start performs context-aware protected loading for the Fx hook.
func (o *capabilityOwner) Start(ctx context.Context) error {
	state := o.privateState()
	if state == nil {
		return errApplication
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.capability != nil {
		return errApplication
	}
	capability, err := state.load(state.path)
	if err != nil || capability == nil {
		if capability != nil {
			_ = closeProtectedCapability(capability)
		}
		return errApplication
	}
	if err := contextError(ctx); err != nil {
		_ = closeProtectedCapability(capability)
		return err
	}
	state.capability = capability
	return nil
}

// Stop clears the process capability exactly once.
func (o *capabilityOwner) Stop(context.Context) error {
	state := o.privateState()
	if state == nil {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.capability == nil {
		return nil
	}
	err := closeProtectedCapability(state.capability)
	state.capability = nil
	if err != nil {
		return errApplication
	}
	return nil
}

// privateState returns the retained protected owner only inside this package.
func (o *capabilityOwner) privateState() *capabilityOwnerGuard {
	if o == nil || o.state == nil {
		return nil
	}
	return o.state.guard
}

// closeProtectedCapability contains Close errors and panics without leaking values.
func closeProtectedCapability(capability protectedCapability) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errApplication
		}
	}()
	if capability == nil {
		return nil
	}
	if err := capability.Close(); err != nil {
		return errApplication
	}
	return nil
}

// Capability returns the loaded value only after successful startup.
func (o *capabilityOwner) Capability() protectedCapability {
	state := o.privateState()
	if state == nil {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.capability
}

// DaemonCapability returns the typed loaded credential for handler integration.
func (o *capabilityOwner) DaemonCapability() *daemon.Capability {
	capability, _ := o.Capability().(*daemon.Capability)
	return capability
}

// String returns a content-free protected-owner diagnostic.
func (capabilityOwner) String() string { return redactedCapabilityOwner }

// GoString returns a content-free protected-owner representation.
func (o capabilityOwner) GoString() string { return o.String() }

// Format prevents formatter traversal into the retained protected path.
func (o capabilityOwner) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, o.String())
}

// MarshalJSON rejects serialization of protected ownership state.
func (capabilityOwner) MarshalJSON() ([]byte, error) { return nil, errApplication }

// MarshalText rejects protected ownership text serialization.
func (capabilityOwner) MarshalText() ([]byte, error) { return nil, errApplication }

// String returns a content-free private owner-state diagnostic.
func (capabilityOwnerState) String() string { return redactedCapabilityOwner }

// GoString returns a content-free private owner-state representation.
func (state capabilityOwnerState) GoString() string { return state.String() }

// Format prevents nested formatting from traversing path or credential state.
func (state capabilityOwnerState) Format(output fmt.State, _ rune) {
	_, _ = io.WriteString(output, state.String())
}

// MarshalJSON rejects private owner-state serialization.
func (capabilityOwnerState) MarshalJSON() ([]byte, error) { return nil, errApplication }

// MarshalText rejects private owner-state text serialization.
func (capabilityOwnerState) MarshalText() ([]byte, error) { return nil, errApplication }

// String returns a content-free private owner-guard diagnostic.
func (capabilityOwnerGuard) String() string { return redactedCapabilityOwner }

// GoString returns a content-free private owner-guard representation.
func (guard capabilityOwnerGuard) GoString() string { return guard.String() }

// Format prevents guard dereferencing from traversing path or credential state.
func (guard capabilityOwnerGuard) Format(output fmt.State, _ rune) {
	_, _ = io.WriteString(output, guard.String())
}

// MarshalJSON rejects private owner-guard serialization.
func (capabilityOwnerGuard) MarshalJSON() ([]byte, error) { return nil, errApplication }

// MarshalText rejects private owner-guard text serialization.
func (capabilityOwnerGuard) MarshalText() ([]byte, error) { return nil, errApplication }

// Application wraps one isolated Fx graph.
type Application struct {
	fx *fx.App
}

// New constructs the production Fx graph with process-local providers.
func New(snapshot config.Snapshot, logOutput io.Writer) (*Application, error) {
	return newWithCapabilityLoader(snapshot, logOutput, func(path string) (protectedCapability, error) {
		return daemon.LoadCapability(path)
	}, defaultRuntimeDependencies())
}

// newWithCapabilityLoader constructs a testable Fx graph without global seams.
func newWithCapabilityLoader(
	snapshot config.Snapshot,
	logOutput io.Writer,
	load capabilityLoader,
	dependencies runtimeDependencies,
) (*Application, error) {
	if logOutput == nil || load == nil || !dependencies.valid() {
		return nil, errApplication
	}
	runtime := fx.New(
		fx.NopLogger,
		fx.Supply(snapshot),
		fx.Supply(dependencies),
		fx.Provide(func() io.Writer { return logOutput }),
		fx.Provide(func() capabilityLoader { return load }),
		fx.Provide(observability.New),
		fx.Provide(newCapabilityOwner),
		fx.Provide(func(
			snapshot config.Snapshot,
			capability *capabilityOwner,
			telemetry *observability.Runtime,
			dependencies runtimeDependencies,
		) (*productionRuntime, error) {
			return newProductionRuntime(snapshot, capability, telemetry, dependencies)
		}),
		fx.Invoke(registerLifecycle),
	)
	if err := runtime.Err(); err != nil {
		return nil, errApplication
	}
	return &Application{fx: runtime}, nil
}

// registerLifecycle binds the ordered process resource owner to Fx.
func registerLifecycle(
	lifecycle fx.Lifecycle,
	runtime *productionRuntime,
) {
	lifecycle.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			return runtime.Start(ctx)
		},
		OnStop: func(ctx context.Context) error {
			return runtime.Stop(ctx)
		},
	})
}

// contextError classifies cancellation without exposing context causes.
func contextError(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errApplication
	}
	return nil
}

// Start starts every Fx lifecycle hook within the caller's bound.
func (a *Application) Start(ctx context.Context) error {
	if a == nil || a.fx == nil || ctx == nil {
		return errApplication
	}
	if err := a.fx.Start(ctx); err != nil {
		return errApplication
	}
	return nil
}

// Done returns Fx's process-signal channel.
func (a *Application) Done() <-chan os.Signal {
	if a == nil || a.fx == nil {
		return nil
	}
	return a.fx.Done()
}

// Stop stops every Fx lifecycle hook within the caller's bound.
func (a *Application) Stop(ctx context.Context) error {
	if a == nil || a.fx == nil || ctx == nil {
		return errApplication
	}
	if err := a.fx.Stop(ctx); err != nil {
		return errApplication
	}
	return nil
}
