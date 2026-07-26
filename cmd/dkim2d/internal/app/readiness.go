package app

import (
	"encoding/json"
	"fmt"
	"io"
	"sync/atomic"
)

const readinessRedacted = "dkim2d_readiness"

type readinessState uint32

const (
	readinessBooting readinessState = iota
	readinessReady
	readinessFatal
	readinessStoppingClean
	readinessStoppingFatal
)

// AuthorityReadiness exposes one provider-owned no-I/O authority snapshot.
type AuthorityReadiness interface {
	AuthorityReady() bool
}

// Readiness owns conservative lifecycle flags around provider authority.
type Readiness struct {
	authority AuthorityReadiness
	state     atomic.Uint32
	fatalGate *atomic.Bool
}

// NewReadiness constructs one initially-not-ready instance snapshot.
func NewReadiness(authority AuthorityReadiness) (*Readiness, error) {
	if nilInterface(authority) {
		return nil, &LifecycleError{}
	}
	return &Readiness{authority: authority}, nil
}

// Ready returns one bounded no-I/O readiness snapshot without exposing a reason.
func (r *Readiness) Ready() bool {
	if r == nil || r.fatalPending() ||
		readinessState(r.state.Load()) != readinessReady {
		return false
	}
	if !sampleAuthorityReadiness(r.authority) {
		return false
	}
	return !r.fatalPending() &&
		readinessState(r.state.Load()) == readinessReady
}

// publishReady atomically publishes readiness only from the booting state.
func (r *Readiness) publishReady() bool {
	if r == nil || r.fatalPending() || !r.state.CompareAndSwap(
		uint32(readinessBooting),
		uint32(readinessReady),
	) {
		return false
	}
	if r.fatalPending() {
		r.withdrawReady()
		return false
	}
	return true
}

// bindFatalGate attaches the lifecycle's lock-free fatal publication gate once.
func (r *Readiness) bindFatalGate(gate *atomic.Bool) bool {
	if r == nil || gate == nil || r.fatalGate != nil ||
		readinessState(r.state.Load()) != readinessBooting {
		return false
	}
	r.fatalGate = gate
	return !r.fatalPending()
}

// fatalPending reports the lifecycle's lock-free pre-publication fatal fact.
func (r *Readiness) fatalPending() bool {
	return r != nil && r.fatalGate != nil && r.fatalGate.Load()
}

// withdrawReady atomically publishes a fatal state that startup cannot reverse.
func (r *Readiness) withdrawReady() bool {
	if r == nil {
		return false
	}
	for {
		current := readinessState(r.state.Load())
		switch current {
		case readinessBooting, readinessReady:
			if r.state.CompareAndSwap(uint32(current), uint32(readinessFatal)) {
				return true
			}
		case readinessStoppingClean:
			if r.state.CompareAndSwap(uint32(current), uint32(readinessStoppingFatal)) {
				return true
			}
		case readinessFatal, readinessStoppingFatal:
			return false
		default:
			return false
		}
	}
}

// beginStopping permanently publishes the not-ready stopping transition.
func (r *Readiness) beginStopping() {
	if r == nil {
		return
	}
	for {
		current := readinessState(r.state.Load())
		next := readinessStoppingClean
		switch current {
		case readinessFatal:
			next = readinessStoppingFatal
		case readinessStoppingClean, readinessStoppingFatal:
			return
		case readinessBooting, readinessReady:
		default:
			next = readinessStoppingFatal
		}
		if r.state.CompareAndSwap(uint32(current), uint32(next)) {
			return
		}
	}
}

// fatal reports whether the monotone lifecycle state contains a fatal transition.
func (r *Readiness) fatal() bool {
	if r == nil {
		return true
	}
	state := readinessState(r.state.Load())
	return state == readinessFatal || state == readinessStoppingFatal
}

// sampleAuthorityReadiness invokes the no-I/O provider fact for outer containment.
func sampleAuthorityReadiness(authority AuthorityReadiness) bool {
	if nilInterface(authority) {
		return false
	}
	return authority.AuthorityReady()
}

// String returns a constant content-free readiness representation.
func (*Readiness) String() string { return readinessRedacted }

// GoString returns a constant content-free readiness representation.
func (*Readiness) GoString() string { return readinessRedacted }

// Format prevents formatting verbs from traversing readiness dependencies.
func (*Readiness) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, readinessRedacted)
}

// MarshalJSON rejects serialization of readiness dependencies.
func (*Readiness) MarshalJSON() ([]byte, error) {
	return nil, &LifecycleError{}
}

// MarshalText rejects text serialization of readiness dependencies.
func (*Readiness) MarshalText() ([]byte, error) {
	return nil, &LifecycleError{}
}

var _ fmt.Formatter = (*Readiness)(nil)
var _ json.Marshaler = (*Readiness)(nil)
