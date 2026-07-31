package adapter

import (
	"context"
	"sync/atomic"
)

type outcomeKey struct{}

// Outcome owns mutable low-cardinality decision metadata for one request context.
type Outcome struct{ failOpen atomic.Bool }

// WithOutcome installs one request-local outcome marker.
func WithOutcome(parent context.Context) (context.Context, *Outcome) {
	outcome := &Outcome{}
	return context.WithValue(parent, outcomeKey{}, outcome), outcome
}

// MarkFailOpen marks a successfully warned accept-unchanged decision.
func MarkFailOpen(ctx context.Context) {
	if outcome, ok := ctx.Value(outcomeKey{}).(*Outcome); ok && outcome != nil {
		outcome.failOpen.Store(true)
	}
}

// FailOpen reports whether the request selected warned accept-unchanged policy.
func (o *Outcome) FailOpen() bool { return o != nil && o.failOpen.Load() }
