package app

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/croessner/dkim2"
)

const (
	inboundProcessorErrorText = "dkim2d inbound processing failure"
	inboundProcessorRedacted  = "dkim2d_inbound_processor"
	inboundResultRedacted     = "dkim2d_inbound_result"
)

// InboundProcessorError reports one content-free assembly or processing failure.
type InboundProcessorError struct{}

// Error returns a constant content-free processing diagnostic.
func (*InboundProcessorError) Error() string { return inboundProcessorErrorText }

// Is recognizes the bounded inbound processing error type.
func (*InboundProcessorError) Is(target error) bool {
	_, ok := target.(*InboundProcessorError)
	return ok
}

// ReplayService is the narrow provider-neutral replay use-case boundary.
type ReplayService interface {
	Coordinate(context.Context, DomainResult) (ReplayOutcome, error)
}

// InboundProcessor composes verification, policy, and replay without changing their owners.
type InboundProcessor struct {
	domain *DomainProcessor
	replay ReplayService
}

// InboundResult keeps domain and replay truth separate for transport mapping.
type InboundResult struct {
	domain DomainResult
	replay ReplayOutcome
}

// NewInboundProcessor constructs one immutable inbound use case.
func NewInboundProcessor(
	domain *DomainProcessor,
	replay ReplayService,
) (*InboundProcessor, error) {
	if domain == nil || domain.state == nil || nilInterface(replay) {
		return nil, &InboundProcessorError{}
	}
	return &InboundProcessor{domain: domain, replay: replay}, nil
}

// Process performs domain evaluation followed by the exact replay gate and batch.
func (p *InboundProcessor) Process(
	ctx context.Context,
	request dkim2.VerifyRequest,
) (InboundResult, error) {
	if p == nil || p.domain == nil || p.replay == nil {
		return InboundResult{}, &InboundProcessorError{}
	}
	domain, err := p.domain.Process(ctx, request)
	if err != nil {
		return InboundResult{}, err
	}
	replay, err := p.replay.Coordinate(ctx, domain)
	if err != nil {
		return InboundResult{}, err
	}
	result := InboundResult{domain: domain, replay: replay}
	if !result.Valid() {
		return InboundResult{}, &InboundProcessorError{}
	}
	return result, nil
}

// Valid reports whether both retained result owners are coherent.
func (r InboundResult) Valid() bool {
	return r.domain.valid() && r.replay.Valid()
}

// Domain returns the immutable verification and policy result.
func (r InboundResult) Domain() (DomainResult, error) {
	if !r.Valid() {
		return DomainResult{}, &InboundProcessorError{}
	}
	return r.domain, nil
}

// Replay returns the immutable replay aggregate and final disposition.
func (r InboundResult) Replay() (ReplayOutcome, error) {
	if !r.Valid() {
		return ReplayOutcome{}, &InboundProcessorError{}
	}
	return r.replay, nil
}

// String returns a content-free inbound-processor representation.
func (InboundProcessor) String() string { return inboundProcessorRedacted }

// GoString returns a content-free inbound-processor representation.
func (InboundProcessor) GoString() string { return inboundProcessorRedacted }

// Format prevents formatting from traversing processing dependencies.
func (InboundProcessor) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, inboundProcessorRedacted)
}

// MarshalJSON rejects serialization of processing dependencies.
func (InboundProcessor) MarshalJSON() ([]byte, error) {
	return nil, &InboundProcessorError{}
}

// MarshalText rejects diagnostic serialization of processing dependencies.
func (InboundProcessor) MarshalText() ([]byte, error) {
	return nil, &InboundProcessorError{}
}

// String returns a content-free inbound-result representation.
func (InboundResult) String() string { return inboundResultRedacted }

// GoString returns a content-free inbound-result representation.
func (InboundResult) GoString() string { return inboundResultRedacted }

// Format prevents formatting from traversing protocol results.
func (InboundResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, inboundResultRedacted)
}

// MarshalJSON rejects serialization outside the HTTP mapper.
func (InboundResult) MarshalJSON() ([]byte, error) {
	return nil, &InboundProcessorError{}
}

// MarshalText rejects diagnostic serialization of protocol results.
func (InboundResult) MarshalText() ([]byte, error) {
	return nil, &InboundProcessorError{}
}

// IsInboundProcessorError reports whether err is a bounded use-case failure.
func IsInboundProcessorError(err error) bool {
	return errors.Is(err, &InboundProcessorError{})
}
