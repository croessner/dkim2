package app

import (
	"context"
	"fmt"
	"io"

	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/daemon"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/lmtp"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/observability"
	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/reinject"
)

const redactedHandler = "dkim2_dsn_propagator_handler{redacted}"

// propagationClient is the narrow daemon boundary used by one transaction.
type propagationClient interface {
	Propagate(context.Context, []byte, string, bool) (daemon.Result, error)
	Commit(context.Context, daemon.Result) error
	Close() error
}

// reinjectionClient is the narrow SMTP submission boundary.
type reinjectionClient interface {
	Send(context.Context, reinject.Message) error
}

// transactionTelemetry is the closed observation boundary of one transaction.
type transactionTelemetry interface {
	RecordTransaction(outcome, reply string)
	RecordReinjection(outcome string)
	RecordCommit(outcome string)
}

// propagationHandler answers one LMTP transaction after the daemon decided,
// the listener accepted, and the propagation coordinate committed.
//
// The adapter never parses DKIM2 fields, never selects a recipient, and never
// falls back to another route. Every unproven state defers.
type propagationHandler struct {
	client         propagationClient
	reinjector     reinjectionClient
	telemetry      transactionTelemetry
	permanentReply config.PermanentFailureReply
}

// newPropagationHandler constructs one complete transaction owner.
func newPropagationHandler(
	client propagationClient,
	reinjector reinjectionClient,
	telemetry transactionTelemetry,
	permanentReply config.PermanentFailureReply,
) (*propagationHandler, error) {
	if client == nil || reinjector == nil || telemetry == nil ||
		permanentReply != config.PermanentFailureReject &&
			permanentReply != config.PermanentFailureDiscard {
		return nil, errApplication
	}
	return &propagationHandler{
		client: client, reinjector: reinjector,
		telemetry: telemetry, permanentReply: permanentReply,
	}, nil
}

// Handle runs the complete fail-closed propagation matrix for one delivery.
func (h *propagationHandler) Handle(
	ctx context.Context,
	delivery lmtp.Delivery,
) lmtp.Reply {
	if h == nil || ctx == nil {
		return lmtp.ReplyDeferredPolicy
	}
	result, err := h.client.Propagate(
		ctx, delivery.Bytes, delivery.ForwardPath, delivery.SMTPUTF8,
	)
	if err != nil {
		return h.complete(observability.OutcomeContractFailure, lmtp.ReplyDeferredPolicy)
	}
	defer result.Clear()
	switch result.Disposition() {
	case daemon.DispositionAccept:
		return h.propagate(ctx, result)
	case daemon.DispositionReject:
		return h.complete(observability.OutcomeRejected, h.rejectReply())
	case daemon.DispositionDiscard:
		outcome, ok := discardOutcome(result.DiscardReason())
		if !ok {
			return h.complete(
				observability.OutcomeContractFailure, lmtp.ReplyDeferredPolicy,
			)
		}
		return h.complete(outcome, lmtp.ReplyAccepted)
	case daemon.DispositionTempfail:
		return h.complete(observability.OutcomeDeferred, lmtp.ReplyDeferredPolicy)
	default:
		return h.complete(observability.OutcomeContractFailure, lmtp.ReplyDeferredPolicy)
	}
}

// propagate re-injects the signed notification and commits its coordinate.
//
// The LMTP transaction is acknowledged only after the listener answered 250
// and the commit operation answered 200. Every other path defers with 451 so
// the MTA retries the delivery.
func (h *propagationHandler) propagate(
	ctx context.Context,
	result daemon.Result,
) lmtp.Reply {
	sendErr := h.reinjector.Send(ctx, reinject.Message{
		ForwardPath:          result.NextHopRecipient(),
		SMTPUTF8Required:     result.SMTPUTF8Required(),
		EightBitMIMERequired: result.EightBitMIMERequired(),
		Bytes:                result.Message(),
	})
	if sendErr != nil {
		h.telemetry.RecordReinjection(string(reinject.OutcomeOf(sendErr)))
		return h.complete(observability.OutcomeDeferred, lmtp.ReplyDeferredTransport)
	}
	h.telemetry.RecordReinjection(observability.ReinjectionAccepted)
	if err := h.client.Commit(ctx, result); err != nil {
		h.telemetry.RecordCommit(observability.CommitDeferred)
		return h.complete(observability.OutcomeDeferred, lmtp.ReplyDeferredTransport)
	}
	h.telemetry.RecordCommit(observability.CommitCommitted)
	return h.complete(observability.OutcomeAccepted, lmtp.ReplyAccepted)
}

// rejectReply applies the adapter's single policy knob to a daemon reject.
func (h *propagationHandler) rejectReply() lmtp.Reply {
	if h.permanentReply == config.PermanentFailureDiscard {
		return lmtp.ReplyAccepted
	}
	return lmtp.ReplyRejected
}

// complete records the closed transaction outcome and returns its reply.
func (h *propagationHandler) complete(outcome string, reply lmtp.Reply) lmtp.Reply {
	h.telemetry.RecordTransaction(outcome, replyClass(reply))
	return reply
}

// replyClass maps one LMTP reply to its closed observable class.
func replyClass(reply lmtp.Reply) string {
	switch reply {
	case lmtp.ReplyAccepted:
		return observability.ReplyAccepted
	case lmtp.ReplyRejected:
		return observability.ReplyRejected
	default:
		return observability.ReplyDeferred
	}
}

// discardOutcome maps one closed discard cause to its closed metric outcome.
func discardOutcome(reason daemon.DiscardReason) (string, bool) {
	switch reason {
	case daemon.DiscardTerminalOrigin:
		return observability.OutcomeDiscardedTerminalOrigin, true
	case daemon.DiscardNotFailure:
		return observability.OutcomeDiscardedNotFailure, true
	case daemon.DiscardNullPreviousSender:
		return observability.OutcomeDiscardedNullPreviousSender, true
	case daemon.DiscardUnsupportedChain:
		return observability.OutcomeDiscardedUnsupportedChain, true
	case daemon.DiscardNotReconstructable:
		return observability.OutcomeDiscardedNotReconstructable, true
	case daemon.DiscardUnprovisionedDomain:
		return observability.OutcomeDiscardedUnprovisionedDomain, true
	case daemon.DiscardCommitted:
		return observability.OutcomeDiscardedCommitted, true
	default:
		return "", false
	}
}

// String returns a content-free handler diagnostic.
func (propagationHandler) String() string { return redactedHandler }

// GoString returns a content-free handler representation.
func (h propagationHandler) GoString() string { return h.String() }

// Format prevents formatting from traversing live transaction dependencies.
func (h propagationHandler) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, h.String())
}

// MarshalJSON rejects handler serialization.
func (propagationHandler) MarshalJSON() ([]byte, error) { return nil, errApplication }

// MarshalText rejects handler text serialization.
func (propagationHandler) MarshalText() ([]byte, error) { return nil, errApplication }

var _ lmtp.Handler = (*propagationHandler)(nil)
