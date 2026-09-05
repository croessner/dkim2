package observability

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"
)

const (
	maxLogAttributes  = 12
	maxLogRecordBytes = 4 << 10

	eventCommitCompleted      = "commit.completed"
	eventConfigAccepted       = "config.accepted"
	eventLifecycleTransition  = "lifecycle.transition"
	eventReadinessTransition  = "readiness.transition"
	eventReinjectionCompleted = "reinjection.completed"
	eventTransactionCompleted = "transaction.completed"

	keyCommitOutcome      = "commit_outcome"
	keyLifecycleState     = "lifecycle_state"
	keyOperation          = "operation"
	keyPermanentReply     = "permanent_failure_reply"
	keyReinjectionOutcome = "reinjection_outcome"
	keyReply              = "reply"
	keyResultClass        = "result_class"
	keyTransactionOutcome = "outcome"

	metricsTarget = "/metrics"

	valueInternal  = "internal"
	valueSuccess   = "success"
	valueFailure   = "failure"
	valueTemporary = "temporary"
)

// TransactionOutcome is the closed adapter transaction vocabulary.
type TransactionOutcome = string

const (
	// OutcomeAccepted marks a propagated and committed notification.
	OutcomeAccepted TransactionOutcome = "accepted"
	// OutcomeRejected marks a permanently refused notification.
	OutcomeRejected TransactionOutcome = "rejected"
	// OutcomeDiscardedTerminalOrigin marks a chain that reached its origin.
	OutcomeDiscardedTerminalOrigin TransactionOutcome = "discarded_terminal_origin"
	// OutcomeDiscardedNotFailure marks a delivered or delayed report.
	OutcomeDiscardedNotFailure TransactionOutcome = "discarded_not_failure"
	// OutcomeDiscardedNullPreviousSender marks a forbidden null previous sender.
	OutcomeDiscardedNullPreviousSender TransactionOutcome = "discarded_null_previous_sender"
	// OutcomeDiscardedUnsupportedChain marks an undescendable chain.
	OutcomeDiscardedUnsupportedChain TransactionOutcome = "discarded_unsupported_chain"
	// OutcomeDiscardedNotReconstructable marks an unrebuildable notification.
	OutcomeDiscardedNotReconstructable TransactionOutcome = "discarded_not_reconstructable"
	// OutcomeDiscardedUnprovisionedDomain marks a domain without a profile.
	OutcomeDiscardedUnprovisionedDomain TransactionOutcome = "discarded_unprovisioned_domain"
	// OutcomeDiscardedCommitted marks an already committed coordinate.
	OutcomeDiscardedCommitted TransactionOutcome = "discarded_committed"
	// OutcomeDeferred marks a temporary refusal handed back to the MTA.
	OutcomeDeferred TransactionOutcome = "deferred"
	// OutcomeContractFailure marks an out-of-contract or transport failure.
	OutcomeContractFailure TransactionOutcome = "contract_failure"
)

const (
	// ReinjectionAccepted marks a listener that accepted the notification.
	ReinjectionAccepted = "accepted"
	// ReinjectionDeferred marks a temporary listener refusal.
	ReinjectionDeferred = "deferred"
	// ReinjectionFailed marks a permanent refusal or transport failure.
	ReinjectionFailed = "failed"
	// ReinjectionSMTPUTF8Unavailable marks a listener without required SMTPUTF8.
	ReinjectionSMTPUTF8Unavailable = "smtputf8_unavailable"
)

const (
	// CommitCommitted marks a committed propagation coordinate.
	CommitCommitted = "committed"
	// CommitDeferred marks a commit that did not resolve its coordinate.
	CommitDeferred = "deferred"
)

const (
	// ReplyAccepted is the LMTP acknowledgement class.
	ReplyAccepted = "accepted"
	// ReplyRejected is the LMTP permanent-refusal class.
	ReplyRejected = "rejected"
	// ReplyDeferred is the LMTP temporary-refusal class.
	ReplyDeferred = "deferred"
)

// boundedJSONHandler admits only the closed adapter event grammar.
type boundedJSONHandler struct {
	destination io.Writer
	level       slog.Level
	attributes  []slog.Attr
	rejectGroup bool
	mu          *sync.Mutex
}

// newBoundedJSONHandler constructs one handler with shared atomic output.
func newBoundedJSONHandler(destination io.Writer, level slog.Level) *boundedJSONHandler {
	return &boundedJSONHandler{destination: destination, level: level, mu: &sync.Mutex{}}
}

// Enabled applies the configured closed log level.
func (h *boundedJSONHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h != nil && level >= h.level
}

// Handle validates and atomically writes one bounded JSON record.
func (h *boundedJSONHandler) Handle(_ context.Context, record slog.Record) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errConfiguration
		}
	}()
	if h == nil || h.destination == nil || h.mu == nil || h.rejectGroup ||
		!allowedEventID(record.Message) || !validLogLevel(record.Level) ||
		record.NumAttrs()+len(h.attributes) > maxLogAttributes {
		return errConfiguration
	}
	attributes := append([]slog.Attr(nil), h.attributes...)
	record.Attrs(func(attribute slog.Attr) bool {
		attributes = append(attributes, attribute)
		return true
	})
	fields, err := admitAttributes(record.Message, attributes)
	if err != nil {
		return err
	}
	output, err := encodeRecord(record.Time, record.Level, record.Message, fields)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	written, writeErr := h.destination.Write(output)
	if writeErr != nil || written != len(output) {
		return errConfiguration
	}
	return nil
}

// WithAttrs returns an isolated handler retaining attributes for later validation.
func (h *boundedJSONHandler) WithAttrs(attributes []slog.Attr) slog.Handler {
	if h == nil {
		return discardHandler{}
	}
	return &boundedJSONHandler{
		destination: h.destination,
		level:       h.level,
		attributes:  append(append([]slog.Attr(nil), h.attributes...), attributes...),
		rejectGroup: h.rejectGroup,
		mu:          h.mu,
	}
}

// WithGroup makes every record on the derived logger fail closed.
func (h *boundedJSONHandler) WithGroup(string) slog.Handler {
	if h == nil {
		return discardHandler{}
	}
	return &boundedJSONHandler{
		destination: h.destination,
		level:       h.level,
		attributes:  append([]slog.Attr(nil), h.attributes...),
		rejectGroup: true,
		mu:          h.mu,
	}
}

// admitAttributes validates unique scalar keys against exact vocabularies.
func admitAttributes(eventID string, attributes []slog.Attr) (map[string]any, error) {
	fields := make(map[string]any, len(attributes))
	for _, attribute := range attributes {
		if attribute.Key == "" {
			return nil, errConfiguration
		}
		if _, duplicate := fields[attribute.Key]; duplicate {
			return nil, errConfiguration
		}
		if allowed := closedVocabulary(attribute.Key); allowed != nil {
			if attribute.Value.Kind() != slog.KindString ||
				!slices.Contains(allowed, attribute.Value.String()) {
				return nil, errConfiguration
			}
			fields[attribute.Key] = attribute.Value.String()
			continue
		}
		if attribute.Key == "ready" {
			if attribute.Value.Kind() != slog.KindBool {
				return nil, errConfiguration
			}
			fields[attribute.Key] = attribute.Value.Bool()
			continue
		}
		return nil, errConfiguration
	}
	operation, required, ok := eventRequirements(eventID)
	if !ok || len(fields) != len(required) {
		return nil, errConfiguration
	}
	for _, key := range required {
		if _, present := fields[key]; !present {
			return nil, errConfiguration
		}
	}
	if fields[keyOperation] != operation {
		return nil, errConfiguration
	}
	return fields, nil
}

// allowedEventID admits only the fixed adapter event inventory.
func allowedEventID(eventID string) bool {
	switch eventID {
	case eventCommitCompleted, eventConfigAccepted, eventLifecycleTransition,
		eventReadinessTransition, eventReinjectionCompleted, eventTransactionCompleted:
		return true
	default:
		return false
	}
}

// closedVocabulary returns a fresh copy of one closed string vocabulary.
func closedVocabulary(key string) []string {
	switch key {
	case keyTransactionOutcome:
		return []string{
			OutcomeAccepted, OutcomeRejected, OutcomeDiscardedTerminalOrigin,
			OutcomeDiscardedNotFailure, OutcomeDiscardedNullPreviousSender,
			OutcomeDiscardedUnsupportedChain, OutcomeDiscardedNotReconstructable,
			OutcomeDiscardedUnprovisionedDomain, OutcomeDiscardedCommitted,
			OutcomeDeferred, OutcomeContractFailure,
		}
	case keyReinjectionOutcome:
		return []string{
			ReinjectionAccepted, ReinjectionDeferred, ReinjectionFailed,
			ReinjectionSMTPUTF8Unavailable,
		}
	case keyCommitOutcome:
		return []string{CommitCommitted, CommitDeferred}
	case keyReply:
		return []string{ReplyAccepted, ReplyRejected, ReplyDeferred}
	case keyPermanentReply:
		return []string{"reject", "discard"}
	case keyLifecycleState:
		return []string{"active", "stopped"}
	case keyOperation:
		return []string{
			"commit", "config", "lifecycle", "readiness", "reinjection",
			"transaction",
		}
	case keyResultClass:
		return []string{valueFailure, valueInternal, valueSuccess, valueTemporary}
	default:
		return nil
	}
}

// eventRequirements returns fresh required keys and the fixed operation binding.
func eventRequirements(eventID string) (string, []string, bool) {
	switch eventID {
	case eventCommitCompleted:
		return "commit", []string{keyCommitOutcome, keyOperation, keyResultClass}, true
	case eventConfigAccepted:
		return "config", []string{keyPermanentReply, keyOperation, keyResultClass}, true
	case eventLifecycleTransition:
		return "lifecycle", []string{keyLifecycleState, keyOperation, keyResultClass}, true
	case eventReadinessTransition:
		return "readiness", []string{keyOperation, "ready", keyResultClass}, true
	case eventReinjectionCompleted:
		return "reinjection", []string{
			keyReinjectionOutcome, keyOperation, keyResultClass,
		}, true
	case eventTransactionCompleted:
		return "transaction", []string{
			keyTransactionOutcome, keyReply, keyOperation, keyResultClass,
		}, true
	default:
		return "", nil, false
	}
}

// encodeRecord serializes one admitted record with fixed envelope fields.
func encodeRecord(
	recordTime time.Time,
	level slog.Level,
	eventID string,
	fields map[string]any,
) ([]byte, error) {
	document := make(map[string]any, len(fields)+4)
	document["time"] = recordTime.UTC().Format(time.RFC3339Nano)
	document["level"] = level.String()
	document["msg"] = eventID
	document["event_id"] = eventID
	maps.Copy(document, fields)
	output, err := json.Marshal(document)
	if err != nil || len(output)+1 > maxLogRecordBytes {
		return nil, errConfiguration
	}
	return append(output, '\n'), nil
}

// validLogLevel accepts only normal slog record levels.
func validLogLevel(level slog.Level) bool {
	return level == slog.LevelDebug || level == slog.LevelInfo ||
		level == slog.LevelWarn || level == slog.LevelError
}

// discardHandler safely absorbs logging through a nil runtime.
type discardHandler struct{}

// Enabled disables every record.
func (discardHandler) Enabled(context.Context, slog.Level) bool { return false }

// Handle discards a record.
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }

// WithAttrs retains the discard behavior.
func (discardHandler) WithAttrs([]slog.Attr) slog.Handler { return discardHandler{} }

// WithGroup retains the discard behavior.
func (discardHandler) WithGroup(string) slog.Handler { return discardHandler{} }
