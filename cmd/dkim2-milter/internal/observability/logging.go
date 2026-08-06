package observability

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/milter"
)

const (
	maxLogAttributes  = 16
	maxLogRecordBytes = 4 << 10

	eventActionCompleted     = "action.completed"
	eventCallbackCompleted   = "callback.completed"
	eventConfigAccepted      = "config.accepted"
	eventConnectionAdmission = "connection.admission"
	eventLifecycleTransition = "lifecycle.transition"
	eventMessageCompleted    = "message.completed"
	eventReadinessTransition = "readiness.transition"
	keyActionKind            = "action_kind"
	keyAdmission             = "admission"
	keyCallbackClass         = "callback_class"
	keyDaemonOperation       = "daemon_operation"
	keyDisposition           = "disposition"
	keyDomainCount           = "processed_domain_count"
	keyDomainRole            = "domain_role"
	keyDomains               = "processed_domains"
	keyDomainsTruncated      = "processed_domains_truncated"
	keyDurationBucket        = "duration_bucket"
	keyFailOpen              = "fail_open"
	keyFailureClass          = "failure_class"
	keyLifecycleState        = "lifecycle_state"
	keyMessageSizeBucket     = "message_size_bucket"
	keyMode                  = "mode"
	keyOperation             = "operation"
	keyRecipientBucket       = "recipient_count_bucket"
	keyResultClass           = "result_class"
	keyStateClass            = "state_class"
	metricsTarget            = "/metrics"

	valueDurationLT1ms  = "lt_1ms"
	valueDurationLT5ms  = "lt_5ms"
	valueDurationGTE30s = "gte_30s"
	valueSizeLT10k      = "lt_10k"
	valueRecipientsGTE  = "gte_1001"
	valueAccept         = "accept"
	valueClose          = "close"
	valueContinue       = "continue"
	valueModeInbound    = "inbound"
	valueModePostfixDSN = "postfix_dsn"
	valueNone           = "none"
	valueOperationDSN   = "delivery_status"
	valueReject         = "reject"
	valueTempfail       = "tempfail"
	valueTemporary      = "temporary"
	valueInternal       = "internal"
	valueSuccess        = "success"
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
	return &boundedJSONHandler{
		destination: destination,
		level:       level,
		mu:          &sync.Mutex{},
	}
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
		!allowedEventID(record.Message) ||
		!validLogLevel(record.Level) ||
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
		switch attribute.Key {
		case keyDomains:
			if attribute.Value.Kind() != slog.KindString {
				return nil, errConfiguration
			}
			fields[attribute.Key] = attribute.Value.String()
		case keyDomainCount:
			if attribute.Value.Kind() != slog.KindUint64 {
				return nil, errConfiguration
			}
			fields[attribute.Key] = attribute.Value.Uint64()
		case keyFailOpen, keyDomainsTruncated, "ready":
			if attribute.Value.Kind() != slog.KindBool {
				return nil, errConfiguration
			}
			fields[attribute.Key] = attribute.Value.Bool()
		default:
			return nil, errConfiguration
		}
	}
	operation, required, ok := eventRequirements(eventID)
	if !ok {
		return nil, errConfiguration
	}
	if len(fields) != len(required) {
		return nil, errConfiguration
	}
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			return nil, errConfiguration
		}
	}
	if fields[keyOperation] != operation {
		return nil, errConfiguration
	}
	if eventID == eventMessageCompleted && !validDomainFields(fields) {
		return nil, errConfiguration
	}
	return fields, nil
}

// validDomainFields independently revalidates the operator-visible domain set
// at the final logging sink.
func validDomainFields(fields map[string]any) bool {
	role, roleOK := fields[keyDomainRole].(string)
	domains, domainsOK := fields[keyDomains].(string)
	count, countOK := fields[keyDomainCount].(uint64)
	truncated, truncatedOK := fields[keyDomainsTruncated].(bool)
	if !roleOK || !domainsOK || !countOK || !truncatedOK ||
		strings.ContainsAny(domains, "@\r\n\x00") {
		return false
	}
	_, ok := milter.NewDomainObservation(role, domains, count, truncated)
	return ok
}

// allowedEventID admits only the fixed adapter event inventory.
func allowedEventID(eventID string) bool {
	switch eventID {
	case eventActionCompleted,
		eventCallbackCompleted,
		eventConfigAccepted,
		eventConnectionAdmission,
		eventLifecycleTransition,
		eventMessageCompleted,
		eventReadinessTransition:
		return true
	default:
		return false
	}
}

// closedVocabulary returns a fresh copy of one closed string vocabulary.
func closedVocabulary(key string) []string {
	switch key {
	case keyActionKind:
		return []string{
			valueAccept,
			"add_header",
			"change_header",
			valueContinue,
			"insert_header",
			valueReject,
			"reply_code",
			valueTempfail,
		}
	case keyAdmission:
		return []string{"accepted", "connection_limit", "message_limit", "byte_limit", "stopping"}
	case keyCallbackClass:
		return []string{
			"abort", "body", "connect", "eoh", "eom", "header", "helo", "mail",
			"macro", "negotiate", "quit", "recipient",
		}
	case keyDaemonOperation:
		return []string{valueOperationDSN, "process", "revise", "sign"}
	case keyDisposition:
		return []string{valueAccept, valueClose, valueContinue, valueReject, valueTempfail}
	case keyDomainRole:
		return []string{"none", "recipient", "signing"}
	case keyDurationBucket:
		return []string{
			valueDurationLT1ms, valueDurationLT5ms, "lt_10ms", "lt_25ms",
			"lt_50ms", "lt_100ms", "lt_250ms", "lt_500ms", "lt_1s",
			"lt_2_5s", "lt_5s", "lt_10s", "lt_30s", valueDurationGTE30s,
		}
	case keyFailureClass:
		return []string{
			"capacity", "contract", "fidelity", "indeterminate", valueInternal,
			valueNone, "timeout", "trust", "unavailable",
		}
	case keyLifecycleState:
		return []string{"active", "failed", "starting", "stopped", "stopping"}
	case keyMessageSizeBucket:
		return []string{
			"0", "lt_1k", valueSizeLT10k, "lt_100k", "lt_1m", "lt_10m", "gte_10m",
		}
	case keyMode:
		return []string{valueModeInbound, "ordinary_transit", "originator", valueModePostfixDSN}
	case keyOperation:
		return []string{
			"action", "callback", "config", "connection", "lifecycle", "message",
			"readiness",
		}
	case keyRecipientBucket:
		return []string{"0", "1", "2_10", "11_100", "101_1000", valueRecipientsGTE}
	case keyResultClass:
		return []string{"failure", valueInternal, valueSuccess, valueTemporary}
	case keyStateClass:
		return []string{
			"body", "connected", "eoh", "headers", "helo", "initial", "mail",
			"negotiated", "recipients", "terminal",
		}
	default:
		return nil
	}
}

// eventRequirements returns fresh required keys and the fixed operation binding.
func eventRequirements(eventID string) (string, []string, bool) {
	switch eventID {
	case eventActionCompleted:
		return "action", []string{keyActionKind, keyOperation, keyResultClass}, true
	case eventCallbackCompleted:
		return "callback", []string{
			keyCallbackClass, keyDurationBucket, keyOperation, keyResultClass,
			keyStateClass,
		}, true
	case eventConfigAccepted:
		return "config", []string{keyFailOpen, keyMode, keyOperation, keyResultClass}, true
	case eventConnectionAdmission:
		return "connection", []string{keyAdmission, keyOperation, keyResultClass}, true
	case eventLifecycleTransition:
		return "lifecycle", []string{keyLifecycleState, keyOperation, keyResultClass}, true
	case eventMessageCompleted:
		return "message", []string{
			keyDaemonOperation, keyDisposition, keyDurationBucket, keyFailOpen, keyFailureClass,
			keyMessageSizeBucket, keyMode, keyOperation, keyRecipientBucket, keyResultClass,
			keyDomainRole, keyDomains, keyDomainCount, keyDomainsTruncated,
		}, true
	case eventReadinessTransition:
		return "readiness", []string{keyOperation, "ready", keyResultClass}, true
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
	for key, value := range fields {
		document[key] = value
	}
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
