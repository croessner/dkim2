package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
)

const (
	maxLogRecordBytes  = 4_096
	maxLogAttributes   = 16
	keyEventID         = "event_id"
	keyMethod          = "method"
	keyProvider        = "provider"
	keyProviderState   = "provider_state"
	keyCacheResult     = "cache_result"
	keyDNSResult       = "dns_result"
	keyOperation       = "operation"
	keyPolicyMode      = "policy_mode"
	keyReasonClass     = "reason_class"
	keyReady           = "ready"
	keyReplayState     = "replay_state"
	keyResult          = "result"
	keyStatusClass     = "status_class"
	keyDisposition     = "disposition"
	keyEvidenceStage   = "evidence_stage"
	keyVerdict         = "verdict"
	valueInternal      = "internal"
	valueFailure       = "failure"
	valueFail          = "fail"
	valueFound         = "found"
	valueHit           = "hit"
	valueIndeterminate = "indeterminate"
	valueInvalid       = "invalid"
	valueMiss          = "miss"
	valueNone          = "none"
	valueNeutral       = "neutral"
	valueNotChecked    = "not_checked"
	valueNotUsed       = "not_used"
	valuePolicy        = "policy"
	valuePanic         = "panic"
	valuePass          = "pass"
	valueProcess       = "process"
	valuePermerror     = "permerror"
	valueRevise        = "revise"
	valueSign          = "sign"
	valueDSNSign       = "dsn_sign"
	valueExport        = "export"
	valueFirstSeen     = "first_seen"
	valueOverflow      = "overflow"
	valueProtocol      = "protocol"
	valueReplayed      = "replayed"
	valueStrict        = "strict"
	valueSuccess       = "success"
	valueTemporary     = "temporary"
	valueTemperror     = "temperror"
	valueTesting       = "testing"
	valueTimeout       = "timeout"
	valueTransport     = "transport"
	valueUnmatched     = "unmatched"
	valueAvailability  = "availability"
	valueDisabled      = "disabled"
	valuePermissive    = "permissive"
	valueStatus2XX     = "2xx"
	valueStatus3XX     = "3xx"
	valueStatus4XX     = "4xx"
	valueStatus5XX     = "5xx"
	valueGTE9          = "gte_9"
	metricReadiness    = "dkim2d_readiness"
)

var errRejectedRecord = errors.New("observability record rejected")

var allowedLogKeys = []string{
	keyCacheResult, "chain_length_bucket", "debug_module", keyDisposition,
	keyDNSResult, "draft", "duration_bucket", "error_class", keyEventID, keyEvidenceStage,
	"lifecycle_state", "message_size_bucket", keyMethod, keyOperation,
	keyPolicyMode, keyProvider, keyProviderState, keyReady, keyReasonClass, "recipient_count_bucket",
	keyReplayState, "replay_store_result", keyResult, "route",
	"signature_count_bucket", keyStatusClass, "tracing_exporter", keyVerdict,
}

var allowedLogValues = map[string][]string{
	keyCacheResult: {valueHit, valueMiss, valueNotUsed},
	"debug_module": {"message_shape", "dns", "replay"},
	keyDisposition: {"accept", "continue", "reject", "tempfail"},
	keyDNSResult:   {valueFound, "missing", valueInvalid, "ambiguous", valueTemporary, valueInternal},
	"draft":        {"draft-ietf-dkim-dkim2-spec-04"},
	"error_class":  {valueNone, "canceled", "deadline", valueTimeout, valueTransport, "tls", "encoding", "shutdown", valueInternal},
	keyEventID:     {"config.accepted", "lifecycle.transition", "readiness.transition", "http.request.completed", "process.completed", "dsn.evidence.completed", "dns.lookup.completed", "replay.coordinate.completed", "datasource.operation.completed", "telemetry.export.failed"},
	keyEvidenceStage: {
		string(dkim2.DSNEvidenceStagePreflight), string(dkim2.DSNEvidenceStageMIMEParse),
		string(dkim2.DSNEvidenceStageEmbeddedMessage), string(dkim2.DSNEvidenceStageEmbeddedVerification),
		string(dkim2.DSNEvidenceStageEmbeddedClaims), string(dkim2.DSNEvidenceStageDeliveryStatusLinkage),
		string(dkim2.DSNEvidenceStageOuterRecipientLinkage), string(dkim2.DSNEvidenceStageSigningDomain),
		string(dkim2.DSNEvidenceStageAuthorized),
	},
	"lifecycle_state":        {"starting", "active", "stopping", "stopped", "failed"},
	keyMethod:                {"GET", "HEAD", "POST", "OPTIONS", "other"},
	keyOperation:             {"config", "lifecycle", "readiness", "health", "metrics", valueProcess, valueSign, valueRevise, valueDSNSign, "verify", "dns_lookup", valuePolicy, "replay_coordinate", "replay_store", "datasource_initial_load", "datasource_refresh", "datasource_resolve", "telemetry_export", valueUnmatched},
	keyPolicyMode:            {valueStrict, valuePermissive, valueTesting},
	keyProvider:              {"flat_file", "memory", "ldap", "postgresql", "mysql"},
	keyProviderState:         {"initializing", "ready", "degraded", "closed"},
	keyReasonClass:           {valueNone, valueProtocol, valuePolicy, valueAvailability, "invalid_request", keyMethod, valueInternal},
	keyReplayState:           {valueNotChecked, valueDisabled, valueFirstSeen, valueReplayed, valueIndeterminate},
	"replay_store_result":    {"not_used", valueSuccess, valueTemporary, valueInternal},
	keyResult:                {valueSuccess, valueFailure, valueTemporary, valueInternal},
	"route":                  {"/healthz", "/readyz", "/metrics", "/v1/process", "/v1/sign", "/v1/revise", "/v1/dsn/sign", valueUnmatched},
	keyStatusClass:           {valueStatus2XX, valueStatus3XX, valueStatus4XX, valueStatus5XX},
	"tracing_exporter":       {valueNone, "otlp_http"},
	keyVerdict:               {valuePass, valueFail, valueNeutral, valueTemperror, valuePermerror},
	"duration_bucket":        {"lt_1ms", "lt_5ms", "lt_10ms", "lt_25ms", "lt_50ms", "lt_100ms", "lt_250ms", "lt_500ms", "lt_1s", "lt_2_5s", "lt_5s", "lt_10s", "lt_30s", "lt_60s", "gte_60s"},
	"message_size_bucket":    {"lt_1k", "lt_10k", "lt_100k", "lt_1m", "lt_10m", "gte_10m"},
	"recipient_count_bucket": {"0", "1", "2_10", "11_100", "101_1000", "gte_1001"},
	"signature_count_bucket": {"0", "1", "2_4", "5_8", valueGTE9},
	"chain_length_bucket":    {"0", "1", "2_4", "5_8", valueGTE9},
}

// Logger owns one central slog logger and its exact debug policy.
type Logger struct {
	logger       *slog.Logger
	messageShape bool
	dns          bool
	replay       bool
}

// NewLogger constructs one instance-owned bounded JSON logger.
func NewLogger(settings config.ObservabilityConfig, destination io.Writer) (*Logger, error) {
	return newLogger(settings, destination, nil)
}

// newLogger constructs one logger with an optional contained drop callback.
func newLogger(
	settings config.ObservabilityConfig,
	destination io.Writer,
	onDrop func(string),
) (*Logger, error) {
	if destination == nil {
		return nil, errRejectedRecord
	}
	level, ok := mapLogLevel(settings.LogLevel())
	if !ok {
		return nil, errRejectedRecord
	}
	handler := &boundedJSONHandler{
		destination: destination,
		level:       level,
		mu:          &sync.Mutex{},
		onDrop:      onDrop,
	}
	return &Logger{
		logger: slog.New(handler), messageShape: settings.DebugMessageShape(),
		dns: settings.DebugDNS(), replay: settings.DebugReplay(),
	}, nil
}

// Slog returns the central logger without changing global slog state.
func (l *Logger) Slog() *slog.Logger {
	if l == nil || l.logger == nil {
		return slog.New(discardHandler{})
	}
	return l.logger
}

// DebugEnabled reports whether one exact bounded debug module is active.
func (l *Logger) DebugEnabled(module string) bool {
	if l == nil {
		return false
	}
	switch module {
	case "message_shape":
		return l.messageShape
	case "dns":
		return l.dns
	case "replay":
		return l.replay
	default:
		return false
	}
}

// boundedJSONHandler validates and serializes one exact log grammar.
type boundedJSONHandler struct {
	destination io.Writer
	level       slog.Level
	attributes  []slog.Attr
	mu          *sync.Mutex
	onDrop      func(string)
}

// Enabled applies the configured admission threshold.
func (h *boundedJSONHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h != nil && level >= h.level
}

// Handle validates and writes one bounded JSON record atomically.
func (h *boundedJSONHandler) Handle(_ context.Context, record slog.Record) (resultErr error) {
	dropReason := valueInvalid
	defer func() {
		if recover() != nil {
			resultErr = errRejectedRecord
			dropReason = valuePanic
		}
		if resultErr != nil {
			notifyLogDrop(h.onDrop, dropReason)
		}
	}()
	if h == nil || h.destination == nil || h.mu == nil || !validEventID(record.Message) ||
		!validRecordLevel(record.Level) ||
		record.NumAttrs()+len(h.attributes) > maxLogAttributes {
		return errRejectedRecord
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
	written, err := h.destination.Write(output)
	if err != nil {
		dropReason = valueExport
		return errRejectedRecord
	}
	if written != len(output) {
		dropReason = valueExport
		return errRejectedRecord
	}
	return nil
}

// WithAttrs returns one isolated handler with validated retained attributes.
func (h *boundedJSONHandler) WithAttrs(attributes []slog.Attr) slog.Handler {
	if h == nil {
		return discardHandler{}
	}
	return &boundedJSONHandler{
		destination: h.destination,
		level:       h.level,
		attributes:  append(append([]slog.Attr(nil), h.attributes...), attributes...),
		mu:          h.mu,
		onDrop:      h.onDrop,
	}
}

// notifyLogDrop contains callback defects behind the logging boundary.
func notifyLogDrop(callback func(string), reason string) {
	if callback == nil {
		return
	}
	defer func() { _ = recover() }()
	callback(reason)
}

// WithGroup rejects groups by returning a handler that discards the call.
func (h *boundedJSONHandler) WithGroup(string) slog.Handler {
	if h == nil {
		return rejectHandler{}
	}
	return rejectHandler{onDrop: h.onDrop}
}

type rejectHandler struct{ onDrop func(string) }

// Enabled admits records so Handle can return the bounded rejection.
func (rejectHandler) Enabled(context.Context, slog.Level) bool { return true }

// Handle rejects a record retained behind an unsupported group.
func (h rejectHandler) Handle(context.Context, slog.Record) error {
	notifyLogDrop(h.onDrop, valueInvalid)
	return errRejectedRecord
}

// WithAttrs retains rejection.
func (h rejectHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

// WithGroup retains rejection.
func (h rejectHandler) WithGroup(string) slog.Handler { return h }

type discardHandler struct{}

// Enabled disables the fallback logger.
func (discardHandler) Enabled(context.Context, slog.Level) bool { return false }

// Handle discards one fallback record.
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }

// WithAttrs returns the same fallback handler.
func (discardHandler) WithAttrs([]slog.Attr) slog.Handler { return discardHandler{} }

// WithGroup returns the same fallback handler.
func (discardHandler) WithGroup(string) slog.Handler { return discardHandler{} }

// admittedField is one already validated key/value pair.
type admittedField struct {
	key   string
	value any
}

// admitAttributes resolves and validates exact scalar attributes.
func admitAttributes(eventID string, attributes []slog.Attr) ([]admittedField, error) {
	fields := make([]admittedField, 0, len(attributes)+1)
	fields = append(fields, admittedField{key: keyEventID, value: eventID})
	seen := map[string]struct{}{keyEventID: {}}
	for _, attribute := range attributes {
		if !slices.Contains(allowedLogKeys, attribute.Key) {
			return nil, errRejectedRecord
		}
		if _, duplicate := seen[attribute.Key]; duplicate {
			return nil, errRejectedRecord
		}
		seen[attribute.Key] = struct{}{}
		value := attribute.Value
		if value.Kind() == slog.KindLogValuer || value.Kind() == slog.KindAny ||
			value.Kind() == slog.KindGroup {
			return nil, errRejectedRecord
		}
		switch value.Kind() {
		case slog.KindBool:
			if attribute.Key != "ready" {
				return nil, errRejectedRecord
			}
			fields = append(fields, admittedField{key: attribute.Key, value: value.Bool()})
		case slog.KindString:
			text := value.String()
			if !slices.Contains(allowedLogValues[attribute.Key], text) {
				return nil, errRejectedRecord
			}
			fields = append(fields, admittedField{key: attribute.Key, value: text})
		default:
			return nil, errRejectedRecord
		}
	}
	return fields, nil
}

// encodeRecord creates one deterministic bounded JSON record.
func encodeRecord(timestamp time.Time, level slog.Level, eventID string, fields []admittedField) ([]byte, error) {
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	var output bytes.Buffer
	output.WriteByte('{')
	base := []admittedField{
		{key: "time", value: timestamp.UTC().Format(time.RFC3339Nano)},
		{key: "level", value: level.String()},
		{key: "msg", value: eventID},
	}
	all := append(base, fields...)
	for index, field := range all {
		if index > 0 {
			output.WriteByte(',')
		}
		key, _ := json.Marshal(field.key)
		value, err := json.Marshal(field.value)
		if err != nil {
			return nil, errRejectedRecord
		}
		output.Write(key)
		output.WriteByte(':')
		output.Write(value)
		if output.Len() >= maxLogRecordBytes {
			return nil, errRejectedRecord
		}
	}
	output.WriteString("}\n")
	if output.Len() > maxLogRecordBytes {
		return nil, errRejectedRecord
	}
	return output.Bytes(), nil
}

// validEventID validates one fixed log message and event identifier.
func validEventID(value string) bool {
	return slices.Contains(allowedLogValues[keyEventID], value)
}

// validRecordLevel limits serialized levels to the four documented values.
func validRecordLevel(level slog.Level) bool {
	switch level {
	case slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError:
		return true
	default:
		return false
	}
}

// mapLogLevel maps one closed config level to slog.
func mapLogLevel(value config.LogLevel) (slog.Level, bool) {
	switch value {
	case config.LogLevelDebug:
		return slog.LevelDebug, true
	case config.LogLevelInfo:
		return slog.LevelInfo, true
	case config.LogLevelWarn:
		return slog.LevelWarn, true
	case config.LogLevelError:
		return slog.LevelError, true
	default:
		return 0, false
	}
}
