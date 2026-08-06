package observability

import (
	"log/slog"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/milter"
)

// RecordConnectionAdmission records one bounded connection admission outcome.
func (r *Runtime) RecordConnectionAdmission(admission string) {
	if r == nil || !closedMetricValue(keyAdmission, admission) {
		return
	}
	resultClass := valueTemporary
	if admission == "accepted" {
		resultClass = valueSuccess
	}
	r.logger.Info(
		eventConnectionAdmission,
		slog.String(keyAdmission, admission),
		slog.String(keyOperation, "connection"),
		slog.String(keyResultClass, resultClass),
	)
	r.registry.RecordConnectionAdmission(admission)
}

// RecordCallback records one bounded callback state and duration.
func (r *Runtime) RecordCallback(
	callbackClass string,
	stateClass string,
	resultClass string,
	duration time.Duration,
) {
	if r == nil || duration < 0 ||
		!closedMetricValue(keyCallbackClass, callbackClass) ||
		!closedMetricValue(keyStateClass, stateClass) ||
		!closedMetricValue(keyResultClass, resultClass) {
		return
	}
	r.logger.Info(
		eventCallbackCompleted,
		slog.String(keyCallbackClass, callbackClass),
		slog.String(keyDurationBucket, durationBucket(duration)),
		slog.String(keyOperation, "callback"),
		slog.String(keyResultClass, resultClass),
		slog.String(keyStateClass, stateClass),
	)
	r.registry.RecordCallback(callbackClass, stateClass, resultClass)
}

// RecordMessage records one bounded message outcome without retaining mail data.
func (r *Runtime) RecordMessage(
	mode string,
	disposition string,
	resultClass string,
	failureClass string,
	duration time.Duration,
	messageBytes uint64,
	recipients uint64,
	failOpen bool,
	domains milter.DomainObservation,
) {
	operation, operationOK := daemonOperationForMode(mode)
	if r == nil || duration < 0 ||
		messageBytes > maxObservedMessageBytes ||
		recipients > maxObservedRecipients ||
		!closedMetricValue(keyMode, mode) ||
		!closedMetricValue(keyDisposition, disposition) ||
		!closedMetricValue(keyResultClass, resultClass) ||
		!closedMetricValue(keyFailureClass, failureClass) ||
		!domains.ValidForMode(mode) ||
		!operationOK ||
		!validMessageOutcome(disposition, resultClass, failureClass, failOpen) {
		return
	}
	r.logger.Info(
		eventMessageCompleted,
		slog.String(keyDaemonOperation, operation),
		slog.String(keyDisposition, disposition),
		slog.Uint64(keyDomainCount, domains.Count()),
		slog.String(keyDomainRole, domains.Role()),
		slog.String(keyDomains, domains.Domains()),
		slog.Bool(keyDomainsTruncated, domains.Truncated()),
		slog.String(keyDurationBucket, durationBucket(duration)),
		slog.Bool(keyFailOpen, failOpen),
		slog.String(keyFailureClass, failureClass),
		slog.String(keyMessageSizeBucket, messageSizeBucket(messageBytes)),
		slog.String(keyMode, mode),
		slog.String(keyOperation, "message"),
		slog.String(keyRecipientBucket, recipientCountBucket(recipients)),
		slog.String(keyResultClass, resultClass),
	)
	r.registry.RecordMessage(
		mode,
		operation,
		disposition,
		resultClass,
		failureClass,
		duration,
		messageBytes,
		recipients,
		failOpen,
	)
}

// daemonOperationForMode derives one immutable operation without caller input.
func daemonOperationForMode(mode string) (string, bool) {
	switch mode {
	case valueModeInbound:
		return "process", true
	case "originator":
		return "sign", true
	case "ordinary_transit":
		return "revise", true
	case valueModePostfixDSN:
		return valueOperationDSN, true
	default:
		return "", false
	}
}

// validMessageOutcome rejects incoherent Cartesian telemetry tuples.
func validMessageOutcome(
	disposition string,
	resultClass string,
	failureClass string,
	failOpen bool,
) bool {
	if failOpen {
		return disposition == valueAccept && resultClass == valueTemporary &&
			(failureClass == "capacity" || failureClass == "timeout" ||
				failureClass == "unavailable")
	}
	if failureClass == valueNone {
		return disposition != valueClose
	}
	if resultClass == valueSuccess || disposition == valueAccept ||
		disposition == valueContinue || disposition == valueReject {
		return false
	}
	return disposition == valueTempfail || disposition == valueClose
}

// RecordAction records one bounded applied action outcome.
func (r *Runtime) RecordAction(actionKind string, resultClass string) {
	if r == nil ||
		!closedMetricValue(keyActionKind, actionKind) ||
		!closedMetricValue(keyResultClass, resultClass) {
		return
	}
	r.logger.Info(
		eventActionCompleted,
		slog.String(keyActionKind, actionKind),
		slog.String(keyOperation, "action"),
		slog.String(keyResultClass, resultClass),
	)
	r.registry.RecordAction(actionKind, resultClass)
}

// durationBucket maps a duration to one closed logging class.
func durationBucket(duration time.Duration) string {
	for _, candidate := range []struct {
		limit time.Duration
		name  string
	}{
		{time.Millisecond, valueDurationLT1ms},
		{5 * time.Millisecond, valueDurationLT5ms},
		{10 * time.Millisecond, "lt_10ms"},
		{25 * time.Millisecond, "lt_25ms"},
		{50 * time.Millisecond, "lt_50ms"},
		{100 * time.Millisecond, "lt_100ms"},
		{250 * time.Millisecond, "lt_250ms"},
		{500 * time.Millisecond, "lt_500ms"},
		{time.Second, "lt_1s"},
		{2500 * time.Millisecond, "lt_2_5s"},
		{5 * time.Second, "lt_5s"},
		{10 * time.Second, "lt_10s"},
		{30 * time.Second, "lt_30s"},
	} {
		if duration < candidate.limit {
			return candidate.name
		}
	}
	return valueDurationGTE30s
}

// messageSizeBucket maps a size to one closed logging class.
func messageSizeBucket(size uint64) string {
	switch {
	case size == 0:
		return "0"
	case size < 1_000:
		return "lt_1k"
	case size < 10_000:
		return valueSizeLT10k
	case size < 100_000:
		return "lt_100k"
	case size < 1_000_000:
		return "lt_1m"
	case size < 10_000_000:
		return "lt_10m"
	default:
		return "gte_10m"
	}
}

// recipientCountBucket maps a count to one closed logging class.
func recipientCountBucket(count uint64) string {
	switch {
	case count == 0:
		return "0"
	case count == 1:
		return "1"
	case count <= 10:
		return "2_10"
	case count <= 100:
		return "11_100"
	case count <= 1_000:
		return "101_1000"
	default:
		return valueRecipientsGTE
	}
}
