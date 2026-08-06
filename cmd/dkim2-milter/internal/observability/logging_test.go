package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

const privacyMarker = "toxic-recipient+secret@example.invalid"

// TestBoundedLoggerEmitsExactClosedJSON proves the permitted event envelope.
func TestBoundedLoggerEmitsExactClosedJSON(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(newBoundedJSONHandler(&output, slog.LevelInfo))
	logger.Info(
		eventMessageCompleted,
		slog.String(keyOperation, "message"),
		slog.String(keyDaemonOperation, "process"),
		slog.String("mode", valueModeInbound),
		slog.String("disposition", valueAccept),
		slog.String(keyResultClass, valueSuccess),
		slog.String("failure_class", valueNone),
		slog.String("duration_bucket", "lt_10ms"),
		slog.String("message_size_bucket", "lt_10k"),
		slog.String("recipient_count_bucket", "2_10"),
		slog.String("domain_role", "recipient"),
		slog.String("processed_domains", "example.test,example.org"),
		slog.Uint64("processed_domain_count", 2),
		slog.Bool("processed_domains_truncated", false),
		slog.Bool("fail_open", false),
	)
	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal("admitted record was not JSON")
	}
	if document["msg"] != eventMessageCompleted ||
		document["event_id"] != eventMessageCompleted ||
		document["mode"] != valueModeInbound ||
		document["processed_domains"] != "example.test,example.org" ||
		document["time"] == "" || document["level"] != "INFO" {
		t.Fatalf("unexpected admitted record: %#v", document)
	}
	if len(output.Bytes()) > maxLogRecordBytes {
		t.Fatal("admitted record exceeded the fixed cap")
	}
}

// TestBoundedLoggerRejectsUnknownValuesAndDangerousKinds proves privacy admission.
func TestBoundedLoggerRejectsUnknownValuesAndDangerousKinds(t *testing.T) {
	tests := []struct {
		name       string
		message    string
		attributes []slog.Attr
		group      bool
	}{
		{name: "unknown event", message: privacyMarker},
		{name: "unknown key", message: eventMessageCompleted, attributes: []slog.Attr{slog.String("recipient", privacyMarker)}},
		{name: "arbitrary value", message: eventMessageCompleted, attributes: []slog.Attr{slog.String(keyMode, privacyMarker)}},
		{name: "error any", message: eventMessageCompleted, attributes: []slog.Attr{slog.Any(keyFailureClass, errors.New(privacyMarker))}},
		{name: "bytes any", message: eventMessageCompleted, attributes: []slog.Attr{slog.Any(keyMode, []byte(privacyMarker))}},
		{name: "integer", message: eventMessageCompleted, attributes: []slog.Attr{slog.Int(keyMode, 1)}},
		{name: "local part in domain", message: eventMessageCompleted, attributes: []slog.Attr{slog.String("processed_domains", privacyMarker)}},
		{name: "duplicate", message: eventMessageCompleted, attributes: []slog.Attr{slog.String(keyMode, valueModeInbound), slog.String(keyMode, valueModeInbound)}},
		{name: "missing required fields", message: eventConfigAccepted, attributes: []slog.Attr{slog.String(keyOperation, "config")}},
		{name: "wrong event operation", message: eventConfigAccepted, attributes: []slog.Attr{
			slog.Bool(keyFailOpen, false),
			slog.String(keyMode, valueModeInbound),
			slog.String(keyOperation, "message"),
			slog.String(keyResultClass, valueSuccess),
		}},
		{name: "group", message: eventMessageCompleted, group: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			var output bytes.Buffer
			logger := slog.New(newBoundedJSONHandler(&output, slog.LevelDebug))
			if testCase.group {
				logger = logger.WithGroup(privacyMarker)
			}
			logger.LogAttrs(
				context.Background(),
				slog.LevelInfo,
				testCase.message,
				testCase.attributes...,
			)
			if output.Len() != 0 || strings.Contains(output.String(), privacyMarker) {
				t.Fatal("rejected record reached the destination")
			}
		})
	}
}

// TestBoundedLoggerRejectsMailboxLocalPartsInCompleteDomainRecords proves the
// final sink validates domain syntax even when every other field is coherent.
func TestBoundedLoggerRejectsMailboxLocalPartsInCompleteDomainRecords(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(newBoundedJSONHandler(&output, slog.LevelInfo))
	logger.Info(
		eventMessageCompleted,
		slog.String(keyOperation, "message"),
		slog.String(keyDaemonOperation, "process"),
		slog.String(keyMode, valueModeInbound),
		slog.String(keyDisposition, valueAccept),
		slog.String(keyResultClass, valueSuccess),
		slog.String(keyFailureClass, valueNone),
		slog.String(keyDurationBucket, "lt_10ms"),
		slog.String(keyMessageSizeBucket, "lt_10k"),
		slog.String(keyRecipientBucket, "1"),
		slog.String(keyDomainRole, "recipient"),
		slog.String(keyDomains, privacyMarker),
		slog.Uint64(keyDomainCount, 1),
		slog.Bool(keyDomainsTruncated, false),
		slog.Bool(keyFailOpen, false),
	)
	if output.Len() != 0 {
		t.Fatal("mailbox local part reached the logging sink")
	}
}

// TestBoundedLoggerRejectsAttributeAndLevelAbuse proves deterministic caps.
func TestBoundedLoggerRejectsAttributeAndLevelAbuse(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(newBoundedJSONHandler(&output, slog.LevelDebug))
	attributes := make([]slog.Attr, 0, maxLogAttributes+1)
	for range maxLogAttributes + 1 {
		attributes = append(attributes, slog.String(keyMode, "inbound"))
	}
	logger.LogAttrs(context.Background(), slog.LevelInfo, eventMessageCompleted, attributes...)
	logger.LogAttrs(context.Background(), slog.Level(99), eventMessageCompleted)
	if output.Len() != 0 {
		t.Fatal("attribute or level abuse reached output")
	}
}

// TestBoundedLoggerAppliesThresholdWithoutLeakingDroppedRecords proves level admission.
func TestBoundedLoggerAppliesThresholdWithoutLeakingDroppedRecords(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(newBoundedJSONHandler(&output, slog.LevelWarn))
	attributes := []any{
		slog.Bool(keyFailOpen, false),
		slog.String(keyMode, "inbound"),
		slog.String(keyOperation, "config"),
		slog.String(keyResultClass, valueSuccess),
	}
	logger.Info(eventConfigAccepted, attributes...)
	logger.Warn(eventConfigAccepted, attributes...)
	if bytes.Count(output.Bytes(), []byte{'\n'}) != 1 ||
		!bytes.Contains(output.Bytes(), []byte(`"level":"WARN"`)) {
		t.Fatal("configured threshold was not applied")
	}
}

// TestEncodeRecordRejectsAnOversizedEnvelope proves the final serialized cap.
func TestEncodeRecordRejectsAnOversizedEnvelope(t *testing.T) {
	fields := make(map[string]any)
	for index := range 1_000 {
		fields[strings.Repeat("x", index+1)] = valueSuccess
	}
	if _, err := encodeRecord(time.Now(), slog.LevelInfo, eventConfigAccepted, fields); err == nil {
		t.Fatal("oversized serialized record was accepted")
	}
}

// TestLoggerContainsDestinationPanics proves logging cannot crash protocol work.
func TestLoggerContainsDestinationPanics(_ *testing.T) {
	logger := slog.New(newBoundedJSONHandler(panicWriter{}, slog.LevelInfo))
	logger.Info(
		eventConfigAccepted,
		slog.Bool(keyFailOpen, false),
		slog.String(keyMode, "inbound"),
		slog.String(keyOperation, "config"),
		slog.String(keyResultClass, valueSuccess),
	)
}

// panicWriter is a hostile logging destination.
type panicWriter struct{}

// Write panics to exercise logging containment.
func (panicWriter) Write([]byte) (int, error) { panic(privacyMarker) }
