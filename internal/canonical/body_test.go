package canonical

import (
	"bytes"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// TestBodyHashInputSection51TerminalHandling verifies DKIM2 body terminal rules.
func TestBodyHashInputSection51TerminalHandling(t *testing.T) {
	tests := []struct {
		name        string
		body        []byte
		want        []byte
		wantRemoved int
		wantAction  BodyTerminalAction
	}{
		{
			name:       "empty body becomes CRLF",
			body:       nil,
			want:       []byte("\r\n"),
			wantAction: BodyTerminalActionAppended,
		},
		{
			name:       "missing terminal CRLF appends one",
			body:       []byte("alpha"),
			want:       []byte("alpha\r\n"),
			wantAction: BodyTerminalActionAppended,
		},
		{
			name:       "single terminal CRLF is preserved",
			body:       []byte("alpha\r\n"),
			want:       []byte("alpha\r\n"),
			wantAction: BodyTerminalActionPreserved,
		},
		{
			name:        "trailing empty CRLF lines collapse",
			body:        []byte("alpha\r\n\r\n\r\n"),
			want:        []byte("alpha\r\n"),
			wantRemoved: 2,
			wantAction:  BodyTerminalActionCollapsed,
		},
		{
			name:        "all-empty CRLF body lines collapse to one",
			body:        []byte("\r\n\r\n"),
			want:        []byte("\r\n"),
			wantRemoved: 1,
			wantAction:  BodyTerminalActionCollapsed,
		},
	}

	canonicalizer, err := NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := mustParseBodyMessage(t, tt.body)
			got, err := canonicalizer.BodyHashInput(msg.Body())
			if err != nil {
				t.Fatalf("BodyHashInput() error = %v", err)
			}
			if !bytes.Equal(got.Bytes(), tt.want) {
				t.Fatalf("BodyHashInput() = %q, want %q", got.Bytes(), tt.want)
			}

			metadata := got.Metadata()
			if metadata.Kind != KindBodyHashInput {
				t.Fatalf("Metadata().Kind = %q, want body hash input", metadata.Kind)
			}
			if metadata.InputBytes != len(tt.body) {
				t.Fatalf("Metadata().InputBytes = %d, want %d", metadata.InputBytes, len(tt.body))
			}
			if metadata.OutputBytes != len(tt.want) {
				t.Fatalf("Metadata().OutputBytes = %d, want %d", metadata.OutputBytes, len(tt.want))
			}
			if metadata.BodyTrailingEmptyLines != tt.wantRemoved {
				t.Fatalf("Metadata().BodyTrailingEmptyLines = %d, want %d", metadata.BodyTrailingEmptyLines, tt.wantRemoved)
			}
			if metadata.BodyTerminalAction != tt.wantAction {
				t.Fatalf("Metadata().BodyTerminalAction = %q, want %q", metadata.BodyTerminalAction, tt.wantAction)
			}
		})
	}
}

// TestBodyHashInputPreservesNonTrailingBytes verifies MIME-agnostic byte preservation.
func TestBodyHashInputPreservesNonTrailingBytes(t *testing.T) {
	body := []byte("Content-Type: text/plain\r\n\r\nnot decoded=3Dyes\r\n\xff\x00mid\r\ntail")
	want := append(bytes.Clone(body), '\r', '\n')

	canonicalizer, err := NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	got, err := canonicalizer.BodyHashInputFromMessage(mustParseBodyMessage(t, body))
	if err != nil {
		t.Fatalf("BodyHashInputFromMessage() error = %v", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("BodyHashInputFromMessage() changed non-trailing body bytes")
	}
}

// TestBodyHashInputBytesAreImmutable verifies callers cannot mutate stored input.
func TestBodyHashInputBytesAreImmutable(t *testing.T) {
	canonicalizer, err := NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}

	body := []byte("immutable")
	msg := mustParseBodyMessage(t, body)
	got, err := canonicalizer.BodyHashInput(msg.Body())
	if err != nil {
		t.Fatalf("BodyHashInput() error = %v", err)
	}

	body[0] = 'X'
	exposed := got.Bytes()
	exposed[0] = 'Y'
	if !bytes.Equal(got.Bytes(), []byte("immutable\r\n")) {
		t.Fatalf("canonical body bytes were mutated: %q", got.Bytes())
	}
	if !bytes.Equal(msg.Body().Bytes(), []byte("immutable")) {
		t.Fatalf("raw message body bytes were mutated: %q", msg.Body().Bytes())
	}
}

// TestBodyHashInputEnforcesOutputLimitWithoutLeakingBody verifies safe limit errors.
func TestBodyHashInputEnforcesOutputLimitWithoutLeakingBody(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxBodyInputBytes = len("secret body\r\n") - 1
	canonicalizer, err := NewCanonicalizer(WithLimits(limits))
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}

	_, err = canonicalizer.BodyHashInput(mustParseBodyMessage(t, []byte("secret body")).Body())
	if !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("BodyHashInput() error = %v, want limit exceeded", err)
	}
	if strings.Contains(err.Error(), "secret body") {
		t.Fatalf("BodyHashInput() error leaked raw body content: %q", err.Error())
	}
}

// mustParseBodyMessage parses synthetic strict-CRLF messages for body tests.
func mustParseBodyMessage(t *testing.T, body []byte) rawmsg.Message {
	t.Helper()

	raw := append([]byte("A: b\r\n\r\n"), body...)
	msg, err := rawmsg.Parse(raw)
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}

	return msg
}
