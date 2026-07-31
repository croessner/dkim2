package filter

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
)

// planProcessorFunc supplies one complete independently authorized plan.
type planProcessorFunc func(context.Context, adapter.FilterRequest) (adapter.Plan, error)

// Process delegates to the independently controlled filter plan fixture.
func (f planProcessorFunc) Process(ctx context.Context, request adapter.FilterRequest) (adapter.Plan, error) {
	return f(ctx, request)
}

// shortWriter deterministically fails after one emitted protocol byte.
type shortWriter struct{ writes int }

// Write creates the output-indeterminate boundary after partial emission.
func (w *shortWriter) Write(input []byte) (int, error) {
	w.writes++
	if len(input) == 0 {
		return 0, nil
	}
	return 1, errors.New("disconnect")
}

// nilShortWriter violates the full-write contract without returning an error.
type nilShortWriter struct{ writes int }

// Write returns one silent short write that must never be retried.
func (w *nilShortWriter) Write(input []byte) (int, error) {
	w.writes++
	if len(input) == 0 {
		return 0, nil
	}
	return len(input) - 1, nil
}

// failSecondWriter accepts one complete chunk before disconnecting partially.
type failSecondWriter struct {
	writes   int
	accepted int
}

// panicWriter simulates a protocol sink that panics after accepting one byte.
type panicWriter struct {
	writes int
}

// Write panics at the output-indeterminate boundary.
func (w *panicWriter) Write([]byte) (int, error) {
	w.writes++
	panic("synthetic protocol sink panic")
}

// Write succeeds once, then reports a one-byte partial disconnect.
func (w *failSecondWriter) Write(input []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		w.accepted += len(input)
		return len(input), nil
	}
	if len(input) == 0 {
		return 0, errors.New("disconnect")
	}
	w.accepted++
	return 1, errors.New("disconnect")
}

// TestRunNeverFallsBackAfterPartialOutput proves no original-message fallback occurs.
func TestRunNeverFallsBackAfterPartialOutput(t *testing.T) {
	plan, err := adapter.NewFilterPlan(adapter.FilterSign, adapter.ResultPass, adapter.DispositionContinue, nil)
	if err != nil {
		t.Fatal("continue plan failed")
	}
	writer := &shortWriter{}
	err = Run(context.Background(), RunConfig{
		Operation: adapter.FilterSign, Arguments: []string{testTransportSender, testTransportRecipient},
		Input: bytes.NewBufferString("Subject: test\n\nbody\n"), Output: writer,
		Processor: planProcessorFunc(func(context.Context, adapter.FilterRequest) (adapter.Plan, error) { return plan, nil }),
	})
	if err == nil || writer.writes != 1 {
		t.Fatal("partial output was treated as success or retried")
	}
}

// TestExecuteContainsDependencyPanics proves public filter execution never
// emits runtime panic diagnostics or reports success.
func TestExecuteContainsDependencyPanics(t *testing.T) {
	t.Run("processor before output", func(t *testing.T) {
		var output bytes.Buffer
		status := Execute(context.Background(), RunConfig{
			Operation: adapter.FilterSign,
			Arguments: []string{testTransportSender, testTransportRecipient},
			Input:     bytes.NewBufferString("Subject: test\n\nbody\n"),
			Output:    &output,
			Processor: planProcessorFunc(func(context.Context, adapter.FilterRequest) (adapter.Plan, error) {
				panic("synthetic processor panic")
			}),
		})
		if status != ExitDefer || output.Len() != 0 {
			t.Fatal("pre-output dependency panic escaped or emitted output")
		}
	})

	t.Run("protocol sink after authorization", func(t *testing.T) {
		plan, err := adapter.NewFilterPlan(
			adapter.FilterSign,
			adapter.ResultPass,
			adapter.DispositionContinue,
			nil,
		)
		if err != nil {
			t.Fatal("continue plan failed")
		}
		output := &panicWriter{}
		status := Execute(context.Background(), RunConfig{
			Operation: adapter.FilterSign,
			Arguments: []string{testTransportSender, testTransportRecipient},
			Input:     bytes.NewBufferString("Subject: test\n\nbody\n"),
			Output:    output,
			Processor: planProcessorFunc(func(context.Context, adapter.FilterRequest) (adapter.Plan, error) {
				return plan, nil
			}),
		})
		if status != ExitDefer || output.writes != 1 {
			t.Fatal("output panic escaped, retried, or reported success")
		}
	})
}

// TestRunTreatsNilShortWriteAsIndeterminate proves a short stdout write is
// terminal even when the writer omits an error.
func TestRunTreatsNilShortWriteAsIndeterminate(t *testing.T) {
	plan, _ := adapter.NewFilterPlan(
		adapter.FilterSign,
		adapter.ResultPass,
		adapter.DispositionContinue,
		nil,
	)
	writer := &nilShortWriter{}
	err := Run(context.Background(), RunConfig{
		Operation: adapter.FilterSign,
		Arguments: []string{testTransportSender, testTransportRecipient},
		Input:     bytes.NewBufferString("Subject: test\n\nbody\n"),
		Output:    writer,
		Processor: planProcessorFunc(func(context.Context, adapter.FilterRequest) (adapter.Plan, error) {
			return plan, nil
		}),
	})
	if err == nil || writer.writes != 1 {
		t.Fatal("nil-error short output was retried or accepted")
	}
}

// TestRunNeverRetriesAfterLargePartialOutput proves a disconnect after a
// complete first stdout chunk cannot trigger daemon or original-message retry.
func TestRunNeverRetriesAfterLargePartialOutput(t *testing.T) {
	first, _ := adapter.NewAction(
		adapter.ActionAddHeader,
		"Message-Instance",
		" "+strings.Repeat("x", 65_000),
	)
	second, _ := adapter.NewAction(
		adapter.ActionAddHeader,
		"DKIM2-Signature",
		" i=1; s=a",
	)
	plan, _ := adapter.NewFilterPlan(
		adapter.FilterSign,
		adapter.ResultPass,
		adapter.DispositionAccept,
		[]adapter.Action{first, second},
	)
	writer := &failSecondWriter{}
	processorCalls := 0
	status := Execute(context.Background(), RunConfig{
		Operation: adapter.FilterSign,
		Arguments: []string{testTransportSender, testTransportRecipient},
		Input:     bytes.NewBufferString("Subject: test\n\nbody\n"),
		Output:    writer,
		Processor: planProcessorFunc(func(context.Context, adapter.FilterRequest) (adapter.Plan, error) {
			processorCalls++
			return plan, nil
		}),
	})
	if status != ExitDefer || writer.writes != 2 ||
		writer.accepted != streamBufferBytes+1 || processorCalls != 1 {
		t.Fatal("large partial output was accepted, retried, or replaced")
	}
}

// TestRunKeepsPreOutputFailuresSilent proves no original message is emitted
// after daemon, admission, or transformation failure.
func TestRunKeepsPreOutputFailuresSilent(t *testing.T) {
	var output bytes.Buffer
	err := Run(context.Background(), RunConfig{
		Operation: adapter.FilterSign,
		Arguments: []string{testTransportSender, testTransportRecipient},
		Input:     bytes.NewBufferString("Subject: test\n\nbody\n"),
		Output:    &output,
		Processor: planProcessorFunc(func(context.Context, adapter.FilterRequest) (adapter.Plan, error) {
			return adapter.Plan{}, adapter.NewError(adapter.FailureUnavailable)
		}),
	})
	if err == nil || output.Len() != 0 {
		t.Fatal("pre-output failure emitted protocol bytes")
	}
}

// TestRunAppendsOneMissingTerminalLF proves the daemon-authorized and emitted
// representations include exactly the newline Exim would otherwise add.
func TestRunAppendsOneMissingTerminalLF(t *testing.T) {
	plan, _ := adapter.NewFilterPlan(
		adapter.FilterSign,
		adapter.ResultPass,
		adapter.DispositionContinue,
		nil,
	)
	var output bytes.Buffer
	err := Run(context.Background(), RunConfig{
		Operation: adapter.FilterSign,
		Arguments: []string{"", testTransportRecipient},
		Input:     bytes.NewBufferString("Subject: test\n\nbody"),
		Output:    &output,
		Processor: planProcessorFunc(func(_ context.Context, request adapter.FilterRequest) (adapter.Plan, error) {
			if !bytes.Equal(request.Message(), []byte("Subject: test\n\nbody\n")) {
				t.Fatal("daemon request did not own completed LF message")
			}
			return plan, nil
		}),
	})
	if err != nil || !bytes.Equal(output.Bytes(), []byte("Subject: test\n\nbody\n")) {
		t.Fatal("completed LF output differs from authorized input")
	}
}

// TestRunRejectsCrossOperationPlanBeforeOutput proves a revise response cannot
// authorize sign output or vice versa.
func TestRunRejectsCrossOperationPlanBeforeOutput(t *testing.T) {
	action, _ := adapter.NewAction(
		adapter.ActionAddHeader,
		"DKIM2-Signature",
		" i=2; s=a",
	)
	plan, _ := adapter.NewFilterPlan(
		adapter.FilterRevise,
		adapter.ResultPass,
		adapter.DispositionAccept,
		[]adapter.Action{action},
	)
	var output bytes.Buffer
	status := Execute(context.Background(), RunConfig{
		Operation: adapter.FilterSign,
		Arguments: []string{testTransportSender, testTransportRecipient},
		Input:     bytes.NewBufferString("Subject: test\n\nbody\n"),
		Output:    &output,
		Processor: planProcessorFunc(func(context.Context, adapter.FilterRequest) (adapter.Plan, error) {
			return plan, nil
		}),
	})
	if status != ExitDefer || output.Len() != 0 {
		t.Fatal("cross-operation plan emitted protocol output")
	}
}

// TestRunRemovesPrivateWorkspace proves transient input and output ownership is
// removed after both success and failure.
func TestRunRemovesPrivateWorkspace(t *testing.T) {
	parent := t.TempDir()
	plan, _ := adapter.NewFilterPlan(
		adapter.FilterSign,
		adapter.ResultPass,
		adapter.DispositionContinue,
		nil,
	)
	var output bytes.Buffer
	if status := Execute(context.Background(), RunConfig{
		Operation: adapter.FilterSign,
		Arguments: []string{testTransportSender, testTransportRecipient},
		Input:     bytes.NewBufferString("Subject: test\n\nbody\n"),
		Output:    &output,
		TempDir:   parent,
		Processor: planProcessorFunc(func(context.Context, adapter.FilterRequest) (adapter.Plan, error) {
			return plan, nil
		}),
	}); status != ExitSuccess {
		t.Fatal("successful private-spool run deferred")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("private filter workspace survived completion")
	}
}

// TestRunRejectsEnvelopeBeforeEvidenceAndDaemon proves unsupported outgoing
// SMTPUTF8 and grouped delivery never reach either authority boundary.
func TestRunRejectsEnvelopeBeforeEvidenceAndDaemon(t *testing.T) {
	incoming, _ := adapter.NewIncomingEvidence(
		[]byte("<incoming@example.test>"),
		[][]byte{[]byte("<received@example.test>")},
		adapter.SessionSMTP,
	)
	tests := [][]string{
		{testLocator, "<séndér@example.test>", testTransportRecipient},
		{testLocator, testTransportSender, "<first@example.test>", "<second@example.test>"},
	}
	for _, arguments := range tests {
		loader := &evidenceStub{incoming: incoming}
		processorCalls := 0
		var output bytes.Buffer
		status := Execute(context.Background(), RunConfig{
			Operation: adapter.FilterRevise,
			Arguments: arguments,
			Input:     bytes.NewBufferString("Subject: \xc3\xa9\n\nbody\xf0\x9f\x93\xa8\n"),
			Output:    &output,
			Loader:    loader,
			Processor: planProcessorFunc(func(context.Context, adapter.FilterRequest) (adapter.Plan, error) {
				processorCalls++
				return adapter.Plan{}, adapter.NewError(adapter.FailureInternal)
			}),
		})
		if status != ExitDefer || output.Len() != 0 ||
			loader.calls != 0 || processorCalls != 0 {
			t.Fatal("invalid outgoing batch reached authority or emitted output")
		}
	}
}
