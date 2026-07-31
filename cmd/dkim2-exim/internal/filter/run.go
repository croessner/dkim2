package filter

import (
	"context"
	"io"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
)

// PlanProcessor authorizes exactly one complete filter request.
type PlanProcessor interface {
	Process(context.Context, adapter.FilterRequest) (adapter.Plan, error)
}

// RunConfig owns all one-shot filter authorities and protocol streams.
type RunConfig struct {
	Operation adapter.FilterOperation
	Arguments []string
	Input     io.Reader
	Output    io.Writer
	Loader    EvidenceLoader
	Processor PlanProcessor
	TempDir   string
	Limits    Limits
}

const (
	// ExitSuccess reports one completely emitted message.
	ExitSuccess = 0
	// ExitDefer requests Exim delivery deferral without protocol output.
	ExitDefer = 75
)

// Execute runs one silent filter invocation and returns its process status.
func Execute(ctx context.Context, config RunConfig) (status int) {
	status = ExitDefer
	defer func() {
		if recover() != nil {
			status = ExitDefer
		}
	}()
	if Run(ctx, config) != nil {
		return ExitDefer
	}
	return ExitSuccess
}

// Run fully reads, authorizes, transforms, and only then streams one message.
func Run(ctx context.Context, config RunConfig) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = adapter.NewError(adapter.FailureInternal)
		}
	}()
	if ctx == nil || config.Output == nil || config.Processor == nil {
		return adapter.NewError(adapter.FailureContract)
	}
	if config.Limits == (Limits{}) {
		config.Limits = DefaultLimits()
	}
	if !config.Limits.Valid() {
		return adapter.NewError(adapter.FailureContract)
	}
	if _, ok := config.Limits.WorkingSetBytes(); !ok {
		return adapter.NewError(adapter.FailureResource)
	}
	invocation, err := parseInvocation(config.Operation, config.Arguments)
	if err != nil {
		return err
	}
	workspace, err := newPrivateWorkspace(config.TempDir)
	if err != nil {
		return err
	}
	defer func() { _ = workspace.close() }()
	message, err := workspace.capture(config.Input, config.Limits.MessageBytes)
	if err != nil {
		return err
	}
	defer clear(message)
	if err := validateCompleteMessageLimited(message, config.Limits); err != nil {
		return err
	}
	request, err := invocation.buildRequest(ctx, message, config.Loader)
	if err != nil {
		return err
	}
	plan, err := config.Processor.Process(ctx, request)
	if err != nil {
		return err
	}
	if !planMatchesRequest(plan, request.Operation()) {
		return adapter.NewError(adapter.FailureContract)
	}
	authorizedMessage := request.Message()
	defer clear(authorizedMessage)
	output, err := TransformLimited(authorizedMessage, plan, config.Limits)
	if err != nil {
		return err
	}
	defer clear(output)
	if err := workspace.prepareOutput(output, config.Limits); err != nil {
		return err
	}
	if err := workspace.seal(); err != nil {
		return err
	}
	streamErr := workspace.stream(ctx, config.Output)
	closeErr := workspace.close()
	if streamErr != nil {
		return streamErr
	}
	if closeErr != nil {
		return adapter.NewError(adapter.FailurePartialOutput)
	}
	return nil
}

// planMatchesRequest prevents cross-operation action-plan substitution.
func planMatchesRequest(plan adapter.Plan, operation adapter.FilterOperation) bool {
	return operation == adapter.FilterSign && plan.Operation() == adapter.OperationSign ||
		operation == adapter.FilterRevise && plan.Operation() == adapter.OperationRevise
}

// writeOutput reports any short or failed protocol write as indeterminate output.
func writeOutput(output io.Writer, message []byte) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = adapter.NewError(adapter.FailurePartialOutput)
		}
	}()
	if output == nil || len(message) == 0 {
		return adapter.NewError(adapter.FailureContract)
	}
	count, err := output.Write(message)
	if err != nil || count != len(message) {
		return adapter.NewError(adapter.FailurePartialOutput)
	}
	return nil
}
