package testclient

import (
	"context"
	"io"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/testclient/generated"
)

// Application owns one command invocation and its deterministic output.
type Application struct {
	output     io.Writer
	newRuntime func(Options) (*Runtime, error)
}

// operationCapabilities owns the separately scoped protected credentials.
type operationCapabilities struct {
	process *Capability
	sign    *Capability
	revise  *Capability
}

// Close releases every loaded operation capability.
func (c operationCapabilities) Close() {
	_ = c.process.Close()
	_ = c.sign.Close()
	_ = c.revise.Close()
}

// NewApplication constructs one command-scoped test client application.
func NewApplication(output io.Writer) *Application {
	return &Application{output: output, newRuntime: NewRuntime}
}

// Validate validates all fixture documents without protected or network access.
func (a *Application) Validate(_ Options, paths []string) error {
	plan, err := LoadExecutionPlan(paths)
	if err != nil {
		return err
	}
	for _, identifier := range plan.FixtureIdentifiers() {
		operation := "validate"
		if err := writeRecord(a.output, ResultRecord{
			Schema: outputSchema, Draft: draftVersion, Fixture: &identifier,
			Operation: &operation, Outcome: outcomeMatch,
		}); err != nil {
			return err
		}
	}
	return nil
}

// Run executes one completely validated deterministic fixture plan.
func (a *Application) Run(options Options, paths []string) error {
	plan, err := LoadExecutionPlan(paths)
	if err != nil {
		return err
	}
	if err := options.validateRequirements(
		plan.requiresCapability,
		plan.requiresSignCapability,
		plan.requiresReviseCapability,
	); err != nil {
		return err
	}
	var capabilities operationCapabilities
	if plan.requiresCapability {
		capabilities.process, err = LoadCapabilityForOperation(
			options.CapabilityFile, OperationProcess,
		)
		if err != nil {
			return err
		}
	}
	if plan.requiresSignCapability {
		capabilities.sign, err = LoadCapabilityForOperation(
			options.SignCapabilityFile, OperationSign,
		)
		if err != nil {
			capabilities.Close()
			return err
		}
	}
	if plan.requiresReviseCapability {
		capabilities.revise, err = LoadCapabilityForOperation(
			options.ReviseCapabilityFile, OperationRevise,
		)
		if err != nil {
			capabilities.Close()
			return err
		}
	}
	defer capabilities.Close()
	if !capabilitiesAreDistinct(
		capabilities.process, capabilities.sign, capabilities.revise,
	) {
		return NewExitError(ExitCapability)
	}
	runtime, err := a.newRuntime(options)
	if err != nil {
		return err
	}
	defer func() { _ = runtime.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), options.Timeout)
	defer cancel()

	resultClass := ExitOK
	for _, planned := range plan.cases {
		class := a.executePlannedCase(ctx, runtime, capabilities, planned)
		if class != ExitOK && (resultClass == ExitOK || class < resultClass) {
			resultClass = class
		}
		if class == ExitTransport || class == ExitCapability {
			break
		}
	}
	if resultClass != ExitOK {
		return newReportedError(resultClass)
	}
	return nil
}

// executePlannedCase executes and records one validated case.
func (a *Application) executePlannedCase(
	ctx context.Context,
	runtime *Runtime,
	capabilities operationCapabilities,
	planned plannedCase,
) ExitClass {
	started := time.Now()
	testCase := planned.value
	var fact ResponseFact
	var err error
	switch testCase.Kind {
	case caseHealth:
		fact, err = runtime.CallHealth(ctx)
	case caseReadiness:
		fact, err = runtime.CallReadiness(ctx)
	case caseProcess:
		var request generated.ProcessRequest
		request, err = generatedProcessRequest(*testCase.Process)
		if err == nil {
			fact, err = runtime.CallProcess(ctx, request, capabilities.process.EditRequest)
		}
	case caseSign:
		var request generated.SignRequest
		request, err = generatedSignRequest(*testCase.Sign)
		if err == nil {
			fact, err = runtime.CallSign(ctx, request, capabilities.sign.EditRequest)
		}
	case caseRevise:
		var request generated.ReviseRequest
		request, err = generatedReviseRequest(*testCase.Revise)
		if err == nil {
			fact, err = runtime.CallRevise(ctx, request, capabilities.revise.EditRequest)
		}
	case caseNegative:
		operation := negativeOperation(*testCase.Negative)
		capability := capabilities.process
		if testCase.Negative.Mutation != mutationWrongRouteCapability {
			switch operation {
			case OperationSign:
				capability = capabilities.sign
			case OperationRevise:
				capability = capabilities.revise
			}
		}
		fact, err = runtime.CallNegativeOperation(
			ctx, operation, testCase.Negative.Mutation, capability,
		)
	default:
		err = NewExitError(ExitInternal)
	}
	class := ExitClassOf(err)
	record := resultForCase(planned, fact, class)
	bucket := DurationBucket(time.Since(started))
	record.DurationBucket = &bucket
	if class == ExitOK && !expectationMatches(testCase.Expect, fact) {
		class = ExitMismatch
		record.Outcome = outcomeMismatch
		value := class.String()
		record.ErrorClass = &value
	}
	if writeErr := writeRecord(a.output, record); writeErr != nil {
		return ExitInternal
	}
	return class
}

// resultForCase constructs the stable allowlisted result projection.
func resultForCase(planned plannedCase, fact ResponseFact, class ExitClass) ResultRecord {
	operation := planned.value.Kind
	record := ResultRecord{
		Schema: outputSchema, Draft: draftVersion,
		Fixture: &planned.fixture, Case: &planned.value.Case,
		Operation: &operation, Outcome: outcomeMatch,
	}
	if fact.Status != 0 {
		record.HTTPStatus = &fact.Status
	}
	if class != ExitOK {
		record.Outcome = outcomeError
		value := class.String()
		record.ErrorClass = &value
	}
	if fact.Process != nil {
		disposition := string(fact.Process.Disposition)
		verification := string(fact.Process.Verification.State)
		policy := string(fact.Process.Policy.Verdict)
		replay := string(fact.Process.Replay.Class)
		record.Disposition = &disposition
		record.VerificationState = &verification
		record.PolicyVerdict = &policy
		record.ReplayClass = &replay
	}
	if fact.Sign != nil {
		disposition := string(fact.Sign.Disposition)
		record.Disposition = &disposition
	}
	if fact.Revise != nil {
		disposition := string(fact.Revise.Disposition)
		record.Disposition = &disposition
	}
	return record
}

// expectationMatches compares only explicitly allowlisted typed facts.
func expectationMatches(expectation fixtureExpectation, fact ResponseFact) bool {
	if fact.Status != expectation.HTTPStatus {
		return false
	}
	if fact.Health != nil {
		return expectation.HealthStatus != nil &&
			string(fact.Health.Status) == *expectation.HealthStatus
	}
	if fact.Readiness != nil {
		return expectation.ReadinessStatus != nil &&
			string(fact.Readiness.Status) == *expectation.ReadinessStatus
	}
	if fact.Process != nil {
		return expectation.Disposition != nil &&
			string(fact.Process.Disposition) == *expectation.Disposition &&
			expectation.VerificationState != nil &&
			string(fact.Process.Verification.State) == *expectation.VerificationState &&
			expectation.PolicyVerdict != nil &&
			string(fact.Process.Policy.Verdict) == *expectation.PolicyVerdict &&
			expectation.ReplayClass != nil &&
			string(fact.Process.Replay.Class) == *expectation.ReplayClass &&
			expectedActionsMatch(expectation.Actions, fact.Process.Actions)
	}
	if fact.Sign != nil {
		return expectedOperationMatches(expectation, fact.Sign)
	}
	if fact.Revise != nil {
		return expectedOperationMatches(expectation, fact.Revise)
	}
	if fact.Error != nil {
		return expectation.ErrorCode != nil && string(fact.Error.Code) == *expectation.ErrorCode
	}
	return false
}

// expectedOperationMatches compares every generated operation response fact.
func expectedOperationMatches(
	expectation fixtureExpectation,
	actual *generated.OperationResponse,
) bool {
	return actual != nil &&
		expectation.Operation != nil &&
		string(actual.Operation) == *expectation.Operation &&
		expectation.Result != nil &&
		string(actual.Result) == *expectation.Result &&
		expectation.Disposition != nil &&
		string(actual.Disposition) == *expectation.Disposition &&
		expectedActionsMatch(expectation.Actions, actual.Actions)
}

// expectedActionsMatch compares exact ordered generated action fields.
func expectedActionsMatch(
	expected *[]fixtureExpectedAction,
	actual generated.ActionPlan,
) bool {
	if expected == nil {
		return len(actual) == 0
	}
	if len(*expected) != len(actual) {
		return false
	}
	for index, action := range *expected {
		if action.Type != string(actual[index].Type) ||
			action.Name != string(actual[index].Name) ||
			action.Value != actual[index].Value {
			return false
		}
	}
	return true
}

// Smoke performs the generated health and readiness checks.
func (a *Application) Smoke(options Options, expectReady bool) error {
	started := time.Now()
	runtime, err := a.newRuntime(options)
	if err != nil {
		return err
	}
	defer func() { _ = runtime.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), options.Timeout)
	defer cancel()
	health, err := runtime.CallHealth(ctx)
	if err != nil {
		return err
	}
	if health.Health == nil {
		return NewExitError(ExitMismatch)
	}
	readiness, err := runtime.CallReadiness(ctx)
	if err != nil {
		return err
	}
	gotReady := readiness.Readiness != nil && readiness.Status == 200
	gotNotReady := readiness.Error != nil && readiness.Status == 503 &&
		(readiness.Error.Code == generated.ErrorResponseCodeServiceNotReady ||
			readiness.Error.Code == generated.ErrorResponseCodeServiceOverloaded)
	if gotReady != expectReady || !expectReady && !gotNotReady {
		return NewExitError(ExitMismatch)
	}
	operation := "smoke"
	bucket := DurationBucket(time.Since(started))
	return writeRecord(a.output, ResultRecord{
		Schema: outputSchema, Draft: draftVersion, Operation: &operation,
		Outcome: outcomeMatch, DurationBucket: &bucket,
	})
}
