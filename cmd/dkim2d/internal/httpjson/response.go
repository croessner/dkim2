package httpjson

import (
	"fmt"
	"io"
	"slices"
	"strconv"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app/outcome"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
)

const mappingSnapshotRedacted = "dkim2d_mapping_snapshot"
const domainProjectionRedacted = "dkim2d_domain_projection"

type verificationCheckSnapshot struct {
	class  dkim2.CheckClass
	reason dkim2.ReasonCode
}

type signatureSetSnapshot struct {
	algorithm                dkim2.Algorithm
	status                   dkim2.SignatureStatus
	reason                   dkim2.ReasonCode
	testingDeclared          bool
	strictIdentityDeclared   bool
	strictIdentityApplicable bool
}

type verificationSnapshot struct {
	state *verificationSnapshotState
}

type verificationSnapshotState struct {
	source                                  dkim2.VerifyResult
	draft                                   string
	state                                   dkim2.ResultState
	scope                                   dkim2.VerificationScope
	historicalContent, historicalSignatures dkim2.HistoricalState
	custody                                 dkim2.CustodyStructure
	primaryReason                           dkim2.ReasonCode
	targetSequence, targetInstance          uint64
	checkCount, signatureCount              int
	checks                                  []verificationCheckSnapshot
	signatures                              []signatureSetSnapshot
}

type policyFindingSnapshot struct {
	reason      dkim2.PolicyReason
	severity    dkim2.PolicyFindingSeverity
	sequence    uint64
	hasSequence bool
	valid       bool
}

type policySnapshot struct {
	state *policySnapshotState
}

type policySnapshotState struct {
	source                                   dkim2.PolicyDecision
	valid                                    bool
	verificationState                        dkim2.ResultState
	mode                                     dkim2.PolicyMode
	verdict                                  dkim2.PolicyVerdict
	primaryReason                            dkim2.PolicyReason
	doNotModify, doNotExplode                dkim2.PolicyCompliance
	dnsTestingEffective                      bool
	feedbackRequested, feedbackRelayRequired bool
	feedbackRelaySequence                    uint64
	feedbackHistory                          dkim2.PolicyHistoryCoverage
	findings                                 []policyFindingSnapshot
	actionValid                              bool
	actionKind                               dkim2.PolicyActionKind
}

type domainProjectionState struct {
	verification generated.VerificationResult
	policy       generated.PolicyResult
}

// DomainProjection owns mapped success DTOs behind a formatting-safe package boundary.
type DomainProjection struct {
	state *domainProjectionState
}

// String returns a content-free mapped-result representation.
func (DomainProjection) String() string { return domainProjectionRedacted }

// GoString returns a content-free Go-syntax representation.
func (DomainProjection) GoString() string { return domainProjectionRedacted }

// Format prevents formatting from traversing response identifiers.
func (DomainProjection) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, domainProjectionRedacted)
}

// MarshalJSON rejects serialization outside the future package-owned wire assembler.
func (DomainProjection) MarshalJSON() ([]byte, error) {
	return nil, newMappingError(MappingInternalContract)
}

// MarshalText rejects diagnostic text serialization of response identifiers.
func (DomainProjection) MarshalText() ([]byte, error) {
	return nil, newMappingError(MappingInternalContract)
}

// domainValues returns mapped DTOs only to the owning HTTP package.
func (p DomainProjection) domainValues() (generated.VerificationResult, generated.PolicyResult, bool) {
	if p.state == nil {
		return generated.VerificationResult{}, generated.PolicyResult{}, false
	}
	return cloneGeneratedVerification(p.state.verification), cloneGeneratedPolicy(p.state.policy), true
}

// cloneGeneratedVerification deep-clones every mutable generated verification field.
func cloneGeneratedVerification(input generated.VerificationResult) generated.VerificationResult {
	output := input
	output.Checks = slices.Clone(input.Checks)
	output.SignatureSets = slices.Clone(input.SignatureSets)
	if input.Target != nil {
		target := *input.Target
		output.Target = &target
	}
	return output
}

// cloneGeneratedPolicy deep-clones every mutable generated policy field.
func cloneGeneratedPolicy(input generated.PolicyResult) generated.PolicyResult {
	output := input
	output.Findings = make([]generated.PolicyFinding, len(input.Findings))
	for index, finding := range input.Findings {
		output.Findings[index] = finding
		if finding.Sequence != nil {
			sequence := *finding.Sequence
			output.Findings[index].Sequence = &sequence
		}
	}
	if input.Feedback.RelaySequence != nil {
		sequence := *input.Feedback.RelaySequence
		output.Feedback.RelaySequence = &sequence
	}
	return output
}

// String returns a content-free verification snapshot representation.
func (verificationSnapshot) String() string { return mappingSnapshotRedacted }

// GoString returns a content-free verification snapshot representation.
func (verificationSnapshot) GoString() string { return mappingSnapshotRedacted }

// Format prevents formatting from traversing verification identifiers.
func (verificationSnapshot) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, mappingSnapshotRedacted)
}

// String returns a content-free policy snapshot representation.
func (policySnapshot) String() string { return mappingSnapshotRedacted }

// GoString returns a content-free policy snapshot representation.
func (policySnapshot) GoString() string { return mappingSnapshotRedacted }

// Format prevents formatting from traversing policy identifiers.
func (policySnapshot) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, mappingSnapshotRedacted)
}

// FinalDisposition is the transport-neutral daemon outcome vocabulary.
type FinalDisposition = outcome.FinalDisposition

const (
	// FinalDispositionAccept permits normal continuation.
	FinalDispositionAccept = outcome.DispositionAccept
	// FinalDispositionReject reports permanent local rejection.
	FinalDispositionReject = outcome.DispositionReject
	// FinalDispositionTempfail requests a retryable deferral.
	FinalDispositionTempfail = outcome.DispositionTempfail
	// FinalDispositionContinue withholds a terminal daemon decision.
	FinalDispositionContinue = outcome.DispositionContinue
)

const (
	authenticationResultPass      = "pass"
	authenticationResultFail      = "fail"
	authenticationResultPermerror = "permerror"
	authenticationResultTemperror = "temperror"
)

// MapDomainResult maps one complete verification and local-policy result atomically.
func MapDomainResult(result dkim2.VerifyResult, decision dkim2.PolicyDecision) (DomainProjection, error) {
	if !result.Valid() || !decision.Valid() {
		return DomainProjection{}, newMappingError(MappingInternalContract)
	}
	verification, err := mapVerificationSnapshot(captureVerification(result))
	if err != nil {
		return DomainProjection{}, err
	}
	policy, err := mapPolicySnapshot(capturePolicy(decision), result.State())
	if err != nil {
		return DomainProjection{}, err
	}
	return DomainProjection{state: &domainProjectionState{
		verification: cloneGeneratedVerification(verification),
		policy:       cloneGeneratedPolicy(policy),
	}}, nil
}

// MapInboundResult maps one complete app result into the exact generated process response.
func MapInboundResult(
	result app.InboundResult,
	authservID string,
) (generated.ProcessResponse, error) {
	if !result.Valid() {
		return generated.ProcessResponse{}, newMappingError(MappingInternalContract)
	}
	domain, domainErr := result.Domain()
	replay, replayErr := result.Replay()
	if domainErr != nil || replayErr != nil || !replay.Valid() {
		return generated.ProcessResponse{}, newMappingError(MappingInternalContract)
	}
	verification, verificationErr := domain.Verification()
	policy, policyErr := domain.Policy()
	if verificationErr != nil || policyErr != nil {
		return generated.ProcessResponse{}, newMappingError(MappingInternalContract)
	}
	projection, err := MapDomainResult(verification, policy)
	if err != nil {
		return generated.ProcessResponse{}, err
	}
	verificationDTO, policyDTO, ok := projection.domainValues()
	replayClass, replayOK := mapReplayClass(replay.Class())
	disposition, dispositionOK := mapDisposition(replay.Disposition())
	if !ok || !replayOK || !dispositionOK {
		return generated.ProcessResponse{}, newMappingError(MappingInternalContract)
	}
	actions, actionsErr := mapProcessReportActions(
		verificationDTO.State,
		disposition,
		authservID,
	)
	if actionsErr != nil {
		return generated.ProcessResponse{}, actionsErr
	}
	return generated.ProcessResponse{
		ApiVersion:   generated.V1,
		Draft:        generated.DraftIetfDkimDkim2Spec05,
		Verification: verificationDTO,
		Policy:       policyDTO,
		Replay:       generated.ReplayResult{Class: replayClass},
		Disposition:  disposition,
		Actions:      actions,
	}, nil
}

// mapProcessReportActions constructs the daemon-owned RFC 8601 mutation plan.
func mapProcessReportActions(
	state generated.VerificationState,
	disposition generated.Disposition,
	authservID string,
) (generated.ActionPlan, error) {
	if authservID == "" ||
		(disposition != generated.DispositionAccept &&
			disposition != generated.DispositionContinue) {
		return generated.ActionPlan{}, nil
	}
	reportResult, resultOK := authenticationResult(state)
	if !validSigningDomain(authservID) || !resultOK {
		return nil, newMappingError(MappingInternalContract)
	}
	return generated.ActionPlan{{
		Type: generated.AddHeader, Name: generated.AuthenticationResults,
		Value: authservID + "; dkim2=" + reportResult,
	}}, nil
}

// authenticationResult maps the closed verification vocabulary to RFC 8601.
func authenticationResult(state generated.VerificationState) (string, bool) {
	switch state {
	case generated.PASS:
		return authenticationResultPass, true
	case generated.FAIL:
		return authenticationResultFail, true
	case generated.PERMERROR:
		return authenticationResultPermerror, true
	case generated.TEMPERROR:
		return authenticationResultTemperror, true
	default:
		return "", false
	}
}

// mapReplayClass maps the privacy-minimal app aggregate without provider detail.
func mapReplayClass(value app.ReplayResultClass) (generated.ReplayResultClass, bool) {
	switch value {
	case app.ReplayResultNotChecked:
		return generated.NotChecked, true
	case app.ReplayResultDisabled:
		return generated.Disabled, true
	case app.ReplayResultFirstSeen:
		return generated.FirstSeen, true
	case app.ReplayResultReplayed:
		return generated.Replayed, true
	case app.ReplayResultIndeterminate:
		return generated.Indeterminate, true
	default:
		return "", false
	}
}

// captureVerification binds bounded mapper scalars to one sealed public result.
func captureVerification(result dkim2.VerifyResult) verificationSnapshot {
	checks := result.Checks()
	checkSnapshots := make([]verificationCheckSnapshot, len(checks))
	for index, check := range checks {
		checkSnapshots[index] = verificationCheckSnapshot{class: check.Class(), reason: check.Reason()}
	}
	signatures := result.SignatureSets()
	signatureSnapshots := make([]signatureSetSnapshot, len(signatures))
	for index, signature := range signatures {
		metadata := signature.KeyPolicyMetadata()
		signatureSnapshots[index] = signatureSetSnapshot{
			algorithm:                signature.Algorithm(),
			status:                   signature.Status(),
			reason:                   signature.Reason(),
			testingDeclared:          metadata.TestingDeclared(),
			strictIdentityDeclared:   metadata.StrictIdentityDeclared(),
			strictIdentityApplicable: metadata.StrictIdentityApplicable(),
		}
	}
	target := result.Target()
	return verificationSnapshot{state: &verificationSnapshotState{
		source: result, draft: result.Draft(), state: result.State(), scope: result.Scope(),
		historicalContent: result.HistoricalContent(), historicalSignatures: result.HistoricalSignatures(),
		custody: result.CustodyStructure(), primaryReason: result.PrimaryReason(),
		targetSequence: target.Sequence(), targetInstance: target.Instance(),
		checkCount: result.CheckCount(), signatureCount: result.SignatureSetCount(),
		checks: checkSnapshots, signatures: signatureSnapshots,
	}}
}

// capturePolicy binds bounded mapper scalars to one sealed public decision.
func capturePolicy(decision dkim2.PolicyDecision) policySnapshot {
	feedback := decision.FeedbackIntent()
	findings := decision.Findings()
	findingSnapshots := make([]policyFindingSnapshot, len(findings))
	for index, finding := range findings {
		sequence, present := finding.Sequence()
		findingSnapshots[index] = policyFindingSnapshot{
			reason: finding.Reason(), severity: finding.Severity(),
			sequence: sequence, hasSequence: present, valid: finding.Valid(),
		}
	}
	actions := decision.ActionPlan()
	actionValues := actions.Actions()
	var actionKind dkim2.PolicyActionKind
	if len(actionValues) == 1 {
		actionKind = actionValues[0].Kind()
	}
	return policySnapshot{state: &policySnapshotState{
		source: decision, valid: decision.Valid(), verificationState: decision.VerificationState(),
		mode: decision.Mode(), verdict: decision.Verdict(), primaryReason: decision.PrimaryReason(),
		doNotModify: decision.DoNotModifyCompliance(), doNotExplode: decision.DoNotExplodeCompliance(),
		dnsTestingEffective: decision.DNSTestingEffective(),
		feedbackRequested:   feedback.Requested(), feedbackRelayRequired: feedback.RelayRequired(),
		feedbackRelaySequence: feedback.RelaySequence(), feedbackHistory: feedback.HistoryCoverage(),
		findings: findingSnapshots, actionValid: actions.Valid() && len(actionValues) == 1 && actionValues[0].Valid(),
		actionKind: actionKind,
	}}
}

// mapVerificationSnapshot validates and maps one mapper-owned immutable view.
func mapVerificationSnapshot(input verificationSnapshot) (generated.VerificationResult, error) {
	if input.state == nil {
		return generated.VerificationResult{}, newMappingError(MappingInternalContract)
	}
	view := input.state
	state, stateOK := mapVerificationState(view.state)
	scope, scopeOK := mapVerificationScope(view.scope)
	historicalContent, contentOK := mapHistoricalContent(view.historicalContent)
	historicalSignatures, signaturesHistoryOK := mapHistoricalSignatures(view.historicalSignatures)
	custody, custodyOK := mapCustodyStructure(view.custody)
	primaryReason, reasonOK := mapVerificationReason(view.primaryReason)
	if view.draft != dkim2.DraftIdentifier || !stateOK || !scopeOK || !contentOK ||
		!signaturesHistoryOK || !custodyOK || !reasonOK ||
		view.checkCount != len(view.checks) || view.signatureCount != len(view.signatures) ||
		len(view.checks) == 0 || len(view.checks) > dkim2.HardMaxCheckFacts ||
		len(view.signatures) > dkim2.HardMaxSignatureFacts ||
		!verificationSnapshotMatchesSource(input) ||
		(view.targetSequence == 0) != (view.targetInstance == 0) {
		return generated.VerificationResult{}, newMappingError(MappingInternalContract)
	}

	checks := make([]generated.VerificationCheck, len(view.checks))
	for index, fact := range view.checks {
		class, classOK := mapCheckClass(fact.class)
		reason, factReasonOK := mapVerificationReason(fact.reason)
		if !classOK || !factReasonOK {
			return generated.VerificationResult{}, newMappingError(MappingInternalContract)
		}
		checks[index] = generated.VerificationCheck{Class: class, Reason: reason}
	}
	signatureSets := make([]generated.SignatureSetResult, len(view.signatures))
	for index, fact := range view.signatures {
		algorithm, algorithmOK := mapAlgorithm(fact.algorithm)
		status, statusOK := mapSignatureStatus(fact.status)
		reason, factReasonOK := mapVerificationReason(fact.reason)
		applicable, applicableOK := mapStrictIdentityApplicable(fact.strictIdentityApplicable)
		if !algorithmOK || !statusOK || !factReasonOK || !applicableOK {
			return generated.VerificationResult{}, newMappingError(MappingInternalContract)
		}
		signatureSets[index] = generated.SignatureSetResult{
			Algorithm: algorithm,
			Status:    status,
			Reason:    reason,
			KeyPolicy: generated.KeyPolicyResult{
				TestingDeclared:          fact.testingDeclared,
				StrictIdentityDeclared:   fact.strictIdentityDeclared,
				StrictIdentityApplicable: applicable,
			},
		}
	}

	var target *generated.VerificationTarget
	if view.targetSequence > 0 {
		sequence, _ := mapCanonicalUint64(view.targetSequence)
		instance, _ := mapCanonicalUint64(view.targetInstance)
		target = &generated.VerificationTarget{
			Sequence: sequence,
			Instance: instance,
		}
	}
	return generated.VerificationResult{
		State: state, PrimaryReason: primaryReason, Scope: scope,
		HistoricalContent: historicalContent, HistoricalSignatures: historicalSignatures,
		CustodyStructure: custody, Target: target, Checks: checks, SignatureSets: signatureSets,
	}, nil
}

// verificationSnapshotMatchesSource rejects views that diverge from their sealed source.
func verificationSnapshotMatchesSource(input verificationSnapshot) bool {
	if input.state == nil || !input.state.source.Valid() {
		return false
	}
	expected := captureVerification(input.state.source)
	want := expected.state
	return want != nil &&
		input.state.draft == want.draft &&
		input.state.state == want.state &&
		input.state.scope == want.scope &&
		input.state.historicalContent == want.historicalContent &&
		input.state.historicalSignatures == want.historicalSignatures &&
		input.state.custody == want.custody &&
		input.state.primaryReason == want.primaryReason &&
		input.state.targetSequence == want.targetSequence &&
		input.state.targetInstance == want.targetInstance &&
		input.state.checkCount == want.checkCount &&
		input.state.signatureCount == want.signatureCount &&
		slices.Equal(input.state.checks, want.checks) &&
		slices.Equal(input.state.signatures, want.signatures)
}

// mapPolicySnapshot validates and maps one mapper-owned local-policy view.
func mapPolicySnapshot(input policySnapshot, verificationState dkim2.ResultState) (
	generated.PolicyResult,
	error,
) {
	if input.state == nil {
		return generated.PolicyResult{}, newMappingError(MappingInternalContract)
	}
	view := input.state
	mode, modeOK := mapPolicyMode(view.mode)
	verdict, verdictOK := mapPolicyVerdict(view.verdict)
	primaryReason, reasonOK := mapPolicyReason(view.primaryReason)
	modify, modifyOK := mapDoNotModify(view.doNotModify)
	explode, explodeOK := mapDoNotExplode(view.doNotExplode)
	history, historyOK := mapPolicyHistoryCoverage(view.feedbackHistory)
	if !view.valid || view.verificationState != verificationState ||
		!modeOK || !verdictOK || !reasonOK || !modifyOK || !explodeOK || !historyOK ||
		len(view.findings) == 0 || len(view.findings) > dkim2.HardMaxPolicyFindings ||
		!view.actionValid || dkim2.PolicyVerdict(view.actionKind) != view.verdict ||
		!feedbackCoherent(input) || !policySnapshotMatchesSource(input) {
		return generated.PolicyResult{}, newMappingError(MappingInternalContract)
	}

	findings := make([]generated.PolicyFinding, len(view.findings))
	for index, finding := range view.findings {
		reason, findingReasonOK := mapPolicyReason(finding.reason)
		severity, severityOK := mapPolicyFindingSeverity(finding.severity)
		if !finding.valid || !findingReasonOK || !severityOK ||
			finding.hasSequence != (finding.sequence > 0) {
			return generated.PolicyResult{}, newMappingError(MappingInternalContract)
		}
		var sequence *generated.CanonicalUint64
		if finding.hasSequence {
			value, _ := mapCanonicalUint64(finding.sequence)
			sequence = &value
		}
		findings[index] = generated.PolicyFinding{Reason: reason, Severity: severity, Sequence: sequence}
	}

	var relaySequence *generated.CanonicalUint64
	if view.feedbackRelayRequired {
		value, _ := mapCanonicalUint64(view.feedbackRelaySequence)
		relaySequence = &value
	}
	return generated.PolicyResult{
		Mode: mode, Verdict: verdict, PrimaryReason: primaryReason,
		DoNotModify: modify, DoNotExplode: explode, DnsTestingEffective: view.dnsTestingEffective,
		Feedback: generated.PolicyFeedback{
			Requested: view.feedbackRequested, RelayRequired: view.feedbackRelayRequired,
			RelaySequence: relaySequence, HistoryCoverage: history,
		},
		Findings: findings,
	}, nil
}

// policySnapshotMatchesSource rejects views that diverge from their sealed source.
func policySnapshotMatchesSource(input policySnapshot) bool {
	if input.state == nil || !input.state.source.Valid() {
		return false
	}
	expected := capturePolicy(input.state.source)
	want := expected.state
	return want != nil &&
		input.state.valid == want.valid &&
		input.state.verificationState == want.verificationState &&
		input.state.mode == want.mode &&
		input.state.verdict == want.verdict &&
		input.state.primaryReason == want.primaryReason &&
		input.state.doNotModify == want.doNotModify &&
		input.state.doNotExplode == want.doNotExplode &&
		input.state.dnsTestingEffective == want.dnsTestingEffective &&
		input.state.feedbackRequested == want.feedbackRequested &&
		input.state.feedbackRelayRequired == want.feedbackRelayRequired &&
		input.state.feedbackRelaySequence == want.feedbackRelaySequence &&
		input.state.feedbackHistory == want.feedbackHistory &&
		input.state.actionValid == want.actionValid &&
		input.state.actionKind == want.actionKind &&
		slices.Equal(input.state.findings, want.findings)
}

// feedbackCoherent enforces the exact relay optional-field invariant.
func feedbackCoherent(input policySnapshot) bool {
	if input.state == nil {
		return false
	}
	return input.state.feedbackRelayRequired && input.state.feedbackRequested && input.state.feedbackRelaySequence > 0 ||
		!input.state.feedbackRelayRequired && input.state.feedbackRelaySequence == 0
}

// mapVerificationState maps the closed four-state vocabulary.
func mapVerificationState(value dkim2.ResultState) (generated.VerificationState, bool) {
	switch value {
	case dkim2.ResultStatePASS:
		return generated.PASS, true
	case dkim2.ResultStateFAIL:
		return generated.FAIL, true
	case dkim2.ResultStatePERMERROR:
		return generated.PERMERROR, true
	case dkim2.ResultStateTEMPERROR:
		return generated.TEMPERROR, true
	default:
		return "", false
	}
}

// mapVerificationReason maps only reasons reachable in verification results.
func mapVerificationReason(value dkim2.ReasonCode) (generated.VerificationReason, bool) {
	switch value {
	case dkim2.ReasonNone:
		return generated.VerificationReasonNone, true
	case dkim2.ReasonLimitExceeded:
		return generated.VerificationReasonLimitExceeded, true
	case dkim2.ReasonMalformedMessage:
		return generated.VerificationReasonMalformedMessage, true
	case dkim2.ReasonMalformedProtocol:
		return generated.VerificationReasonMalformedProtocol, true
	case dkim2.ReasonDuplicateHashAlgorithm:
		return generated.VerificationReasonDuplicateHashAlgorithm, true
	case dkim2.ReasonInvalidRecipeJSON:
		return generated.VerificationReasonInvalidRecipeJson, true
	case dkim2.ReasonDuplicateSelector:
		return generated.VerificationReasonDuplicateSelector, true
	case dkim2.ReasonTooManySignatures:
		return generated.VerificationReasonTooManySignatures, true
	case dkim2.ReasonMissingProtocol:
		return generated.VerificationReasonMissingProtocol, true
	case dkim2.ReasonSequenceInvalid:
		return generated.VerificationReasonSequenceInvalid, true
	case dkim2.ReasonUnsupportedAlgorithm:
		return generated.VerificationReasonUnsupportedAlgorithm, true
	case dkim2.ReasonHashMismatch:
		return generated.VerificationReasonHashMismatch, true
	case dkim2.ReasonSignatureMismatch:
		return generated.VerificationReasonSignatureMismatch, true
	case dkim2.ReasonMissingKey:
		return generated.VerificationReasonMissingKey, true
	case dkim2.ReasonInvalidKey:
		return generated.VerificationReasonInvalidKey, true
	case dkim2.ReasonAmbiguousKey:
		return generated.VerificationReasonAmbiguousKey, true
	case dkim2.ReasonRevokedKey:
		return generated.VerificationReasonRevokedKey, true
	case dkim2.ReasonUnsupportedKeyType:
		return generated.VerificationReasonUnsupportedKeyType, true
	case dkim2.ReasonKeyAlgorithmMismatch:
		return generated.VerificationReasonKeyAlgorithmMismatch, true
	case dkim2.ReasonProviderTemporary:
		return generated.VerificationReasonProviderTemporary, true
	case dkim2.ReasonProviderPermanent:
		return generated.VerificationReasonProviderPermanent, true
	case dkim2.ReasonProviderContract:
		return generated.VerificationReasonProviderContract, true
	case dkim2.ReasonTimestampInvalid:
		return generated.VerificationReasonTimestampInvalid, true
	case dkim2.ReasonEnvelopeMismatch:
		return generated.VerificationReasonEnvelopeMismatch, true
	case dkim2.ReasonDomainAlignmentMismatch:
		return generated.VerificationReasonDomainAlignmentMismatch, true
	case dkim2.ReasonNextDomainMismatch:
		return generated.VerificationReasonNextDomainMismatch, true
	case dkim2.ReasonOutOfBandRequired:
		return generated.VerificationReasonOutOfBandRequired, true
	case dkim2.ReasonInternalContract:
		return generated.VerificationReasonInternalContract, true
	default:
		return "", false
	}
}

// mapVerificationScope maps current diagnostic and authenticated-chain scope.
func mapVerificationScope(value dkim2.VerificationScope) (generated.VerificationResultScope, bool) {
	switch value {
	case dkim2.VerificationScopeCurrent:
		return generated.Current, true
	case dkim2.VerificationScopeChain:
		return generated.Chain, true
	default:
		return "", false
	}
}

// mapHistoricalContent maps authenticated content-history coverage.
func mapHistoricalContent(value dkim2.HistoricalState) (generated.VerificationResultHistoricalContent, bool) {
	switch value {
	case dkim2.HistoricalStateNotEvaluated:
		return generated.VerificationResultHistoricalContentNotEvaluated, true
	case dkim2.HistoricalStateComplete:
		return generated.VerificationResultHistoricalContentComplete, true
	case dkim2.HistoricalStatePartial:
		return generated.VerificationResultHistoricalContentPartial, true
	default:
		return "", false
	}
}

// mapHistoricalSignatures maps authenticated signature-history coverage.
func mapHistoricalSignatures(value dkim2.HistoricalState) (generated.VerificationResultHistoricalSignatures, bool) {
	switch value {
	case dkim2.HistoricalStateNotEvaluated:
		return generated.VerificationResultHistoricalSignaturesNotEvaluated, true
	case dkim2.HistoricalStateComplete:
		return generated.VerificationResultHistoricalSignaturesComplete, true
	default:
		return "", false
	}
}

// mapCustodyStructure maps the structural next-domain vocabulary.
func mapCustodyStructure(value dkim2.CustodyStructure) (generated.VerificationResultCustodyStructure, bool) {
	switch value {
	case dkim2.CustodyStructureNotEvaluated:
		return generated.VerificationResultCustodyStructureNotEvaluated, true
	case dkim2.CustodyStructureNotPresent:
		return generated.VerificationResultCustodyStructureNotPresent, true
	case dkim2.CustodyStructureNDLinksEvaluated:
		return generated.VerificationResultCustodyStructureNdLinksEvaluated, true
	case dkim2.CustodyStructureTerminalNDRequiresOOB:
		return generated.VerificationResultCustodyStructureTerminalNdRequiresOob, true
	default:
		return "", false
	}
}

// mapCheckClass maps the closed verification check vocabulary.
func mapCheckClass(value dkim2.CheckClass) (generated.VerificationCheckClass, bool) {
	switch value {
	case dkim2.CheckClassMessage:
		return generated.VerificationCheckClassMessage, true
	case dkim2.CheckClassProtocol:
		return generated.VerificationCheckClassProtocol, true
	case dkim2.CheckClassBodyHash:
		return generated.VerificationCheckClassBodyHash, true
	case dkim2.CheckClassHeaderHash:
		return generated.VerificationCheckClassHeaderHash, true
	case dkim2.CheckClassSignature:
		return generated.VerificationCheckClassSignature, true
	case dkim2.CheckClassKey:
		return generated.VerificationCheckClassKey, true
	case dkim2.CheckClassTimestamp:
		return generated.VerificationCheckClassTimestamp, true
	case dkim2.CheckClassEnvelope:
		return generated.VerificationCheckClassEnvelope, true
	case dkim2.CheckClassDomainAlignment:
		return generated.VerificationCheckClassDomainAlignment, true
	case dkim2.CheckClassNextDomain:
		return generated.VerificationCheckClassNextDomain, true
	case dkim2.CheckClassProvider:
		return generated.VerificationCheckClassProvider, true
	case dkim2.CheckClassInternalContract:
		return generated.VerificationCheckClassInternalContract, true
	default:
		return "", false
	}
}

// mapAlgorithm maps the bounded signature algorithm family.
func mapAlgorithm(value dkim2.Algorithm) (generated.SignatureSetResultAlgorithm, bool) {
	switch value {
	case dkim2.AlgorithmRSASHA256:
		return generated.RsaSha256, true
	case dkim2.AlgorithmEd25519SHA256:
		return generated.Ed25519Sha256, true
	case dkim2.AlgorithmUnknown:
		return generated.Unknown, true
	default:
		return "", false
	}
}

// mapSignatureStatus maps the closed per-signature status.
func mapSignatureStatus(value dkim2.SignatureStatus) (generated.SignatureSetResultStatus, bool) {
	switch value {
	case dkim2.SignatureStatusPASS:
		return generated.SignatureSetResultStatusPass, true
	case dkim2.SignatureStatusFAIL:
		return generated.SignatureSetResultStatusFail, true
	case dkim2.SignatureStatusPERMERROR:
		return generated.SignatureSetResultStatusPermerror, true
	case dkim2.SignatureStatusTEMPERROR:
		return generated.SignatureSetResultStatusTemperror, true
	case dkim2.SignatureStatusIgnored:
		return generated.SignatureSetResultStatusIgnored, true
	default:
		return "", false
	}
}

// mapPolicyMode maps the server-owned local policy selection.
func mapPolicyMode(value dkim2.PolicyMode) (generated.PolicyResultMode, bool) {
	switch value {
	case dkim2.PolicyModeStrict:
		return generated.Strict, true
	case dkim2.PolicyModePermissive:
		return generated.Permissive, true
	case dkim2.PolicyModeTesting:
		return generated.Testing, true
	default:
		return "", false
	}
}

// mapPolicyVerdict maps the closed local policy verdict.
func mapPolicyVerdict(value dkim2.PolicyVerdict) (generated.PolicyResultVerdict, bool) {
	switch value {
	case dkim2.PolicyVerdictAccept:
		return generated.PolicyResultVerdictAccept, true
	case dkim2.PolicyVerdictReject:
		return generated.PolicyResultVerdictReject, true
	case dkim2.PolicyVerdictTempfail:
		return generated.PolicyResultVerdictTempfail, true
	case dkim2.PolicyVerdictContinue:
		return generated.PolicyResultVerdictContinue, true
	default:
		return "", false
	}
}

// mapDisposition maps the daemon outcome without conflating it with policy verdict.
func mapDisposition(value FinalDisposition) (generated.Disposition, bool) {
	switch value {
	case FinalDispositionAccept:
		return generated.DispositionAccept, true
	case FinalDispositionReject:
		return generated.DispositionReject, true
	case FinalDispositionTempfail:
		return generated.DispositionTempfail, true
	case FinalDispositionContinue:
		return generated.DispositionContinue, true
	default:
		return "", false
	}
}

// mapHistoricalState maps the shared singleton into the content-history generated type.
func mapHistoricalState(value dkim2.HistoricalState) (generated.VerificationResultHistoricalContent, bool) {
	return mapHistoricalContent(value)
}

// mapStrictIdentityApplicable maps the Draft-05 singleton false invariant.
func mapStrictIdentityApplicable(value bool) (generated.KeyPolicyResultStrictIdentityApplicable, bool) {
	if value {
		return false, false
	}
	return generated.False, true
}

// mapCanonicalUint64 renders one positive identifier without JSON numeric loss.
func mapCanonicalUint64(value uint64) (generated.CanonicalUint64, bool) {
	if value == 0 {
		return "", false
	}
	return strconv.FormatUint(value, 10), true
}

// mapPolicyReason maps every reachable decision and finding reason.
func mapPolicyReason(value dkim2.PolicyReason) (generated.PolicyReason, bool) {
	switch value {
	case dkim2.PolicyReasonProtocolPass:
		return generated.ProtocolPass, true
	case dkim2.PolicyReasonProtocolFail:
		return generated.ProtocolFail, true
	case dkim2.PolicyReasonProtocolPermerror:
		return generated.ProtocolPermerror, true
	case dkim2.PolicyReasonProtocolTemperror:
		return generated.ProtocolTemperror, true
	case dkim2.PolicyReasonPermissiveOverride:
		return generated.PermissiveOverride, true
	case dkim2.PolicyReasonTestingModeObserve:
		return generated.TestingModeObserve, true
	case dkim2.PolicyReasonDNSTestingEffective:
		return generated.DnsTestingEffective, true
	case dkim2.PolicyReasonDNSTestingMixed:
		return generated.DnsTestingMixed, true
	case dkim2.PolicyReasonDNSTestingIneligible:
		return generated.DnsTestingIneligible, true
	case dkim2.PolicyReasonDoNotModifyIndeterminate:
		return generated.DonotmodifyIndeterminate, true
	case dkim2.PolicyReasonDoNotModifyNotEvaluated:
		return generated.DonotmodifyNotEvaluated, true
	case dkim2.PolicyReasonDoNotExplodeViolated:
		return generated.DonotexplodeViolated, true
	case dkim2.PolicyReasonDoNotExplodeIndeterminate:
		return generated.DonotexplodeIndeterminate, true
	case dkim2.PolicyReasonDoNotExplodeNotEvaluated:
		return generated.DonotexplodeNotEvaluated, true
	case dkim2.PolicyReasonFeedbackRequested:
		return generated.FeedbackRequested, true
	case dkim2.PolicyReasonFeedbackRelaySelected:
		return generated.FeedbackRelaySelected, true
	case dkim2.PolicyReasonFeedHereInert:
		return generated.FeedhereInert, true
	case dkim2.PolicyReasonExplodedReported:
		return generated.ExplodedReported, true
	default:
		return "", false
	}
}

// mapDoNotModify maps every reachable modification-compliance state.
func mapDoNotModify(value dkim2.PolicyCompliance) (generated.PolicyResultDoNotModify, bool) {
	switch value {
	case dkim2.PolicyComplianceNotRequested:
		return generated.PolicyResultDoNotModifyNotRequested, true
	case dkim2.PolicyComplianceIndeterminate:
		return generated.PolicyResultDoNotModifyIndeterminate, true
	case dkim2.PolicyComplianceNotEvaluated:
		return generated.PolicyResultDoNotModifyNotEvaluated, true
	default:
		return "", false
	}
}

// mapDoNotExplode maps every reachable explosion-compliance state.
func mapDoNotExplode(value dkim2.PolicyCompliance) (generated.PolicyResultDoNotExplode, bool) {
	switch value {
	case dkim2.PolicyComplianceNotRequested:
		return generated.PolicyResultDoNotExplodeNotRequested, true
	case dkim2.PolicyComplianceViolated:
		return generated.PolicyResultDoNotExplodeViolated, true
	case dkim2.PolicyComplianceIndeterminate:
		return generated.PolicyResultDoNotExplodeIndeterminate, true
	case dkim2.PolicyComplianceNotEvaluated:
		return generated.PolicyResultDoNotExplodeNotEvaluated, true
	default:
		return "", false
	}
}

// mapPolicyHistoryCoverage maps explicit authenticated feedback-history coverage.
func mapPolicyHistoryCoverage(value dkim2.PolicyHistoryCoverage) (generated.PolicyFeedbackHistoryCoverage, bool) {
	switch value {
	case dkim2.PolicyHistoryComplete:
		return generated.PolicyFeedbackHistoryCoverageComplete, true
	case dkim2.PolicyHistoryIndeterminate:
		return generated.PolicyFeedbackHistoryCoverageIndeterminate, true
	case dkim2.PolicyHistoryNotEvaluated:
		return generated.PolicyFeedbackHistoryCoverageNotEvaluated, true
	default:
		return "", false
	}
}

// mapPolicyFindingSeverity maps the closed finding severity.
func mapPolicyFindingSeverity(value dkim2.PolicyFindingSeverity) (generated.PolicyFindingSeverity, bool) {
	switch value {
	case dkim2.PolicySeverityInfo:
		return generated.Info, true
	case dkim2.PolicySeverityWarning:
		return generated.Warning, true
	case dkim2.PolicySeverityPermanent:
		return generated.Permanent, true
	case dkim2.PolicySeverityTemporary:
		return generated.Temporary, true
	default:
		return "", false
	}
}
