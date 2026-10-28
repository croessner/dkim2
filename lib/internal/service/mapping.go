package service

import (
	"slices"

	"github.com/croessner/dkim2/internal/combine"
	"github.com/croessner/dkim2/internal/policy"
	"github.com/croessner/dkim2/internal/verify"
)

type outcomeSeverity uint8

const (
	severityPass outcomeSeverity = iota
	severityTemporary
	severityFailure
	severityPermanent
)

type mappingAccumulator struct {
	severity           outcomeSeverity
	reason             Reason
	checks             []CheckFact
	signatures         []SignatureSetFact
	completeSignatures []SignatureSetFact
	required           map[verify.CheckKind]bool
	setIndices         [hardMaxSignatureFacts]bool
	signatureChecks    map[Algorithm]int
	signatureSets      map[Algorithm]int
	supportedPass      int
	maxChecks          int
	maxSignatures      int
	hardOverflow       bool
	target             verify.Target
	envelopeStatus     verify.EnvelopeStatus
	alignmentStatus    verify.DomainAlignmentStatus
	nextDomainStatus   verify.NextDomainStatus
	locallyDisabled    bool
}

// mapVerificationResult centrally maps protocol facts into the four-state service contract.
func mapVerificationResult(input verify.Result, limits Limits) Result {
	target := Target{Sequence: input.Target().Sequence, Instance: input.Target().InstanceNumber}
	if err := limits.Validate(); err != nil {
		return internalContractResult(target)
	}
	checks := input.Checks()
	// Facts are mapped in field order so per-set reporting and the sealed
	// policy facts line up with the parsed sig-any/sig-all layout.
	sets := input.SignatureSets()
	slices.SortStableFunc(sets, func(left, right verify.SignatureSetResult) int { return left.Index - right.Index })
	accumulator := mappingAccumulator{
		reason:             ReasonNone,
		checks:             make([]CheckFact, 0, min(len(checks), limits.MaxCheckFacts)),
		signatures:         make([]SignatureSetFact, 0, min(len(sets), limits.MaxSignatureFacts)),
		completeSignatures: make([]SignatureSetFact, 0, min(len(sets), hardMaxSignatureFacts)),
		required:           make(map[verify.CheckKind]bool, 7),
		signatureChecks:    make(map[Algorithm]int, 3),
		signatureSets:      make(map[Algorithm]int, 3),
		maxChecks:          limits.MaxCheckFacts,
		maxSignatures:      limits.MaxSignatureFacts,
		target:             input.Target(),
		hardOverflow:       len(checks) > DefaultLimits().MaxCheckFacts || len(sets) > hardMaxSignatureFacts,
	}
	if inputContractDefect(checks, sets, input.Target()) {
		accumulator.add(severityPermanent, ReasonInternalContract)
	}
	if target.Sequence == 0 || target.Instance == 0 {
		accumulator.add(severityPermanent, ReasonInternalContract)
	}
	if !input.Status().Known() || input.Status() == verify.TargetStatusNotEvaluated || input.Status() == verify.TargetStatusUnknown {
		accumulator.add(severityPermanent, ReasonInternalContract)
	}

	for _, check := range checks {
		accumulator.mapCheck(check)
	}
	for _, set := range sets {
		accumulator.mapSignatureSet(set)
	}
	accumulator.applySignatureCombination(input.SignatureLayout(), sets)
	accumulator.requireCompleteCurrentChecks()
	if len(sets) <= hardMaxSignatureFacts {
		accumulator.requireContiguousSetIndices(len(sets))
	}

	custody := mapCustody(input.CustodyStatus())
	if custody == CustodyNotEvaluated {
		accumulator.add(severityPermanent, ReasonInternalContract)
	}
	if custody == CustodyTerminalNDRequiresOOB {
		accumulator.add(severityFor(ReasonOutOfBandRequired), ReasonOutOfBandRequired)
	}
	accumulator.enforceCustodyCoherence(custody)
	if accumulator.supportedPass == 0 && accumulator.severity < severityTemporary {
		accumulator.add(severityPermanent, ReasonUnsupportedAlgorithm)
	}
	accumulator.enforceTargetStatus(input.Status())
	if accumulator.hardOverflow {
		accumulator.add(severityPermanent, ReasonLimitExceeded)
	}

	slices.SortFunc(accumulator.checks, compareCheckFacts)
	result := newResult(stateForSeverity(accumulator.severity), custody, target, accumulator.reason, accumulator.checks, accumulator.signatures)
	if accumulator.locallyDisabled {
		result = result.withLocallyDisabledAlgorithm()
	}
	if len(accumulator.completeSignatures) > hardMaxSignatureFacts {
		return result
	}
	var replayProjection ReplayProjection
	hasReplayProjection := false
	if source, ok := input.ReplayProjection(); ok && result.state == StatePASS {
		if projection, mapped := mapReplayProjection(source); mapped {
			replayProjection = projection
			hasReplayProjection = true
		}
	}
	projection, err := buildSelectedPolicyProjection(result.state, result.primaryReason, target, input, accumulator.completeSignatures)
	if err != nil {
		return result
	}
	result = result.withPolicyProjection(projection)
	if hasReplayProjection && result.policyProjection.Valid() {
		result = result.withReplayProjection(replayProjection)
	}
	return result
}

// enforceTargetStatus rejects inconsistent aggregate and target-state combinations.
func (a *mappingAccumulator) enforceTargetStatus(status verify.TargetStatus) {
	switch status {
	case verify.TargetStatusPass:
		if a.severity != severityPass || a.supportedPass == 0 {
			a.add(severityPermanent, ReasonInternalContract)
		}
	case verify.TargetStatusFail, verify.TargetStatusMixed:
		if a.severity < severityFailure {
			a.add(severityPermanent, ReasonInternalContract)
		}
	case verify.TargetStatusUnsupported:
		if a.severity != severityPermanent {
			a.add(severityPermanent, ReasonInternalContract)
		}
	case verify.TargetStatusIndeterminate:
		if a.severity != severityTemporary && a.severity != severityPermanent {
			a.add(severityPermanent, ReasonInternalContract)
		}
	case verify.TargetStatusNotEvaluated, verify.TargetStatusUnknown:
		a.add(severityPermanent, ReasonInternalContract)
	default:
		a.add(severityPermanent, ReasonInternalContract)
	}
}

// inputContractDefect scans all supplied facts without input-sized allocation.
func inputContractDefect(checks []verify.CheckResult, sets []verify.SignatureSetResult, target verify.Target) bool {
	for _, check := range checks {
		if check.Target != target || target.Sequence == 0 || target.InstanceNumber == 0 || !checkShapeKnown(check) {
			return true
		}
	}
	for _, set := range sets {
		if _, known := mapAlgorithm(set.Algorithm); !known || !set.Status.Known() || !set.KeyStatus.Known() || set.Index < 0 || !signatureKeyPairValid(set.Status, set.KeyStatus) || !signatureAlgorithmCoherent(set.Algorithm, set.Status) {
			return true
		}
	}
	return boundedSetIndexDefect(sets)
}

// boundedSetIndexDefect validates zero-origin indices with fixed hard-bound storage.
func boundedSetIndexDefect(sets []verify.SignatureSetResult) bool {
	var seen [hardMaxSignatureFacts]bool
	for _, set := range sets {
		if set.Index >= hardMaxSignatureFacts {
			if len(sets) <= hardMaxSignatureFacts {
				return true
			}
			continue
		}
		if set.Index < 0 || seen[set.Index] {
			return true
		}
		seen[set.Index] = true
	}
	if len(sets) <= hardMaxSignatureFacts {
		for index := range sets {
			if !seen[index] {
				return true
			}
		}
	}
	return false
}

// signatureAlgorithmCoherent restricts unknown algorithms to unsupported-algorithm set results.
func signatureAlgorithmCoherent(algorithm verify.Algorithm, status verify.SignatureSetStatus) bool {
	if algorithm == verify.AlgorithmUnknown {
		return status == verify.SignatureSetStatusUnsupportedAlgorithm
	}
	return supportedAlgorithm(algorithm) && status != verify.SignatureSetStatusUnsupportedAlgorithm
}

// checkShapeKnown validates closed typed dimensions without aggregating facts.
func checkShapeKnown(check verify.CheckResult) bool {
	if _, known := mapCheckClass(check.Kind); !known || !check.Status.Known() || !knownErrorCode(check.Code) {
		return false
	}
	if check.Code == verify.ErrorCodeProviderError {
		if check.ProviderFailureClass != "" && !check.ProviderFailureClass.Known() {
			return false
		}
	} else if check.ProviderFailureClass != "" {
		return false
	}
	switch check.Kind {
	case verify.CheckKindBodyHash, verify.CheckKindHeaderHash:
		return check.HashStatus.Known()
	case verify.CheckKindSignature:
		return knownAlgorithm(check.Algorithm)
	case verify.CheckKindTimestamp:
		return check.TimestampStatus.Known()
	case verify.CheckKindEnvelope:
		return check.EnvelopeStatus.Known()
	case verify.CheckKindDomainAlignment:
		return check.DomainAlignmentStatus.Known()
	case verify.CheckKindNextDomain:
		return check.NextDomainStatus.Known()
	case verify.CheckKindKey:
		return true
	default:
		return false
	}
}

// mapCheck validates and maps one typed verification check fact.
func (a *mappingAccumulator) mapCheck(check verify.CheckResult) {
	class, knownKind := mapCheckClass(check.Kind)
	targetInvalid := a.target != (verify.Target{}) && (check.Target != a.target || check.Target.Sequence == 0 || check.Target.InstanceNumber == 0)
	if !knownKind || !check.Status.Known() || !knownErrorCode(check.Code) || check.Code != verify.ErrorCodeProviderError && check.ProviderFailureClass != "" || targetInvalid {
		a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		return
	}
	if a.required[check.Kind] {
		// Multiple signature checks are expected, while every other current check is singular.
		if check.Kind != verify.CheckKindSignature {
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
			return
		}
	}
	a.required[check.Kind] = true

	switch check.Kind {
	case verify.CheckKindBodyHash, verify.CheckKindHeaderHash:
		a.mapHashCheck(class, check)
	case verify.CheckKindSignature:
		a.mapSignatureCheck(class, check)
	case verify.CheckKindTimestamp:
		a.mapTimestampCheck(class, check)
	case verify.CheckKindEnvelope:
		a.mapEnvelopeCheck(class, check)
	case verify.CheckKindDomainAlignment:
		a.mapAlignmentCheck(class, check)
	case verify.CheckKindNextDomain:
		a.mapNextDomainCheck(class, check)
	default:
		a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
	}
}

// mapHashCheck maps aggregate supported-hash facts without interpreting digest bytes.
func (a *mappingAccumulator) mapHashCheck(class CheckClass, check verify.CheckResult) {
	if !check.HashStatus.Known() {
		a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		return
	}
	switch check.HashStatus {
	case verify.HashStatusPass:
		if check.Status != verify.CheckStatusPass || check.Code != "" {
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
			return
		}
		a.appendCheck(CheckFact{Class: class, Reason: ReasonNone})
	case verify.HashStatusMismatch:
		if check.Status == verify.CheckStatusFail && check.Code == verify.ErrorCodeHashMismatch {
			a.addFact(class, severityFailure, ReasonHashMismatch)
		} else {
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		}
	case verify.HashStatusUnsupported:
		if check.Status == verify.CheckStatusUnsupported && check.Code == verify.ErrorCodeUnsupportedAlgorithm {
			a.addFact(class, severityPermanent, ReasonUnsupportedAlgorithm)
		} else {
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		}
	case verify.HashStatusInvalid, verify.HashStatusNotChecked:
		if check.HashStatus == verify.HashStatusInvalid && check.Status == verify.CheckStatusFail && check.Code == verify.ErrorCodeMalformedState {
			a.addFact(class, severityPermanent, ReasonMalformedProtocol)
		} else {
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		}
	default:
		a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
	}
}

// mapSignatureCheck validates bounded signature-check consistency. Per-set
// checks are recorded as facts only; the aggregate severity of signatures is
// decided once by the Section 14.6 combination in applySignatureCombination,
// so a failing set in a losing alternative group cannot override a passing
// group. Contract violations still fail closed.
func (a *mappingAccumulator) mapSignatureCheck(class CheckClass, check verify.CheckResult) {
	if !knownAlgorithm(check.Algorithm) {
		a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		return
	}
	switch check.Code {
	case "":
		if check.Status != verify.CheckStatusPass || !supportedAlgorithm(check.Algorithm) {
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
			return
		}
		a.appendCheck(CheckFact{Class: class, Reason: ReasonNone})
		a.signatureChecks[Algorithm(check.Algorithm)]++
	case verify.ErrorCodeUnsupportedAlgorithm:
		if check.Status != verify.CheckStatusUnsupported || check.Algorithm != verify.AlgorithmUnknown {
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
			return
		}
		a.appendCheck(CheckFact{Class: class, Reason: ReasonUnsupportedAlgorithm})
		a.signatureChecks[AlgorithmUnknown]++
	case verify.ErrorCodeSignatureMismatch:
		if check.Status == verify.CheckStatusFail && supportedAlgorithm(check.Algorithm) {
			a.appendCheck(CheckFact{Class: class, Reason: ReasonSignatureMismatch})
			a.signatureChecks[Algorithm(check.Algorithm)]++
		} else {
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		}
	case verify.ErrorCodeProviderError:
		if check.Status != verify.CheckStatusFail {
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
			return
		}
		switch check.ProviderFailureClass {
		case verify.ProviderFailureTemporary:
			a.appendCheck(CheckFact{Class: CheckProvider, Reason: ReasonProviderTemporary})
		case verify.ProviderFailurePermanent:
			a.appendCheck(CheckFact{Class: CheckProvider, Reason: ReasonProviderPermanent})
		case verify.ProviderFailureContract, "":
			a.appendCheck(CheckFact{Class: CheckProvider, Reason: ReasonProviderContract})
		default:
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		}
		if supportedAlgorithm(check.Algorithm) {
			a.signatureChecks[Algorithm(check.Algorithm)]++
		}
	default:
		reason, _ := mapKeyErrorCode(check.Code)
		if check.Status != verify.CheckStatusFail || reason == ReasonInternalContract {
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		} else {
			a.appendCheck(CheckFact{Class: classForReason(reason), Reason: reason})
			if supportedAlgorithm(check.Algorithm) {
				a.signatureChecks[Algorithm(check.Algorithm)]++
			}
		}
	}
}

// mapTimestampCheck maps deterministic timestamp policy detail.
func (a *mappingAccumulator) mapTimestampCheck(class CheckClass, check verify.CheckResult) {
	if !check.TimestampStatus.Known() {
		a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		return
	}
	if check.TimestampStatus == verify.TimestampStatusPass && check.Status == verify.CheckStatusPass && check.Code == "" {
		a.appendCheck(CheckFact{Class: class, Reason: ReasonNone})
		return
	}
	if (check.TimestampStatus == verify.TimestampStatusFuture || check.TimestampStatus == verify.TimestampStatusExpired || check.TimestampStatus == verify.TimestampStatusInvalid) && check.Status == verify.CheckStatusFail && check.Code == verify.ErrorCodeTimestampInvalid {
		a.addFact(class, severityFor(ReasonTimestampInvalid), ReasonTimestampInvalid)
		return
	}
	a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
}

// mapEnvelopeCheck maps current SMTP-envelope facts.
func (a *mappingAccumulator) mapEnvelopeCheck(class CheckClass, check verify.CheckResult) {
	if !check.EnvelopeStatus.Known() {
		a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		return
	}
	a.envelopeStatus = check.EnvelopeStatus
	switch check.EnvelopeStatus {
	case verify.EnvelopeStatusPass:
		if check.Status == verify.CheckStatusPass && check.Code == "" {
			a.appendCheck(CheckFact{Class: class, Reason: ReasonNone})
			return
		}
	case verify.EnvelopeStatusNotApplicable:
		if check.Status == verify.CheckStatusNotApplicable && check.Code == "" {
			a.appendCheck(CheckFact{Class: class, Reason: ReasonNone})
			return
		}
	case verify.EnvelopeStatusMissing, verify.EnvelopeStatusMismatch, verify.EnvelopeStatusInvalid, verify.EnvelopeStatusReversePathMismatch, verify.EnvelopeStatusRecipientValueMismatch:
		if check.Status == verify.CheckStatusFail && check.Code == verify.ErrorCodeEnvelopeMismatch {
			a.addFact(class, severityFor(ReasonEnvelopeMismatch), ReasonEnvelopeMismatch)
			return
		}
	}
	a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
}

// mapAlignmentCheck maps current signing-domain alignment facts.
func (a *mappingAccumulator) mapAlignmentCheck(class CheckClass, check verify.CheckResult) {
	if !check.DomainAlignmentStatus.Known() {
		a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		return
	}
	a.alignmentStatus = check.DomainAlignmentStatus
	switch check.DomainAlignmentStatus {
	case verify.DomainAlignmentStatusPass:
		if check.Status == verify.CheckStatusPass && check.Code == "" {
			a.appendCheck(CheckFact{Class: class, Reason: ReasonNone})
			return
		}
	case verify.DomainAlignmentStatusNotApplicable:
		if check.Status == verify.CheckStatusNotApplicable && check.Code == "" {
			a.appendCheck(CheckFact{Class: class, Reason: ReasonNone})
			return
		}
	case verify.DomainAlignmentStatusMismatch:
		if check.Status == verify.CheckStatusFail && check.Code == verify.ErrorCodeDomainAlignmentMismatch {
			a.addFact(class, severityFor(ReasonDomainAlignmentMismatch), ReasonDomainAlignmentMismatch)
			return
		}
	case verify.DomainAlignmentStatusInvalid:
		if check.Status == verify.CheckStatusFail && check.Code == verify.ErrorCodeMalformedState {
			a.addFact(class, severityFor(ReasonDomainAlignmentMismatch), ReasonDomainAlignmentMismatch)
			return
		}
	}
	a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
}

// mapNextDomainCheck maps structural custody facts without domain values.
func (a *mappingAccumulator) mapNextDomainCheck(class CheckClass, check verify.CheckResult) {
	if !check.NextDomainStatus.Known() {
		a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		return
	}
	a.nextDomainStatus = check.NextDomainStatus
	switch check.NextDomainStatus {
	case verify.NextDomainStatusPass:
		if check.Status == verify.CheckStatusPass && check.Code == "" {
			a.appendCheck(CheckFact{Class: class, Reason: ReasonNone})
			return
		}
	case verify.NextDomainStatusNotApplicable:
		if check.Status == verify.CheckStatusNotApplicable && check.Code == "" {
			a.appendCheck(CheckFact{Class: class, Reason: ReasonNone})
			return
		}
	case verify.NextDomainStatusOutOfBandRequired:
		if check.Status == verify.CheckStatusUnsupported && check.Code == verify.ErrorCodeOutOfBandRequired {
			a.addFact(class, severityFor(ReasonOutOfBandRequired), ReasonOutOfBandRequired)
		} else {
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		}
		return
	case verify.NextDomainStatusMismatch, verify.NextDomainStatusMissingNext:
		if check.Status == verify.CheckStatusFail && (check.NextDomainStatus == verify.NextDomainStatusMismatch && check.Code == verify.ErrorCodeNextDomainMismatch || check.NextDomainStatus == verify.NextDomainStatusMissingNext && check.Code == verify.ErrorCodeMissingNextSignature) {
			a.addFact(class, severityFor(ReasonNextDomainMismatch), ReasonNextDomainMismatch)
		} else {
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		}
		return
	}
	a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
}

// mapSignatureSet validates and records one per-set fact. Only contract
// violations add severity here; the aggregate signature severity comes from
// the Section 14.6 combination.
func (a *mappingAccumulator) mapSignatureSet(set verify.SignatureSetResult) {
	algorithm, algorithmKnown := mapAlgorithm(set.Algorithm)
	trackedIndex := set.Index >= 0 && set.Index < hardMaxSignatureFacts
	if !algorithmKnown || !set.Status.Known() || !set.KeyStatus.Known() || set.Index < 0 || trackedIndex && a.setIndices[set.Index] || !signatureKeyPairValid(set.Status, set.KeyStatus) || !signatureAlgorithmCoherent(set.Algorithm, set.Status) {
		a.add(severityPermanent, ReasonInternalContract)
		a.appendSignature(SignatureSetFact{Algorithm: AlgorithmUnknown, Status: SignaturePERMERROR, Reason: ReasonInternalContract})
		return
	}
	if trackedIndex {
		a.setIndices[set.Index] = true
	}
	a.signatureSets[algorithm]++
	fact := signatureSetFact(algorithm, set)
	if fact.Reason == ReasonInternalContract {
		a.add(severityPermanent, fact.Reason)
	}
	if fact.Status == SignaturePASS {
		a.supportedPass++
	}
	a.appendSignature(fact)
}

// signatureSetFact projects one validated set result onto its bounded
// per-set fact: PASS, FAIL, TEMPERROR, or PERMERROR with its specific
// reason. An unknown algorithm is the Draft-08 Section 14.6 step 4 PERMERROR
// intermediate unsupported_algorithm, exactly like a locally disabled one.
// Every non-passing fact names the parsed selector (Section 14.6 step 8).
func signatureSetFact(algorithm Algorithm, set verify.SignatureSetResult) SignatureSetFact {
	fact := SignatureSetFact{Algorithm: algorithm}
	switch set.Status {
	case verify.SignatureSetStatusPass:
		if set.KeyStatus != verify.KeyStatusFound || algorithm == AlgorithmUnknown {
			fact.Status, fact.Reason = SignaturePERMERROR, ReasonInternalContract
		} else {
			fact.Status, fact.Reason = SignaturePASS, ReasonNone
		}
	case verify.SignatureSetStatusFail:
		if set.KeyStatus != verify.KeyStatusFound || algorithm == AlgorithmUnknown {
			fact.Status, fact.Reason = SignaturePERMERROR, ReasonInternalContract
		} else {
			fact.Status, fact.Reason = SignatureFAIL, ReasonSignatureMismatch
		}
	case verify.SignatureSetStatusUnsupportedAlgorithm:
		if set.KeyStatus != verify.KeyStatusUnsupportedAlgorithm || algorithm != AlgorithmUnknown {
			fact.Status, fact.Reason = SignaturePERMERROR, ReasonInternalContract
		} else {
			fact.Status, fact.Reason = SignaturePERMERROR, ReasonUnsupportedAlgorithm
		}
	case verify.SignatureSetStatusProviderTemporary:
		fact.Status, fact.Reason = SignatureTEMPERROR, ReasonProviderTemporary
		if set.KeyStatus != verify.KeyStatusProviderTemporary {
			fact.Status, fact.Reason = SignaturePERMERROR, ReasonInternalContract
		}
	default:
		fact.Status, fact.Reason = SignaturePERMERROR, reasonForSignatureSet(set)
	}
	if fact.Status != SignaturePASS && fact.Reason != ReasonInternalContract {
		fact.Selector = set.Selector
	}
	return fact
}

// applySignatureCombination adds the one aggregate signature severity: the
// Section 14.6 combination of the per-set results under the parsed layout,
// computed by the single verify owner. PASS adds nothing; TEMPERROR and FAIL
// add provider_temporary and signature_mismatch; PERMERROR adds the reason of
// the decisive set, the first set carrying the combined result inside the
// first group whose result equals it, so the public reason is deterministic.
func (a *mappingAccumulator) applySignatureCombination(layout combine.Layout, sets []verify.SignatureSetResult) {
	if len(sets) == 0 || a.hardOverflow {
		return
	}
	outcome := verify.CombineSignatureSets(layout, sets)
	if !outcome.Valid() {
		a.add(severityPermanent, ReasonInternalContract)
		return
	}
	switch outcome.Result() {
	case combine.ResultPass:
	case combine.ResultTempError:
		a.add(severityTemporary, ReasonProviderTemporary)
	case combine.ResultFail:
		a.add(severityFailure, ReasonSignatureMismatch)
	default:
		decisive, _ := verify.SignatureSetAt(sets, outcome.Decisive())
		algorithm, _ := mapAlgorithm(decisive.Algorithm)
		a.add(severityPermanent, signatureSetFact(algorithm, decisive).Reason)
		a.locallyDisabled = decisive.Status == verify.SignatureSetStatusDisabledAlgorithm
	}
}

// signatureKeyPairValid exhaustively validates signature and key-status coherence.
func signatureKeyPairValid(status verify.SignatureSetStatus, keyStatus verify.KeyStatus) bool {
	switch status {
	case verify.SignatureSetStatusNotChecked:
		return keyStatus == verify.KeyStatusNotChecked
	case verify.SignatureSetStatusPass, verify.SignatureSetStatusFail:
		return keyStatus == verify.KeyStatusFound
	case verify.SignatureSetStatusUnsupportedAlgorithm:
		return keyStatus == verify.KeyStatusUnsupportedAlgorithm
	case verify.SignatureSetStatusDisabledAlgorithm:
		return keyStatus == verify.KeyStatusDisabledAlgorithm
	case verify.SignatureSetStatusMissingKey:
		return keyStatus == verify.KeyStatusMissing
	case verify.SignatureSetStatusInvalidKey:
		return keyStatus == verify.KeyStatusInvalid
	case verify.SignatureSetStatusAmbiguousKey:
		return keyStatus == verify.KeyStatusAmbiguous
	case verify.SignatureSetStatusRevokedKey:
		return keyStatus == verify.KeyStatusRevoked
	case verify.SignatureSetStatusUnsupportedKeyType:
		return keyStatus == verify.KeyStatusUnsupportedKeyType
	case verify.SignatureSetStatusKeyAlgorithmMismatch:
		return keyStatus == verify.KeyStatusAlgorithmMismatch
	case verify.SignatureSetStatusWrongKeyType:
		return keyStatus == verify.KeyStatusWrongType
	case verify.SignatureSetStatusKeyPolicyRejected:
		return keyStatus == verify.KeyStatusPolicyRejected
	case verify.SignatureSetStatusProviderError:
		return keyStatus == verify.KeyStatusProviderError
	case verify.SignatureSetStatusProviderTemporary:
		return keyStatus == verify.KeyStatusProviderTemporary
	case verify.SignatureSetStatusProviderPermanent:
		return keyStatus == verify.KeyStatusProviderPermanent
	case verify.SignatureSetStatusProviderContract:
		return keyStatus == verify.KeyStatusProviderContract
	default:
		return false
	}
}

// requireCompleteCurrentChecks prevents partial synthetic or corrupted facts from passing.
func (a *mappingAccumulator) requireCompleteCurrentChecks() {
	for _, kind := range []verify.CheckKind{verify.CheckKindBodyHash, verify.CheckKindHeaderHash, verify.CheckKindSignature, verify.CheckKindTimestamp, verify.CheckKindEnvelope, verify.CheckKindDomainAlignment, verify.CheckKindNextDomain} {
		if !a.required[kind] {
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		}
	}
	for _, algorithm := range []Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256, AlgorithmMLDSA44, AlgorithmUnknown} {
		if a.signatureChecks[algorithm] != a.signatureSets[algorithm] {
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		}
	}
}

// requireContiguousSetIndices enforces zero-origin signature-set positions without gaps.
func (a *mappingAccumulator) requireContiguousSetIndices(count int) {
	for index := range count {
		if !a.setIndices[index] {
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
			return
		}
	}
}

// enforceCustodyCoherence validates current-check facts against whole-sequence coverage.
func (a *mappingAccumulator) enforceCustodyCoherence(custody Custody) {
	switch custody {
	case CustodyNotPresent:
		if a.envelopeStatus == verify.EnvelopeStatusNotApplicable || a.nextDomainStatus == verify.NextDomainStatusPass {
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		}
	case CustodyNDLinksEvaluated:
		if a.envelopeStatus == verify.EnvelopeStatusNotApplicable || a.nextDomainStatus != verify.NextDomainStatusNotApplicable {
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		}
	case CustodyTerminalNDRequiresOOB:
		if a.envelopeStatus != verify.EnvelopeStatusNotApplicable || a.alignmentStatus != verify.DomainAlignmentStatusNotApplicable || a.nextDomainStatus != verify.NextDomainStatusOutOfBandRequired {
			a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
		}
	case CustodyNotEvaluated:
	default:
		a.addFact(CheckInternalContract, severityPermanent, ReasonInternalContract)
	}
}

// addFact appends one bounded fact and applies deterministic precedence.
func (a *mappingAccumulator) addFact(class CheckClass, severity outcomeSeverity, reason Reason) {
	a.appendCheck(CheckFact{Class: class, Reason: reason})
	a.add(severity, reason)
}

// appendCheck retains a fact only within the configured output cap.
func (a *mappingAccumulator) appendCheck(fact CheckFact) {
	if len(a.checks) < a.maxChecks {
		a.checks = append(a.checks, fact)
		return
	}
	worst := 0
	for index := 1; index < len(a.checks); index++ {
		if compareCheckFacts(a.checks[worst], a.checks[index]) < 0 {
			worst = index
		}
	}
	if len(a.checks) > 0 && compareCheckFacts(fact, a.checks[worst]) < 0 {
		a.checks[worst] = fact
	}
}

// appendSignature retains a signature fact only within the configured output cap.
func (a *mappingAccumulator) appendSignature(fact SignatureSetFact) {
	if len(a.completeSignatures) < hardMaxSignatureFacts+1 {
		a.completeSignatures = append(a.completeSignatures, fact)
	}
	if len(a.signatures) < a.maxSignatures {
		a.signatures = append(a.signatures, fact)
	}
}

// add selects the highest severity and deterministic reason rank.
func (a *mappingAccumulator) add(severity outcomeSeverity, reason Reason) {
	if severity > a.severity || severity == a.severity && reasonRank(reason) < reasonRank(a.reason) {
		a.severity = severity
		a.reason = reason
	}
}

// severityFor returns the aggregate precedence of one reason from its single
// Draft-08 Section 14.1 state owner, so a check fact can never carry a
// severity that disagrees with the state its reason reports.
func severityFor(reason Reason) outcomeSeverity {
	switch StateForReason(reason) {
	case StatePASS:
		return severityPass
	case StateTEMPERROR:
		return severityTemporary
	case StateFAIL:
		return severityFailure
	default:
		return severityPermanent
	}
}

// StateForReason returns the Draft-08 Section 14.1 state that a result with
// this primary reason reports. The policy package owns the classification;
// an unknown or request-only reason is PERMERROR, which fails closed.
func StateForReason(reason Reason) State {
	if reason == ReasonInvalidRequest {
		return StatePERMERROR
	}
	switch protocol, _ := policy.ProtocolForVerificationReason(policy.VerificationReason(reason)); protocol {
	case policy.ProtocolPASS:
		return StatePASS
	case policy.ProtocolFAIL:
		return StateFAIL
	case policy.ProtocolTEMPERROR:
		return StateTEMPERROR
	default:
		return StatePERMERROR
	}
}

// stateForSeverity maps aggregate precedence to exactly four states.
func stateForSeverity(severity outcomeSeverity) State {
	switch severity {
	case severityPermanent:
		return StatePERMERROR
	case severityFailure:
		return StateFAIL
	case severityTemporary:
		return StateTEMPERROR
	default:
		return StatePASS
	}
}

// mapCustody maps whole-sequence structural coverage without inventing evaluated state.
func mapCustody(status verify.CustodyStatus) Custody {
	switch status {
	case verify.CustodyStatusNotPresent:
		return CustodyNotPresent
	case verify.CustodyStatusNDLinksEvaluated:
		return CustodyNDLinksEvaluated
	case verify.CustodyStatusTerminalNDRequiresOOB:
		return CustodyTerminalNDRequiresOOB
	default:
		return CustodyNotEvaluated
	}
}

// mapCheckClass maps the closed verification check-kind vocabulary.
func mapCheckClass(kind verify.CheckKind) (CheckClass, bool) {
	switch kind {
	case verify.CheckKindBodyHash:
		return CheckBodyHash, true
	case verify.CheckKindHeaderHash:
		return CheckHeaderHash, true
	case verify.CheckKindSignature:
		return CheckSignature, true
	case verify.CheckKindKey:
		return CheckKey, true
	case verify.CheckKindTimestamp:
		return CheckTimestamp, true
	case verify.CheckKindEnvelope:
		return CheckEnvelope, true
	case verify.CheckKindDomainAlignment:
		return CheckDomainAlignment, true
	case verify.CheckKindNextDomain:
		return CheckNextDomain, true
	default:
		return CheckInternalContract, false
	}
}

// mapAlgorithm bounds unknown spellings to one fixed token.
func mapAlgorithm(algorithm verify.Algorithm) (Algorithm, bool) {
	switch algorithm {
	case verify.AlgorithmRSASHA256:
		return AlgorithmRSASHA256, true
	case verify.AlgorithmEd25519SHA256:
		return AlgorithmEd25519SHA256, true
	case verify.AlgorithmMLDSA44:
		return AlgorithmMLDSA44, true
	case verify.AlgorithmUnknown:
		return AlgorithmUnknown, true
	default:
		return AlgorithmUnknown, false
	}
}

// knownAlgorithm reports whether a check carries a bounded algorithm token.
func knownAlgorithm(algorithm verify.Algorithm) bool {
	_, known := mapAlgorithm(algorithm)
	return known
}

// supportedAlgorithm reports whether a check names one of the Draft-08
// Section 3 verifier-mandatory algorithms.
func supportedAlgorithm(algorithm verify.Algorithm) bool {
	return algorithm == verify.AlgorithmRSASHA256 || algorithm == verify.AlgorithmEd25519SHA256 ||
		algorithm == verify.AlgorithmMLDSA44
}

// knownErrorCode rejects arbitrary internal tokens while allowing success.
func knownErrorCode(code verify.ErrorCode) bool {
	switch code {
	case "", verify.ErrorCodeInvalidOptions, verify.ErrorCodeInvalidRequest, verify.ErrorCodeLimitExceeded,
		verify.ErrorCodeUnsupportedAlgorithm, verify.ErrorCodeUnsupportedTarget, verify.ErrorCodeDisabledAlgorithm,
		verify.ErrorCodeMissingKey, verify.ErrorCodeAmbiguousKey, verify.ErrorCodeInvalidKey, verify.ErrorCodeRevokedKey,
		verify.ErrorCodeUnsupportedKeyType, verify.ErrorCodeKeyAlgorithmMismatch, verify.ErrorCodeWrongKeyType,
		verify.ErrorCodeKeyPolicyRejected, verify.ErrorCodeProviderError, verify.ErrorCodeMalformedState,
		verify.ErrorCodeDuplicateHashAlgorithm, verify.ErrorCodeInvalidRecipeJSON,
		verify.ErrorCodeDuplicateSelector,
		verify.ErrorCodeSequenceInvalid,
		verify.ErrorCodeMissingTarget, verify.ErrorCodeDuplicateTarget, verify.ErrorCodeHashMismatch,
		verify.ErrorCodeSignatureMismatch, verify.ErrorCodeTimestampInvalid, verify.ErrorCodeEnvelopeMismatch,
		verify.ErrorCodeDomainAlignmentMismatch, verify.ErrorCodeNextDomainMismatch, verify.ErrorCodeMissingNextSignature,
		verify.ErrorCodeCustodyMismatch, verify.ErrorCodeOutOfBandRequired, verify.ErrorCodeInternalMisuse:
		return true
	default:
		return false
	}
}

// mapKeyErrorCode maps key/provider error codes to bounded precedence.
func mapKeyErrorCode(code verify.ErrorCode) (Reason, outcomeSeverity) {
	switch code {
	case verify.ErrorCodeMissingKey:
		return ReasonMissingKey, severityPermanent
	case verify.ErrorCodeAmbiguousKey:
		return ReasonAmbiguousKey, severityPermanent
	case verify.ErrorCodeInvalidKey, verify.ErrorCodeWrongKeyType, verify.ErrorCodeKeyPolicyRejected:
		return ReasonInvalidKey, severityPermanent
	case verify.ErrorCodeRevokedKey:
		return ReasonRevokedKey, severityPermanent
	case verify.ErrorCodeUnsupportedKeyType:
		return ReasonUnsupportedKeyType, severityPermanent
	case verify.ErrorCodeKeyAlgorithmMismatch:
		return ReasonKeyAlgorithmMismatch, severityPermanent
	case verify.ErrorCodeProviderError:
		return ReasonProviderContract, severityPermanent
	case verify.ErrorCodeDisabledAlgorithm:
		return ReasonUnsupportedAlgorithm, severityPermanent
	default:
		return ReasonInternalContract, severityPermanent
	}
}

// reasonForSignatureSet maps every non-pass signature status.
func reasonForSignatureSet(set verify.SignatureSetResult) Reason {
	switch set.Status {
	case verify.SignatureSetStatusMissingKey:
		return ReasonMissingKey
	case verify.SignatureSetStatusAmbiguousKey:
		return ReasonAmbiguousKey
	case verify.SignatureSetStatusRevokedKey:
		return ReasonRevokedKey
	case verify.SignatureSetStatusUnsupportedKeyType:
		return ReasonUnsupportedKeyType
	case verify.SignatureSetStatusKeyAlgorithmMismatch:
		return ReasonKeyAlgorithmMismatch
	case verify.SignatureSetStatusInvalidKey, verify.SignatureSetStatusWrongKeyType, verify.SignatureSetStatusKeyPolicyRejected:
		return ReasonInvalidKey
	case verify.SignatureSetStatusProviderPermanent:
		return ReasonProviderPermanent
	case verify.SignatureSetStatusProviderError, verify.SignatureSetStatusProviderContract:
		return ReasonProviderContract
	case verify.SignatureSetStatusDisabledAlgorithm, verify.SignatureSetStatusNotChecked:
		return ReasonUnsupportedAlgorithm
	default:
		return ReasonInternalContract
	}
}

// classForReason selects the bounded check class for key/provider reasons.
func classForReason(reason Reason) CheckClass {
	if reason == ReasonProviderTemporary || reason == ReasonProviderPermanent || reason == ReasonProviderContract {
		return CheckProvider
	}
	return CheckKey
}

// reasonRank makes equal-precedence primary reasons independent of input order.
func reasonRank(reason Reason) int {
	for index, candidate := range []Reason{ReasonInternalContract, ReasonLimitExceeded, ReasonMalformedMessage, ReasonMalformedProtocol, ReasonDuplicateHashAlgorithm, ReasonInvalidRecipeJSON, ReasonInvalidRecipe, ReasonFromNotAuthentic, ReasonDuplicateSelector, ReasonMissingProtocol, ReasonSequenceInvalid, ReasonUnsupportedAlgorithm, ReasonMissingKey, ReasonRevokedKey, ReasonUnsupportedKeyType, ReasonKeyAlgorithmMismatch, ReasonInvalidKey, ReasonAmbiguousKey, ReasonProviderPermanent, ReasonProviderContract, ReasonTimestampInvalid, ReasonEnvelopeMismatch, ReasonDomainAlignmentMismatch, ReasonNextDomainMismatch, ReasonCustodyMismatch, ReasonOutOfBandRequired, ReasonBodyHistoryUnavailable, ReasonHashMismatch, ReasonSignatureMismatch, ReasonProviderTemporary, ReasonNone} {
		if reason == candidate {
			return index
		}
	}
	return 0
}

// compareCheckFacts orders bounded check facts deterministically.
func compareCheckFacts(left, right CheckFact) int {
	if left.Class < right.Class {
		return -1
	}
	if left.Class > right.Class {
		return 1
	}
	if left.Reason < right.Reason {
		return -1
	}
	if left.Reason > right.Reason {
		return 1
	}
	return 0
}
