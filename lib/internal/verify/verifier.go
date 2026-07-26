package verify

import (
	"context"
	"errors"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/signature"
)

type verificationInput struct {
	request    Request
	instances  []instance.MessageInstance
	signatures []signature.Signature
}

// Verify extracts DKIM2 fields from a raw message and verifies the selected target.
func (v Verifier) Verify(ctx context.Context, request Request) (Result, error) {
	result, input, err := v.verifyCurrent(ctx, request)
	if err != nil || !aggregateCurrentPass(result) {
		return result, err
	}
	return v.attachAuthenticatedHistory(ctx, result, input)
}

// VerifyCurrent verifies authoritative current facts without reconstructing authenticated history.
func (v Verifier) VerifyCurrent(ctx context.Context, request Request) (Result, error) {
	result, _, err := v.verifyCurrent(ctx, request)
	return result, err
}

// verifyCurrent owns the shared extraction, current verification, and replay-projection path.
func (v Verifier) verifyCurrent(ctx context.Context, request Request) (Result, verificationInput, error) {
	if ctx == nil {
		return Result{}, verificationInput{}, newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	input, err := v.extractVerificationInput(request, recipe.DefaultLimits().MaxDecodedRecipeBytes)
	if err != nil {
		return Result{}, verificationInput{}, err
	}

	result, err := v.verifyCurrentExtracted(ctx, input)
	if typed, ok := err.(*Error); ok && len(input.signatures) == 0 {
		typed.custody = CustodyStatusNotPresent
	}
	return result, input, err
}

// extractVerificationInput parses protocol fields once through their authoritative owners.
func (v Verifier) extractVerificationInput(request Request, maxDecodedRecipeBytes int) (verificationInput, error) {
	recipeLimits := recipe.DefaultLimits()
	recipeLimits.MaxDecodedRecipeBytes = maxDecodedRecipeBytes
	instanceParser, err := instance.NewParser(verifierInstanceLimits(v.options.Limits.MaxInstanceHashSets, recipeLimits))
	if err != nil {
		return verificationInput{}, malformedStateError(CheckKindSignature, Target{}, err)
	}
	instances, err := instanceParser.Extract(request.Message)
	if err != nil {
		if instance.IsErrorCode(err, instance.ErrorCodeLimitExceeded) {
			return verificationInput{}, newError(ErrorCodeLimitExceeded, ErrorLocation{Check: CheckKindSignature}, ErrorDetails{Class: ErrorClassLimit}, nil)
		}
		if instance.IsErrorCode(err, instance.ErrorCodeMissingOrigin) || instance.IsErrorCode(err, instance.ErrorCodeDuplicateNumber) || instance.IsErrorCode(err, instance.ErrorCodeSequenceGap) {
			typed := newError(ErrorCodeSequenceInvalid, ErrorLocation{Check: CheckKindSignature}, ErrorDetails{Class: ErrorClassMalformed}, nil)
			if len(request.Message.Headers().FieldsByName(instance.HeaderName)) == 0 &&
				len(request.Message.Headers().FieldsByName(signature.HeaderName)) == 0 {
				typed.custody = CustodyStatusNotPresent
			}
			return verificationInput{}, typed
		}
		return verificationInput{}, malformedStateError(CheckKindSignature, Target{}, err)
	}
	signatureParser, err := signature.NewParser(signature.Limits{
		MaxRecipients:    v.options.Limits.MaxEnvelopeRecipients,
		MaxSignatureSets: v.options.Limits.MaxSignatureSets,
	})
	if err != nil {
		return verificationInput{}, malformedStateError(CheckKindSignature, Target{}, err)
	}
	signatures, err := signatureParser.Extract(request.Message)
	if err != nil {
		if signature.IsErrorCode(err, signature.ErrorCodeLimitExceeded) {
			return verificationInput{}, newError(ErrorCodeLimitExceeded, ErrorLocation{Check: CheckKindSignature}, ErrorDetails{Class: ErrorClassLimit}, nil)
		}
		code := ErrorCodeMalformedState
		if signature.IsErrorCode(err, signature.ErrorCodeMissingOrigin) || signature.IsErrorCode(err, signature.ErrorCodeDuplicateSequence) || signature.IsErrorCode(err, signature.ErrorCodeSequenceGap) {
			code = ErrorCodeSequenceInvalid
		}
		typed := newError(code, ErrorLocation{Check: CheckKindSignature}, ErrorDetails{Class: ErrorClassMalformed}, err)
		if len(request.Message.Headers().FieldsByName(signature.HeaderName)) == 0 && signature.IsErrorCode(err, signature.ErrorCodeMissingOrigin) {
			typed.custody = CustodyStatusNotPresent
		}
		return verificationInput{}, typed
	}

	return verificationInput{request: request, instances: instances, signatures: signatures}, nil
}

// verifierInstanceLimits binds decoded Message-Instance recipes to recipe-owned limits.
func verifierInstanceLimits(maxHashSets int, recipeLimits recipe.Limits) instance.Limits {
	limits := instance.DefaultLimits()
	limits.MaxHashSets = maxHashSets
	decodedRecipeLimit := recipeLimits.MaxDecodedRecipeBytes
	if decodedRecipeLimit == 0 {
		decodedRecipeLimit = recipe.DefaultLimits().MaxDecodedRecipeBytes
	}
	limits.TagLimits.MaxBase64DecodedBytes = decodedRecipeLimit
	return limits
}

// verifyCurrentExtracted verifies current protocol state extracted exclusively from Request.Message.
func (v Verifier) verifyCurrentExtracted(ctx context.Context, input verificationInput) (Result, error) {
	targetSignature, targetInstance, custody, target, err := selectVerificationTarget(input)
	if err != nil {
		return Result{}, err
	}
	targetFlags := newTargetFlagCandidate(targetSignature)
	currentSequence := highestSignatureSequence(input.signatures)
	if input.request.TargetSequence != 0 && target.InstanceNumber < highestInstanceNumber(input.instances) {
		return Result{}, unsupportedHistoricalTargetError(target)
	}

	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		return Result{}, malformedStateError(CheckKindSignature, target, err)
	}
	hashes, err := compareTargetHashes(canonicalizer, input.request.Message, targetInstance, target)
	if err != nil {
		return Result{}, err
	}
	digest, err := signatureInputDigest(canonicalizer, input.request.Message, target)
	if err != nil {
		return Result{}, err
	}
	signatures := v.evaluateSignatureSets(ctx, targetSignature, digest, target)
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	timestamp := v.checkTimestamp(targetSignature, target)
	nextDomain := checkNextDomain(targetSignature, target, currentSequence)
	envelope := v.checkEnvelope(input.request, targetSignature, target, currentSequence)
	domainAlignment, err := checkDomainAlignment(custody, target)
	if err != nil {
		return Result{}, err
	}

	checks := make([]CheckResult, 0, 6+len(signatures.checks))
	checks = append(checks, hashes.body, hashes.header)
	checks = append(checks, signatures.checks...)
	checks = append(checks, timestamp.check, nextDomain.check, envelope.check, domainAlignment.check)
	status := targetStatus(hashes.pass, timestamp.pass, envelope.pass, domainAlignment.pass, nextDomain, signatures)

	result := NewResultWithCustody(target, status, checks, signatures.sets, custodyStatus(custody)).withTargetFlagCandidate(targetFlags)
	if !aggregateCurrentPass(result) {
		return result, nil
	}
	if projection, ok := buildReplayProjection(input, targetSignature, targetInstance, hashes, digest, result); ok {
		result = result.withReplayProjection(projection)
	}
	return result, nil
}

// attachAuthenticatedHistory runs only after coherent aggregate current PASS.
func (v Verifier) attachAuthenticatedHistory(ctx context.Context, current Result, input verificationInput) (Result, error) {
	target := current.Target().InstanceNumber
	fallback := func() (Result, error) { return current.withHistory(newInternalContractHistoryWalk(target)), nil }
	state, err := recipe.NewState(input.request.Message)
	if err != nil {
		return fallback()
	}
	collection, err := instance.NewCollection(input.instances)
	if err != nil {
		return fallback()
	}
	walk, err := v.history.Walk(ctx, current, collection, state)
	if err != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		return fallback()
	}
	if !walk.Valid() || walk.TargetInstance() != target {
		return fallback()
	}
	return current.withHistory(walk), nil
}

// newTargetFlagCandidate derives bounded evidence from the already parsed selected signature.
func newTargetFlagCandidate(parsed signature.Signature) TargetFlagCandidate {
	flags := parsed.Flags()
	return TargetFlagCandidate{
		sequence:     parsed.Sequence(),
		doNotModify:  flags.HasKnown(signature.FlagDoNotModify),
		doNotExplode: flags.HasKnown(signature.FlagDoNotExplode),
		feedback:     flags.HasKnown(signature.FlagFeedback),
		feedHere:     flags.HasKnown(signature.FlagFeedHere),
		exploded:     flags.HasKnown(signature.FlagExploded),
	}
}

// custodyStatus maps one validated shared custody result into the public vocabulary.
func custodyStatus(result signature.CustodyResult) CustodyStatus {
	if !result.Evaluated() {
		return CustodyStatusNotPresent
	}
	if result.Status() == signature.CustodyStatusTerminalNextDomain {
		return CustodyStatusTerminalNDRequiresOOB
	}
	if result.HadNextDomain() {
		return CustodyStatusNDLinksEvaluated
	}
	return CustodyStatusNotPresent
}

// selectVerificationTarget validates parsed references and chooses the target signature.
func selectVerificationTarget(input verificationInput) (signature.Signature, instance.MessageInstance, signature.CustodyResult, Target, error) {
	instances := input.instances
	signatures := input.signatures
	if err := validateInstanceCollection(instances); err != nil {
		return signature.Signature{}, instance.MessageInstance{}, signature.CustodyResult{}, Target{}, err
	}
	if err := validateSignatureCollection(signatures); err != nil {
		return signature.Signature{}, instance.MessageInstance{}, signature.CustodyResult{}, Target{}, err
	}
	if err := validateReferencedInstances(instances, signatures); err != nil {
		return signature.Signature{}, instance.MessageInstance{}, signature.CustodyResult{}, Target{}, err
	}

	targetSequence := input.request.TargetSequence
	if targetSequence == 0 {
		targetSequence = highestSignatureSequence(signatures)
	}
	targetSignature, err := signatureBySequence(signatures, targetSequence)
	if err != nil {
		return signature.Signature{}, instance.MessageInstance{}, signature.CustodyResult{}, Target{}, err
	}
	target := Target{
		Sequence:       targetSignature.Sequence(),
		InstanceNumber: targetSignature.InstanceNumber(),
	}
	allowedDirectSequence := uint64(0)
	if targetSequence == highestSignatureSequence(signatures) {
		allowedDirectSequence = targetSequence
	}
	custody, err := validateCustodyChain(signatures, allowedDirectSequence)
	if err != nil {
		return signature.Signature{}, instance.MessageInstance{}, signature.CustodyResult{}, target, err
	}
	targetInstance, err := instanceByNumber(instances, target.InstanceNumber)
	if err != nil {
		return signature.Signature{}, instance.MessageInstance{}, signature.CustodyResult{}, target, err
	}

	return targetSignature, targetInstance, custody, target, nil
}

// highestInstanceNumber returns the current Message-Instance number.
func highestInstanceNumber(instances []instance.MessageInstance) uint64 {
	var highest uint64
	for _, parsed := range instances {
		if parsed.Number() > highest {
			highest = parsed.Number()
		}
	}

	return highest
}

// validateInstanceCollection verifies contiguous unique Message-Instance numbers.
func validateInstanceCollection(instances []instance.MessageInstance) error {
	if len(instances) == 0 {
		return targetMissingError("message_instance", 0, Target{})
	}
	if err := instance.ValidateSequence(instances); err != nil {
		var typed *instance.Error
		if !errors.As(err, &typed) {
			return malformedSequenceError("message_instance", Target{})
		}
		switch typed.Code() {
		case instance.ErrorCodeLimitExceeded:
			return newError(ErrorCodeLimitExceeded, ErrorLocation{Check: CheckKindSignature}, ErrorDetails{Class: ErrorClassLimit}, nil)
		case instance.ErrorCodeDuplicateNumber:
			return targetDuplicateError("message_instance", typed.ObservedNumber(), Target{InstanceNumber: typed.ObservedNumber()})
		default:
			return malformedSequenceError("message_instance", Target{InstanceNumber: typed.ExpectedNumber()})
		}
	}
	return nil
}

// validateSignatureCollection verifies contiguous unique DKIM2-Signature sequences.
func validateSignatureCollection(signatures []signature.Signature) error {
	if len(signatures) == 0 {
		return targetMissingError("dkim2_signature", 0, Target{})
	}

	if err := signature.ValidateSequence(signatures); err != nil {
		var typed *signature.Error
		if !errors.As(err, &typed) {
			return malformedSequenceError("dkim2_signature", Target{})
		}
		switch typed.Code() {
		case signature.ErrorCodeLimitExceeded:
			return newError(ErrorCodeLimitExceeded, ErrorLocation{Check: CheckKindSignature}, ErrorDetails{Class: ErrorClassLimit}, nil)
		case signature.ErrorCodeDuplicateSequence:
			return targetDuplicateError("dkim2_signature", typed.ObservedNumber(), Target{Sequence: typed.ObservedNumber()})
		default:
			return malformedSequenceError("dkim2_signature", Target{Sequence: typed.ExpectedNumber()})
		}
	}
	return nil
}

// validateReferencedInstances rejects current instances above every signature reference.
func validateReferencedInstances(instances []instance.MessageInstance, signatures []signature.Signature) error {
	if err := signature.ValidateInstanceReferences(instances, signatures); err != nil {
		var typed *signature.Error
		if !errors.As(err, &typed) {
			return malformedSequenceError("message_instance", Target{})
		}
		return malformedSequenceError("message_instance", Target{InstanceNumber: typed.ObservedNumber()})
	}
	return nil
}

// highestSignatureSequence returns the current signature sequence.
func highestSignatureSequence(signatures []signature.Signature) uint64 {
	var highest uint64
	for _, parsed := range signatures {
		if parsed.Sequence() > highest {
			highest = parsed.Sequence()
		}
	}

	return highest
}

// signatureBySequence returns exactly one signature with sequence.
func signatureBySequence(signatures []signature.Signature, sequence uint64) (signature.Signature, error) {
	for _, parsed := range signatures {
		if parsed.Sequence() == sequence {
			return parsed, nil
		}
	}

	return signature.Signature{}, targetMissingError("dkim2_signature", sequence, Target{Sequence: sequence})
}

// instanceByNumber returns exactly one instance with number.
func instanceByNumber(instances []instance.MessageInstance, number uint64) (instance.MessageInstance, error) {
	for _, parsed := range instances {
		if parsed.Number() == number {
			return parsed, nil
		}
	}

	return instance.MessageInstance{}, targetMissingError("message_instance", number, Target{InstanceNumber: number})
}

// targetStatus summarizes protocol and signature-set facts for the selected target.
func targetStatus(hashPass bool, timestampPass bool, envelopePass bool, domainAlignmentPass bool, nextDomain nextDomainEvaluation, signatures signatureEvaluation) TargetStatus {
	if !hashPass || !timestampPass || !envelopePass || !domainAlignmentPass {
		return TargetStatusFail
	}
	if signatures.pass > 0 && signatures.fail == 0 && signatures.other == 0 {
		if signatures.temporary > 0 {
			return TargetStatusIndeterminate
		}
		if nextDomain.unsupported {
			return TargetStatusUnsupported
		}
		return TargetStatusPass
	}
	if signatures.pass > 0 {
		return TargetStatusMixed
	}
	if signatures.fail > 0 {
		return TargetStatusFail
	}
	if signatures.temporary > 0 {
		return TargetStatusIndeterminate
	}

	return TargetStatusUnsupported
}

// checkEnvelope applies current-envelope matching semantics for the selected target.
func (v Verifier) checkEnvelope(request Request, targetSignature signature.Signature, target Target, currentSequence uint64) envelopeEvaluation {
	if targetSignature.HasNextDomain() {
		return envelopeCheckResult(target, EnvelopeStatusNotApplicable)
	}
	if target.Sequence != currentSequence && request.SkipEnvelopeForNonCurrentTarget && !request.RequireEnvelope {
		return envelopeCheckResult(target, EnvelopeStatusNotApplicable)
	}
	if count := request.Envelope.RecipientCount(); count > v.options.Limits.MaxEnvelopeRecipients {
		return envelopeLimitCheckResult(target)
	}

	return envelopeCheckResult(target, compareCurrentEnvelope(request.Envelope, targetSignature))
}

// unsupportedHistoricalTargetError rejects targets whose historical message bytes are unavailable.
func unsupportedHistoricalTargetError(target Target) *Error {
	return newError(ErrorCodeUnsupportedTarget, ErrorLocation{
		Check:          CheckKindSignature,
		TargetSequence: target.Sequence,
		InstanceNumber: target.InstanceNumber,
	}, ErrorDetails{
		Class:  ErrorClassUnsupported,
		Status: CheckStatusUnsupported,
	}, nil)
}

// targetMissingError reports absent selected signature or instance state.
func targetMissingError(targetName string, number uint64, target Target) *Error {
	return newError(ErrorCodeMissingTarget, ErrorLocation{
		Check:          CheckKindSignature,
		TargetSequence: target.Sequence,
		InstanceNumber: target.InstanceNumber,
	}, ErrorDetails{
		Class:      ErrorClassMissing,
		TargetName: targetName,
		Count:      int(number),
	}, nil)
}

// targetDuplicateError reports duplicate selected signature or instance state.
func targetDuplicateError(targetName string, number uint64, target Target) *Error {
	return newError(ErrorCodeDuplicateTarget, ErrorLocation{
		Check:          CheckKindSignature,
		TargetSequence: target.Sequence,
		InstanceNumber: target.InstanceNumber,
	}, ErrorDetails{
		Class:      ErrorClassDuplicate,
		TargetName: targetName,
		Count:      int(number),
	}, nil)
}

// malformedSequenceError reports sequence gaps or unreferenced instances.
func malformedSequenceError(targetName string, target Target) *Error {
	return newError(ErrorCodeMalformedState, ErrorLocation{
		Check:          CheckKindSignature,
		TargetSequence: target.Sequence,
		InstanceNumber: target.InstanceNumber,
	}, ErrorDetails{
		Class:      ErrorClassMalformed,
		TargetName: targetName,
	}, nil)
}

// malformedStateError wraps parser or canonicalization failures safely.
func malformedStateError(kind CheckKind, target Target, cause error) *Error {
	return newError(ErrorCodeMalformedState, ErrorLocation{
		Check:          kind,
		TargetSequence: target.Sequence,
		InstanceNumber: target.InstanceNumber,
	}, ErrorDetails{
		Class:  ErrorClassMalformed,
		Status: CheckStatusFail,
	}, cause)
}

// signatureMismatchError reports cryptographic verification failure safely.
func signatureMismatchError(algorithm Algorithm, target Target, index int) *Error {
	return newError(ErrorCodeSignatureMismatch, ErrorLocation{
		Check:          CheckKindSignature,
		SignatureIndex: index,
		TargetSequence: target.Sequence,
		InstanceNumber: target.InstanceNumber,
	}, ErrorDetails{
		Class:     ErrorClassSignature,
		Algorithm: algorithm,
		Status:    CheckStatusFail,
	}, nil)
}
