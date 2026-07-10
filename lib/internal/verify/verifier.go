package verify

import (
	"context"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/signature"
)

type verificationInput struct {
	request    Request
	instances  []instance.MessageInstance
	signatures []signature.Signature
}

// Verify extracts DKIM2 fields from a raw message and verifies the selected target.
func (v Verifier) Verify(ctx context.Context, request Request) (Result, error) {
	instances, err := instance.Extract(request.Message)
	if err != nil {
		return Result{}, malformedStateError(CheckKindSignature, Target{}, err)
	}
	signatures, err := signature.Extract(request.Message)
	if err != nil {
		return Result{}, malformedStateError(CheckKindSignature, Target{}, err)
	}

	return v.verifyExtracted(ctx, verificationInput{request: request, instances: instances, signatures: signatures})
}

// verifyExtracted verifies protocol state extracted exclusively from Request.Message.
func (v Verifier) verifyExtracted(ctx context.Context, input verificationInput) (Result, error) {
	targetSignature, targetInstance, target, err := selectVerificationTarget(input)
	if err != nil {
		return Result{}, err
	}
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
	timestamp := v.checkTimestamp(targetSignature, target)
	nextDomain := checkNextDomain(targetSignature, target, currentSequence)
	envelope := v.checkEnvelope(input.request, targetSignature, target, currentSequence)
	domainAlignment := checkDomainAlignment(targetSignature, target)

	checks := make([]CheckResult, 0, 6+len(signatures.checks))
	checks = append(checks, hashes.body, hashes.header)
	checks = append(checks, signatures.checks...)
	checks = append(checks, timestamp.check, nextDomain.check, envelope.check, domainAlignment.check)
	status := targetStatus(hashes.pass, timestamp.pass, envelope.pass, domainAlignment.pass, nextDomain, signatures)

	return NewResult(target, status, checks, signatures.sets), nil
}

// selectVerificationTarget validates parsed references and chooses the target signature.
func selectVerificationTarget(input verificationInput) (signature.Signature, instance.MessageInstance, Target, error) {
	instances := input.instances
	signatures := input.signatures
	if err := validateInstanceCollection(instances); err != nil {
		return signature.Signature{}, instance.MessageInstance{}, Target{}, err
	}
	if err := validateNextDomainChain(signatures); err != nil {
		return signature.Signature{}, instance.MessageInstance{}, Target{}, err
	}
	if err := validateSignatureCollection(signatures); err != nil {
		return signature.Signature{}, instance.MessageInstance{}, Target{}, err
	}
	if err := validateReferencedInstances(instances, signatures); err != nil {
		return signature.Signature{}, instance.MessageInstance{}, Target{}, err
	}
	if err := validateCurrentInstanceReference(instances, signatures); err != nil {
		return signature.Signature{}, instance.MessageInstance{}, Target{}, err
	}

	targetSequence := input.request.TargetSequence
	if targetSequence == 0 {
		targetSequence = highestSignatureSequence(signatures)
	}
	targetSignature, err := signatureBySequence(signatures, targetSequence)
	if err != nil {
		return signature.Signature{}, instance.MessageInstance{}, Target{}, err
	}
	target := Target{
		Sequence:       targetSignature.Sequence(),
		InstanceNumber: targetSignature.InstanceNumber(),
	}
	targetInstance, err := instanceByNumber(instances, target.InstanceNumber)
	if err != nil {
		return signature.Signature{}, instance.MessageInstance{}, target, err
	}

	return targetSignature, targetInstance, target, nil
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

// validateCurrentInstanceReference enforces the draft-versioned highest i= to highest m= interpretation.
func validateCurrentInstanceReference(instances []instance.MessageInstance, signatures []signature.Signature) error {
	var highestInstance uint64
	for _, parsed := range instances {
		if parsed.Number() > highestInstance {
			highestInstance = parsed.Number()
		}
	}
	var current signature.Signature
	for _, parsed := range signatures {
		if parsed.Sequence() > current.Sequence() {
			current = parsed
		}
	}
	if current.InstanceNumber() != highestInstance {
		return malformedSequenceError("current_instance_reference", Target{
			Sequence:       current.Sequence(),
			InstanceNumber: current.InstanceNumber(),
		})
	}

	return nil
}

// validateInstanceCollection verifies contiguous unique Message-Instance numbers.
func validateInstanceCollection(instances []instance.MessageInstance) error {
	if len(instances) == 0 {
		return targetMissingError("message_instance", 0, Target{})
	}

	seen := make(map[uint64]int, len(instances))
	maxNumber := uint64(0)
	for _, parsed := range instances {
		number := parsed.Number()
		if _, exists := seen[number]; exists {
			return targetDuplicateError("message_instance", number, Target{InstanceNumber: number})
		}
		seen[number] = parsed.HeaderIndex()
		if number > maxNumber {
			maxNumber = number
		}
	}
	for expected := uint64(1); expected <= maxNumber; expected++ {
		if _, exists := seen[expected]; !exists {
			return malformedSequenceError("message_instance", Target{InstanceNumber: expected})
		}
	}

	return nil
}

// validateSignatureCollection verifies contiguous unique DKIM2-Signature sequences.
func validateSignatureCollection(signatures []signature.Signature) error {
	if len(signatures) == 0 {
		return targetMissingError("dkim2_signature", 0, Target{})
	}

	seen := make(map[uint64]int, len(signatures))
	maxSequence := uint64(0)
	for _, parsed := range signatures {
		sequence := parsed.Sequence()
		if _, exists := seen[sequence]; exists {
			return targetDuplicateError("dkim2_signature", sequence, Target{Sequence: sequence})
		}
		seen[sequence] = parsed.HeaderIndex()
		if sequence > maxSequence {
			maxSequence = sequence
		}
	}
	for expected := uint64(1); expected <= maxSequence; expected++ {
		if _, exists := seen[expected]; !exists {
			return malformedSequenceError("dkim2_signature", Target{Sequence: expected})
		}
	}

	return nil
}

// validateReferencedInstances rejects current instances above every signature reference.
func validateReferencedInstances(instances []instance.MessageInstance, signatures []signature.Signature) error {
	maxReference := uint64(0)
	for _, parsed := range signatures {
		if parsed.InstanceNumber() > maxReference {
			maxReference = parsed.InstanceNumber()
		}
	}
	for _, parsed := range instances {
		if parsed.Number() > maxReference {
			return malformedSequenceError("message_instance", Target{InstanceNumber: parsed.Number()})
		}
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
