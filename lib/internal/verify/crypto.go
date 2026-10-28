package verify

import (
	"context"
	"errors"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/combine"
	"github.com/croessner/dkim2/internal/cryptodkim2"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
)

// signatureEvaluation holds per-set facts in field order and their Section
// 14.6 combination under the parsed sig-any/sig-all layout.
type signatureEvaluation struct {
	checks  []CheckResult
	sets    []SignatureSetResult
	layout  combine.Layout
	outcome combine.Outcome
}

// signatureDigests holds the per-algorithm message representatives of one
// Section 12.8 signature input: the SHA-256 digest that rsa-sha256 and
// ed25519-sha256 sign, and the complete input bytes that pure mldsa44 signs.
type signatureDigests struct {
	sha256 []byte
	input  canonical.ByteInput
}

// forAlgorithm returns the message representative the algorithm signs, or
// nil for an algorithm without a representative contract. Which algorithms
// sign the input directly is owned by cryptodkim2, the same owner the signer
// uses.
func (d signatureDigests) forAlgorithm(algorithm Algorithm) []byte {
	representative := d.sha256
	if cryptodkim2.SignsInputDirectly(algorithm) {
		// Copied only when an algorithm needs the input itself, so a
		// classical-only verification retains no second input copy.
		representative = d.input.Bytes()
	}
	if !algorithm.Signable() || !cryptodkim2.ValidRepresentativeLength(algorithm, len(representative)) {
		return nil
	}
	return representative
}

// computeSignatureDigests derives every message representative from one
// canonical Section 12.8 input. The immutable input is retained for pure
// mldsa44 verification; it is the canonical protocol-field byte string,
// already bounded by the canonicalizer's signature-input limit.
func computeSignatureDigests(canonicalizer canonical.Canonicalizer, input canonical.ByteInput) (signatureDigests, error) {
	sha256Digest, err := canonicalizer.SHA256Digest(input)
	if err != nil {
		return signatureDigests{}, err
	}
	return signatureDigests{sha256: sha256Digest.Bytes(), input: input}, nil
}

// signatureInputDigest calculates the digests over Section 12.8 input bytes.
func signatureInputDigest(canonicalizer canonical.Canonicalizer, message rawmsg.Message, target Target) (signatureDigests, error) {
	signatureInput, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{
		Headers:        message.Headers(),
		TargetSequence: target.Sequence,
	})
	if err != nil {
		return signatureDigests{}, malformedStateError(CheckKindSignature, target, err)
	}
	digests, err := computeSignatureDigests(canonicalizer, signatureInput)
	if err != nil {
		return signatureDigests{}, malformedStateError(CheckKindSignature, target, err)
	}

	return digests, nil
}

// evaluateSignatureSets checks every signature set for the selected target
// and combines the per-set intermediates with the shared Section 14.6
// algebra. An unknown or locally disabled algorithm is decided without a key
// lookup.
func (v Verifier) evaluateSignatureSets(ctx context.Context, targetSignature signature.Signature, digests signatureDigests, target Target) signatureEvaluation {
	sets := targetSignature.SignatureSets()
	evaluation := signatureEvaluation{
		checks: make([]CheckResult, 0, len(sets)),
		sets:   make([]SignatureSetResult, 0, len(sets)),
		layout: targetSignature.SignatureLayout(),
	}
	if len(sets) > v.options.Limits.MaxSignatureSets {
		evaluation.checks = append(evaluation.checks, CheckResult{
			Kind:   CheckKindSignature,
			Status: CheckStatusFail,
			Code:   ErrorCodeLimitExceeded,
			Target: target,
		})

		return evaluation
	}

	for index, set := range sets {
		if ctx == nil || ctx.Err() != nil {
			break
		}
		setResult := v.evaluateSignatureSet(ctx, targetSignature, set, index, digests, target)
		evaluation.sets = append(evaluation.sets, setResult)
		evaluation.checks = append(evaluation.checks, signatureCheckResult(setResult, target))
		if ctx.Err() != nil {
			break
		}
	}
	evaluation.combine()

	return evaluation
}

// combine computes the Section 14.6 outcome of the evaluated sets. An
// incomplete evaluation (cancellation) yields an invalid outcome.
func (e *signatureEvaluation) combine() {
	e.outcome = CombineSignatureSets(e.layout, e.sets)
}

// evaluateSignatureSet checks one selector:algorithm:signature tuple. Every
// outcome carries the parsed selector; the service decides which outcomes
// expose it.
func (v Verifier) evaluateSignatureSet(ctx context.Context, targetSignature signature.Signature, set signature.Set, index int, digests signatureDigests, target Target) SignatureSetResult {
	algorithm := Algorithm(set.Algorithm())
	result := SignatureSetResult{
		Index:     index,
		Algorithm: algorithm,
		Status:    SignatureSetStatusNotChecked,
		KeyStatus: KeyStatusNotChecked,
		Selector:  set.Selector(),
	}

	switch status := v.options.AlgorithmPolicy.ClassifyAlgorithm(algorithm); status {
	case KeyStatusFound:
	case KeyStatusUnsupportedAlgorithm:
		result.Status = SignatureSetStatusUnsupportedAlgorithm
		result.KeyStatus = status

		return result
	default:
		result.Status = SignatureSetStatusDisabledAlgorithm
		result.KeyStatus = status

		return result
	}

	key, err := v.keyProvider.LookupKey(ctx, KeyQuery{
		Domain:    targetSignature.Domain(),
		Selector:  set.Selector(),
		Algorithm: algorithm,
	})
	if ctx.Err() != nil {
		return result
	}
	if err != nil {
		failureClass := ProviderFailureClassOf(err)
		if !providerKeyErrorPairValid(key, algorithm, err, failureClass) {
			result.Status = SignatureSetStatusProviderContract
			result.KeyStatus = KeyStatusProviderContract

			return result
		}
		result.Status, result.KeyStatus = signatureSetStatusFromKeyError(err, key.Metadata.Status, failureClass)

		return result
	}
	if !ValidProviderSource(key.Metadata.Source) {
		result.Status = SignatureSetStatusProviderContract
		result.KeyStatus = KeyStatusProviderContract

		return result
	}
	if key.Algorithm != algorithm {
		result.Status = SignatureSetStatusProviderContract
		result.KeyStatus = KeyStatusProviderContract

		return result
	}
	if key.Metadata.Status != KeyStatusFound {
		switch key.Metadata.Status {
		case KeyStatusMissing, KeyStatusInvalid, KeyStatusAmbiguous, KeyStatusRevoked, KeyStatusUnsupportedKeyType, KeyStatusAlgorithmMismatch:
			result.KeyStatus = key.Metadata.Status
			result.Status = signatureSetStatusFromKeyStatus(key.Metadata.Status)
		default:
			result.KeyStatus = KeyStatusProviderContract
			result.Status = SignatureSetStatusProviderContract
		}

		return result
	}
	material, keyStatus, err := validatePublicKeyMaterial(algorithm, key.Material, v.options.AlgorithmPolicy)
	if err != nil {
		result.Status, result.KeyStatus = signatureSetStatusFromKeyError(
			err, keyStatus, ProviderFailureClassOf(err),
		)

		return result
	}

	result.KeyStatus = KeyStatusFound
	if err := verifySignatureDigest(algorithm, material, digests.forAlgorithm(algorithm), set.Signature().Decoded(), target, index); err != nil {
		result.Status = SignatureSetStatusFail

		return result
	}

	result.Status = SignatureSetStatusPass

	return result
}

// providerKeyErrorPairValid validates typed internal provider error disjointness.
func providerKeyErrorPairValid(
	key PublicKey,
	algorithm Algorithm,
	err error,
	failureClass ProviderFailureClass,
) bool {
	if key.Material != nil {
		return false
	}
	if failureClass.Known() {
		return key.Algorithm == "" && key.Metadata == (KeyMetadata{})
	}
	if key.Algorithm != algorithm || !key.Metadata.Status.Known() {
		return false
	}
	var typed *Error
	if !errors.As(err, &typed) {
		return false
	}
	_, mapped := signatureSetStatusFromKeyError(err, key.Metadata.Status, failureClass)
	return mapped == key.Metadata.Status && mapped != KeyStatusProviderError || IsErrorCode(err, ErrorCodeProviderError) && mapped == KeyStatusProviderError
}

// verifySignatureDigest verifies one decoded signature over the algorithm's
// Section 12.8 message representative.
func verifySignatureDigest(algorithm Algorithm, material any, representative []byte, signatureBytes []byte, target Target, index int) error {
	err := cryptodkim2.VerifyRepresentative(algorithm, material, representative, signatureBytes, cryptodkim2.DefaultLimits())
	if err == nil {
		return nil
	}
	switch cryptodkim2.ErrorCodeOf(err) {
	case cryptodkim2.ErrorCodeUnsupportedAlgorithm:
		return unsupportedAlgorithmError(algorithm)
	case cryptodkim2.ErrorCodeWrongKeyType:
		return wrongKeyTypeError(algorithm)
	case cryptodkim2.ErrorCodeInvalidKey:
		return invalidKeyError(algorithm)
	case cryptodkim2.ErrorCodeKeyPolicyRejected:
		return keyPolicyRejectedError(algorithm)
	default:
		return signatureMismatchError(algorithm, target, index)
	}
}

// signatureSetStatusFromKeyError maps key errors into signature-set facts.
func signatureSetStatusFromKeyError(
	err error,
	status KeyStatus,
	failureClass ProviderFailureClass,
) (SignatureSetStatus, KeyStatus) {
	switch failureClass {
	case ProviderFailureTemporary:
		return SignatureSetStatusProviderTemporary, KeyStatusProviderTemporary
	case ProviderFailurePermanent:
		return SignatureSetStatusProviderPermanent, KeyStatusProviderPermanent
	case ProviderFailureContract:
		return SignatureSetStatusProviderContract, KeyStatusProviderContract
	}
	switch {
	case IsErrorCode(err, ErrorCodeMissingKey):
		return SignatureSetStatusMissingKey, KeyStatusMissing
	case IsErrorCode(err, ErrorCodeAmbiguousKey):
		return SignatureSetStatusAmbiguousKey, KeyStatusAmbiguous
	case IsErrorCode(err, ErrorCodeWrongKeyType):
		return SignatureSetStatusWrongKeyType, KeyStatusWrongType
	case IsErrorCode(err, ErrorCodeKeyPolicyRejected):
		return SignatureSetStatusKeyPolicyRejected, KeyStatusPolicyRejected
	case IsErrorCode(err, ErrorCodeUnsupportedAlgorithm):
		return SignatureSetStatusUnsupportedAlgorithm, KeyStatusUnsupportedAlgorithm
	case IsErrorCode(err, ErrorCodeDisabledAlgorithm):
		return SignatureSetStatusDisabledAlgorithm, KeyStatusDisabledAlgorithm
	case IsErrorCode(err, ErrorCodeProviderError):
		return SignatureSetStatusProviderError, KeyStatusProviderError
	case IsErrorCode(err, ErrorCodeInvalidKey):
		return SignatureSetStatusInvalidKey, KeyStatusInvalid
	case status.Known():
		return signatureSetStatusFromKeyStatus(status), status
	default:
		return SignatureSetStatusProviderError, KeyStatusProviderError
	}
}

// signatureSetStatusFromKeyStatus maps provider key status into signature-set status.
func signatureSetStatusFromKeyStatus(status KeyStatus) SignatureSetStatus {
	switch status {
	case KeyStatusMissing:
		return SignatureSetStatusMissingKey
	case KeyStatusAmbiguous:
		return SignatureSetStatusAmbiguousKey
	case KeyStatusRevoked:
		return SignatureSetStatusRevokedKey
	case KeyStatusUnsupportedKeyType:
		return SignatureSetStatusUnsupportedKeyType
	case KeyStatusAlgorithmMismatch:
		return SignatureSetStatusKeyAlgorithmMismatch
	case KeyStatusWrongType:
		return SignatureSetStatusWrongKeyType
	case KeyStatusPolicyRejected:
		return SignatureSetStatusKeyPolicyRejected
	case KeyStatusUnsupportedAlgorithm:
		return SignatureSetStatusUnsupportedAlgorithm
	case KeyStatusDisabledAlgorithm:
		return SignatureSetStatusDisabledAlgorithm
	case KeyStatusInvalid:
		return SignatureSetStatusInvalidKey
	case KeyStatusProviderTemporary:
		return SignatureSetStatusProviderTemporary
	case KeyStatusProviderPermanent:
		return SignatureSetStatusProviderPermanent
	case KeyStatusProviderContract:
		return SignatureSetStatusProviderContract
	default:
		return SignatureSetStatusProviderError
	}
}

// signatureCheckResult constructs one bounded crypto check fact.
func signatureCheckResult(set SignatureSetResult, target Target) CheckResult {
	status := CheckStatusFail
	code := ErrorCodeSignatureMismatch
	providerClass := ProviderFailureClass("")
	switch set.Status {
	case SignatureSetStatusPass:
		status = CheckStatusPass
		code = ""
	case SignatureSetStatusUnsupportedAlgorithm:
		status = CheckStatusUnsupported
		code = ErrorCodeUnsupportedAlgorithm
	case SignatureSetStatusDisabledAlgorithm:
		code = ErrorCodeDisabledAlgorithm
	case SignatureSetStatusMissingKey:
		code = ErrorCodeMissingKey
	case SignatureSetStatusInvalidKey:
		code = ErrorCodeInvalidKey
	case SignatureSetStatusRevokedKey:
		code = ErrorCodeRevokedKey
	case SignatureSetStatusUnsupportedKeyType:
		code = ErrorCodeUnsupportedKeyType
	case SignatureSetStatusKeyAlgorithmMismatch:
		code = ErrorCodeKeyAlgorithmMismatch
	case SignatureSetStatusWrongKeyType:
		code = ErrorCodeWrongKeyType
	case SignatureSetStatusKeyPolicyRejected:
		code = ErrorCodeKeyPolicyRejected
	case SignatureSetStatusProviderError:
		code = ErrorCodeProviderError
	case SignatureSetStatusProviderTemporary, SignatureSetStatusProviderPermanent, SignatureSetStatusProviderContract:
		code = ErrorCodeProviderError
		switch set.Status {
		case SignatureSetStatusProviderTemporary:
			providerClass = ProviderFailureTemporary
		case SignatureSetStatusProviderPermanent:
			providerClass = ProviderFailurePermanent
		default:
			providerClass = ProviderFailureContract
		}
	case SignatureSetStatusAmbiguousKey:
		code = ErrorCodeAmbiguousKey
	}

	return CheckResult{
		Kind:                 CheckKindSignature,
		Status:               status,
		Code:                 code,
		Algorithm:            set.Algorithm,
		ProviderFailureClass: providerClass,
		Target:               target,
	}
}
