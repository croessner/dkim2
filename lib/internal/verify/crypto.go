package verify

import (
	"context"
	"errors"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/cryptodkim2"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
)

type signatureEvaluation struct {
	checks    []CheckResult
	sets      []SignatureSetResult
	pass      int
	fail      int
	other     int
	temporary int
	ignored   int
}

// signatureDigests holds the Section 12.8 signature-input digests: SHA-256
// for rsa-sha256 and ed25519-sha256, SHA-512 for mldsa44-ed25519-sha512.
type signatureDigests struct {
	sha256 []byte
	sha512 []byte
}

// forAlgorithm returns the digest the algorithm signs, or nil for an
// algorithm without a digest contract.
func (d signatureDigests) forAlgorithm(algorithm Algorithm) []byte {
	switch algorithm {
	case signature.AlgorithmRSASHA256, signature.AlgorithmEd25519SHA256:
		return d.sha256
	case signature.AlgorithmMLDSA44Ed25519SHA512:
		return d.sha512
	default:
		return nil
	}
}

// computeSignatureDigests derives both signature-input digests from one
// canonical Section 12.8 input.
func computeSignatureDigests(canonicalizer canonical.Canonicalizer, input canonical.ByteInput) (signatureDigests, error) {
	sha256Digest, err := canonicalizer.SHA256Digest(input)
	if err != nil {
		return signatureDigests{}, err
	}
	sha512Digest, err := canonicalizer.SHA512Digest(input)
	if err != nil {
		return signatureDigests{}, err
	}
	return signatureDigests{sha256: sha256Digest.Bytes(), sha512: sha512Digest.Bytes()}, nil
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

// evaluateSignatureSets checks every signature set for the selected target.
func (v Verifier) evaluateSignatureSets(ctx context.Context, targetSignature signature.Signature, digests signatureDigests, target Target) signatureEvaluation {
	sets := targetSignature.SignatureSets()
	evaluation := signatureEvaluation{
		checks: make([]CheckResult, 0, len(sets)),
		sets:   make([]SignatureSetResult, 0, len(sets)),
	}
	if len(sets) > v.options.Limits.MaxSignatureSets {
		evaluation.checks = append(evaluation.checks, CheckResult{
			Kind:   CheckKindSignature,
			Status: CheckStatusFail,
			Code:   ErrorCodeLimitExceeded,
			Target: target,
		})
		evaluation.fail++

		return evaluation
	}

	for index, set := range sets {
		if ctx == nil || ctx.Err() != nil {
			break
		}
		setResult := v.evaluateSignatureSet(ctx, targetSignature, set, index, digests, target)
		evaluation.sets = append(evaluation.sets, setResult)
		evaluation.checks = append(evaluation.checks, signatureCheckResult(setResult, target))
		evaluation.account(setResult)
		if ctx.Err() != nil {
			break
		}
	}

	return evaluation
}

// account records one evaluated set in the closed aggregate result buckets.
func (e *signatureEvaluation) account(setResult SignatureSetResult) {
	switch setResult.Status {
	case SignatureSetStatusPass:
		e.pass++
	case SignatureSetStatusFail, SignatureSetStatusInvalidKey, SignatureSetStatusWrongKeyType, SignatureSetStatusKeyPolicyRejected, SignatureSetStatusProviderError, SignatureSetStatusProviderPermanent, SignatureSetStatusProviderContract, SignatureSetStatusAmbiguousKey, SignatureSetStatusRevokedKey, SignatureSetStatusUnsupportedKeyType, SignatureSetStatusKeyAlgorithmMismatch:
		e.fail++
	case SignatureSetStatusProviderTemporary:
		e.temporary++
	case SignatureSetStatusUnsupportedAlgorithm:
		e.ignored++
	default:
		e.other++
	}
}

// evaluateSignatureSet checks one selector:algorithm:signature tuple.
func (v Verifier) evaluateSignatureSet(ctx context.Context, targetSignature signature.Signature, set signature.Set, index int, digests signatureDigests, target Target) SignatureSetResult {
	algorithm := Algorithm(set.Algorithm())
	result := SignatureSetResult{
		Index:     index,
		Algorithm: algorithm,
		Status:    SignatureSetStatusNotChecked,
		KeyStatus: KeyStatusNotChecked,
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
		result.Selector = set.Selector()

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

// verifySignatureDigest verifies one decoded signature over Section 12.8 digest bytes.
func verifySignatureDigest(algorithm Algorithm, material any, digest []byte, signatureBytes []byte, target Target, index int) error {
	err := cryptodkim2.VerifyDigest(algorithm, material, digest, signatureBytes, cryptodkim2.DefaultLimits())
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
