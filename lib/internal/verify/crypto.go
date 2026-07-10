package verify

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
)

type signatureEvaluation struct {
	checks  []CheckResult
	sets    []SignatureSetResult
	pass    int
	fail    int
	other   int
	ignored int
}

// signatureInputDigest calculates SHA-256 over M3 Section 9.6 input bytes.
func signatureInputDigest(canonicalizer canonical.Canonicalizer, message rawmsg.Message, target Target) ([]byte, error) {
	signatureInput, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{
		Headers:        message.Headers(),
		TargetSequence: target.Sequence,
	})
	if err != nil {
		return nil, malformedStateError(CheckKindSignature, target, err)
	}
	digest, err := canonicalizer.SHA256Digest(signatureInput)
	if err != nil {
		return nil, malformedStateError(CheckKindSignature, target, err)
	}

	return digest.Bytes(), nil
}

// evaluateSignatureSets checks every signature set for the selected target.
func (v Verifier) evaluateSignatureSets(ctx context.Context, targetSignature signature.Signature, digest []byte, target Target) signatureEvaluation {
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
		setResult := v.evaluateSignatureSet(ctx, targetSignature, set, index, digest, target)
		evaluation.sets = append(evaluation.sets, setResult)
		evaluation.checks = append(evaluation.checks, signatureCheckResult(setResult, target))
		switch setResult.Status {
		case SignatureSetStatusPass:
			evaluation.pass++
		case SignatureSetStatusFail, SignatureSetStatusInvalidKey, SignatureSetStatusWrongKeyType, SignatureSetStatusKeyPolicyRejected, SignatureSetStatusProviderError, SignatureSetStatusAmbiguousKey:
			evaluation.fail++
		case SignatureSetStatusUnsupportedAlgorithm:
			evaluation.ignored++
		default:
			evaluation.other++
		}
	}

	return evaluation
}

// evaluateSignatureSet checks one selector:algorithm:signature tuple.
func (v Verifier) evaluateSignatureSet(ctx context.Context, targetSignature signature.Signature, set signature.Set, index int, digest []byte, target Target) SignatureSetResult {
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
	if err != nil {
		result.Status, result.KeyStatus = signatureSetStatusFromKeyError(err, key.Metadata.Status)

		return result
	}
	if key.Algorithm != algorithm || key.Metadata.Status != KeyStatusFound {
		result.Status = SignatureSetStatusInvalidKey
		result.KeyStatus = KeyStatusInvalid

		return result
	}

	material, keyStatus, err := validatePublicKeyMaterial(algorithm, key.Material, v.options.AlgorithmPolicy)
	if err != nil {
		result.Status, result.KeyStatus = signatureSetStatusFromKeyError(err, keyStatus)

		return result
	}

	result.KeyStatus = KeyStatusFound
	if err := verifySignatureDigest(algorithm, material, digest, set.Signature().Decoded(), target, index); err != nil {
		result.Status = SignatureSetStatusFail

		return result
	}

	result.Status = SignatureSetStatusPass

	return result
}

// verifySignatureDigest verifies one decoded signature over Section 9.6 digest bytes.
func verifySignatureDigest(algorithm Algorithm, material any, digest []byte, signatureBytes []byte, target Target, index int) error {
	switch algorithm {
	case AlgorithmRSASHA256:
		key, ok := material.(*rsa.PublicKey)
		if !ok {
			return wrongKeyTypeError(algorithm)
		}

		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, signatureBytes)
	case AlgorithmEd25519SHA256:
		key, ok := material.(ed25519.PublicKey)
		if !ok {
			return wrongKeyTypeError(algorithm)
		}
		if !ed25519.Verify(key, digest, signatureBytes) {
			return signatureMismatchError(algorithm, target, index)
		}

		return nil
	default:
		return unsupportedAlgorithmError(algorithm)
	}
}

// signatureSetStatusFromKeyError maps key errors into signature-set facts.
func signatureSetStatusFromKeyError(err error, status KeyStatus) (SignatureSetStatus, KeyStatus) {
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
	default:
		return SignatureSetStatusProviderError
	}
}

// signatureCheckResult constructs one bounded crypto check fact.
func signatureCheckResult(set SignatureSetResult, target Target) CheckResult {
	status := CheckStatusFail
	code := ErrorCodeSignatureMismatch
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
	case SignatureSetStatusWrongKeyType:
		code = ErrorCodeWrongKeyType
	case SignatureSetStatusKeyPolicyRejected:
		code = ErrorCodeKeyPolicyRejected
	case SignatureSetStatusProviderError:
		code = ErrorCodeProviderError
	case SignatureSetStatusAmbiguousKey:
		code = ErrorCodeAmbiguousKey
	}

	return CheckResult{
		Kind:      CheckKindSignature,
		Status:    status,
		Code:      code,
		Algorithm: set.Algorithm,
		Target:    target,
	}
}
