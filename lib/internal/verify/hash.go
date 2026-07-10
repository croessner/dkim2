package verify

import (
	"crypto/subtle"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
)

const sha256DigestLength = 32

type hashCheckResults struct {
	body   CheckResult
	header CheckResult
	pass   bool
}

// compareTargetHashes compares current M3 sha256 hashes with the target instance.
func compareTargetHashes(canonicalizer canonical.Canonicalizer, message rawmsg.Message, targetInstance instance.MessageInstance, target Target) (hashCheckResults, error) {
	hashSet, hashState := targetSHA256HashSet(targetInstance)
	if hashState != HashStatusPass {
		status, code := checkStatusForHashState(hashState)

		return hashCheckResults{
			body:   hashCheckResult(CheckKindBodyHash, status, code, target),
			header: hashCheckResult(CheckKindHeaderHash, status, code, target),
		}, nil
	}

	bodyResult, err := canonicalizer.BodyHashFromMessage(message)
	if err != nil {
		return hashCheckResults{}, malformedStateError(CheckKindBodyHash, target, err)
	}
	bodyDigest, ok := bodyResult.Digest()
	if !ok {
		return hashCheckResults{}, malformedStateError(CheckKindBodyHash, target, nil)
	}
	headerResult, err := canonicalizer.HeaderHashFromMessage(message)
	if err != nil {
		return hashCheckResults{}, malformedStateError(CheckKindHeaderHash, target, err)
	}
	headerDigest, ok := headerResult.Digest()
	if !ok {
		return hashCheckResults{}, malformedStateError(CheckKindHeaderHash, target, nil)
	}

	expectedBodyHash, ok := hashSet.BodyHash()
	if !ok {
		return hashCheckResults{
			body:   hashCheckResult(CheckKindBodyHash, CheckStatusFail, ErrorCodeMalformedState, target),
			header: hashCheckResult(CheckKindHeaderHash, CheckStatusFail, ErrorCodeMalformedState, target),
		}, nil
	}
	expectedHeaderHash, ok := hashSet.HeaderHash()
	if !ok {
		return hashCheckResults{
			body:   hashCheckResult(CheckKindBodyHash, CheckStatusFail, ErrorCodeMalformedState, target),
			header: hashCheckResult(CheckKindHeaderHash, CheckStatusFail, ErrorCodeMalformedState, target),
		}, nil
	}

	bodyStatus, bodyCode := compareSHA256Digest(bodyDigest.Bytes(), expectedBodyHash.Decoded())
	headerStatus, headerCode := compareSHA256Digest(headerDigest.Bytes(), expectedHeaderHash.Decoded())

	return hashCheckResults{
		body:   hashCheckResult(CheckKindBodyHash, bodyStatus, bodyCode, target),
		header: hashCheckResult(CheckKindHeaderHash, headerStatus, headerCode, target),
		pass:   bodyStatus == CheckStatusPass && headerStatus == CheckStatusPass,
	}, nil
}

// targetSHA256HashSet finds the known sha256 hash set for an instance.
func targetSHA256HashSet(targetInstance instance.MessageInstance) (instance.HashSet, HashStatus) {
	hashSets := targetInstance.HashSets()
	if len(hashSets) == 0 {
		return instance.HashSet{}, HashStatusMissingSHA256
	}

	sawUnknown := false
	for _, hashSet := range hashSets {
		if hashSet.Name() != instance.HashAlgorithmSHA256 {
			if !hashSet.Known() {
				sawUnknown = true
			}
			continue
		}
		if !hashSet.Known() {
			return instance.HashSet{}, HashStatusInvalid
		}

		return hashSet, HashStatusPass
	}
	if sawUnknown {
		return instance.HashSet{}, HashStatusUnsupported
	}

	return instance.HashSet{}, HashStatusMissingSHA256
}

// compareSHA256Digest compares two fixed-size digest byte slices fail closed.
func compareSHA256Digest(current []byte, expected []byte) (CheckStatus, ErrorCode) {
	if len(current) != sha256DigestLength || len(expected) != sha256DigestLength {
		return CheckStatusFail, ErrorCodeMalformedState
	}
	if subtle.ConstantTimeCompare(current, expected) != 1 {
		return CheckStatusFail, ErrorCodeHashMismatch
	}

	return CheckStatusPass, ""
}

// checkStatusForHashState maps hash-state vocabulary to check facts.
func checkStatusForHashState(status HashStatus) (CheckStatus, ErrorCode) {
	switch status {
	case HashStatusUnsupported:
		return CheckStatusUnsupported, ErrorCodeUnsupportedAlgorithm
	case HashStatusMissingSHA256:
		return CheckStatusFail, ErrorCodeMissingTarget
	case HashStatusInvalid:
		return CheckStatusFail, ErrorCodeMalformedState
	default:
		return CheckStatusFail, ErrorCodeMalformedState
	}
}

// hashCheckResult constructs one bounded hash check fact.
func hashCheckResult(kind CheckKind, status CheckStatus, code ErrorCode, target Target) CheckResult {
	return CheckResult{
		Kind:   kind,
		Status: status,
		Code:   code,
		Target: target,
	}
}
