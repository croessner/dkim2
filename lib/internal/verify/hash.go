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

// compareTargetHashes compares current SHA-256 hashes with the target instance.
func compareTargetHashes(canonicalizer canonical.Canonicalizer, message rawmsg.Message, targetInstance instance.MessageInstance, target Target) (hashCheckResults, error) {
	hashSet, hashState := targetSHA256HashSet(targetInstance)
	if hashState != HashStatusPass {
		status, code := checkStatusForHashState(hashState)

		return hashCheckResults{
			body:   hashCheckResult(CheckKindBodyHash, status, code, hashState, target),
			header: hashCheckResult(CheckKindHeaderHash, status, code, hashState, target),
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
			body:   hashCheckResult(CheckKindBodyHash, CheckStatusFail, ErrorCodeMalformedState, HashStatusInvalid, target),
			header: hashCheckResult(CheckKindHeaderHash, CheckStatusFail, ErrorCodeMalformedState, HashStatusInvalid, target),
		}, nil
	}
	expectedHeaderHash, ok := hashSet.HeaderHash()
	if !ok {
		return hashCheckResults{
			body:   hashCheckResult(CheckKindBodyHash, CheckStatusFail, ErrorCodeMalformedState, HashStatusInvalid, target),
			header: hashCheckResult(CheckKindHeaderHash, CheckStatusFail, ErrorCodeMalformedState, HashStatusInvalid, target),
		}, nil
	}

	bodyStatus, bodyCode := compareSHA256Digest(bodyDigest.Bytes(), expectedBodyHash.Decoded())
	headerStatus, headerCode := compareSHA256Digest(headerDigest.Bytes(), expectedHeaderHash.Decoded())

	return hashCheckResults{
		body:   hashCheckResult(CheckKindBodyHash, bodyStatus, bodyCode, hashStatusFromCheck(bodyStatus), target),
		header: hashCheckResult(CheckKindHeaderHash, headerStatus, headerCode, hashStatusFromCheck(headerStatus), target),
		pass:   bodyStatus == CheckStatusPass && headerStatus == CheckStatusPass,
	}, nil
}

// targetSHA256HashSet finds the known sha256 hash set for an instance.
func targetSHA256HashSet(targetInstance instance.MessageInstance) (instance.HashSet, HashStatus) {
	hashSet, status := targetInstance.SHA256HashSet()
	switch status {
	case instance.HashSelectionStatusSelected:
		return hashSet, HashStatusPass
	case instance.HashSelectionStatusUnsupported:
		return instance.HashSet{}, HashStatusUnsupported
	default:
		return instance.HashSet{}, HashStatusMissingSHA256
	}
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
func hashCheckResult(kind CheckKind, status CheckStatus, code ErrorCode, hashStatus HashStatus, target Target) CheckResult {
	return CheckResult{
		Kind:       kind,
		Status:     status,
		Code:       code,
		HashStatus: hashStatus,
		Target:     target,
	}
}

// hashStatusFromCheck maps digest comparison state to the typed hash vocabulary.
func hashStatusFromCheck(status CheckStatus) HashStatus {
	if status == CheckStatusPass {
		return HashStatusPass
	}
	if status == CheckStatusFail {
		return HashStatusMismatch
	}
	return HashStatusInvalid
}
