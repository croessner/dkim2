package verify

import (
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
)

const sha256DigestLength = 32

const hashCheckResultsRedactedText = "verify.hashCheckResults{redacted}"

type hashCheckResults struct {
	body                 CheckResult
	header               CheckResult
	pass                 bool
	canonicalWork        int
	localHeaderSHA256    [sha256DigestLength]byte
	hasLocalHeaderSHA256 bool
	localBodySHA256      [sha256DigestLength]byte
	hasLocalBodySHA256   bool
}

// String returns a constant representation without authenticated digest bytes.
func (hashCheckResults) String() string { return hashCheckResultsRedactedText }

// GoString returns a constant representation without authenticated digest bytes.
func (hashCheckResults) GoString() string { return hashCheckResultsRedactedText }

// Format prevents formatting from traversing authenticated digest bytes.
func (hashCheckResults) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, hashCheckResultsRedactedText)
}

// compareTargetHashes requires every supported advertised hash tuple to match.
func compareTargetHashes(canonicalizer canonical.Canonicalizer, message rawmsg.Message, targetInstance instance.MessageInstance, target Target) (hashCheckResults, error) {
	sets, selection := targetInstance.SupportedHashSets()
	if selection != instance.HashSelectionStatusSelected {
		status, code := checkStatusForHashSelection(selection)
		return hashCheckResults{body: hashCheckResult(CheckKindBodyHash, status, code, HashStatusUnsupported, target), header: hashCheckResult(CheckKindHeaderHash, status, code, HashStatusUnsupported, target)}, nil
	}
	bodyInput, err := canonicalizer.BodyHashInputFromMessage(message)
	if err != nil {
		return hashCheckResults{}, malformedStateError(CheckKindBodyHash, target, err)
	}
	headerInput, err := canonicalizer.HeaderHashInputFromMessage(message)
	if err != nil {
		return hashCheckResults{}, malformedStateError(CheckKindHeaderHash, target, err)
	}
	bodyStatus, bodyCode := CheckStatusPass, ErrorCode("")
	headerStatus, headerCode := CheckStatusPass, ErrorCode("")
	for _, set := range sets {
		algorithm, ok := canonicalHashAlgorithm(set.Name())
		if !ok {
			return hashCheckResults{}, malformedStateError(CheckKindHeaderHash, target, nil)
		}
		digester, newErr := canonical.NewCanonicalizer(canonical.WithLimits(canonicalizer.Options().Limits), canonical.WithHashAlgorithm(algorithm))
		if newErr != nil {
			return hashCheckResults{}, malformedStateError(CheckKindHeaderHash, target, newErr)
		}
		bodyDigest, bodyErr := digester.Digest(bodyInput)
		headerDigest, headerErr := digester.Digest(headerInput)
		expectedBody, bodyOK := set.BodyHash()
		expectedHeader, headerOK := set.HeaderHash()
		if bodyErr != nil || headerErr != nil || !bodyOK || !headerOK {
			return hashCheckResults{}, malformedStateError(CheckKindHeaderHash, target, nil)
		}
		if compared, comparedCode := compareDigest(bodyDigest.Bytes(), expectedBody.Decoded()); compared != CheckStatusPass {
			bodyStatus, bodyCode = compared, comparedCode
		}
		if compared, comparedCode := compareDigest(headerDigest.Bytes(), expectedHeader.Decoded()); compared != CheckStatusPass {
			headerStatus, headerCode = compared, comparedCode
		}
	}
	local, err := canonical.NewCanonicalizer(canonical.WithLimits(canonicalizer.Options().Limits), canonical.WithHashAlgorithm(canonical.HashAlgorithmSHA256))
	if err != nil {
		return hashCheckResults{}, malformedStateError(CheckKindHeaderHash, target, err)
	}
	localHeader, err := local.Digest(headerInput)
	if err != nil || localHeader.Len() != sha256DigestLength {
		return hashCheckResults{}, malformedStateError(CheckKindHeaderHash, target, err)
	}
	localBody, err := local.Digest(bodyInput)
	if err != nil || localBody.Len() != sha256DigestLength {
		return hashCheckResults{}, malformedStateError(CheckKindBodyHash, target, err)
	}
	results := hashCheckResults{body: hashCheckResult(CheckKindBodyHash, bodyStatus, bodyCode, hashStatusFromCheck(bodyStatus), target), header: hashCheckResult(CheckKindHeaderHash, headerStatus, headerCode, hashStatusFromCheck(headerStatus), target), pass: bodyStatus == CheckStatusPass && headerStatus == CheckStatusPass, canonicalWork: canonicalWorkBytes(bodyInput) + canonicalWorkBytes(headerInput)}
	copy(results.localHeaderSHA256[:], localHeader.Bytes())
	results.hasLocalHeaderSHA256 = true
	copy(results.localBodySHA256[:], localBody.Bytes())
	results.hasLocalBodySHA256 = true
	return results, nil
}

// compareTargetHeaderHash requires every supported retained-header tuple to match.
func compareTargetHeaderHash(canonicalizer canonical.Canonicalizer, message rawmsg.Message, targetInstance instance.MessageInstance, target Target) (headerHashCheckResult, error) {
	sets, selection := targetInstance.SupportedHashSets()
	if selection != instance.HashSelectionStatusSelected {
		status, code := checkStatusForHashSelection(selection)
		return headerHashCheckResult{check: hashCheckResult(CheckKindHeaderHash, status, code, HashStatusUnsupported, target)}, nil
	}
	headerInput, err := canonicalizer.HeaderHashInputFromMessage(message)
	if err != nil {
		return headerHashCheckResult{}, malformedStateError(CheckKindHeaderHash, target, err)
	}
	status, code := CheckStatusPass, ErrorCode("")
	for _, set := range sets {
		algorithm, ok := canonicalHashAlgorithm(set.Name())
		if !ok {
			return headerHashCheckResult{}, malformedStateError(CheckKindHeaderHash, target, nil)
		}
		digester, newErr := canonical.NewCanonicalizer(canonical.WithLimits(canonicalizer.Options().Limits), canonical.WithHashAlgorithm(algorithm))
		if newErr != nil {
			return headerHashCheckResult{}, malformedStateError(CheckKindHeaderHash, target, newErr)
		}
		digest, digestErr := digester.Digest(headerInput)
		expected, expectedOK := set.HeaderHash()
		if digestErr != nil || !expectedOK {
			return headerHashCheckResult{}, malformedStateError(CheckKindHeaderHash, target, digestErr)
		}
		if compared, comparedCode := compareDigest(digest.Bytes(), expected.Decoded()); compared != CheckStatusPass {
			status, code = compared, comparedCode
		}
	}
	return headerHashCheckResult{check: hashCheckResult(CheckKindHeaderHash, status, code, hashStatusFromCheck(status), target), pass: status == CheckStatusPass}, nil
}

type headerHashCheckResult struct {
	check CheckResult
	pass  bool
}

// canonicalWorkBytes charges at least all scanned input even when canonical output collapses.
func canonicalWorkBytes(input canonical.ByteInput) int {
	return max(input.Len(), input.Metadata().InputBytes)
}

// canonicalHashAlgorithm maps parser-owned known names to canonical digest algorithms.
func canonicalHashAlgorithm(name string) (canonical.HashAlgorithm, bool) {
	algorithm := canonical.HashAlgorithm(name)
	return algorithm, algorithm.Known()
}

// compareDigest compares equal-length digest byte slices fail closed.
func compareDigest(current, expected []byte) (CheckStatus, ErrorCode) {
	if len(current) == 0 || len(current) != len(expected) {
		return CheckStatusFail, ErrorCodeMalformedState
	}
	if subtle.ConstantTimeCompare(current, expected) != 1 {
		return CheckStatusFail, ErrorCodeHashMismatch
	}
	return CheckStatusPass, ""
}

// checkStatusForHashSelection maps parser selection state to check facts.
func checkStatusForHashSelection(selection instance.HashSelectionStatus) (CheckStatus, ErrorCode) {
	if selection == instance.HashSelectionStatusUnsupported {
		return CheckStatusUnsupported, ErrorCodeUnsupportedAlgorithm
	}
	return CheckStatusFail, ErrorCodeMalformedState
}

// hashCheckResult constructs one bounded hash check fact.
func hashCheckResult(kind CheckKind, status CheckStatus, code ErrorCode, hashStatus HashStatus, target Target) CheckResult {
	return CheckResult{Kind: kind, Status: status, Code: code, HashStatus: hashStatus, Target: target}
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
