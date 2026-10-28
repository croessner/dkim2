package verify

import (
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/combine"
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

// compareTargetHashes evaluates the target h= value with the shared Section
// 14.7 algebra over the current header and body. A FAIL marks the
// dimensions in which the decisive hash-set did not match; a PERMERROR (no
// group of implemented algorithms) reports both dimensions unsupported.
func compareTargetHashes(canonicalizer canonical.Canonicalizer, message rawmsg.Message, targetInstance instance.MessageInstance, target Target) (hashCheckResults, error) {
	bodyInput, err := canonicalizer.BodyHashInputFromMessage(message)
	if err != nil {
		return hashCheckResults{}, malformedStateError(CheckKindBodyHash, target, err)
	}
	headerInput, err := canonicalizer.HeaderHashInputFromMessage(message)
	if err != nil {
		return hashCheckResults{}, malformedStateError(CheckKindHeaderHash, target, err)
	}
	evaluation, err := evaluateInstanceHashes(canonicalizer.Options().Limits, targetInstance, headerInput, bodyInput, true)
	if err != nil {
		return hashCheckResults{}, malformedStateError(CheckKindHeaderHash, target, err)
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
	results := hashCheckResults{
		header:        hashDimensionCheck(CheckKindHeaderHash, evaluation, evaluation.headerMismatch, target),
		body:          hashDimensionCheck(CheckKindBodyHash, evaluation, evaluation.bodyMismatch, target),
		pass:          evaluation.pass(),
		canonicalWork: canonicalWorkBytes(bodyInput) + canonicalWorkBytes(headerInput),
	}
	copy(results.localHeaderSHA256[:], localHeader.Bytes())
	results.hasLocalHeaderSHA256 = true
	copy(results.localBodySHA256[:], localBody.Bytes())
	results.hasLocalBodySHA256 = true
	return results, nil
}

// compareTargetHeaderHash evaluates the target h= value for a header-only
// DSN original (Section 16.4 item 3): the Section 14.7 algebra applies with
// a hash-set passing when its header hash matches, because no body exists.
func compareTargetHeaderHash(canonicalizer canonical.Canonicalizer, message rawmsg.Message, targetInstance instance.MessageInstance, target Target) (headerHashCheckResult, error) {
	headerInput, err := canonicalizer.HeaderHashInputFromMessage(message)
	if err != nil {
		return headerHashCheckResult{}, malformedStateError(CheckKindHeaderHash, target, err)
	}
	evaluation, err := evaluateInstanceHashes(canonicalizer.Options().Limits, targetInstance, headerInput, canonical.ByteInput{}, false)
	if err != nil {
		return headerHashCheckResult{}, malformedStateError(CheckKindHeaderHash, target, err)
	}
	return headerHashCheckResult{check: hashDimensionCheck(CheckKindHeaderHash, evaluation, evaluation.headerMismatch, target), pass: evaluation.pass()}, nil
}

// hashDimensionCheck projects one Section 14.7 outcome onto the bounded
// header or body check fact.
func hashDimensionCheck(kind CheckKind, evaluation hashEvaluation, mismatch bool, target Target) CheckResult {
	switch evaluation.outcome.Result() {
	case combine.ResultPass:
		return hashCheckResult(kind, CheckStatusPass, "", HashStatusPass, target)
	case combine.ResultFail:
		if mismatch {
			return hashCheckResult(kind, CheckStatusFail, ErrorCodeHashMismatch, HashStatusMismatch, target)
		}
		return hashCheckResult(kind, CheckStatusPass, "", HashStatusPass, target)
	default:
		return hashCheckResult(kind, CheckStatusUnsupported, ErrorCodeUnsupportedAlgorithm, HashStatusUnsupported, target)
	}
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

// hashCheckResult constructs one bounded hash check fact.
func hashCheckResult(kind CheckKind, status CheckStatus, code ErrorCode, hashStatus HashStatus, target Target) CheckResult {
	return CheckResult{Kind: kind, Status: status, Code: code, HashStatus: hashStatus, Target: target}
}
