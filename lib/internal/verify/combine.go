package verify

import (
	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/combine"
	"github.com/croessner/dkim2/internal/instance"
)

// signatureSetIntermediate maps one evaluated signature set onto its
// Draft-08 Section 14.6 intermediate result: PASS for a verified signature,
// FAIL for a signature mismatch, TEMPERROR for a temporarily unavailable
// key, and PERMERROR for every permanent key or provider error, for an
// algorithm this verifier does not implement (step 4, decided without a key
// lookup), and for an algorithm local policy disables.
func signatureSetIntermediate(status SignatureSetStatus) combine.Result {
	switch status {
	case SignatureSetStatusPass:
		return combine.ResultPass
	case SignatureSetStatusFail:
		return combine.ResultFail
	case SignatureSetStatusProviderTemporary:
		return combine.ResultTempError
	default:
		return combine.ResultPermError
	}
}

// CombineSignatureSets is the single owner of the Section 14.6 signature
// algebra for verification facts. It places each per-set result at its
// field-order Index and combines them under the parsed sig-any/sig-all
// layout; the outcome's decisive index is that field-order Index. Duplicate
// or missing indexes make the outcome invalid. Current verification,
// inherited and revision signatures, the headers-only DSN check, and the
// service mapping all use it.
func CombineSignatureSets(layout combine.Layout, sets []SignatureSetResult) combine.Outcome {
	intermediates := make([]combine.Result, len(sets))
	for _, set := range sets {
		if set.Index < 0 || set.Index >= len(sets) || intermediates[set.Index] != 0 {
			return combine.Outcome{}
		}
		intermediates[set.Index] = signatureSetIntermediate(set.Status)
	}
	return combine.Signatures(layout, intermediates)
}

// SignatureSetAt returns the set with the given field-order Index, the
// lookup for a combination outcome's decisive set.
func SignatureSetAt(sets []SignatureSetResult, index int) (SignatureSetResult, bool) {
	for _, set := range sets {
		if set.Index == index {
			return set, true
		}
	}
	return SignatureSetResult{}, false
}

// hashEvaluation is the Section 14.7 outcome of one Message-Instance h=
// value against one reconstructed message state.
type hashEvaluation struct {
	outcome combine.Outcome
	// headerMismatch and bodyMismatch describe the decisive set of a FAIL
	// outcome: which of its two hashes did not match.
	headerMismatch bool
	bodyMismatch   bool
}

// pass reports whether the h= combination passed.
func (e hashEvaluation) pass() bool { return e.outcome.Pass() }

// permanentError reports whether the h= combination is PERMERROR, that is,
// unsupported rather than matched or mismatched.
func (e hashEvaluation) permanentError() bool {
	return e.outcome.Result() == combine.ResultPermError
}

// historyDimensions projects the outcome onto the bounded per-dimension
// history vocabulary: matched dimensions for PASS, unsupported dimensions
// for PERMERROR, and the decisive set's mismatching dimensions for FAIL. An
// absent body is reported as unavailable.
func (e hashEvaluation) historyDimensions(bodyKnown bool) (HistoryDimensionState, HistoryDimensionState) {
	header, body := HistoryDimensionMatched, HistoryDimensionMatched
	switch e.outcome.Result() {
	case combine.ResultPass:
	case combine.ResultFail:
		if e.headerMismatch {
			header = HistoryDimensionMismatch
		}
		if e.bodyMismatch {
			body = HistoryDimensionMismatch
		}
	default:
		header, body = HistoryDimensionUnsupported, HistoryDimensionUnsupported
	}
	if !bodyKnown {
		body = HistoryDimensionUnavailable
	}
	return header, body
}

// hashSetMatch records the per-dimension comparison of one hash-set.
type hashSetMatch struct {
	implemented bool
	header      bool
	body        bool
}

// evaluateInstanceHashes is the single owner of the Section 14.7 hash
// algebra. Every hash-set whose algorithm this verifier implements is
// compared against the canonical header input and, when bodyKnown, the body
// input; a set passes when both match. Without a body (Section 16.4 item 3,
// or history below a null Recipe) a set passes when its header hash
// matches. An unimplemented algorithm is a PERMERROR intermediate. The
// per-set intermediates are combined under the parsed hash-any/hash-all
// layout. Digest failures are returned as errors for the caller's own
// fail-closed mapping.
func evaluateInstanceHashes(limits canonical.Limits, parsed instance.MessageInstance, header, body canonical.ByteInput, bodyKnown bool) (hashEvaluation, error) {
	sets := parsed.HashSets()
	matches := make([]hashSetMatch, len(sets))
	intermediates := make([]combine.Result, len(sets))
	for index, set := range sets {
		match, err := compareHashSet(limits, set, header, body, bodyKnown)
		if err != nil {
			return hashEvaluation{}, err
		}
		matches[index] = match
		switch {
		case !match.implemented:
			intermediates[index] = combine.ResultPermError
		case match.header && (!bodyKnown || match.body):
			intermediates[index] = combine.ResultPass
		default:
			intermediates[index] = combine.ResultFail
		}
	}
	outcome := combine.Hashes(parsed.HashLayout(), intermediates)
	if !outcome.Valid() {
		return hashEvaluation{}, malformedStateError(CheckKindHeaderHash, Target{InstanceNumber: parsed.Number()}, nil)
	}
	evaluation := hashEvaluation{outcome: outcome}
	if outcome.Result() == combine.ResultFail {
		decisive := matches[outcome.Decisive()]
		evaluation.headerMismatch = !decisive.header
		evaluation.bodyMismatch = bodyKnown && !decisive.body
	}
	return evaluation, nil
}

// compareHashSet compares one hash-set in constant time per digest.
func compareHashSet(limits canonical.Limits, set instance.HashSet, header, body canonical.ByteInput, bodyKnown bool) (hashSetMatch, error) {
	algorithm, implemented := canonicalHashAlgorithm(set.Name())
	expectedHeader, headerOK := set.HeaderHash()
	expectedBody, bodyOK := set.BodyHash()
	if !set.Known() || !implemented || !headerOK || !bodyOK {
		return hashSetMatch{}, nil
	}
	digester, err := canonical.NewCanonicalizer(canonical.WithLimits(limits), canonical.WithHashAlgorithm(algorithm))
	if err != nil {
		return hashSetMatch{}, err
	}
	headerDigest, err := digester.Digest(header)
	if err != nil {
		return hashSetMatch{}, err
	}
	match := hashSetMatch{implemented: true}
	match.header, _ = compareDigestMatch(headerDigest.Bytes(), expectedHeader.Decoded())
	if !bodyKnown {
		return match, nil
	}
	bodyDigest, err := digester.Digest(body)
	if err != nil {
		return hashSetMatch{}, err
	}
	match.body, _ = compareDigestMatch(bodyDigest.Bytes(), expectedBody.Decoded())
	return match, nil
}

// compareDigestMatch reports whether two digests are equal through the
// constant-time comparison owner.
func compareDigestMatch(current, expected []byte) (bool, ErrorCode) {
	status, code := compareDigest(current, expected)
	return status == CheckStatusPass, code
}

// HashCombinationComputable reports whether at least one hash-set of the
// parsed h= value uses an algorithm this verifier implements, so that the
// Section 14.7 combination depends on a computed digest. When it is false
// every intermediate is PERMERROR and the combination is PERMERROR without
// reconstructing any state; callers use it as a cheap precondition and must
// otherwise evaluate the full combination, where a FAIL intermediate wins
// over PERMERROR.
func HashCombinationComputable(parsed instance.MessageInstance) bool {
	for _, set := range parsed.HashSets() {
		if _, implemented := canonicalHashAlgorithm(set.Name()); set.Known() && implemented {
			return true
		}
	}
	return false
}

// digestFreeHashEvaluation returns the Section 14.7 evaluation of an h=
// value without any implemented hash-set: every intermediate is PERMERROR and
// the outcome is the combination of those intermediates. It reports false
// when a digest is needed, or when the layout is incoherent, so the caller
// falls through to evaluateInstanceHashes and its fail-closed mapping.
func digestFreeHashEvaluation(parsed instance.MessageInstance) (hashEvaluation, bool) {
	if HashCombinationComputable(parsed) {
		return hashEvaluation{}, false
	}
	intermediates := make([]combine.Result, len(parsed.HashSets()))
	for index := range intermediates {
		intermediates[index] = combine.ResultPermError
	}
	outcome := combine.Hashes(parsed.HashLayout(), intermediates)
	if !outcome.Valid() {
		return hashEvaluation{}, false
	}
	return hashEvaluation{outcome: outcome}, true
}
