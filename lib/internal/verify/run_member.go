package verify

import (
	"context"

	"github.com/croessner/dkim2/internal/canonical"
)

// RunMemberOutcome is the closed result of verifying embedded run members.
type RunMemberOutcome string

const (
	// RunMemberVerified reports that every requested signature verified cryptographically.
	RunMemberVerified RunMemberOutcome = "verified"
	// RunMemberUnverified reports at least one requested signature that did not verify.
	RunMemberUnverified RunMemberOutcome = "unverified"
	// RunMemberTemporary reports a typed temporary key-provider failure before a permanent answer.
	RunMemberTemporary RunMemberOutcome = "temporary"
)

// Known reports whether the outcome belongs to the closed vocabulary.
func (o RunMemberOutcome) Known() bool {
	return o == RunMemberVerified || o == RunMemberUnverified || o == RunMemberTemporary
}

// VerifyEmbeddedSignatures verifies the named non-highest DKIM2-Signature
// sequences of an already extracted embedded original over the Section 9.6
// fields they cover. The fields are present in the embedded original as is,
// so no historical reconstruction is needed. It applies the same bounded key
// lookup order and set semantics as the all-hop revision proof and does not
// evaluate timestamps or envelopes: run members are the local system's own
// signatures whose cryptographic integrity is the only fact this seam
// establishes.
func (v Verifier) VerifyEmbeddedSignatures(ctx context.Context, embedded EmbeddedInput, sequences []uint64) (RunMemberOutcome, error) {
	if ctx == nil || !v.valid() || !embedded.Valid() {
		return "", newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(sequences) == 0 {
		return RunMemberVerified, nil
	}
	input := embedded.input
	message := input.request.Message
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		return "", malformedStateError(CheckKindSignature, Target{}, err)
	}
	for _, sequence := range sequences {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		parsed, err := signatureBySequence(input.signatures, sequence)
		if err != nil {
			return "", err
		}
		target := Target{Sequence: parsed.Sequence(), InstanceNumber: parsed.InstanceNumber()}
		digest, err := signatureInputDigest(canonicalizer, message, target)
		if err != nil {
			return "", err
		}
		plan, outcome := v.prepareRevisionSignatureSets(parsed)
		if outcome != "" {
			return RunMemberUnverified, nil
		}
		evaluation := v.evaluateRevisionSignatureSets(ctx, parsed, digest, target, plan)
		if err := ctx.Err(); err != nil {
			return "", err
		}
		switch revisionSignatureOutcome(evaluation) {
		case RevisionProofVerified:
		case RevisionProofProviderTemporary:
			return RunMemberTemporary, nil
		default:
			return RunMemberUnverified, nil
		}
	}
	return RunMemberVerified, nil
}
