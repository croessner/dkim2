package dsn

import (
	"regexp"
	"strings"
	"testing"
)

// receivedVocabularyPins freezes the exact wire spelling of every closed
// projection, stage, and error value so a rename breaks visibly.
const receivedVocabularyPins = `structure=valid
structure=malformed
structure=limit_exceeded
embedded=verified
embedded=verified_headers_only
embedded=unverified
embedded=temperror
embedded=absent
embedded=not_evaluated
local_hop=local
local_hop=not_local
local_hop=mismatch
local_hop=temperror
local_hop=not_evaluated
outer_alignment=aligned
outer_alignment=misaligned
outer_alignment=not_evaluated
recipient_linkage=linked
recipient_linkage=unlinked
recipient_linkage=not_evaluated
propagation=not_applicable
propagation=eligible
propagation=terminal_origin
propagation=not_failure
propagation=forbidden_null_previous_sender
propagation=unsupported_chain
propagation=not_reconstructable
propagation=not_evaluated
stage=preflight
stage=structure
stage=embedded_verification
stage=local_hop
stage=outer_alignment
stage=recipient_linkage
stage=failure_class
stage=previous_hop
error=invalid_request
error=canceled
error=internal`

// receivedVocabularyMember is one closed member with its constants and Known predicate.
type receivedVocabularyMember struct {
	name   string
	values []string
	known  func(string) bool
}

// receivedVocabularyMembers lists every closed vocabulary in projection order.
func receivedVocabularyMembers() []receivedVocabularyMember {
	return []receivedVocabularyMember{
		{name: "structure", values: []string{string(StructureValid), string(StructureMalformed), string(StructureLimitExceeded)},
			known: func(v string) bool { return StructureResult(v).Known() }},
		{name: "embedded", values: []string{string(EmbeddedVerified), string(EmbeddedVerifiedHeadersOnly), string(EmbeddedUnverified), string(EmbeddedTemporaryError), string(EmbeddedAbsent), string(EmbeddedNotEvaluated)},
			known: func(v string) bool { return EmbeddedResult(v).Known() }},
		{name: "local_hop", values: []string{string(LocalHopLocal), string(LocalHopNotLocal), string(LocalHopMismatch), string(LocalHopTemporaryError), string(LocalHopNotEvaluated)},
			known: func(v string) bool { return LocalHopResult(v).Known() }},
		{name: "outer_alignment", values: []string{string(OuterAlignmentAligned), string(OuterAlignmentMisaligned), string(OuterAlignmentNotEvaluated)},
			known: func(v string) bool { return OuterAlignmentResult(v).Known() }},
		{name: "recipient_linkage", values: []string{string(RecipientLinkageLinked), string(RecipientLinkageUnlinked), string(RecipientLinkageNotEvaluated)},
			known: func(v string) bool { return RecipientLinkageResult(v).Known() }},
		{name: "propagation", values: []string{
			string(PropagationNotApplicable), string(PropagationEligible), string(PropagationTerminalOrigin), string(PropagationNotFailure),
			string(PropagationForbiddenNullPreviousSender), string(PropagationUnsupportedChain), string(PropagationNotReconstructable), string(PropagationNotEvaluated),
		}, known: func(v string) bool { return PropagationResult(v).Known() }},
		{name: "stage", values: []string{
			string(ReceivedStagePreflight), string(ReceivedStageStructure), string(ReceivedStageEmbeddedVerification), string(ReceivedStageLocalHop),
			string(ReceivedStageOuterAlignment), string(ReceivedStageRecipientLinkage), string(ReceivedStageFailureClass), string(ReceivedStagePreviousHop),
		}, known: func(v string) bool { return ReceivedStage(v).Known() }},
		{name: "error", values: []string{string(ReceivedErrorInvalidRequest), string(ReceivedErrorCanceled), string(ReceivedErrorInternal)},
			known: func(v string) bool { return ReceivedErrorCode(v).Known() }},
	}
}

// TestReceivedEvaluationVocabulariesAreClosedTokens proves every projection
// value is known, unique within its member, restricted to the RFC 8601 pvalue
// token syntax so a later policy.dsn= property needs no renaming, and spelled
// exactly as the specification tables state.
func TestReceivedEvaluationVocabulariesAreClosedTokens(t *testing.T) {
	token := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	var rendered strings.Builder
	for _, member := range receivedVocabularyMembers() {
		seen := make(map[string]struct{}, len(member.values))
		for _, value := range member.values {
			if !token.MatchString(value) {
				t.Fatalf("%s value %q is not a pvalue token", member.name, value)
			}
			if _, duplicate := seen[value]; duplicate {
				t.Fatalf("%s value %q is duplicated", member.name, value)
			}
			seen[value] = struct{}{}
			if !member.known(value) {
				t.Fatalf("%s value %q is not Known()", member.name, value)
			}
			rendered.WriteString(member.name + "=" + value + "\n")
		}
		for _, unknown := range []string{"", "VALID", "not evaluated", "valid;", "unknown_value"} {
			if member.known(unknown) {
				t.Fatalf("%s accepted unknown value %q", member.name, unknown)
			}
		}
	}
	if got := strings.TrimSuffix(rendered.String(), "\n"); got != receivedVocabularyPins {
		t.Fatalf("vocabulary spelling changed:\n%s", got)
	}
}
