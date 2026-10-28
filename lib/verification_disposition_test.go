package dkim2

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/policy"
)

// dispositionTableReasons lists every public verification reason in the
// order the disposition table reports them.
var dispositionTableReasons = []ReasonCode{
	ReasonNone, ReasonInvalidRequest, ReasonLimitExceeded, ReasonMalformedMessage,
	ReasonMalformedProtocol, ReasonDuplicateHashAlgorithm, ReasonInvalidRecipeJSON,
	ReasonInvalidRecipe, ReasonFromNotAuthentic, ReasonDuplicateSelector, ReasonMissingProtocol,
	ReasonSequenceInvalid, ReasonUnsupportedAlgorithm, ReasonHashMismatch,
	ReasonSignatureMismatch, ReasonMissingKey, ReasonInvalidKey, ReasonAmbiguousKey,
	ReasonRevokedKey, ReasonUnsupportedKeyType, ReasonKeyAlgorithmMismatch,
	ReasonProviderTemporary, ReasonProviderPermanent, ReasonProviderContract,
	ReasonTimestampInvalid, ReasonEnvelopeMismatch, ReasonDomainAlignmentMismatch,
	ReasonNextDomainMismatch, ReasonCustodyMismatch, ReasonOutOfBandRequired,
	ReasonBodyHistoryUnavailable, ReasonInternalContract,
}

// dispositionTableModes lists every public local policy mode.
var dispositionTableModes = []PolicyMode{PolicyModeStrict, PolicyModePermissive, PolicyModeTesting}

// wantDispositionTable is the authoritative reason x mode disposition table:
// reason, mode, verification state, verdict, policy primary reason, action.
// An empty state marks a reason that no sealed verification result may carry.
var wantDispositionTable = []string{
	"none|strict|PASS|accept|protocol_pass|accept|",
	"none|permissive|PASS|accept|protocol_pass|accept|",
	"none|testing|PASS|continue|testing_mode_observe|continue|",
	"invalid_request|strict|||||",
	"invalid_request|permissive|||||",
	"invalid_request|testing|||||",
	"limit_exceeded|strict|PERMERROR|reject|protocol_permerror|reject|",
	"limit_exceeded|permissive|PERMERROR|accept|permissive_override|accept|",
	"limit_exceeded|testing|PERMERROR|continue|testing_mode_observe|continue|",
	"malformed_message|strict|PERMERROR|reject|protocol_permerror|reject|",
	"malformed_message|permissive|PERMERROR|accept|permissive_override|accept|",
	"malformed_message|testing|PERMERROR|continue|testing_mode_observe|continue|",
	"malformed_protocol|strict|PERMERROR|reject|protocol_permerror|reject|",
	"malformed_protocol|permissive|PERMERROR|accept|permissive_override|accept|",
	"malformed_protocol|testing|PERMERROR|continue|testing_mode_observe|continue|",
	"duplicate_hash_algorithm|strict|PERMERROR|reject|protocol_permerror|reject|",
	"duplicate_hash_algorithm|permissive|PERMERROR|accept|permissive_override|accept|",
	"duplicate_hash_algorithm|testing|PERMERROR|continue|testing_mode_observe|continue|",
	"invalid_recipe_json|strict|PERMERROR|reject|protocol_permerror|reject|",
	"invalid_recipe_json|permissive|PERMERROR|accept|permissive_override|accept|",
	"invalid_recipe_json|testing|PERMERROR|continue|testing_mode_observe|continue|",
	// New reason, Draft-08 Section 14.2 "Recipe <value> is invalid": PERMERROR.
	// Before this change the same cases were invalid_recipe_json or
	// malformed_protocol, both PERMERROR, so every disposition is unchanged.
	"invalid_recipe|strict|PERMERROR|reject|protocol_permerror|reject|",
	"invalid_recipe|permissive|PERMERROR|accept|permissive_override|accept|",
	"invalid_recipe|testing|PERMERROR|continue|testing_mode_observe|continue|",
	// Deliberate: Draft-08 Sections 14.1 and 14.8 make an inauthentic From a
	// FAIL (was PERMERROR). Verdicts and actions are unchanged; only the
	// strict primary policy reason moves from protocol_permerror to
	// protocol_fail.
	"from_not_authentic|strict|FAIL|reject|protocol_fail|reject|",
	"from_not_authentic|permissive|FAIL|accept|permissive_override|accept|",
	"from_not_authentic|testing|FAIL|continue|testing_mode_observe|continue|",
	"duplicate_selector|strict|PERMERROR|reject|protocol_permerror|reject|",
	"duplicate_selector|permissive|PERMERROR|accept|permissive_override|accept|",
	"duplicate_selector|testing|PERMERROR|continue|testing_mode_observe|continue|",
	"missing_protocol|strict|PERMERROR|reject|protocol_permerror|reject|",
	"missing_protocol|permissive|PERMERROR|accept|permissive_override|accept|",
	"missing_protocol|testing|PERMERROR|continue|testing_mode_observe|continue|",
	"sequence_invalid|strict|PERMERROR|reject|protocol_permerror|reject|",
	"sequence_invalid|permissive|PERMERROR|accept|permissive_override|accept|",
	"sequence_invalid|testing|PERMERROR|continue|testing_mode_observe|continue|",
	"unsupported_algorithm|strict|PERMERROR|reject|protocol_permerror|reject|",
	"unsupported_algorithm|permissive|PERMERROR|accept|permissive_override|accept|",
	"unsupported_algorithm|testing|PERMERROR|continue|testing_mode_observe|continue|",
	"hash_mismatch|strict|FAIL|reject|protocol_fail|reject|",
	"hash_mismatch|permissive|FAIL|accept|permissive_override|accept|",
	"hash_mismatch|testing|FAIL|continue|testing_mode_observe|continue|",
	"signature_mismatch|strict|FAIL|reject|protocol_fail|reject|",
	"signature_mismatch|permissive|FAIL|accept|permissive_override|accept|",
	"signature_mismatch|testing|FAIL|continue|testing_mode_observe|continue|",
	"missing_key|strict|PERMERROR|reject|protocol_permerror|reject|",
	"missing_key|permissive|PERMERROR|accept|permissive_override|accept|",
	"missing_key|testing|PERMERROR|continue|testing_mode_observe|continue|",
	"invalid_key|strict|PERMERROR|reject|protocol_permerror|reject|",
	"invalid_key|permissive|PERMERROR|accept|permissive_override|accept|",
	"invalid_key|testing|PERMERROR|continue|testing_mode_observe|continue|",
	"ambiguous_key|strict|PERMERROR|reject|protocol_permerror|reject|",
	"ambiguous_key|permissive|PERMERROR|accept|permissive_override|accept|",
	"ambiguous_key|testing|PERMERROR|continue|testing_mode_observe|continue|",
	"revoked_key|strict|PERMERROR|reject|protocol_permerror|reject|",
	"revoked_key|permissive|PERMERROR|accept|permissive_override|accept|",
	"revoked_key|testing|PERMERROR|continue|testing_mode_observe|continue|",
	"unsupported_key_type|strict|PERMERROR|reject|protocol_permerror|reject|",
	"unsupported_key_type|permissive|PERMERROR|accept|permissive_override|accept|",
	"unsupported_key_type|testing|PERMERROR|continue|testing_mode_observe|continue|",
	"key_algorithm_mismatch|strict|PERMERROR|reject|protocol_permerror|reject|",
	"key_algorithm_mismatch|permissive|PERMERROR|accept|permissive_override|accept|",
	"key_algorithm_mismatch|testing|PERMERROR|continue|testing_mode_observe|continue|",
	"provider_temporary|strict|TEMPERROR|tempfail|protocol_temperror|tempfail|",
	"provider_temporary|permissive|TEMPERROR|tempfail|protocol_temperror|tempfail|",
	"provider_temporary|testing|TEMPERROR|continue|testing_mode_observe|continue|",
	"provider_permanent|strict|PERMERROR|reject|protocol_permerror|reject|",
	"provider_permanent|permissive|PERMERROR|accept|permissive_override|accept|",
	"provider_permanent|testing|PERMERROR|continue|testing_mode_observe|continue|",
	"provider_contract|strict|PERMERROR|reject|protocol_permerror|reject|",
	"provider_contract|permissive|PERMERROR|accept|permissive_override|accept|",
	"provider_contract|testing|PERMERROR|continue|testing_mode_observe|continue|",
	// Deliberate: Draft-08 Section 14.3 timestamp failures are FAIL (was
	// PERMERROR); verdicts and actions are unchanged.
	"timestamp_invalid|strict|FAIL|reject|protocol_fail|reject|",
	"timestamp_invalid|permissive|FAIL|accept|permissive_override|accept|",
	"timestamp_invalid|testing|FAIL|continue|testing_mode_observe|continue|",
	// Deliberate: Draft-08 Section 14.4 MAIL FROM / RCPT TO mismatches are FAIL
	// (was PERMERROR); verdicts and actions are unchanged.
	"envelope_mismatch|strict|FAIL|reject|protocol_fail|reject|",
	"envelope_mismatch|permissive|FAIL|accept|permissive_override|accept|",
	"envelope_mismatch|testing|FAIL|continue|testing_mode_observe|continue|",
	// Deliberate: Draft-08 Section 14.4 "MAIL FROM and d= do not match" is FAIL
	// (was PERMERROR); verdicts and actions are unchanged.
	"domain_alignment_mismatch|strict|FAIL|reject|protocol_fail|reject|",
	"domain_alignment_mismatch|permissive|FAIL|accept|permissive_override|accept|",
	"domain_alignment_mismatch|testing|FAIL|continue|testing_mode_observe|continue|",
	// Deliberate: Draft-08 Section 14.4 nd= failures are FAIL (was
	// PERMERROR); verdicts and actions are unchanged.
	"next_domain_mismatch|strict|FAIL|reject|protocol_fail|reject|",
	"next_domain_mismatch|permissive|FAIL|accept|permissive_override|accept|",
	"next_domain_mismatch|testing|FAIL|continue|testing_mode_observe|continue|",
	// New reason, Draft-08 Section 14.4 "mf= / d= does not match the rt= of
	// i=<y>": FAIL. These cases were PERMERROR malformed_protocol before, with
	// the same reject, accept, and continue verdicts.
	"custody_mismatch|strict|FAIL|reject|protocol_fail|reject|",
	"custody_mismatch|permissive|FAIL|accept|permissive_override|accept|",
	"custody_mismatch|testing|FAIL|continue|testing_mode_observe|continue|",
	// Deliberate: Draft-08 Sections 13.2 and 14.4 make a terminal nd= without
	// an out-of-band arrangement FAIL (was PERMERROR); verdicts and actions
	// are unchanged.
	"out_of_band_required|strict|FAIL|reject|protocol_fail|reject|",
	"out_of_band_required|permissive|FAIL|accept|permissive_override|accept|",
	"out_of_band_required|testing|FAIL|continue|testing_mode_observe|continue|",
	// New reason, Draft-08 Section 13: a null body Recipe makes the message
	// not Fully Verified, so FAIL. Such messages were PASS with partial
	// history before; this is the one deliberate verdict change: strict mode
	// now rejects them (was accept), permissive mode accepts them by
	// override, and testing mode continues as before.
	"body_history_unavailable|strict|FAIL|reject|protocol_fail|reject|",
	"body_history_unavailable|permissive|FAIL|accept|permissive_override|accept|",
	"body_history_unavailable|testing|FAIL|continue|testing_mode_observe|continue|",
	"internal_contract|strict|PERMERROR|reject|protocol_permerror|reject|",
	"internal_contract|permissive|PERMERROR|accept|permissive_override|accept|",
	"internal_contract|testing|PERMERROR|continue|testing_mode_observe|continue|",
}

// TestDispositionTableCoversEveryReasonAndPolicyMode records, for every public
// verification reason and every policy mode, the only state the sealed result
// invariants admit and the local policy disposition evaluated from it.
func TestDispositionTableCoversEveryReasonAndPolicyMode(t *testing.T) {
	for _, reason := range dispositionTableReasons {
		if !reason.Known() {
			t.Fatalf("table reason %q is not in the public vocabulary", reason)
		}
	}
	got := computeDispositionTable(t)
	if !slices.Equal(got, wantDispositionTable) {
		t.Fatalf("disposition table changed:\n%s", strings.Join(got, "\n"))
	}
}

// computeDispositionTable evaluates every reason and mode through the public
// policy facade and renders one stable row per cell.
func computeDispositionTable(t *testing.T) []string {
	t.Helper()
	rows := make([]string, 0, len(dispositionTableReasons)*len(dispositionTableModes))
	for _, reason := range dispositionTableReasons {
		results := sealedResultsForReason(t, reason)
		states := make([]ResultState, 0, len(results))
		for _, result := range results {
			if !slices.Contains(states, result.State()) {
				states = append(states, result.State())
			}
		}
		if len(states) > 1 {
			t.Fatalf("reason %q admits more than one state: %v", reason, states)
		}
		for _, mode := range dispositionTableModes {
			if len(results) == 0 {
				rows = append(rows, fmt.Sprintf("%s|%s|||||", reason, mode))
				continue
			}
			row := ""
			for _, result := range results {
				decision, err := EvaluatePolicy(result, WithPolicyMode(mode))
				if err != nil || !decision.Valid() {
					t.Fatalf("EvaluatePolicy(%q, %q) = %v", reason, mode, err)
				}
				actions := decision.ActionPlan().Actions()
				candidate := fmt.Sprintf("%s|%s|%s|%s|%s|%s|", reason, mode, result.State(),
					decision.Verdict(), decision.PrimaryReason(), actions[0].Kind())
				if row != "" && row != candidate {
					t.Fatalf("reason %q mode %q has divergent dispositions: %q and %q", reason, mode, row, candidate)
				}
				row = candidate
			}
			rows = append(rows, row)
		}
	}
	return rows
}

// sealedResultsForReason returns every library-owned sealed result shape that
// carries reason and satisfies the public result and policy-provenance
// invariants: the selected current target, an inherited revision failure,
// a Chain of Custody failure, and the target-unavailable form.
func sealedResultsForReason(t *testing.T, reason ReasonCode) []VerifyResult {
	t.Helper()
	var results []VerifyResult
	for _, state := range []ResultState{ResultStatePASS, ResultStateFAIL, ResultStatePERMERROR, ResultStateTEMPERROR} {
		protocol, _ := publicPolicyProtocol(state)
		if result, ok := selectedDispositionResult(protocol, state, reason); ok {
			results = append(results, result)
		}
		if result, ok := revisionFailureDispositionResult(protocol, state, reason); ok {
			results = append(results, result)
		}
	}
	if result, ok := chainFailureDispositionResult(reason); ok {
		results = append(results, result)
	}
	if result, ok := unavailableDispositionResult(reason); ok {
		results = append(results, result)
	}
	return results
}

// selectedDispositionResult builds a selected current-target result whose
// single signature fact is coherent with the state and reason when possible.
func selectedDispositionResult(protocol policy.ProtocolClass, state ResultState, reason ReasonCode) (VerifyResult, bool) {
	fact, ok := dispositionSignatureFact(state, reason)
	if !ok {
		return VerifyResult{}, false
	}
	var hops []policy.HopFact
	if state == ResultStatePASS {
		hop, err := policy.NewAuthenticatedHopFact(1, policy.TransitionOrigin, false, false, false)
		if err != nil {
			return VerifyResult{}, false
		}
		hops = []policy.HopFact{hop}
	}
	projection, err := policy.NewSelectedProjection(protocol, policy.VerificationReason(reason), 1, hops, []policy.SignatureFact{fact}, policy.DefaultLimits())
	if err != nil {
		return VerifyResult{}, false
	}
	return dispositionResult(state, reason, newVerificationTarget(1, 1), CustodyStructureNotPresent, projection)
}

// revisionFailureDispositionResult builds an inherited revision failure over
// a passing current target.
func revisionFailureDispositionResult(protocol policy.ProtocolClass, state ResultState, reason ReasonCode) (VerifyResult, bool) {
	pass, err := policy.NewSignatureFact(policy.SetAlgorithmRSA, policy.SetStatusPass, policy.SetReasonNone)
	if err != nil {
		return VerifyResult{}, false
	}
	current, err := policy.NewSelectedProjection(policy.ProtocolPASS, policy.VerificationReasonNone, 2, nil, []policy.SignatureFact{pass}, policy.DefaultLimits())
	if err != nil {
		hop, hopErr := policy.NewAuthenticatedHopFact(2, policy.TransitionNotEvaluated, false, false, false)
		if hopErr != nil {
			return VerifyResult{}, false
		}
		current, err = policy.NewSelectedProjection(policy.ProtocolPASS, policy.VerificationReasonNone, 2, []policy.HopFact{hop}, []policy.SignatureFact{pass}, policy.DefaultLimits())
		if err != nil {
			return VerifyResult{}, false
		}
	}
	projection, err := policy.NewRevisionFailureProjection(protocol, policy.VerificationReason(reason), current, policy.DefaultLimits())
	if err != nil {
		return VerifyResult{}, false
	}
	return dispositionResult(state, reason, newVerificationTarget(2, 2), CustodyStructureNotPresent, projection)
}

// chainFailureDispositionResult builds a selected target whose Chain of
// Custody check failed before any signature was evaluated.
func chainFailureDispositionResult(reason ReasonCode) (VerifyResult, bool) {
	projection, err := policy.NewChainFailureProjection(policy.VerificationReason(reason), 2)
	if err != nil {
		return VerifyResult{}, false
	}
	return dispositionResult(ResultStateFAIL, reason, newVerificationTarget(2, 1), CustodyStructureNotEvaluated, projection)
}

// unavailableDispositionResult builds the target-unavailable form when the
// reason is a pre-target reason.
func unavailableDispositionResult(reason ReasonCode) (VerifyResult, bool) {
	projection, err := policy.NewUnavailableProjection(policy.PreTargetReason(reason))
	if err != nil {
		return VerifyResult{}, false
	}
	return dispositionResult(ResultStatePERMERROR, reason, VerificationTarget{}, CustodyStructureNotEvaluated, projection)
}

// dispositionResult seals one public result and keeps it only when every
// public and provenance invariant accepts it.
func dispositionResult(state ResultState, reason ReasonCode, target VerificationTarget, custody CustodyStructure, projection policy.Projection) (VerifyResult, bool) {
	result := newVerifyResult(verifyResultData{
		state: state, scope: VerificationScopeCurrent,
		historicalContent: HistoricalStateNotEvaluated, historicalSignatures: HistoricalStateNotEvaluated,
		custodyStructure: custody, target: target, primaryReason: reason,
		checks: []CheckFact{newCheckFact(CheckClassProtocol, reason)}, policyProjection: projection,
	})
	if result.State() != state || result.PrimaryReason() != reason || !result.Valid() {
		return VerifyResult{}, false
	}
	return result, true
}

// dispositionSignatureFact selects the one signature-set fact whose Section
// 14.6 outcome is coherent with state and reason.
func dispositionSignatureFact(state ResultState, reason ReasonCode) (policy.SignatureFact, bool) {
	status, setReason := policy.SetStatusPass, policy.SetReasonNone
	switch {
	case state == ResultStateFAIL && reason == ReasonSignatureMismatch:
		status, setReason = policy.SetStatusFail, policy.SetReasonSignatureMismatch
	case state == ResultStateTEMPERROR:
		status, setReason = policy.SetStatusTemperror, policy.SetReasonProviderTemporary
	case state == ResultStatePERMERROR && policy.SetReason(reason) != policy.SetReasonUnsupportedAlgorithm &&
		policy.SetReason(reason).Known() && policy.SetReason(reason) != policy.SetReasonNone &&
		policy.SetReason(reason) != policy.SetReasonSignatureMismatch && policy.SetReason(reason) != policy.SetReasonProviderTemporary:
		status, setReason = policy.SetStatusPermerror, policy.SetReason(reason)
	}
	fact, err := policy.NewSignatureFact(policy.SetAlgorithmRSA, status, setReason)
	return fact, err == nil
}
