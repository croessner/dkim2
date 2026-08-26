package policy

type dnsTestingOutcome struct {
	reason    PolicyReason
	effective bool
}

// evaluateDNSTesting applies the exact closed testing eligibility matrix.
func evaluateDNSTesting(projection Projection) (dnsTestingOutcome, error) {
	if projection.Form() == TargetUnavailable {
		return dnsTestingOutcome{}, nil
	}
	facts := projection.SignatureFacts()
	anyTesting := false
	for _, fact := range facts {
		if fact.TestingDeclared() {
			anyTesting = true
			break
		}
	}
	if !anyTesting {
		return dnsTestingOutcome{}, nil
	}
	if projection.revisionFailure {
		return dnsTestingOutcome{reason: ReasonDNSTestingIneligible}, nil
	}
	if !dnsTopLevelEligible(projection.Protocol(), projection.VerificationReason()) {
		return dnsTestingOutcome{reason: ReasonDNSTestingIneligible}, nil
	}
	supported := 0
	for _, fact := range facts {
		if fact.Algorithm() == SetAlgorithmUnknown || fact.Status() == SetStatusIgnored {
			continue
		}
		supported++
		if !fact.TestingDeclared() {
			return dnsTestingOutcome{reason: ReasonDNSTestingMixed}, nil
		}
	}
	if supported == 0 {
		return dnsTestingOutcome{reason: ReasonDNSTestingIneligible}, nil
	}
	if !dnsSetRowsEligible(projection.Protocol(), projection.VerificationReason(), facts) {
		return dnsTestingOutcome{reason: ReasonDNSTestingIneligible}, nil
	}
	return dnsTestingOutcome{reason: ReasonDNSTestingEffective, effective: true}, nil
}

// dnsTopLevelEligible reports whether protocol and reason have a testing row.
func dnsTopLevelEligible(protocol ProtocolClass, reason VerificationReason) bool {
	switch protocol {
	case ProtocolPASS:
		return reason == VerificationReasonNone
	case ProtocolFAIL:
		return reason == VerificationReasonSignatureMismatch || reason == VerificationReasonHashMismatch
	case ProtocolPERMERROR:
		return eligiblePermanentRank(reason) >= 0 || postKeyPermanentTestingEligible(reason)
	default:
		return false
	}
}

// dnsSetRowsEligible validates every supported outcome-driving set pair.
func dnsSetRowsEligible(protocol ProtocolClass, reason VerificationReason, facts []SignatureFact) bool {
	permanent := false
	postKeyPermanent := protocol == ProtocolPERMERROR && postKeyPermanentTestingEligible(reason)
	for _, fact := range facts {
		if fact.Algorithm() == SetAlgorithmUnknown || fact.Status() == SetStatusIgnored {
			continue
		}
		switch protocol {
		case ProtocolPASS:
			if fact.Status() != SetStatusPass || fact.Reason() != SetReasonNone {
				return false
			}
		case ProtocolFAIL:
			if reason == VerificationReasonHashMismatch && (fact.Status() != SetStatusPass || fact.Reason() != SetReasonNone) {
				return false
			}
			if reason == VerificationReasonSignatureMismatch && !isPassingOrSignatureFailure(fact) {
				return false
			}
		case ProtocolPERMERROR:
			if fact.Status() == SetStatusPass && fact.Reason() == SetReasonNone {
				continue
			}
			if postKeyPermanent {
				return false
			}
			if fact.Status() != SetStatusPermerror || eligiblePermanentRank(VerificationReason(fact.Reason())) < 0 {
				return false
			}
			permanent = true
		}
	}
	return protocol != ProtocolPERMERROR || postKeyPermanent || permanent
}

// postKeyPermanentTestingEligible identifies failures reached after coherent passing signature sets.
func postKeyPermanentTestingEligible(reason VerificationReason) bool {
	switch reason {
	case VerificationReasonTimestampInvalid, VerificationReasonEnvelopeMismatch, VerificationReasonDomainAlignmentMismatch,
		VerificationReasonNextDomainMismatch, VerificationReasonOutOfBandRequired:
		return true
	default:
		return false
	}
}

// isPassingOrSignatureFailure reports one eligible FAIL signature-set row.
func isPassingOrSignatureFailure(fact SignatureFact) bool {
	return fact.Status() == SetStatusPass && fact.Reason() == SetReasonNone ||
		fact.Status() == SetStatusFail && fact.Reason() == SetReasonSignatureMismatch
}
