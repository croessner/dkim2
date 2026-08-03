package domainadmin

import "github.com/croessner/dkim2/provider"

// operationReportFacts contains only identity-free immutable plan counts and generations.
type operationReportFacts struct {
	expected    uint64
	current     uint64
	candidate   uint64
	credentials uint32
	rsa         uint32
	ed25519     uint32
}

// journalReportFacts derives bounded report facts from one protected complete operation.
func journalReportFacts(journal *Journal) (operationReportFacts, bool) {
	if journal == nil {
		return operationReportFacts{}, false
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.closed {
		return operationReportFacts{}, false
	}
	return planReportFactsLocked(journal.plan)
}

// planReportFactsLocked derives counts from the immutable protected plan without identities.
func planReportFactsLocked(plan *Plan) (operationReportFacts, bool) {
	if plan == nil {
		return operationReportFacts{}, false
	}
	plan.mu.Lock()
	defer plan.mu.Unlock()
	if plan.closed || plan.candidateGeneration == 0 || len(plan.credentials) == 0 || len(plan.credentials) > 2 {
		return operationReportFacts{}, false
	}
	facts := operationReportFacts{
		expected: plan.expectedCurrent, candidate: plan.candidateGeneration,
		credentials: uint32(len(plan.credentials)),
	}
	for _, credential := range plan.credentials {
		switch credential.algorithm {
		case provider.AlgorithmRSASHA256:
			facts.rsa++
		case provider.AlgorithmEd25519SHA256:
			facts.ed25519++
		default:
			return operationReportFacts{}, false
		}
	}
	if facts.candidate <= facts.expected || facts.rsa > 1 || facts.ed25519 > 1 ||
		facts.rsa+facts.ed25519 != facts.credentials {
		return operationReportFacts{}, false
	}
	return facts, true
}
