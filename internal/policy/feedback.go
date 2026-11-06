package policy

// FeedbackIntent stores bounded authenticated feedback routing intent.
type FeedbackIntent struct {
	requested     bool
	relayRequired bool
	relaySequence uint64
	history       HistoryCoverage
}

// Requested reports whether authenticated feedback was requested.
func (i FeedbackIntent) Requested() bool { return i.requested }

// RelayRequired reports whether an authenticated eligible relay exists.
func (i FeedbackIntent) RelayRequired() bool { return i.relayRequired }

// RelaySequence returns the highest eligible relay sequence or zero.
func (i FeedbackIntent) RelaySequence() uint64 { return i.relaySequence }

// HistoryCoverage returns the explicit feedback-history coverage.
func (i FeedbackIntent) HistoryCoverage() HistoryCoverage { return i.history }

// Valid reports whether feedback intent is internally coherent.
func (i FeedbackIntent) Valid() bool {
	return i.history.Known() && (i.relayRequired && i.requested && i.relaySequence > 0 || !i.relayRequired && i.relaySequence == 0)
}

type feedbackSummary struct {
	intent       FeedbackIntent
	requestCount int
	inertCount   int
}

// feedbackFindingCount returns the exact bounded finding count.
func (s feedbackSummary) feedbackFindingCount() int {
	count := s.requestCount + s.inertCount
	if s.intent.relayRequired {
		count++
	}
	return count
}

// summarizeFeedback derives intent and counts without allocating findings.
func summarizeFeedback(hops []HopFact, history HistoryCoverage) feedbackSummary {
	summary := feedbackSummary{intent: FeedbackIntent{history: history}}
	seenFeedback := false
	for _, hop := range hops {
		if hop.Feedback() {
			seenFeedback = true
			summary.intent.requested = true
			summary.requestCount++
		}
		if !hop.FeedHere() {
			continue
		}
		if seenFeedback {
			summary.intent.relayRequired = true
			summary.intent.relaySequence = hop.Sequence()
		} else {
			summary.inertCount++
		}
	}
	return summary
}

// feedbackFindings constructs deterministic request and relay findings.
func feedbackFindings(hops []HopFact, summary feedbackSummary) ([]Finding, []Finding, error) {
	requests := make([]Finding, 0, summary.requestCount)
	relays := make([]Finding, 0, summary.inertCount+1)
	seenFeedback := false
	for _, hop := range hops {
		if hop.Feedback() {
			seenFeedback = true
			finding, err := newFinding(ReasonFeedbackRequested, hop.Sequence(), true)
			if err != nil {
				return nil, nil, err
			}
			requests = append(requests, finding)
		}
		if hop.FeedHere() && !seenFeedback {
			finding, err := newFinding(ReasonFeedHereInert, hop.Sequence(), true)
			if err != nil {
				return nil, nil, err
			}
			relays = append(relays, finding)
		}
	}
	if summary.intent.relayRequired {
		finding, err := newFinding(ReasonFeedbackRelaySelected, summary.intent.relaySequence, true)
		if err != nil {
			return nil, nil, err
		}
		relays = append(relays, finding)
	}
	return requests, relays, nil
}
