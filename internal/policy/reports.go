package policy

// countReportFindings pre-counts exact exploded-report findings without allocation.
func countReportFindings(hops []HopFact) int {
	count := 0
	for _, hop := range hops {
		if hop.Exploded() {
			count++
		}
	}
	return count
}

// explodedReportFindings derives one informational finding per authenticated
// exploded report. Draft-07 Section 10.10 removed the donotmodify and
// donotexplode request flags, so authenticated hop flags carry no compliance
// evaluation and never change the local verdict.
func explodedReportFindings(hops []HopFact) ([]Finding, error) {
	reports := make([]Finding, 0, len(hops))
	for _, hop := range hops {
		if !hop.Exploded() {
			continue
		}
		finding, err := newFinding(ReasonExplodedReported, hop.Sequence(), true)
		if err != nil {
			return nil, err
		}
		reports = append(reports, finding)
	}
	return reports, nil
}
