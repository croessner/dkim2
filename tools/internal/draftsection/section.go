// Package draftsection validates citations against the pinned DKIM2 Draft-08 structure.
package draftsection

import "strings"

const (
	fullDraft  = "draft-ietf-dkim-dkim2-spec-08"
	shortDraft = "Draft-08"
)

var sectionOrder = func() map[string]int {
	sections := []string{
		"1", "1.1",
		"2", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8", "2.9", "2.10", "2.11", "2.12", "2.13", "2.14",
		"3", "3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7",
		"4", "4.1",
		"5", "5.1", "5.2",
		"6", "6.1", "6.2",
		"7", "7.1", "7.2",
		"8",
		"9", "9.1", "9.2", "9.3",
		"10", "10.1", "10.2", "10.3", "10.4", "10.5", "10.6", "10.7", "10.8", "10.9", "10.10",
		"11",
		"12", "12.1", "12.2", "12.3", "12.4", "12.5", "12.6", "12.7", "12.8",
		"13", "13.1", "13.2", "13.3", "13.4",
		"14", "14.1", "14.2", "14.3", "14.4", "14.5", "14.6", "14.7", "14.8",
		"15", "15.1",
		"16", "16.1", "16.2", "16.3", "16.4",
		"17", "18", "19", "20", "21", "21.1", "21.2",
	}
	order := make(map[string]int, len(sections))
	for index, section := range sections {
		order[section] = index
	}
	return order
}()

// CitationValid accepts non-Draft-08 text unchanged and validates every current
// Draft-08 Section/Sections citation against the pinned closed section set.
func CitationValid(value string) bool {
	suffix, plural, current := citationSuffix(value)
	if !current {
		return true
	}
	if suffix == "" {
		return false
	}
	if strings.Contains(suffix, " through ") {
		if !plural || strings.Count(suffix, " through ") != 1 {
			return false
		}
		start, end, _ := strings.Cut(suffix, " through ")
		startOrder, startExists := sectionOrder[start]
		endOrder, endExists := sectionOrder[end]
		return startExists && endExists && startOrder < endOrder
	}
	return sectionListValid(suffix, plural)
}

// citationSuffix recognizes both manifest and issue-log Draft-08 citation prefixes.
func citationSuffix(value string) (string, bool, bool) {
	for _, draft := range []string{fullDraft, shortDraft} {
		if suffix, found := strings.CutPrefix(value, draft+" Sections "); found {
			return suffix, true, true
		}
		if suffix, found := strings.CutPrefix(value, draft+" Section "); found {
			return suffix, false, true
		}
		if strings.Contains(value, draft) {
			return "", false, true
		}
	}
	return "", false, false
}

// sectionListValid validates singular and enumerated section citation syntax.
func sectionListValid(value string, plural bool) bool {
	normalized := strings.ReplaceAll(value, ", and ", ",")
	normalized = strings.ReplaceAll(normalized, " and ", ",")
	normalized = strings.ReplaceAll(normalized, ", ", ",")
	if normalized == "" || strings.ContainsAny(normalized, " \t\r\n") {
		return false
	}
	parts := strings.Split(normalized, ",")
	if plural != (len(parts) > 1) {
		return false
	}
	seen := make(map[string]struct{}, len(parts))
	for _, section := range parts {
		if _, exists := sectionOrder[section]; !exists {
			return false
		}
		if _, duplicate := seen[section]; duplicate {
			return false
		}
		seen[section] = struct{}{}
	}
	return true
}
