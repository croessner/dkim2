// Package authresults owns the bounded local Authentication-Results profile.
// Reports are untrusted outside their issuing administrative domain. Comments
// are diagnostic only and must never become a policy or reputation input.
package authresults

import (
	"strings"

	dkim2 "github.com/croessner/dkim2"
)

// Report is an immutable, validated local report without message identifiers.
type Report struct{ authority, result, reason string }

// New admits a canonical authority, four-state result, and optional closed reason.
func New(authority, result, reason string) (Report, bool) {
	if !validDomain(authority) || (result != "pass" && result != "fail" && result != "permerror" && result != "temperror") {
		return Report{}, false
	}
	if reason == "none" {
		reason = ""
	}
	if reason != "" && (result == "pass" || !knownReason(reason)) {
		return Report{}, false
	}
	return Report{authority: authority, result: result, reason: reason}, true
}

// Parse admits only the canonical local profile, including legacy bare results.
func Parse(value string) (Report, bool) {
	if len(value) > 384 {
		return Report{}, false
	}
	authority, tail, ok := strings.Cut(value, "; dkim2=")
	if !ok {
		return Report{}, false
	}
	result, comment, hasComment := strings.Cut(tail, " (reason=")
	reason := ""
	if hasComment {
		if !strings.HasSuffix(comment, ")") {
			return Report{}, false
		}
		reason = strings.TrimSuffix(comment, ")")
		if reason == "" {
			return Report{}, false
		}
	}
	report, valid := New(authority, result, reason)
	return report, valid && report.Value() == value
}

// Value returns the canonical field value; the zero value is not a report.
func (r Report) Value() string {
	if r.authority == "" {
		return ""
	}
	value := r.authority + "; dkim2=" + r.result
	if r.reason != "" {
		value += " (reason=" + r.reason + ")"
	}
	return value
}

// Matches binds a parsed report to the configured authority and final outcome.
func (r Report) Matches(authority, result string) bool {
	return r.authority != "" && r.authority == authority && r.result == result
}

// MatchesReason rejects contradictory diagnostics while admitting legacy reports.
func (r Report) MatchesReason(reason string) bool {
	return r.authority != "" && (r.reason == "" || r.reason == reason)
}

// Authority returns the validated administrative identity for wire validation.
func (r Report) Authority() string { return r.authority }

// knownReason admits protocol reasons and the final replay coordinator reasons.
func knownReason(reason string) bool {
	return dkim2.ReasonCode(reason).Known() || reason == "duplicate_message_without_exploded" || reason == "replay_indeterminate" || reason == "replay_evidence_unavailable"
}

// validDomain constrains authority to bounded canonical DNS labels.
func validDomain(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}
