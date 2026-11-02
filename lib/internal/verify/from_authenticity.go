package verify

import (
	"bytes"
	"slices"

	"github.com/croessner/dkim2/internal/mailbox"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/signature"
)

// fromAuthenticityPlan is the pure phase of the Draft-09 Sections 11, 11.1,
// and 14.8 From evaluation (local interpretation D2). A history is accepted
// only when every From state is a direct (downward) match or an upward
// candidate; upward lists the deduplicated A-label From domains whose Domain
// Policy Record must still be resolved, in field order from m=1 upward.
type fromAuthenticityPlan struct {
	accepted  bool
	offending uint64
	upward    []string
}

// fromStateMatch classifies one From state against its responsible d=.
type fromStateMatch uint8

const (
	// fromStateNotAuthentic reports no match in either direction, more than
	// one From field or address, a group without a mailbox, a domain literal,
	// or a malformed value.
	fromStateNotAuthentic fromStateMatch = iota
	// fromStateDirect reports the Section 7.1 item 3 match with the From
	// domain as Parameter1 and d= as Parameter2.
	fromStateDirect
	// fromStateUpward reports that only the reversed match (d= as Parameter1,
	// the From domain as Parameter2) succeeds; the From domain's Domain
	// Policy Record decides it (Sections 3.8 and 11.1).
	fromStateUpward
)

// classifyFromAuthenticity applies the pure phase to a complete
// authenticated history. states lists the reconstructed message states from
// the current state (highest m=) down to the m=1 state. A From state begins at
// m=1 and at every later instance whose From differs from the previous
// instance; its responsible signature is the lowest numbered signature whose
// m= is at least that instance (Section 11). A pre-entry From restored by an
// r= on the m=1 Message-Instance is outside the DKIM2 history and is not
// evaluated. A state that is not Authentic rejects immediately without any
// DNS work and reports the responsible signature sequence, or zero when no
// responsible signature exists.
func classifyFromAuthenticity(states []recipe.State, signatures []signature.Signature) fromAuthenticityPlan {
	if len(states) == 0 {
		return fromAuthenticityPlan{}
	}
	ordered, err := signature.OrderBySequence(signatures)
	if err != nil || len(ordered) == 0 {
		return fromAuthenticityPlan{}
	}
	var previous [][]byte
	var upward []string
	for index := len(states) - 1; index >= 0; index-- {
		instanceNumber := uint64(len(states) - index)
		current := fromValues(states[index])
		if instanceNumber > 1 && sameFromValues(previous, current) {
			continue
		}
		previous = current
		responsible, found := responsibleSignature(ordered, instanceNumber)
		if !found {
			return fromAuthenticityPlan{}
		}
		match, fromDomain := classifyFromState(current, responsible.Domain())
		switch match {
		case fromStateDirect:
		case fromStateUpward:
			if !slices.Contains(upward, fromDomain) {
				upward = append(upward, fromDomain)
			}
		default:
			return fromAuthenticityPlan{offending: responsible.Sequence()}
		}
	}
	return fromAuthenticityPlan{accepted: true, upward: upward}
}

// SignerFromAuthenticFor reports whether the From header fields of headers
// form one From state that signingDomain makes Authentic through the
// downward relaxed match only (From domain equal to or a subdomain of d=).
// It is the local stricter Signer rule (disposition D8): Draft-09 Sections
// 11.1 and 12.4 also let a subdomain d= make a parent From Authentic when the
// From domain's Domain Policy Record permits it, but our Signers and the DSN
// identity resolver only sign with keys at the correct level, so they never
// need the upward match and never query a Domain Policy Record.
func SignerFromAuthenticFor(headers rawmsg.HeaderBlock, signingDomain string) bool {
	match, _ := classifyFromState(fromHeaderValues(headers), signingDomain)
	return match == fromStateDirect
}

// SameFromState reports whether two header blocks carry byte-identical From
// header fields, which means the From header field was not replaced.
func SameFromState(left, right rawmsg.HeaderBlock) bool {
	return sameFromValues(fromHeaderValues(left), fromHeaderValues(right))
}

// fromValues returns the unfolded values of every From field in one state.
func fromValues(state recipe.State) [][]byte {
	return fromHeaderValues(state.Headers())
}

// fromHeaderValues returns the unfolded values of every From field.
func fromHeaderValues(headers rawmsg.HeaderBlock) [][]byte {
	fields := headers.FieldsByName("from")
	values := make([][]byte, 0, len(fields))
	for _, field := range fields {
		values = append(values, field.UnfoldedValue())
	}
	return values
}

// sameFromValues reports whether two states carry byte-identical From fields.
func sameFromValues(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index], right[index]) {
			return false
		}
	}
	return true
}

// responsibleSignature selects the lowest numbered signature whose m= is at
// least instanceNumber (Draft-09 Section 11). ordered is sorted by i=.
func responsibleSignature(ordered []signature.Signature, instanceNumber uint64) (signature.Signature, bool) {
	for _, candidate := range ordered {
		if candidate.InstanceNumber() >= instanceNumber {
			return candidate, true
		}
	}
	return signature.Signature{}, false
}

// classifyFromState classifies one From state for the responsible d= and
// returns the canonical A-label From domain (Draft-09 Sections 7.1 item 3,
// 7.2, 11, and 18). The direct match runs first; the reversed match is tried
// only when it fails. Sibling domains never match in either direction.
func classifyFromState(values [][]byte, signingDomain string) (fromStateMatch, string) {
	if len(values) != 1 {
		return fromStateNotAuthentic, ""
	}
	author, status := mailbox.ParseAuthor(values[0])
	if status != mailbox.StatusSingle {
		return fromStateNotAuthentic, ""
	}
	fromDomain := author.Domain()
	switch {
	case signature.RelaxedDomainMatch(signingDomain, fromDomain):
		return fromStateDirect, fromDomain
	case signature.RelaxedDomainMatch(fromDomain, signingDomain):
		return fromStateUpward, fromDomain
	default:
		return fromStateNotAuthentic, ""
	}
}

// historyFromAuthentic collects the current state and every reconstructed
// state of a complete authenticated walk, ordered from the highest m= down
// to m=1, and applies classifyFromAuthenticity. An incomplete walk or a
// missing reconstructed state cannot prove authenticity and fails closed.
func historyFromAuthentic(current recipe.State, walk HistoryWalk, signatures []signature.Signature) fromAuthenticityPlan {
	transitions := walk.Transitions()
	if walk.ReachedInstance() != 1 || len(transitions) != int(walk.TargetInstance()-1) {
		return fromAuthenticityPlan{}
	}
	states := make([]recipe.State, 0, len(transitions)+1)
	states = append(states, current)
	for _, transition := range transitions {
		state, ok := transition.ReconstructedState()
		if !ok {
			return fromAuthenticityPlan{}
		}
		states = append(states, state)
	}
	return classifyFromAuthenticity(states, signatures)
}
