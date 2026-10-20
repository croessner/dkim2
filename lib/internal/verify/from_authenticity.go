package verify

import (
	"bytes"

	"github.com/croessner/dkim2/internal/mailbox"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/signature"
)

// fromAuthenticityAccepted applies Draft-07 Sections 11 and 14.8 to a
// complete authenticated history. states lists the reconstructed message
// states from the current state (highest m=) down to the m=1 state. A From
// state begins at m=1 and at every later instance whose From differs from
// the previous instance; each such state must consist of exactly one From
// field with exactly one non-literal mailbox whose domain relaxed-matches
// (From domain as Parameter1, d= as Parameter2) the d= of the lowest
// numbered signature whose m= is at least that instance. A pre-entry From
// restored by an r= on the m=1 Message-Instance is outside the DKIM2 history
// and is not evaluated. It returns the offending signature sequence on
// failure, or zero when no responsible signature exists.
func fromAuthenticityAccepted(states []recipe.State, signatures []signature.Signature) (uint64, bool) {
	if len(states) == 0 {
		return 0, false
	}
	ordered, err := signature.OrderBySequence(signatures)
	if err != nil || len(ordered) == 0 {
		return 0, false
	}
	var previous [][]byte
	for index := len(states) - 1; index >= 0; index-- {
		instanceNumber := uint64(len(states) - index)
		current := fromValues(states[index])
		if instanceNumber > 1 && sameFromValues(previous, current) {
			continue
		}
		previous = current
		responsible, found := responsibleSignature(ordered, instanceNumber)
		if !found {
			return 0, false
		}
		if !fromStateAuthentic(current, responsible.Domain()) {
			return responsible.Sequence(), false
		}
	}
	return 0, true
}

// FromAuthenticFor reports whether the From header fields of headers form one
// Authentic From state for signingDomain (Draft-07 Section 11). Signers use it
// to choose d= under Section 12.4; verifiers apply the same rule per state.
func FromAuthenticFor(headers rawmsg.HeaderBlock, signingDomain string) bool {
	return fromStateAuthentic(fromHeaderValues(headers), signingDomain)
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
// least instanceNumber (Draft-07 Section 11). ordered is sorted by i=.
func responsibleSignature(ordered []signature.Signature, instanceNumber uint64) (signature.Signature, bool) {
	for _, candidate := range ordered {
		if candidate.InstanceNumber() >= instanceNumber {
			return candidate, true
		}
	}
	return signature.Signature{}, false
}

// fromStateAuthentic reports whether one From state is Authentic for d=.
func fromStateAuthentic(values [][]byte, signingDomain string) bool {
	if len(values) != 1 {
		return false
	}
	author, status := mailbox.ParseAuthor(values[0])
	if status != mailbox.StatusSingle {
		return false
	}
	return signature.RelaxedDomainMatch(signingDomain, author.Domain())
}

// historyFromAuthentic collects the current state and every reconstructed
// state of a complete authenticated walk, ordered from the highest m= down
// to m=1, and applies fromAuthenticityAccepted. An incomplete walk or a
// missing reconstructed state cannot prove authenticity and fails closed.
func historyFromAuthentic(current recipe.State, walk HistoryWalk, signatures []signature.Signature) bool {
	transitions := walk.Transitions()
	if walk.ReachedInstance() != 1 || len(transitions) != int(walk.TargetInstance()-1) {
		return false
	}
	states := make([]recipe.State, 0, len(transitions)+1)
	states = append(states, current)
	for _, transition := range transitions {
		state, ok := transition.ReconstructedState()
		if !ok {
			return false
		}
		states = append(states, state)
	}
	_, accepted := fromAuthenticityAccepted(states, signatures)
	return accepted
}
