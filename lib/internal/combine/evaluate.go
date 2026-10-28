package combine

// Result is one Draft-08 intermediate or overall verification result of a
// signature or hash-set combination (Sections 14.6 and 14.7).
type Result uint8

const (
	// ResultPass is a PASS intermediate or overall result.
	ResultPass Result = iota + 1
	// ResultFail is a FAIL intermediate or overall result.
	ResultFail
	// ResultTempError is a TEMPERROR intermediate or overall result. It
	// occurs only for signatures; hash combinations never yield it.
	ResultTempError
	// ResultPermError is a PERMERROR intermediate or overall result.
	ResultPermError
)

// Known reports whether r is one of the four closed results.
func (r Result) Known() bool {
	return r >= ResultPass && r <= ResultPermError
}

// Outcome is the overall result of one combination plus the decisive set:
// within the first group whose group result equals the overall result, the
// first set in field order whose intermediate equals that result. A set of a
// group with a different result never explains the outcome. Reporting uses
// the decisive set, so the public reason of a non-PASS outcome is
// deterministic.
type Outcome struct {
	result   Result
	decisive int
	valid    bool
}

// Result returns the overall combination result.
func (o Outcome) Result() Result { return o.result }

// Decisive returns the field-order index of the decisive set: the first set
// carrying the overall result inside the first group whose result equals it.
func (o Outcome) Decisive() int { return o.decisive }

// Valid reports whether the outcome was computed from a coherent layout and
// intermediate list.
func (o Outcome) Valid() bool { return o.valid }

// Pass reports whether the outcome is a valid overall PASS.
func (o Outcome) Pass() bool { return o.valid && o.result == ResultPass }

// Signatures combines per-signature intermediates exactly as Draft-08
// Section 14.6 steps 5 to 7 prescribe. Each sig-all group is PASS when every
// signature passes, else TEMPERROR when every non-PASS signature is
// TEMPERROR, else FAIL when any signature is FAIL, else PERMERROR. The
// sig-any result is PASS when any group passes, else TEMPERROR when any group
// is TEMPERROR, else FAIL when any group is FAIL, else PERMERROR.
func Signatures(layout Layout, intermediates []Result) Outcome {
	return combine(layout, intermediates, signatureAll, signatureAny, true)
}

// Hashes combines per-hash-set intermediates exactly as Draft-08 Section
// 14.7 steps 3 to 5 prescribe. A single hash-set yields its intermediate.
// Each hash-all group is PASS when every hash-set passes, else FAIL when any
// is FAIL, else PERMERROR; the hash-any result is PASS when any group passes,
// else FAIL when any group is FAIL, else PERMERROR. Hash intermediates are
// never TEMPERROR; one makes the outcome invalid.
func Hashes(layout Layout, intermediates []Result) Outcome {
	return combine(layout, intermediates, hashAll, hashAny, false)
}

// combine applies one all-rule per group and one any-rule across groups,
// then selects the decisive set: the first group whose own result equals the
// overall result, and in that group the first set whose intermediate equals
// it. Every all-rule result is carried by at least one of its sets, so a
// matching group without such a set is an incoherent combination.
func combine(layout Layout, intermediates []Result, allRule func([]Result) Result, anyRule func([]Result) Result, allowTemp bool) Outcome {
	if !layout.Valid() || layout.Sets() != len(intermediates) {
		return Outcome{}
	}
	for _, intermediate := range intermediates {
		if !intermediate.Known() || !allowTemp && intermediate == ResultTempError {
			return Outcome{}
		}
	}
	groups := make([]Result, layout.Groups())
	starts := make([]int, layout.Groups())
	start := 0
	for group := range groups {
		size := int(layout.sizes[group])
		starts[group] = start
		groups[group] = allRule(intermediates[start : start+size])
		start += size
	}
	result := anyRule(groups)
	for group, groupResult := range groups {
		if groupResult != result {
			continue
		}
		size := int(layout.sizes[group])
		for index := starts[group]; index < starts[group]+size; index++ {
			if intermediates[index] == result {
				return Outcome{result: result, decisive: index, valid: true}
			}
		}
		return Outcome{}
	}
	return Outcome{}
}

// signatureAll applies the Section 14.6 step 6 sig-all rule.
func signatureAll(results []Result) Result {
	allPass, nonPassAllTemp, anyFail := true, true, false
	for _, result := range results {
		if result == ResultPass {
			continue
		}
		allPass = false
		if result != ResultTempError {
			nonPassAllTemp = false
		}
		if result == ResultFail {
			anyFail = true
		}
	}
	switch {
	case allPass:
		return ResultPass
	case nonPassAllTemp:
		return ResultTempError
	case anyFail:
		return ResultFail
	default:
		return ResultPermError
	}
}

// signatureAny applies the Section 14.6 step 7 sig-any rule.
func signatureAny(results []Result) Result {
	return firstPresent(results, ResultPass, ResultTempError, ResultFail)
}

// hashAll applies the Section 14.7 step 4 hash-all rule.
func hashAll(results []Result) Result {
	allPass, anyFail := true, false
	for _, result := range results {
		allPass = allPass && result == ResultPass
		anyFail = anyFail || result == ResultFail
	}
	switch {
	case allPass:
		return ResultPass
	case anyFail:
		return ResultFail
	default:
		return ResultPermError
	}
}

// hashAny applies the Section 14.7 step 5 hash-any rule.
func hashAny(results []Result) Result {
	return firstPresent(results, ResultPass, ResultFail)
}

// firstPresent returns the first candidate, in precedence order, that occurs
// in results, and PERMERROR when none occurs.
func firstPresent(results []Result, precedence ...Result) Result {
	for _, candidate := range precedence {
		for _, result := range results {
			if result == candidate {
				return candidate
			}
		}
	}
	return ResultPermError
}
