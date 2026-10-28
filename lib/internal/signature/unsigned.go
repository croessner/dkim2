package signature

import "github.com/croessner/dkim2/internal/combine"

// unsignedSetComponent names one set of the Section 12.8 unsigned s= value:
// the selector and algorithm spellings whose signature value is nulled.
type unsignedSetComponent struct {
	selector  string
	algorithm string
}

// appendUnsignedSetList is the single owner of the Draft-08 Section 12.8
// unsigned s= rendering shared by signer and verifier: every set keeps its
// selector, algorithm name, and both colons, the signature value is the null
// string, the "," and "|" separators stay exactly where the layout puts
// them, and no white space is emitted. It reports false when the layout does
// not describe the sets or a component is empty.
func appendUnsignedSetList(output []byte, sets []unsignedSetComponent, layout combine.Layout) ([]byte, bool) {
	if len(sets) == 0 || !layout.Valid() || layout.Sets() != len(sets) {
		return nil, false
	}
	for index, set := range sets {
		if set.selector == "" || set.algorithm == "" {
			return nil, false
		}
		if separator := layout.SeparatorBefore(index); separator != 0 {
			output = append(output, separator)
		}
		output = append(output, set.selector...)
		output = append(output, ':')
		output = append(output, set.algorithm...)
		output = append(output, ':')
	}
	return output, true
}

// UnsignedSignatureValue renders the Section 12.8 unsigned s= value of this
// parsed field from its group structure, keeping the received selector
// spelling. Verifier canonicalization and the signer's completion proof both
// use it, so the separators that were signed are the ones that are checked.
func (s Signature) UnsignedSignatureValue() ([]byte, bool) {
	sets := make([]unsignedSetComponent, len(s.signatures))
	for index, set := range s.signatures {
		sets[index] = unsignedSetComponent{selector: set.rawSelector, algorithm: set.algorithm}
	}
	return appendUnsignedSetList(nil, sets, s.setLayout)
}

// signingGroup returns the fixed generated-layout group of a signable
// algorithm: classical algorithms form the first sig-all group and
// a post-quantum algorithm forms a separate alternative group after "|", the
// Section 10.9 phased-deployment pattern that lets a verifier without the
// newer algorithm pass through the classical group.
func (a Algorithm) signingGroup() int {
	switch a {
	case AlgorithmRSASHA256, AlgorithmEd25519SHA256:
		return 0
	default:
		return 1
	}
}

// generatedSetLayout derives the fixed signer layout from set plans already
// sorted into canonical signing order. It is computed before any signature
// value exists, so every value covers the same unsigned field.
func generatedSetLayout(plans []SetPlan) (combine.Layout, bool) {
	if len(plans) == 0 {
		return combine.Layout{}, false
	}
	sizes := make([]int, 0, 2)
	current := -1
	for _, plan := range plans {
		group := plan.Algorithm.signingGroup()
		if group < current {
			return combine.Layout{}, false
		}
		if group != current {
			sizes = append(sizes, 0)
			current = group
		}
		sizes[len(sizes)-1]++
	}
	return combine.NewLayout(sizes...)
}

// unsignedSetListFromPlans renders the Section 12.8 unsigned s= value of a
// generated target through the shared renderer.
func unsignedSetListFromPlans(plans []SetPlan) ([]byte, bool) {
	layout, ok := generatedSetLayout(plans)
	if !ok {
		return nil, false
	}
	sets := make([]unsignedSetComponent, len(plans))
	for index, plan := range plans {
		sets[index] = unsignedSetComponent{selector: plan.Selector, algorithm: string(plan.Algorithm)}
	}
	return appendUnsignedSetList(nil, sets, layout)
}
