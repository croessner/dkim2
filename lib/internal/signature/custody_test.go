package signature

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

// TestCustodyDirectAlignmentUsesOnlyMailFromLabelReduction locks Section 9.4 direction.
func TestCustodyDirectAlignmentUsesOnlyMailFromLabelReduction(t *testing.T) {
	pass := []Signature{ordinaryCustodySignature(1, "example.test", "<\"sender@local\"@sub.example.test>", "<next@relay.test>")}
	result, err := ValidateCustody(pass, CustodyLimits{})
	if err != nil || !result.Valid() || result.Status() != CustodyStatusOrdinaryComplete {
		t.Fatalf("direct relaxed alignment code=%s status=%s", custodyTestCode(err), result.Status())
	}
	fail := []Signature{ordinaryCustodySignature(1, "sub.example.test", "<sender@example.test>", "<next@relay.test>")}
	result, err = ValidateCustody(fail, CustodyLimits{})
	if !IsErrorCode(err, ErrorCodeCustodyMismatch) || !result.Evaluated() || result.Valid() || result.DirectAlignment(1) != CustodyDirectAlignmentMismatch {
		t.Fatalf("reversed direct alignment code=%s status=%s", custodyTestCode(err), result.DirectAlignment(1))
	}
}

// TestCustodyOrdinaryAdjacencyMatchesPreviousRecipientInOneDirection locks adjacent hops.
func TestCustodyOrdinaryAdjacencyMatchesPreviousRecipientInOneDirection(t *testing.T) {
	first := ordinaryCustodySignature(1, "origin.test", "<sender@origin.test>", "<next@relay.example>")
	passing := ordinaryCustodySignature(2, "relay.example", "<sender@sub.relay.example>", "<final@dest.test>")
	if result, err := ValidateCustody([]Signature{first, passing}, CustodyLimits{}); err != nil || result.Status() != CustodyStatusOrdinaryComplete {
		t.Fatalf("adjacent ordinary pass code=%s status=%s", custodyTestCode(err), result.Status())
	}
	reversedFirst := ordinaryCustodySignature(1, "origin.test", "<sender@origin.test>", "<next@sub.relay.example>")
	reversedNext := ordinaryCustodySignature(2, "relay.example", "<sender@relay.example>", "<final@dest.test>")
	if _, err := ValidateCustody([]Signature{reversedFirst, reversedNext}, CustodyLimits{}); !IsErrorCode(err, ErrorCodeCustodyMismatch) {
		t.Fatalf("reversed adjacency code=%s", custodyTestCode(err))
	}
	nearMiss := ordinaryCustodySignature(2, "evilrelay.example", "<sender@evilrelay.example>", "<final@dest.test>")
	if _, err := ValidateCustody([]Signature{first, nearMiss}, CustodyLimits{}); !IsErrorCode(err, ErrorCodeCustodyMismatch) {
		t.Fatalf("near-miss adjacency code=%s", custodyTestCode(err))
	}
}

// TestCustodyNextDomainTransitionsAreExact verifies ordinary entry, runs, and ordinary termination.
func TestCustodyNextDomainTransitionsAreExact(t *testing.T) {
	ordinary := ordinaryCustodySignature(1, "origin.test", "<sender@origin.test>", "<other@elsewhere.test>", "<next@entry.example>")
	entry := nextDomainCustodySignature(2, "entry.example", "middle.example")
	continuation := nextDomainCustodySignature(3, "middle.example", "exit.example")
	termination := ordinaryCustodySignature(4, "exit.example", "<sender@exit.example>", "<final@dest.test>")
	result, err := ValidateCustody([]Signature{ordinary, entry, continuation, termination}, CustodyLimits{})
	if err != nil || result.Status() != CustodyStatusOrdinaryComplete || result.Count() != 4 {
		t.Fatalf("terminated nd run code=%s status=%s count=%d", custodyTestCode(err), result.Status(), result.Count())
	}
	terminal, err := ValidateCustody([]Signature{ordinary, entry, continuation}, CustodyLimits{})
	if err != nil || terminal.Status() != CustodyStatusTerminalNextDomain {
		t.Fatalf("terminal nd code=%s status=%s", custodyTestCode(err), terminal.Status())
	}
	badEntry := nextDomainCustodySignature(2, "sub.entry.example", "middle.example")
	if _, err := ValidateCustody([]Signature{ordinary, badEntry}, CustodyLimits{}); !IsErrorCode(err, ErrorCodeCustodyMismatch) {
		t.Fatalf("relaxed ordinary-to-nd code=%s", custodyTestCode(err))
	} else if typed := err.(*Error); typed.ObservedNumber() != 2 || typed.TagName() != string(TagNameNextDomain) {
		t.Fatalf("ordinary-to-nd location sequence=%d tag=%s", typed.ObservedNumber(), typed.TagName())
	}
	parentEntry := nextDomainCustodySignature(2, "example", "middle.example")
	if _, err := ValidateCustody([]Signature{ordinary, parentEntry}, CustodyLimits{}); !IsErrorCode(err, ErrorCodeCustodyMismatch) {
		t.Fatalf("parent ordinary-to-nd code=%s", custodyTestCode(err))
	}
	badContinuation := nextDomainCustodySignature(3, "sub.middle.example", "exit.example")
	if _, err := ValidateCustody([]Signature{ordinary, entry, badContinuation}, CustodyLimits{}); !IsErrorCode(err, ErrorCodeCustodyMismatch) {
		t.Fatalf("relaxed nd continuation code=%s", custodyTestCode(err))
	} else if typed := err.(*Error); typed.ObservedNumber() != 2 || typed.TagName() != string(TagNameNextDomain) {
		t.Fatalf("nd continuation location sequence=%d tag=%s", typed.ObservedNumber(), typed.TagName())
	}
	parentContinuation := ordinaryCustodySignature(3, "example", "<sender@example>", "<final@dest.test>")
	if _, err := ValidateCustody([]Signature{ordinary, entry, parentContinuation}, CustodyLimits{}); !IsErrorCode(err, ErrorCodeCustodyMismatch) {
		t.Fatalf("parent nd termination code=%s", custodyTestCode(err))
	}
}

// TestCustodyNullReversePathAndBoundsFailClosed verifies direct null and collection limits.
func TestCustodyNullReversePathAndBoundsFailClosed(t *testing.T) {
	directNull := ordinaryCustodySignature(1, "origin.test", "<>", "<next@relay.test>")
	if _, err := ValidateCustody([]Signature{directNull}, CustodyLimits{}); err != nil {
		t.Fatalf("direct null reverse path code=%s", custodyTestCode(err))
	}
	nextNull := ordinaryCustodySignature(2, "relay.test", "<>", "<final@dest.test>")
	if _, err := ValidateCustody([]Signature{directNull, nextNull}, CustodyLimits{}); !IsErrorCode(err, ErrorCodeCustodyMismatch) {
		t.Fatalf("adjacent null reverse path code=%s", custodyTestCode(err))
	}
	oversized := make([]Signature, DefaultLimits().MaxSignatures+1)
	if _, err := ValidateCustody(oversized, CustodyLimits{}); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("oversized custody code=%s", custodyTestCode(err))
	}
	gap := []Signature{ordinaryCustodySignature(1, "one.test", "<a@one.test>", "<b@two.test>"), ordinaryCustodySignature(3, "two.test", "<b@two.test>", "<c@three.test>")}
	if _, err := ValidateCustody(gap, CustodyLimits{}); !IsErrorCode(err, ErrorCodeSequenceGap) {
		t.Fatalf("custody gap code=%s", custodyTestCode(err))
	}
}

// TestCustodyRecipientLimitAcceptsExactAndRejectsOneOver locks the per-hop ceiling.
func TestCustodyRecipientLimitAcceptsExactAndRejectsOneOver(t *testing.T) {
	const limit = 2
	exact := ordinaryCustodySignature(1, "origin.test", "<sender@origin.test>", "<one@first.test>", "<two@second.test>")
	if _, err := ValidateCustody([]Signature{exact}, CustodyLimits{MaxRecipientsPerSignature: limit}); err != nil {
		t.Fatalf("exact recipient limit code=%s", custodyTestCode(err))
	}
	oneOver := ordinaryCustodySignature(1, "origin.test", "<sender@origin.test>", "<one@first.test>", "<two@second.test>", "<three@third.test>")
	if _, err := ValidateCustody([]Signature{oneOver}, CustodyLimits{MaxRecipientsPerSignature: limit}); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("one-over recipient limit code=%s", custodyTestCode(err))
	}
}

// TestCustodySortsAscendingAndRejectsSequenceAmbiguity verifies bounded ordering semantics.
func TestCustodySortsAscendingAndRejectsSequenceAmbiguity(t *testing.T) {
	first := ordinaryCustodySignature(1, "one.test", "<a@one.test>", "<b@two.test>")
	second := ordinaryCustodySignature(2, "two.test", "<b@two.test>", "<c@three.test>")
	if result, err := ValidateCustody([]Signature{second, first}, CustodyLimits{}); err != nil || result.Count() != 2 {
		t.Fatalf("out-of-order custody code=%s count=%d", custodyTestCode(err), result.Count())
	}
	if _, err := ValidateCustody([]Signature{first, first}, CustodyLimits{}); !IsErrorCode(err, ErrorCodeDuplicateSequence) {
		t.Fatalf("duplicate custody code=%s", custodyTestCode(err))
	}
	maximum := second
	maximum.sequence = math.MaxUint64
	if _, err := ValidateCustody([]Signature{first, maximum}, CustodyLimits{}); !IsErrorCode(err, ErrorCodeSequenceGap) {
		t.Fatalf("MaxUint64 custody code=%s", custodyTestCode(err))
	}
}

// TestCustodyRejectsContradictoryAndNonDNSPathForms verifies fail-closed envelope derivation.
func TestCustodyRejectsContradictoryAndNonDNSPathForms(t *testing.T) {
	contradictory := nextDomainCustodySignature(1, "entry.test", "next.test")
	contradictory.mailFrom = EnvelopePath{value: []byte("<a@entry.test>")}
	contradictory.recipients = []EnvelopePath{{value: []byte("<b@next.test>")}}
	zero := Signature{sequence: 1, instanceNumber: 1, domain: "entry.test"}
	hiddenNextDomain := ordinaryCustodySignature(1, "entry.test", "<a@entry.test>", "<b@next.test>")
	hiddenNextDomain.nextDomain = "secret.next.test"
	addressLiteral := ordinaryCustodySignature(1, "entry.test", "<a@[192.0.2.1]>", "<b@next.test>")
	for _, chain := range [][]Signature{{contradictory}, {zero}, {hiddenNextDomain}} {
		if _, err := ValidateCustody(chain, CustodyLimits{}); !IsErrorCode(err, ErrorCodeCustodyMismatch) {
			t.Fatalf("invalid envelope form code=%s", custodyTestCode(err))
		}
	}
	addressResult, err := ValidateCustody([]Signature{addressLiteral}, CustodyLimits{})
	if !IsErrorCode(err, ErrorCodeCustodyMismatch) || addressResult.DirectAlignment(1) != CustodyDirectAlignmentInvalid {
		t.Fatalf("address-literal mf evaluation code=%s status=%s", custodyTestCode(err), addressResult.DirectAlignment(1))
	}
	literalRecipient := ordinaryCustodySignature(1, "entry.test", "<a@entry.test>", "<b@[192.0.2.1]>")
	if _, err := ValidateCustody([]Signature{literalRecipient}, CustodyLimits{}); err != nil {
		t.Fatalf("terminal address-literal rt code=%s", custodyTestCode(err))
	}
	literalSuccessor := ordinaryCustodySignature(2, "next.test", "<b@next.test>", "<c@final.test>")
	if _, err := ValidateCustody([]Signature{literalRecipient, literalSuccessor}, CustodyLimits{}); !IsErrorCode(err, ErrorCodeCustodyMismatch) {
		t.Fatalf("address-literal rt transition code=%s", custodyTestCode(err))
	}
	sourceRoute := ordinaryCustodySignature(1, "entry.test", "<@route.test:a@sub.entry.test>", "<b@next.test>")
	if _, err := ValidateCustody([]Signature{sourceRoute}, CustodyLimits{}); err != nil {
		t.Fatalf("source-route domain extraction code=%s", custodyTestCode(err))
	}
}

// TestCustodyFormattingIsConstantAndSecretSafe verifies result and error fmt paths.
func TestCustodyFormattingIsConstantAndSecretSafe(t *testing.T) {
	result := CustodyResult{status: CustodyStatus("secretcustodydomain"), count: 1, initialized: true}
	err := newError(ErrorCodeCustodyMismatch, ErrorLocation{}, ErrorDetails{}, nil)
	for _, formatted := range []string{
		fmt.Sprintf("%v", result), fmt.Sprintf("%+v", result), fmt.Sprintf("%#v", result), result.String(), result.GoString(),
		fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err), err.GoString(),
	} {
		if strings.Contains(formatted, "secretcustodydomain") || !strings.Contains(formatted, "signature.") && !strings.Contains(formatted, "signature parser error") {
			t.Fatal("custody formatting exposed content or bypassed safe formatter")
		}
	}
}

// TestCustodyResultRejectsForgedTerminalState verifies result-owned coherence.
func TestCustodyResultRejectsForgedTerminalState(t *testing.T) {
	forged := CustodyResult{
		status: CustodyStatusTerminalNextDomain, count: 1,
		direct: []CustodyDirectAlignmentStatus{CustodyDirectAlignmentNotApplicableNextDomain}, initialized: true,
	}
	if forged.Valid() {
		t.Fatal("terminal custody result without nd= evidence became valid")
	}
}

// ordinaryCustodySignature constructs one parser-equivalent ordinary custody fixture.
func ordinaryCustodySignature(sequence uint64, domain, mailFrom string, recipients ...string) Signature {
	paths := make([]EnvelopePath, len(recipients))
	for index, recipient := range recipients {
		paths[index] = EnvelopePath{value: []byte(recipient)}
	}
	return Signature{
		sequence: sequence, instanceNumber: 1, domain: domain,
		mailFrom: EnvelopePath{value: []byte(mailFrom)}, recipients: paths,
	}
}

// nextDomainCustodySignature constructs one parser-equivalent next-domain fixture.
func nextDomainCustodySignature(sequence uint64, domain, nextDomain string) Signature {
	return Signature{sequence: sequence, instanceNumber: 1, domain: domain, nextDomain: nextDomain, hasNextDomain: true}
}

// custodyTestCode returns a closed code without formatting arbitrary errors.
func custodyTestCode(err error) ErrorCode {
	if typed, ok := err.(*Error); ok {
		return typed.Code()
	}
	return ""
}
