package signature

import (
	"bytes"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// FuzzDKIM2SignatureRender exercises bounded target validation and deterministic rendering.
func FuzzDKIM2SignatureRender(f *testing.F) {
	f.Add(uint64(1), uint64(1), []byte("selector"), []byte("nonce"), false)
	f.Add(^uint64(0), ^uint64(0), []byte("bad selector"), bytes.Repeat([]byte{'n'}, 65), true)

	f.Fuzz(func(t *testing.T, sequence, instanceNumber uint64, selectorSeed, nonceSeed []byte, nextDomain bool) {
		request := fuzzSignatureTargetRequest(sequence, instanceNumber, selectorSeed, nonceSeed, nextDomain)
		first, firstErr := NewUnsignedTarget(request, DefaultRenderLimits())
		second, secondErr := NewUnsignedTarget(request, DefaultRenderLimits())
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("repeated construction classification differs: first=%v second=%v", firstErr, secondErr)
		}
		if firstErr != nil {
			return
		}
		if !first.Valid() || !second.Valid() || !bytes.Equal(first.UnsignedBytes(), second.UnsignedBytes()) {
			t.Fatal("valid repeated unsigned targets differ")
		}
		complete, err := first.Complete([]SetValue{{
			Selector: request.Sets[0].Selector, Algorithm: request.Sets[0].Algorithm,
			Signature: bytes.Repeat([]byte{0x5a}, 64),
		}})
		if err != nil {
			t.Fatalf("Complete() error = %v", err)
		}
		message, err := rawmsg.Parse(complete.Bytes())
		if err != nil || message.Headers().Len() != 1 {
			t.Fatalf("rawmsg.Parse(rendered) error = %v", err)
		}
		parsed, err := Parse(message.Headers().Fields()[0])
		if err != nil || parsed.Sequence() != request.Sequence ||
			parsed.InstanceNumber() != request.InstanceNumber || parsed.Domain() != request.Domain {
			t.Fatalf("Parse(rendered) sequence=%d instance=%d domain=%q error=%v",
				parsed.Sequence(), parsed.InstanceNumber(), parsed.Domain(), err)
		}
		sets := parsed.SignatureSets()
		if len(sets) != 1 || sets[0].Selector() != request.Sets[0].Selector ||
			Algorithm(sets[0].Algorithm()) != request.Sets[0].Algorithm {
			t.Fatal("parsed signature set differs from rendered target")
		}
		nonce, noncePresent := parsed.Nonce()
		if noncePresent != request.NoncePresent || noncePresent && !bytes.Equal(nonce, request.Nonce) {
			t.Fatal("parsed nonce differs from rendered target")
		}
		if nextDomain {
			domain, present := parsed.NextDomain()
			if !present || domain != request.NextDomain || len(parsed.MailFrom().Value()) != 0 || len(parsed.Recipients()) != 0 {
				t.Fatal("parsed next-domain target has wrong envelope form")
			}
		} else if parsed.HasNextDomain() ||
			!bytes.Equal(parsed.MailFrom().Value(), request.MailFrom) ||
			len(parsed.Recipients()) != 1 ||
			!bytes.Equal(parsed.Recipients()[0].Value(), request.Recipients[0]) {
			t.Fatal("parsed ordinary target has wrong envelope form")
		}
	})
}

// FuzzCustodyTransitions exercises ordinary and next-domain custody terminal forms.
func FuzzCustodyTransitions(f *testing.F) {
	f.Add(false, false, false, byte(0))
	f.Add(false, true, false, byte(0))
	f.Add(true, false, false, byte(0))
	f.Add(true, true, false, byte(0))
	f.Add(false, false, true, byte(0))
	f.Add(true, true, false, byte(1))

	f.Fuzz(func(t *testing.T, priorNextDomain, currentNextDomain, domainMismatch bool, sequenceOffset byte) {
		headers := fuzzPriorCustodyHeaders(t, priorNextDomain)
		domain := "b.test"
		if domainMismatch {
			domain = "wrong.test"
		}
		request := TargetRequest{
			Sequence: 2 + uint64(sequenceOffset%2), InstanceNumber: 2, Timestamp: 2,
			Domain: domain,
			Sets:   []SetPlan{{Selector: "current", Algorithm: AlgorithmEd25519SHA256}},
		}
		if currentNextDomain {
			request.NextDomain = "c.test"
		} else {
			request.MailFrom = []byte("<sender@b.test>")
			request.Recipients = [][]byte{[]byte("<recipient@c.test>")}
		}
		target, targetErr := NewUnsignedTarget(request, DefaultRenderLimits())
		if targetErr != nil {
			t.Fatalf("NewUnsignedTarget(current) error = %v", targetErr)
		}
		first, firstErr := ValidateUnsignedExtension(headers, target, DefaultCustodyLimits())
		second, secondErr := ValidateUnsignedExtension(headers, target, DefaultCustodyLimits())
		if (firstErr == nil) != (secondErr == nil) || first.Evaluated() != second.Evaluated() ||
			first.Status() != second.Status() {
			t.Fatalf("repeated custody classification differs: first=%v/%q second=%v/%q",
				firstErr, first.Status(), secondErr, second.Status())
		}
		wantValid := !domainMismatch && sequenceOffset%2 == 0
		if !wantValid {
			if firstErr == nil || first.Valid() {
				t.Fatal("invalid custody transition unexpectedly passed")
			}
			return
		}
		wantStatus := CustodyStatusOrdinaryComplete
		wantDirect := CustodyDirectAlignmentPass
		if currentNextDomain {
			wantStatus = CustodyStatusTerminalNextDomain
			wantDirect = CustodyDirectAlignmentNotApplicableNextDomain
		}
		if firstErr != nil || !first.Valid() || !first.Evaluated() || first.Count() != 2 ||
			first.Status() != wantStatus || first.DirectAlignment(2) != wantDirect ||
			first.HadNextDomain() != (priorNextDomain || currentNextDomain) {
			t.Fatalf("valid transition result valid=%t evaluated=%t count=%d status=%q direct=%q nd=%t error=%v",
				first.Valid(), first.Evaluated(), first.Count(), first.Status(), first.DirectAlignment(2),
				first.HadNextDomain(), firstErr)
		}
	})
}

// FuzzUnsignedSignatureTarget exercises completion and Section 9.6 unsigned rebuilding.
func FuzzUnsignedSignatureTarget(f *testing.F) {
	f.Add([]byte("selector"), []byte("signature"))
	f.Add([]byte("bad selector"), bytes.Repeat([]byte{0xff}, 128))

	f.Fuzz(func(t *testing.T, selectorSeed, signatureSeed []byte) {
		request := fuzzSignatureTargetRequest(1, 1, selectorSeed, nil, false)
		target, err := NewUnsignedTarget(request, DefaultRenderLimits())
		if err != nil {
			return
		}
		signatureBytes := make([]byte, 64)
		for index, value := range signatureSeed {
			signatureBytes[index%len(signatureBytes)] ^= value
		}
		values := []SetValue{{
			Selector: request.Sets[0].Selector, Algorithm: AlgorithmEd25519SHA256,
			Signature: signatureBytes,
		}}
		complete, err := target.Complete(values)
		if err != nil || !complete.Valid() {
			t.Fatalf("Complete() error = %v", err)
		}
		rebuilt, err := target.RebuildUnsignedFromComplete(complete)
		if err != nil || !rebuilt.Valid() || !bytes.Equal(rebuilt.UnsignedBytes(), target.UnsignedBytes()) {
			t.Fatalf("RebuildUnsignedFromComplete() error = %v", err)
		}
	})
}

// fuzzSignatureTargetRequest constructs one bounded ordinary or next-domain target.
func fuzzSignatureTargetRequest(sequence, instanceNumber uint64, selectorSeed, nonceSeed []byte, nextDomain bool) TargetRequest {
	if sequence == 0 {
		sequence = 1
	}
	if instanceNumber == 0 {
		instanceNumber = 1
	}
	selector := fuzzDNSLabel(selectorSeed)
	nonce := bytes.Clone(nonceSeed)
	if len(nonce) > 64 {
		nonce = nonce[:64]
	}
	const nonceAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	for index := range nonce {
		nonce[index] = nonceAlphabet[int(nonce[index])%len(nonceAlphabet)]
	}
	request := TargetRequest{
		Sequence: sequence, InstanceNumber: instanceNumber, Timestamp: 1,
		Domain: "example.test", Sets: []SetPlan{{Selector: selector, Algorithm: AlgorithmEd25519SHA256}},
		Nonce: nonce, NoncePresent: len(nonce) > 0,
	}
	if nextDomain {
		request.NextDomain = "next.test"
	} else {
		request.MailFrom = []byte("<sender@example.test>")
		request.Recipients = [][]byte{[]byte("<recipient@next.test>")}
	}
	return request
}

// fuzzDNSLabel maps arbitrary bytes to one nonempty valid lowercase DNS label.
func fuzzDNSLabel(seed []byte) string {
	if len(seed) == 0 {
		return "selector"
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	size := len(seed)
	if size > 63 {
		size = 63
	}
	label := make([]byte, size)
	for index := range label {
		label[index] = alphabet[int(seed[index])%len(alphabet)]
	}
	return string(label)
}

// fuzzPriorCustodyHeaders creates one complete valid first-hop field for transition testing.
func fuzzPriorCustodyHeaders(t *testing.T, nextDomain bool) rawmsg.HeaderBlock {
	t.Helper()
	request := TargetRequest{
		Sequence: 1, InstanceNumber: 1, Timestamp: 1, Domain: "a.test",
		Sets: []SetPlan{{Selector: "prior", Algorithm: AlgorithmEd25519SHA256}},
	}
	if nextDomain {
		request.NextDomain = "b.test"
	} else {
		request.MailFrom = []byte("<sender@a.test>")
		request.Recipients = [][]byte{[]byte("<recipient@b.test>")}
	}
	target, err := NewUnsignedTarget(request, DefaultRenderLimits())
	if err != nil {
		t.Fatalf("NewUnsignedTarget(prior) error = %v", err)
	}
	complete, err := target.Complete([]SetValue{{
		Selector: "prior", Algorithm: AlgorithmEd25519SHA256, Signature: bytes.Repeat([]byte{1}, 64),
	}})
	if err != nil {
		t.Fatalf("Complete(prior) error = %v", err)
	}
	message, err := rawmsg.Parse(complete.Bytes())
	if err != nil || message.Headers().Len() != 1 {
		t.Fatalf("rawmsg.Parse(prior) error = %v", err)
	}
	return message.Headers()
}
