package filter

import (
	"bytes"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
)

// TestTransformInsertsOnlyTheAdmittedOrderedFields proves inherited LF bytes
// remain unchanged and M16 ordered additions precede the existing separator.
func TestTransformInsertsOnlyTheAdmittedOrderedFields(t *testing.T) {
	first, err := adapter.NewAction(adapter.ActionAddHeader, "Message-Instance", " i=1; m=a")
	if err != nil {
		t.Fatal("message-instance action failed")
	}
	second, err := adapter.NewAction(adapter.ActionAddHeader, "DKIM2-Signature", " i=1; s=a")
	if err != nil {
		t.Fatal("signature action failed")
	}
	plan, err := adapter.NewFilterPlan(adapter.FilterSign, adapter.ResultPass, adapter.DispositionAccept, []adapter.Action{first, second})
	if err != nil {
		t.Fatal("sign plan failed")
	}
	output, err := Transform([]byte("Subject: preserved\n\nbody\n"), plan)
	want := []byte("Subject: preserved\nMessage-Instance: i=1; m=a\nDKIM2-Signature: i=1; s=a\n\nbody\n")
	if err != nil || !bytes.Equal(output, want) {
		t.Fatal("rewrite changed inherited bytes or action order")
	}
}

// TestTransformPreservesNotApplicableSignBytes proves a sign 204 can only
// produce a detached unchanged copy of the complete transport message.
func TestTransformPreservesNotApplicableSignBytes(t *testing.T) {
	plan, err := adapter.NewFilterPlan(
		adapter.FilterSign, adapter.ResultNone, adapter.DispositionContinue, nil,
	)
	if err != nil {
		t.Fatal("not-applicable sign plan failed")
	}
	message := []byte("Subject: unsigned\n\nbinary\x00body\n")
	output, err := Transform(message, plan)
	if err != nil || !bytes.Equal(output, message) {
		t.Fatal("not-applicable sign changed complete-message bytes")
	}
	output[0] = 'X'
	if message[0] != 'S' {
		t.Fatal("not-applicable sign output aliases protected input")
	}
}

// TestTransformDoesNotInventPostColonWhitespace proves action values remain
// byte-exact after the field-name colon.
func TestTransformDoesNotInventPostColonWhitespace(t *testing.T) {
	first, _ := adapter.NewAction(adapter.ActionAddHeader, "Message-Instance", "\ti=1; m=a")
	second, _ := adapter.NewAction(adapter.ActionAddHeader, "DKIM2-Signature", " i=1; s=a")
	plan, _ := adapter.NewFilterPlan(
		adapter.FilterSign,
		adapter.ResultPass,
		adapter.DispositionAccept,
		[]adapter.Action{first, second},
	)
	output, err := Transform([]byte("Subject: x\n\nbody\n"), plan)
	want := []byte("Subject: x\nMessage-Instance:\ti=1; m=a\nDKIM2-Signature: i=1; s=a\n\nbody\n")
	if err != nil || !bytes.Equal(output, want) {
		t.Fatal("rewrite changed daemon-authorized post-colon bytes")
	}
}

// TestTransformPreservesHeaderOnlyForm proves the adapter can append admitted
// fields without inventing a header/body separator.
func TestTransformPreservesHeaderOnlyForm(t *testing.T) {
	first, _ := adapter.NewAction(adapter.ActionAddHeader, "Message-Instance", " i=1; m=a")
	second, _ := adapter.NewAction(adapter.ActionAddHeader, "DKIM2-Signature", " i=1; s=a")
	plan, _ := adapter.NewFilterPlan(
		adapter.FilterSign,
		adapter.ResultPass,
		adapter.DispositionAccept,
		[]adapter.Action{first, second},
	)
	output, err := Transform([]byte("Subject: x\n"), plan)
	want := []byte("Subject: x\nMessage-Instance: i=1; m=a\nDKIM2-Signature: i=1; s=a\n")
	if err != nil || !bytes.Equal(output, want) {
		t.Fatal("header-only rewrite invented a body separator")
	}
}

// TestTransformPrependsFieldsBeforeAnEmptyHeaderBlock proves generated fields
// cannot cross the sole inherited header/body separator into body bytes.
func TestTransformPrependsFieldsBeforeAnEmptyHeaderBlock(t *testing.T) {
	action, _ := adapter.NewAction(
		adapter.ActionAddHeader,
		"DKIM2-Signature",
		" i=2; s=a",
	)
	plan, _ := adapter.NewFilterPlan(
		adapter.FilterRevise,
		adapter.ResultPass,
		adapter.DispositionAccept,
		[]adapter.Action{action},
	)
	output, err := Transform([]byte("\nbody\n"), plan)
	want := []byte("DKIM2-Signature: i=2; s=a\n\nbody\n")
	if err != nil {
		t.Fatal("empty inherited header block rewrite failed")
	}
	if !bytes.Equal(output, want) {
		t.Fatal("empty inherited header block moved an action into the body")
	}
}

// TestTransformPreservesBinaryBody proves only the inherited header block is
// changed while body CRLF, bare CR, NUL, and UTF-8 bytes remain exact.
func TestTransformPreservesBinaryBody(t *testing.T) {
	action, _ := adapter.NewAction(adapter.ActionAddHeader, "DKIM2-Signature", " i=2; s=a")
	plan, _ := adapter.NewFilterPlan(
		adapter.FilterRevise,
		adapter.ResultPass,
		adapter.DispositionAccept,
		[]adapter.Action{action},
	)
	body := []byte("lf\ncrlf\r\nbare\rnul\x00utf8\xf0\x9f\x93\xa8\n")
	message := append([]byte("Subject: x\n\n"), body...)
	output, err := Transform(message, plan)
	if err != nil || !bytes.Equal(
		output,
		append([]byte("Subject: x\nDKIM2-Signature: i=2; s=a\n\n"), body...),
	) {
		t.Fatal("rewrite changed binary body bytes")
	}
}

// TestTransformRejectsUnprovenInput proves malformed full-message state cannot
// be accepted merely because an action plan itself is valid.
func TestTransformRejectsUnprovenInput(t *testing.T) {
	first, _ := adapter.NewAction(adapter.ActionAddHeader, "Message-Instance", " i=1; m=a")
	second, _ := adapter.NewAction(adapter.ActionAddHeader, "DKIM2-Signature", " i=1; s=a")
	plan, _ := adapter.NewFilterPlan(
		adapter.FilterSign,
		adapter.ResultPass,
		adapter.DispositionAccept,
		[]adapter.Action{first, second},
	)
	for _, message := range [][]byte{
		[]byte("not a field\n"),
		[]byte("Subject: x\r\n\r\nbody\r\n"),
		[]byte("Subject: x\nbroken\n\nbody\n"),
		[]byte("Subject: x\n"),
	} {
		if bytes.Equal(message, []byte("Subject: x\n")) {
			continue
		}
		if _, err := Transform(message, plan); err == nil {
			t.Fatal("malformed source message reached transformed output")
		}
	}
}

// FuzzTransform exercises complete-message rewriting with arbitrary inherited
// bytes while keeping the admitted plan independently fixed.
func FuzzTransform(f *testing.F) {
	action, _ := adapter.NewAction(adapter.ActionAddHeader, "DKIM2-Signature", " i=2; s=a")
	plan, _ := adapter.NewFilterPlan(
		adapter.FilterRevise,
		adapter.ResultPass,
		adapter.DispositionAccept,
		[]adapter.Action{action},
	)
	f.Add([]byte("Subject: seed\n\nbody\n"))
	f.Fuzz(func(_ *testing.T, message []byte) {
		if len(message) > maxInputBytes+1 {
			return
		}
		_, _ = Transform(message, plan)
	})
}
