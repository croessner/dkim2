package rawmsg

import (
	"bytes"
	"testing"
)

// TestHeaderBlockNameAccessorsPreserveOrderAndCopies verifies duplicate lookup safety.
func TestHeaderBlockNameAccessorsPreserveOrderAndCopies(t *testing.T) {
	raw := []byte("X-Test: one\r\nSubject: value\r\nx-test: two\r\n\r\nbody")
	msg, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	matches := msg.Headers().FieldsByName("X-Test")
	if len(matches) != 2 {
		t.Fatalf("FieldsByName returned %d matches, want 2", len(matches))
	}
	if matches[0].Index() != 0 || matches[1].Index() != 2 {
		t.Fatalf("match indexes = %d,%d want 0,2", matches[0].Index(), matches[1].Index())
	}
	if got := matches[0].RawValue(); !bytes.Equal(got, []byte(" one")) {
		t.Fatalf("first raw value = %q", got)
	}

	rawName := matches[0].RawName()
	rawName[0] = 'Z'
	again := msg.Headers().FieldsByName("x-test")
	if got := again[0].RawName(); !bytes.Equal(got, []byte("X-Test")) {
		t.Fatalf("FieldsByName returned mutable field state: %q", got)
	}

	last, ok := msg.Headers().LastFieldByName("X-TEST")
	if !ok {
		t.Fatal("LastFieldByName did not find duplicate")
	}
	if last.Index() != 2 {
		t.Fatalf("last index = %d, want 2", last.Index())
	}
}

// TestHeaderBlockNameAccessorsRejectInvalidLookupNames verifies invalid names miss safely.
func TestHeaderBlockNameAccessorsRejectInvalidLookupNames(t *testing.T) {
	msg, err := Parse([]byte("Subject: value\r\n\r\nbody"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if got := msg.Headers().FieldsByName("Bad Name"); got != nil {
		t.Fatalf("FieldsByName invalid lookup returned %d matches", len(got))
	}
	if _, ok := msg.Headers().LastFieldByName("Bad:Name"); ok {
		t.Fatal("LastFieldByName matched invalid lookup")
	}
}
