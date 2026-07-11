package tagvalue

import "testing"

// TestDNSScanValidatesKnownAndUnknownNamesUniformly verifies the shared exact-mode contract.
func TestDNSScanValidatesKnownAndUnknownNamesUniformly(t *testing.T) {
	field, err := Scan([]byte("v=DKIM1; V=extension; future_tag=opaque;"), KnownTags{}, Limits{MaxTags: 3, MaxTagNameBytes: 63, MaxTagValueBytes: 64, MaxFieldValueBytes: 128, MaxBase64DecodedBytes: 64})
	if err != nil || field.Len() != 3 || field.Tags()[0].Name() != "v" || field.Tags()[1].Name() != "V" {
		t.Fatalf("Scan() field=%#v error=%v", field, err)
	}
	for _, input := range []string{"future=x; future=y", "future=bad\x00value", "future=x\n"} {
		if _, err := Scan([]byte(input), KnownTags{}, Limits{}); err == nil {
			t.Fatalf("Scan(%q) unexpectedly passed", input)
		}
	}
	if _, err := Scan([]byte("p=bad\x00value"), MustKnownTags("p"), Limits{}); err == nil {
		t.Fatal("known DNS tag bypassed generic tag-value grammar")
	}
}
