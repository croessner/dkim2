package instance

import (
	"slices"
	"strings"
	"testing"
)

// TestHashSetFWSPositions pins every Draft-08 Section 9.3 white-space
// position of mi-h-tag: [FWS] after "=", around hash-name, before and inside
// both base64string hashes, and around "," separators are accepted; white
// space inside hash-name and between header-hash padding and the second
// colon is rejected because no production admits it there.
func TestHashSetFWSPositions(t *testing.T) {
	header := base64OfByte(0x11, 32)
	body := base64OfByte(0x22, 32)
	if !strings.HasSuffix(header, "=") {
		t.Fatal("fixture header hash must carry padding")
	}
	second := "sha512:" + base64OfByte(0x33, 64) + ":" + base64OfByte(0x44, 64)
	accepted := map[string]string{
		"after equals":              " \tsha256:" + header + ":" + body,
		"before hash-name colon":    "sha256 \t:" + header + ":" + body,
		"before header-hash":        "sha256: \t" + header + ":" + body,
		"inside header-hash":        "sha256:" + header[:8] + " \t" + header[8:] + ":" + body,
		"inside header padding":     "sha256:" + header[:len(header)-1] + " =" + ":" + body,
		"unpadded header then wsp":  "future:" + base64OfByte(0x55, 66) + " :" + base64OfByte(0x66, 66),
		"before body-hash":          "sha256:" + header + ": \t" + body,
		"inside body-hash":          "sha256:" + header + ":" + body[:8] + "\t" + body[8:],
		"after body padding":        "sha256:" + header + ":" + body + " \t",
		"around comma":              "sha256:" + header + ":" + body + " \t, \t" + second,
		"tab before comma no space": "sha256:" + header + ":" + body + "\t," + second,
	}
	for name, value := range accepted {
		t.Run("accepted/"+name, func(t *testing.T) {
			parsed, err := Parse(messageInstanceField(t, 0, "m=1; h="+value))
			if err != nil {
				t.Fatalf("Parse(%q) error = %v", value, err)
			}
			if !parsed.HashLayout().Valid() || parsed.HashLayout().Sets() != len(parsed.HashSets()) {
				t.Fatalf("HashLayout() = %v for %d sets", parsed.HashLayout().GroupSizes(), len(parsed.HashSets()))
			}
		})
	}
	rejected := map[string]string{
		"inside hash-name":            "sha 256:" + header + ":" + body,
		"after header padding":        "sha256:" + header + " :" + body,
		"tab after header padding":    "sha256:" + header + "\t:" + body,
		"only wsp header":             "sha256: \t:" + body,
		"empty set between commas":    "sha256:" + header + ":" + body + ", ," + second,
		"leading comma":               "," + "sha256:" + header + ":" + body,
		"trailing comma":              "sha256:" + header + ":" + body + ",",
		"doubled bar":                 "sha256:" + header + ":" + body + "||" + second,
		"leading bar":                 "|sha256:" + header + ":" + body,
		"trailing bar with wsp":       "sha256:" + header + ":" + body + " | ",
		"empty group between bars":    "sha256:" + header + ":" + body + "| |" + second,
		"comma then bar empty member": "sha256:" + header + ":" + body + ",|" + second,
	}
	for name, value := range rejected {
		t.Run("rejected/"+name, func(t *testing.T) {
			if _, err := Parse(messageInstanceField(t, 0, "m=1; h="+value)); !IsErrorCode(err, ErrorCodeMalformedHashSet) {
				t.Fatalf("Parse(%q) error = %v, want malformed hash set", value, err)
			}
		})
	}
}

// TestHashGroupsRejectDuplicateNamesAcrossGroups pins Section 9.3: an
// algorithm must not appear more than once in one Message-Instance, in any
// group.
func TestHashGroupsRejectDuplicateNamesAcrossGroups(t *testing.T) {
	first := "sha256:" + base64OfByte(1, 32) + ":" + base64OfByte(2, 32)
	again := "sha256:" + base64OfByte(3, 32) + ":" + base64OfByte(4, 32)
	if _, err := Parse(messageInstanceField(t, 0, "m=1; h="+first+" | "+again)); !IsErrorCode(err, ErrorCodeDuplicateHashName) {
		t.Fatalf("Parse() error = %v, want duplicate hash name across groups", err)
	}
}

// TestHashGroupsCountSetsAcrossGroupsForLimit pins that max_hash_sets counts
// every set in every group.
func TestHashGroupsCountSetsAcrossGroupsForLimit(t *testing.T) {
	parser, err := NewParser(Limits{MaxHashSets: 2})
	if err != nil {
		t.Fatal(err)
	}
	value := "m=1; h=a:YQ==:Yg==|b:YQ==:Yg==|c:YQ==:Yg=="
	if _, err := parser.ParseField(messageInstanceField(t, 0, value)); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("ParseField() error = %v, want limit exceeded", err)
	}
}

// TestHashLayoutOfSingleGroup proves a ","-only value is one hash-all group.
func TestHashLayoutOfSingleGroup(t *testing.T) {
	value := "sha256:" + base64OfByte(1, 32) + ":" + base64OfByte(2, 32) + ",future:YQ==:Yg=="
	parsed, err := Parse(messageInstanceField(t, 0, "m=1; h="+value))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(parsed.HashLayout().GroupSizes(), []int{2}) {
		t.Fatalf("HashLayout() = %v, want [2]", parsed.HashLayout().GroupSizes())
	}
}

// TestHashAlternativeGroupsParse proves "|" groups are parsed into the
// hash-any layout now that the Section 14.7 algebra evaluates them.
func TestHashAlternativeGroupsParse(t *testing.T) {
	value := "sha256:" + base64OfByte(1, 32) + ":" + base64OfByte(2, 32) + " | future:YQ==:Yg==,sha512:" + base64OfByte(3, 64) + ":" + base64OfByte(4, 64)
	parsed, err := Parse(messageInstanceField(t, 0, "m=1; h="+value))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !slices.Equal(parsed.HashLayout().GroupSizes(), []int{1, 2}) || len(parsed.HashSets()) != 3 {
		t.Fatalf("HashLayout() = %v", parsed.HashLayout().GroupSizes())
	}
}
