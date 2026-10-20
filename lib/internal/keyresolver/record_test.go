package keyresolver

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

const (
	validDNSKeyData   = "QUJDRA=="
	decodedDNSKeyData = "ABCD"
)

// TestParseRecordAcceptsClosedLegalMatrix verifies defaults, supported types, FWS, and ignored retired tags.
func TestParseRecordAcceptsClosedLegalMatrix(t *testing.T) {
	tests := []struct {
		name    string
		record  string
		status  RecordStatus
		keyType KeyType
		keyData string
	}{
		{name: "p only defaults", record: "p=" + validDNSKeyData, status: RecordStatusKeyData, keyType: KeyTypeRSA, keyData: decodedDNSKeyData},
		{name: "version and rsa", record: "v=DKIM1; k=rsa; p=" + validDNSKeyData + ";", status: RecordStatusKeyData, keyType: KeyTypeRSA, keyData: decodedDNSKeyData},
		{name: "ed25519", record: "v=DKIM1;k=ed25519;p=" + validDNSKeyData, status: RecordStatusKeyData, keyType: KeyTypeEd25519, keyData: decodedDNSKeyData},
		{name: "folded base64", record: "v=DKIM1;\r\n\tk=rsa; p=QU\r\n JDRA==", status: RecordStatusKeyData, keyType: KeyTypeRSA, keyData: decodedDNSKeyData},
		{name: "revoked empty", record: "p=", status: RecordStatusRevoked, keyType: KeyTypeRSA},
		{name: "revoked whitespace", record: "k=ed25519; p= \t", status: RecordStatusRevoked, keyType: KeyTypeEd25519},
		{name: "revoked with retired t", record: "k=ed25519; p=; t=y:s", status: RecordStatusRevoked, keyType: KeyTypeEd25519},
		{name: "unsupported record", record: "k=future-key2; p=" + validDNSKeyData, status: RecordStatusUnsupportedKeyType, keyType: KeyTypeUnsupported},
		{name: "unsupported rsa case", record: "k=RSA; p=" + validDNSKeyData, status: RecordStatusUnsupportedKeyType, keyType: KeyTypeUnsupported},
		{name: "unsupported ed case", record: "k=Ed25519; p=" + validDNSKeyData, status: RecordStatusUnsupportedKeyType, keyType: KeyTypeUnsupported},
		{name: "unsupported with retired t", record: "k=future-key2; p=" + validDNSKeyData + "; t=y:s", status: RecordStatusUnsupportedKeyType, keyType: KeyTypeUnsupported},
		{name: "unpadded one character", record: "p=QUI", status: RecordStatusKeyData, keyType: KeyTypeRSA, keyData: "AB"},
		{name: "unpadded two characters", record: "p=QQ", status: RecordStatusKeyData, keyType: KeyTypeRSA, keyData: "A"},
		{name: "retired testing flag", record: "p=" + validDNSKeyData + "; t=y", status: RecordStatusKeyData, keyType: KeyTypeRSA, keyData: decodedDNSKeyData},
		{name: "retired strict flag", record: "p=" + validDNSKeyData + "; t=s", status: RecordStatusKeyData, keyType: KeyTypeRSA, keyData: decodedDNSKeyData},
		{name: "retired combined flags", record: "p=" + validDNSKeyData + "; t=y : s : y : future-flag", status: RecordStatusKeyData, keyType: KeyTypeRSA, keyData: decodedDNSKeyData},
		{name: "retired folded flags", record: "p=" + validDNSKeyData + "; t=y\r\n \t:\r\n s", status: RecordStatusKeyData, keyType: KeyTypeRSA, keyData: decodedDNSKeyData},
		{name: "retired uppercase flags", record: "p=" + validDNSKeyData + "; t=Y:Y:Future", status: RecordStatusKeyData, keyType: KeyTypeRSA, keyData: decodedDNSKeyData},
		{name: "retired and unknown ignored", record: "p=" + validDNSKeyData + "; h=; n=operator note; s=odd value; future_tag=opaque", status: RecordStatusKeyData, keyType: KeyTypeRSA, keyData: decodedDNSKeyData},
		{name: "uppercase aliases unknown", record: "V=DKIM2; K=ed25519; p=" + validDNSKeyData, status: RecordStatusKeyData, keyType: KeyTypeRSA, keyData: decodedDNSKeyData},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := []byte(tt.record)
			before := bytes.Clone(input)
			parsed, err := ParseRecord(input, DefaultLimits())
			if err != nil {
				t.Fatalf("ParseRecord() error = %v", err)
			}
			if !bytes.Equal(input, before) {
				t.Fatal("ParseRecord() mutated input")
			}
			if !parsed.Valid() || parsed.Status() != tt.status || parsed.KeyType() != tt.keyType || string(parsed.PublicKeyData()) != tt.keyData || parsed.Draft() != DNSDraftIdentifier {
				t.Fatalf("ParseRecord() = status=%q type=%q data=%q draft=%q", parsed.Status(), parsed.KeyType(), parsed.PublicKeyData(), parsed.Draft())
			}
		})
	}
}

// TestParseRecordRejectsVersionAndRequiredTagContradictions verifies v and p precedence.
func TestParseRecordRejectsVersionAndRequiredTagContradictions(t *testing.T) {
	tests := []struct {
		name   string
		record string
		code   RecordErrorCode
	}{
		{name: "missing p", record: "v=DKIM1; k=rsa", code: RecordErrorMissingPublicKey},
		{name: "unsupported missing p", record: "k=future-key", code: RecordErrorMissingPublicKey},
		{name: "wrong version", record: "v=DKIM2; p=" + validDNSKeyData, code: RecordErrorInvalidVersion},
		{name: "version wrong case", record: "v=dkim1; p=" + validDNSKeyData, code: RecordErrorInvalidVersion},
		{name: "version not first", record: "future=x; v=DKIM1; p=" + validDNSKeyData, code: RecordErrorInvalidVersion},
		{name: "defined before version", record: "k=rsa; v=DKIM1; p=" + validDNSKeyData, code: RecordErrorInvalidVersion},
		{name: "uppercase P is unknown", record: "P=" + validDNSKeyData, code: RecordErrorMissingPublicKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRecord([]byte(tt.record), DefaultLimits())
			if !IsRecordErrorCode(err, tt.code) {
				t.Fatalf("ParseRecord() error = %v, want %q", err, tt.code)
			}
		})
	}
}

// TestParseRecordRejectsMalformedKeyTypes verifies DNS-01 hyphenated-word syntax.
func TestParseRecordRejectsMalformedKeyTypes(t *testing.T) {
	for _, keyType := range []string{"", "_future", "-future", "future-", "future_key", "future key", "1future"} {
		record := "k=" + keyType + "; p=" + validDNSKeyData
		if _, err := ParseRecord([]byte(record), DefaultLimits()); !IsRecordErrorCode(err, RecordErrorInvalidKeyType) {
			t.Fatalf("key type %q error = %v", keyType, err)
		}
	}
}

// TestParseRecordUsesLowercaseKDespiteDraftABNFDefect verifies the recorded Erratum 5137 interpretation.
func TestParseRecordUsesLowercaseKDespiteDraftABNFDefect(t *testing.T) {
	parsed, err := ParseRecord([]byte("v=DKIM1; k=ed25519; p="+validDNSKeyData), DefaultLimits())
	if err != nil || parsed.KeyType() != KeyTypeEd25519 {
		t.Fatalf("lowercase k parse type=%q error=%v", parsed.KeyType(), err)
	}
	parsed, err = ParseRecord([]byte("V=DKIM1; p="+validDNSKeyData), DefaultLimits())
	if err != nil || parsed.KeyType() != KeyTypeRSA {
		t.Fatalf("uppercase V alias changed default type=%q error=%v", parsed.KeyType(), err)
	}
}

// TestParseRecordRejectsDuplicateDefinedRetiredAndUnknownTags verifies full-list uniqueness.
func TestParseRecordRejectsDuplicateDefinedRetiredAndUnknownTags(t *testing.T) {
	for _, record := range []string{
		"p=QQ==; p=Qg==", "v=DKIM1; v=DKIM1; p=QQ==", "k=rsa; k=rsa; p=QQ==",
		"p=QQ==; h=; h=sha256", "p=QQ==; n=a; n=b", "p=QQ==; s=*; s=email",
		"p=QQ==; future=x; future=y", "p=QQ==; V=x; V=y", "p=QQ==; t=y; t=y", "p=QQ==; t=bad!; t=s",
	} {
		if _, err := ParseRecord([]byte(record), DefaultLimits()); !IsRecordErrorCode(err, RecordErrorInvalidSyntax) {
			t.Fatalf("duplicate record %q error = %v", record, err)
		}
	}
}

// TestParseRecordIgnoresRetiredTestingTag verifies DNS-01 Section 3.4.1:
// any syntactically valid t= value, including formerly malformed flag lists,
// leaves the parsed record identical to one without t=.
func TestParseRecordIgnoresRetiredTestingTag(t *testing.T) {
	baseline, err := ParseRecord([]byte("p="+validDNSKeyData), DefaultLimits())
	if err != nil {
		t.Fatalf("baseline ParseRecord() error = %v", err)
	}
	for _, flags := range []string{"", "y", "s", "y:s", ":y", "y:", "y::s", "_future", "future_flag", "future flag", "1future", "bad!"} {
		parsed, err := ParseRecord([]byte("p="+validDNSKeyData+"; t="+flags), DefaultLimits())
		if err != nil {
			t.Fatalf("t=%q error = %v", flags, err)
		}
		if !reflect.DeepEqual(parsed, baseline) {
			t.Fatalf("t=%q changed parsed record: %#v", flags, parsed)
		}
	}
}

// TestParseRecordRejectsMalformedSyntaxAndBase64 verifies shared scanner and decoder enforcement.
func TestParseRecordRejectsMalformedSyntaxAndBase64(t *testing.T) {
	tests := []struct {
		record string
		code   RecordErrorCode
	}{
		{record: "p=QQ==;;", code: RecordErrorInvalidSyntax},
		{record: "p=QQ==\n", code: RecordErrorInvalidSyntax},
		{record: "p=QQ==\r\nX", code: RecordErrorInvalidSyntax},
		{record: "p=Q@==", code: RecordErrorInvalidPublicKeyData},
		{record: "p=Q", code: RecordErrorInvalidPublicKeyData},
		{record: "p=QR", code: RecordErrorInvalidPublicKeyData},
		{record: "p=QR==", code: RecordErrorInvalidPublicKeyData},
		{record: "p=QQ===", code: RecordErrorInvalidPublicKeyData},
		{record: "future=bad\x00value; p=QQ==", code: RecordErrorInvalidSyntax},
	}
	for _, tt := range tests {
		if _, err := ParseRecord([]byte(tt.record), DefaultLimits()); !IsRecordErrorCode(err, tt.code) {
			t.Fatalf("record %q error = %v, want %q", tt.record, err, tt.code)
		}
	}
}

// TestParseRecordRejectsControlsInRetiredTags verifies ignored semantics still obey generic grammar.
func TestParseRecordRejectsControlsInRetiredTags(t *testing.T) {
	for _, tag := range []string{"h", "n", "s"} {
		record := "p=" + validDNSKeyData + "; " + tag + "=toxic\x00value"
		if _, err := ParseRecord([]byte(record), DefaultLimits()); !IsRecordErrorCode(err, RecordErrorInvalidSyntax) {
			t.Fatalf("retired tag %q error=%v", tag, err)
		}
	}
}

// TestParseRecordEnforcesEveryConfiguredLimit verifies exact and one-over seams.
func TestParseRecordEnforcesEveryConfiguredLimit(t *testing.T) {
	base := DefaultLimits()
	tests := []struct {
		name   string
		limits Limits
		exact  string
		over   string
	}{
		{name: "record bytes", limits: func() Limits { l := base; l.MaxTXTRecordBytes = 2; return l }(), exact: "p=", over: "p= "},
		{name: "tags", limits: func() Limits { l := base; l.MaxTags = 1; return l }(), exact: "p=", over: "k=rsa;p="},
		{name: "tag name", limits: func() Limits { l := base; l.MaxTagNameBytes = 1; return l }(), exact: "p=", over: "xx=x;p="},
		{name: "tag value", limits: func() Limits { l := base; l.MaxTagValueBytes = 4; return l }(), exact: "p=QUJD", over: "p=QUJDRA=="},
		{name: "decoded key", limits: func() Limits { l := base; l.MaxDecodedKeyBytes = 3; return l }(), exact: "p=QUJD", over: "p=QUJDRA=="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseRecord([]byte(tt.exact), tt.limits); err != nil {
				t.Fatalf("exact ParseRecord() error = %v", err)
			}
			if _, err := ParseRecord([]byte(tt.over), tt.limits); !IsRecordErrorCode(err, RecordErrorLimitExceeded) {
				t.Fatalf("ParseRecord() error = %v, want limit", err)
			}
		})
	}
}

// TestParseRecordRejectsInvalidLimitsAsContract verifies configuration misuse is not record-derived limit state.
func TestParseRecordRejectsInvalidLimitsAsContract(t *testing.T) {
	for _, limits := range []Limits{{}, func() Limits { l := DefaultLimits(); l.MaxTags = 129; return l }()} {
		if _, err := ParseRecord([]byte("p="+validDNSKeyData), limits); !IsRecordErrorCode(err, RecordErrorContract) {
			t.Fatalf("ParseRecord() invalid limits error=%v", err)
		}
	}
}

// TestParseRecordClassificationIsDeterministic verifies repeated malformed input has one typed outcome.
func TestParseRecordClassificationIsDeterministic(t *testing.T) {
	input := []byte("v=DKIM2; p=TOXIC")
	_, first := ParseRecord(input, DefaultLimits())
	_, second := ParseRecord(bytes.Clone(input), DefaultLimits())
	if first == nil || second == nil {
		t.Fatalf("classification first=%v second=%v", first, second)
	}
	if RecordErrorCodeOf(first) != RecordErrorInvalidVersion || RecordErrorCodeOf(second) != RecordErrorCodeOf(first) || first.Error() != second.Error() {
		t.Fatalf("classification first=%v second=%v", first, second)
	}
}

// TestUnsupportedKeyTypeValidatesBase64ButSkipsKeyDecode verifies textual validity precedes unsupported state.
func TestUnsupportedKeyTypeValidatesBase64ButSkipsKeyDecode(t *testing.T) {
	limits := DefaultLimits()
	parsed, err := ParseRecord([]byte("k=future-key; p=VE9YSUM="), limits)
	if err != nil || parsed.Status() != RecordStatusUnsupportedKeyType || len(parsed.PublicKeyData()) != 0 {
		t.Fatalf("ParseRecord() status=%q data=%q error=%v", parsed.Status(), parsed.PublicKeyData(), err)
	}
	if _, err = ParseRecord([]byte("k=future-key; p=TOXIC-NOT-BASE64"), limits); !IsRecordErrorCode(err, RecordErrorInvalidPublicKeyData) {
		t.Fatalf("malformed unsupported p= error=%v", err)
	}
	limits.MaxDecodedKeyBytes = 1
	if _, err = ParseRecord([]byte("k=future-key; p=QUJD"), limits); !IsRecordErrorCode(err, RecordErrorLimitExceeded) {
		t.Fatalf("over-limit unsupported p= error=%v", err)
	}
	parsed, err = ParseRecord([]byte("k=future-key; p= "), limits)
	if err != nil || parsed.Status() != RecordStatusRevoked {
		t.Fatalf("empty p precedence status=%q error=%v", parsed.Status(), err)
	}
}

// TestParsedRecordIsImmutable verifies detached key data and closed record vocabulary.
func TestParsedRecordIsImmutable(t *testing.T) {
	input := []byte("p=" + validDNSKeyData + "; t=y:s")
	parsed, err := ParseRecord(input, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'
	data := parsed.PublicKeyData()
	data[0] = 'Z'
	if string(parsed.PublicKeyData()) != decodedDNSKeyData || !parsed.Valid() {
		t.Fatalf("parsed record mutated: data=%q", parsed.PublicKeyData())
	}
	if RecordStatus("").Known() || KeyType("").Known() || (Record{}).Valid() {
		t.Fatal("zero record state accepted")
	}
}

// TestRecordErrorsAreBoundedAndSecretSafe verifies toxic input never reaches diagnostics.
func TestRecordErrorsAreBoundedAndSecretSafe(t *testing.T) {
	const toxic = "TOXIC-SELECTOR-DOMAIN-KEY-MATERIAL"
	_, err := ParseRecord([]byte("p="+toxic), DefaultLimits())
	if err == nil || strings.Contains(err.Error(), toxic) || strings.Contains(err.Error(), "p=") {
		t.Fatalf("ParseRecord() error = %v", err)
	}
}
