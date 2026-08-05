package keyresolver

import (
	"bytes"
	"errors"
	"strings"

	"github.com/croessner/dkim2/internal/tagvalue"
)

// DNSDraftIdentifier records the active DNS key-record behavior baseline.
const DNSDraftIdentifier = "draft-chuang-dkim2-dns-04"

var dnsRecordTags = tagvalue.MustKnownTags("v", "h", "k", "n", "p", "s", "t")

// KeyType identifies one bounded DNS key type or unsupported declaration.
type KeyType string

const (
	// KeyTypeRSA identifies RSA public-key data as PKCS#1 or SubjectPublicKeyInfo DER.
	KeyTypeRSA KeyType = "rsa"
	// KeyTypeEd25519 identifies raw Ed25519 public-key data.
	KeyTypeEd25519 KeyType = "ed25519"
	// KeyTypeUnsupported records a valid but unrecognized key type without retaining spelling.
	KeyTypeUnsupported KeyType = "unsupported"
)

// Known reports whether the key type belongs to the closed parser vocabulary.
func (k KeyType) Known() bool {
	switch k {
	case KeyTypeRSA, KeyTypeEd25519, KeyTypeUnsupported:
		return true
	default:
		return false
	}
}

// RecordStatus identifies decoded key data, revocation, or unsupported key type.
type RecordStatus string

const (
	// RecordStatusKeyData reports bounded decoded p= bytes for a supported key type.
	RecordStatusKeyData RecordStatus = "key_data"
	// RecordStatusRevoked reports an explicitly empty p= value.
	RecordStatusRevoked RecordStatus = "revoked"
	// RecordStatusUnsupportedKeyType reports a valid unrecognized k= value.
	RecordStatusUnsupportedKeyType RecordStatus = "unsupported_key_type"
)

// Known reports whether the status belongs to the closed parser vocabulary.
func (s RecordStatus) Known() bool {
	switch s {
	case RecordStatusKeyData, RecordStatusRevoked, RecordStatusUnsupportedKeyType:
		return true
	default:
		return false
	}
}

// Record stores one immutable bounded DNS-04 key record interpretation.
type Record struct {
	draft       string
	status      RecordStatus
	keyType     KeyType
	publicKey   []byte
	metadata    Metadata
	initialized bool
}

// Draft returns the exact DNS draft behavior identifier.
func (r Record) Draft() string { return r.draft }

// Status returns the closed parsed-record status.
func (r Record) Status() RecordStatus { return r.status }

// KeyType returns the declared, default, or bounded unsupported key type.
func (r Record) KeyType() KeyType { return r.keyType }

// PublicKeyData returns detached decoded p= bytes for supported non-revoked records.
func (r Record) PublicKeyData() []byte { return bytes.Clone(r.publicKey) }

// Metadata returns immutable bounded key policy declarations.
func (r Record) Metadata() Metadata { return r.metadata }

// Valid reports whether record state is internally coherent and parser-owned.
func (r Record) Valid() bool {
	if !r.initialized || r.draft != DNSDraftIdentifier || !r.status.Known() || !r.keyType.Known() || !r.metadata.Valid() {
		return false
	}
	switch r.status {
	case RecordStatusKeyData:
		return (r.keyType == KeyTypeRSA || r.keyType == KeyTypeEd25519) && len(r.publicKey) > 0
	case RecordStatusRevoked:
		return len(r.publicKey) == 0
	case RecordStatusUnsupportedKeyType:
		return r.keyType == KeyTypeUnsupported && len(r.publicKey) == 0
	default:
		return false
	}
}

// RecordErrorCode identifies one bounded DNS key-record parser failure.
type RecordErrorCode string

const (
	// RecordErrorContract reports invalid parser configuration or injected invariant state.
	RecordErrorContract RecordErrorCode = "contract"
	// RecordErrorInvalidSyntax reports malformed generic tag-list syntax.
	RecordErrorInvalidSyntax RecordErrorCode = "invalid_syntax"
	// RecordErrorLimitExceeded reports a configured record resource limit.
	RecordErrorLimitExceeded RecordErrorCode = "limit_exceeded"
	// RecordErrorInvalidVersion reports a non-first or non-DKIM1 v= tag.
	RecordErrorInvalidVersion RecordErrorCode = "invalid_version"
	// RecordErrorMissingPublicKey reports an omitted required p= tag.
	RecordErrorMissingPublicKey RecordErrorCode = "missing_public_key"
	// RecordErrorInvalidKeyType reports malformed k= hyphenated-word syntax.
	RecordErrorInvalidKeyType RecordErrorCode = "invalid_key_type"
	// RecordErrorInvalidPublicKeyData reports malformed or over-limit p= Base64 data.
	RecordErrorInvalidPublicKeyData RecordErrorCode = "invalid_public_key_data"
	// RecordErrorInvalidFlags reports malformed t= flag-list syntax.
	RecordErrorInvalidFlags RecordErrorCode = "invalid_flags"
)

// Known reports whether the error code belongs to the closed parser vocabulary.
func (c RecordErrorCode) Known() bool {
	switch c {
	case RecordErrorContract, RecordErrorInvalidSyntax, RecordErrorLimitExceeded, RecordErrorInvalidVersion,
		RecordErrorMissingPublicKey, RecordErrorInvalidKeyType,
		RecordErrorInvalidPublicKeyData, RecordErrorInvalidFlags:
		return true
	default:
		return false
	}
}

type recordError struct{ code RecordErrorCode }

// Error returns a bounded diagnostic without TXT, tag, or key data.
func (e *recordError) Error() string {
	if e == nil || !e.code.Known() {
		return "dns key record failure"
	}
	return "dns key record failure: " + string(e.code)
}

// RecordErrorCode returns the closed parser failure code.
func (e *recordError) RecordErrorCode() RecordErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

type classifiedRecordError interface {
	error
	RecordErrorCode() RecordErrorCode
}

// newRecordError constructs one cause-free bounded record parser error.
func newRecordError(code RecordErrorCode) error {
	if !code.Known() {
		code = RecordErrorInvalidSyntax
	}
	return &recordError{code: code}
}

// RecordErrorCodeOf returns a known parser code without inspecting error text.
func RecordErrorCodeOf(err error) RecordErrorCode {
	var classified classifiedRecordError
	if !errors.As(err, &classified) || !classified.RecordErrorCode().Known() {
		return ""
	}
	return classified.RecordErrorCode()
}

// IsRecordErrorCode reports whether err carries the requested known parser code.
func IsRecordErrorCode(err error, code RecordErrorCode) bool {
	return code.Known() && RecordErrorCodeOf(err) == code
}

// ParseRecord parses one already-concatenated bounded DNS-04 TXT key record.
func ParseRecord(input []byte, limits Limits) (Record, error) {
	if err := limits.Validate(); err != nil {
		return Record{}, newRecordError(RecordErrorContract)
	}
	field, err := tagvalue.Scan(input, dnsRecordTags, tagvalue.Limits{
		MaxFieldValueBytes: limits.MaxTXTRecordBytes,
		MaxTags:            limits.MaxTags, MaxTagNameBytes: limits.MaxTagNameBytes,
		MaxTagValueBytes:      limits.MaxTagValueBytes,
		MaxBase64DecodedBytes: limits.MaxDecodedKeyBytes,
	})
	if err != nil {
		return Record{}, mappedScannerError(err)
	}
	tags := field.Tags()
	if version, ok := field.Get("v"); ok && (len(tags) == 0 || tags[0].Name() != "v" || version.Value() != "DKIM1") {
		return Record{}, newRecordError(RecordErrorInvalidVersion)
	}
	publicKeyTag, ok := field.Get("p")
	if !ok {
		return Record{}, newRecordError(RecordErrorMissingPublicKey)
	}
	keyType, err := parsedKeyType(field)
	if err != nil {
		return Record{}, err
	}
	metadata, err := parsedMetadata(field)
	if err != nil {
		return Record{}, err
	}
	base := Record{draft: DNSDraftIdentifier, keyType: keyType, metadata: metadata, initialized: true}
	if publicKeyTag.Value() == "" {
		base.status = RecordStatusRevoked
		return base, nil
	}
	parsed, err := tagvalue.ParseOptionalPaddingBase64String([]byte(publicKeyTag.Value()), tagvalue.Limits{
		MaxFieldValueBytes: limits.MaxTXTRecordBytes,
		MaxTags:            limits.MaxTags, MaxTagNameBytes: limits.MaxTagNameBytes,
		MaxTagValueBytes:      limits.MaxTagValueBytes,
		MaxBase64DecodedBytes: limits.MaxDecodedKeyBytes,
	})
	if err != nil {
		if tagvalue.IsErrorCode(err, tagvalue.ErrorCodeLimitExceeded) {
			return Record{}, newRecordError(RecordErrorLimitExceeded)
		}
		return Record{}, newRecordError(RecordErrorInvalidPublicKeyData)
	}
	if keyType == KeyTypeUnsupported {
		base.status = RecordStatusUnsupportedKeyType
		return base, nil
	}
	base.status = RecordStatusKeyData
	base.publicKey = parsed.Decoded()
	return base, nil
}

// mappedScannerError maps shared lexical failures without retaining raw details.
func mappedScannerError(err error) error {
	if tagvalue.IsErrorCode(err, tagvalue.ErrorCodeLimitExceeded) {
		return newRecordError(RecordErrorLimitExceeded)
	}
	return newRecordError(RecordErrorInvalidSyntax)
}

// parsedKeyType validates exact supported or hyphenated-word extension k= values.
func parsedKeyType(field tagvalue.Field) (KeyType, error) {
	tag, ok := field.Get("k")
	if !ok {
		return KeyTypeRSA, nil
	}
	value := tag.Value()
	switch value {
	case "rsa":
		return KeyTypeRSA, nil
	case "ed25519":
		return KeyTypeEd25519, nil
	default:
		if !validHyphenatedWord(value) {
			return "", newRecordError(RecordErrorInvalidKeyType)
		}
		return KeyTypeUnsupported, nil
	}
}

// parsedMetadata validates t= members and retains only recognized bounded flags.
func parsedMetadata(field tagvalue.Field) (Metadata, error) {
	tag, ok := field.Get("t")
	if !ok {
		return newMetadata(false, false), nil
	}
	testing := false
	strict := false
	for _, raw := range strings.Split(tag.Value(), ":") {
		flag := strings.Trim(raw, " \t")
		if !validHyphenatedWord(flag) {
			return Metadata{}, newRecordError(RecordErrorInvalidFlags)
		}
		switch flag {
		case "y":
			testing = true
		case "s":
			strict = true
		}
	}
	return newMetadata(testing, strict), nil
}

// validHyphenatedWord enforces DNS-04 ALPHA edge and ALPHA/DIGIT/hyphen interior syntax.
func validHyphenatedWord(value string) bool {
	if len(value) == 0 || !asciiAlpha(value[0]) || !asciiAlphaDigit(value[len(value)-1]) {
		return false
	}
	for index := 1; index < len(value)-1; index++ {
		if !asciiAlphaDigit(value[index]) && value[index] != '-' {
			return false
		}
	}
	return true
}

// asciiAlpha reports whether one byte belongs to ASCII ALPHA.
func asciiAlpha(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

// asciiAlphaDigit reports whether one byte belongs to ASCII ALPHA or DIGIT.
func asciiAlphaDigit(value byte) bool {
	return asciiAlpha(value) || value >= '0' && value <= '9'
}
