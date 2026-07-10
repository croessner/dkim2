package signature

import (
	"bytes"
	"slices"

	"github.com/croessner/dkim2/internal/tagvalue"
)

const (
	// HeaderName is the lowercase rawmsg name for DKIM2-Signature fields.
	HeaderName = "dkim2-signature"
	// AlgorithmRSASHA256 is the baseline RSA signature algorithm name.
	AlgorithmRSASHA256 = "rsa-sha256"
	// AlgorithmEd25519SHA256 is the baseline Ed25519 signature algorithm name.
	AlgorithmEd25519SHA256 = "ed25519-sha256"
)

// Limits contains fail-closed DKIM2-Signature parser resource settings.
type Limits struct {
	// TagLimits bounds shared DKIM2 tag-list and base64string parsing.
	TagLimits tagvalue.Limits
	// MaxRecipients bounds comma-separated rt= forward paths.
	MaxRecipients int
	// MaxSignatureSets bounds comma-separated s= selector signatures.
	MaxSignatureSets int
	// MaxFlags bounds comma-separated f= flags.
	MaxFlags int
	// MaxNonceBytes bounds printable ASCII n= values.
	MaxNonceBytes int
}

// DefaultLimits returns restrictive DKIM2-Signature parser defaults.
func DefaultLimits() Limits {
	return Limits{
		TagLimits:        tagvalue.DefaultLimits(),
		MaxRecipients:    2000,
		MaxSignatureSets: 16,
		MaxFlags:         32,
		MaxNonceBytes:    64,
	}
}

// Validate rejects unsafe DKIM2-Signature parser limit values.
func (l Limits) Validate() error {
	if l.MaxRecipients < 0 {
		return invalidLimitError("max_recipients", l.MaxRecipients)
	}
	if l.MaxSignatureSets < 0 {
		return invalidLimitError("max_signature_sets", l.MaxSignatureSets)
	}
	if l.MaxFlags < 0 {
		return invalidLimitError("max_flags", l.MaxFlags)
	}
	if l.MaxNonceBytes < 0 {
		return invalidLimitError("max_nonce_bytes", l.MaxNonceBytes)
	}

	return nil
}

// Signature stores one immutable parsed DKIM2-Signature field.
type Signature struct {
	sequence       uint64
	instanceNumber uint64
	timestamp      uint64
	mailFrom       EnvelopePath
	recipients     []EnvelopePath
	nextDomain     string
	hasNextDomain  bool
	domain         string
	signatures     []Set
	flags          Flags
	nonce          []byte
	hasNonce       bool
	headerIndex    int
}

// Sequence returns the parsed i= DKIM2-Signature sequence number.
func (s Signature) Sequence() uint64 {
	return s.sequence
}

// InstanceNumber returns the parsed m= Message-Instance reference.
func (s Signature) InstanceNumber() uint64 {
	return s.instanceNumber
}

// TimestampSeconds returns the parsed t= Unix timestamp seconds value.
func (s Signature) TimestampSeconds() uint64 {
	return s.timestamp
}

// MailFrom returns the decoded mf= reverse-path container.
func (s Signature) MailFrom() EnvelopePath {
	return s.mailFrom.clone()
}

// Recipients returns immutable copies of decoded rt= forward-path containers.
func (s Signature) Recipients() []EnvelopePath {
	return cloneEnvelopePaths(s.recipients)
}

// NextDomain returns the canonical nd= domain when the next-domain envelope form is present.
func (s Signature) NextDomain() (string, bool) {
	if !s.hasNextDomain {
		return "", false
	}

	return s.nextDomain, true
}

// HasNextDomain reports whether the signature uses the nd= envelope form.
func (s Signature) HasNextDomain() bool {
	return s.hasNextDomain
}

// Domain returns the canonical signing domain from d=.
func (s Signature) Domain() string {
	return s.domain
}

// SignatureSets returns immutable copies of s= selector signatures.
func (s Signature) SignatureSets() []Set {
	return cloneSignatureSets(s.signatures)
}

// Flags returns immutable f= flag data.
func (s Signature) Flags() Flags {
	return s.flags.clone()
}

// Nonce returns the optional printable ASCII n= value when present.
func (s Signature) Nonce() ([]byte, bool) {
	if !s.hasNonce {
		return nil, false
	}

	return bytes.Clone(s.nonce), true
}

// HeaderIndex returns the M1 raw header occurrence index.
func (s Signature) HeaderIndex() int {
	return s.headerIndex
}

// EnvelopePath stores one immutable base64-wrapped SMTP path.
type EnvelopePath struct {
	value     []byte
	container tagvalue.Base64String
}

// Value returns the decoded parser-owned SMTP path bytes.
func (p EnvelopePath) Value() []byte {
	return bytes.Clone(p.value)
}

// Base64 returns the strict base64string container that carried the path.
func (p EnvelopePath) Base64() tagvalue.Base64String {
	return p.container
}

// clone returns a deep copy of one envelope path.
func (p EnvelopePath) clone() EnvelopePath {
	p.value = bytes.Clone(p.value)

	return p
}

// Set stores one immutable selector:algorithm:signature tuple.
type Set struct {
	selector       string
	algorithm      string
	knownAlgorithm bool
	signature      tagvalue.Base64String
}

// Selector returns the canonical selector name for DNS key lookup.
func (s Set) Selector() string {
	return s.selector
}

// Algorithm returns the canonical signature algorithm name.
func (s Set) Algorithm() string {
	return s.algorithm
}

// KnownAlgorithm reports whether the parser knows this algorithm.
func (s Set) KnownAlgorithm() bool {
	return s.knownAlgorithm
}

// Signature returns the strict base64string signature container.
func (s Set) Signature() tagvalue.Base64String {
	return s.signature
}

// clone returns a deep copy of one signature set.
func (s Set) clone() Set {
	return s
}

// cloneEnvelopePaths returns deep copies of decoded envelope paths.
func cloneEnvelopePaths(input []EnvelopePath) []EnvelopePath {
	if len(input) == 0 {
		return nil
	}

	output := slices.Clone(input)
	for i := range output {
		output[i] = output[i].clone()
	}

	return output
}

// cloneSignatureSets returns deep copies of parsed signature sets.
func cloneSignatureSets(input []Set) []Set {
	if len(input) == 0 {
		return nil
	}

	output := slices.Clone(input)
	for i := range output {
		output[i] = output[i].clone()
	}

	return output
}
