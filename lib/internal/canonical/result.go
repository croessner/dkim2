package canonical

import (
	"bytes"
	"encoding/base64"
)

const (
	sha256DigestBytes = 32
	sha512DigestBytes = 64
)

// BodyTerminalAction records how Section 6.1 terminal CRLF handling behaved.
type BodyTerminalAction string

const (
	// BodyTerminalActionUnspecified records no body terminal action.
	BodyTerminalActionUnspecified BodyTerminalAction = ""
	// BodyTerminalActionPreserved records an existing single terminal CRLF.
	BodyTerminalActionPreserved BodyTerminalAction = "preserved"
	// BodyTerminalActionAppended records that one terminal CRLF was appended.
	BodyTerminalActionAppended BodyTerminalAction = "appended"
	// BodyTerminalActionCollapsed records that trailing empty lines collapsed to one CRLF.
	BodyTerminalActionCollapsed BodyTerminalAction = "collapsed"
)

// ExcludedHeaderCounts stores allowlisted Section 6.2 exclusion counters.
type ExcludedHeaderCounts struct {
	// Received counts excluded Received fields.
	Received int
	// ReturnPath counts excluded Return-Path fields.
	ReturnPath int
	// DeliveredTo counts excluded Delivered-To fields.
	DeliveredTo int
	// AuthenticationResults counts excluded Authentication-Results fields.
	AuthenticationResults int
	// XHeader counts excluded X-* fields.
	XHeader int
	// DKIMSignature counts excluded DKIM-Signature fields.
	DKIMSignature int
	// ExactUnsigned counts the eight exact Draft-06 registered exclusions.
	ExactUnsigned int
	// ARC counts the three exact excluded ARC fields.
	ARC int
	// MessageInstance counts excluded Message-Instance fields.
	MessageInstance int
	// DKIM2Signature counts excluded DKIM2-Signature fields.
	DKIM2Signature int
}

// Total returns the total excluded-header count.
func (c ExcludedHeaderCounts) Total() int {
	return nonNegative(c.Received) +
		nonNegative(c.ReturnPath) +
		nonNegative(c.DeliveredTo) +
		nonNegative(c.AuthenticationResults) +
		nonNegative(c.XHeader) +
		nonNegative(c.DKIMSignature) +
		nonNegative(c.ExactUnsigned) +
		nonNegative(c.ARC) +
		nonNegative(c.MessageInstance) +
		nonNegative(c.DKIM2Signature)
}

// Metadata carries bounded canonicalization debug facts.
type Metadata struct {
	// Kind records the canonicalization byte stream.
	Kind Kind
	// Draft records the active DKIM2 draft baseline.
	Draft string
	// Algorithm records a safe hash algorithm name when relevant.
	Algorithm HashAlgorithm
	// InputBytes records the parser-owned input size.
	InputBytes int
	// OutputBytes records the canonical output size.
	OutputBytes int
	// IncludedFields records canonicalized field count when relevant.
	IncludedFields int
	// ExcludedFields records excluded field count when relevant.
	ExcludedFields int
	// ExcludedHeaderCounts records allowlisted Section 6.2 exclusion reasons.
	ExcludedHeaderCounts ExcludedHeaderCounts
	// BodyTrailingEmptyLines records collapsed terminal empty body lines.
	BodyTrailingEmptyLines int
	// BodyTerminalAction records terminal CRLF handling for body input.
	BodyTerminalAction BodyTerminalAction
}

// ByteInput stores immutable canonical byte output and bounded metadata.
type ByteInput struct {
	kind     Kind
	bytes    []byte
	metadata Metadata
}

// Digest stores immutable digest bytes and padded base64 text.
type Digest struct {
	algorithm HashAlgorithm
	bytes     []byte
	base64    string
}

// Result stores canonical bytes and an optional digest result.
type Result struct {
	canonical ByteInput
	digest    Digest
	hasDigest bool
}

// NewCanonicalBytes constructs immutable canonical byte output.
func NewCanonicalBytes(kind Kind, input []byte, metadata Metadata) (ByteInput, error) {
	if !validKind(kind) {
		return ByteInput{}, newError(ErrorCodeInternalMisuse, ErrorLocation{Kind: kind}, ErrorDetails{
			Class:      ErrorClassInternal,
			TargetName: "canonical_kind",
		}, nil)
	}

	canonical := bytes.Clone(input)
	metadata = sanitizeMetadata(kind, len(canonical), metadata)

	return ByteInput{
		kind:     kind,
		bytes:    canonical,
		metadata: metadata,
	}, nil
}

// Bytes returns a copy of the canonical byte output.
func (c ByteInput) Bytes() []byte {
	return bytes.Clone(c.bytes)
}

// Kind returns the canonical byte stream kind.
func (c ByteInput) Kind() Kind {
	return c.kind
}

// Len returns the canonical byte length.
func (c ByteInput) Len() int {
	return len(c.bytes)
}

// Metadata returns bounded debug metadata by value.
func (c ByteInput) Metadata() Metadata {
	return c.metadata
}

// NewDigest constructs an immutable supported Message-Instance digest container.
func NewDigest(algorithm HashAlgorithm, digest []byte) (Digest, error) {
	expected := digestSize(algorithm)
	if expected == 0 {
		return Digest{}, newError(ErrorCodeUnsupportedAlgorithm, ErrorLocation{}, ErrorDetails{
			Class:     ErrorClassAlgorithm,
			Algorithm: algorithm,
		}, nil)
	}
	if len(digest) != expected {
		return Digest{}, newError(ErrorCodeMalformedState, ErrorLocation{}, ErrorDetails{
			Class:     ErrorClassMalformed,
			Algorithm: algorithm,
			LimitName: "digest_bytes",
			Limit:     expected,
			Count:     len(digest),
		}, nil)
	}

	copied := bytes.Clone(digest)

	return Digest{
		algorithm: algorithm,
		bytes:     copied,
		base64:    base64.StdEncoding.EncodeToString(copied),
	}, nil
}

// NewSHA256Digest constructs an immutable SHA-256 digest container.
func NewSHA256Digest(digest []byte) (Digest, error) {
	return NewDigest(HashAlgorithmSHA256, digest)
}

// NewSHA512Digest constructs an immutable SHA-512 digest container.
func NewSHA512Digest(digest []byte) (Digest, error) {
	return NewDigest(HashAlgorithmSHA512, digest)
}

// digestSize returns the fixed decoded size for one supported algorithm.
func digestSize(algorithm HashAlgorithm) int {
	switch algorithm {
	case HashAlgorithmSHA256:
		return sha256DigestBytes
	case HashAlgorithmSHA512:
		return sha512DigestBytes
	default:
		return 0
	}
}

// Bytes returns a copy of the digest bytes.
func (d Digest) Bytes() []byte {
	return bytes.Clone(d.bytes)
}

// Algorithm returns the digest algorithm name.
func (d Digest) Algorithm() HashAlgorithm {
	return d.algorithm
}

// Base64 returns padded RFC 4648 digest text.
func (d Digest) Base64() string {
	return d.base64
}

// Len returns the digest byte length.
func (d Digest) Len() int {
	return len(d.bytes)
}

// NewResult constructs a canonicalization result with a digest.
func NewResult(canonical ByteInput, digest Digest) Result {
	return Result{
		canonical: canonical,
		digest:    digest,
		hasDigest: true,
	}
}

// NewResultWithoutDigest constructs a canonicalization result without a digest.
func NewResultWithoutDigest(canonical ByteInput) Result {
	return Result{
		canonical: canonical,
	}
}

// CanonicalBytes returns the immutable canonical bytes container.
func (r Result) CanonicalBytes() ByteInput {
	return r.canonical
}

// Digest returns the immutable digest container when present.
func (r Result) Digest() (Digest, bool) {
	if !r.hasDigest {
		return Digest{}, false
	}

	return r.digest, true
}

// sanitizeMetadata clamps metadata counters and applies stable defaults.
func sanitizeMetadata(kind Kind, outputBytes int, metadata Metadata) Metadata {
	metadata.Kind = kind
	if metadata.Draft == "" {
		metadata.Draft = DraftBaseline
	} else {
		metadata.Draft = safeDiagnosticToken(metadata.Draft)
	}
	if metadata.Algorithm != "" {
		metadata.Algorithm = HashAlgorithm(safeDiagnosticToken(string(metadata.Algorithm)))
	}
	metadata.InputBytes = nonNegative(metadata.InputBytes)
	metadata.OutputBytes = outputBytes
	metadata.IncludedFields = nonNegative(metadata.IncludedFields)
	metadata.ExcludedFields = nonNegative(metadata.ExcludedFields)
	metadata.ExcludedHeaderCounts = sanitizeExcludedHeaderCounts(metadata.ExcludedHeaderCounts)
	metadata.BodyTrailingEmptyLines = nonNegative(metadata.BodyTrailingEmptyLines)
	metadata.BodyTerminalAction = sanitizeBodyTerminalAction(metadata.BodyTerminalAction)

	return metadata
}

// sanitizeExcludedHeaderCounts clamps exclusion counters to safe lower bounds.
func sanitizeExcludedHeaderCounts(counts ExcludedHeaderCounts) ExcludedHeaderCounts {
	return ExcludedHeaderCounts{
		Received:              nonNegative(counts.Received),
		ReturnPath:            nonNegative(counts.ReturnPath),
		DeliveredTo:           nonNegative(counts.DeliveredTo),
		AuthenticationResults: nonNegative(counts.AuthenticationResults),
		XHeader:               nonNegative(counts.XHeader),
		DKIMSignature:         nonNegative(counts.DKIMSignature),
		ExactUnsigned:         nonNegative(counts.ExactUnsigned),
		ARC:                   nonNegative(counts.ARC),
		MessageInstance:       nonNegative(counts.MessageInstance),
		DKIM2Signature:        nonNegative(counts.DKIM2Signature),
	}
}

// sanitizeBodyTerminalAction removes unknown body terminal-action tokens.
func sanitizeBodyTerminalAction(action BodyTerminalAction) BodyTerminalAction {
	switch action {
	case BodyTerminalActionUnspecified, BodyTerminalActionPreserved, BodyTerminalActionAppended, BodyTerminalActionCollapsed:
		return action
	default:
		return BodyTerminalActionUnspecified
	}
}

// nonNegative clamps metadata counters to their safe lower bound.
func nonNegative(value int) int {
	if value < 0 {
		return 0
	}

	return value
}
