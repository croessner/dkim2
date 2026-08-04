package dsn

import "github.com/croessner/dkim2/internal/rawmsg"

const (
	defaultMaxMessageBytes = 32 * 1024 * 1024
	defaultMaxPartBytes    = 24 * 1024 * 1024
	hardMaxBoundaryBytes   = 70
)

// ContentType identifies the restricted DSN MIME media types exposed by this package.
type ContentType string

const (
	// ContentTypeDeliveryStatus identifies the required second report part.
	ContentTypeDeliveryStatus ContentType = "message/delivery-status"
	// ContentTypeRFC822 identifies a complete embedded original message.
	ContentTypeRFC822 ContentType = "message/rfc822"
	// ContentTypeRFC822Headers identifies an embedded original-message header block.
	ContentTypeRFC822Headers ContentType = "text/rfc822-headers"
)

// Options bounds structural report parsing before any DSN interpretation occurs.
type Options struct {
	// MaxMessageBytes bounds the complete RFC 5322 report.
	MaxMessageBytes int
	// MaxPartBytes bounds each of the exactly three MIME parts.
	MaxPartBytes int
	// MaxBoundaryBytes bounds the MIME boundary before delimiter scanning.
	MaxBoundaryBytes int
}

// DefaultOptions returns restrictive resource limits for DSN structural parsing.
func DefaultOptions() Options {
	return Options{
		MaxMessageBytes:  defaultMaxMessageBytes,
		MaxPartBytes:     defaultMaxPartBytes,
		MaxBoundaryBytes: hardMaxBoundaryBytes,
	}
}

// Part exposes one immutable MIME part without interpreting its content.
type Part struct {
	message     rawmsg.Message
	contentType ContentType
}

// RawBytes returns a detached exact MIME-part representation, including MIME headers.
func (p Part) RawBytes() []byte {
	return p.message.RawBytes()
}

// Headers returns the immutable MIME-part header block.
func (p Part) Headers() rawmsg.HeaderBlock {
	return p.message.Headers()
}

// BodyBytes returns a detached exact MIME-part content representation.
func (p Part) BodyBytes() []byte {
	return p.message.Body().Bytes()
}

// ContentType returns the validated restricted media type for the part.
func (p Part) ContentType() ContentType {
	return p.contentType
}

// Report exposes the three required RFC 3462 report parts without interpreting their fields.
type Report struct {
	message        rawmsg.Message
	humanReadable  Part
	deliveryStatus Part
	original       Part
}

// RawMessage returns the validated byte-preserving top-level report representation.
func (r Report) RawMessage() rawmsg.Message {
	return r.message
}

// HumanReadable returns the first report part without imposing a content type on it.
func (r Report) HumanReadable() Part {
	return r.humanReadable
}

// DeliveryStatus returns the required message/delivery-status second part.
func (r Report) DeliveryStatus() Part {
	return r.deliveryStatus
}

// OriginalMessage returns the required message/rfc822 or text/rfc822-headers third part.
func (r Report) OriginalMessage() Part {
	return r.original
}
