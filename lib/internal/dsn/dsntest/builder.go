// Package dsntest builds deterministic DKIM2-signed messages and RFC 6522
// delivery-status reports for received-DSN evaluation tests.
//
// It renders Message-Instance and DKIM2-Signature fields directly and signs
// them with deterministic Ed25519 keys so that fixtures are reproducible
// across the dsn, verify, and public facade test layers. It is test support
// only and must never be imported by production code.
package dsntest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
)

const (
	// AlgorithmName is the DKIM2 algorithm token used by every generated signature.
	AlgorithmName = "ed25519-sha256"
	// DefaultTimestamp is the deterministic t= value used by generated signatures.
	DefaultTimestamp = uint64(1700000000)
	// DefaultBoundary is the MIME boundary used by generated reports.
	DefaultBoundary = "dsn-boundary"
)

// placeholderSignature is a parser-valid Ed25519-length signature used before signing.
var placeholderSignature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))

// Key is one deterministic test signing identity bound to a selector.
type Key struct {
	Selector string
	Private  ed25519.PrivateKey
}

// KeyForLabel derives one deterministic Ed25519 key from a stable label.
func KeyForLabel(label string, selector string) Key {
	seed := sha256.Sum256([]byte("dkim2-dsntest-key:" + label))
	return Key{Selector: selector, Private: ed25519.NewKeyFromSeed(seed[:])}
}

// Public returns the verification key for the identity.
func (k Key) Public() ed25519.PublicKey {
	return k.Private.Public().(ed25519.PublicKey)
}

// Hop describes one DKIM2-Signature field added by one signing system.
type Hop struct {
	// Domain is the d= signing domain.
	Domain string
	// Key signs the Section 9.6 input for this hop.
	Key Key
	// Timestamp is the t= value; zero selects DefaultTimestamp.
	Timestamp uint64
	// MailFrom is the exact bracketed mf= reverse path, ignored when NextDomain is set.
	MailFrom string
	// Recipients are the exact bracketed rt= forward paths, ignored when NextDomain is set.
	Recipients []string
	// NextDomain selects the nd= envelope form when non-empty.
	NextDomain string
	// Instance is the m= reference; zero selects instance 1.
	Instance uint64
	// CorruptSignature replaces the computed signature with an invalid value.
	CorruptSignature bool
	// UnsignedAbove renders CRLF-terminated header fields directly above this
	// hop's DKIM2-Signature field, such as trace fields the hop prepended.
	UnsignedAbove string
}

// Revision describes one earlier Message-Instance state below the current
// state of an Original. Revisions are listed in ascending m= order, so the
// first revision is m=1 and the current Headers and Body form the highest
// instance.
type Revision struct {
	// Headers is the CRLF-terminated base header block of the earlier state.
	Headers string
	// Body is the exact body of the earlier state.
	Body string
	// Recipe is the JSON recipe carried by the next higher Message-Instance
	// that reconstructs this state; empty renders that instance without r=.
	Recipe string
}

// Original describes one signed embedded original message.
type Original struct {
	// Headers is the CRLF-terminated base header block without protocol fields.
	Headers string
	// Body is the exact message body placed after the header separator.
	Body string
	// Hops are applied in ascending i= order; the last hop is the highest signature.
	Hops []Hop
	// Revisions lists earlier states in ascending m= order; the current state
	// becomes m=len(Revisions)+1 and each hop selects its instance explicitly.
	Revisions []Revision
	// ExtraInstances renders additional Message-Instance fields verbatim above the highest instance.
	ExtraInstances []string
	// Prepend renders CRLF-terminated header fields above every signature,
	// such as trace fields added by the system that received the message.
	Prepend string
}

// Build renders and signs the original. The returned bytes are the complete
// message; HeaderBlock returns the header-only representation of the same bytes.
func (o Original) Build() ([]byte, error) {
	if len(o.Hops) == 0 || o.Headers == "" || !strings.HasSuffix(o.Headers, "\r\n") {
		return nil, errors.New("dsntest: original requires CRLF headers and at least one hop")
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		return nil, err
	}
	instanceFields, err := o.renderInstances(canonicalizer)
	if err != nil {
		return nil, err
	}
	signatureFields := make([]string, 0, len(o.Hops))
	highest := uint64(0)
	for index, hop := range o.Hops {
		sequence := uint64(index + 1)
		if hop.Instance > highest {
			highest = hop.Instance
		}
		if highest == 0 {
			highest = 1
		}
		unsigned := hop.UnsignedAbove + renderSignature(sequence, hop, placeholderSignature)
		candidate := unsigned + joinReverse(signatureFields) + joinReverse(instanceFields[:min(int(highest), len(instanceFields))]) + o.Headers + "\r\n" + o.Body
		signed, signErr := signCandidate(canonicalizer, []byte(candidate), sequence, hop)
		if signErr != nil {
			return nil, signErr
		}
		signatureFields = append(signatureFields, hop.UnsignedAbove+renderSignature(sequence, hop, signed))
	}
	instances := joinReverse(instanceFields)
	for _, extra := range o.ExtraInstances {
		instances = extra + instances
	}
	return []byte(o.Prepend + joinReverse(signatureFields) + instances + o.Headers + "\r\n" + o.Body), nil
}

// renderInstances renders every Message-Instance field in ascending m= order
// with the hashes of each revision and current state and the recipe that
// reconstructs the state below each instance. Each hop is signed over the
// instances that existed when it signed, so the candidate for hop i carries
// only instances up to the highest instance referenced so far.
func (o Original) renderInstances(canonicalizer canonical.Canonicalizer) ([]string, error) {
	states := make([]Revision, 0, len(o.Revisions)+1)
	states = append(states, o.Revisions...)
	states = append(states, Revision{Headers: o.Headers, Body: o.Body})
	rendered := make([]string, 0, len(states))
	for index, state := range states {
		number := uint64(index + 1)
		hashes, err := instanceHashes(canonicalizer, state.Headers, state.Body)
		if err != nil {
			return nil, err
		}
		line := "Message-Instance: m=" + itoa(number) + "; h=" + hashes + ";"
		if index > 0 && states[index-1].Recipe != "" {
			line += " r=" + base64.StdEncoding.EncodeToString([]byte(states[index-1].Recipe)) + ";"
		}
		rendered = append(rendered, line+"\r\n")
	}
	return rendered, nil
}

// instanceHashes computes the sha256 header and body hash tuple of one state.
func instanceHashes(canonicalizer canonical.Canonicalizer, headers, body string) (string, error) {
	if headers == "" || !strings.HasSuffix(headers, "\r\n") {
		return "", errors.New("dsntest: state requires CRLF headers")
	}
	base, err := rawmsg.Parse([]byte(headers + "\r\n" + body))
	if err != nil {
		return "", err
	}
	headerHash, err := canonicalizer.HeaderHashFromMessage(base)
	if err != nil {
		return "", err
	}
	bodyHash, err := canonicalizer.BodyHashFromMessage(base)
	if err != nil {
		return "", err
	}
	headerDigest, ok := headerHash.Digest()
	if !ok {
		return "", errors.New("dsntest: header digest missing")
	}
	bodyDigest, ok := bodyHash.Digest()
	if !ok {
		return "", errors.New("dsntest: body digest missing")
	}
	return "sha256:" + headerDigest.Base64() + ":" + bodyDigest.Base64(), nil
}

// HeaderBlock returns the header-only representation of a built original.
func HeaderBlock(message []byte) []byte {
	separator := strings.Index(string(message), "\r\n\r\n")
	if separator < 0 {
		return append([]byte(nil), message...)
	}
	return append([]byte(nil), message[:separator+2]...)
}

// signCandidate computes the Section 9.6 signature for one target sequence.
func signCandidate(canonicalizer canonical.Canonicalizer, candidate []byte, sequence uint64, hop Hop) (string, error) {
	message, err := rawmsg.Parse(candidate)
	if err != nil {
		return "", err
	}
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{Headers: message.Headers(), TargetSequence: sequence})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(input.Bytes())
	signature := ed25519.Sign(hop.Key.Private, digest[:])
	if hop.CorruptSignature {
		signature[0] ^= 0xff
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// renderSignature renders one DKIM2-Signature field with the supplied s= signature text.
func renderSignature(sequence uint64, hop Hop, signatureText string) string {
	timestamp := hop.Timestamp
	if timestamp == 0 {
		timestamp = DefaultTimestamp
	}
	instance := hop.Instance
	if instance == 0 {
		instance = 1
	}
	field := "DKIM2-Signature: i=" + itoa(sequence) + "; m=" + itoa(instance) + "; t=" + itoa(timestamp) + "; "
	if hop.NextDomain != "" {
		field += "nd=" + hop.NextDomain + "; "
	} else {
		recipients := make([]string, len(hop.Recipients))
		for index, recipient := range hop.Recipients {
			recipients[index] = base64.StdEncoding.EncodeToString([]byte(recipient))
		}
		field += "mf=" + base64.StdEncoding.EncodeToString([]byte(hop.MailFrom)) + "; rt=" + strings.Join(recipients, ",") + "; "
	}
	return field + "d=" + hop.Domain + "; s=" + hop.Key.Selector + ":" + AlgorithmName + ":" + signatureText + ";\r\n"
}

// joinReverse concatenates rendered fields so the highest sequence is first.
func joinReverse(fields []string) string {
	var builder strings.Builder
	for index := len(fields) - 1; index >= 0; index-- {
		builder.WriteString(fields[index])
	}
	return builder.String()
}

// itoa formats one unsigned decimal without importing strconv into fixtures repeatedly.
func itoa(value uint64) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	position := len(digits)
	for value > 0 {
		position--
		digits[position] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[position:])
}

// Report describes one RFC 6522 delivery-status report around an embedded original.
type Report struct {
	// OuterHeaders is the CRLF-terminated outer header block without Content-Type or protocol fields.
	OuterHeaders string
	// Human is the first part body.
	Human string
	// DeliveryStatus is the exact message/delivery-status body.
	DeliveryStatus string
	// OriginalContentType is message/rfc822 or text/rfc822-headers.
	OriginalContentType string
	// Original is the embedded original bytes for the third part.
	Original []byte
	// Signer optionally signs the outer report as i=1 with mf=<> and its recipients.
	Signer *Hop
	// Boundary overrides the MIME boundary when non-empty.
	Boundary string
}

// Build renders the report and, when a signer is supplied, signs the outer message.
func (r Report) Build() ([]byte, error) {
	boundary := r.Boundary
	if boundary == "" {
		boundary = DefaultBoundary
	}
	if r.OuterHeaders == "" || !strings.HasSuffix(r.OuterHeaders, "\r\n") || r.OriginalContentType == "" {
		return nil, errors.New("dsntest: report requires CRLF outer headers and an original content type")
	}
	headers := r.OuterHeaders + "MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=" + boundary + "\r\n"
	body := "--" + boundary + "\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n" + r.Human + "\r\n" +
		"--" + boundary + "\r\nContent-Type: message/delivery-status\r\n\r\n" + r.DeliveryStatus + "\r\n" +
		"--" + boundary + "\r\nContent-Type: " + r.OriginalContentType + "\r\n\r\n" + string(r.Original) + "\r\n" +
		"--" + boundary + "--\r\n"
	if r.Signer == nil {
		return []byte(headers + "\r\n" + body), nil
	}
	signed, err := (Original{Headers: headers, Body: body, Hops: []Hop{*r.Signer}}).Build()
	if err != nil {
		return nil, err
	}
	return signed, nil
}

// FailedDeliveryStatus renders one generic RFC 3464 body with a single failed recipient group.
func FailedDeliveryStatus(reportingMTA string, finalRecipient string, status string) string {
	return "Reporting-MTA: dns; " + reportingMTA + "\r\n\r\n" +
		"Final-Recipient: rfc822; " + finalRecipient + "\r\n" +
		"Action: failed\r\nStatus: " + status + "\r\n"
}
