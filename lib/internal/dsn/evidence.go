package dsn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
	"github.com/croessner/dkim2/internal/verify"
)

// EvidenceForm identifies the bounded representation retained for the original message.
type EvidenceForm string

const (
	// EvidenceFormComplete identifies a complete message/rfc822 original with body evidence.
	EvidenceFormComplete EvidenceForm = "complete"
	// EvidenceFormHeadersOnly identifies a text/rfc822-headers original without body evidence.
	EvidenceFormHeadersOnly EvidenceForm = "headers_only"
)

// EvidenceErrorCode identifies one content-free DSN evidence failure.
type EvidenceErrorCode string

const (
	// EvidenceErrorCodeInvalidEvaluator reports an uninitialized verifier dependency.
	EvidenceErrorCodeInvalidEvaluator EvidenceErrorCode = "invalid_evaluator"
	// EvidenceErrorCodeInvalidRequest reports an unsafe DSN evidence request shape.
	EvidenceErrorCodeInvalidRequest EvidenceErrorCode = "invalid_request"
	// EvidenceErrorCodeInvalidOriginal reports malformed or ambiguous embedded original bytes.
	EvidenceErrorCodeInvalidOriginal EvidenceErrorCode = "invalid_original"
	// EvidenceErrorCodeVerificationFailed reports non-passing cryptographic original evidence.
	EvidenceErrorCodeVerificationFailed EvidenceErrorCode = "verification_failed"
	// EvidenceErrorCodeVerificationIndeterminate reports transient or otherwise non-final verification evidence.
	EvidenceErrorCodeVerificationIndeterminate EvidenceErrorCode = "verification_indeterminate"
)

// EvidenceError is a typed, content-free DSN evidence failure.
type EvidenceError struct {
	code  EvidenceErrorCode
	cause error
}

// Error returns a bounded diagnostic that never includes original message or envelope content.
func (e *EvidenceError) Error() string {
	if e == nil {
		return "dsn evidence error: <nil>"
	}
	return fmt.Sprintf("dsn evidence error: code=%s", e.code)
}

// Unwrap exposes an already content-free verifier or parser cause for typed callers.
func (e *EvidenceError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Is matches evidence errors by stable code.
func (e *EvidenceError) Is(target error) bool {
	var targetError *EvidenceError
	return errors.As(target, &targetError) && e != nil && targetError != nil && e.code == targetError.code
}

// Code returns the stable evidence failure code.
func (e *EvidenceError) Code() EvidenceErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

// IsEvidenceErrorCode reports whether err contains the requested evidence code.
func IsEvidenceErrorCode(err error, code EvidenceErrorCode) bool {
	var evidenceError *EvidenceError
	return errors.As(err, &evidenceError) && evidenceError.Code() == code
}

// EvidenceRequest carries one parsed DSN whose embedded protocol object must
// be authenticated without pretending signed claims were externally observed.
type EvidenceRequest struct {
	// Report is the parser-owned RFC 3462 DSN report.
	Report Report
	// PostfixCompatibleOrder admits only the bounded field ordering and folding
	// emitted by Postfix bounce(8), after the caller has independently proven
	// the dedicated trusted-Postfix route.
	PostfixCompatibleOrder bool
}

// Evidence stores the authenticated embedded DKIM2 target without retaining message content.
type Evidence struct {
	form             EvidenceForm
	target           verify.Target
	mailFrom         []byte
	signingDomain    string
	recipientDomains []string
	recipientPaths   [][]byte
}

// Valid reports whether the evidence binds one supported original representation to an authenticated target.
func (e Evidence) Valid() bool {
	return (e.form == EvidenceFormComplete || e.form == EvidenceFormHeadersOnly) && e.target.Sequence > 0 && e.target.InstanceNumber > 0 &&
		len(e.mailFrom) > 0 && !bytes.Equal(e.mailFrom, []byte("<>")) && e.signingDomain != "" && len(e.recipientDomains) > 0
}

// Form returns the retained original representation.
func (e Evidence) Form() EvidenceForm {
	return e.form
}

// Target returns the authenticated highest embedded DKIM2 target identifiers.
func (e Evidence) Target() verify.Target {
	return e.target
}

// MailFrom returns a detached exact highest-signature mf= path. It is retained
// only to bind the outer DSN recipient to the authenticated original sender.
func (e Evidence) MailFrom() []byte { return bytes.Clone(e.mailFrom) }

// SigningDomain returns the canonical d= domain from the authenticated highest embedded DKIM2 signature.
func (e Evidence) SigningDomain() string {
	return e.signingDomain
}

// RecipientDomains returns detached canonical DNS domains from every highest embedded rt= recipient.
func (e Evidence) RecipientDomains() []string {
	return append([]string(nil), e.recipientDomains...)
}

// EvidenceEvaluator owns the narrow Draft-04 Section 12 embedded-original verification boundary.
type EvidenceEvaluator struct {
	verifier verify.Verifier
}

// NewEvidenceEvaluator constructs a DSN evaluator from one validated DKIM2 verifier.
func NewEvidenceEvaluator(verifier verify.Verifier) (EvidenceEvaluator, error) {
	if !verifier.Valid() {
		return EvidenceEvaluator{}, newEvidenceError(EvidenceErrorCodeInvalidEvaluator, nil)
	}
	return EvidenceEvaluator{verifier: verifier}, nil
}

// Evaluate verifies an embedded original before DSN signing authorization.
// Complete originals require complete body and header verification, while headers-only
// originals use the dedicated header-only verifier and never substitute a body.
func (e EvidenceEvaluator) Evaluate(ctx context.Context, request EvidenceRequest) (Evidence, error) {
	if ctx == nil || !e.verifier.Valid() || !request.Report.RawMessage().Initialized() {
		return Evidence{}, newEvidenceError(EvidenceErrorCodeInvalidRequest, nil)
	}
	original := request.Report.OriginalMessage()
	parsed, err := rawmsg.Parse(original.BodyBytes())
	if err != nil {
		return Evidence{}, newEvidenceError(EvidenceErrorCodeInvalidOriginal, nil)
	}
	verificationRequest := verify.Request{
		Message: parsed,
	}
	switch original.ContentType() {
	case ContentTypeRFC822:
		result, verifyErr := e.verifier.VerifyDeliveryStatusComplete(ctx, verificationRequest)
		if verifyErr != nil {
			return Evidence{}, newEvidenceError(EvidenceErrorCodeVerificationFailed, verifyErr)
		}
		if result.Status() != verify.TargetStatusPass {
			return Evidence{}, evidenceStatusError(result.Status())
		}
		evidence, evidenceErr := authenticatedEvidence(EvidenceFormComplete, parsed, result.Target())
		if evidenceErr != nil || !deliveryStatusLinksRecipient(request.Report, evidence.recipientPaths, request.PostfixCompatibleOrder) {
			return Evidence{}, newEvidenceError(EvidenceErrorCodeInvalidOriginal, evidenceErr)
		}
		return evidence, nil
	case ContentTypeRFC822Headers:
		headerEvidence, verifyErr := e.verifier.VerifyDeliveryStatusHeadersOnly(ctx, verificationRequest)
		if verifyErr != nil {
			return Evidence{}, newEvidenceError(EvidenceErrorCodeVerificationFailed, verifyErr)
		}
		if !headerEvidence.Valid() {
			return Evidence{}, evidenceStatusError(headerEvidence.Status())
		}
		evidence, evidenceErr := authenticatedEvidence(EvidenceFormHeadersOnly, parsed, headerEvidence.Target())
		if evidenceErr != nil || !deliveryStatusLinksRecipient(request.Report, evidence.recipientPaths, request.PostfixCompatibleOrder) {
			return Evidence{}, newEvidenceError(EvidenceErrorCodeInvalidOriginal, evidenceErr)
		}
		return evidence, nil
	default:
		return Evidence{}, newEvidenceError(EvidenceErrorCodeInvalidOriginal, nil)
	}
}

// authenticatedEvidence derives only the local-identity facts required from the already authenticated highest target.
func authenticatedEvidence(form EvidenceForm, message rawmsg.Message, target verify.Target) (Evidence, error) {
	signatures, err := signature.Extract(message)
	if err != nil {
		return Evidence{}, newEvidenceError(EvidenceErrorCodeInvalidOriginal, nil)
	}
	for _, parsed := range signatures {
		if parsed.Sequence() != target.Sequence || parsed.InstanceNumber() != target.InstanceNumber {
			continue
		}
		recipients := parsed.Recipients()
		domains := make([]string, len(recipients))
		paths := make([][]byte, len(recipients))
		for index, recipient := range recipients {
			path, pathValid := signature.CanonicalEnvelopePath(recipient.Value(), false)
			domain, valid := signature.CanonicalEnvelopeDomain(recipient.Value(), false)
			if !valid || !pathValid {
				return Evidence{}, newEvidenceError(EvidenceErrorCodeInvalidOriginal, nil)
			}
			domains[index] = domain
			paths[index] = path
		}
		mailFrom := parsed.MailFrom().Value()
		if parsed.Domain() == "" || len(domains) == 0 || !signature.ValidEnvelopePath(mailFrom, false) {
			return Evidence{}, newEvidenceError(EvidenceErrorCodeInvalidOriginal, nil)
		}
		return Evidence{
			form: form, target: target, mailFrom: bytes.Clone(mailFrom),
			signingDomain: parsed.Domain(), recipientDomains: domains, recipientPaths: paths,
		}, nil
	}
	return Evidence{}, newEvidenceError(EvidenceErrorCodeInvalidOriginal, nil)
}

const (
	maxDeliveryStatusBytes           = 256 << 10
	maxDeliveryStatusLineBytes       = 4096
	maxDeliveryStatusRecipientGroups = 256
	maxDeliveryStatusFieldsPerGroup  = 64
	maxDeliveryStatusTotalFields     = 2048
	maxDeliveryStatusCommentDepth    = 16
)

// deliveryStatusLinksRecipient validates the bounded RFC 3464 field-block
// structure and requires one complete recipient group to name an authenticated
// highest-signature rt= path. Folding fails closed. RFC 3461 xtext is decoded
// only for Original-Recipient; Final-Recipient is compared as its raw address.
func deliveryStatusLinksRecipient(report Report, signed [][]byte, postfixCompatible bool) bool {
	body := report.DeliveryStatus().BodyBytes()
	defer clear(body)
	if deliveryStatusBodyLinksRecipient(body, signed, false) {
		return true
	}
	return postfixCompatible && deliveryStatusBodyLinksRecipient(body, signed, true)
}

// deliveryStatusBodyLinksRecipient validates one bounded RFC 3464 body and
// reports whether a structurally complete recipient group links to signed rt=.
func deliveryStatusBodyLinksRecipient(body []byte, signed [][]byte, postfixCompatible bool) bool {
	if len(body) == 0 || len(body) > maxDeliveryStatusBytes {
		return false
	}
	if postfixCompatible {
		unfolded, valid := unfoldPostfixDeliveryStatus(body)
		if !valid {
			return false
		}
		defer clear(unfolded)
		body = unfolded
	}
	group := deliveryStatusFieldGroup{}
	groupIndex := 0
	totalFields := 0
	linked := false
	position := 0
	for position < len(body) {
		relativeEnd := bytes.Index(body[position:], []byte("\r\n"))
		lineEnd := len(body)
		if relativeEnd >= 0 {
			lineEnd = position + relativeEnd
		}
		line := body[position:lineEnd]
		if len(line) > maxDeliveryStatusLineBytes || bytes.ContainsAny(line, "\r\n") {
			return false
		}
		if relativeEnd < 0 {
			position = len(body)
		} else {
			position = lineEnd + 2
		}
		if len(line) == 0 {
			groupLinked, valid := finishDeliveryStatusGroup(groupIndex, group, signed, postfixCompatible)
			if !valid {
				return false
			}
			linked = linked || groupLinked
			groupIndex++
			group = deliveryStatusFieldGroup{}
			continue
		}
		if line[0] == ' ' || line[0] == '\t' ||
			!group.add(groupIndex, line, postfixCompatible) {
			return false
		}
		totalFields++
		if group.fieldCount > maxDeliveryStatusFieldsPerGroup ||
			totalFields > maxDeliveryStatusTotalFields {
			return false
		}
	}
	if group.fieldCount > 0 {
		groupLinked, valid := finishDeliveryStatusGroup(groupIndex, group, signed, postfixCompatible)
		if !valid {
			return false
		}
		linked = linked || groupLinked
		groupIndex++
	}
	return groupIndex >= 2 && groupIndex-1 <= maxDeliveryStatusRecipientGroups && linked
}

type deliveryStatusFieldGroup struct {
	fieldCount         int
	seen               uint32
	lastRank           int
	extensionStarted   bool
	originalEnvelopeID []byte
	reportingMTA       []byte
	dsnGateway         []byte
	receivedFromMTA    []byte
	arrivalDate        []byte
	originalRecipient  []byte
	finalRecipient     []byte
	action             []byte
	status             []byte
	remoteMTA          []byte
	diagnosticCode     []byte
	lastAttemptDate    []byte
	finalLogID         []byte
	willRetryUntil     []byte
	postfixMailName    []byte
	postfixQueueID     []byte
	postfixSender      []byte
}

type deliveryStatusField uint8

const (
	deliveryStatusFieldExtension deliveryStatusField = iota
	deliveryStatusFieldOriginalEnvelopeID
	deliveryStatusFieldReportingMTA
	deliveryStatusFieldDSNGateway
	deliveryStatusFieldReceivedFromMTA
	deliveryStatusFieldArrivalDate
	deliveryStatusFieldOriginalRecipient
	deliveryStatusFieldFinalRecipient
	deliveryStatusFieldAction
	deliveryStatusFieldStatus
	deliveryStatusFieldRemoteMTA
	deliveryStatusFieldDiagnosticCode
	deliveryStatusFieldLastAttemptDate
	deliveryStatusFieldFinalLogID
	deliveryStatusFieldWillRetryUntil
)

// add classifies and admits one unfolded field into the selected strict group state machine.
func (g *deliveryStatusFieldGroup) add(groupIndex int, line []byte, postfixCompatible bool) bool {
	if g == nil {
		return false
	}
	colon := bytes.IndexByte(line, ':')
	if colon < 1 || !validDeliveryStatusFieldName(line[:colon]) {
		return false
	}
	value := bytes.Trim(line[colon+1:], " \t")
	field := classifyDeliveryStatusField(line[:colon])
	if postfixCompatible {
		return g.addPostfix(groupIndex, line[:colon], field, value)
	}
	rank, allowed := deliveryStatusFieldRank(groupIndex, field)
	if !allowed {
		return false
	}
	if field == deliveryStatusFieldExtension {
		if !g.mandatoryFieldsSeen(groupIndex) {
			return false
		}
		g.extensionStarted = true
		g.fieldCount++
		return true
	}
	bit := uint32(1) << field
	if g.extensionStarted || g.seen&bit != 0 || g.fieldCount > 0 && rank < g.lastRank {
		return false
	}
	if !g.prerequisitesSeen(groupIndex, field) {
		return false
	}
	g.seen |= bit
	g.lastRank = rank
	g.fieldCount++
	switch field {
	case deliveryStatusFieldOriginalEnvelopeID:
		g.originalEnvelopeID = value
	case deliveryStatusFieldReportingMTA:
		g.reportingMTA = value
	case deliveryStatusFieldDSNGateway:
		g.dsnGateway = value
	case deliveryStatusFieldReceivedFromMTA:
		g.receivedFromMTA = value
	case deliveryStatusFieldArrivalDate:
		g.arrivalDate = value
	case deliveryStatusFieldOriginalRecipient:
		g.originalRecipient = value
	case deliveryStatusFieldFinalRecipient:
		g.finalRecipient = value
	case deliveryStatusFieldAction:
		g.action = value
	case deliveryStatusFieldStatus:
		g.status = value
	case deliveryStatusFieldRemoteMTA:
		g.remoteMTA = value
	case deliveryStatusFieldDiagnosticCode:
		g.diagnosticCode = value
	case deliveryStatusFieldLastAttemptDate:
		g.lastAttemptDate = value
	case deliveryStatusFieldFinalLogID:
		g.finalLogID = value
	case deliveryStatusFieldWillRetryUntil:
		g.willRetryUntil = value
	}
	return true
}

// addPostfix admits exactly the historical field order emitted by Postfix
// bounce_notify_util.c. It does not turn the generic RFC parser into an
// order-insensitive parser.
func (g *deliveryStatusFieldGroup) addPostfix(
	groupIndex int,
	name []byte,
	field deliveryStatusField,
	value []byte,
) bool {
	if groupIndex == 0 {
		return g.addPostfixMessageField(name, field, value)
	}
	return g.addPostfixRecipientField(field, value)
}

// addPostfixMessageField admits one field in Postfix's exact per-message sequence.
func (g *deliveryStatusFieldGroup) addPostfixMessageField(
	name []byte,
	field deliveryStatusField,
	value []byte,
) bool {
	if field == deliveryStatusFieldExtension {
		return g.addPostfixExtension(name, value)
	}
	var rank int
	switch field {
	case deliveryStatusFieldReportingMTA:
		rank = 0
	case deliveryStatusFieldOriginalEnvelopeID:
		rank = 1
	case deliveryStatusFieldArrivalDate:
		rank = 4
	default:
		return false
	}
	bit := uint32(1) << field
	if g.seen&bit != 0 || g.fieldCount > 0 && rank < g.lastRank ||
		field == deliveryStatusFieldReportingMTA && g.fieldCount != 0 ||
		field == deliveryStatusFieldOriginalEnvelopeID && !g.has(deliveryStatusFieldReportingMTA) ||
		field == deliveryStatusFieldArrivalDate && len(g.postfixQueueID) == 0 {
		return false
	}
	g.seen |= bit
	g.lastRank = rank
	g.fieldCount++
	switch field {
	case deliveryStatusFieldReportingMTA:
		g.reportingMTA = value
	case deliveryStatusFieldOriginalEnvelopeID:
		g.originalEnvelopeID = value
	case deliveryStatusFieldArrivalDate:
		g.arrivalDate = value
	}
	return true
}

// addPostfixExtension admits only matching queue and sender fields in their fixed positions.
func (g *deliveryStatusFieldGroup) addPostfixExtension(name, value []byte) bool {
	const prefix = "x-"
	queueSuffix := []byte("-queue-id")
	senderSuffix := []byte("-sender")
	if !bytes.EqualFold(name[:min(len(name), len(prefix))], []byte(prefix)) ||
		!g.has(deliveryStatusFieldReportingMTA) || g.has(deliveryStatusFieldArrivalDate) {
		return false
	}
	var mailName []byte
	switch {
	case len(name) > len(prefix)+len(queueSuffix) && bytes.EqualFold(name[len(name)-len(queueSuffix):], queueSuffix):
		if len(g.postfixQueueID) != 0 || len(g.postfixSender) != 0 || g.lastRank > 2 {
			return false
		}
		mailName = name[len(prefix) : len(name)-len(queueSuffix)]
		if !validDeliveryStatusAtom(mailName) || !validDeliveryStatusAtom(value) {
			return false
		}
		g.postfixQueueID = value
		g.postfixMailName = mailName
		g.lastRank = 2
	case len(name) > len(prefix)+len(senderSuffix) && bytes.EqualFold(name[len(name)-len(senderSuffix):], senderSuffix):
		if len(g.postfixQueueID) == 0 || len(g.postfixSender) != 0 || g.lastRank > 3 {
			return false
		}
		mailName = name[len(prefix) : len(name)-len(senderSuffix)]
		if !bytes.EqualFold(mailName, g.postfixMailName) ||
			!validDeliveryStatusTypedText(value, "", false) {
			return false
		}
		g.postfixSender = value
		g.lastRank = 3
	default:
		return false
	}
	g.fieldCount++
	return true
}

// addPostfixRecipientField admits one field in Postfix's exact per-recipient sequence.
func (g *deliveryStatusFieldGroup) addPostfixRecipientField(
	field deliveryStatusField,
	value []byte,
) bool {
	var rank int
	switch field {
	case deliveryStatusFieldFinalRecipient:
		rank = 0
	case deliveryStatusFieldOriginalRecipient:
		rank = 1
	case deliveryStatusFieldAction:
		rank = 2
	case deliveryStatusFieldStatus:
		rank = 3
	case deliveryStatusFieldRemoteMTA:
		rank = 4
	case deliveryStatusFieldDiagnosticCode:
		rank = 5
	case deliveryStatusFieldWillRetryUntil:
		rank = 6
	default:
		return false
	}
	bit := uint32(1) << field
	if g.seen&bit != 0 || g.fieldCount > 0 && rank < g.lastRank ||
		field == deliveryStatusFieldFinalRecipient && g.fieldCount != 0 ||
		field == deliveryStatusFieldOriginalRecipient && !g.has(deliveryStatusFieldFinalRecipient) ||
		field == deliveryStatusFieldAction && !g.has(deliveryStatusFieldFinalRecipient) ||
		field == deliveryStatusFieldStatus && !g.has(deliveryStatusFieldAction) ||
		rank >= 4 && !g.has(deliveryStatusFieldStatus) {
		return false
	}
	g.seen |= bit
	g.lastRank = rank
	g.fieldCount++
	switch field {
	case deliveryStatusFieldFinalRecipient:
		g.finalRecipient = value
	case deliveryStatusFieldOriginalRecipient:
		g.originalRecipient = value
	case deliveryStatusFieldAction:
		g.action = value
	case deliveryStatusFieldStatus:
		g.status = value
	case deliveryStatusFieldRemoteMTA:
		g.remoteMTA = value
	case deliveryStatusFieldDiagnosticCode:
		g.diagnosticCode = value
	case deliveryStatusFieldWillRetryUntil:
		g.willRetryUntil = value
	}
	return true
}

func classifyDeliveryStatusField(name []byte) deliveryStatusField {
	fields := []struct {
		name  string
		field deliveryStatusField
	}{
		{"original-envelope-id", deliveryStatusFieldOriginalEnvelopeID},
		{"reporting-mta", deliveryStatusFieldReportingMTA},
		{"dsn-gateway", deliveryStatusFieldDSNGateway},
		{"received-from-mta", deliveryStatusFieldReceivedFromMTA},
		{"arrival-date", deliveryStatusFieldArrivalDate},
		{"original-recipient", deliveryStatusFieldOriginalRecipient},
		{"final-recipient", deliveryStatusFieldFinalRecipient},
		{"action", deliveryStatusFieldAction},
		{"status", deliveryStatusFieldStatus},
		{"remote-mta", deliveryStatusFieldRemoteMTA},
		{"diagnostic-code", deliveryStatusFieldDiagnosticCode},
		{"last-attempt-date", deliveryStatusFieldLastAttemptDate},
		{"final-log-id", deliveryStatusFieldFinalLogID},
		{"will-retry-until", deliveryStatusFieldWillRetryUntil},
	}
	for _, candidate := range fields {
		if bytes.EqualFold(name, []byte(candidate.name)) {
			return candidate.field
		}
	}
	return deliveryStatusFieldExtension
}

func deliveryStatusFieldRank(groupIndex int, field deliveryStatusField) (int, bool) {
	if field == deliveryStatusFieldExtension {
		return 100, true
	}
	if groupIndex == 0 {
		switch field {
		case deliveryStatusFieldOriginalEnvelopeID:
			return 0, true
		case deliveryStatusFieldReportingMTA:
			return 1, true
		case deliveryStatusFieldDSNGateway:
			return 2, true
		case deliveryStatusFieldReceivedFromMTA:
			return 3, true
		case deliveryStatusFieldArrivalDate:
			return 4, true
		default:
			return 0, false
		}
	}
	switch field {
	case deliveryStatusFieldOriginalRecipient:
		return 0, true
	case deliveryStatusFieldFinalRecipient:
		return 1, true
	case deliveryStatusFieldAction:
		return 2, true
	case deliveryStatusFieldStatus:
		return 3, true
	case deliveryStatusFieldRemoteMTA:
		return 4, true
	case deliveryStatusFieldDiagnosticCode:
		return 5, true
	case deliveryStatusFieldLastAttemptDate:
		return 6, true
	case deliveryStatusFieldFinalLogID:
		return 7, true
	case deliveryStatusFieldWillRetryUntil:
		return 8, true
	default:
		return 0, false
	}
}

func (g deliveryStatusFieldGroup) has(field deliveryStatusField) bool {
	return g.seen&(uint32(1)<<field) != 0
}

func (g deliveryStatusFieldGroup) mandatoryFieldsSeen(groupIndex int) bool {
	if groupIndex == 0 {
		return g.has(deliveryStatusFieldReportingMTA)
	}
	return g.has(deliveryStatusFieldFinalRecipient) &&
		g.has(deliveryStatusFieldAction) && g.has(deliveryStatusFieldStatus)
}

func (g deliveryStatusFieldGroup) prerequisitesSeen(groupIndex int, field deliveryStatusField) bool {
	if groupIndex == 0 {
		return field == deliveryStatusFieldOriginalEnvelopeID ||
			field == deliveryStatusFieldReportingMTA || g.has(deliveryStatusFieldReportingMTA)
	}
	switch field {
	case deliveryStatusFieldOriginalRecipient, deliveryStatusFieldFinalRecipient:
		return true
	case deliveryStatusFieldAction:
		return g.has(deliveryStatusFieldFinalRecipient)
	case deliveryStatusFieldStatus:
		return g.has(deliveryStatusFieldAction)
	default:
		return g.has(deliveryStatusFieldStatus)
	}
}

func finishDeliveryStatusGroup(
	index int,
	group deliveryStatusFieldGroup,
	signed [][]byte,
	postfixCompatible bool,
) (bool, bool) {
	if group.fieldCount == 0 {
		return false, false
	}
	if index == 0 {
		if !group.mandatoryFieldsSeen(index) || !validDeliveryStatusOptionalMessageFields(group) ||
			postfixCompatible && len(group.postfixQueueID) == 0 {
			return false, false
		}
		return false, validDeliveryStatusTypedText(group.reportingMTA, "", false)
	}
	if index > maxDeliveryStatusRecipientGroups || !group.mandatoryFieldsSeen(index) ||
		!validDeliveryStatusAction(group.action) || !validDeliveryStatusCode(group.status) ||
		!validDeliveryStatusOptionalRecipientFields(group) ||
		postfixCompatible && !group.has(deliveryStatusFieldDiagnosticCode) {
		return false, false
	}
	finalPath, valid := deliveryStatusFinalRecipientPath(group.finalRecipient)
	if !valid {
		return false, false
	}
	linked := deliveryStatusPathMatches(finalPath, signed)
	clear(finalPath)
	if group.has(deliveryStatusFieldOriginalRecipient) {
		originalPath, originalValid := deliveryStatusOriginalRecipientPath(group.originalRecipient)
		if !originalValid {
			return false, false
		}
		linked = linked || deliveryStatusPathMatches(originalPath, signed)
		clear(originalPath)
	}
	return linked, true
}

// unfoldPostfixDeliveryStatus unfolds only RFC 822 continuation lines from a
// bounded Postfix delivery-status part. Generic DSNs retain the strict
// no-folding contract. Every unfolded logical field remains line-bounded.
func unfoldPostfixDeliveryStatus(body []byte) ([]byte, bool) {
	if len(body) == 0 || len(body) > maxDeliveryStatusBytes {
		return nil, false
	}
	output := make([]byte, 0, len(body))
	logicalStart := 0
	position := 0
	haveField := false
	foldable := false
	for position < len(body) {
		relativeEnd := bytes.Index(body[position:], []byte("\r\n"))
		lineEnd := len(body)
		if relativeEnd >= 0 {
			lineEnd = position + relativeEnd
		}
		line := body[position:lineEnd]
		if len(line) > maxDeliveryStatusLineBytes || bytes.ContainsAny(line, "\r\n") {
			clear(output)
			return nil, false
		}
		continuation := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
		if continuation {
			if !haveField || !foldable || len(output) < 2 || !bytes.HasSuffix(output, []byte("\r\n")) {
				clear(output)
				return nil, false
			}
			continued := bytes.TrimLeft(line, " \t")
			if len(continued) == 0 {
				clear(output)
				return nil, false
			}
			output = output[:len(output)-2]
			output = append(output, ' ')
			output = append(output, continued...)
			if len(output)-logicalStart > maxDeliveryStatusLineBytes {
				clear(output)
				return nil, false
			}
		} else {
			if len(line) == 0 {
				haveField = false
				foldable = false
			} else {
				haveField = true
				colon := bytes.IndexByte(line, ':')
				if colon < 1 {
					clear(output)
					return nil, false
				}
				field := classifyDeliveryStatusField(line[:colon])
				foldable = field == deliveryStatusFieldRemoteMTA ||
					field == deliveryStatusFieldDiagnosticCode
				logicalStart = len(output)
			}
			output = append(output, line...)
		}
		if relativeEnd >= 0 {
			output = append(output, '\r', '\n')
			position = lineEnd + 2
		} else {
			position = len(body)
		}
	}
	return output, true
}

// deliveryStatusFinalRecipientPath maps the raw RFC 3464 Final-Recipient
// generic-address to the canonical DKIM2 envelope path. It deliberately does
// not apply RFC 3461 xtext decoding.
func deliveryStatusFinalRecipientPath(value []byte) ([]byte, bool) {
	address, valid := parseDeliveryStatusTypedText(value, "rfc822", false)
	if !valid || !validDeliveryStatusRawAddress(address) {
		return nil, false
	}
	return canonicalDeliveryStatusRecipientPath(address)
}

// deliveryStatusOriginalRecipientPath decodes the RFC 3461 ORCPT xtext carried
// by Original-Recipient before canonical envelope comparison.
func deliveryStatusOriginalRecipientPath(value []byte) ([]byte, bool) {
	encoded, valid := parseDeliveryStatusTypedText(value, "rfc822", false)
	if !valid {
		return nil, false
	}
	decoded, valid := decodeDeliveryStatusXText(encoded)
	if !valid || !validDeliveryStatusRawAddress(decoded) {
		clear(decoded)
		return nil, false
	}
	defer clear(decoded)
	return canonicalDeliveryStatusRecipientPath(decoded)
}

func canonicalDeliveryStatusRecipientPath(address []byte) ([]byte, bool) {
	path := make([]byte, 0, len(address)+2)
	path = append(path, '<')
	path = append(path, address...)
	path = append(path, '>')
	defer clear(path)
	return signature.CanonicalEnvelopePath(path, false)
}

func parseDeliveryStatusTypedText(value []byte, requiredType string, allowEmpty bool) ([]byte, bool) {
	separator := bytes.IndexByte(value, ';')
	if separator < 1 {
		return nil, false
	}
	typeName := bytes.Trim(value[:separator], " \t")
	text := bytes.Trim(value[separator+1:], " \t")
	if len(typeName) == 0 || !allowEmpty && len(text) == 0 || !validDeliveryStatusAtom(typeName) ||
		requiredType != "" && !bytes.EqualFold(typeName, []byte(requiredType)) {
		return nil, false
	}
	for _, current := range text {
		if current == '\r' || current == '\n' || current == 0 || current == 127 || current < 32 && current != ' ' && current != '\t' {
			return nil, false
		}
	}
	return text, true
}

func validDeliveryStatusTypedText(value []byte, requiredType string, allowEmpty bool) bool {
	_, valid := parseDeliveryStatusTypedText(value, requiredType, allowEmpty)
	return valid
}

func validDeliveryStatusOptionalMessageFields(group deliveryStatusFieldGroup) bool {
	if group.has(deliveryStatusFieldOriginalEnvelopeID) && !validDeliveryStatusUnfoldedText(group.originalEnvelopeID, true) ||
		group.has(deliveryStatusFieldDSNGateway) && !validDeliveryStatusTypedText(group.dsnGateway, "", false) ||
		group.has(deliveryStatusFieldReceivedFromMTA) && !validDeliveryStatusTypedText(group.receivedFromMTA, "", false) ||
		group.has(deliveryStatusFieldArrivalDate) && !validDeliveryStatusDate(group.arrivalDate) {
		return false
	}
	return true
}

func validDeliveryStatusOptionalRecipientFields(group deliveryStatusFieldGroup) bool {
	if group.has(deliveryStatusFieldRemoteMTA) && !validDeliveryStatusTypedText(group.remoteMTA, "", false) ||
		group.has(deliveryStatusFieldDiagnosticCode) && !validDeliveryStatusTypedText(group.diagnosticCode, "", true) ||
		group.has(deliveryStatusFieldLastAttemptDate) && !validDeliveryStatusDate(group.lastAttemptDate) ||
		group.has(deliveryStatusFieldFinalLogID) && !validDeliveryStatusUnfoldedText(group.finalLogID, true) ||
		group.has(deliveryStatusFieldWillRetryUntil) &&
			(!bytes.EqualFold(group.action, []byte("delayed")) || !validDeliveryStatusDate(group.willRetryUntil)) {
		return false
	}
	return true
}

func validDeliveryStatusDate(value []byte) bool {
	normalized, valid := normalizeDeliveryStatusDateCFWS(value)
	if !valid {
		return false
	}
	defer clear(normalized)
	parts := bytes.Fields(normalized)
	weekday := -1
	if len(parts) == 6 {
		if len(parts[0]) != 4 || parts[0][3] != ',' {
			return false
		}
		weekday = deliveryStatusWeekday(parts[0][:3])
		if weekday < 0 {
			return false
		}
		parts = parts[1:]
	}
	if len(parts) != 5 {
		return false
	}
	day, valid := deliveryStatusDecimal(parts[0], 1, 2)
	month := deliveryStatusMonth(parts[1])
	year, yearValid := deliveryStatusDecimal(parts[2], 2, 4)
	hour, minute, second, timeValid := deliveryStatusClock(parts[3])
	if !valid || month == 0 || !yearValid || !timeValid ||
		!validDeliveryStatusNumericZone(parts[4]) {
		return false
	}
	if len(parts[2]) == 2 {
		year += 1900
	}
	parsed := time.Date(year, month, day, hour, minute, second, 0, time.UTC)
	if parsed.Year() != year || parsed.Month() != month || parsed.Day() != day {
		return false
	}
	return weekday < 0 || int(parsed.Weekday()) == weekday
}

// normalizeDeliveryStatusDateCFWS removes bounded RFC 822 comments and
// canonicalizes linear whitespace without accepting folded CRLF. Comment
// parsing is iterative and capped independently of the enclosing line bound.
func normalizeDeliveryStatusDateCFWS(value []byte) ([]byte, bool) {
	if len(value) == 0 || len(value) > maxDeliveryStatusLineBytes {
		return nil, false
	}
	normalized := make([]byte, 0, len(value))
	commentDepth := 0
	pendingSpace := false
	for index := 0; index < len(value); index++ {
		current := value[index]
		if current == '\r' || current == '\n' || current == 127 ||
			current < 32 && current != ' ' && current != '\t' {
			clear(normalized)
			return nil, false
		}
		if commentDepth > 0 {
			switch current {
			case '\\':
				index++
				if index >= len(value) || !validDeliveryStatusQuotedPairByte(value[index]) {
					clear(normalized)
					return nil, false
				}
			case '(':
				commentDepth++
				if commentDepth > maxDeliveryStatusCommentDepth {
					clear(normalized)
					return nil, false
				}
			case ')':
				commentDepth--
			}
			continue
		}
		switch current {
		case '(':
			commentDepth = 1
			pendingSpace = true
		case ')', '\\':
			clear(normalized)
			return nil, false
		case ' ', '\t':
			pendingSpace = true
		default:
			if pendingSpace && len(normalized) > 0 && deliveryStatusDateNeedsSpace(normalized[len(normalized)-1], current) {
				normalized = append(normalized, ' ')
			}
			normalized = append(normalized, current)
			pendingSpace = false
		}
	}
	if commentDepth != 0 || len(normalized) == 0 {
		clear(normalized)
		return nil, false
	}
	return normalized, true
}

func validDeliveryStatusQuotedPairByte(value byte) bool {
	return value == ' ' || value == '\t' || value >= 33 && value <= 126
}

func deliveryStatusDateNeedsSpace(previous, current byte) bool {
	if current == ',' || current == ':' || previous == ':' {
		return false
	}
	return true
}

func deliveryStatusWeekday(value []byte) int {
	for index, name := range []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"} {
		if bytes.EqualFold(value, []byte(name)) {
			return index
		}
	}
	return -1
}

func deliveryStatusMonth(value []byte) time.Month {
	for index, name := range []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"} {
		if bytes.EqualFold(value, []byte(name)) {
			return time.Month(index + 1)
		}
	}
	return 0
}

func deliveryStatusDecimal(value []byte, minimum, maximum int) (int, bool) {
	if len(value) < minimum || len(value) > maximum {
		return 0, false
	}
	result := 0
	for _, current := range value {
		if current < '0' || current > '9' {
			return 0, false
		}
		result = result*10 + int(current-'0')
	}
	return result, true
}

func deliveryStatusClock(value []byte) (int, int, int, bool) {
	if len(value) != 5 && len(value) != 8 || value[2] != ':' || len(value) == 8 && value[5] != ':' {
		return 0, 0, 0, false
	}
	hour, hourValid := deliveryStatusDecimal(value[:2], 2, 2)
	minute, minuteValid := deliveryStatusDecimal(value[3:5], 2, 2)
	second := 0
	secondValid := true
	if len(value) == 8 {
		second, secondValid = deliveryStatusDecimal(value[6:], 2, 2)
	}
	return hour, minute, second,
		hourValid && minuteValid && secondValid && hour < 24 && minute < 60 && second < 60
}

func validDeliveryStatusNumericZone(value []byte) bool {
	if len(value) != 5 || value[0] != '+' && value[0] != '-' {
		return false
	}
	hour, hourValid := deliveryStatusDecimal(value[1:3], 2, 2)
	minute, minuteValid := deliveryStatusDecimal(value[3:], 2, 2)
	return hourValid && minuteValid && hour < 24 && minute < 60
}

func validDeliveryStatusRawAddress(value []byte) bool {
	return validDeliveryStatusUnfoldedText(value, false)
}

// validDeliveryStatusUnfoldedText validates one bounded RFC 822 text value
// after the enclosing field parser has removed CRLF framing. SP and HTAB are
// data; all other controls and DEL fail closed.
func validDeliveryStatusUnfoldedText(value []byte, allowEmpty bool) bool {
	if len(value) == 0 {
		return allowEmpty
	}
	for _, current := range value {
		if current == 127 || current < 32 && current != ' ' && current != '\t' {
			return false
		}
	}
	return true
}

func validDeliveryStatusAction(value []byte) bool {
	for _, action := range [][]byte{
		[]byte("failed"), []byte("delayed"), []byte("delivered"),
		[]byte("relayed"), []byte("expanded"),
	} {
		if bytes.EqualFold(value, action) {
			return true
		}
	}
	return false
}

func validDeliveryStatusCode(value []byte) bool {
	if len(value) < 5 || value[1] != '.' ||
		(value[0] != '2' && value[0] != '4' && value[0] != '5') {
		return false
	}
	secondEnd := bytes.IndexByte(value[2:], '.')
	if secondEnd < 1 {
		return false
	}
	secondEnd += 2
	return validDeliveryStatusCodeComponent(value[2:secondEnd]) &&
		validDeliveryStatusCodeComponent(value[secondEnd+1:])
}

func validDeliveryStatusCodeComponent(value []byte) bool {
	if len(value) < 1 || len(value) > 3 || len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, current := range value {
		if current < '0' || current > '9' {
			return false
		}
	}
	return true
}

func validDeliveryStatusFieldName(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, current := range value {
		if current < 33 || current > 126 || current == ':' {
			return false
		}
	}
	return true
}

func validDeliveryStatusAtom(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, current := range value {
		if current < 33 || current > 126 || deliveryStatusAtomSpecial(current) {
			return false
		}
	}
	return true
}

func decodeDeliveryStatusXText(value []byte) ([]byte, bool) {
	decoded := make([]byte, 0, len(value))
	for index := 0; index < len(value); index++ {
		current := value[index]
		if current == '+' {
			if index+2 >= len(value) || !upperHexByte(value[index+1]) || !upperHexByte(value[index+2]) {
				clear(decoded)
				return nil, false
			}
			decoded = append(decoded, hexByte(value[index+1])<<4|hexByte(value[index+2]))
			index += 2
			continue
		}
		if current < 33 || current > 126 || current == '=' {
			clear(decoded)
			return nil, false
		}
		decoded = append(decoded, current)
	}
	return decoded, true
}

func deliveryStatusAtomSpecial(value byte) bool {
	switch value {
	case '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '.', '[', ']':
		return true
	default:
		return false
	}
}

func upperHexByte(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'A' && value <= 'F'
}

func hexByte(value byte) byte {
	if value <= '9' {
		return value - '0'
	}
	return value - 'A' + 10
}

func deliveryStatusPathMatches(path []byte, signed [][]byte) bool {
	for _, candidate := range signed {
		if bytes.Equal(path, candidate) {
			return true
		}
	}
	return false
}

// evidenceStatusError maps bounded verifier outcomes to a DSN evidence authorization failure.
func evidenceStatusError(status verify.TargetStatus) error {
	if status == verify.TargetStatusIndeterminate {
		return newEvidenceError(EvidenceErrorCodeVerificationIndeterminate, nil)
	}
	return newEvidenceError(EvidenceErrorCodeVerificationFailed, nil)
}

// newEvidenceError constructs a content-free evidence error around typed parser or verifier causes.
func newEvidenceError(code EvidenceErrorCode, cause error) *EvidenceError {
	return &EvidenceError{code: code, cause: cause}
}
