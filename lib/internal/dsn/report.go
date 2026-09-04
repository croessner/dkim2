package dsn

import "bytes"

// deliveryStatusRecipient stores the bounded facts of one validated RFC 3464
// per-recipient group. Paths are canonical DKIM2 envelope paths; the raw
// Original-Recipient value is retained only for verbatim propagation.
type deliveryStatusRecipient struct {
	index             int
	finalPath         []byte
	originalPath      []byte
	hasOriginal       bool
	originalRecipient []byte
	action            []byte
	status            []byte
}

// links reports whether the group names one of the authenticated rt= paths
// through its raw Final-Recipient or its xtext-decoded Original-Recipient.
func (g deliveryStatusRecipient) links(signed [][]byte) bool {
	if deliveryStatusPathMatches(g.finalPath, signed) {
		return true
	}
	return g.hasOriginal && deliveryStatusPathMatches(g.originalPath, signed)
}

// failed reports whether the group carries Action: failed.
func (g deliveryStatusRecipient) failed() bool {
	return bytes.EqualFold(g.action, []byte("failed"))
}

// clear zeroes every retained byte slice.
func (g *deliveryStatusRecipient) clear() {
	clear(g.finalPath)
	clear(g.originalPath)
	clear(g.originalRecipient)
	clear(g.action)
	clear(g.status)
}

// deliveryStatusReport stores one validated RFC 3464 body as bounded facts.
type deliveryStatusReport struct {
	envelopeID    []byte
	hasEnvelopeID bool
	recipients    []deliveryStatusRecipient
}

// linksAny reports whether at least one recipient group names an authenticated rt= path.
func (r deliveryStatusReport) linksAny(signed [][]byte) bool {
	for _, recipient := range r.recipients {
		if recipient.links(signed) {
			return true
		}
	}
	return false
}

// linked returns the recipient groups that name an authenticated rt= path in report order.
func (r deliveryStatusReport) linked(signed [][]byte) []deliveryStatusRecipient {
	var linked []deliveryStatusRecipient
	for _, recipient := range r.recipients {
		if recipient.links(signed) {
			linked = append(linked, recipient)
		}
	}
	return linked
}

// clear zeroes every retained byte slice.
func (r *deliveryStatusReport) clear() {
	clear(r.envelopeID)
	for index := range r.recipients {
		r.recipients[index].clear()
	}
}

// parseDeliveryStatusBody validates one bounded RFC 3464 body under the
// selected strict profile and returns its per-message and per-recipient
// facts. Folding fails closed in the generic profile. It reports false for
// every structural, ordering, cardinality, syntax, or limit violation.
func parseDeliveryStatusBody(body []byte, postfixBounceOrder bool) (deliveryStatusReport, bool) {
	if len(body) == 0 || len(body) > maxDeliveryStatusBytes {
		return deliveryStatusReport{}, false
	}
	if postfixBounceOrder {
		unfolded, valid := unfoldPostfixDeliveryStatus(body)
		if !valid {
			return deliveryStatusReport{}, false
		}
		defer clear(unfolded)
		body = unfolded
	}
	report := deliveryStatusReport{}
	group := deliveryStatusFieldGroup{}
	groupIndex := 0
	totalFields := 0
	position := 0
	for position < len(body) {
		relativeEnd := bytes.Index(body[position:], []byte("\r\n"))
		lineEnd := len(body)
		if relativeEnd >= 0 {
			lineEnd = position + relativeEnd
		}
		line := body[position:lineEnd]
		if len(line) > maxDeliveryStatusLineBytes || bytes.ContainsAny(line, "\r\n") {
			report.clear()
			return deliveryStatusReport{}, false
		}
		if relativeEnd < 0 {
			position = len(body)
		} else {
			position = lineEnd + 2
		}
		if len(line) == 0 {
			if !report.finishGroup(groupIndex, group, postfixBounceOrder) {
				report.clear()
				return deliveryStatusReport{}, false
			}
			groupIndex++
			group = deliveryStatusFieldGroup{}
			continue
		}
		if line[0] == ' ' || line[0] == '\t' || !group.add(groupIndex, line, postfixBounceOrder) {
			report.clear()
			return deliveryStatusReport{}, false
		}
		totalFields++
		if group.fieldCount > maxDeliveryStatusFieldsPerGroup || totalFields > maxDeliveryStatusTotalFields {
			report.clear()
			return deliveryStatusReport{}, false
		}
	}
	if group.fieldCount > 0 {
		if !report.finishGroup(groupIndex, group, postfixBounceOrder) {
			report.clear()
			return deliveryStatusReport{}, false
		}
		groupIndex++
	}
	if groupIndex < 2 || groupIndex-1 > maxDeliveryStatusRecipientGroups {
		report.clear()
		return deliveryStatusReport{}, false
	}
	return report, true
}

// finishGroup validates one completed field group and records its bounded facts.
func (r *deliveryStatusReport) finishGroup(index int, group deliveryStatusFieldGroup, postfixBounceOrder bool) bool {
	if group.fieldCount == 0 {
		return false
	}
	if index == 0 {
		if !group.mandatoryFieldsSeen(index) || !validDeliveryStatusOptionalMessageFields(group) ||
			postfixBounceOrder && len(group.postfixQueueID) == 0 ||
			!validDeliveryStatusTypedText(group.reportingMTA, "", false) {
			return false
		}
		if group.has(deliveryStatusFieldOriginalEnvelopeID) {
			r.envelopeID = bytes.Clone(group.originalEnvelopeID)
			r.hasEnvelopeID = true
		}
		return true
	}
	if index > maxDeliveryStatusRecipientGroups || !group.mandatoryFieldsSeen(index) ||
		!validDeliveryStatusAction(group.action) || !validDeliveryStatusCode(group.status) ||
		!validDeliveryStatusOptionalRecipientFields(group) ||
		postfixBounceOrder && !group.has(deliveryStatusFieldDiagnosticCode) {
		return false
	}
	finalPath, valid := deliveryStatusFinalRecipientPath(group.finalRecipient)
	if !valid {
		return false
	}
	recipient := deliveryStatusRecipient{
		index: index, finalPath: finalPath, action: bytes.Clone(group.action), status: bytes.Clone(group.status),
	}
	if group.has(deliveryStatusFieldOriginalRecipient) {
		originalPath, originalValid := deliveryStatusOriginalRecipientPath(group.originalRecipient)
		if !originalValid {
			recipient.clear()
			return false
		}
		recipient.originalPath = originalPath
		recipient.hasOriginal = true
		recipient.originalRecipient = bytes.Clone(group.originalRecipient)
	}
	r.recipients = append(r.recipients, recipient)
	return true
}
