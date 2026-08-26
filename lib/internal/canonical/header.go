package canonical

import (
	"sort"
	"strings"

	"github.com/croessner/dkim2/internal/rawmsg"
)

const (
	canonicalHeaderLineEnding = "\r\n"
	receivedHeaderName        = "received"
)

type headerFieldRecord struct {
	nameLower      string
	originalIndex  int
	canonicalBytes []byte
}

type excludedHeaderKind uint8

const (
	excludedHeaderNone excludedHeaderKind = iota
	excludedHeaderReceived
	excludedHeaderReturnPath
	excludedHeaderDeliveredTo
	excludedHeaderAuthenticationResults
	excludedHeaderX
	excludedHeaderDKIMSignature
	excludedHeaderExactUnsigned
	excludedHeaderARC
	excludedHeaderMessageInstance
	excludedHeaderDKIM2Signature
)

// HeaderHashInput builds DKIM2 Section 6.2 canonical header hash input.
func (c Canonicalizer) HeaderHashInput(headers rawmsg.HeaderBlock) (ByteInput, error) {
	if !headers.Initialized() {
		return ByteInput{}, newError(ErrorCodeMalformedState, ErrorLocation{Kind: KindHeaderHashInput}, ErrorDetails{Class: ErrorClassMalformed}, nil)
	}
	fields := headers.Fields()
	if len(fields) > c.options.Limits.MaxFieldCount {
		return ByteInput{}, headerLimitExceededError("max_field_count", len(fields), c.options.Limits.MaxFieldCount, 0)
	}

	records := make([]headerFieldRecord, 0, len(fields))
	excludedCounts := ExcludedHeaderCounts{}
	for _, field := range fields {
		nameLower := field.NameLower()
		if countExcludedHeader(nameLower, &excludedCounts) {
			continue
		}

		canonicalBytes := canonicalizeHeaderFieldBytes(nameLower, field.UnfoldedValue())
		if len(canonicalBytes) > c.options.Limits.MaxFieldBytes {
			return ByteInput{}, headerLimitExceededError("max_field_bytes", len(canonicalBytes), c.options.Limits.MaxFieldBytes, field.Index())
		}

		records = append(records, headerFieldRecord{
			nameLower:      nameLower,
			originalIndex:  field.Index(),
			canonicalBytes: canonicalBytes,
		})
	}

	sortHeaderFieldRecords(records)

	canonical := make([]byte, 0)
	for _, record := range records {
		if len(canonical)+len(record.canonicalBytes) > c.options.Limits.MaxHeaderInputBytes {
			return ByteInput{}, headerLimitExceededError("max_header_input_bytes", len(canonical)+len(record.canonicalBytes), c.options.Limits.MaxHeaderInputBytes, record.originalIndex)
		}
		canonical = append(canonical, record.canonicalBytes...)
	}

	return NewCanonicalBytes(KindHeaderHashInput, canonical, Metadata{
		InputBytes:           len(headers.OriginalBytes()),
		IncludedFields:       len(records),
		ExcludedFields:       excludedCounts.Total(),
		ExcludedHeaderCounts: excludedCounts,
		BodyTerminalAction:   BodyTerminalActionUnspecified,
	})
}

// HeaderHashInputFromMessage builds Section 6.2 header input from a raw message.
func (c Canonicalizer) HeaderHashInputFromMessage(message rawmsg.Message) (ByteInput, error) {
	return c.HeaderHashInput(message.Headers())
}

// HeaderHash calculates the selected Message-Instance digest over Section 6.2 input.
func (c Canonicalizer) HeaderHash(headers rawmsg.HeaderBlock) (Result, error) {
	canonical, err := c.HeaderHashInput(headers)
	if err != nil {
		return Result{}, err
	}

	digest, err := c.Digest(canonical)
	if err != nil {
		return Result{}, err
	}

	return NewResult(canonical, digest), nil
}

// HeaderHashFromMessage calculates the selected header digest from a raw message.
func (c Canonicalizer) HeaderHashFromMessage(message rawmsg.Message) (Result, error) {
	return c.HeaderHash(message.Headers())
}

// canonicalizeHeaderFieldBytes applies Section 6.2 value WSP rules to one field.
func canonicalizeHeaderFieldBytes(nameLower string, unfoldedValue []byte) []byte {
	canonicalValue := compressHeaderValueWSP(trimHeaderValueWSP(unfoldedValue))
	canonical := make([]byte, 0, len(nameLower)+1+len(canonicalValue)+len(canonicalHeaderLineEnding))
	canonical = append(canonical, nameLower...)
	canonical = append(canonical, ':')
	canonical = append(canonical, canonicalValue...)
	canonical = append(canonical, canonicalHeaderLineEnding...)

	return canonical
}

// trimHeaderValueWSP deletes WSP adjacent to the colon and field terminator.
func trimHeaderValueWSP(value []byte) []byte {
	start := 0
	for start < len(value) && isHeaderWSP(value[start]) {
		start++
	}

	end := len(value)
	for end > start && isHeaderWSP(value[end-1]) {
		end--
	}

	return value[start:end]
}

// compressHeaderValueWSP compresses every Section 6.2 value WSP run to one SP.
func compressHeaderValueWSP(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}

	compressed := make([]byte, 0, len(value))
	inWSP := false
	for _, b := range value {
		if isHeaderWSP(b) {
			if !inWSP {
				compressed = append(compressed, ' ')
				inWSP = true
			}
			continue
		}

		compressed = append(compressed, b)
		inWSP = false
	}

	return compressed
}

// isHeaderWSP reports whether b is RFC 5322 WSP for header hash input.
func isHeaderWSP(b byte) bool {
	return b == ' ' || b == '\t'
}

// excludedHeaderKindForName classifies the authoritative Section 4 and Section 6.2 exclusion set.
func excludedHeaderKindForName(nameLower string) excludedHeaderKind {
	switch {
	case nameLower == receivedHeaderName || strings.HasPrefix(nameLower, receivedHeaderName+"-"):
		return excludedHeaderReceived
	case nameLower == "return-path":
		return excludedHeaderReturnPath
	case nameLower == "delivered-to":
		return excludedHeaderDeliveredTo
	case nameLower == "authentication-results":
		return excludedHeaderAuthenticationResults
	case strings.HasPrefix(nameLower, "x-"):
		return excludedHeaderX
	case nameLower == "dkim-signature":
		return excludedHeaderDKIMSignature
	case exactUnsignedHeaderName(nameLower):
		return excludedHeaderExactUnsigned
	case nameLower == "arc-authentication-results" || nameLower == "arc-message-signature" || nameLower == "arc-seal":
		return excludedHeaderARC
	case nameLower == "message-instance":
		return excludedHeaderMessageInstance
	case nameLower == "dkim2-signature":
		return excludedHeaderDKIM2Signature
	default:
		return excludedHeaderNone
	}
}

// exactUnsignedHeaderName reports the Draft-05 exact registered-field exclusions.
func exactUnsignedHeaderName(nameLower string) bool {
	switch nameLower {
	case "apparently-to", "auto-submitted", "dl-expansion-history", "original-recipient",
		"sio-label-history", "vbr-info", "x400-received", "x400-trace":
		return true
	default:
		return false
	}
}

// countExcludedHeader records allowlisted Section 6.2 exclusions.
func countExcludedHeader(nameLower string, counts *ExcludedHeaderCounts) bool {
	switch excludedHeaderKindForName(nameLower) {
	case excludedHeaderReceived:
		counts.Received++
	case excludedHeaderReturnPath:
		counts.ReturnPath++
	case excludedHeaderDeliveredTo:
		counts.DeliveredTo++
	case excludedHeaderAuthenticationResults:
		counts.AuthenticationResults++
	case excludedHeaderX:
		counts.XHeader++
	case excludedHeaderDKIMSignature:
		counts.DKIMSignature++
	case excludedHeaderExactUnsigned:
		counts.ExactUnsigned++
	case excludedHeaderARC:
		counts.ARC++
	case excludedHeaderMessageInstance:
		counts.MessageInstance++
	case excludedHeaderDKIM2Signature:
		counts.DKIM2Signature++
	case excludedHeaderNone:
		return false
	}

	return true
}

// sortHeaderFieldRecords orders fields by name and reverse duplicate occurrence.
func sortHeaderFieldRecords(records []headerFieldRecord) {
	sort.SliceStable(records, func(i int, j int) bool {
		if records[i].nameLower != records[j].nameLower {
			return records[i].nameLower < records[j].nameLower
		}

		return records[i].originalIndex > records[j].originalIndex
	})
}

// headerLimitExceededError reports header canonicalization limits safely.
func headerLimitExceededError(limitName string, count int, limit int, fieldIndex int) *Error {
	return newError(ErrorCodeLimitExceeded, ErrorLocation{Kind: KindHeaderHashInput, FieldIndex: fieldIndex}, ErrorDetails{
		Class:     ErrorClassLimit,
		LimitName: limitName,
		Limit:     limit,
		Count:     count,
	}, nil)
}
