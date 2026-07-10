package canonical

import (
	"sort"
	"strings"

	"github.com/croessner/dkim2/internal/rawmsg"
)

const canonicalHeaderLineEnding = "\r\n"

type headerFieldRecord struct {
	nameLower      string
	originalIndex  int
	canonicalBytes []byte
}

// HeaderHashInput builds DKIM2 Section 6.2 canonical header hash input.
func (c Canonicalizer) HeaderHashInput(headers rawmsg.HeaderBlock) (ByteInput, error) {
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

// HeaderHash calculates SHA-256 over DKIM2 Section 6.2 canonical header input.
func (c Canonicalizer) HeaderHash(headers rawmsg.HeaderBlock) (Result, error) {
	canonical, err := c.HeaderHashInput(headers)
	if err != nil {
		return Result{}, err
	}

	digest, err := c.SHA256Digest(canonical)
	if err != nil {
		return Result{}, err
	}

	return NewResult(canonical, digest), nil
}

// HeaderHashFromMessage calculates SHA-256 header hash input from a raw message.
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

// countExcludedHeader records allowlisted Section 6.2 exclusions.
func countExcludedHeader(nameLower string, counts *ExcludedHeaderCounts) bool {
	switch {
	case nameLower == "received":
		counts.Received++
	case nameLower == "return-path":
		counts.ReturnPath++
	case nameLower == "delivered-to":
		counts.DeliveredTo++
	case nameLower == "authentication-results":
		counts.AuthenticationResults++
	case strings.HasPrefix(nameLower, "x-"):
		counts.XHeader++
	case nameLower == "dkim-signature":
		counts.DKIMSignature++
	case strings.HasPrefix(nameLower, "arc-"):
		counts.ARC++
	case nameLower == "message-instance":
		counts.MessageInstance++
	case nameLower == "dkim2-signature":
		counts.DKIM2Signature++
	default:
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
