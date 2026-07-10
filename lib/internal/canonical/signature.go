package canonical

import (
	"bytes"
	"sort"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
	"github.com/croessner/dkim2/internal/tagvalue"
)

const targetNameSignatureSet = "signature_set"

var knownSignatureInputTags = tagvalue.MustKnownTags("i", "m", "t", "mf", "rt", "nd", "d", "s", "n", "f")

// SignatureInputSelection identifies the immutable header source and target for Section 9.6 input.
type SignatureInputSelection struct {
	// Headers is the sole authority for protocol field parsing and rendering.
	Headers rawmsg.HeaderBlock
	// TargetSequence selects the DKIM2-Signature i= value rendered incomplete.
	TargetSequence uint64
}

type signatureInputRecord struct {
	number         uint64
	headerIndex    int
	canonicalBytes []byte
}

// SignatureInput builds DKIM2 Section 9.6 canonical signature input.
func (c Canonicalizer) SignatureInput(selection SignatureInputSelection) (ByteInput, error) {
	protocolFieldCount := len(selection.Headers.FieldsByName(instance.HeaderName)) + len(selection.Headers.FieldsByName(signature.HeaderName))
	if protocolFieldCount > c.options.Limits.MaxFieldCount {
		return ByteInput{}, signatureLimitExceededError("max_field_count", protocolFieldCount, c.options.Limits.MaxFieldCount, 0)
	}

	instances, signatures, err := extractSignatureInputState(selection.Headers)
	if err != nil {
		return ByteInput{}, err
	}

	target, err := selectSignatureTarget(signatures, selection.TargetSequence)
	if err != nil {
		return ByteInput{}, err
	}

	instanceRecords, err := c.signatureInputInstanceRecords(selection.Headers, instances, target.InstanceNumber())
	if err != nil {
		return ByteInput{}, err
	}
	signatureRecords, err := c.signatureInputCompleteSignatureRecords(selection.Headers, signatures, target.Sequence())
	if err != nil {
		return ByteInput{}, err
	}
	targetRecord, err := c.signatureInputTargetRecord(selection.Headers, target)
	if err != nil {
		return ByteInput{}, err
	}

	includedFields := len(instanceRecords) + len(signatureRecords) + 1
	if includedFields > c.options.Limits.MaxFieldCount {
		return ByteInput{}, signatureLimitExceededError("max_field_count", includedFields, c.options.Limits.MaxFieldCount, target.HeaderIndex())
	}

	canonical := make([]byte, 0)
	for _, record := range instanceRecords {
		canonical, err = appendSignatureInputField(canonical, record, c.options.Limits.MaxSignatureInputBytes)
		if err != nil {
			return ByteInput{}, err
		}
	}
	for _, record := range signatureRecords {
		canonical, err = appendSignatureInputField(canonical, record, c.options.Limits.MaxSignatureInputBytes)
		if err != nil {
			return ByteInput{}, err
		}
	}
	canonical, err = appendSignatureInputField(canonical, targetRecord, c.options.Limits.MaxSignatureInputBytes)
	if err != nil {
		return ByteInput{}, err
	}

	return NewCanonicalBytes(KindSignatureInput, canonical, Metadata{
		InputBytes:     protocolFieldInputBytes(selection.Headers, instanceRecords, signatureRecords, targetRecord),
		IncludedFields: includedFields,
		ExcludedFields: len(instances) + len(signatures) - includedFields,
	})
}

// SignatureInputFromMessage builds Section 9.6 input from parser-owned headers.
func (c Canonicalizer) SignatureInputFromMessage(message rawmsg.Message, targetSequence uint64) (ByteInput, error) {
	return c.SignatureInput(SignatureInputSelection{
		Headers:        message.Headers(),
		TargetSequence: targetSequence,
	})
}

// extractSignatureInputState parses and validates protocol fields from one authoritative header block.
func extractSignatureInputState(headers rawmsg.HeaderBlock) ([]instance.MessageInstance, []signature.Signature, error) {
	instanceFields := headers.FieldsByName(instance.HeaderName)
	instances := make([]instance.MessageInstance, 0, len(instanceFields))
	for _, field := range instanceFields {
		parsed, err := instance.Parse(field)
		if err != nil {
			return nil, nil, err
		}
		instances = append(instances, parsed)
	}
	if err := instance.ValidateSequence(instances); err != nil {
		return nil, nil, err
	}

	signatureFields := headers.FieldsByName(signature.HeaderName)
	signatures := make([]signature.Signature, 0, len(signatureFields))
	for _, field := range signatureFields {
		parsed, err := signature.Parse(field)
		if err != nil {
			return nil, nil, err
		}
		signatures = append(signatures, parsed)
	}
	if err := signature.ValidateSequence(signatures); err != nil {
		return nil, nil, err
	}
	if err := signature.ValidateInstanceReferences(instances, signatures); err != nil {
		return nil, nil, err
	}

	return instances, signatures, nil
}

// signatureInputInstanceRecords selects Message-Instance fields covered by target m=.
func (c Canonicalizer) signatureInputInstanceRecords(headers rawmsg.HeaderBlock, instances []instance.MessageInstance, targetInstance uint64) ([]signatureInputRecord, error) {
	if targetInstance == 0 {
		return nil, signatureMissingTargetError("message_instance", targetInstance)
	}
	if targetInstance > uint64(len(instances)) {
		return nil, signatureMissingTargetError("message_instance", targetInstance)
	}

	byNumber := make(map[uint64]instance.MessageInstance, len(instances))
	for _, parsed := range instances {
		number := parsed.Number()
		if _, exists := byNumber[number]; exists {
			return nil, signatureDuplicateTargetError("message_instance", number, parsed.HeaderIndex())
		}
		byNumber[number] = parsed
	}

	records := make([]signatureInputRecord, 0, targetInstance)
	for expected := uint64(1); expected <= targetInstance; expected++ {
		parsed, ok := byNumber[expected]
		if !ok {
			return nil, signatureMissingTargetError("message_instance", expected)
		}
		field, err := signatureInputFieldByIndex(headers, parsed.HeaderIndex(), instance.HeaderName)
		if err != nil {
			return nil, err
		}
		reparsed, parseErr := instance.Parse(field)
		if parseErr != nil || reparsed.Number() != parsed.Number() {
			return nil, signatureAmbiguousSelectionError("message_instance", parsed.Number(), parsed.HeaderIndex(), parseErr)
		}

		canonicalBytes, err := c.canonicalizeSignatureInputField(field)
		if err != nil {
			return nil, err
		}
		records = append(records, signatureInputRecord{
			number:         parsed.Number(),
			headerIndex:    parsed.HeaderIndex(),
			canonicalBytes: canonicalBytes,
		})
	}

	sortSignatureInputRecords(records)

	return records, nil
}

// signatureInputCompleteSignatureRecords selects complete DKIM2-Signature fields before target.
func (c Canonicalizer) signatureInputCompleteSignatureRecords(headers rawmsg.HeaderBlock, signatures []signature.Signature, targetSequence uint64) ([]signatureInputRecord, error) {
	if targetSequence > uint64(len(signatures)) {
		return nil, signatureMissingTargetError("dkim2_signature", targetSequence)
	}

	bySequence := make(map[uint64]signature.Signature, len(signatures))
	for _, parsed := range signatures {
		sequence := parsed.Sequence()
		if _, exists := bySequence[sequence]; exists {
			return nil, signatureDuplicateTargetError("dkim2_signature", sequence, parsed.HeaderIndex())
		}
		bySequence[sequence] = parsed
	}

	records := make([]signatureInputRecord, 0)
	for expected := uint64(1); expected < targetSequence; expected++ {
		parsed, ok := bySequence[expected]
		if !ok {
			return nil, signatureMissingTargetError("dkim2_signature", expected)
		}
		field, err := signatureInputFieldByIndex(headers, parsed.HeaderIndex(), signature.HeaderName)
		if err != nil {
			return nil, err
		}
		reparsed, parseErr := signature.Parse(field)
		if parseErr != nil || reparsed.Sequence() != parsed.Sequence() {
			return nil, signatureAmbiguousSelectionError("dkim2_signature", parsed.Sequence(), parsed.HeaderIndex(), parseErr)
		}

		canonicalBytes, err := c.canonicalizeSignatureInputField(field)
		if err != nil {
			return nil, err
		}
		records = append(records, signatureInputRecord{
			number:         parsed.Sequence(),
			headerIndex:    parsed.HeaderIndex(),
			canonicalBytes: canonicalBytes,
		})
	}

	sortSignatureInputRecords(records)

	return records, nil
}

// signatureInputTargetRecord renders the selected DKIM2-Signature with null s= values.
func (c Canonicalizer) signatureInputTargetRecord(headers rawmsg.HeaderBlock, target signature.Signature) (signatureInputRecord, error) {
	field, err := signatureInputFieldByIndex(headers, target.HeaderIndex(), signature.HeaderName)
	if err != nil {
		return signatureInputRecord{}, err
	}
	reparsed, parseErr := signature.Parse(field)
	if parseErr != nil || reparsed.Sequence() != target.Sequence() {
		return signatureInputRecord{}, signatureAmbiguousSelectionError("dkim2_signature", target.Sequence(), target.HeaderIndex(), parseErr)
	}

	incompleteValue, err := renderIncompleteSignatureValue(field.UnfoldedValue(), target)
	if err != nil {
		return signatureInputRecord{}, err
	}
	canonicalBytes := canonicalizeSignatureInputFieldBytes(signature.HeaderName, incompleteValue)
	if len(canonicalBytes) > c.options.Limits.MaxFieldBytes {
		return signatureInputRecord{}, signatureLimitExceededError("max_field_bytes", len(canonicalBytes), c.options.Limits.MaxFieldBytes, target.HeaderIndex())
	}

	return signatureInputRecord{
		number:         target.Sequence(),
		headerIndex:    target.HeaderIndex(),
		canonicalBytes: canonicalBytes,
	}, nil
}

// canonicalizeSignatureInputField applies Section 9.6 to one complete field.
func (c Canonicalizer) canonicalizeSignatureInputField(field rawmsg.HeaderField) ([]byte, error) {
	canonicalBytes := canonicalizeSignatureInputFieldBytes(field.NameLower(), field.UnfoldedValue())
	if len(canonicalBytes) > c.options.Limits.MaxFieldBytes {
		return nil, signatureLimitExceededError("max_field_bytes", len(canonicalBytes), c.options.Limits.MaxFieldBytes, field.Index())
	}

	return canonicalBytes, nil
}

// canonicalizeSignatureInputFieldBytes deletes all WSP while retaining colon and CRLF.
func canonicalizeSignatureInputFieldBytes(nameLower string, unfoldedValue []byte) []byte {
	canonical := make([]byte, 0, len(nameLower)+1+len(unfoldedValue)+len(canonicalHeaderLineEnding))
	canonical = append(canonical, nameLower...)
	canonical = append(canonical, ':')
	canonical = appendSignatureInputValueWithoutWSP(canonical, unfoldedValue)
	canonical = append(canonical, canonicalHeaderLineEnding...)

	return canonical
}

// appendSignatureInputValueWithoutWSP appends value bytes with all WSP removed.
func appendSignatureInputValueWithoutWSP(output []byte, value []byte) []byte {
	for _, b := range value {
		if isSignatureInputWSP(b) {
			continue
		}
		output = append(output, b)
	}

	return output
}

// renderIncompleteSignatureValue renders target tags with null signature strings.
func renderIncompleteSignatureValue(unfoldedValue []byte, target signature.Signature) ([]byte, error) {
	tagField, err := tagvalue.ScanTerminated(unfoldedValue, knownSignatureInputTags, tagvalue.DefaultLimits())
	if err != nil {
		return nil, signatureAmbiguousSelectionError("dkim2_signature", target.Sequence(), target.HeaderIndex(), err)
	}

	tags := tagField.Tags()
	if len(tags) == 0 {
		return nil, signatureAmbiguousSelectionError("dkim2_signature", target.Sequence(), target.HeaderIndex(), nil)
	}

	var rendered bytes.Buffer
	sawSignatureTag := false
	for _, tag := range tags {
		rendered.WriteString(tag.RawName())
		rendered.WriteByte('=')
		if tag.Name() != "s" {
			rendered.WriteString(tag.Value())
			rendered.WriteByte(';')
			continue
		}

		sawSignatureTag = true
		nullValue, renderErr := renderNullSignatureSets(tag.Value(), len(target.SignatureSets()))
		if renderErr != nil {
			return nil, signatureAmbiguousSelectionError("dkim2_signature", target.Sequence(), target.HeaderIndex(), renderErr)
		}
		rendered.Write(nullValue)
		rendered.WriteByte(';')
	}
	if !sawSignatureTag {
		return nil, signatureAmbiguousSelectionError("dkim2_signature", target.Sequence(), target.HeaderIndex(), nil)
	}

	return rendered.Bytes(), nil
}

// renderNullSignatureSets keeps selector and algorithm components and blanks signatures.
func renderNullSignatureSets(value string, expectedCount int) ([]byte, error) {
	parts := bytes.Split([]byte(value), []byte{','})
	if len(parts) != expectedCount {
		return nil, newError(ErrorCodeMalformedState, ErrorLocation{Kind: KindSignatureInput}, ErrorDetails{
			Class:      ErrorClassMalformed,
			TargetName: targetNameSignatureSet,
			Count:      len(parts),
			Limit:      expectedCount,
		}, nil)
	}

	rendered := make([]byte, 0, len(value))
	for i, part := range parts {
		components := bytes.Split(part, []byte{':'})
		if len(components) != 3 {
			return nil, newError(ErrorCodeMalformedState, ErrorLocation{Kind: KindSignatureInput}, ErrorDetails{
				Class:      ErrorClassMalformed,
				TargetName: targetNameSignatureSet,
				Count:      len(components),
				Limit:      3,
			}, nil)
		}

		selector := trimSignatureInputWSP(components[0])
		algorithm := trimSignatureInputWSP(components[1])
		if len(selector) == 0 || len(algorithm) == 0 {
			return nil, newError(ErrorCodeMalformedState, ErrorLocation{Kind: KindSignatureInput}, ErrorDetails{
				Class:      ErrorClassMalformed,
				TargetName: targetNameSignatureSet,
			}, nil)
		}

		if i > 0 {
			rendered = append(rendered, ',')
		}
		rendered = append(rendered, selector...)
		rendered = append(rendered, ':')
		rendered = append(rendered, algorithm...)
		rendered = append(rendered, ':')
	}

	return rendered, nil
}

// selectSignatureTarget finds exactly one DKIM2-Signature with the target i=.
func selectSignatureTarget(signatures []signature.Signature, targetSequence uint64) (signature.Signature, error) {
	if targetSequence == 0 {
		return signature.Signature{}, signatureMissingTargetError("dkim2_signature", targetSequence)
	}

	var target signature.Signature
	foundTarget := false
	seen := make(map[uint64]int, len(signatures))
	for _, parsed := range signatures {
		sequence := parsed.Sequence()
		if firstIndex, exists := seen[sequence]; exists {
			return signature.Signature{}, signatureDuplicateTargetError("dkim2_signature", sequence, firstIndex)
		}
		seen[sequence] = parsed.HeaderIndex()
		if sequence != targetSequence {
			continue
		}
		target = parsed
		foundTarget = true
	}
	if !foundTarget {
		return signature.Signature{}, signatureMissingTargetError("dkim2_signature", targetSequence)
	}

	return target, nil
}

// signatureInputFieldByIndex returns the expected raw header occurrence.
func signatureInputFieldByIndex(headers rawmsg.HeaderBlock, index int, nameLower string) (rawmsg.HeaderField, error) {
	field, ok := headers.Field(index)
	if !ok {
		return rawmsg.HeaderField{}, signatureAmbiguousSelectionError(nameLower, 0, index, nil)
	}
	if field.NameLower() != nameLower {
		return rawmsg.HeaderField{}, signatureAmbiguousSelectionError(nameLower, 0, index, nil)
	}

	return field, nil
}

// appendSignatureInputField appends one field and enforces total input size.
func appendSignatureInputField(output []byte, record signatureInputRecord, limit int) ([]byte, error) {
	if len(output)+len(record.canonicalBytes) > limit {
		return nil, signatureLimitExceededError("max_signature_input_bytes", len(output)+len(record.canonicalBytes), limit, record.headerIndex)
	}

	return append(output, record.canonicalBytes...), nil
}

// protocolFieldInputBytes counts raw protocol field bytes selected for metadata.
func protocolFieldInputBytes(headers rawmsg.HeaderBlock, instances []signatureInputRecord, signatures []signatureInputRecord, target signatureInputRecord) int {
	total := 0
	for _, record := range instances {
		total += rawProtocolFieldLen(headers, record.headerIndex)
	}
	for _, record := range signatures {
		total += rawProtocolFieldLen(headers, record.headerIndex)
	}
	total += rawProtocolFieldLen(headers, target.headerIndex)

	return total
}

// rawProtocolFieldLen returns one raw field length without exposing bytes.
func rawProtocolFieldLen(headers rawmsg.HeaderBlock, fieldIndex int) int {
	field, ok := headers.Field(fieldIndex)
	if !ok {
		return 0
	}

	return len(field.OriginalBytes())
}

// sortSignatureInputRecords orders selected fields by parsed m= or i= value.
func sortSignatureInputRecords(records []signatureInputRecord) {
	sort.SliceStable(records, func(i int, j int) bool {
		return records[i].number < records[j].number
	})
}

// trimSignatureInputWSP removes surrounding WSP before null s= rendering.
func trimSignatureInputWSP(input []byte) []byte {
	start := 0
	for start < len(input) && isSignatureInputWSP(input[start]) {
		start++
	}

	end := len(input)
	for end > start && isSignatureInputWSP(input[end-1]) {
		end--
	}

	return input[start:end]
}

// isSignatureInputWSP reports whether b is WSP deleted by Section 9.6.
func isSignatureInputWSP(b byte) bool {
	return b == ' ' || b == '\t'
}

// signatureLimitExceededError reports signature input size violations safely.
func signatureLimitExceededError(limitName string, count int, limit int, fieldIndex int) *Error {
	return newError(ErrorCodeLimitExceeded, ErrorLocation{Kind: KindSignatureInput, FieldIndex: fieldIndex}, ErrorDetails{
		Class:     ErrorClassLimit,
		LimitName: limitName,
		Limit:     limit,
		Count:     count,
	}, nil)
}

// signatureMissingTargetError reports absent target fields without raw data.
func signatureMissingTargetError(targetName string, targetNumber uint64) *Error {
	return newError(ErrorCodeMissingTarget, ErrorLocation{Kind: KindSignatureInput, TargetNumber: targetNumber}, ErrorDetails{
		Class:      ErrorClassMissing,
		TargetName: targetName,
	}, nil)
}

// signatureDuplicateTargetError reports repeated target identifiers safely.
func signatureDuplicateTargetError(targetName string, targetNumber uint64, fieldIndex int) *Error {
	return newError(ErrorCodeDuplicateTarget, ErrorLocation{Kind: KindSignatureInput, FieldIndex: fieldIndex, TargetNumber: targetNumber}, ErrorDetails{
		Class:      ErrorClassDuplicate,
		TargetName: targetName,
		Count:      2,
	}, nil)
}

// signatureAmbiguousSelectionError reports mismatched parsed and raw field state.
func signatureAmbiguousSelectionError(targetName string, targetNumber uint64, fieldIndex int, cause error) *Error {
	return newError(ErrorCodeAmbiguousSelection, ErrorLocation{Kind: KindSignatureInput, FieldIndex: fieldIndex, TargetNumber: targetNumber}, ErrorDetails{
		Class:      ErrorClassAmbiguous,
		TargetName: targetName,
	}, cause)
}
