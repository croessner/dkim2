package recipe

import (
	"strconv"
	"unicode/utf8"
)

const jsonIntegerBufferBytes = 32

// generationSerializationPlan combines validated header and body plans for internal serialization.
type generationSerializationPlan struct {
	headers     headerPlanningResult
	body        bodyPlanningResult
	bodyOutcome BodyGenerationOutcome
	unavailable BodyUnavailableReason
	initialized bool
}

// Valid reports only closed top-level state without rescanning protected plan data.
func (p generationSerializationPlan) Valid() bool {
	if !p.initialized || !p.headers.initialized || !p.body.initialized || !p.bodyOutcome.Known() || p.body.outcome != p.bodyOutcome {
		return false
	}
	switch p.bodyOutcome {
	case BodyGenerationUnchanged:
		return !p.unavailable.Known() && !p.body.unavailable.Known() && len(p.body.steps) == 0 && len(p.headers.plans) > 0
	case BodyGenerationGenerated:
		return !p.unavailable.Known() && !p.body.unavailable.Known()
	case BodyGenerationUnavailable:
		return p.unavailable.Known() && p.body.unavailable == p.unavailable && len(p.body.steps) == 0
	default:
		return false
	}
}

// newGenerationSerializationPlan moves internal dimension plans without cloning protected data.
func newGenerationSerializationPlan(headers headerPlanningResult, body bodyPlanningResult) (generationSerializationPlan, error) {
	if !headers.initialized || !body.initialized || !body.outcome.Known() || len(headers.plans) == 0 && body.outcome == BodyGenerationUnchanged {
		return generationSerializationPlan{}, generationInvariantErrorForDimension(DimensionRecipe)
	}
	plan := generationSerializationPlan{
		headers: headers, body: body, bodyOutcome: body.outcome, unavailable: body.unavailable, initialized: true,
	}
	if !plan.Valid() {
		return generationSerializationPlan{}, generationInvariantErrorForDimension(DimensionRecipe)
	}
	return plan, nil
}

// serializedGenerationPlan stores unexposed decoded JSON awaiting complete self-proof.
type serializedGenerationPlan struct {
	bodyOutcome     BodyGenerationOutcome
	unavailable     BodyUnavailableReason
	decodedJSON     []byte
	classifications []headerClassification
	classified      bool
	validated       bool
	initialized     bool
}

// Valid reports closed metadata without rescanning or cloning protected JSON.
func (r serializedGenerationPlan) Valid() bool {
	if !r.initialized || !r.validated || len(r.decodedJSON) == 0 || !r.bodyOutcome.Known() {
		return false
	}
	if !r.classified && len(r.classifications) != 0 {
		return false
	}
	if r.bodyOutcome == BodyGenerationUnavailable {
		return r.unavailable.Known()
	}
	return !r.unavailable.Known()
}

// serializationPreflight owns strict structural and semantic output accounting.
type serializationPreflight struct {
	limits                       Limits
	counter                      *generationCounter
	depth, maxDepth              int
	tokens, members              int
	headerNames, headerNameBytes int
	totalSteps, copyRanges       int
	totalCopiedItems             int
	dataStrings, literalBytes    int
	workUnits                    int
	sealedSize                   int
	sealed                       bool
}

// newSerializationPreflight binds one normalized limit set and generation counter.
func newSerializationPreflight(limits Limits, counter *generationCounter) *serializationPreflight {
	return &serializationPreflight{limits: limits, counter: counter}
}

// chargeWork accounts serializer-local and operation-wide work before action.
func (p *serializationPreflight) chargeWork(count int) error {
	if p == nil || p.counter == nil || count < 0 {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	work, ok := checkedAdd(p.workUnits, count)
	if !ok || work > p.limits.MaxOperationWorkUnits {
		return generationLimitError(limitNameMaxOperationWorkUnits, p.limits.MaxOperationWorkUnits, work, DimensionRecipe)
	}
	if err := p.counter.chargeWork(count, DimensionRecipe); err != nil {
		return err
	}
	p.workUnits = work
	return nil
}

// chargeToken enforces the exact parser-visible token ceiling.
func (p *serializationPreflight) chargeToken() error {
	tokens, ok := checkedAdd(p.tokens, 1)
	if !ok || tokens > p.limits.MaxJSONTokens {
		return generationLimitError(limitNameMaxJSONTokens, p.limits.MaxJSONTokens, tokens, DimensionRecipe)
	}
	if err := p.chargeWork(1); err != nil {
		return err
	}
	p.tokens = tokens
	return nil
}

// chargeMember enforces the exact parser-visible object-member ceiling.
func (p *serializationPreflight) chargeMember() error {
	members, ok := checkedAdd(p.members, 1)
	if !ok || members > p.limits.MaxJSONMembers {
		return generationLimitError(limitNameMaxJSONMembers, p.limits.MaxJSONMembers, members, DimensionRecipe)
	}
	if err := p.chargeWork(1); err != nil {
		return err
	}
	p.members = members
	return nil
}

// enterContainer enforces the exact serializer nesting ceiling.
func (p *serializationPreflight) enterContainer() error {
	depth, ok := checkedAdd(p.depth, 1)
	if !ok || depth > p.limits.MaxJSONDepth {
		return generationLimitError(limitNameMaxJSONDepth, p.limits.MaxJSONDepth, depth, DimensionRecipe)
	}
	p.depth = depth
	if depth > p.maxDepth {
		p.maxDepth = depth
	}
	return nil
}

// leaveContainer closes one validated serializer nesting level.
func (p *serializationPreflight) leaveContainer() error {
	if p == nil || p.depth <= 0 {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	p.depth--
	return nil
}

// seal records that all validation, sizing, and writer work passed before allocation.
func (p *serializationPreflight) seal(size int) error {
	if p == nil || p.counter == nil || p.sealed || p.depth != 0 || size <= 0 || size > p.limits.MaxDecodedRecipeBytes {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	p.sealedSize, p.sealed = size, true
	return nil
}

// validatePlan enforces inherited recipe semantic limits before output allocation.
func (p *serializationPreflight) validatePlan(plan generationSerializationPlan) error {
	if p == nil || !plan.Valid() {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	previousName := ""
	for _, header := range plan.headers.plans {
		if previousName != "" {
			comparisonWork, ok := checkedSum(len(previousName), len(header.canonicalName), 1)
			if !ok {
				return generationLimitError(limitNameMaxOperationWorkUnits, p.limits.MaxOperationWorkUnits, comparisonWork, DimensionHeader)
			}
			if err := p.chargeWork(comparisonWork); err != nil {
				return err
			}
			if header.canonicalName <= previousName {
				return generationInvariantErrorForDimension(DimensionHeader)
			}
		}
		if err := p.validateHeader(header); err != nil {
			return err
		}
		previousName = header.canonicalName
	}
	if plan.bodyOutcome == BodyGenerationGenerated {
		if err := p.validateSteps(plan.body.steps, DimensionBody, p.limits.MaxBodySteps, limitNameMaxBodySteps, ""); err != nil {
			return err
		}
	}
	return nil
}

// validateHeader enforces sorted lowercase header-key and per-plan limits.
func (p *serializationPreflight) validateHeader(plan headerPlan) error {
	scanWork, ok := checkedMultiply(len(plan.name), 2)
	if ok {
		scanWork, ok = checkedAdd(scanWork, 2)
	}
	if !ok {
		return generationLimitError(limitNameMaxOperationWorkUnits, p.limits.MaxOperationWorkUnits, scanWork, DimensionHeader)
	}
	if err := p.chargeWork(scanWork); err != nil {
		return err
	}
	if !plan.initialized || plan.name != plan.canonicalName || !validSerializationHeaderName(plan.name) {
		return generationInvariantErrorForDimension(DimensionHeader)
	}
	headerNames, ok := checkedAdd(p.headerNames, 1)
	if !ok || headerNames > p.limits.MaxHeaderNames {
		return generationLimitError(limitNameMaxHeaderNames, p.limits.MaxHeaderNames, headerNames, DimensionHeader)
	}
	if len(plan.name) > p.limits.MaxHeaderNameBytes {
		return generationLimitError(limitNameMaxHeaderNameBytes, p.limits.MaxHeaderNameBytes, len(plan.name), DimensionHeader)
	}
	nameBytes, ok := checkedAdd(p.headerNameBytes, len(plan.name))
	if !ok || nameBytes > p.limits.MaxTotalHeaderNameBytes {
		return generationLimitError(limitNameMaxTotalHeaderNameBytes, p.limits.MaxTotalHeaderNameBytes, nameBytes, DimensionHeader)
	}
	p.headerNameBytes = nameBytes
	p.headerNames = headerNames
	return p.validateSteps(plan.steps, DimensionHeader, p.limits.MaxStepsPerHeader, limitNameMaxStepsPerHeader, plan.name)
}

// validateSteps enforces shared step, range, copy, and literal ceilings.
func (p *serializationPreflight) validateSteps(steps []step, dimension Dimension, maximum int, limitName, headerName string) error {
	if len(steps) > maximum {
		return generationLimitError(limitName, maximum, len(steps), dimension)
	}
	previousCopyEnd := 0
	for _, instruction := range steps {
		if err := p.chargeWork(1); err != nil {
			return err
		}
		totalSteps, ok := checkedAdd(p.totalSteps, 1)
		if !ok || totalSteps > p.limits.MaxTotalSteps {
			return generationLimitError(limitNameMaxTotalSteps, p.limits.MaxTotalSteps, totalSteps, dimension)
		}
		p.totalSteps = totalSteps
		if start, end, copyStep := instruction.copyRange(); copyStep {
			if start <= 0 || end < start || len(instruction.data) != 0 || previousCopyEnd != 0 && start <= previousCopyEnd {
				return generationInvariantErrorForDimension(dimension)
			}
			if err := p.validateCopy(start, end, dimension); err != nil {
				return err
			}
			previousCopyEnd = end
			continue
		}
		if !instruction.initialized || instruction.kind != StepKindData || instruction.copyStart != 0 || instruction.copyEnd != 0 || len(instruction.data) == 0 {
			return generationInvariantErrorForDimension(dimension)
		}
		for _, literal := range instruction.data {
			if err := p.validateLiteral(literal, dimension, headerName); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateCopy enforces all inherited copy-range ceilings with checked arithmetic.
func (p *serializationPreflight) validateCopy(start, end int, dimension Dimension) error {
	copyRanges, ok := checkedAdd(p.copyRanges, 1)
	if !ok || copyRanges > p.limits.MaxCopyRanges {
		return generationLimitError(limitNameMaxCopyRanges, p.limits.MaxCopyRanges, copyRanges, dimension)
	}
	width, ok := checkedAdd(end-start, 1)
	if !ok || width > p.limits.MaxCopiedItemsPerRange {
		return generationLimitError(limitNameMaxCopiedItemsPerRange, p.limits.MaxCopiedItemsPerRange, width, dimension)
	}
	total, ok := checkedAdd(p.totalCopiedItems, width)
	if !ok || total > p.limits.MaxTotalCopiedItems {
		return generationLimitError(limitNameMaxTotalCopiedItems, p.limits.MaxTotalCopiedItems, total, dimension)
	}
	p.totalCopiedItems = total
	p.copyRanges = copyRanges
	return nil
}

// validateLiteral enforces decoded string, aggregate, and dimension line ceilings.
func (p *serializationPreflight) validateLiteral(literal []byte, dimension Dimension, headerName string) error {
	validationWork, ok := checkedMultiply(len(literal), 2)
	if ok {
		validationWork, ok = checkedAdd(validationWork, 1)
	}
	if !ok {
		return generationLimitError(limitNameMaxOperationWorkUnits, p.limits.MaxOperationWorkUnits, validationWork, dimension)
	}
	if err := p.chargeWork(validationWork); err != nil {
		return err
	}
	if !validDataLiteral(literal) {
		return serializationFailureError(dimension)
	}
	dataStrings, ok := checkedAdd(p.dataStrings, 1)
	if !ok || dataStrings > p.limits.MaxDataStrings {
		return generationLimitError(limitNameMaxDataStrings, p.limits.MaxDataStrings, dataStrings, dimension)
	}
	if len(literal) > p.limits.MaxDataStringBytes {
		return generationLimitError(limitNameMaxDataStringBytes, p.limits.MaxDataStringBytes, len(literal), dimension)
	}
	total, ok := checkedAdd(p.literalBytes, len(literal))
	if !ok || total > p.limits.MaxTotalLiteralBytes {
		return generationLimitError(limitNameMaxTotalLiteralBytes, p.limits.MaxTotalLiteralBytes, total, dimension)
	}
	p.literalBytes = total
	p.dataStrings = dataStrings
	if dimension == DimensionHeader {
		lineBytes, lineOK := checkedSum(len(headerName), 1, len(literal))
		fieldBytes, fieldOK := checkedAdd(lineBytes, 2)
		if !lineOK || lineBytes > p.limits.MaxHeaderLineBytes {
			return generationLimitError(limitNameMaxHeaderLineBytes, p.limits.MaxHeaderLineBytes, lineBytes, dimension)
		}
		if !fieldOK || fieldBytes > p.limits.MaxHeaderFieldBytes {
			return generationLimitError(limitNameMaxHeaderFieldBytes, p.limits.MaxHeaderFieldBytes, fieldBytes, dimension)
		}
	}
	if dimension == DimensionBody && len(literal) > p.limits.MaxBodyLineBytes {
		return generationLimitError(limitNameMaxBodyLineBytes, p.limits.MaxBodyLineBytes, len(literal), dimension)
	}
	return nil
}

// validSerializationHeaderName validates lowercase RFC 5322 ftext without allocation.
func validSerializationHeaderName(name string) bool {
	if len(name) == 0 {
		return false
	}
	for index := 0; index < len(name); index++ {
		current := name[index]
		if current <= 32 || current >= 127 || current == ':' || current >= 'A' && current <= 'Z' {
			return false
		}
	}
	return true
}

// recipeJSONEmitter performs either exact sizing or one exact-capacity write.
type recipeJSONEmitter struct {
	preflight *serializationPreflight
	write     bool
	expected  int
	size      int
	output    []byte
}

// newRecipeJSONSizer constructs an allocation-free exact output preflight.
func newRecipeJSONSizer(limits Limits, counter *generationCounter) *recipeJSONEmitter {
	return &recipeJSONEmitter{preflight: newSerializationPreflight(limits, counter)}
}

// newRecipeJSONWriter constructs one exact-capacity writer after successful preflight.
func newRecipeJSONWriter(preflight *serializationPreflight, size int) (*recipeJSONEmitter, error) {
	if preflight == nil || preflight.counter == nil || !preflight.sealed || preflight.sealedSize != size || size <= 0 || preflight.limits != preflight.counter.limits.RecipeLimits {
		return nil, generationInvariantErrorForDimension(DimensionRecipe)
	}
	return &recipeJSONEmitter{preflight: preflight, write: true, expected: size, output: make([]byte, 0, size)}, nil
}

// appendString charges exact bytes before sizing or writing them.
func (e *recipeJSONEmitter) appendString(value string) error {
	if !e.ready() || !e.write && e.preflight.sealed {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	next, ok := checkedAdd(e.size, len(value))
	limit := e.preflight.limits.MaxDecodedRecipeBytes
	if !ok || next > limit || e.write && next > e.expected {
		return generationLimitError(limitNameMaxDecodedRecipeBytes, limit, next, DimensionRecipe)
	}
	if e.write {
		e.output = append(e.output, value...)
	} else {
		reserved, reserveOK := checkedMultiply(len(value), 2)
		if !reserveOK {
			return generationLimitError(limitNameMaxOperationWorkUnits, e.preflight.limits.MaxOperationWorkUnits, reserved, DimensionRecipe)
		}
		if err := e.preflight.chargeWork(reserved); err != nil {
			return err
		}
	}
	e.size = next
	return nil
}

// appendBytes charges exact bytes before sizing or writing them.
func (e *recipeJSONEmitter) appendBytes(value []byte) error {
	if !e.ready() || !e.write && e.preflight.sealed {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	next, ok := checkedAdd(e.size, len(value))
	limit := e.preflight.limits.MaxDecodedRecipeBytes
	if !ok || next > limit || e.write && next > e.expected {
		return generationLimitError(limitNameMaxDecodedRecipeBytes, limit, next, DimensionRecipe)
	}
	if e.write {
		e.output = append(e.output, value...)
	} else {
		reserved, reserveOK := checkedMultiply(len(value), 2)
		if !reserveOK {
			return generationLimitError(limitNameMaxOperationWorkUnits, e.preflight.limits.MaxOperationWorkUnits, reserved, DimensionRecipe)
		}
		if err := e.preflight.chargeWork(reserved); err != nil {
			return err
		}
	}
	e.size = next
	return nil
}

// appendTokenString charges one lexical token before its exact bytes.
func (e *recipeJSONEmitter) appendTokenString(value string) error {
	if !e.ready() {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	if !e.write {
		if err := e.preflight.chargeToken(); err != nil {
			return err
		}
	}
	return e.appendString(value)
}

// beginContainer enters one bounded JSON container and emits its opening token.
func (e *recipeJSONEmitter) beginContainer(token string) error {
	if !e.ready() {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	if !e.write {
		if err := e.preflight.enterContainer(); err != nil {
			return err
		}
	}
	return e.appendTokenString(token)
}

// endContainer emits one closing token and leaves its bounded container.
func (e *recipeJSONEmitter) endContainer(token string) error {
	if !e.ready() {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	if err := e.appendTokenString(token); err != nil {
		return err
	}
	if !e.write {
		return e.preflight.leaveContainer()
	}
	return nil
}

// writeMemberNameString emits one string member name and colon.
func (e *recipeJSONEmitter) writeMemberNameString(value string) error {
	if !e.ready() {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	if !e.write {
		if err := e.preflight.chargeMember(); err != nil {
			return err
		}
	}
	if err := e.writeJSONStringString(value); err != nil {
		return err
	}
	return e.appendTokenString(":")
}

// writeJSONStringString emits one exact valid UTF-8 string without HTML escaping.
func (e *recipeJSONEmitter) writeJSONStringString(value string) error {
	if !e.ready() {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	if !e.write {
		scanWork, err := e.reserveJSONStringValidation(len(value))
		if err != nil {
			return err
		}
		if !utf8.ValidString(value) {
			return serializationFailureError(DimensionRecipe)
		}
		if err := e.reserveJSONStringEmission(scanWork); err != nil {
			return err
		}
	}
	if err := e.appendString("\""); err != nil {
		return err
	}
	if err := e.writeEscapedString(value); err != nil {
		return err
	}
	return e.appendString("\"")
}

// writeJSONStringBytes emits one exact valid UTF-8 byte string without replacement.
func (e *recipeJSONEmitter) writeJSONStringBytes(value []byte) error {
	if !e.ready() {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	if !e.write {
		scanWork, err := e.reserveJSONStringValidation(len(value))
		if err != nil {
			return err
		}
		if !utf8.Valid(value) {
			return serializationFailureError(DimensionRecipe)
		}
		if err := e.reserveJSONStringEmission(scanWork); err != nil {
			return err
		}
	}
	if err := e.appendString("\""); err != nil {
		return err
	}
	if err := e.writeEscapedBytes(value); err != nil {
		return err
	}
	return e.appendString("\"")
}

// reserveJSONStringValidation precharges one complete UTF-8 validation scan.
func (e *recipeJSONEmitter) reserveJSONStringValidation(byteCount int) (int, error) {
	scanWork, ok := checkedAdd(byteCount, 1)
	if !ok {
		return 0, generationLimitError(limitNameMaxOperationWorkUnits, e.preflight.limits.MaxOperationWorkUnits, scanWork, DimensionRecipe)
	}
	if err := e.preflight.chargeWork(scanWork); err != nil {
		return 0, err
	}
	return scanWork, nil
}

// reserveJSONStringEmission precharges sizing, writer scans, and the string token.
func (e *recipeJSONEmitter) reserveJSONStringEmission(scanWork int) error {
	reservedScans, ok := checkedMultiply(scanWork, 2)
	if !ok {
		return generationLimitError(limitNameMaxOperationWorkUnits, e.preflight.limits.MaxOperationWorkUnits, reservedScans, DimensionRecipe)
	}
	if err := e.preflight.chargeWork(reservedScans); err != nil {
		return err
	}
	return e.preflight.chargeToken()
}

// writeEscapedString emits one prevalidated string under the fixed RFC 8259 policy.
func (e *recipeJSONEmitter) writeEscapedString(value string) error {
	if !e.ready() {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	for index := 0; index < len(value); index++ {
		if err := e.writeEscapedByte(value[index]); err != nil {
			return err
		}
	}
	return nil
}

// writeEscapedBytes emits one prevalidated byte string under the fixed RFC 8259 policy.
func (e *recipeJSONEmitter) writeEscapedBytes(value []byte) error {
	if !e.ready() {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	for _, current := range value {
		if err := e.writeEscapedByte(current); err != nil {
			return err
		}
	}
	return nil
}

// writeEscapedByte emits one byte with lowercase control escaping where required.
func (e *recipeJSONEmitter) writeEscapedByte(current byte) error {
	if !e.ready() {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	switch current {
	case '"':
		return e.appendString(`\"`)
	case '\\':
		return e.appendString(`\\`)
	case '\b':
		return e.appendString(`\b`)
	case '\t':
		return e.appendString(`\t`)
	case '\f':
		return e.appendString(`\f`)
	default:
		if current < 0x20 {
			const hexadecimal = "0123456789abcdef"
			encoded := [6]byte{'\\', 'u', '0', '0', hexadecimal[current>>4], hexadecimal[current&0x0f]}
			return e.appendBytes(encoded[:])
		}
		return e.appendByte(current)
	}
}

// appendByte charges one exact byte before sizing or writing it.
func (e *recipeJSONEmitter) appendByte(value byte) error {
	if !e.ready() || !e.write && e.preflight.sealed {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	next, ok := checkedAdd(e.size, 1)
	limit := e.preflight.limits.MaxDecodedRecipeBytes
	if !ok || next > limit || e.write && next > e.expected {
		return generationLimitError(limitNameMaxDecodedRecipeBytes, limit, next, DimensionRecipe)
	}
	if e.write {
		e.output = append(e.output, value)
	} else if err := e.preflight.chargeWork(2); err != nil {
		return err
	}
	e.size = next
	return nil
}

// writePositiveInteger emits one canonical positive base-10 JSON number.
func (e *recipeJSONEmitter) writePositiveInteger(value int) error {
	if !e.ready() {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	if value <= 0 {
		return serializationFailureError(DimensionRecipe)
	}
	if !e.write {
		formatWork, ok := checkedMultiply(jsonIntegerBufferBytes, 2)
		if !ok {
			return generationLimitError(limitNameMaxOperationWorkUnits, e.preflight.limits.MaxOperationWorkUnits, formatWork, DimensionRecipe)
		}
		if err := e.preflight.chargeWork(formatWork); err != nil {
			return err
		}
		if err := e.preflight.chargeToken(); err != nil {
			return err
		}
	}
	var storage [jsonIntegerBufferBytes]byte
	digits := strconv.AppendInt(storage[:0], int64(value), 10)
	return e.appendBytes(digits)
}

// emitPlan emits one fixed-order compact combined plan into a sizer or writer.
func (e *recipeJSONEmitter) emitPlan(plan generationSerializationPlan) error {
	if e == nil || !plan.Valid() {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	if err := e.beginContainer("{"); err != nil {
		return err
	}
	wroteMember := false
	if len(plan.headers.plans) > 0 {
		if err := e.writeMemberNameString("h"); err != nil {
			return err
		}
		if err := e.beginContainer("{"); err != nil {
			return err
		}
		for index, header := range plan.headers.plans {
			if index > 0 {
				if err := e.appendTokenString(","); err != nil {
					return err
				}
			}
			if err := e.writeMemberNameString(header.name); err != nil {
				return err
			}
			if err := e.emitSteps(header.steps); err != nil {
				return err
			}
		}
		if err := e.endContainer("}"); err != nil {
			return err
		}
		wroteMember = true
	}
	if plan.bodyOutcome != BodyGenerationUnchanged {
		if wroteMember {
			if err := e.appendTokenString(","); err != nil {
				return err
			}
		}
		if err := e.writeMemberNameString("b"); err != nil {
			return err
		}
		if plan.bodyOutcome == BodyGenerationUnavailable {
			if err := e.appendTokenString("null"); err != nil {
				return err
			}
		} else if err := e.emitSteps(plan.body.steps); err != nil {
			return err
		}
	}
	return e.endContainer("}")
}

// emitSteps emits one ordered compact c/d step array.
func (e *recipeJSONEmitter) emitSteps(steps []step) error {
	if !e.ready() {
		return generationInvariantErrorForDimension(DimensionRecipe)
	}
	if err := e.beginContainer("["); err != nil {
		return err
	}
	for index, instruction := range steps {
		if index > 0 {
			if err := e.appendTokenString(","); err != nil {
				return err
			}
		}
		if err := e.beginContainer("{"); err != nil {
			return err
		}
		if start, end, copyStep := instruction.copyRange(); copyStep {
			if err := e.writeMemberNameString("c"); err != nil {
				return err
			}
			if err := e.beginContainer("["); err != nil {
				return err
			}
			if err := e.writePositiveInteger(start); err != nil {
				return err
			}
			if err := e.appendTokenString(","); err != nil {
				return err
			}
			if err := e.writePositiveInteger(end); err != nil {
				return err
			}
			if err := e.endContainer("]"); err != nil {
				return err
			}
		} else {
			if err := e.writeMemberNameString("d"); err != nil {
				return err
			}
			if err := e.beginContainer("["); err != nil {
				return err
			}
			for literalIndex, literal := range instruction.data {
				if literalIndex > 0 {
					if err := e.appendTokenString(","); err != nil {
						return err
					}
				}
				if err := e.writeJSONStringBytes(literal); err != nil {
					return err
				}
			}
			if err := e.endContainer("]"); err != nil {
				return err
			}
		}
		if err := e.endContainer("}"); err != nil {
			return err
		}
	}
	return e.endContainer("]")
}

// ready reports whether the emitter is bound to one operation-owned counter.
func (e *recipeJSONEmitter) ready() bool {
	return e != nil && e.preflight != nil && e.preflight.counter != nil
}

// serializeGenerationPlan performs exact validation, sizing, allocation, and writing.
func (b *generationPlanBudget) serializeGenerationPlan(plan generationSerializationPlan) (serializedGenerationPlan, error) {
	if b == nil || b.counter == nil || b.limits != b.counter.limits.RecipeLimits || !plan.Valid() {
		return serializedGenerationPlan{}, generationInvariantErrorForDimension(DimensionRecipe)
	}
	sizer := newRecipeJSONSizer(b.limits, b.counter)
	if err := sizer.preflight.validatePlan(plan); err != nil {
		return serializedGenerationPlan{}, err
	}
	if err := sizer.emitPlan(plan); err != nil {
		return serializedGenerationPlan{}, err
	}
	if sizer.preflight.depth != 0 || sizer.size <= 0 {
		return serializedGenerationPlan{}, generationInvariantErrorForDimension(DimensionRecipe)
	}
	if err := sizer.preflight.seal(sizer.size); err != nil {
		return serializedGenerationPlan{}, err
	}
	if err := b.counter.checkJSONBytes(sizer.size); err != nil {
		return serializedGenerationPlan{}, err
	}
	writer, err := newRecipeJSONWriter(sizer.preflight, sizer.size)
	if err != nil {
		return serializedGenerationPlan{}, err
	}
	if err := writer.emitPlan(plan); err != nil {
		return serializedGenerationPlan{}, err
	}
	if writer.size != sizer.size || len(writer.output) != sizer.size || cap(writer.output) != sizer.size {
		return serializedGenerationPlan{}, generationInvariantErrorForDimension(DimensionRecipe)
	}
	if err := b.counter.commitJSONBytes(writer.size); err != nil {
		return serializedGenerationPlan{}, err
	}
	result := serializedGenerationPlan{
		bodyOutcome: plan.bodyOutcome, unavailable: plan.unavailable, decodedJSON: writer.output,
		classifications: plan.headers.classifications,
		classified:      plan.headers.classified, initialized: true, validated: true,
	}
	if !result.Valid() {
		return serializedGenerationPlan{}, generationInvariantErrorForDimension(DimensionRecipe)
	}
	return result, nil
}

// serializationFailureError returns one secret-safe deterministic encoding failure.
func serializationFailureError(dimension Dimension) *Error {
	return newError(ErrorCodeSerializationFailure, ErrorLocation{}, ErrorDetails{Class: ErrorClassSerialization, Dimension: dimension}, nil)
}
