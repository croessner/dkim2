package signature

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/tagvalue"
)

const (
	maxRenderedFieldBytes  = 64 * 1024
	maxRenderedLineBytes   = 998
	maxGeneratedRecipients = 128
	maxGeneratedSets       = 2
	maxEnvelopePathBytes   = 32 * 1024
	maxGeneratedNonceBytes = 64
	maxSignatureBytes      = 1024
)

// SetPlan identifies one signature set whose value will be supplied later.
type SetPlan struct {
	Selector  string
	Algorithm Algorithm
}

// String returns a constant secret-safe set-plan summary.
func (p SetPlan) String() string { return "signature.SetPlan{redacted}" }

// GoString returns the constant secret-safe set-plan Go representation.
func (p SetPlan) GoString() string { return p.String() }

// Format routes every set-plan fmt form through the secret-safe summary.
func (p SetPlan) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, p.String()) }

// SetValue supplies one completed signature for an unsigned set plan.
type SetValue struct {
	Selector  string
	Algorithm Algorithm
	Signature []byte
}

// String returns a constant secret-safe set-value summary.
func (v SetValue) String() string { return "signature.SetValue{redacted}" }

// GoString returns the constant secret-safe set-value Go representation.
func (v SetValue) GoString() string { return v.String() }

// Format routes every set-value fmt form through the secret-safe summary.
func (v SetValue) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, v.String()) }

// SetLength identifies one planned completed signature without carrying signature bytes.
type SetLength struct {
	Selector  string
	Algorithm Algorithm
	Bytes     int
}

// String returns a constant secret-safe set-length summary.
func (l SetLength) String() string { return "signature.SetLength{redacted}" }

// GoString returns the constant secret-safe set-length Go representation.
func (l SetLength) GoString() string { return l.String() }

// Format routes every set-length fmt form through the secret-safe summary.
func (l SetLength) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, l.String()) }

// TargetRequest contains immutable input for one generated DKIM2-Signature target.
type TargetRequest struct {
	Sequence       uint64
	InstanceNumber uint64
	Timestamp      uint64
	MailFrom       []byte
	Recipients     [][]byte
	NextDomain     string
	Domain         string
	Sets           []SetPlan
	Nonce          []byte
	NoncePresent   bool
	Flags          []string
}

// String returns a constant secret-safe target-request summary.
func (r TargetRequest) String() string { return "signature.TargetRequest{redacted}" }

// GoString returns the constant secret-safe target-request Go representation.
func (r TargetRequest) GoString() string { return r.String() }

// Format routes every target-request fmt form through the secret-safe summary.
func (r TargetRequest) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// RenderLimits bounds deterministic DKIM2-Signature rendering.
type RenderLimits struct {
	MaxFieldBytes        int
	MaxLineBytes         int
	MaxRecipients        int
	MaxSignatureSets     int
	MaxEnvelopePathBytes int
	MaxNonceBytes        int
	MaxSignatureBytes    int
}

// DefaultRenderLimits returns the exact hard limits for generated signature fields.
func DefaultRenderLimits() RenderLimits {
	return RenderLimits{
		MaxFieldBytes: maxRenderedFieldBytes, MaxLineBytes: maxRenderedLineBytes,
		MaxRecipients: maxGeneratedRecipients, MaxSignatureSets: maxGeneratedSets,
		MaxEnvelopePathBytes: maxEnvelopePathBytes, MaxNonceBytes: maxGeneratedNonceBytes,
		MaxSignatureBytes: maxSignatureBytes,
	}
}

// Validate rejects nonpositive, widened, or incoherent render limits.
func (l RenderLimits) Validate() error {
	hard := DefaultRenderLimits()
	values := []struct {
		name  string
		value int
		hard  int
	}{
		{"max_field_bytes", l.MaxFieldBytes, hard.MaxFieldBytes},
		{"max_line_bytes", l.MaxLineBytes, hard.MaxLineBytes},
		{"max_recipients", l.MaxRecipients, hard.MaxRecipients},
		{"max_signature_sets", l.MaxSignatureSets, hard.MaxSignatureSets},
		{"max_envelope_path_bytes", l.MaxEnvelopePathBytes, hard.MaxEnvelopePathBytes},
		{"max_nonce_bytes", l.MaxNonceBytes, hard.MaxNonceBytes},
		{"max_signature_bytes", l.MaxSignatureBytes, hard.MaxSignatureBytes},
	}
	for _, candidate := range values {
		if candidate.value <= 0 || candidate.value > candidate.hard {
			return invalidLimitError(candidate.name, candidate.value)
		}
	}
	return nil
}

// normalized fills zero render limits with restrictive defaults.
func (l RenderLimits) normalized() (RenderLimits, error) {
	defaults := DefaultRenderLimits()
	values := []struct{ target, fallback *int }{
		{&l.MaxFieldBytes, &defaults.MaxFieldBytes}, {&l.MaxLineBytes, &defaults.MaxLineBytes},
		{&l.MaxRecipients, &defaults.MaxRecipients}, {&l.MaxSignatureSets, &defaults.MaxSignatureSets},
		{&l.MaxEnvelopePathBytes, &defaults.MaxEnvelopePathBytes}, {&l.MaxNonceBytes, &defaults.MaxNonceBytes},
		{&l.MaxSignatureBytes, &defaults.MaxSignatureBytes},
	}
	for _, value := range values {
		if *value.target == 0 {
			*value.target = *value.fallback
		}
	}
	if err := l.Validate(); err != nil {
		return RenderLimits{}, err
	}
	return l, nil
}

// UnsignedTarget owns immutable bytes that intentionally contain empty s= values.
type UnsignedTarget struct {
	request  TargetRequest
	limits   RenderLimits
	unsigned []byte
}

// CompleteField owns one immutable complete DKIM2-Signature field.
type CompleteField struct {
	field []byte
}

// NewUnsignedTarget validates, canonicalizes, and renders one immutable unsigned target.
func NewUnsignedTarget(request TargetRequest, limits RenderLimits) (UnsignedTarget, error) {
	resolved, err := limits.normalized()
	if err != nil {
		return UnsignedTarget{}, err
	}
	canonical, err := canonicalTargetRequest(request, resolved)
	if err != nil {
		return UnsignedTarget{}, err
	}
	size, err := preflightTarget(canonical, nil, resolved)
	if err != nil {
		return UnsignedTarget{}, err
	}
	unsigned, err := renderTarget(canonical, nil, resolved, size)
	if err != nil {
		return UnsignedTarget{}, err
	}
	return UnsignedTarget{request: canonical, limits: resolved, unsigned: unsigned}, nil
}

// UnsignedBytes returns detached canonical bytes for the signing input target.
func (t UnsignedTarget) UnsignedBytes() []byte {
	return bytes.Clone(t.unsigned)
}

// Valid reports whether the target owns coherent canonical unsigned bytes.
func (t UnsignedTarget) Valid() bool {
	if len(t.unsigned) == 0 || t.limits.Validate() != nil {
		return false
	}
	rebuilt, err := NewUnsignedTarget(t.request, t.limits)
	return err == nil && bytes.Equal(rebuilt.unsigned, t.unsigned)
}

// Sequence returns the target i= value.
func (t UnsignedTarget) Sequence() uint64 {
	if !t.Valid() {
		return 0
	}
	return t.request.Sequence
}

// InstanceNumber returns the target m= value.
func (t UnsignedTarget) InstanceNumber() uint64 {
	if !t.Valid() {
		return 0
	}
	return t.request.InstanceNumber
}

// PreflightComplete returns the exact complete-field size without signature bytes or callbacks.
func (t UnsignedTarget) PreflightComplete(lengths []SetLength) (int, error) {
	values, err := t.canonicalCompleteLengths(lengths)
	if err != nil {
		return 0, err
	}
	return preflightTarget(t.request, values, t.limits)
}

// Complete validates signature values and returns a distinct complete field type.
func (t UnsignedTarget) Complete(values []SetValue) (CompleteField, error) {
	inputs := make([]completionInput, len(values))
	for index, value := range values {
		inputs[index] = completionInput{
			selector: value.Selector, algorithm: value.Algorithm,
			bytes: len(value.Signature), signature: value.Signature,
		}
	}
	renderValues, err := t.canonicalCompletionPlan(inputs)
	if err != nil {
		return CompleteField{}, err
	}
	size, err := preflightTarget(t.request, renderValues, t.limits)
	if err != nil {
		return CompleteField{}, err
	}
	field, err := renderTarget(t.request, renderValues, t.limits, size)
	if err != nil {
		return CompleteField{}, err
	}
	return CompleteField{field: field}, nil
}

// RebuildUnsignedFromComplete reparses a complete field and proves exact logical target equality.
func (t UnsignedTarget) RebuildUnsignedFromComplete(complete CompleteField) (UnsignedTarget, error) {
	if !t.Valid() || len(complete.field) == 0 {
		return UnsignedTarget{}, renderConstructionError("s")
	}

	completeField, err := parseRenderedSignatureField(complete.field)
	if err != nil {
		return UnsignedTarget{}, renderConstructionError("s")
	}
	parsed, err := Parse(completeField)
	if err != nil {
		return UnsignedTarget{}, renderConstructionError("s")
	}
	completeTags, err := tagvalue.ScanTerminated(completeField.UnfoldedValue(), knownSignatureTags, tagvalue.DefaultLimits())
	if err != nil {
		return UnsignedTarget{}, renderConstructionError("s")
	}
	unsignedField, err := parseRenderedSignatureField(t.unsigned)
	if err != nil {
		return UnsignedTarget{}, renderConstructionError("s")
	}
	unsignedTags, err := tagvalue.ScanTerminated(unsignedField.UnfoldedValue(), knownSignatureTags, tagvalue.DefaultLimits())
	if err != nil || !matchesUnsignedTagSequence(completeTags, unsignedTags) {
		return UnsignedTarget{}, renderConstructionError("s")
	}

	rebuilt, err := NewUnsignedTarget(targetRequestFromComplete(parsed), t.limits)
	if err != nil || !bytes.Equal(rebuilt.unsigned, t.unsigned) {
		return UnsignedTarget{}, renderConstructionError("s")
	}
	return rebuilt, nil
}

// parseRenderedSignatureField requires exactly one complete RFC 5322 header field.
func parseRenderedSignatureField(field []byte) (rawmsg.HeaderField, error) {
	if !bytes.HasSuffix(field, []byte("\r\n")) {
		return rawmsg.HeaderField{}, renderConstructionError("s")
	}
	message, err := rawmsg.Parse(field)
	if err != nil || message.Framing() != rawmsg.MessageFramingHeaderOnly ||
		message.Headers().Len() != 1 || message.Body().Len() != 0 {
		return rawmsg.HeaderField{}, renderConstructionError("s")
	}
	fields := message.Headers().FieldsByName(HeaderName)
	if len(fields) != 1 {
		return rawmsg.HeaderField{}, renderConstructionError("s")
	}
	return fields[0], nil
}

// matchesUnsignedTagSequence compares exact Section 9.6 logical tags after nulling every signature.
func matchesUnsignedTagSequence(complete tagvalue.Field, unsigned tagvalue.Field) bool {
	completeTags := complete.Tags()
	unsignedTags := unsigned.Tags()
	if len(completeTags) != len(unsignedTags) {
		return false
	}
	for index := range completeTags {
		if completeTags[index].Name() != unsignedTags[index].Name() {
			return false
		}
		completeValue, ok := logicalUnsignedTagValue(completeTags[index])
		if !ok || !bytes.Equal(completeValue, signatureValueWithoutWSP(unsignedTags[index].Value())) {
			return false
		}
	}
	return true
}

// logicalUnsignedTagValue removes WSP and blanks all completed s= payloads atomically.
func logicalUnsignedTagValue(tag tagvalue.Tag) ([]byte, bool) {
	value := signatureValueWithoutWSP(tag.Value())
	if tag.Name() != string(TagNameSignatures) {
		return value, true
	}

	sets := bytes.Split(value, []byte{','})
	if len(sets) == 0 {
		return nil, false
	}
	unsigned := make([]byte, 0, len(value))
	for index, set := range sets {
		components := bytes.Split(set, []byte{':'})
		if len(components) != 3 || len(components[0]) == 0 || len(components[1]) == 0 || len(components[2]) == 0 {
			return nil, false
		}
		if index > 0 {
			unsigned = append(unsigned, ',')
		}
		unsigned = append(unsigned, components[0]...)
		unsigned = append(unsigned, ':')
		unsigned = append(unsigned, components[1]...)
		unsigned = append(unsigned, ':')
	}
	return unsigned, true
}

// signatureValueWithoutWSP applies the Section 9.6 WSP deletion rule to one tag value.
func signatureValueWithoutWSP(value string) []byte {
	withoutWSP := make([]byte, 0, len(value))
	for index := 0; index < len(value); index++ {
		if isWSP(value[index]) {
			continue
		}
		withoutWSP = append(withoutWSP, value[index])
	}
	return withoutWSP
}

// targetRequestFromComplete derives an unsigned construction request only from reparsed complete state.
func targetRequestFromComplete(parsed Signature) TargetRequest {
	recipients := parsed.Recipients()
	request := TargetRequest{
		Sequence:       parsed.Sequence(),
		InstanceNumber: parsed.InstanceNumber(),
		Timestamp:      parsed.TimestampSeconds(),
		Domain:         parsed.Domain(),
		Recipients:     make([][]byte, len(recipients)),
	}
	for index := range recipients {
		request.Recipients[index] = recipients[index].Value()
	}
	if nextDomain, ok := parsed.NextDomain(); ok {
		request.NextDomain = nextDomain
	} else {
		request.MailFrom = parsed.MailFrom().Value()
	}

	nonce, hasNonce := parsed.Nonce()
	request.Nonce = nonce
	request.NoncePresent = hasNonce

	flags := parsed.Flags().Values()
	request.Flags = make([]string, len(flags))
	for index := range flags {
		request.Flags[index] = flags[index].Name()
	}

	sets := parsed.SignatureSets()
	request.Sets = make([]SetPlan, len(sets))
	for index := range sets {
		request.Sets[index] = SetPlan{
			Selector:  sets[index].Selector(),
			Algorithm: Algorithm(sets[index].Algorithm()),
		}
	}
	return request
}

// canonicalCompleteLengths validates and orders signature lengths against the immutable set plan.
func (t UnsignedTarget) canonicalCompleteLengths(lengths []SetLength) ([]renderSetValue, error) {
	inputs := make([]completionInput, len(lengths))
	for index, length := range lengths {
		inputs[index] = completionInput{selector: length.Selector, algorithm: length.Algorithm, bytes: length.Bytes}
	}
	return t.canonicalCompletionPlan(inputs)
}

// completionInput carries one untrusted callback value or pre-callback length.
type completionInput struct {
	selector  string
	algorithm Algorithm
	bytes     int
	signature []byte
}

// canonicalCompletionPlan owns shared preflight and callback-result validation.
func (t UnsignedTarget) canonicalCompletionPlan(inputs []completionInput) ([]renderSetValue, error) {
	if len(t.unsigned) == 0 || len(t.request.Sets) == 0 || len(inputs) != len(t.request.Sets) {
		return nil, renderConstructionError("s")
	}
	canonical := slices.Clone(inputs)
	seen := make(map[string]struct{}, len(canonical))
	for index := range canonical {
		selector, ok := canonicalDNSName([]byte(canonical[index].selector))
		if !ok || !canonical[index].algorithm.Known() {
			return nil, renderConstructionError("s")
		}
		canonical[index].selector = selector
		key := selector + "\x00" + string(canonical[index].algorithm)
		if _, exists := seen[key]; exists {
			return nil, renderConstructionError("s")
		}
		seen[key] = struct{}{}
		if err := validateGeneratedSignatureLength(canonical[index].algorithm, canonical[index].bytes, t.limits); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(canonical, func(left, right completionInput) int {
		return compareSetPlans(SetPlan{Selector: left.selector, Algorithm: left.algorithm}, SetPlan{Selector: right.selector, Algorithm: right.algorithm})
	})
	values := make([]renderSetValue, len(canonical))
	for index, plan := range t.request.Sets {
		if canonical[index].selector != plan.Selector || canonical[index].algorithm != plan.Algorithm {
			return nil, renderConstructionError("s")
		}
		values[index] = renderSetValue{signature: bytes.Clone(canonical[index].signature), bytes: canonical[index].bytes}
	}
	return values, nil
}

// validateGeneratedSignatureLength enforces algorithm and callback byte contracts.
func validateGeneratedSignatureLength(algorithm Algorithm, length int, limits RenderLimits) error {
	if length <= 0 || length > limits.MaxSignatureBytes {
		return renderLimitError("max_signature_bytes", limits.MaxSignatureBytes, length)
	}
	if algorithm == AlgorithmEd25519SHA256 && length != ed25519SignatureBytes {
		return newError(ErrorCodeInvalidSignatureLength, ErrorLocation{}, ErrorDetails{TagName: "s", Limit: ed25519SignatureBytes, Count: length}, nil)
	}
	return nil
}

// Bytes returns detached bytes for one complete DKIM2-Signature field.
func (f CompleteField) Bytes() []byte {
	return bytes.Clone(f.field)
}

// Valid reports whether the complete field contains nonempty bytes.
func (f CompleteField) Valid() bool { return len(f.field) > 0 }

// String returns a constant secret-safe unsigned-target summary.
func (t UnsignedTarget) String() string { return "signature.UnsignedTarget{redacted}" }

// GoString returns the constant secret-safe unsigned-target Go representation.
func (t UnsignedTarget) GoString() string { return t.String() }

// Format routes every unsigned-target fmt form through the secret-safe summary.
func (t UnsignedTarget) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, t.String()) }

// String returns a constant secret-safe complete-field summary.
func (f CompleteField) String() string { return "signature.CompleteField{redacted}" }

// GoString returns the constant secret-safe complete-field Go representation.
func (f CompleteField) GoString() string { return f.String() }

// Format routes every complete-field fmt form through the secret-safe summary.
func (f CompleteField) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, f.String()) }

// canonicalTargetRequest validates and detaches request-owned content.
func canonicalTargetRequest(request TargetRequest, limits RenderLimits) (TargetRequest, error) {
	if request.Sequence == 0 || request.InstanceNumber == 0 {
		return TargetRequest{}, renderConstructionError("i")
	}
	domain, ok := canonicalDNSName([]byte(request.Domain))
	if !ok {
		return TargetRequest{}, newError(ErrorCodeInvalidDomain, ErrorLocation{}, ErrorDetails{TagName: "d"}, nil)
	}
	request.Domain = domain
	if err := canonicalizeEnvelope(&request, limits); err != nil {
		return TargetRequest{}, err
	}
	sets, err := canonicalizeSetPlans(request.Sets, limits)
	if err != nil {
		return TargetRequest{}, err
	}
	request.Sets = sets
	if request.NoncePresent {
		if len(request.Nonce) > limits.MaxNonceBytes || !validGeneratedNonce(request.Nonce) {
			return TargetRequest{}, newError(ErrorCodeInvalidNonce, ErrorLocation{}, ErrorDetails{TagName: "n", Limit: limits.MaxNonceBytes, Count: len(request.Nonce)}, nil)
		}
		request.Nonce = bytes.Clone(request.Nonce)
	} else if len(request.Nonce) != 0 {
		return TargetRequest{}, newError(ErrorCodeInvalidNonce, ErrorLocation{}, ErrorDetails{TagName: "n"}, nil)
	}
	flags, err := canonicalizeGeneratedFlags(request.Flags)
	if err != nil {
		return TargetRequest{}, err
	}
	request.Flags = flags
	return request, nil
}

// canonicalizeEnvelope validates exactly one supported envelope form and detaches bytes.
func canonicalizeEnvelope(request *TargetRequest, limits RenderLimits) error {
	hasNextDomain := request.NextDomain != ""
	hasOrdinary := len(request.MailFrom) != 0 || len(request.Recipients) != 0
	if hasNextDomain == hasOrdinary {
		return invalidEnvelopeFormError(0)
	}
	if hasNextDomain {
		nextDomain, ok := canonicalDNSName([]byte(request.NextDomain))
		if !ok {
			return newError(ErrorCodeInvalidDomain, ErrorLocation{}, ErrorDetails{TagName: "nd"}, nil)
		}
		request.NextDomain = nextDomain
		return nil
	}
	if len(request.Recipients) == 0 || len(request.Recipients) > limits.MaxRecipients {
		return renderLimitError("max_recipients", limits.MaxRecipients, len(request.Recipients))
	}
	if !validEnvelopePath(request.MailFrom, true) {
		return newError(ErrorCodeInvalidEnvelopePath, ErrorLocation{}, ErrorDetails{TagName: "mf"}, nil)
	}
	totalBytes := len(request.MailFrom)
	request.MailFrom = bytes.Clone(request.MailFrom)
	recipients := make([][]byte, len(request.Recipients))
	seen := make(map[string]struct{}, len(request.Recipients))
	for index, recipient := range request.Recipients {
		if !validEnvelopePath(recipient, false) {
			return newError(ErrorCodeInvalidEnvelopePath, ErrorLocation{RecipientIndex: index}, ErrorDetails{TagName: "rt"}, nil)
		}
		if _, exists := seen[string(recipient)]; exists {
			return newError(ErrorCodeInvalidEnvelopePath, ErrorLocation{RecipientIndex: index}, ErrorDetails{TagName: "rt"}, nil)
		}
		seen[string(recipient)] = struct{}{}
		if totalBytes > limits.MaxEnvelopePathBytes-len(recipient) {
			return renderLimitError("max_envelope_path_bytes", limits.MaxEnvelopePathBytes, limits.MaxEnvelopePathBytes+1)
		}
		totalBytes += len(recipient)
		recipients[index] = bytes.Clone(recipient)
	}
	request.Recipients = recipients
	return nil
}

// canonicalizeSetPlans validates, sorts, and detaches generated signature plans.
func canonicalizeSetPlans(input []SetPlan, limits RenderLimits) ([]SetPlan, error) {
	if len(input) == 0 || len(input) > limits.MaxSignatureSets {
		return nil, renderLimitError("max_signature_sets", limits.MaxSignatureSets, len(input))
	}
	seenSelectors := make(map[string]struct{}, len(input))
	seenAlgorithms := make(map[Algorithm]struct{}, len(input))
	output := make([]SetPlan, 0, len(input))
	for index, plan := range input {
		selector, ok := canonicalDNSName([]byte(plan.Selector))
		if !ok || !plan.Algorithm.Known() {
			return nil, renderConstructionError("s")
		}
		if _, exists := seenAlgorithms[plan.Algorithm]; exists {
			return nil, newError(ErrorCodeDuplicateSignatureAlgorithm, ErrorLocation{SignatureIndex: index}, ErrorDetails{TagName: "s"}, nil)
		}
		if _, exists := seenSelectors[selector]; exists {
			return nil, newError(ErrorCodeDuplicateSelector, ErrorLocation{SignatureIndex: index}, ErrorDetails{TagName: "s"}, nil)
		}
		seenAlgorithms[plan.Algorithm] = struct{}{}
		seenSelectors[selector] = struct{}{}
		output = append(output, SetPlan{Selector: selector, Algorithm: plan.Algorithm})
	}
	slices.SortFunc(output, compareSetPlans)
	return output, nil
}

// canonicalizeGeneratedFlags accepts only unique known flags in canonical order.
func canonicalizeGeneratedFlags(input []string) ([]string, error) {
	output := make([]string, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for index, raw := range input {
		name, ok := canonicalTokenName([]byte(raw))
		if !ok || !knownFlag(name) {
			return nil, malformedFlagError(0, index)
		}
		if _, exists := seen[name]; exists {
			return nil, newError(ErrorCodeDuplicateKnownFlag, ErrorLocation{FlagIndex: index}, ErrorDetails{TagName: "f"}, nil)
		}
		seen[name] = struct{}{}
		output = append(output, name)
	}
	slices.SortFunc(output, compareGeneratedFlags)
	return output, nil
}

// compareGeneratedFlags applies the frozen DKIM2 flag order.
func compareGeneratedFlags(left, right string) int {
	return generatedFlagRank(left) - generatedFlagRank(right)
}

// generatedFlagRank returns the frozen order of parser-known flags.
func generatedFlagRank(name string) int {
	switch name {
	case FlagDoNotModify:
		return 0
	case FlagDoNotExplode:
		return 1
	case FlagFeedback:
		return 2
	case FlagFeedHere:
		return 3
	case FlagExploded:
		return 4
	default:
		return 5
	}
}

// compareSetPlans orders baseline RSA before Ed25519 and then by selector.
func compareSetPlans(left, right SetPlan) int {
	if left.Algorithm != right.Algorithm {
		if left.Algorithm == AlgorithmRSASHA256 {
			return -1
		}
		return 1
	}
	return strings.Compare(left.Selector, right.Selector)
}

// validGeneratedNonce accepts printable ASCII except the tag terminator.
func validGeneratedNonce(value []byte) bool {
	return ValidNonceSyntax(value)
}

// fieldEmitter shares exact grammar accounting between preflight and rendering.
type fieldEmitter struct {
	limits  RenderLimits
	builder *bytes.Buffer
	size    int
	line    int
	err     error
}

// renderSetValue carries either signature bytes or their pre-callback length.
type renderSetValue struct {
	signature []byte
	bytes     int
}

// preflightTarget calculates the exact field size without allocating encoded or field bytes.
func preflightTarget(request TargetRequest, values []renderSetValue, limits RenderLimits) (int, error) {
	emitter := &fieldEmitter{limits: limits}
	emitTarget(emitter, request, values)
	if emitter.err != nil {
		return 0, emitter.err
	}
	if emitter.line != 0 {
		return 0, newError(ErrorCodeRenderInvariant, ErrorLocation{}, ErrorDetails{}, nil)
	}
	return emitter.size, nil
}

// renderTarget emits the frozen field after exact preflight succeeds.
func renderTarget(request TargetRequest, values []renderSetValue, limits RenderLimits, size int) ([]byte, error) {
	var builder bytes.Buffer
	builder.Grow(size)
	emitter := &fieldEmitter{limits: limits, builder: &builder}
	emitTarget(emitter, request, values)
	if emitter.err != nil || emitter.size != size {
		return nil, newError(ErrorCodeRenderInvariant, ErrorLocation{}, ErrorDetails{}, nil)
	}
	return builder.Bytes(), nil
}

// emitTarget owns the single frozen tag and FWS grammar for preflight and rendering.
func emitTarget(emitter *fieldEmitter, request TargetRequest, values []renderSetValue) {
	emitter.text("DKIM2-Signature: i=")
	emitter.text(strconv.FormatUint(request.Sequence, 10))
	emitter.text(";")
	emitter.crlf()
	emitter.text("\tm=")
	emitter.text(strconv.FormatUint(request.InstanceNumber, 10))
	emitter.text(";")
	emitter.crlf()
	emitter.text("\tt=")
	emitter.text(strconv.FormatUint(request.Timestamp, 10))
	emitter.text(";")
	emitter.crlf()
	if request.NextDomain != "" {
		emitter.text("\tnd=")
		emitter.text(request.NextDomain)
		emitter.text(";")
		emitter.crlf()
	} else {
		emitter.text("\tmf=")
		emitter.base64(request.MailFrom, len(request.MailFrom))
		emitter.text(";")
		emitter.crlf()
		emitter.text("\trt=")
		for index, recipient := range request.Recipients {
			if index > 0 {
				emitter.text(",")
				emitter.crlf()
				emitter.text("\t")
			}
			emitter.base64(recipient, len(recipient))
		}
		emitter.text(";")
		emitter.crlf()
	}
	emitter.text("\td=")
	emitter.text(request.Domain)
	emitter.text(";")
	emitter.crlf()
	emitter.text("\ts=")
	for index, plan := range request.Sets {
		if index > 0 {
			emitter.text(",")
			emitter.crlf()
			emitter.text("\t")
		}
		emitter.text(plan.Selector)
		emitter.text(":")
		emitter.text(string(plan.Algorithm))
		emitter.text(":")
		if values != nil {
			emitter.base64(values[index].signature, values[index].bytes)
		}
	}
	emitter.text(";")
	emitter.crlf()
	if request.NoncePresent {
		emitter.text("\tn=")
		emitter.text(string(request.Nonce))
		emitter.text(";")
		emitter.crlf()
	}
	if len(request.Flags) > 0 {
		emitter.text("\tf=")
		for index, flag := range request.Flags {
			if index > 0 {
				emitter.text(",")
			}
			emitter.text(flag)
		}
		emitter.text(";")
		emitter.crlf()
	}
}

// text accounts for and optionally writes one no-CRLF text segment.
func (e *fieldEmitter) text(value string) {
	e.textCount(len(value))
	if e.err == nil && e.builder != nil {
		e.builder.WriteString(value)
	}
}

// textCount accounts for one no-CRLF text segment without allocating content.
func (e *fieldEmitter) textCount(count int) {
	if e.err != nil {
		return
	}
	if count < 0 || count > e.limits.MaxFieldBytes-e.size {
		e.err = renderLimitError("max_field_bytes", e.limits.MaxFieldBytes, e.limits.MaxFieldBytes+1)
		return
	}
	if count > e.limits.MaxLineBytes-e.line {
		e.err = renderLimitError("max_line_bytes", e.limits.MaxLineBytes, e.limits.MaxLineBytes+1)
		return
	}
	e.size += count
	e.line += count
}

// crlf accounts for and optionally writes one CRLF physical-line boundary.
func (e *fieldEmitter) crlf() {
	if e.err != nil {
		return
	}
	if 2 > e.limits.MaxFieldBytes-e.size {
		e.err = renderLimitError("max_field_bytes", e.limits.MaxFieldBytes, e.limits.MaxFieldBytes+1)
		return
	}
	e.size += 2
	e.line = 0
	if e.builder != nil {
		e.builder.WriteString("\r\n")
	}
}

// base64 accounts for and optionally writes padded Base64 in exact 64-character folds.
func (e *fieldEmitter) base64(decoded []byte, decodedBytes int) {
	if e.err != nil {
		return
	}
	var encoded string
	if e.builder != nil {
		if len(decoded) != decodedBytes {
			e.err = newError(ErrorCodeRenderInvariant, ErrorLocation{}, ErrorDetails{}, nil)
			return
		}
		encoded = tagvalue.EncodeBase64(decoded)
	}
	encodedLen, ok := tagvalue.WalkBase64Chunks(decodedBytes, func(first bool, offset, size int) {
		if !first {
			e.crlf()
			e.text("\t")
		}
		if e.builder == nil {
			e.textCount(size)
		} else {
			e.text(encoded[offset : offset+size])
		}
	})
	if !ok || e.builder != nil && len(encoded) != encodedLen {
		e.err = newError(ErrorCodeRenderInvariant, ErrorLocation{}, ErrorDetails{}, nil)
	}
}

// renderConstructionError constructs a content-free generator input failure.
func renderConstructionError(tagName string) *Error {
	return newError(ErrorCodeInvalidConstruction, ErrorLocation{}, ErrorDetails{TagName: TagName(tagName)}, nil)
}

// renderLimitError constructs a content-free generated-field limit failure.
func renderLimitError(limitName string, limit, count int) *Error {
	return newError(ErrorCodeLimitExceeded, ErrorLocation{}, ErrorDetails{LimitName: LimitName(limitName), Limit: limit, Count: count}, nil)
}
