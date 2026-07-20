package instance

import (
	"bytes"
	"fmt"
	"io"
	"strconv"

	"github.com/croessner/dkim2/internal/tagvalue"
)

const (
	hardMaxRenderedFieldBytes = 64 * 1024
	hardMaxRenderedLineBytes  = 998
	hardMaxSigningRecipeBytes = 45 * 1024
)

// SigningRequest contains immutable input for one generated Message-Instance.
type SigningRequest struct {
	Number        uint64
	HeaderHash    []byte
	BodyHash      []byte
	Recipe        []byte
	RecipePresent bool
}

// String returns a secret-safe signing-request summary.
func (r SigningRequest) String() string { return "instance.SigningRequest{redacted}" }

// GoString returns a secret-safe signing-request Go representation.
func (r SigningRequest) GoString() string { return r.String() }

// Format routes every fmt form through the secret-safe summary.
func (r SigningRequest) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// RenderLimits bounds deterministic Message-Instance rendering.
type RenderLimits struct {
	MaxFieldBytes  int
	MaxLineBytes   int
	MaxRecipeBytes int
}

// DefaultRenderLimits returns the exact signing field hard limits.
func DefaultRenderLimits() RenderLimits {
	return RenderLimits{MaxFieldBytes: hardMaxRenderedFieldBytes, MaxLineBytes: hardMaxRenderedLineBytes, MaxRecipeBytes: hardMaxSigningRecipeBytes}
}

// Validate rejects widening, nonpositive, or incoherent render limits.
func (l RenderLimits) Validate() error {
	if l.MaxFieldBytes <= 0 || l.MaxFieldBytes > hardMaxRenderedFieldBytes {
		return renderOptionsError("max_field_bytes", l.MaxFieldBytes)
	}
	if l.MaxLineBytes <= 0 || l.MaxLineBytes > hardMaxRenderedLineBytes {
		return renderOptionsError("max_line_bytes", l.MaxLineBytes)
	}
	if l.MaxRecipeBytes <= 0 || l.MaxRecipeBytes > hardMaxSigningRecipeBytes {
		return renderOptionsError("max_recipe_bytes", l.MaxRecipeBytes)
	}
	return nil
}

// normalized fills zero render limits with restrictive defaults.
func (l RenderLimits) normalized() (RenderLimits, error) {
	defaults := DefaultRenderLimits()
	if l.MaxFieldBytes == 0 {
		l.MaxFieldBytes = defaults.MaxFieldBytes
	}
	if l.MaxLineBytes == 0 {
		l.MaxLineBytes = defaults.MaxLineBytes
	}
	if l.MaxRecipeBytes == 0 {
		l.MaxRecipeBytes = defaults.MaxRecipeBytes
	}
	if err := l.Validate(); err != nil {
		return RenderLimits{}, err
	}
	return l, nil
}

// NewForSigning constructs one immutable generated Message-Instance model.
func NewForSigning(request SigningRequest) (MessageInstance, error) {
	if request.Number == 0 || len(request.HeaderHash) != sha256HashBytes || len(request.BodyHash) != sha256HashBytes {
		return MessageInstance{}, newError(ErrorCodeInvalidConstruction, ErrorLocation{}, ErrorDetails{}, nil)
	}
	if !request.RecipePresent && len(request.Recipe) != 0 || request.RecipePresent && len(request.Recipe) == 0 {
		return MessageInstance{}, newError(ErrorCodeInvalidConstruction, ErrorLocation{}, ErrorDetails{TagName: "r"}, nil)
	}
	if len(request.Recipe) > hardMaxSigningRecipeBytes {
		return MessageInstance{}, renderLimitError("max_recipe_bytes", hardMaxSigningRecipeBytes, len(request.Recipe))
	}
	headerHash, err := parseGeneratedBase64(request.HeaderHash)
	if err != nil {
		return MessageInstance{}, err
	}
	bodyHash, err := parseGeneratedBase64(request.BodyHash)
	if err != nil {
		return MessageInstance{}, err
	}
	hashSet := HashSet{
		name: HashAlgorithmSHA256, known: true, headerHash: headerHash, bodyHash: bodyHash,
		headerHashValue: []byte(headerHash.EncodedString()), bodyHashValue: []byte(bodyHash.EncodedString()),
	}
	model := MessageInstance{number: request.Number, hashes: []HashSet{hashSet}}
	if request.RecipePresent {
		recipe, recipeErr := parseGeneratedBase64(request.Recipe)
		if recipeErr != nil {
			return MessageInstance{}, recipeErr
		}
		model.recipe, model.hasRecipe = recipe, true
	}
	return model, nil
}

// PreflightSigningField returns the exact rendered size without allocating field bytes.
func PreflightSigningField(number uint64, recipeBytes int, recipePresent bool, limits RenderLimits) (int, error) {
	resolved, err := limits.normalized()
	if err != nil {
		return 0, err
	}
	return preflightSigningFieldResolved(number, recipeBytes, recipePresent, resolved)
}

// preflightSigningFieldResolved returns the exact rendered size under validated limits.
func preflightSigningFieldResolved(number uint64, recipeBytes int, recipePresent bool, resolved RenderLimits) (int, error) {
	if number == 0 || recipeBytes < 0 || !recipePresent && recipeBytes != 0 || recipePresent && recipeBytes == 0 {
		return 0, newError(ErrorCodeInvalidConstruction, ErrorLocation{}, ErrorDetails{}, nil)
	}
	if recipeBytes > resolved.MaxRecipeBytes {
		return 0, renderLimitError("max_recipe_bytes", resolved.MaxRecipeBytes, recipeBytes)
	}
	emitter := &instanceEmitter{limits: resolved}
	emitSigningField(emitter, number, "", "", "", recipeBytes, recipePresent)
	if emitter.err != nil {
		return 0, emitter.err
	}
	return emitter.size, nil
}

// Render emits the deterministic complete Message-Instance field.
func (m MessageInstance) Render(limits RenderLimits) ([]byte, error) {
	if m.number == 0 || len(m.hashes) != 1 || !m.hashes[0].known || m.hashes[0].name != HashAlgorithmSHA256 ||
		m.hashes[0].headerHash.DecodedLen() != sha256HashBytes || m.hashes[0].bodyHash.DecodedLen() != sha256HashBytes {
		return nil, newError(ErrorCodeInvalidConstruction, ErrorLocation{}, ErrorDetails{}, nil)
	}
	recipeBytes := 0
	if m.hasRecipe {
		recipeBytes = m.recipe.DecodedLen()
	}
	size, err := PreflightSigningField(m.number, recipeBytes, m.hasRecipe, limits)
	if err != nil {
		return nil, err
	}
	resolved, err := limits.normalized()
	if err != nil {
		return nil, err
	}
	var builder bytes.Buffer
	builder.Grow(size)
	emitter := &instanceEmitter{limits: resolved, builder: &builder}
	emitSigningField(emitter, m.number, m.hashes[0].headerHash.EncodedString(), m.hashes[0].bodyHash.EncodedString(), m.recipe.EncodedString(), recipeBytes, m.hasRecipe)
	if emitter.err != nil || emitter.size != size {
		return nil, newError(ErrorCodeRenderInvariant, ErrorLocation{}, ErrorDetails{}, nil)
	}
	return builder.Bytes(), nil
}

// String returns a secret-safe Message-Instance summary.
func (m MessageInstance) String() string { return "instance.MessageInstance{redacted}" }

// GoString returns a secret-safe Message-Instance Go representation.
func (m MessageInstance) GoString() string { return m.String() }

// Format routes every fmt form through the secret-safe summary.
func (m MessageInstance) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, m.String()) }

// String returns a secret-safe hash-set summary.
func (h HashSet) String() string { return "instance.HashSet{redacted}" }

// GoString returns a secret-safe hash-set Go representation.
func (h HashSet) GoString() string { return h.String() }

// Format routes every fmt form through the secret-safe hash-set summary.
func (h HashSet) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, h.String()) }

// parseGeneratedBase64 creates one immutable strict Base64 container.
func parseGeneratedBase64(decoded []byte) (tagvalue.Base64String, error) {
	parsed, err := tagvalue.ParseBase64String([]byte(tagvalue.EncodeBase64(decoded)), tagvalue.DefaultLimits())
	if err != nil {
		return tagvalue.Base64String{}, newError(ErrorCodeRenderInvariant, ErrorLocation{}, ErrorDetails{}, nil)
	}
	return parsed, nil
}

// instanceEmitter shares exact field and line accounting between preflight and rendering.
type instanceEmitter struct {
	limits  RenderLimits
	builder *bytes.Buffer
	size    int
	line    int
	err     error
}

// emitSigningField owns the single frozen Message-Instance tag and FWS grammar.
func emitSigningField(e *instanceEmitter, number uint64, headerHash, bodyHash, recipe string, recipeBytes int, recipePresent bool) {
	e.text("Message-Instance: m=")
	e.text(strconv.FormatUint(number, 10))
	e.text(";")
	e.crlf()
	e.text("\th=sha256:")
	e.base64(headerHash, sha256HashBytes)
	e.text(":")
	e.base64(bodyHash, sha256HashBytes)
	e.text(";")
	e.crlf()
	if recipePresent {
		e.text("\tr=")
		e.base64(recipe, recipeBytes)
		e.text(";")
		e.crlf()
	}
}

// text accounts for and optionally writes one no-CRLF segment.
func (e *instanceEmitter) text(value string) {
	e.textCount(len(value))
	if e.err == nil && e.builder != nil {
		e.builder.WriteString(value)
	}
}

// textCount accounts for one no-CRLF segment without allocating content.
func (e *instanceEmitter) textCount(count int) {
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

// crlf accounts for and optionally writes one physical-line boundary.
func (e *instanceEmitter) crlf() {
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

// base64 accounts for and optionally writes padded Base64 in 64-character folds.
func (e *instanceEmitter) base64(encoded string, decodedBytes int) {
	encodedBytes, ok := tagvalue.WalkBase64Chunks(decodedBytes, nil)
	if !ok || e.builder != nil && len(encoded) != encodedBytes {
		e.err = newError(ErrorCodeRenderInvariant, ErrorLocation{}, ErrorDetails{}, nil)
		return
	}
	_, _ = tagvalue.WalkBase64Chunks(decodedBytes, func(first bool, offset, size int) {
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
}

// renderOptionsError constructs one bounded renderer-option failure.
func renderOptionsError(name string, actual int) *Error {
	return newError(ErrorCodeInvalidOptions, ErrorLocation{}, ErrorDetails{LimitName: LimitName(name), Count: actual}, nil)
}

// renderLimitError constructs one bounded renderer-limit failure.
func renderLimitError(name string, limit, actual int) *Error {
	return newError(ErrorCodeLimitExceeded, ErrorLocation{}, ErrorDetails{LimitName: LimitName(name), Limit: limit, Count: actual}, nil)
}
