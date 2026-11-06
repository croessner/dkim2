package verify

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/tagvalue"
)

// TestVerifierInstanceParserUsesRecipeDecodedByteLimit proves exact and one-over parser integration.
func TestVerifierInstanceParserUsesRecipeDecodedByteLimit(t *testing.T) {
	defaults := recipe.DefaultLimits()
	zeroConfigured := verifierInstanceLimits(DefaultLimits().MaxInstanceHashSets, recipe.Limits{})
	if zeroConfigured.TagLimits.MaxBase64DecodedBytes != defaults.MaxDecodedRecipeBytes {
		t.Fatalf("zero recipe limits resolved decoded bound = %d, want %d", zeroConfigured.TagLimits.MaxBase64DecodedBytes, defaults.MaxDecodedRecipeBytes)
	}
	configured := verifierInstanceLimits(DefaultLimits().MaxInstanceHashSets, defaults)
	if configured.TagLimits.MaxBase64DecodedBytes != defaults.MaxDecodedRecipeBytes {
		t.Fatalf("verifier decoded recipe limit = %d, want %d", configured.TagLimits.MaxBase64DecodedBytes, defaults.MaxDecodedRecipeBytes)
	}
	exactEncoded := []byte(base64.StdEncoding.EncodeToString(make([]byte, defaults.MaxDecodedRecipeBytes)))
	if parsed, err := tagvalue.ParseBase64String(exactEncoded, configured.TagLimits); err != nil || parsed.DecodedLen() != defaults.MaxDecodedRecipeBytes {
		t.Fatalf("exact default decoded recipe limit rejected: length=%d err=%v", parsed.DecodedLen(), err)
	}
	overEncoded := []byte(base64.StdEncoding.EncodeToString(make([]byte, defaults.MaxDecodedRecipeBytes+1)))
	if _, err := tagvalue.ParseBase64String(overEncoded, configured.TagLimits); !tagvalue.IsErrorCode(err, tagvalue.ErrorCodeLimitExceeded) {
		t.Fatalf("one-over default recipe was not rejected by wired tag limits: %v", err)
	}
	reachableDecodedLimit := configured.TagLimits
	reachableDecodedLimit.MaxFieldValueBytes = len(overEncoded)
	reachableDecodedLimit.MaxTagValueBytes = len(overEncoded)
	_, err := tagvalue.ParseBase64String(overEncoded, reachableDecodedLimit)
	var defaultTagErr *tagvalue.Error
	if !errors.As(err, &defaultTagErr) || defaultTagErr.Code() != tagvalue.ErrorCodeLimitExceeded || defaultTagErr.Limit() != defaults.MaxDecodedRecipeBytes || defaultTagErr.Count() != defaults.MaxDecodedRecipeBytes+1 {
		t.Fatalf("one-over default decoded recipe limit mismatch: %v", err)
	}

	limits := recipe.DefaultLimits()
	limits.MaxDecodedRecipeBytes = 32
	limits.MaxTotalLiteralBytes = 32
	limits.MaxDataStringBytes = 32
	parser, err := instance.NewParser(verifierInstanceLimits(DefaultLimits().MaxInstanceHashSets, limits))
	if err != nil {
		t.Fatalf("instance.NewParser() error = %v", err)
	}

	exact, err := parser.ParseField(verifierRecipeLimitField(t, make([]byte, limits.MaxDecodedRecipeBytes)))
	if err != nil {
		t.Fatalf("exact decoded recipe limit rejected: %v", err)
	}
	decoded, ok := exact.Recipe()
	if !ok || decoded.DecodedLen() != limits.MaxDecodedRecipeBytes {
		t.Fatalf("exact decoded recipe length = %d,%t", decoded.DecodedLen(), ok)
	}

	parsed, err := parser.ParseField(verifierRecipeLimitField(t, make([]byte, limits.MaxDecodedRecipeBytes+1)))
	var tagErr *tagvalue.Error
	if parsed.Number() != 0 || !instance.IsErrorCode(err, instance.ErrorCodeInvalidRecipeBase64) || !errors.As(err, &tagErr) || tagErr.Code() != tagvalue.ErrorCodeLimitExceeded || tagErr.Limit() != limits.MaxDecodedRecipeBytes || tagErr.Count() != limits.MaxDecodedRecipeBytes+1 {
		t.Fatalf("one-over decoded recipe limit mismatch: instance=%d err=%v", parsed.Number(), err)
	}
}

// verifierRecipeLimitField constructs one small parser-valid Message-Instance fixture.
func verifierRecipeLimitField(t *testing.T, decodedRecipe []byte) rawmsg.HeaderField {
	t.Helper()
	zeroHash := base64.StdEncoding.EncodeToString(make([]byte, 32))
	value := "m=1; h=sha256:" + zeroHash + ":" + zeroHash + "; r=" + base64.StdEncoding.EncodeToString(decodedRecipe) + ";"
	message, err := rawmsg.Parse([]byte("Message-Instance: " + value + "\r\n\r\n"))
	if err != nil {
		t.Fatalf("rawmsg fixture parse failed: bytes=%d", len(value))
	}
	fields := message.Headers().FieldsByName(strings.ToLower(instance.HeaderName))
	if len(fields) != 1 {
		t.Fatalf("Message-Instance fixture fields = %d", len(fields))
	}
	return fields[0]
}
