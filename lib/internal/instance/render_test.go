package instance

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestMessageInstanceSigningModelRendersDeterministically verifies tag order and FWS.
func TestMessageInstanceSigningModelRendersDeterministically(t *testing.T) {
	headerHash := bytes.Repeat([]byte{0x11}, 32)
	bodyHash := bytes.Repeat([]byte{0x22}, 32)
	recipe := []byte(`{"h":{"subject":[{"d":"old"}]}}`)
	model, err := NewForSigning(SigningRequest{Number: 7, HeaderHash: headerHash, BodyHash: bodyHash, Recipe: recipe, RecipePresent: true})
	if err != nil {
		t.Fatalf("NewForSigning() code=%s", instanceTestErrorCode(err))
	}

	got, err := model.Render(RenderLimits{})
	if err != nil {
		t.Fatalf("Render() code=%s", instanceTestErrorCode(err))
	}
	want := "Message-Instance: m=7;\r\n" +
		"\th=sha256:" + base64.StdEncoding.EncodeToString(headerHash) + ":" + base64.StdEncoding.EncodeToString(bodyHash) + ";\r\n" +
		"\tr=" + base64.StdEncoding.EncodeToString(recipe) + ";\r\n"
	if string(got) != want {
		t.Fatalf("Render() deterministic equality=false got_length=%d want_length=%d", len(got), len(want))
	}
	encodedHeaderHash := []byte(base64.StdEncoding.EncodeToString(headerHash))
	if !bytes.Equal(model.HashSets()[0].HeaderHashValue(), encodedHeaderHash) {
		t.Fatal("constructed hash accessor does not preserve canonical wire semantics")
	}
	sets := model.HashSets()
	setHash := sets[0].HeaderHashValue()
	setHash[0] = 0xee
	sets[0] = HashSet{}
	if got := model.HashSets()[0].HeaderHashValue()[0]; got != encodedHeaderHash[0] {
		t.Fatalf("returned hash-set mutation changed model byte to %x", got)
	}
	parsed := parseRawMessage(t, string(got)+"\r\nbody")
	fields := parsed.Headers().FieldsByName(HeaderName)
	if len(fields) != 1 {
		t.Fatalf("rendered field count=%d", len(fields))
	}
	roundTrip, err := Parse(fields[0])
	if err != nil {
		t.Fatalf("rendered field round trip code=%s", instanceTestErrorCode(err))
	}
	if !bytes.Equal(roundTrip.HashSets()[0].HeaderHashValue(), model.HashSets()[0].HeaderHashValue()) {
		t.Fatal("generated and parsed hash accessors have different semantics")
	}
	headerHash[0], bodyHash[0], recipe[0] = 0xff, 0xff, 0xff
	regot, err := model.Render(RenderLimits{})
	if err != nil || string(regot) != want {
		t.Fatalf("caller mutation changed model: equal=%t code=%s", string(regot) == want, instanceTestErrorCode(err))
	}
}

// TestMessageInstanceRecipeLimitAndFolding verifies exact/one-over recipe behavior.
func TestMessageInstanceRecipeLimitAndFolding(t *testing.T) {
	request := SigningRequest{
		Number: 1, HeaderHash: bytes.Repeat([]byte{1}, 32), BodyHash: bytes.Repeat([]byte{2}, 32),
		Recipe: bytes.Repeat([]byte{'x'}, 45*1024), RecipePresent: true,
	}
	model, err := NewForSigning(request)
	if err != nil {
		t.Fatalf("exact recipe NewForSigning() code=%s", instanceTestErrorCode(err))
	}
	rendered, err := model.Render(RenderLimits{})
	if err != nil {
		t.Fatalf("exact recipe Render() code=%s", instanceTestErrorCode(err))
	}
	if len(rendered) > 64*1024 {
		t.Fatalf("rendered field size = %d", len(rendered))
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(rendered), "\r\n"), "\r\n") {
		if len(line) > 998 {
			t.Fatalf("physical line length = %d", len(line))
		}
	}
	encodedRecipe := base64.StdEncoding.EncodeToString(request.Recipe)
	if !bytes.Contains(rendered, []byte(foldBase64ForTest(encodedRecipe))) {
		t.Fatal("long recipe did not use exact 64-character CRLF HTAB folding")
	}
	request.Recipe = append(request.Recipe, 'x')
	if _, err := NewForSigning(request); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("one-over recipe code=%s", instanceTestErrorCode(err))
	}
}

// TestMessageInstancePreflightMatchesRenderAndRejectsLineOneOver proves pre-allocation accounting.
func TestMessageInstancePreflightMatchesRenderAndRejectsLineOneOver(t *testing.T) {
	for _, test := range []struct {
		name          string
		recipeBytes   int
		recipePresent bool
	}{
		{name: "without recipe"},
		{name: "exact recipe", recipeBytes: 45 * 1024, recipePresent: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			size, err := PreflightSigningField(1, test.recipeBytes, test.recipePresent, RenderLimits{})
			if err != nil {
				t.Fatalf("PreflightSigningField() code=%s", instanceTestErrorCode(err))
			}
			request := SigningRequest{Number: 1, HeaderHash: bytes.Repeat([]byte{1}, 32), BodyHash: bytes.Repeat([]byte{2}, 32)}
			if test.recipePresent {
				request.Recipe = bytes.Repeat([]byte{'x'}, test.recipeBytes)
				request.RecipePresent = true
			}
			model, err := NewForSigning(request)
			if err != nil {
				t.Fatalf("NewForSigning() code=%s", instanceTestErrorCode(err))
			}
			rendered, err := model.Render(RenderLimits{})
			if err != nil || len(rendered) != size {
				t.Fatalf("preflight/render size equality=%t code=%s", len(rendered) == size, instanceTestErrorCode(err))
			}
		})
	}
	const exactLongestLine = 100
	if _, err := PreflightSigningField(1, 0, false, RenderLimits{MaxLineBytes: exactLongestLine}); err != nil {
		t.Fatalf("exact line preflight code=%s", instanceTestErrorCode(err))
	}
	if _, err := PreflightSigningField(1, 0, false, RenderLimits{MaxLineBytes: exactLongestLine - 1}); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("one-over line preflight code=%s", instanceTestErrorCode(err))
	}
}

// foldBase64ForTest returns the frozen 64-character CRLF HTAB representation.
func foldBase64ForTest(encoded string) string {
	var builder strings.Builder
	for start := 0; start < len(encoded); start += 64 {
		if start > 0 {
			builder.WriteString("\r\n\t")
		}
		end := min(start+64, len(encoded))
		builder.WriteString(encoded[start:end])
	}
	return builder.String()
}

// TestMessageInstanceFormattingIsRedacted verifies all fmt forms hide model content.
func TestMessageInstanceFormattingIsRedacted(t *testing.T) {
	request := SigningRequest{
		Number: 1, HeaderHash: bytes.Repeat([]byte{1}, 32), BodyHash: bytes.Repeat([]byte{2}, 32),
		Recipe: []byte("secret-instance-recipe-marker"), RecipePresent: true,
	}
	for _, value := range []string{fmt.Sprintf("%v", request), fmt.Sprintf("%+v", request), fmt.Sprintf("%#v", request), request.String(), request.GoString()} {
		if strings.Contains(value, "secret-instance-recipe-marker") || !strings.Contains(value, "redacted") {
			t.Fatal("signing request formatting was not redacted")
		}
	}
	model, err := NewForSigning(request)
	if err != nil {
		t.Fatalf("NewForSigning() code = %s", instanceTestErrorCode(err))
	}
	for _, value := range []string{fmt.Sprintf("%v", model), fmt.Sprintf("%+v", model), fmt.Sprintf("%#v", model), model.String(), model.GoString()} {
		if strings.Contains(value, "secret-instance-recipe-marker") || !strings.Contains(value, "redacted") {
			t.Fatal("model formatting was not redacted")
		}
	}
	secretHashSet := HashSet{headerHashValue: []byte("secret-instance-recipe-marker"), bodyHashValue: []byte("secret-instance-recipe-marker")}
	for _, value := range []string{fmt.Sprintf("%v", secretHashSet), fmt.Sprintf("%+v", secretHashSet), fmt.Sprintf("%#v", secretHashSet), secretHashSet.String(), secretHashSet.GoString()} {
		if strings.Contains(value, "secret-instance-recipe-marker") || !strings.Contains(value, "redacted") {
			t.Fatal("hash-set formatting was not redacted")
		}
	}
}

// instanceTestErrorCode returns a safe code without formatting arbitrary errors.
func instanceTestErrorCode(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code()
	}
	return ""
}
