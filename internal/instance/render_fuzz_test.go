package instance

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// FuzzMessageInstanceRender exercises deterministic construction, rendering, and parsing.
func FuzzMessageInstanceRender(f *testing.F) {
	f.Add(uint64(1), []byte("header"), []byte("body"), []byte(nil))
	f.Add(^uint64(0), bytes.Repeat([]byte{0xff}, 32), bytes.Repeat([]byte{0x80}, 32), []byte(`{"h":[]}`))

	f.Fuzz(func(t *testing.T, number uint64, headerSeed, bodySeed, recipeSeed []byte) {
		if number == 0 {
			number = 1
		}
		headerHash := fuzzInstanceDigest(headerSeed)
		bodyHash := fuzzInstanceDigest(bodySeed)
		recipe := bytes.Clone(recipeSeed)
		if len(recipe) > 1024 {
			recipe = recipe[:1024]
		}
		model, err := NewForSigning(SigningRequest{
			Number: number, HeaderHash: headerHash, BodyHash: bodyHash,
			Recipe: recipe, RecipePresent: len(recipe) > 0,
		})
		if err != nil {
			t.Fatalf("NewForSigning() rejected bounded input: %v", err)
		}
		first, err := model.Render(DefaultRenderLimits())
		if err != nil {
			t.Fatalf("Render() error = %v", err)
		}
		second, err := model.Render(DefaultRenderLimits())
		if err != nil || !bytes.Equal(first, second) {
			t.Fatalf("repeated Render() differs: error=%v", err)
		}
		message, err := rawmsg.Parse(first)
		if err != nil || message.Headers().Len() != 1 {
			t.Fatalf("rendered field parse error = %v", err)
		}
		parsed, err := Parse(message.Headers().Fields()[0])
		if err != nil || parsed.Number() != number {
			t.Fatalf("Parse() number=%d error=%v", parsed.Number(), err)
		}
		hashSet, status := parsed.SHA256HashSet()
		parsedHeader, headerOK := hashSet.HeaderHash()
		parsedBody, bodyOK := hashSet.BodyHash()
		if status != HashSelectionStatusSelected || !headerOK || !bodyOK ||
			!bytes.Equal(parsedHeader.Decoded(), headerHash) || !bytes.Equal(parsedBody.Decoded(), bodyHash) {
			t.Fatal("parsed hash tuple differs from the generated model")
		}
		parsedRecipe, recipePresent := parsed.Recipe()
		if recipePresent != (len(recipe) > 0) ||
			recipePresent && !bytes.Equal(parsedRecipe.Decoded(), recipe) {
			t.Fatal("parsed recipe differs from the generated model")
		}
	})
}

// fuzzInstanceDigest expands arbitrary input into one deterministic SHA-256-sized value.
func fuzzInstanceDigest(seed []byte) []byte {
	digest := make([]byte, 32)
	for index, value := range seed {
		digest[index%len(digest)] ^= value
	}
	if len(seed) >= 8 {
		binary.LittleEndian.PutUint64(digest[:8], binary.LittleEndian.Uint64(seed[:8]))
	}
	return digest
}
