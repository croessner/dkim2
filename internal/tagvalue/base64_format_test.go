package tagvalue

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
)

// TestBase64RenderingHelpersShareExactChunkLayout proves size, fold, and walk agreement.
func TestBase64RenderingHelpersShareExactChunkLayout(t *testing.T) {
	decoded := strings.Repeat("a", 49)
	encoded := EncodeBase64([]byte(decoded))
	if len(encoded) != 68 {
		t.Fatalf("encoded length = %d, want 68", len(encoded))
	}
	wantFolded := encoded[:64] + "\r\n\t" + encoded[64:]
	if got := FoldBase64(encoded); got != wantFolded {
		t.Fatal("FoldBase64() did not use the canonical 64-character boundary")
	}
	if got, ok := FoldedBase64Size(len(decoded)); !ok || got != len(wantFolded) {
		t.Fatalf("FoldedBase64Size() = %d, %t; want %d, true", got, ok, len(wantFolded))
	}
	var chunks []string
	encodedBytes, ok := WalkBase64Chunks(len(decoded), func(first bool, offset, size int) {
		chunks = append(chunks, fmt.Sprintf("%t:%d:%d", first, offset, size))
	})
	if !ok || encodedBytes != len(encoded) || strings.Join(chunks, ",") != "true:0:64,false:64:4" {
		t.Fatalf("WalkBase64Chunks() layout = %d, %t, %v", encodedBytes, ok, chunks)
	}
}

// TestBase64RenderingHelpersRejectArithmeticOverflow proves checked preflight math.
func TestBase64RenderingHelpersRejectArithmeticOverflow(t *testing.T) {
	if got, ok := WalkBase64Chunks(-1, nil); ok || got != math.MaxInt {
		t.Fatalf("negative WalkBase64Chunks() = %d, %t", got, ok)
	}
	if got, ok := FoldedBase64Size(math.MaxInt); ok || got != math.MaxInt {
		t.Fatalf("overflow FoldedBase64Size() = %d, %t", got, ok)
	}
}

// TestNextBase64ChunkDoesNotOverflowAtMaxInt proves final-offset arithmetic is bounded.
func TestNextBase64ChunkDoesNotOverflowAtMaxInt(t *testing.T) {
	encodedBytes := math.MaxInt - 3
	size, next, done := nextBase64Chunk(encodedBytes, encodedBytes-4)
	if size != 4 || next != encodedBytes || !done {
		t.Fatalf("final chunk = %d, %d, %t", size, next, done)
	}
	size, next, done = nextBase64Chunk(encodedBytes, encodedBytes-68)
	if size != 64 || next != encodedBytes-4 || done {
		t.Fatalf("penultimate chunk = %d, %d, %t", size, next, done)
	}
}

// TestBase64StringFormattingIsConstantAndSecretSafe proves every fmt form hides content and length.
func TestBase64StringFormattingIsConstantAndSecretSafe(t *testing.T) {
	marker := []byte("base64-secret-marker")
	value, err := ParseBase64String([]byte(EncodeBase64(marker)), DefaultLimits())
	if err != nil {
		t.Fatalf("ParseBase64String() error type = %T", err)
	}
	want := "tagvalue.Base64String{redacted}"
	for _, formatted := range []string{value.String(), value.GoString(), fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)} {
		if formatted != want {
			t.Fatalf("formatted Base64String differs from constant summary")
		}
		if strings.Contains(formatted, string(marker)) || strings.Contains(formatted, strconv.Itoa(len(marker))) {
			t.Fatalf("formatted Base64String exposed content or decoded length")
		}
	}
}
