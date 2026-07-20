package tagvalue

import (
	"encoding/base64"
	"math"
	"strings"
)

const renderedBase64ChunkBytes = 64

// EncodeBase64 returns canonical padded RFC 4648 Base64 for immutable input.
func EncodeBase64(input []byte) string {
	return base64.StdEncoding.EncodeToString(input)
}

// FoldBase64 inserts exact CRLF HTAB boundaries after each 64-character chunk.
func FoldBase64(encoded string) string {
	if len(encoded) <= renderedBase64ChunkBytes {
		return encoded
	}
	var builder strings.Builder
	builder.Grow(len(encoded) + (len(encoded)-1)/renderedBase64ChunkBytes*3)
	walkEncodedBase64Chunks(len(encoded), func(first bool, offset, size int) {
		if !first {
			builder.WriteString("\r\n\t")
		}
		builder.WriteString(encoded[offset : offset+size])
	})
	return builder.String()
}

// FoldedBase64Size returns the exact padded encoding and fold byte count.
func FoldedBase64Size(decodedBytes int) (int, bool) {
	encoded, ok := base64EncodedSize(decodedBytes)
	if !ok {
		return math.MaxInt, false
	}
	if encoded == 0 {
		return 0, true
	}
	folds := (encoded - 1) / renderedBase64ChunkBytes
	if folds > (math.MaxInt-encoded)/3 {
		return math.MaxInt, false
	}
	return encoded + folds*3, true
}

// WalkBase64Chunks visits the exact canonical chunks for a decoded byte count.
func WalkBase64Chunks(decodedBytes int, visit func(first bool, offset, size int)) (int, bool) {
	encodedBytes, ok := base64EncodedSize(decodedBytes)
	if !ok {
		return math.MaxInt, false
	}
	walkEncodedBase64Chunks(encodedBytes, visit)
	return encodedBytes, true
}

// base64EncodedSize returns the checked canonical padded Base64 length.
func base64EncodedSize(decodedBytes int) (int, bool) {
	if decodedBytes < 0 || decodedBytes > math.MaxInt-2 {
		return math.MaxInt, false
	}
	groups := (decodedBytes + 2) / 3
	if groups > math.MaxInt/4 {
		return math.MaxInt, false
	}
	return groups * 4, true
}

// walkEncodedBase64Chunks owns the exact 64-character chunk boundaries.
func walkEncodedBase64Chunks(encodedBytes int, visit func(first bool, offset, size int)) {
	if visit == nil {
		return
	}
	for offset := 0; offset < encodedBytes; {
		size, next, done := nextBase64Chunk(encodedBytes, offset)
		visit(offset == 0, offset, size)
		if done {
			return
		}
		offset = next
	}
}

// nextBase64Chunk advances without adding beyond the final representable offset.
func nextBase64Chunk(encodedBytes, offset int) (size, next int, done bool) {
	remaining := encodedBytes - offset
	size = min(renderedBase64ChunkBytes, remaining)
	if size == remaining {
		return size, encodedBytes, true
	}
	return size, offset + size, false
}
