package rawmsg

import (
	"bytes"
	"testing"
)

// FuzzSignedMessageInsertion exercises exact inherited-byte preservation and bounded rejection.
func FuzzSignedMessageInsertion(f *testing.F) {
	f.Add([]byte("Subject: seed\r\n\r\nbody\r\n"), []byte("DKIM2-Signature: i=1;\r\n"))
	f.Add([]byte("Subject: header-only\r\n"), []byte("Message-Instance: m=1;\r\n"))
	f.Add([]byte("Subject: seed\n\nbody"), []byte("X: bad\n"))

	f.Fuzz(func(t *testing.T, sourceSeed, fieldSeed []byte) {
		if len(sourceSeed) > 4096 {
			sourceSeed = sourceSeed[:4096]
		}
		if len(fieldSeed) > 2048 {
			fieldSeed = fieldSeed[:2048]
		}
		source, sourceErr := Parse(sourceSeed)
		if sourceErr != nil {
			return
		}
		request := InsertionRequest{
			Message: source, TransportForm: TransportFormFinalNetworkPreDotStuffing,
			Fields: [][]byte{bytes.Clone(fieldSeed)}, Options: DefaultParserOptions(),
		}
		first, firstErr := InsertValidatedFields(request)
		second, secondErr := InsertValidatedFields(request)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("repeated insertion classification differs: first=%v second=%v", firstErr, secondErr)
		}
		if firstErr != nil {
			return
		}
		if !first.Initialized() || !second.Initialized() ||
			!bytes.Equal(first.RawBytes(), second.RawBytes()) {
			t.Fatal("successful repeated insertion differs")
		}
		sourceFields := source.Headers().Fields()
		insertedFields := first.Headers().Fields()
		if len(insertedFields) != len(sourceFields)+1 {
			t.Fatalf("inserted field count=%d, want %d", len(insertedFields), len(sourceFields)+1)
		}
		for index := range sourceFields {
			if !bytes.Equal(sourceFields[index].OriginalBytes(), insertedFields[index].OriginalBytes()) {
				t.Fatalf("inherited field %d changed", index)
			}
		}
		if !bytes.Equal(insertedFields[len(sourceFields)].OriginalBytes(), fieldSeed) ||
			!bytes.Equal(source.Body().Bytes(), first.Body().Bytes()) ||
			source.Framing() != first.Framing() {
			t.Fatal("successful insertion changed field payload, body, or framing")
		}
	})
}
