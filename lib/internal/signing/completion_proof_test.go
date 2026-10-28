package signing

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
)

// completionProofFixture holds one completed signing field, its generated
// fields, and the source header fields split for byte-level recomposition.
type completionProofFixture struct {
	coordinator Coordinator
	completed   CompletedSigningField
	generated   [][]byte
	fields      [][]byte
	body        []byte
}

// newCompletionProofFixture completes one field and exposes the exact pieces
// the completion proof binds, without finalizing the message.
func newCompletionProofFixture(t *testing.T, harness signerHarness) completionProofFixture {
	t.Helper()
	authorizer := authorizerFunc(func(_ context.Context, query AuthorizationQuery) (AuthorizationResult, error) {
		return NewAuthorizationResult(query, AuthorizationAuthorized), nil
	})
	coordinator := harness.newCoordinatorWithAuthorizer(t, authorizer, harness.defaultSigner(t), Limits{})
	completed, recovery, err := coordinator.CompleteField(context.Background(), harness.request)
	if err != nil || !completed.Valid() || recovery.Valid() {
		t.Fatalf("CompleteField() field=%t recovery=%t error=%v", completed.Valid(), recovery.Valid(), err)
	}
	generated := make([][]byte, 0, 2)
	if completed.plan.HasNewInstance() {
		generated = append(generated, completed.plan.RenderedInstance())
	}
	generated = append(generated, completed.field.Bytes())
	source := completed.message
	fields := make([][]byte, 0, source.Headers().Len())
	for _, field := range source.Headers().Fields() {
		fields = append(fields, field.OriginalBytes())
	}
	return completionProofFixture{
		coordinator: coordinator, completed: completed, generated: generated, fields: fields,
		body: bytes.Clone(source.RawBytes()[source.Metadata().HeaderBytes:]),
	}
}

// compose parses one candidate final message built from complete fields in
// the given physical order followed by the unchanged separator and body.
func (f completionProofFixture) compose(t *testing.T, fields ...[]byte) rawmsg.Message {
	t.Helper()
	raw := bytes.Join(fields, nil)
	raw = append(raw, f.body...)
	message, err := rawmsg.Parse(raw)
	if err != nil {
		t.Fatalf("rawmsg.Parse(candidate) error = %v", err)
	}
	return message
}

// prove runs the completion proof over one candidate final message.
func (f completionProofFixture) prove(message rawmsg.Message) error {
	return f.coordinator.proveCompletedMessage(message, f.completed, f.generated)
}

// ordinaryIndex returns the first inherited field that is not a protocol field.
func (f completionProofFixture) ordinaryIndex(t *testing.T) int {
	t.Helper()
	for index, field := range f.fields {
		if !isProofProtocolField(field) {
			return index
		}
	}
	t.Fatal("fixture has no ordinary header field")
	return -1
}

// protocolIndexes returns the inherited protocol field positions.
func (f completionProofFixture) protocolIndexes() []int {
	indexes := make([]int, 0)
	for index, field := range f.fields {
		if isProofProtocolField(field) {
			indexes = append(indexes, index)
		}
	}
	return indexes
}

// isProofProtocolField reports whether one complete field is a
// Message-Instance or DKIM2-Signature field, compared case-insensitively.
func isProofProtocolField(field []byte) bool {
	colon := bytes.IndexByte(field, ':')
	if colon < 0 {
		return false
	}
	name := strings.ToLower(string(field[:colon]))
	return name == instance.HeaderName || name == signature.HeaderName
}

// joinProofFields concatenates field groups into one physical order.
func joinProofFields(groups ...[][]byte) [][]byte {
	joined := make([][]byte, 0)
	for _, group := range groups {
		joined = append(joined, group...)
	}
	return joined
}

// replacedProofField returns fields with the entry at index replaced by field.
func replacedProofField(fields [][]byte, index int, field []byte) [][]byte {
	output := joinProofFields(fields)
	output[index] = field
	return output
}

// TestCompletionProofIsIndependentOfTraceBlockPlacement proves the completion
// proof identifies this hop's fields by m= and i=: the generated block passes
// at the top, at the bottom, and between inherited fields, for an originator
// (new Message-Instance) and for a signer over an existing chain.
func TestCompletionProofIsIndependentOfTraceBlockPlacement(t *testing.T) {
	for name, harness := range map[string]func(*testing.T) signerHarness{
		"originator": func(t *testing.T) signerHarness { return newSignerHarness(t, AlgorithmEd25519SHA256) },
		"existing":   func(t *testing.T) signerHarness { return newExistingSignerHarness(t, AlgorithmEd25519SHA256) },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newCompletionProofFixture(t, harness(t))
			for placement, order := range map[string][][]byte{
				"top":    joinProofFields(fixture.generated, fixture.fields),
				"bottom": joinProofFields(fixture.fields, fixture.generated),
				"middle": joinProofFields(fixture.fields[:1], fixture.generated, fixture.fields[1:]),
			} {
				if err := fixture.prove(fixture.compose(t, order...)); err != nil {
					t.Fatalf("%s placement rejected: %v", placement, err)
				}
			}
		})
	}
}

// TestCompletionProofRejectsForgedAndReorderedProtocolFields proves the
// placement-independent proof still fails closed: a forged extra
// DKIM2-Signature or Message-Instance anywhere in the header, an altered or
// internally reordered generated block, a reordered inherited chain, or an
// extra field all fail with protocol tampering.
func TestCompletionProofRejectsForgedAndReorderedProtocolFields(t *testing.T) {
	t.Run("originator", func(t *testing.T) {
		fixture := newCompletionProofFixture(t, newSignerHarness(t, AlgorithmEd25519SHA256))
		if len(fixture.generated) != 2 {
			t.Fatalf("originator generated %d fields, want Message-Instance and DKIM2-Signature", len(fixture.generated))
		}
		ordinary := fixture.ordinaryIndex(t)
		instanceField, signatureField := fixture.generated[0], fixture.generated[1]
		// Alter the last t= digit so the field still parses with the same i=.
		altered := bytes.Clone(signatureField)
		timestamp := bytes.Index(altered, []byte("t="))
		if timestamp < 0 {
			t.Fatal("generated signature lacks t=")
		}
		digit := timestamp + 2
		for digit+1 < len(altered) && altered[digit+1] >= '0' && altered[digit+1] <= '9' {
			digit++
		}
		altered[digit] = '0' + (altered[digit]-'0'+1)%10
		cases := map[string][][]byte{
			"forged signature on top":           joinProofFields([][]byte{signatureField}, fixture.generated, replacedProofField(fixture.fields, ordinary, nil)),
			"forged signature below block":      joinProofFields(fixture.generated, replacedProofField(fixture.fields, ordinary, signatureField)),
			"forged signature at bottom":        joinProofFields(fixture.generated, removedProofField(fixture.fields, ordinary), [][]byte{signatureField}),
			"forged instance in inherited part": joinProofFields(fixture.generated, replacedProofField(fixture.fields, ordinary, instanceField)),
			"generated block reordered":         joinProofFields([][]byte{signatureField, instanceField}, fixture.fields),
			"generated signature altered":       joinProofFields([][]byte{instanceField, altered}, fixture.fields),
			"extra signature adds a field":      joinProofFields(fixture.generated, fixture.fields, [][]byte{signatureField}),
		}
		assertCompletionProofTampering(t, fixture, cases)
	})
	t.Run("existing", func(t *testing.T) {
		fixture := newCompletionProofFixture(t, newExistingSignerHarness(t, AlgorithmEd25519SHA256))
		protocol := fixture.protocolIndexes()
		if len(protocol) < 2 {
			t.Fatalf("existing fixture carries %d inherited protocol fields, want at least 2", len(protocol))
		}
		ordinary := fixture.ordinaryIndex(t)
		own := fixture.generated[len(fixture.generated)-1]
		inheritedSignature := fixture.fields[protocol[len(protocol)-1]]
		swapped := joinProofFields(fixture.fields)
		swapped[protocol[0]], swapped[protocol[1]] = swapped[protocol[1]], swapped[protocol[0]]
		cases := map[string][][]byte{
			"forged own signature in inherited part": joinProofFields(fixture.generated, replacedProofField(fixture.fields, ordinary, own)),
			"duplicate inherited signature on top":   joinProofFields([][]byte{inheritedSignature}, fixture.generated, removedProofField(fixture.fields, ordinary)),
			"duplicate inherited signature at end":   joinProofFields(fixture.generated, removedProofField(fixture.fields, ordinary), [][]byte{inheritedSignature}),
			"inherited chain reordered":              joinProofFields(fixture.generated, swapped),
		}
		assertCompletionProofTampering(t, fixture, cases)
	})
}

// removedProofField returns fields without the entry at index.
func removedProofField(fields [][]byte, index int) [][]byte {
	return joinProofFields(fields[:index], fields[index+1:])
}

// assertCompletionProofTampering requires every candidate order to fail with
// the closed protocol tampering code.
func assertCompletionProofTampering(t *testing.T, fixture completionProofFixture, cases map[string][][]byte) {
	t.Helper()
	for name, order := range cases {
		t.Run(name, func(t *testing.T) {
			present := make([][]byte, 0, len(order))
			for _, field := range order {
				if field != nil {
					present = append(present, field)
				}
			}
			if err := fixture.prove(fixture.compose(t, present...)); !IsErrorCode(err, ErrorCodeProtocolTampering) {
				t.Fatalf("proof error = %v, want %s", err, ErrorCodeProtocolTampering)
			}
		})
	}
}
