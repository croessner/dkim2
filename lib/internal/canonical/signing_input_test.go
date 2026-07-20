package canonical

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/signature"
)

const (
	signingSelectorNew        = "new"
	signingLimitMaxFieldBytes = "max_field_bytes"
	signingLimitMaxFieldCount = "max_field_count"
)

// TestSignatureInputSelectionsRedactProtectedState verifies generic formatting cannot dump headers.
func TestSignatureInputSelectionsRedactProtectedState(t *testing.T) {
	for _, value := range []any{SignatureInputSelection{}, SigningInputSelection{}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			rendered := fmt.Sprintf(format, value)
			if !strings.Contains(rendered, "redacted") {
				t.Fatalf("format %q rendered %q", format, rendered)
			}
		}
	}
}

// TestSigningInputBuildsOriginFromGeneratedStructuredFields verifies the m=1/i=1 origin path.
func TestSigningInputBuildsOriginFromGeneratedStructuredFields(t *testing.T) {
	generated, generatedField := mustGeneratedSigningInstance(t, 1)
	target := mustSigningTarget(t, 1, 1, []signature.SetPlan{{
		Selector: "rsa-origin", Algorithm: signature.AlgorithmRSASHA256,
	}})
	headers := mustParseSignatureMessage(t, "Subject: ordinary\r\n").Headers()

	got, err := mustCanonicalizer(t).SigningInput(SigningInputSelection{
		Headers: headers, GeneratedInstance: generated, GeneratedInstanceField: generatedField,
		HasGeneratedInstance: true, Target: target,
	})
	if err != nil {
		t.Fatalf("SigningInput() error = %v", err)
	}

	want := append(signingCanonicalField(t, generatedField), signingCanonicalField(t, target.UnsignedBytes())...)
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("SigningInput() = %q, want %q", got.Bytes(), want)
	}
	metadata := got.Metadata()
	if metadata.IncludedFields != 2 || metadata.ExcludedFields != 1 || metadata.InputBytes != len(generatedField)+len(target.UnsignedBytes()) {
		t.Fatalf("SigningInput() metadata = %+v, want two protocol fields and one excluded ordinary field", metadata)
	}
}

// TestSigningInputBuildsUnchangedExistingRevision verifies a new signature may cover the current instance.
func TestSigningInputBuildsUnchangedExistingRevision(t *testing.T) {
	headers := mustParseSignatureMessage(t,
		messageInstanceLine(1, "existing")+
			signatureLine(1, "old:rsa-sha256:"+base64Text("old signature"), "\r\n")+
			"Subject: excluded\r\n").Headers()
	target := mustSigningTarget(t, 2, 1, []signature.SetPlan{{
		Selector: signingSelectorNew, Algorithm: signature.AlgorithmRSASHA256,
	}})

	got, err := mustCanonicalizer(t).SigningInput(SigningInputSelection{
		Headers: headers,
		Target:  target,
	})
	if err != nil {
		t.Fatalf("SigningInput() error = %v", err)
	}

	output := string(got.Bytes())
	if !strings.Contains(output, "s=old:rsa-sha256:"+base64Text("old signature")+";") {
		t.Fatalf("SigningInput() omitted or nulled inherited complete signature: %q", output)
	}
	if !strings.HasSuffix(output, string(signingCanonicalField(t, target.UnsignedBytes()))) {
		t.Fatalf("SigningInput() target is not the final field: %q", output)
	}
	if strings.Contains(output, "subject:") {
		t.Fatalf("SigningInput() included ordinary header: %q", output)
	}
}

// TestSigningInputRequiresExactGeneratedPlannerBytes verifies generated Message-Instance authority.
func TestSigningInputRequiresExactGeneratedPlannerBytes(t *testing.T) {
	headers := mustParseSignatureMessage(t,
		messageInstanceLine(1, "existing")+
			signatureLine(1, "old:rsa-sha256:"+base64Text("old signature"), "\r\n")).Headers()
	generated, generatedField := mustGeneratedSigningInstance(t, 2)
	target := mustSigningTarget(t, 2, 2, []signature.SetPlan{{
		Selector: signingSelectorNew, Algorithm: signature.AlgorithmRSASHA256,
	}})

	got, err := mustCanonicalizer(t).SigningInput(SigningInputSelection{
		Headers: headers, GeneratedInstance: generated, GeneratedInstanceField: generatedField,
		HasGeneratedInstance: true, Target: target,
	})
	if err != nil {
		t.Fatalf("SigningInput() error = %v", err)
	}
	if !bytes.Contains(got.Bytes(), signingCanonicalField(t, generatedField)) {
		t.Fatalf("SigningInput() omitted exact generated planner field: %q", got.Bytes())
	}

	reflowed := bytes.Replace(generatedField, []byte("Message-Instance:"), []byte("message-instance:"), 1)
	if bytes.Equal(reflowed, generatedField) {
		t.Fatal("generated-field mismatch fixture did not change bytes")
	}
	_, err = mustCanonicalizer(t).SigningInput(SigningInputSelection{
		Headers: headers, GeneratedInstance: generated, GeneratedInstanceField: reflowed,
		HasGeneratedInstance: true, Target: target,
	})
	if !IsErrorCode(err, ErrorCodeMissingTarget) {
		t.Fatalf("SigningInput(reflowed planner field) error = %v, want missing target", err)
	}
}

// TestSigningInputOrdersSemanticSequencesAndNullsOnlyTarget verifies the Section 9.6 order.
func TestSigningInputOrdersSemanticSequencesAndNullsOnlyTarget(t *testing.T) {
	headers := mustParseSignatureMessage(t,
		messageInstanceLine(2, "second")+
			signatureLine(2, "old-b:rsa-sha256:"+base64Text("second signature"), "\r\n")+
			messageInstanceLine(1, "first")+
			signatureLine(1, "old-a:rsa-sha256:"+base64Text("first signature"), "\r\n")).Headers()
	target := mustSigningTarget(t, 3, 2, []signature.SetPlan{
		{Selector: "rsa-new", Algorithm: signature.AlgorithmRSASHA256},
		{Selector: "ed-new", Algorithm: signature.AlgorithmEd25519SHA256},
	})

	got, err := mustCanonicalizer(t).SigningInput(SigningInputSelection{Headers: headers, Target: target})
	if err != nil {
		t.Fatalf("SigningInput() error = %v", err)
	}

	output := string(got.Bytes())
	orderedTokens := []string{
		"message-instance:m=1;",
		"message-instance:m=2;",
		"dkim2-signature:i=1;",
		"dkim2-signature:i=2;",
		"dkim2-signature:i=3;",
	}
	offset := -1
	for _, token := range orderedTokens {
		next := strings.Index(output, token)
		if next <= offset {
			t.Fatalf("SigningInput() semantic order failed at %q: %q", token, output)
		}
		offset = next
	}
	targetText := string(signingCanonicalField(t, target.UnsignedBytes()))
	if !strings.HasSuffix(output, targetText) {
		t.Fatalf("SigningInput() target is not last: %q", output)
	}
	if !strings.Contains(targetText, "s=rsa-new:rsa-sha256:,ed-new:ed25519-sha256:;") {
		t.Fatalf("SigningInput() target does not keep every s= empty: %q", targetText)
	}
	if !strings.Contains(output, base64Text("first signature")) || !strings.Contains(output, base64Text("second signature")) {
		t.Fatalf("SigningInput() did not retain inherited signature values: %q", output)
	}
}

// TestSigningInputRejectsPresenceContradictionsAndSequenceGaps verifies fail-closed selection.
func TestSigningInputRejectsPresenceContradictionsAndSequenceGaps(t *testing.T) {
	emptyHeaders := mustParseSignatureMessage(t, "Subject: ordinary\r\n").Headers()
	generatedOne, generatedOneField := mustGeneratedSigningInstance(t, 1)
	originTarget := mustSigningTarget(t, 1, 1, []signature.SetPlan{{
		Selector: signingSelectorNew, Algorithm: signature.AlgorithmRSASHA256,
	}})
	generatedTwo, generatedTwoField := mustGeneratedSigningInstance(t, 2)

	tests := []struct {
		name      string
		selection SigningInputSelection
	}{
		{
			name: "absent flag with model",
			selection: SigningInputSelection{
				Headers: emptyHeaders, GeneratedInstance: generatedOne, Target: originTarget,
			},
		},
		{
			name: "absent flag with bytes",
			selection: SigningInputSelection{
				Headers: emptyHeaders, GeneratedInstanceField: generatedOneField, Target: originTarget,
			},
		},
		{
			name: "present flag with zero model",
			selection: SigningInputSelection{
				Headers: emptyHeaders, GeneratedInstanceField: generatedOneField,
				HasGeneratedInstance: true, Target: originTarget,
			},
		},
		{
			name: "present flag without bytes",
			selection: SigningInputSelection{
				Headers: emptyHeaders, GeneratedInstance: generatedOne,
				HasGeneratedInstance: true, Target: originTarget,
			},
		},
		{
			name: "generated instance gap",
			selection: SigningInputSelection{
				Headers: emptyHeaders, GeneratedInstance: generatedTwo, GeneratedInstanceField: generatedTwoField,
				HasGeneratedInstance: true, Target: mustSigningTarget(t, 1, 2, []signature.SetPlan{{
					Selector: signingSelectorNew, Algorithm: signature.AlgorithmRSASHA256,
				}}),
			},
		},
		{
			name: "target signature gap",
			selection: SigningInputSelection{
				Headers: emptyHeaders, GeneratedInstance: generatedOne, GeneratedInstanceField: generatedOneField,
				HasGeneratedInstance: true, Target: mustSigningTarget(t, 2, 1, []signature.SetPlan{{
					Selector: signingSelectorNew, Algorithm: signature.AlgorithmRSASHA256,
				}}),
			},
		},
		{
			name: "target instance contradicts generated",
			selection: SigningInputSelection{
				Headers: emptyHeaders, GeneratedInstance: generatedOne, GeneratedInstanceField: generatedOneField,
				HasGeneratedInstance: true, Target: mustSigningTarget(t, 1, 2, []signature.SetPlan{{
					Selector: signingSelectorNew, Algorithm: signature.AlgorithmRSASHA256,
				}}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := mustCanonicalizer(t).SigningInput(tt.selection); !IsErrorCode(err, ErrorCodeMissingTarget) {
				t.Fatalf("SigningInput() error = %v, want missing target", err)
			}
		})
	}
}

// TestSigningInputHonorsExactAndOneOverLimits verifies exact field and input accounting.
func TestSigningInputHonorsExactAndOneOverLimits(t *testing.T) {
	generated, generatedField := mustGeneratedSigningInstance(t, 1)
	target := mustSigningTarget(t, 1, 1, []signature.SetPlan{{
		Selector: signingSelectorNew, Algorithm: signature.AlgorithmRSASHA256,
	}})
	selection := SigningInputSelection{
		Headers:           mustParseSignatureMessage(t, "Subject: excluded\r\n").Headers(),
		GeneratedInstance: generated, GeneratedInstanceField: generatedField,
		HasGeneratedInstance: true, Target: target,
	}
	baseline, err := mustCanonicalizer(t).SigningInput(selection)
	if err != nil {
		t.Fatalf("SigningInput() baseline error = %v", err)
	}
	maxFieldBytes := maxSigningFieldLength(baseline.Bytes())

	tests := []struct {
		name      string
		configure func(*Limits)
		wantError bool
		limitName string
	}{
		{
			name: "exact field bytes",
			configure: func(limits *Limits) {
				limits.MaxFieldBytes = maxFieldBytes
			},
		},
		{
			name: "one over field bytes",
			configure: func(limits *Limits) {
				limits.MaxFieldBytes = maxFieldBytes - 1
			},
			wantError: true, limitName: signingLimitMaxFieldBytes,
		},
		{
			name: "exact input bytes",
			configure: func(limits *Limits) {
				limits.MaxSignatureInputBytes = baseline.Len()
			},
		},
		{
			name: "one over input bytes",
			configure: func(limits *Limits) {
				limits.MaxSignatureInputBytes = baseline.Len() - 1
			},
			wantError: true, limitName: "max_signature_input_bytes",
		},
		{
			name: "exact field count",
			configure: func(limits *Limits) {
				limits.MaxFieldCount = 2
			},
		},
		{
			name: "one over field count",
			configure: func(limits *Limits) {
				limits.MaxFieldCount = 1
			},
			wantError: true, limitName: signingLimitMaxFieldCount,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limits := DefaultLimits()
			tt.configure(&limits)
			canonicalizer, newErr := NewCanonicalizer(WithLimits(limits))
			if newErr != nil {
				t.Fatalf("NewCanonicalizer() error = %v", newErr)
			}
			got, signingErr := canonicalizer.SigningInput(selection)
			if !tt.wantError {
				if signingErr != nil {
					t.Fatalf("SigningInput() error = %v", signingErr)
				}
				if !bytes.Equal(got.Bytes(), baseline.Bytes()) {
					t.Fatal("SigningInput() exact-limit bytes differ from baseline")
				}
				return
			}
			if !IsErrorCode(signingErr, ErrorCodeLimitExceeded) {
				t.Fatalf("SigningInput() error = %v, want limit exceeded", signingErr)
			}
			var canonicalErr *Error
			if !errors.As(signingErr, &canonicalErr) || canonicalErr.LimitName() != tt.limitName {
				t.Fatalf("SigningInput() error = %v, want limit %q", signingErr, tt.limitName)
			}
		})
	}
}

// TestSigningInputDetachesCallerAndResultBytes verifies immutable ownership boundaries.
func TestSigningInputDetachesCallerAndResultBytes(t *testing.T) {
	generated, generatedField := mustGeneratedSigningInstance(t, 1)
	target := mustSigningTarget(t, 1, 1, []signature.SetPlan{{
		Selector: signingSelectorNew, Algorithm: signature.AlgorithmRSASHA256,
	}})
	selection := SigningInputSelection{
		Headers:           mustParseSignatureMessage(t, "Subject: excluded\r\n").Headers(),
		GeneratedInstance: generated, GeneratedInstanceField: generatedField,
		HasGeneratedInstance: true, Target: target,
	}

	got, err := mustCanonicalizer(t).SigningInput(selection)
	if err != nil {
		t.Fatalf("SigningInput() error = %v", err)
	}
	want := got.Bytes()
	generatedField[0] ^= 0xff
	exposed := got.Bytes()
	exposed[0] ^= 0xff
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatal("SigningInput() retained caller or returned mutable byte storage")
	}
}

// mustGeneratedSigningInstance constructs one deterministic planner-owned Message-Instance.
func mustGeneratedSigningInstance(t *testing.T, number uint64) (instance.MessageInstance, []byte) {
	t.Helper()
	model, err := instance.NewForSigning(instance.SigningRequest{
		Number: number, HeaderHash: bytes.Repeat([]byte{0x21}, 32), BodyHash: bytes.Repeat([]byte{0x42}, 32),
	})
	if err != nil {
		t.Fatalf("instance.NewForSigning() error = %v", err)
	}
	rendered, err := model.Render(instance.DefaultRenderLimits())
	if err != nil {
		t.Fatalf("MessageInstance.Render() error = %v", err)
	}
	return model, rendered
}

// mustSigningTarget constructs one deterministic structured unsigned signature target.
func mustSigningTarget(t *testing.T, sequence, instanceNumber uint64, sets []signature.SetPlan) signature.UnsignedTarget {
	t.Helper()
	target, err := signature.NewUnsignedTarget(signature.TargetRequest{
		Sequence: sequence, InstanceNumber: instanceNumber, Timestamp: 1700000100 + sequence,
		MailFrom: []byte("<sender@example.test>"), Recipients: [][]byte{[]byte("<recipient@example.net>")},
		Domain: "signer.example", Sets: sets,
	}, signature.DefaultRenderLimits())
	if err != nil {
		t.Fatalf("signature.NewUnsignedTarget() error = %v", err)
	}
	return target
}

// signingCanonicalField independently applies the draft Section 9.6 field transform.
func signingCanonicalField(t *testing.T, field []byte) []byte {
	t.Helper()
	colon := bytes.IndexByte(field, ':')
	if colon <= 0 {
		t.Fatalf("generated field has no valid name separator: %q", field)
	}
	canonical := make([]byte, 0, len(field))
	canonical = append(canonical, strings.ToLower(string(field[:colon]))...)
	canonical = append(canonical, ':')
	for _, value := range field[colon+1:] {
		if value != ' ' && value != '\t' && value != '\r' && value != '\n' {
			canonical = append(canonical, value)
		}
	}
	return append(canonical, '\r', '\n')
}

// maxSigningFieldLength returns the longest CRLF-terminated canonical field.
func maxSigningFieldLength(input []byte) int {
	maximum := 0
	for _, field := range bytes.SplitAfter(input, []byte("\r\n")) {
		if len(field) > maximum {
			maximum = len(field)
		}
	}
	return maximum
}
