package canonical

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

const signatureInputSecretMarker = "secret"

// TestSignatureInputOrdersFieldsAndNullsTarget verifies Section 12.8 field order.
func TestSignatureInputOrdersFieldsAndNullsTarget(t *testing.T) {
	msg := mustParseSignatureMessage(t,
		messageInstanceLine(2, " \tlate value")+
			signatureLine(2, "sel-b:rsa-sha256:"+base64Text("target signature"), " n=target-note;\r\n")+
			messageInstanceLine(1, "early value")+
			signatureLine(1, "sel-a:rsa-sha256:"+base64Text("complete signature"), " f=feedback;\r\n")+
			strings.Replace(signatureLine(3, "sel-c:rsa-sha256:"+base64Text("later signature"), " n=later;\r\n"), "m=3", "m=2", 1))
	canonicalizer := mustCanonicalizer(t)

	got, err := canonicalizer.SignatureInputFromMessage(msg, 2)
	if err != nil {
		t.Fatalf("SignatureInputFromMessage() error = %v", err)
	}

	hash := sha256HashText()
	want := []byte(
		"message-instance:m=1;h=sha256:" + hash + ":" + hash + ";x=earlyvalue;\r\n" +
			"message-instance:m=2;h=sha256:" + hash + ":" + hash + ";x=latevalue;\r\n" +
			"dkim2-signature:i=1;m=1;t=1700000001;mf=PD4=;rt=PHJjcHRAZXhhbXBsZS5pbnZhbGlkPg==;d=signer.invalid;s=sel-a:rsa-sha256:" + base64Text("complete signature") + ";f=feedback;\r\n" +
			"dkim2-signature:i=2;m=2;t=1700000002;mf=PD4=;rt=PHJjcHRAZXhhbXBsZS5pbnZhbGlkPg==;d=signer.invalid;s=sel-b:rsa-sha256:;n=target-note;\r\n")
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("SignatureInputFromMessage() = %q, want %q", got.Bytes(), want)
	}

	metadata := got.Metadata()
	if metadata.IncludedFields != 4 {
		t.Fatalf("IncludedFields = %d, want 4", metadata.IncludedFields)
	}
	if metadata.ExcludedFields != 1 {
		t.Fatalf("ExcludedFields = %d, want 1 later signature", metadata.ExcludedFields)
	}
}

// TestSignatureInputNullsMultiAlgorithmSets verifies every s= value is nulled.
func TestSignatureInputNullsMultiAlgorithmSets(t *testing.T) {
	msg := mustParseSignatureMessage(t,
		messageInstanceLine(1, "state")+
			signatureLine(1,
				"sel-rsa:rsa-sha256:"+base64Text("rsa signature")+", sel-ed:ed25519-sha256:"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 64)),
				" x=kept extension;\r\n"))
	canonicalizer := mustCanonicalizer(t)

	got, err := canonicalizer.SignatureInputFromMessage(msg, 1)
	if err != nil {
		t.Fatalf("SignatureInputFromMessage() error = %v", err)
	}

	wantContains := "s=sel-rsa:rsa-sha256:,sel-ed:ed25519-sha256:"
	if !strings.Contains(string(got.Bytes()), wantContains) {
		t.Fatalf("SignatureInputFromMessage() = %q, want null multi-signature set", got.Bytes())
	}
	if strings.Contains(string(got.Bytes()), base64Text("rsa signature")) {
		t.Fatalf("SignatureInputFromMessage() kept target signature bytes: %q", got.Bytes())
	}
	if !strings.Contains(string(got.Bytes()), "x=keptextension") {
		t.Fatalf("SignatureInputFromMessage() dropped extension tag from target: %q", got.Bytes())
	}
}

// TestSignatureInputPreservesTargetValueSpellingAndTerminator verifies Draft-07
// target rendering fidelity for case-sensitive values and for target fields with
// and without the optional final semicolon.
func TestSignatureInputPreservesTargetValueSpellingAndTerminator(t *testing.T) {
	hash := sha256HashText()
	signatureText := base64Text("target signature")
	for _, terminator := range []string{";", ""} {
		msg := mustParseSignatureMessage(t,
			"Message-Instance: m=1; h=sha256:"+hash+":"+hash+";\r\n"+
				"DKIM2-Signature: i=1; m=1; t=1700000001; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS5pbnZhbGlkPg==; d=Signer.Invalid; s=Sel-A:rsa-sha256:"+signatureText+"; x_case=ValueCASE"+terminator+"\r\n")
		canonicalizer := mustCanonicalizer(t)

		got, err := canonicalizer.SignatureInputFromMessage(msg, 1)
		if err != nil {
			t.Fatalf("SignatureInputFromMessage(terminator=%q) error = %v", terminator, err)
		}

		wantTarget := "dkim2-signature:i=1;m=1;t=1700000001;mf=PD4=;rt=PHJjcHRAZXhhbXBsZS5pbnZhbGlkPg==;d=Signer.Invalid;s=Sel-A:rsa-sha256:;x_case=ValueCASE" + terminator + "\r\n"
		if !bytes.HasSuffix(got.Bytes(), []byte(wantTarget)) {
			t.Fatalf("SignatureInputFromMessage() = %q, want target suffix %q", got.Bytes(), wantTarget)
		}
		if bytes.Contains(got.Bytes(), []byte(signatureText)) {
			t.Fatalf("SignatureInputFromMessage() kept target signature bytes: %q", got.Bytes())
		}
	}
}

// TestSignatureInputRejectsUppercaseTargetTagName reproduces the Draft-07
// Section 10 lowercase tag-name requirement at the canonicalization boundary.
func TestSignatureInputRejectsUppercaseTargetTagName(t *testing.T) {
	hash := sha256HashText()
	msg := mustParseSignatureMessage(t,
		"Message-Instance: m=1; h=sha256:"+hash+":"+hash+";\r\n"+
			"DKIM2-Signature: i=1; m=1; t=1700000001; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS5pbnZhbGlkPg==; d=signer.invalid; S=sel:rsa-sha256:"+base64Text("sig")+";\r\n")
	if _, err := mustCanonicalizer(t).SignatureInputFromMessage(msg, 1); err == nil {
		t.Fatal("SignatureInputFromMessage() accepted an uppercase target tag name")
	}
}

// TestSignatureInputPreservesNextDomainEnvelopeForm verifies Draft-07 nd= target rendering.
func TestSignatureInputPreservesNextDomainEnvelopeForm(t *testing.T) {
	msg := mustParseSignatureMessage(t,
		messageInstanceLine(1, "state")+
			"DKIM2-Signature: i=1; m=1; t=1700000001; nd=Next.Invalid; d=signer.invalid; s=sel-a:rsa-sha256:"+base64Text("target signature")+";\r\n")

	got, err := mustCanonicalizer(t).SignatureInputFromMessage(msg, 1)
	if err != nil {
		t.Fatalf("SignatureInputFromMessage() error = %v", err)
	}
	if !bytes.Contains(got.Bytes(), []byte("nd=Next.Invalid;")) {
		t.Fatalf("SignatureInputFromMessage() = %q, want preserved nd= tag", got.Bytes())
	}
	if bytes.Contains(got.Bytes(), []byte(base64Text("target signature"))) {
		t.Fatalf("SignatureInputFromMessage() retained target signature bytes: %q", got.Bytes())
	}
}

// TestSignatureInputDeletesAllWSP verifies Section 12.8 does not compress WSP.
func TestSignatureInputDeletesAllWSP(t *testing.T) {
	msg := mustParseSignatureMessage(t,
		"Message-Instance:\tm = 1 ; h = sha256:"+sha256HashText()+":"+sha256HashText()+" ; x = alpha beta;\r\n"+
			signatureLine(1, "sel-a:rsa-sha256:"+base64Text("target signature"), " n=note value;\r\n"))
	canonicalizer := mustCanonicalizer(t)

	got, err := canonicalizer.SignatureInputFromMessage(msg, 1)
	if err != nil {
		t.Fatalf("SignatureInputFromMessage() error = %v", err)
	}

	if bytes.ContainsAny(got.Bytes(), " \t") {
		t.Fatalf("SignatureInputFromMessage() retained WSP: %q", got.Bytes())
	}
	if !bytes.Contains(got.Bytes(), []byte("x=alphabeta")) {
		t.Fatalf("SignatureInputFromMessage() compressed instead of deleting WSP: %q", got.Bytes())
	}
	if !bytes.HasSuffix(got.Bytes(), []byte("\r\n")) {
		t.Fatalf("SignatureInputFromMessage() did not retain final CRLF: %q", got.Bytes())
	}
}

// TestSignatureInputBytesAreImmutable verifies returned and parser bytes are not mutated.
func TestSignatureInputBytesAreImmutable(t *testing.T) {
	rawHeaders := []byte(messageInstanceLine(1, "state") +
		signatureLine(1, "sel-a:rsa-sha256:"+base64Text("target signature"), "\r\n"))
	msg := mustParseSignatureMessage(t, string(rawHeaders))
	canonicalizer := mustCanonicalizer(t)

	got, err := canonicalizer.SignatureInputFromMessage(msg, 1)
	if err != nil {
		t.Fatalf("SignatureInputFromMessage() error = %v", err)
	}

	rawHeaders[0] = 'X'
	exposed := got.Bytes()
	exposed[0] = 'X'
	if bytes.HasPrefix(got.Bytes(), []byte("X")) {
		t.Fatalf("canonical signature bytes were mutated: %q", got.Bytes())
	}
	if bytes.HasPrefix(msg.Headers().OriginalBytes(), []byte("X")) {
		t.Fatalf("raw header bytes were mutated: %q", msg.Headers().OriginalBytes())
	}
}

// TestSignatureInputRejectsMissingTarget verifies absent i= selection fails closed.
func TestSignatureInputRejectsMissingTarget(t *testing.T) {
	msg := mustParseSignatureMessage(t,
		messageInstanceLine(1, "state")+
			signatureLine(1, "sel-a:rsa-sha256:"+base64Text("target signature"), "\r\n"))
	canonicalizer := mustCanonicalizer(t)

	_, err := canonicalizer.SignatureInputFromMessage(msg, 2)
	if !IsErrorCode(err, ErrorCodeMissingTarget) {
		t.Fatalf("SignatureInputFromMessage() error = %v, want missing target", err)
	}
}

// TestSignatureInputRejectsDuplicateTargetIdentifiers verifies duplicate raw IDs fail.
func TestSignatureInputRejectsDuplicateTargetIdentifiers(t *testing.T) {
	msg := mustParseSignatureMessage(t,
		messageInstanceLine(1, "state")+
			signatureLine(1, "sel-a:rsa-sha256:"+base64Text("first signature"), "\r\n")+
			signatureLine(1, "sel-a:rsa-sha256:"+base64Text("target signature"), "\r\n"))
	canonicalizer := mustCanonicalizer(t)

	_, err := canonicalizer.SignatureInput(SignatureInputSelection{
		Headers:        msg.Headers(),
		TargetSequence: 1,
	})
	if err == nil {
		t.Fatal("SignatureInput() error = nil, want duplicate target rejection")
	}
}

// TestSignatureInputUsesHeaderBlockAsSoleAuthority verifies no independently supplied parsed state exists.
func TestSignatureInputUsesHeaderBlockAsSoleAuthority(t *testing.T) {
	other := mustParseSignatureMessage(t,
		messageInstanceLine(1, "other")+
			signatureLine(1, "sel-b:rsa-sha256:"+base64Text("other signature"), "\r\n"))
	canonicalizer := mustCanonicalizer(t)

	got, err := canonicalizer.SignatureInput(SignatureInputSelection{
		Headers:        other.Headers(),
		TargetSequence: 1,
	})
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}
	if !bytes.Contains(got.Bytes(), []byte("x=other")) || !bytes.Contains(got.Bytes(), []byte("s=sel-b:rsa-sha256:")) {
		t.Fatalf("SignatureInput() = %q, want fields derived from authoritative headers", got.Bytes())
	}
}

// TestSignatureInputEnforcesLimitsSecretSafely verifies bounded diagnostics.
func TestSignatureInputEnforcesLimitsSecretSafely(t *testing.T) {
	msg := mustParseSignatureMessage(t,
		messageInstanceLine(1, "secret marker")+
			signatureLine(1, "sel-a:rsa-sha256:"+base64Text("target secret signature"), "\r\n"))

	tests := []struct {
		name       string
		mutate     func(*Limits)
		limitName  string
		secretText string
	}{
		{
			name: "field count",
			mutate: func(limits *Limits) {
				limits.MaxFieldCount = 1
			},
			limitName:  "max_field_count",
			secretText: signatureInputSecretMarker,
		},
		{
			name: "field bytes",
			mutate: func(limits *Limits) {
				limits.MaxFieldBytes = 10
			},
			limitName:  "max_field_bytes",
			secretText: signatureInputSecretMarker,
		},
		{
			name: "signature input bytes",
			mutate: func(limits *Limits) {
				limits.MaxSignatureInputBytes = 10
			},
			limitName:  "max_signature_input_bytes",
			secretText: signatureInputSecretMarker,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limits := DefaultLimits()
			tt.mutate(&limits)
			canonicalizer, err := NewCanonicalizer(WithLimits(limits))
			if err != nil {
				t.Fatalf("NewCanonicalizer() error = %v", err)
			}

			_, err = canonicalizer.SignatureInput(SignatureInputSelection{
				Headers:        msg.Headers(),
				TargetSequence: 1,
			})
			if !IsErrorCode(err, ErrorCodeLimitExceeded) {
				t.Fatalf("SignatureInput() error = %v, want limit exceeded", err)
			}
			var canonicalErr *Error
			if !errors.As(err, &canonicalErr) {
				t.Fatalf("SignatureInput() error = %T, want *Error", err)
			}
			if canonicalErr.LimitName() != tt.limitName {
				t.Fatalf("LimitName() = %q, want %q", canonicalErr.LimitName(), tt.limitName)
			}
			if strings.Contains(err.Error(), tt.secretText) {
				t.Fatalf("SignatureInput() error leaked secret marker: %q", err.Error())
			}
		})
	}
}

// mustParseSignatureMessage parses synthetic DKIM2 protocol header fixtures.
func mustParseSignatureMessage(t *testing.T, headers string) rawmsg.Message {
	t.Helper()

	msg, err := rawmsg.Parse([]byte(headers + "\r\nbody"))
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}

	return msg
}

// messageInstanceLine renders a synthetic Message-Instance field.
func messageInstanceLine(number uint64, extensionValue string) string {
	hash := sha256HashText()

	return "Message-Instance: m=" + strconvFormat(number) + "; h=sha256:" + hash + ":" + hash + "; x=" + extensionValue + ";\r\n"
}

// signatureLine renders a synthetic DKIM2-Signature field.
func signatureLine(sequence uint64, signatureSets string, suffix string) string {
	return "DKIM2-Signature: i=" + strconvFormat(sequence) +
		"; m=" + strconvFormat(sequence) +
		"; t=170000000" + strconvFormat(sequence) +
		"; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS5pbnZhbGlkPg==; d=signer.invalid; s=" + signatureSets + ";" + suffix
}

// sha256HashText returns a padded synthetic 32-byte hash value.
func sha256HashText() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
}

// base64Text returns padded synthetic base64 text.
func base64Text(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}

// strconvFormat formats small synthetic sequence numbers.
func strconvFormat(value uint64) string {
	return strconv.FormatUint(value, 10)
}
