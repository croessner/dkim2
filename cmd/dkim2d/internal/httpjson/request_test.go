//nolint:goconst // Exact envelope fixtures remain local to independent mapper assertions.
package httpjson

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/wire"
)

// TestDecodeCanonicalBase64 enforces the standard padded canonical wire spelling.
func TestDecodeCanonicalBase64(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		text string
		want []byte
	}{
		{name: transportTestEmpty, text: "", want: []byte{}},
		{name: "one", text: "YQ==", want: []byte("a")},
		{name: "two", text: "YWI=", want: []byte("ab")},
		{name: "three", text: "YWJj", want: []byte("abc")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := decodeCanonicalBase64([]byte(test.text))
			if err != nil || !bytes.Equal(got, test.want) {
				t.Fatalf("decodeCanonicalBase64() = %x, %v", got, err)
			}
		})
	}

	for _, invalid := range []string{
		"YR==", "YWJ=", "YQ", "YQ=", "YQ===", "YQ==AA==", "YQ==\n",
		"YQ==\r\n", "YQ== ", "\tYQ==", "-Q==", "_Q==",
	} {
		if _, err := decodeCanonicalBase64([]byte(invalid)); !IsMappingError(err, MappingInvalidContract) {
			t.Fatalf("noncanonical %q error = %v", invalid, err)
		}
	}
}

// TestMapProcessRequestPreservesRawAndSMTPUTF8Bytes proves no message or envelope normalization.
func TestMapProcessRequestPreservesRawAndSMTPUTF8Bytes(t *testing.T) {
	t.Parallel()
	raw := []byte("From: \xc3\xa9@example.test\r\nX-Fold: a\r\n\tb\r\n\r\nbody\x00\xff")
	reverse := "<u\u0308ser@example.test>"
	recipients := []string{"<δοκιμή@example.test>", "<üser@xn--bcher-kva.test>"}
	input := processRequestFixture(t, raw, reverse, recipients)

	mapped, err := MapProcessRequest(input)
	if err != nil {
		t.Fatalf("MapProcessRequest() error = %v", err)
	}
	request, err := mapped.VerifyRequest()
	if err != nil {
		t.Fatalf("VerifyRequest() error = %v", err)
	}
	if !bytes.Equal(request.RawMessage(), raw) || !bytes.Equal(request.ReversePath(), []byte(reverse)) {
		t.Fatal("raw message or reverse path changed")
	}
	gotRecipients := request.ForwardPaths()
	for index := range recipients {
		if !bytes.Equal(gotRecipients[index], []byte(recipients[index])) {
			t.Fatalf("recipient %d changed", index)
		}
	}
}

// TestDomainRequestVerifyRequestReturnsImmutableValue proves repeated and concurrent access needs no second ownership copy.
func TestDomainRequestVerifyRequestReturnsImmutableValue(t *testing.T) {
	t.Parallel()
	raw := []byte("From: sender@example.test\r\n\r\nbody")
	reverse := []byte("<sender@example.test>")
	recipients := [][]byte{
		[]byte("<first@example.test>"),
		[]byte("<second@example.test>"),
	}
	input := processRequestFixture(
		t,
		raw,
		string(reverse),
		[]string{string(recipients[0]), string(recipients[1])},
	)
	mapped, err := MapProcessRequest(input)
	if err != nil {
		t.Fatalf("MapProcessRequest() error = %v", err)
	}

	first, err := mapped.VerifyRequest()
	if err != nil {
		t.Fatalf("first VerifyRequest() error = %v", err)
	}
	second, err := mapped.VerifyRequest()
	if err != nil {
		t.Fatalf("second VerifyRequest() error = %v", err)
	}
	if !bytes.Equal(first.RawMessage(), second.RawMessage()) ||
		!bytes.Equal(first.ReversePath(), second.ReversePath()) ||
		!equalByteSlices(first.ForwardPaths(), second.ForwardPaths()) {
		t.Fatal("repeated VerifyRequest() calls changed the immutable value")
	}

	firstRaw := first.RawMessage()
	firstReverse := first.ReversePath()
	firstRecipients := first.ForwardPaths()
	firstRaw[0] ^= 0xff
	firstReverse[0] ^= 0xff
	firstRecipients[0][0] ^= 0xff
	if !bytes.Equal(second.RawMessage(), raw) ||
		!bytes.Equal(second.ReversePath(), reverse) ||
		!equalByteSlices(second.ForwardPaths(), recipients) {
		t.Fatal("accessor mutation changed the stored immutable value")
	}

	const goroutines = 32
	var waitGroup sync.WaitGroup
	waitGroup.Add(goroutines)
	for range goroutines {
		go func() {
			defer waitGroup.Done()
			request, requestErr := mapped.VerifyRequest()
			if requestErr != nil {
				t.Errorf("concurrent VerifyRequest() error = %v", requestErr)
				return
			}
			if !bytes.Equal(request.RawMessage(), raw) ||
				!bytes.Equal(request.ReversePath(), reverse) ||
				!equalByteSlices(request.ForwardPaths(), recipients) {
				t.Error("concurrent VerifyRequest() changed the immutable value")
			}
		}()
	}
	waitGroup.Wait()
}

// TestZeroDomainRequestRejectsVerifyRequest proves absent mapper state fails closed.
func TestZeroDomainRequestRejectsVerifyRequest(t *testing.T) {
	t.Parallel()
	if _, err := (DomainRequest{}).VerifyRequest(); !IsMappingError(err, MappingInvalidContract) {
		t.Fatalf("zero VerifyRequest() error = %v", err)
	}
}

// TestMapProcessRequestRejectsInvalidTransportShapes proves failure is atomic and content-free.
func TestMapProcessRequestRejectsInvalidTransportShapes(t *testing.T) {
	t.Parallel()
	valid := processRequestFixture(t, []byte{}, "", []string{""})
	tests := []struct {
		name  string
		input generated.ProcessRequest
	}{
		{name: testZeroName, input: generated.ProcessRequest{}},
		{name: "wrong api", input: func() generated.ProcessRequest {
			value := valid
			value.ApiVersion = generated.APIVersion("future")
			return value
		}()},
		{name: "wrong draft", input: func() generated.ProcessRequest {
			value := valid
			value.Draft = generated.DraftVersion("future")
			return value
		}()},
		{name: "zero raw wrapper", input: func() generated.ProcessRequest {
			value := valid
			value.Message.RawRfc5322Base64 = wire.ProtectedString{}
			return value
		}()},
		{name: "no recipients", input: func() generated.ProcessRequest {
			value := valid
			value.Smtp.RcptTo = nil
			return value
		}()},
	}
	for _, test := range tests {
		if got, err := MapProcessRequest(test.input); !IsMappingError(err, MappingInvalidContract) ||
			!strings.Contains(fmt.Sprintf("%#v", got), domainRequestRedacted) {
			t.Fatalf("%s: result/error = %#v/%v", test.name, got, err)
		}
	}
}

// equalByteSlices reports whether two ordered byte-slice collections are identical.
func equalByteSlices(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index], right[index]) {
			return false
		}
	}
	return true
}

// TestMapProcessRequestClassifiesEnvelopeResourceBounds proves exact maxima and 413-class failures.
func TestMapProcessRequestClassifiesEnvelopeResourceBounds(t *testing.T) {
	t.Parallel()
	path256 := strings.Repeat("x", maxSMTPPathBytes)
	exact := processRequestFixture(t, nil, path256, make([]string, dkim2.HardMaxRecipients))
	for index := range exact.Smtp.RcptTo {
		value, err := wire.NewProtectedString(path256)
		if err != nil {
			t.Fatalf("NewProtectedString(path) error = %v", err)
		}
		exact.Smtp.RcptTo[index] = value
	}
	if _, err := MapProcessRequest(exact); err != nil {
		t.Fatalf("simultaneous envelope maximum error = %v", err)
	}

	reverseOver := processRequestFixture(t, nil, strings.Repeat("x", maxSMTPPathBytes+1), []string{""})
	if _, err := MapProcessRequest(reverseOver); !IsMappingError(err, MappingRequestTooLarge) {
		t.Fatalf("reverse-path maximum plus one error = %v", err)
	}
	recipientOver := processRequestFixture(t, nil, "", []string{strings.Repeat("x", maxSMTPPathBytes+1)})
	if _, err := MapProcessRequest(recipientOver); !IsMappingError(err, MappingRequestTooLarge) {
		t.Fatalf("forward-path maximum plus one error = %v", err)
	}

	countOver := exact
	countOver.Smtp.RcptTo = append(countOver.Smtp.RcptTo, exact.Smtp.RcptTo[0])
	if _, err := MapProcessRequest(countOver); !IsMappingError(err, MappingRequestTooLarge) {
		t.Fatalf("recipient-count maximum plus one error = %v", err)
	}
}

// TestMapProcessRequestCountsUnicodePathsInBytes proves scalar count cannot bypass SMTP path limits.
func TestMapProcessRequestCountsUnicodePathsInBytes(t *testing.T) {
	t.Parallel()
	exact := strings.Repeat("é", maxSMTPPathBytes/2)
	over := strings.Repeat("é", maxSMTPPathBytes/2+1)
	for _, testCase := range []struct {
		name       string
		reverse    string
		recipients []string
		wantLarge  bool
	}{
		{name: "reverse exact", reverse: exact, recipients: []string{""}},
		{name: "reverse over", reverse: over, recipients: []string{""}, wantLarge: true},
		{name: "recipient exact", recipients: []string{exact}},
		{name: "recipient over", recipients: []string{over}, wantLarge: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := MapProcessRequest(processRequestFixture(t, nil, testCase.reverse, testCase.recipients))
			if testCase.wantLarge && !IsMappingError(err, MappingRequestTooLarge) {
				t.Fatal("multibyte path above the byte bound was not rejected")
			}
			if !testCase.wantLarge && err != nil {
				t.Fatal("multibyte path at the byte bound was rejected")
			}
		})
	}
}

// TestMapProcessRequestFormattingIsContentFree proves DTO-to-domain ownership does not create a formatting leak.
func TestMapProcessRequestFormattingIsContentFree(t *testing.T) {
	t.Parallel()
	const marker = "TOXIC-RAW-MAPPER-MARKER"
	mapped, err := MapProcessRequest(processRequestFixture(t, []byte(marker), "<marker@example.test>", []string{"<recipient@example.test>"}))
	if err != nil {
		t.Fatalf("MapProcessRequest() error = %v", err)
	}
	values := []any{mapped, &mapped, any(mapped), []DomainRequest{mapped}, map[DomainRequest]bool{mapped: true}}
	var output strings.Builder
	for _, value := range values {
		fmt.Fprintf(&output, "%s %q %v %+v %#v %x %p\n", value, value, value, value, value, value, value)
	}
	formatted := output.String()
	if strings.Contains(formatted, marker) || strings.Contains(formatted, "recipient@example") || !strings.Contains(formatted, domainRequestRedacted) {
		t.Fatal("formatted domain request was not content-free")
	}
	if encoded, marshalErr := json.Marshal(mapped); marshalErr == nil || len(encoded) != 0 {
		t.Fatal("domain request allowed direct JSON serialization")
	}
	if encoded, marshalErr := mapped.MarshalText(); marshalErr == nil || len(encoded) != 0 {
		t.Fatal("domain request allowed direct text serialization")
	}
}

// TestMapProcessRequestAdmitsOnlyLocalScanEximFidelity proves exact receive-time ownership.
func TestMapProcessRequestAdmitsOnlyLocalScanEximFidelity(t *testing.T) {
	request := processRequestFixture(t, []byte("From: sender@example.test\r\n\r\nbody\r\n"), "<sender@example.test>", []string{"<recipient@example.net>"})
	localScan := generated.EximLocalScanObservedCrlf
	request.Message.Fidelity = &localScan
	if _, err := MapProcessRequest(request); err != nil {
		t.Fatal("Exim local-scan fidelity was rejected")
	}
	transport := generated.EximTransportFilterCrlf
	request.Message.Fidelity = &transport
	if _, err := MapProcessRequest(request); !IsMappingError(err, MappingInvalidContract) {
		t.Fatal("Exim transport-filter fidelity crossed into process")
	}
	request.Message.Fidelity = nil
	if _, err := MapProcessRequest(request); err != nil {
		t.Fatal("absent process fidelity did not preserve direct-raw compatibility")
	}
}

// TestDecodeCanonicalBase64Maximum proves the exact raw-message bound and its next canonical spelling.
func TestDecodeCanonicalBase64Maximum(t *testing.T) {
	raw := make([]byte, dkim2.HardMaxRawMessageBytes)
	encoded := base64.StdEncoding.EncodeToString(raw)
	if len(encoded) != maxEncodedMessageBytes {
		t.Fatalf("encoded length = %d", len(encoded))
	}
	if decoded, err := decodeCanonicalBase64([]byte(encoded)); err != nil || len(decoded) != len(raw) {
		t.Fatalf("maximum decode = %d, %v", len(decoded), err)
	}

	over := base64.StdEncoding.EncodeToString(make([]byte, dkim2.HardMaxRawMessageBytes+1))
	if _, err := decodeCanonicalBase64([]byte(over)); !IsMappingError(err, MappingRequestTooLarge) {
		t.Fatalf("maximum plus one error = %v", err)
	}
}

// FuzzDecodeCanonicalBase64 proves accepted values have one exact padded spelling.
func FuzzDecodeCanonicalBase64(f *testing.F) {
	for _, seed := range [][]byte{nil, []byte("YQ=="), []byte("YWI="), []byte("YWJj"), []byte("YR=="), []byte("YQ==\n")} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if len(encoded) > 4096 {
			return
		}
		decoded, err := decodeCanonicalBase64(encoded)
		if err != nil {
			return
		}
		if got := base64.StdEncoding.EncodeToString(decoded); !bytes.Equal(encoded, []byte(got)) {
			t.Fatal("accepted spelling was not canonical")
		}
	})
}

// FuzzMapProcessRequest proves successful mapping preserves every decoded byte.
func FuzzMapProcessRequest(f *testing.F) {
	f.Add([]byte("From: a@example.test\r\n\r\nbody\r\n"), "<>", "<a@example.test>")
	f.Add([]byte{}, "", "")
	f.Fuzz(func(t *testing.T, raw []byte, reverse, recipient string) {
		if len(raw) > 4096 || len(reverse) > 512 || len(recipient) > 512 ||
			!utf8.ValidString(reverse) || !utf8.ValidString(recipient) {
			return
		}
		input := processRequestFixture(t, raw, reverse, []string{recipient})
		mapped, err := MapProcessRequest(input)
		if err != nil {
			if !IsMappingError(err, MappingInvalidContract) && !IsMappingError(err, MappingRequestTooLarge) {
				t.Fatal("mapper returned an unclassified failure")
			}
			return
		}
		request, err := mapped.VerifyRequest()
		if err != nil || !bytes.Equal(request.RawMessage(), raw) ||
			!bytes.Equal(request.ReversePath(), []byte(reverse)) ||
			len(request.ForwardPaths()) != 1 ||
			!bytes.Equal(request.ForwardPaths()[0], []byte(recipient)) {
			t.Fatal("successful mapper changed decoded bytes")
		}
	})
}

// processRequestFixture constructs one generated request without weakening wrapper opacity.
func processRequestFixture(t testing.TB, raw []byte, reverse string, recipients []string) generated.ProcessRequest {
	t.Helper()
	message, err := wire.NewProtectedString(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("NewProtectedString(message) error = %v", err)
	}
	mailFrom, err := wire.NewProtectedString(reverse)
	if err != nil {
		t.Fatalf("NewProtectedString(mail_from) error = %v", err)
	}
	rcptTo := make([]wire.ProtectedString, len(recipients))
	for index, recipient := range recipients {
		rcptTo[index], err = wire.NewProtectedString(recipient)
		if err != nil {
			t.Fatalf("NewProtectedString(rcpt_to) error = %v", err)
		}
	}
	fidelity := generated.RawRfc5322
	return generated.ProcessRequest{
		ApiVersion: generated.V1,
		Draft:      generated.DraftIetfDkimDkim2Spec06,
		Message:    generated.MessageInput{RawRfc5322Base64: message, Fidelity: &fidelity},
		Smtp:       generated.SMTPInput{MailFrom: mailFrom, RcptTo: rcptTo},
	}
}
