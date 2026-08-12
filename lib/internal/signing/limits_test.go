package signing

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
)

// TestDefaultLimitsMatchDurableSigningContract locks every shared signing ceiling.
func TestDefaultLimitsMatchDurableSigningContract(t *testing.T) {
	want := Limits{
		MaxMessageBytes:                 32 * 1024 * 1024,
		MaxHeaderBytes:                  1024 * 1024,
		MaxHeaderFields:                 rawmsg.DefaultParserOptions().MaxHeaderFields,
		MaxFieldBytes:                   64 * 1024,
		MaxLineBytes:                    998,
		MaxInstances:                    128,
		MaxSignatures:                   128,
		MaxProtocolFields:               256,
		MaxHashSetsPerInstance:          16,
		MaxSignatureSetsPerField:        16,
		MaxTotalSignatureSets:           256,
		MaxPublicKeyLookups:             256,
		MaxSignatureInputBytes:          2 * 1024 * 1024,
		MaxCanonicalWorkBytes:           64 * 1024 * 1024,
		MaxGeneratedRecipients:          128,
		MaxParentOutputCopiesAndTickets: 128,
		MaxEnvelopePathBytes:            32 * 1024,
		MaxDecodedRecipeBytes:           45 * 1024,
		MaxGeneratedSignatureSets:       2,
		MaxAuthorizationCalls:           4,
		MaxPrivateSigningCalls:          2,
		MaxNonceBytes:                   64,
		MinRSABits:                      1024,
		MaxRSABits:                      8192,
		RequiredRSAExponent:             65537,
		MaxPrivateSignatureBytes:        1024,
		Ed25519PublicKeyBytes:           32,
		Ed25519SignatureBytes:           64,
		MaxNewInstances:                 1,
		RequiredNewSignatures:           1,
	}
	if got := DefaultLimits(); got != want {
		t.Fatalf("DefaultLimits() mismatch: equal=%t", got == want)
	}
	if got, err := (Limits{}).normalized(); err != nil || got != want {
		t.Fatalf("zero limits normalization: code=%s equal=%t", testErrorCode(err), got == want)
	}

	typ := reflect.TypeFor[Limits]()
	if _, ok := typ.FieldByName("MaxParentCopies"); ok {
		t.Fatal("separate parent-copy limit must not exist")
	}
	if _, ok := typ.FieldByName("MaxCopyTickets"); ok {
		t.Fatal("separate copy-ticket limit must not exist")
	}
}

// TestLimitsAllowOnlyCoherentNarrowing verifies exact and one-over option behavior.
func TestLimitsAllowOnlyCoherentNarrowing(t *testing.T) {
	narrow := DefaultLimits()
	narrow.MaxGeneratedRecipients = 1
	narrow.MaxParentOutputCopiesAndTickets = 1
	narrow.MaxPublicKeyLookups = 1
	narrow.MinRSABits = 2048
	narrow.MaxRSABits = 4096
	if err := narrow.Validate(); err != nil {
		t.Fatalf("narrow limits code=%s", testErrorCode(err))
	}

	typ := reflect.TypeOf(DefaultLimits())
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		t.Run(field.Name, func(t *testing.T) {
			candidate := DefaultLimits()
			value := reflect.ValueOf(&candidate).Elem().Field(index)
			if field.Name == "MinRSABits" {
				value.SetInt(value.Int() - 1)
			} else {
				value.SetInt(value.Int() + 1)
			}
			if err := candidate.Validate(); !IsErrorCode(err, ErrorCodeInvalidOptions) {
				t.Fatalf("Validate() accepted widening/change for %s: code=%s", field.Name, testErrorCode(err))
			}
		})
	}
	negative := DefaultLimits()
	negative.MaxCanonicalWorkBytes = -1
	if err := negative.Validate(); !IsErrorCode(err, ErrorCodeInvalidOptions) {
		t.Fatalf("negative limit code=%s", testErrorCode(err))
	}
}

// TestLimitsRejectCrossResourceIncoherence verifies generated-set and RSA callback contracts.
func TestLimitsRejectCrossResourceIncoherence(t *testing.T) {
	generatedSets := DefaultLimits()
	generatedSets.MaxTotalSignatureSets = 1
	if err := generatedSets.Validate(); !IsErrorCode(err, ErrorCodeInvalidOptions) {
		t.Fatalf("generated-set incoherence code=%s", testErrorCode(err))
	}
	rsaCallback := DefaultLimits()
	rsaCallback.MaxPrivateSignatureBytes--
	if err := rsaCallback.Validate(); !IsErrorCode(err, ErrorCodeInvalidOptions) {
		t.Fatalf("RSA callback incoherence code=%s", testErrorCode(err))
	}
}

// TestRecipeFieldPreflightAcceptsExactAndRejectsOneOver proves the signing subset cap.
func TestRecipeFieldPreflightAcceptsExactAndRejectsOneOver(t *testing.T) {
	limits := DefaultLimits()
	size, err := PreflightMessageInstanceField(1, limits.MaxDecodedRecipeBytes, true, limits)
	if err != nil {
		t.Fatalf("exact recipe preflight code=%s", testErrorCode(err))
	}
	if size > limits.MaxFieldBytes {
		t.Fatalf("exact recipe field size = %d, limit %d", size, limits.MaxFieldBytes)
	}
	model, err := instance.NewForSigning(instance.SigningRequest{
		Number: 1, HeaderHash: bytes.Repeat([]byte{1}, 32), BodyHash: bytes.Repeat([]byte{2}, 32),
		Recipe: bytes.Repeat([]byte{'x'}, limits.MaxDecodedRecipeBytes), RecipePresent: true,
	})
	if err != nil {
		t.Fatalf("instance.NewForSigning() code=%s", instanceErrorCode(err))
	}
	rendered, err := model.Render(instance.RenderLimits{})
	if err != nil {
		t.Fatalf("MessageInstance.Render() code=%s", instanceErrorCode(err))
	}
	if size != len(rendered) {
		t.Fatalf("PreflightMessageInstanceField() = %d, rendered = %d", size, len(rendered))
	}
	if _, err := PreflightMessageInstanceField(1, limits.MaxDecodedRecipeBytes+1, true, limits); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("one-over recipe code=%s", testErrorCode(err))
	}
}

// instanceErrorCode returns a closed instance code without formatting arbitrary errors.
func instanceErrorCode(err error) instance.ErrorCode {
	var typed *instance.Error
	if errors.As(err, &typed) {
		return typed.Code()
	}
	return ""
}
