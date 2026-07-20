package signing

import (
	"math"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
)

// Limits contains the signing increment's hard and narrowable ceilings.
type Limits struct {
	MaxMessageBytes                 int
	MaxHeaderBytes                  int
	MaxHeaderFields                 int
	MaxFieldBytes                   int
	MaxLineBytes                    int
	MaxInstances                    int
	MaxSignatures                   int
	MaxProtocolFields               int
	MaxHashSetsPerInstance          int
	MaxSignatureSetsPerField        int
	MaxTotalSignatureSets           int
	MaxPublicKeyLookups             int
	MaxSignatureInputBytes          int
	MaxCanonicalWorkBytes           int
	MaxGeneratedRecipients          int
	MaxParentOutputCopiesAndTickets int
	MaxEnvelopePathBytes            int
	MaxDecodedRecipeBytes           int
	MaxGeneratedSignatureSets       int
	MaxAuthorizationCalls           int
	MaxPrivateSigningCalls          int
	MaxNonceBytes                   int
	MinRSABits                      int
	MaxRSABits                      int
	RequiredRSAExponent             int
	MaxPrivateSignatureBytes        int
	Ed25519PublicKeyBytes           int
	Ed25519SignatureBytes           int
	MaxNewInstances                 int
	RequiredNewSignatures           int
}

// DefaultLimits returns the exact durable signing hard ceilings.
func DefaultLimits() Limits {
	instanceLimits := instance.DefaultLimits()
	instanceRender := instance.DefaultRenderLimits()
	signatureLimits := signature.DefaultLimits()
	signatureRender := signature.DefaultRenderLimits()
	return Limits{
		MaxMessageBytes: 32 * 1024 * 1024, MaxHeaderBytes: 1024 * 1024,
		MaxHeaderFields: rawmsg.DefaultParserOptions().MaxHeaderFields,
		MaxFieldBytes:   min(instanceRender.MaxFieldBytes, signatureRender.MaxFieldBytes),
		MaxLineBytes:    min(instanceRender.MaxLineBytes, signatureRender.MaxLineBytes),
		MaxInstances:    instanceLimits.MaxInstances, MaxSignatures: signatureLimits.MaxSignatures,
		MaxProtocolFields: 256, MaxHashSetsPerInstance: instanceLimits.MaxHashSets,
		MaxSignatureSetsPerField: signatureLimits.MaxSignatureSets, MaxTotalSignatureSets: 256,
		MaxPublicKeyLookups: 256, MaxSignatureInputBytes: 2 * 1024 * 1024,
		MaxCanonicalWorkBytes: 64 * 1024 * 1024, MaxGeneratedRecipients: signatureRender.MaxRecipients,
		MaxParentOutputCopiesAndTickets: 128, MaxEnvelopePathBytes: signatureRender.MaxEnvelopePathBytes,
		MaxDecodedRecipeBytes: instanceRender.MaxRecipeBytes, MaxGeneratedSignatureSets: signatureRender.MaxSignatureSets,
		MaxAuthorizationCalls: 4, MaxPrivateSigningCalls: 2, MaxNonceBytes: signatureRender.MaxNonceBytes,
		MinRSABits: 1024, MaxRSABits: 8192, RequiredRSAExponent: 65537,
		MaxPrivateSignatureBytes: signatureRender.MaxSignatureBytes, Ed25519PublicKeyBytes: 32,
		Ed25519SignatureBytes: 64, MaxNewInstances: 1, RequiredNewSignatures: 1,
	}
}

// Validate rejects widening, negative, exact-value, and coherence violations.
func (l Limits) Validate() error {
	hard := DefaultLimits()
	values := []struct {
		name        LimitName
		value       int
		hardMaximum int
	}{
		{LimitNameMaxMessageBytes, l.MaxMessageBytes, hard.MaxMessageBytes},
		{LimitNameMaxHeaderBytes, l.MaxHeaderBytes, hard.MaxHeaderBytes},
		{LimitNameMaxHeaderFields, l.MaxHeaderFields, hard.MaxHeaderFields},
		{LimitNameMaxFieldBytes, l.MaxFieldBytes, hard.MaxFieldBytes},
		{LimitNameMaxLineBytes, l.MaxLineBytes, hard.MaxLineBytes},
		{LimitNameMaxInstances, l.MaxInstances, hard.MaxInstances},
		{LimitNameMaxSignatures, l.MaxSignatures, hard.MaxSignatures},
		{LimitNameMaxProtocolFields, l.MaxProtocolFields, hard.MaxProtocolFields},
		{LimitNameMaxHashSetsPerInstance, l.MaxHashSetsPerInstance, hard.MaxHashSetsPerInstance},
		{LimitNameMaxSignatureSetsPerField, l.MaxSignatureSetsPerField, hard.MaxSignatureSetsPerField},
		{LimitNameMaxTotalSignatureSets, l.MaxTotalSignatureSets, hard.MaxTotalSignatureSets},
		{LimitNameMaxPublicKeyLookups, l.MaxPublicKeyLookups, hard.MaxPublicKeyLookups},
		{LimitNameMaxSignatureInputBytes, l.MaxSignatureInputBytes, hard.MaxSignatureInputBytes},
		{LimitNameMaxCanonicalWorkBytes, l.MaxCanonicalWorkBytes, hard.MaxCanonicalWorkBytes},
		{LimitNameMaxGeneratedRecipients, l.MaxGeneratedRecipients, hard.MaxGeneratedRecipients},
		{LimitNameMaxParentOutputCopiesAndTickets, l.MaxParentOutputCopiesAndTickets, hard.MaxParentOutputCopiesAndTickets},
		{LimitNameMaxEnvelopePathBytes, l.MaxEnvelopePathBytes, hard.MaxEnvelopePathBytes},
		{LimitNameMaxDecodedRecipeBytes, l.MaxDecodedRecipeBytes, hard.MaxDecodedRecipeBytes},
		{LimitNameMaxGeneratedSignatureSets, l.MaxGeneratedSignatureSets, hard.MaxGeneratedSignatureSets},
		{LimitNameMaxAuthorizationCalls, l.MaxAuthorizationCalls, hard.MaxAuthorizationCalls},
		{LimitNameMaxPrivateSigningCalls, l.MaxPrivateSigningCalls, hard.MaxPrivateSigningCalls},
		{LimitNameMaxNonceBytes, l.MaxNonceBytes, hard.MaxNonceBytes},
		{LimitNameMaxRSABits, l.MaxRSABits, hard.MaxRSABits},
		{LimitNameMaxPrivateSignatureBytes, l.MaxPrivateSignatureBytes, hard.MaxPrivateSignatureBytes},
		{LimitNameMaxNewInstances, l.MaxNewInstances, hard.MaxNewInstances},
	}
	for _, candidate := range values {
		if candidate.value <= 0 || candidate.value > candidate.hardMaximum {
			return optionsError(candidate.name, candidate.value)
		}
	}
	if l.MinRSABits < hard.MinRSABits || l.MinRSABits > l.MaxRSABits {
		return optionsError(LimitNameMinRSABits, l.MinRSABits)
	}
	if l.RequiredRSAExponent != hard.RequiredRSAExponent ||
		l.Ed25519PublicKeyBytes != hard.Ed25519PublicKeyBytes ||
		l.Ed25519SignatureBytes != hard.Ed25519SignatureBytes ||
		l.RequiredNewSignatures != hard.RequiredNewSignatures {
		return optionsError(LimitNameExactCryptographicContract, 0)
	}
	if l.MaxFieldBytes > l.MaxHeaderBytes || l.MaxHeaderBytes > l.MaxMessageBytes ||
		l.MaxGeneratedSignatureSets > l.MaxSignatureSetsPerField ||
		l.MaxGeneratedSignatureSets > l.MaxTotalSignatureSets ||
		l.MaxGeneratedSignatureSets > l.MaxPrivateSigningCalls ||
		l.MaxPrivateSignatureBytes < (l.MaxRSABits+7)/8 {
		return optionsError(LimitNameLimitCoherence, 0)
	}
	if _, err := instance.PreflightSigningField(1, l.MaxDecodedRecipeBytes, true, instance.RenderLimits{
		MaxFieldBytes: l.MaxFieldBytes, MaxLineBytes: l.MaxLineBytes, MaxRecipeBytes: l.MaxDecodedRecipeBytes,
	}); err != nil {
		return optionsError(LimitNameRecipeFieldCoherence, 0)
	}
	return nil
}

// normalized resolves zero values to defaults before validating them.
func (l Limits) normalized() (Limits, error) {
	defaults := DefaultLimits()
	input := []struct{ target, fallback *int }{
		{&l.MaxMessageBytes, &defaults.MaxMessageBytes}, {&l.MaxHeaderBytes, &defaults.MaxHeaderBytes},
		{&l.MaxHeaderFields, &defaults.MaxHeaderFields},
		{&l.MaxFieldBytes, &defaults.MaxFieldBytes}, {&l.MaxLineBytes, &defaults.MaxLineBytes},
		{&l.MaxInstances, &defaults.MaxInstances}, {&l.MaxSignatures, &defaults.MaxSignatures},
		{&l.MaxProtocolFields, &defaults.MaxProtocolFields}, {&l.MaxHashSetsPerInstance, &defaults.MaxHashSetsPerInstance},
		{&l.MaxSignatureSetsPerField, &defaults.MaxSignatureSetsPerField}, {&l.MaxTotalSignatureSets, &defaults.MaxTotalSignatureSets},
		{&l.MaxPublicKeyLookups, &defaults.MaxPublicKeyLookups}, {&l.MaxSignatureInputBytes, &defaults.MaxSignatureInputBytes},
		{&l.MaxCanonicalWorkBytes, &defaults.MaxCanonicalWorkBytes}, {&l.MaxGeneratedRecipients, &defaults.MaxGeneratedRecipients},
		{&l.MaxParentOutputCopiesAndTickets, &defaults.MaxParentOutputCopiesAndTickets}, {&l.MaxEnvelopePathBytes, &defaults.MaxEnvelopePathBytes},
		{&l.MaxDecodedRecipeBytes, &defaults.MaxDecodedRecipeBytes}, {&l.MaxGeneratedSignatureSets, &defaults.MaxGeneratedSignatureSets},
		{&l.MaxAuthorizationCalls, &defaults.MaxAuthorizationCalls}, {&l.MaxPrivateSigningCalls, &defaults.MaxPrivateSigningCalls},
		{&l.MaxNonceBytes, &defaults.MaxNonceBytes}, {&l.MinRSABits, &defaults.MinRSABits},
		{&l.MaxRSABits, &defaults.MaxRSABits}, {&l.RequiredRSAExponent, &defaults.RequiredRSAExponent},
		{&l.MaxPrivateSignatureBytes, &defaults.MaxPrivateSignatureBytes}, {&l.Ed25519PublicKeyBytes, &defaults.Ed25519PublicKeyBytes},
		{&l.Ed25519SignatureBytes, &defaults.Ed25519SignatureBytes}, {&l.MaxNewInstances, &defaults.MaxNewInstances},
		{&l.RequiredNewSignatures, &defaults.RequiredNewSignatures},
	}
	for _, value := range input {
		if *value.target == 0 {
			*value.target = *value.fallback
		}
	}
	if err := l.Validate(); err != nil {
		return Limits{}, err
	}
	return l, nil
}

// PreflightMessageInstanceField returns the exact rendered field size before allocation.
func PreflightMessageInstanceField(number uint64, recipeBytes int, recipePresent bool, limits Limits) (int, error) {
	resolved, err := limits.normalized()
	if err != nil {
		return 0, err
	}
	size, instanceErr := instance.PreflightSigningField(number, recipeBytes, recipePresent, instance.RenderLimits{
		MaxFieldBytes: resolved.MaxFieldBytes, MaxLineBytes: resolved.MaxLineBytes, MaxRecipeBytes: resolved.MaxDecodedRecipeBytes,
	})
	if instanceErr != nil {
		if recipeBytes > resolved.MaxDecodedRecipeBytes {
			return 0, limitError(LimitNameMaxDecodedRecipeBytes, resolved.MaxDecodedRecipeBytes, recipeBytes)
		}
		return 0, newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	return size, nil
}

// checkedAdd adds nonnegative integers without overflow.
func checkedAdd(left, right int) (int, bool) {
	if left < 0 || right < 0 || left > math.MaxInt-right {
		return math.MaxInt, false
	}
	return left + right, true
}

// optionsError constructs one bounded options failure.
func optionsError(name LimitName, actual int) *Error {
	return newError(ErrorCodeInvalidOptions, ErrorLocation{Phase: PhaseOptions}, ErrorDetails{LimitName: name, Actual: actual})
}

// limitError constructs one bounded limit failure.
func limitError(name LimitName, limit, actual int) *Error {
	return newError(ErrorCodeLimitExceeded, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{LimitName: name, Limit: limit, Actual: actual})
}
