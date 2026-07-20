package dkim2

import (
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/routeplan"
	"github.com/croessner/dkim2/internal/signing"
	"github.com/croessner/dkim2/internal/verify"
)

// SigningLimits contains public narrow-only signing ceilings.
//
// Zero-valued fields use the corresponding hard default. Callers narrowing
// related dimensions must keep the resulting set coherent.
type SigningLimits struct {
	// MaxMessageBytes bounds exact input and completed output bytes.
	MaxMessageBytes int
	// MaxHeaderBytes bounds the completed raw header block.
	MaxHeaderBytes int
	// MaxHeaderFields bounds completed header occurrences.
	MaxHeaderFields int
	// MaxFieldBytes bounds one generated protocol field.
	MaxFieldBytes int
	// MaxLineBytes bounds one generated physical header line.
	MaxLineBytes int
	// MaxInstances bounds all Message-Instance fields.
	MaxInstances int
	// MaxSignatures bounds all DKIM2-Signature fields.
	MaxSignatures int
	// MaxProtocolFields bounds both protocol field families together.
	MaxProtocolFields int
	// MaxHashSetsPerInstance bounds hash sets in one instance.
	MaxHashSetsPerInstance int
	// MaxSignatureSetsPerField bounds signature sets in one field.
	MaxSignatureSetsPerField int
	// MaxTotalSignatureSets bounds inherited and generated signature sets.
	MaxTotalSignatureSets int
	// MaxPublicKeyLookups bounds inherited and generated publication lookups.
	MaxPublicKeyLookups int
	// MaxSignatureInputBytes bounds one Section 9.6 input.
	MaxSignatureInputBytes int
	// MaxCanonicalWorkBytes bounds aggregate canonical work.
	MaxCanonicalWorkBytes int
	// MaxGeneratedRecipients bounds recipients rendered into one new field.
	MaxGeneratedRecipients int
	// MaxParentOutputCopiesAndTickets bounds the coupled fanout cardinality.
	MaxParentOutputCopiesAndTickets int
	// MaxEnvelopePathBytes bounds decoded generated envelope paths.
	MaxEnvelopePathBytes int
	// MaxDecodedRecipeBytes bounds one generated or inherited recipe.
	MaxDecodedRecipeBytes int
	// MaxGeneratedSignatureSets bounds sets emitted in the new field.
	MaxGeneratedSignatureSets int
	// MaxAuthorizationCalls bounds applicable authorization callbacks.
	MaxAuthorizationCalls int
	// MaxPrivateSigningCalls bounds generated private signing callbacks.
	MaxPrivateSigningCalls int
	// MaxNonceBytes bounds optional signing nonce bytes.
	MaxNonceBytes int
	// MinRSABits is the smallest accepted RSA key size.
	MinRSABits int
	// MaxRSABits is the largest accepted RSA key size.
	MaxRSABits int
	// MaxPrivateSignatureBytes bounds one private callback result.
	MaxPrivateSignatureBytes int
	// MaxRouteDescriptorBytes bounds aggregate fanout descriptor bytes.
	MaxRouteDescriptorBytes int
	// MaxRouteWorkUnits bounds fanout planning work.
	MaxRouteWorkUnits int
	// MaxUniquePreSignSourceBytes bounds unique source bytes hashed per fanout.
	MaxUniquePreSignSourceBytes int
	// MaxRouteAuthorityCalls bounds one signing or release attempt.
	MaxRouteAuthorityCalls int
}

// DefaultSigningLimits returns every public hard ceiling explicitly.
func DefaultSigningLimits() SigningLimits {
	signingDefaults := signing.DefaultLimits()
	routeDefaults := routeplan.DefaultLimits()
	return SigningLimits{
		MaxMessageBytes: signingDefaults.MaxMessageBytes, MaxHeaderBytes: signingDefaults.MaxHeaderBytes,
		MaxHeaderFields: signingDefaults.MaxHeaderFields, MaxFieldBytes: signingDefaults.MaxFieldBytes,
		MaxLineBytes: signingDefaults.MaxLineBytes, MaxInstances: signingDefaults.MaxInstances,
		MaxSignatures: signingDefaults.MaxSignatures, MaxProtocolFields: signingDefaults.MaxProtocolFields,
		MaxHashSetsPerInstance:          signingDefaults.MaxHashSetsPerInstance,
		MaxSignatureSetsPerField:        signingDefaults.MaxSignatureSetsPerField,
		MaxTotalSignatureSets:           signingDefaults.MaxTotalSignatureSets,
		MaxPublicKeyLookups:             signingDefaults.MaxPublicKeyLookups,
		MaxSignatureInputBytes:          signingDefaults.MaxSignatureInputBytes,
		MaxCanonicalWorkBytes:           signingDefaults.MaxCanonicalWorkBytes,
		MaxGeneratedRecipients:          signingDefaults.MaxGeneratedRecipients,
		MaxParentOutputCopiesAndTickets: signingDefaults.MaxParentOutputCopiesAndTickets,
		MaxEnvelopePathBytes:            signingDefaults.MaxEnvelopePathBytes,
		MaxDecodedRecipeBytes:           signingDefaults.MaxDecodedRecipeBytes,
		MaxGeneratedSignatureSets:       signingDefaults.MaxGeneratedSignatureSets,
		MaxAuthorizationCalls:           signingDefaults.MaxAuthorizationCalls,
		MaxPrivateSigningCalls:          signingDefaults.MaxPrivateSigningCalls,
		MaxNonceBytes:                   signingDefaults.MaxNonceBytes, MinRSABits: signingDefaults.MinRSABits,
		MaxRSABits:                  signingDefaults.MaxRSABits,
		MaxPrivateSignatureBytes:    signingDefaults.MaxPrivateSignatureBytes,
		MaxRouteDescriptorBytes:     routeDefaults.MaxDescriptorBytes,
		MaxRouteWorkUnits:           routeDefaults.MaxWorkUnits,
		MaxUniquePreSignSourceBytes: routeDefaults.MaxUniqueSourceBytes,
		MaxRouteAuthorityCalls:      routeDefaults.MaxAuthorityCalls,
	}
}

// Validate rejects widening and incoherent narrowed limits.
func (l SigningLimits) Validate() error {
	_, err := resolveSigningLimits(l)
	if err != nil {
		return newSigningError(SigningErrorInvalidOptions)
	}
	return nil
}

// WithSigningLimits applies one immutable narrow-only limit set.
func WithSigningLimits(limits SigningLimits) SignerOption {
	return func(config *signerConfig) error {
		if config == nil {
			return newSigningError(SigningErrorInvalidOptions)
		}
		if _, err := resolveSigningLimits(limits); err != nil {
			return newSigningError(SigningErrorInvalidOptions)
		}
		config.limits = limits
		return nil
	}
}

type resolvedSigningLimits struct {
	signing      signing.Limits
	routes       routeplan.Limits
	generation   recipe.GenerationLimits
	verification verify.Limits
	revision     verify.RevisionLimits
	algorithm    verify.AlgorithmPolicy
}

// resolveSigningLimits maps one public set into each existing invariant owner.
func resolveSigningLimits(input SigningLimits) (resolvedSigningLimits, error) {
	defaults := DefaultSigningLimits()
	values := []struct{ target, fallback *int }{
		{&input.MaxMessageBytes, &defaults.MaxMessageBytes},
		{&input.MaxHeaderBytes, &defaults.MaxHeaderBytes},
		{&input.MaxHeaderFields, &defaults.MaxHeaderFields},
		{&input.MaxFieldBytes, &defaults.MaxFieldBytes},
		{&input.MaxLineBytes, &defaults.MaxLineBytes},
		{&input.MaxInstances, &defaults.MaxInstances},
		{&input.MaxSignatures, &defaults.MaxSignatures},
		{&input.MaxProtocolFields, &defaults.MaxProtocolFields},
		{&input.MaxHashSetsPerInstance, &defaults.MaxHashSetsPerInstance},
		{&input.MaxSignatureSetsPerField, &defaults.MaxSignatureSetsPerField},
		{&input.MaxTotalSignatureSets, &defaults.MaxTotalSignatureSets},
		{&input.MaxPublicKeyLookups, &defaults.MaxPublicKeyLookups},
		{&input.MaxSignatureInputBytes, &defaults.MaxSignatureInputBytes},
		{&input.MaxCanonicalWorkBytes, &defaults.MaxCanonicalWorkBytes},
		{&input.MaxGeneratedRecipients, &defaults.MaxGeneratedRecipients},
		{&input.MaxParentOutputCopiesAndTickets, &defaults.MaxParentOutputCopiesAndTickets},
		{&input.MaxEnvelopePathBytes, &defaults.MaxEnvelopePathBytes},
		{&input.MaxDecodedRecipeBytes, &defaults.MaxDecodedRecipeBytes},
		{&input.MaxGeneratedSignatureSets, &defaults.MaxGeneratedSignatureSets},
		{&input.MaxAuthorizationCalls, &defaults.MaxAuthorizationCalls},
		{&input.MaxPrivateSigningCalls, &defaults.MaxPrivateSigningCalls},
		{&input.MaxNonceBytes, &defaults.MaxNonceBytes},
		{&input.MinRSABits, &defaults.MinRSABits},
		{&input.MaxRSABits, &defaults.MaxRSABits},
		{&input.MaxPrivateSignatureBytes, &defaults.MaxPrivateSignatureBytes},
		{&input.MaxRouteDescriptorBytes, &defaults.MaxRouteDescriptorBytes},
		{&input.MaxRouteWorkUnits, &defaults.MaxRouteWorkUnits},
		{&input.MaxUniquePreSignSourceBytes, &defaults.MaxUniquePreSignSourceBytes},
		{&input.MaxRouteAuthorityCalls, &defaults.MaxRouteAuthorityCalls},
	}
	for _, value := range values {
		if *value.target == 0 {
			*value.target = *value.fallback
		}
	}

	signingLimits := signing.DefaultLimits()
	signingLimits.MaxMessageBytes = input.MaxMessageBytes
	signingLimits.MaxHeaderBytes = input.MaxHeaderBytes
	signingLimits.MaxHeaderFields = input.MaxHeaderFields
	signingLimits.MaxFieldBytes = input.MaxFieldBytes
	signingLimits.MaxLineBytes = input.MaxLineBytes
	signingLimits.MaxInstances = input.MaxInstances
	signingLimits.MaxSignatures = input.MaxSignatures
	signingLimits.MaxProtocolFields = input.MaxProtocolFields
	signingLimits.MaxHashSetsPerInstance = input.MaxHashSetsPerInstance
	signingLimits.MaxSignatureSetsPerField = input.MaxSignatureSetsPerField
	signingLimits.MaxTotalSignatureSets = input.MaxTotalSignatureSets
	signingLimits.MaxPublicKeyLookups = input.MaxPublicKeyLookups
	signingLimits.MaxSignatureInputBytes = input.MaxSignatureInputBytes
	signingLimits.MaxCanonicalWorkBytes = input.MaxCanonicalWorkBytes
	signingLimits.MaxGeneratedRecipients = input.MaxGeneratedRecipients
	signingLimits.MaxParentOutputCopiesAndTickets = input.MaxParentOutputCopiesAndTickets
	signingLimits.MaxEnvelopePathBytes = input.MaxEnvelopePathBytes
	signingLimits.MaxDecodedRecipeBytes = input.MaxDecodedRecipeBytes
	signingLimits.MaxGeneratedSignatureSets = input.MaxGeneratedSignatureSets
	signingLimits.MaxAuthorizationCalls = input.MaxAuthorizationCalls
	signingLimits.MaxPrivateSigningCalls = input.MaxPrivateSigningCalls
	signingLimits.MaxNonceBytes = input.MaxNonceBytes
	signingLimits.MinRSABits = input.MinRSABits
	signingLimits.MaxRSABits = input.MaxRSABits
	signingLimits.MaxPrivateSignatureBytes = input.MaxPrivateSignatureBytes
	if err := signingLimits.Validate(); err != nil {
		return resolvedSigningLimits{}, err
	}

	routeLimits := routeplan.Limits{
		MaxCopiesAndTickets:  input.MaxParentOutputCopiesAndTickets,
		MaxDescriptorBytes:   input.MaxRouteDescriptorBytes,
		MaxWorkUnits:         input.MaxRouteWorkUnits,
		MaxSourceBytes:       input.MaxMessageBytes,
		MaxUniqueSourceBytes: input.MaxUniquePreSignSourceBytes,
		MaxRecipientsPerCopy: input.MaxGeneratedRecipients,
		MaxEnvelopePathBytes: input.MaxEnvelopePathBytes,
		MaxAuthorityCalls:    input.MaxRouteAuthorityCalls,
	}
	if err := routeLimits.Validate(); err != nil {
		return resolvedSigningLimits{}, err
	}

	recipeLimits := recipe.DefaultLimits()
	recipeLimits.MaxDecodedRecipeBytes = input.MaxDecodedRecipeBytes
	recipeLimits.MaxTotalLiteralBytes = min(recipeLimits.MaxTotalLiteralBytes, input.MaxDecodedRecipeBytes)
	recipeLimits.MaxDataStringBytes = min(recipeLimits.MaxDataStringBytes, recipeLimits.MaxTotalLiteralBytes)
	generationLimits := recipe.GenerationLimits{RecipeLimits: recipeLimits}
	if err := generationLimits.Validate(); err != nil {
		return resolvedSigningLimits{}, err
	}

	verificationLimits := verify.DefaultLimits()
	verificationLimits.MaxInstanceHashSets = input.MaxHashSetsPerInstance
	verificationLimits.MaxSignatureSets = input.MaxSignatureSetsPerField
	revisionLimits := verify.DefaultRevisionLimits()
	revisionLimits.MaxProtocolFields = input.MaxProtocolFields
	revisionLimits.MaxTotalSignatureSets = input.MaxTotalSignatureSets
	revisionLimits.MaxPublicKeyLookups = input.MaxPublicKeyLookups
	revisionLimits.MaxCanonicalWorkBytes = input.MaxCanonicalWorkBytes
	revisionLimits.MaxSignatureInputBytes = input.MaxSignatureInputBytes
	revisionLimits.MaxDecodedRecipeBytes = input.MaxDecodedRecipeBytes
	algorithmPolicy := verify.DefaultAlgorithmPolicy()
	algorithmPolicy.MinRSABits = input.MinRSABits
	algorithmPolicy.MaxRSABits = input.MaxRSABits
	verificationOptions := verify.DefaultOptions()
	verificationOptions.AlgorithmPolicy = algorithmPolicy
	verificationOptions.Limits = verificationLimits
	verificationOptions.RevisionLimits = revisionLimits
	if err := verificationOptions.Validate(); err != nil {
		return resolvedSigningLimits{}, err
	}

	return resolvedSigningLimits{
		signing: signingLimits, routes: routeLimits, generation: generationLimits,
		verification: verificationLimits, revision: revisionLimits, algorithm: algorithmPolicy,
	}, nil
}
