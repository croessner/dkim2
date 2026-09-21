package httpjson

import (
	"context"
	"math"
	"math/bits"
	"sync"

	"github.com/croessner/dkim2"
)

const (
	// Go 1.27.0 io.ReadAll in src/io/io.go retains a 497,039,680-byte sum of
	// intermediate chunk capacities at this exact input maximum while it
	// allocates the final exact-size result.
	maximumProcessBodyCapacityBytes = uint64((maxProcessBodyBytes + 8191) / 8192 * 8192)
	maximumReadAllIntermediateBytes = uint64(497_039_680)

	// The Go 1.27.0 decoder measurement retains a 512 MiB buffer and replaces
	// a 256 MiB buffer at the final growth. Both allocations are live during
	// replacement; the runtime probe locks these effective capacities.
	maximumJSONDecoderRetainedBytes = uint64(512 << 20)
	maximumJSONDecoderCapacityBytes = uint64(256<<20 + 512<<20)

	// Large Base64 byte/string storage rounds to the Go 1.27.0 8 KiB runtime
	// allocation page even though its logical maximum remains 178,956,972.
	maximumEncodedMessageCapacityBytes = uint64((maxEncodedMessageBytes + 8191) / 8192 * 8192)
	maximumRawMessageCapacityBytes     = uint64(dkim2.HardMaxRawMessageBytes)

	// Go 1.27.0 encoding/base64.DecodeString allocates DecodedLen before it
	// subtracts canonical padding, so the maximum result has one spare byte.
	maximumBase64DecodedCapacityBytes = maximumRawMessageCapacityBytes + 1

	// A generated request owns the decoded protected strings, the recipient
	// slice's worst 64-bit slice headers, and bounded decoder/struct storage.
	maximumRecipientSliceHeaderBytes = uint64(dkim2.HardMaxRecipients * 24)
	maximumGeneratedRequestDTOBytes  = maximumEncodedMessageCapacityBytes +
		uint64(maxEnvelopeBytes) +
		maximumRecipientSliceHeaderBytes +
		64*1024

	// The generic OpenAPI value tree may retain every decoded JSON string byte.
	// RFC 8259 string decoding never expands beyond the source text, while the
	// lexical 8,192-token ceiling bounds maps, slices, interfaces, numbers, and
	// transient container growth. A second complete body capacity provides more
	// than 5.8 KiB of Go 1.27.0 structure per accepted token, independently of the
	// generated DTO layout and in addition to every retained decoded string.
	maximumValidationGenericStringBytes    = maximumProcessBodyCapacityBytes
	maximumValidationGenericStructureBytes = maximumProcessBodyCapacityBytes
	maximumValidationGenericValueBytes     = maximumValidationGenericStringBytes +
		maximumValidationGenericStructureBytes

	// Each immutable request generation owns a raw message, complete envelope,
	// recipient slice, and bounded Go object/interface storage.
	maximumImmutableRequestGenerationBytes = maximumRawMessageCapacityBytes +
		uint64(maxEnvelopeBytes) +
		maximumRecipientSliceHeaderBytes +
		64*1024

	// MapProcessRequest temporarily owns decoded SMTP path bytes and the
	// recipient slice before NewVerifyRequest clones the immutable request.
	maximumMappingEnvelopeScratchBytes = uint64(maxEnvelopeBytes) +
		maximumRecipientSliceHeaderBytes +
		64*1024

	// rawmsg.Message retains the authoritative raw bytes and one complete
	// header/body component generation. The component generation cannot exceed
	// the same closed raw-message maximum.
	maximumLibraryParsedRawMessageBytes = maximumRawMessageCapacityBytes
	maximumLibraryParsedComponentBytes  = maximumRawMessageCapacityBytes
	maximumLibraryParsedMessageBytes    = maximumLibraryParsedRawMessageBytes +
		maximumLibraryParsedComponentBytes

	// Current verification can overlap the four named full-body owners below.
	// The inbound service path calls verify.Verifier.VerifyCurrent;
	// authenticated HistoryWalk and recipe.State storage are unreachable.
	maximumLibraryMessageBodyCloneBytes    = maximumRawMessageCapacityBytes
	maximumLibraryBodyBytesCopyBytes       = maximumRawMessageCapacityBytes
	maximumLibraryCanonicalBodyOutputBytes = maximumRawMessageCapacityBytes
	maximumLibraryCanonicalBodyCloneBytes  = maximumRawMessageCapacityBytes
	maximumLibraryCanonicalOverlapBytes    = maximumLibraryMessageBodyCloneBytes +
		maximumLibraryBodyBytesCopyBytes +
		maximumLibraryCanonicalBodyOutputBytes +
		maximumLibraryCanonicalBodyCloneBytes

	// rawmsg pre-counts and exactly preallocates at most 2,097,152 40-byte
	// BodyLine values. Current verification retains the parser index, validated
	// message index, and canonical body view; it never retains a history view.
	maximumLibraryParsedBodyLineBytes    = uint64(2_097_152 * 40)
	maximumLibraryValidatedBodyLineBytes = uint64(2_097_152 * 40)
	maximumLibraryCanonicalBodyLineBytes = uint64(2_097_152 * 40)
	maximumLibraryBodyLineIndexBytes     = maximumLibraryParsedBodyLineBytes +
		maximumLibraryValidatedBodyLineBytes +
		maximumLibraryCanonicalBodyLineBytes

	// One complete header generation owns the HeaderBlock original plus the
	// distinct per-field original, raw name/value, lowercase name, and unfolded
	// backing stores. Message retention, message.Headers(), and Fields() or
	// FieldsByName() can overlap three such generations during current
	// canonicalization. Each also owns 2,000 exact HeaderField values and four
	// allocation-class rounding allowances per field.
	maximumLibraryHeaderBlockOriginalBytes   = uint64(1 * 1024 * 1024)
	maximumLibraryHeaderFieldOriginalBytes   = uint64(1 * 1024 * 1024)
	maximumLibraryHeaderRawFieldBytes        = uint64(1 * 1024 * 1024)
	maximumLibraryHeaderLowerNameBytes       = uint64(1 * 1024 * 1024)
	maximumLibraryHeaderUnfoldedBytes        = uint64(1 * 1024 * 1024)
	maximumLibraryHeaderFieldValuesBytes     = uint64(2_000 * 128)
	maximumLibraryHeaderAllocationRounding   = uint64(4 * 2_000 * 32)
	maximumLibraryFirstHeaderGenerationBytes = maximumLibraryHeaderBlockOriginalBytes +
		maximumLibraryHeaderFieldOriginalBytes +
		maximumLibraryHeaderRawFieldBytes +
		maximumLibraryHeaderLowerNameBytes +
		maximumLibraryHeaderUnfoldedBytes +
		maximumLibraryHeaderFieldValuesBytes +
		maximumLibraryHeaderAllocationRounding
	maximumLibrarySecondHeaderGenerationBytes = maximumLibraryFirstHeaderGenerationBytes
	maximumLibraryThirdHeaderGenerationBytes  = maximumLibraryFirstHeaderGenerationBytes
	maximumLibraryHeaderBytes                 = maximumLibraryFirstHeaderGenerationBytes +
		maximumLibrarySecondHeaderGenerationBytes +
		maximumLibraryThirdHeaderGenerationBytes

	// Current extraction retains every parser result even though only one target
	// is verified. These coefficients are locked to parser hard limits and Go
	// object sizes by source-drift probes.
	maximumLibraryInstanceValuesBytes        = uint64(128 * 120)
	maximumLibraryInstanceHashSetBytes       = uint64(128 * 16 * 216)
	maximumLibraryDecodedRecipeBytes         = uint64(128 * 49_152)
	maximumLibraryProtocolCloneOriginalBytes = uint64(1 * 1024 * 1024)
	maximumLibraryProtocolCloneEncodedBytes  = uint64(1 * 1024 * 1024)
	maximumLibraryProtocolCloneDecodedBytes  = uint64(1 * 1024 * 1024)
	maximumLibraryInstanceBytes              = maximumLibraryInstanceValuesBytes +
		maximumLibraryInstanceHashSetBytes +
		maximumLibraryDecodedRecipeBytes +
		maximumLibraryProtocolCloneOriginalBytes +
		maximumLibraryProtocolCloneEncodedBytes +
		maximumLibraryProtocolCloneDecodedBytes

	maximumLibrarySignatureValuesBytes    = uint64(128 * 272)
	maximumLibrarySignatureRecipientBytes = uint64(128 * 2_000 * 96)
	maximumLibrarySignatureSetBytes       = uint64(128 * 16 * 112)
	maximumLibrarySignatureFlagBytes      = uint64(128 * 32 * 24)
	maximumLibraryTargetRecipientBytes    = uint64(2_000 * 96)
	maximumLibraryTargetSetBytes          = uint64(16 * 112)
	maximumLibraryTargetFlagBytes         = uint64(32 * 24)
	maximumLibrarySignatureBytes          = maximumLibrarySignatureValuesBytes +
		maximumLibrarySignatureRecipientBytes +
		maximumLibrarySignatureSetBytes +
		maximumLibrarySignatureFlagBytes +
		maximumLibraryTargetRecipientBytes +
		maximumLibraryTargetSetBytes +
		maximumLibraryTargetFlagBytes

	// HeaderHashInput and SignatureInput each overlap per-field records, the
	// aggregate output, and NewCanonicalBytes' immutable clone. The two
	// operations are sequential, but naming both complete inventories keeps
	// the source graph conservative and independently drift-reviewable.
	maximumLibraryCanonicalHeaderRecordBytes    = uint64(2 * 1024 * 1024)
	maximumLibraryCanonicalHeaderAggregateBytes = uint64(2 * 1024 * 1024)
	maximumLibraryCanonicalHeaderCloneBytes     = uint64(2 * 1024 * 1024)
	maximumLibraryCanonicalHeaderBytes          = maximumLibraryCanonicalHeaderRecordBytes +
		maximumLibraryCanonicalHeaderAggregateBytes +
		maximumLibraryCanonicalHeaderCloneBytes
	maximumLibraryCanonicalSignatureRecordBytes    = uint64(2 * 1024 * 1024)
	maximumLibraryCanonicalSignatureAggregateBytes = uint64(2 * 1024 * 1024)
	maximumLibraryCanonicalSignatureCloneBytes     = uint64(2 * 1024 * 1024)
	maximumLibraryCanonicalSignatureBytes          = maximumLibraryCanonicalSignatureRecordBytes +
		maximumLibraryCanonicalSignatureAggregateBytes +
		maximumLibraryCanonicalSignatureCloneBytes
	maximumLibraryCanonicalProtocolBytes = maximumLibraryCanonicalHeaderBytes +
		maximumLibraryCanonicalSignatureBytes

	// service.Verify creates one immutable core envelope. Current comparison
	// then clones current paths, clones the selected signed paths and their
	// Base64 containers, canonicalizes both sides, and retains one recipient
	// identity map. Every byte and container term is bounded by the 2,000-path,
	// 256-byte RFC 5321 envelope contract or the 1 MiB header ceiling.
	maximumLibraryCoreEnvelopePayloadBytes     = uint64(maxEnvelopeBytes)
	maximumLibraryCoreEnvelopeSliceBytes       = maximumRecipientSliceHeaderBytes
	maximumLibraryCurrentEnvelopePayloadBytes  = uint64(maxEnvelopeBytes)
	maximumLibraryCurrentEnvelopeSliceBytes    = maximumRecipientSliceHeaderBytes
	maximumLibrarySignedEnvelopeValueBytes     = uint64(maxEnvelopeBytes)
	maximumLibrarySignedEnvelopeOriginalBytes  = uint64(1 * 1024 * 1024)
	maximumLibrarySignedEnvelopeEncodedBytes   = uint64(1 * 1024 * 1024)
	maximumLibrarySignedEnvelopeDecodedBytes   = uint64(maxEnvelopeBytes)
	maximumLibrarySignedEnvelopeContainerBytes = uint64(2_000 * 96)
	maximumLibraryCanonicalRecipientBytes      = uint64(maxEnvelopeBytes)
	maximumLibraryRecipientIdentityMapBytes    = uint64(2_000 * 128)
	maximumLibraryEnvelopeTransientPathBytes   = uint64(8 * 256)
	maximumLibraryEnvelopeBytes                = maximumLibraryCoreEnvelopePayloadBytes +
		maximumLibraryCoreEnvelopeSliceBytes +
		maximumLibraryCurrentEnvelopePayloadBytes +
		maximumLibraryCurrentEnvelopeSliceBytes +
		maximumLibrarySignedEnvelopeValueBytes +
		maximumLibrarySignedEnvelopeOriginalBytes +
		maximumLibrarySignedEnvelopeEncodedBytes +
		maximumLibrarySignedEnvelopeDecodedBytes +
		maximumLibrarySignedEnvelopeContainerBytes +
		maximumLibraryCanonicalRecipientBytes +
		maximumLibraryRecipientIdentityMapBytes +
		maximumLibraryEnvelopeTransientPathBytes

	maximumLibraryKeyTXTBytes         = uint64(64 * 1024)
	maximumLibraryKeyTagValueBytes    = uint64(64 * 1024)
	maximumLibraryKeyDecodedBytes     = uint64(64 * 1024)
	maximumLibraryKeyReplacementBytes = uint64(64 * 1024)
	maximumLibraryKeyTagValuesBytes   = uint64(128 * 128)
	maximumLibraryKeyNameBytes        = uint64(3 * 253)
	maximumLibraryKeyBytes            = maximumLibraryKeyTXTBytes +
		maximumLibraryKeyTagValueBytes +
		maximumLibraryKeyDecodedBytes +
		maximumLibraryKeyReplacementBytes +
		maximumLibraryKeyTagValuesBytes +
		maximumLibraryKeyNameBytes

	maximumLibraryVerifyResultFactBytes  = uint64(128*256 + 16*256)
	maximumLibraryServiceResultFactBytes = uint64(128*256 + 16*256)
	maximumLibraryPublicResultFactBytes  = uint64(128*256 + 16*256)
	maximumLibraryAdapterResultFactBytes = uint64(128*256 + 16*256)
	maximumLibraryResultFixedBytes       = uint64(256 * 1024)
	maximumLibraryResultBytes            = maximumLibraryVerifyResultFactBytes +
		maximumLibraryServiceResultFactBytes +
		maximumLibraryPublicResultFactBytes +
		maximumLibraryAdapterResultFactBytes +
		maximumLibraryResultFixedBytes

	maximumLibraryReplayRecipientBytes      = uint64(maxEnvelopeBytes)
	maximumLibraryReplayScopeBytes          = uint64(2_000 * 256)
	maximumLibraryReplayIdentityDigestBytes = uint64(2_000 * 32)
	maximumLibraryReplayEnvelopeDigestBytes = uint64(2_000 * 32)
	maximumLibraryReplayKeyDigestBytes      = uint64(2_000 * 32)
	maximumLibraryReplayCheckDigestBytes    = uint64(2_000 * 32)
	maximumLibraryReplayVerifyStateBytes    = uint64(2_000 * 128)
	maximumLibraryReplayServiceStateBytes   = uint64(2_000 * 128)
	maximumLibraryReplayKeyCheckBytes       = uint64(2_000 * 128)
	maximumLibraryReplayBytes               = maximumLibraryReplayRecipientBytes +
		maximumLibraryReplayScopeBytes +
		maximumLibraryReplayIdentityDigestBytes +
		maximumLibraryReplayEnvelopeDigestBytes +
		maximumLibraryReplayKeyDigestBytes +
		maximumLibraryReplayCheckDigestBytes +
		maximumLibraryReplayVerifyStateBytes +
		maximumLibraryReplayServiceStateBytes +
		maximumLibraryReplayKeyCheckBytes

	maximumLibraryVerifyPolicyBytes  = uint64(128 * 256)
	maximumLibraryServicePolicyBytes = uint64(128 * 256)
	maximumLibraryPublicPolicyBytes  = uint64(128 * 256)
	maximumLibraryAdapterPolicyBytes = uint64(128 * 256)
	maximumLibraryPolicyFixedBytes   = uint64(256 * 1024)
	maximumLibraryPolicyBytes        = maximumLibraryVerifyPolicyBytes +
		maximumLibraryServicePolicyBytes +
		maximumLibraryPublicPolicyBytes +
		maximumLibraryAdapterPolicyBytes +
		maximumLibraryPolicyFixedBytes

	maximumLibraryProtocolBytes = maximumLibraryInstanceBytes +
		maximumLibrarySignatureBytes +
		maximumLibraryCanonicalProtocolBytes +
		maximumLibraryEnvelopeBytes +
		maximumLibraryKeyBytes +
		maximumLibraryResultBytes +
		maximumLibraryReplayBytes +
		maximumLibraryPolicyBytes

	// Extracted current parser objects remain live through canonicalization, so
	// the current phase strictly dominates the parse phase. Source-drift tests
	// lock this liveness relation and the VerifyCurrent reachability contract.
	maximumLibraryParsePhaseBytes = maximumLibraryParsedMessageBytes +
		maximumLibraryBodyLineIndexBytes +
		maximumLibraryHeaderBytes +
		maximumLibraryInstanceBytes +
		maximumLibrarySignatureBytes
	maximumLibraryCurrentPhaseBytes = maximumLibraryParsedMessageBytes +
		maximumLibraryCanonicalOverlapBytes +
		maximumLibraryBodyLineIndexBytes +
		maximumLibraryHeaderBytes +
		maximumLibraryProtocolBytes
	maximumLibraryRuntimeBytes = maximumLibraryCurrentPhaseBytes

	maximumSuccessResponseBytes     = uint64(maxSuccessResponseBytes)
	maximumFixedRequestStorageBytes = uint64(4 * 1024 * 1024)

	// DomainRequest and VerifyRequest transfer one opaque immutable allocation.
	// The domain phase therefore retains the verified facade request plus the
	// service request and its extracted clone, not a fourth request generation.
	maximumFacadeRequestBytes           = maximumImmutableRequestGenerationBytes
	maximumServiceRequestBytes          = maximumImmutableRequestGenerationBytes
	maximumServiceExtractedRequestBytes = maximumImmutableRequestGenerationBytes

	// The maximum domain phase retains the encoded body and generated DTO,
	// three named immutable request generations, current-only library runtime,
	// bounded response, and fixed request storage simultaneously.
	maximumDomainWorkingSetBytes = maximumProcessBodyCapacityBytes +
		maximumGeneratedRequestDTOBytes +
		maximumFacadeRequestBytes +
		maximumServiceRequestBytes +
		maximumServiceExtractedRequestBytes +
		maximumLibraryRuntimeBytes +
		maximumSuccessResponseBytes +
		maximumFixedRequestStorageBytes
	// At the expanded batch framing ceiling, generic validation owns more
	// memory than current verification. Keep both phase equations explicit.
	maximumValidationWorkingSetBytes = maximumFixedRequestStorageBytes +
		2*maximumProcessBodyCapacityBytes + maximumReadAllIntermediateBytes +
		maximumJSONDecoderCapacityBytes + maximumValidationGenericValueBytes
	maximumLegalWorkingSetHighWaterBytes = max(maximumDomainWorkingSetBytes, maximumValidationWorkingSetBytes)
	// maximumLegalWorkingSetMarginBytes fails compilation if the pinned
	// worst case at the closed library ceiling ever stops fitting inside the
	// process budget with its reservation headroom. The deployment-scaled
	// sizing below derives every runtime reservation, but this subtraction
	// keeps the measured inventory itself a compile-time invariant.
	maximumLegalWorkingSetMarginBytes = processWorkingSetAggregateBytes -
		workingSetUnitHeadroomBytes - maximumLegalWorkingSetHighWaterBytes
)

const workingSetErrorText = "http request working-set accounting failure"

type workingSetContextKey struct{}

type workingSetContext struct {
	mu     sync.Mutex
	ledger *workingSetLedger
}

// withWorkingSetContext installs one private content-free accounting capability.
func withWorkingSetContext(
	ctx context.Context,
	ledger *workingSetLedger,
) (context.Context, *workingSetContext, error) {
	if ctx == nil || ledger == nil {
		return ctx, nil, &workingSetError{code: workingSetErrorInvariant}
	}
	holder := &workingSetContext{ledger: ledger}
	return context.WithValue(ctx, workingSetContextKey{}, holder), holder, nil
}

// workingSetLedgerFromContext returns the current private accounting owner.
func workingSetLedgerFromContext(ctx context.Context) (*workingSetLedger, bool) {
	if ctx == nil {
		return nil, false
	}
	holder, ok := ctx.Value(workingSetContextKey{}).(*workingSetContext)
	if !ok || holder == nil {
		return nil, false
	}
	holder.mu.Lock()
	defer holder.mu.Unlock()
	return holder.ledger, holder.ledger != nil
}

// Clear removes the accounting owner from every retained request context.
func (c *workingSetContext) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.ledger = nil
	c.mu.Unlock()
}

type workingSetErrorCode uint8

const (
	workingSetErrorInvariant workingSetErrorCode = iota + 1
	workingSetErrorOverflow
	workingSetErrorReservation
)

// workingSetError reports only one bounded accounting failure class.
type workingSetError struct {
	code workingSetErrorCode
}

// Error returns a constant diagnostic that contains no request-derived data.
func (*workingSetError) Error() string { return workingSetErrorText }

// Code returns the bounded accounting failure class.
func (e *workingSetError) Code() workingSetErrorCode {
	if e == nil {
		return 0
	}
	return e.code
}

type workingSetSlot uint8

const (
	workingSetFixedStorage workingSetSlot = iota
	workingSetBodyReadChunks
	workingSetBodySnapshot
	workingSetValidationReadChunks
	workingSetValidationBodySnapshot
	workingSetValidationDecoder
	workingSetValidationValue
	workingSetGeneratedDecoder
	workingSetGeneratedDTO
	workingSetBase64EncodedCopy
	workingSetBase64InputString
	workingSetBase64Decoded
	workingSetCanonicalBase64
	workingSetCanonicalBase64String
	workingSetCanonicalCompareCopy
	workingSetMappingEnvelopeScratch
	workingSetDomainRequest
	workingSetVerifyRequest
	workingSetServiceRequest
	workingSetServiceExtracted
	workingSetLibraryRuntime
	workingSetResponse
	workingSetSlotCount
)

// valid reports whether a slot belongs to the closed ownership inventory.
func (s workingSetSlot) valid() bool {
	return s < workingSetSlotCount
}

// workingSetSnapshot is one content-free accounting observation.
type workingSetSnapshot struct {
	Limit      uint64
	Live       uint64
	HighWater  uint64
	OwnedSlots int
	Failed     bool
}

// ProvedBelowReservation reports a healthy strict peak-live proof.
func (s workingSetSnapshot) ProvedBelowReservation() bool {
	return !s.Failed && s.Limit > 0 && s.Live <= s.HighWater &&
		s.HighWater < s.Limit
}

// workingSetLedger owns checked per-request live-capacity accounting.
//
// The ledger is intentionally fixed-slot and content-free: callers choose a
// reviewed ownership class and pass only an allocation capacity. They claim a
// replacement before releasing its predecessor whenever both can be live.
type workingSetLedger struct {
	mu        sync.Mutex
	limit     uint64
	sizing    workingSetSizing
	live      uint64
	highWater uint64
	owned     [workingSetSlotCount]uint64
	failed    bool
}

// newWorkingSetLedger constructs one bounded per-request ownership ledger from
// the deployment's proven capacity inventory.
func newWorkingSetLedger(sizing workingSetSizing) (*workingSetLedger, error) {
	limit := sizing.UnitBytes()
	if limit == 0 || limit > processWorkingSetAggregateBytes {
		return nil, &workingSetError{code: workingSetErrorInvariant}
	}
	return &workingSetLedger{limit: limit, sizing: sizing}, nil
}

// Claim adds one newly live capacity before any replaced owner is released.
func (l *workingSetLedger) Claim(slot workingSetSlot, capacity uint64) error {
	if l == nil {
		return &workingSetError{code: workingSetErrorInvariant}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failed || !slot.valid() || capacity == 0 || l.owned[slot] != 0 ||
		l.limit == 0 {
		return l.failLocked(workingSetErrorInvariant)
	}
	if capacity > math.MaxUint64-l.live {
		return l.failLocked(workingSetErrorOverflow)
	}
	next := l.live + capacity
	if next > l.limit {
		return l.failLocked(workingSetErrorReservation)
	}
	l.owned[slot] = capacity
	l.live = next
	if next > l.highWater {
		l.highWater = next
	}
	return nil
}

// Release removes one unreachable capacity, including during failed cleanup.
func (l *workingSetLedger) Release(slot workingSetSlot) error {
	if l == nil {
		return &workingSetError{code: workingSetErrorInvariant}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !slot.valid() || l.owned[slot] == 0 || l.owned[slot] > l.live {
		return l.failLocked(workingSetErrorInvariant)
	}
	l.live -= l.owned[slot]
	l.owned[slot] = 0
	return nil
}

// Transfer changes the logical owner of one unchanged live allocation.
func (l *workingSetLedger) Transfer(from workingSetSlot, to workingSetSlot) error {
	if l == nil {
		return &workingSetError{code: workingSetErrorInvariant}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failed || !from.valid() || !to.valid() || from == to ||
		l.owned[from] == 0 || l.owned[to] != 0 {
		return l.failLocked(workingSetErrorInvariant)
	}
	l.owned[to] = l.owned[from]
	l.owned[from] = 0
	return nil
}

// Snapshot returns only bounded capacity counters and closed state.
func (l *workingSetLedger) Snapshot() workingSetSnapshot {
	if l == nil {
		return workingSetSnapshot{Failed: true}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ownedSlots := 0
	for _, capacity := range l.owned {
		if capacity != 0 {
			ownedSlots++
		}
	}
	return workingSetSnapshot{
		Limit:      l.limit,
		Live:       l.live,
		HighWater:  l.highWater,
		OwnedSlots: ownedSlots,
		Failed:     l.failed,
	}
}

// ReleaseAll makes every accounted request allocation unreachable at terminal
// ownership handoff while preserving the observed high-water proof.
func (l *workingSetLedger) ReleaseAll() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	clear(l.owned[:])
	l.live = 0
}

// BeginBodyRead reserves the maximum Go 1.27.0 ReadAll overlap before reading.
func (l *workingSetLedger) BeginBodyRead() error {
	if err := l.Claim(workingSetBodyReadChunks, l.sizing.readAllIntermediate); err != nil {
		return err
	}
	return l.Claim(workingSetBodySnapshot, l.sizing.processBodyCapacity)
}

// FinishBodyRead makes the transient ReadAll chunk owner unreachable.
func (l *workingSetLedger) FinishBodyRead() error {
	return l.Release(workingSetBodyReadChunks)
}

// BeginValidation reserves all kin-openapi copy and generic-value owners.
func (l *workingSetLedger) BeginValidation() error {
	if err := l.Claim(
		workingSetValidationReadChunks,
		l.sizing.readAllIntermediate,
	); err != nil {
		return err
	}
	if err := l.Claim(
		workingSetValidationBodySnapshot,
		l.sizing.processBodyCapacity,
	); err != nil {
		return err
	}
	if err := l.Claim(
		workingSetValidationDecoder,
		l.sizing.jsonDecoderCapacity,
	); err != nil {
		return err
	}
	return l.Claim(workingSetValidationValue, l.sizing.validationGeneric)
}

// FinishValidation drops every validation-only body and generic-value owner.
func (l *workingSetLedger) FinishValidation() error {
	for _, slot := range [...]workingSetSlot{
		workingSetValidationValue,
		workingSetValidationDecoder,
		workingSetValidationBodySnapshot,
		workingSetValidationReadChunks,
	} {
		if err := l.Release(slot); err != nil {
			return err
		}
	}
	return nil
}

// BeginGeneratedProcessing reserves the strict decoder and generated DTO
// before the generated handler begins decoding.
func (l *workingSetLedger) BeginGeneratedProcessing() error {
	claims := [...]struct {
		slot     workingSetSlot
		capacity uint64
	}{
		{workingSetGeneratedDecoder, l.sizing.jsonDecoderCapacity},
		{workingSetGeneratedDTO, l.sizing.generatedRequestDTO},
	}
	for _, claim := range claims {
		if err := l.Claim(claim.slot, claim.capacity); err != nil {
			return err
		}
	}
	return nil
}

// FinishGeneratedDecode releases decoder storage after the DTO is complete.
func (l *workingSetLedger) FinishGeneratedDecode() error {
	return l.Release(workingSetGeneratedDecoder)
}

// BeginRequestMapping reserves every canonical Base64 and domain-request owner.
func (l *workingSetLedger) BeginRequestMapping() error {
	for _, claim := range [...]struct {
		slot     workingSetSlot
		capacity uint64
	}{
		{workingSetBase64EncodedCopy, l.sizing.encodedMessage},
		{workingSetBase64InputString, l.sizing.encodedMessage},
		{workingSetBase64Decoded, l.sizing.base64Decoded},
		{workingSetCanonicalBase64, l.sizing.encodedMessage},
		{workingSetCanonicalBase64String, l.sizing.encodedMessage},
		{workingSetCanonicalCompareCopy, l.sizing.encodedMessage},
		{workingSetMappingEnvelopeScratch, maximumMappingEnvelopeScratchBytes},
		{workingSetDomainRequest, l.sizing.requestGeneration},
	} {
		if err := l.Claim(claim.slot, claim.capacity); err != nil {
			return err
		}
	}
	return nil
}

// FinishRequestMapping releases conversion scratch after DomainRequest owns its clone.
func (l *workingSetLedger) FinishRequestMapping() error {
	for _, slot := range [...]workingSetSlot{
		workingSetMappingEnvelopeScratch,
		workingSetCanonicalCompareCopy,
		workingSetCanonicalBase64String,
		workingSetCanonicalBase64,
		workingSetBase64Decoded,
		workingSetBase64InputString,
		workingSetBase64EncodedCopy,
	} {
		if err := l.Release(slot); err != nil {
			return err
		}
	}
	return nil
}

// BeginVerifyRequest transfers the opaque immutable request to its facade owner.
func (l *workingSetLedger) BeginVerifyRequest() error {
	return l.Transfer(workingSetDomainRequest, workingSetVerifyRequest)
}

// BeginDomainProcessing reserves service, library, and response owners.
func (l *workingSetLedger) BeginDomainProcessing() error {
	for _, claim := range [...]struct {
		slot     workingSetSlot
		capacity uint64
	}{
		{workingSetServiceRequest, l.sizing.requestGeneration},
		{workingSetServiceExtracted, l.sizing.requestGeneration},
		{workingSetLibraryRuntime, l.sizing.libraryRuntime},
		{workingSetResponse, maximumSuccessResponseBytes},
	} {
		if err := l.Claim(claim.slot, claim.capacity); err != nil {
			return err
		}
	}
	return nil
}

// failLocked marks accounting unusable while preserving cleanup ownership.
func (l *workingSetLedger) failLocked(code workingSetErrorCode) error {
	if l != nil {
		l.failed = true
	}
	return &workingSetError{code: code}
}

// Deployment-scaled working-set sizing.
//
// Every constant above states the worst case at the closed library ceiling of
// dkim2.HardMaxRawMessageBytes. A deployment that configures a smaller
// server.message_bytes can never reach those capacities, yet the fixed unit
// reservation made every request pay the maximum and therefore capped process
// concurrency at two. The sizing below reproduces the same ownership
// inventory as a function of the configured ceiling, so a smaller deployment
// reserves proportionally less and may admit proportionally more requests.
//
// Only two terms are not analytic in the input size, and each has its own
// structure rather than a flat ratio.
//
// io.ReadAll grows through a series whose successive retained totals differ by
// a factor of 1.5, so the complete sum of intermediate capacities converges
// below three times the final capacity. Measurement across the supported range
// peaks at 1.464 times the final capacity, well inside that bound.
//
// The JSON decoder replaces a buffer by the next power of two and keeps both
// live during the swap, so its overlap is exactly one and a half times the
// power of two that covers the body. Measurement reproduces that ratio at
// every size, not merely at the ceiling. Two conditions carry that equality:
// the Go 1.27.0 default jsonv2 decoder doubles from 64 bytes, and the boundary
// hands the generated decoder a bytes.Reader that fills every requested slice,
// so a short read can never force one extra doubling. TestPinnedWorkingSetCapacityBounds
// keeps the ceiling equality pinned, which is what detects a decoder change.
//
// TestWorkingSetSizingOverApproximatesMeasuredGrowth replays both probes at
// every supported ceiling and requires measured <= modelled. Over-approximation
// is the only safe direction: an undercut reservation would let one request
// own more memory than the process budget accounted for.
const (
	// workingSetReadAllCapacityFactor bounds the retained sum of intermediate
	// ReadAll capacities as a multiple of the final body capacity.
	workingSetReadAllCapacityFactor = uint64(3)
	// workingSetJSONNumerator over workingSetJSONDenominator is the decoder's
	// replaced plus replacement buffer, relative to the covering power of two.
	workingSetJSONNumerator   = uint64(3)
	workingSetJSONDenominator = uint64(2)
	// workingSetUnitHeadroomBytes is the fixed allowance added to the proven
	// phase high-water mark before it becomes the per-request reservation.
	workingSetUnitHeadroomBytes = uint64(64 << 20)
	// workingSetPageBytes is the Go 1.27.0 large-allocation rounding page.
	workingSetPageBytes = uint64(8192)
	// workingSetBodyLineCeiling mirrors the parser's closed BodyLine ceiling.
	// Production accounting keeps the literal, and
	// TestWorkingSetBodyLineLiteralsMatchTheParser compares all three literals
	// against rawmsg and the concrete Go object size.
	workingSetBodyLineCeiling = uint64(2_097_152)
	// workingSetBodyLineBytes is one Go 1.27.0 BodyLine value.
	workingSetBodyLineBytes = uint64(40)
	// workingSetBodyLineGenerations counts the parser, validated and canonical
	// indexes that current verification retains at the same time.
	workingSetBodyLineGenerations = uint64(3)
)

// roundWorkingSetPage rounds one large allocation to the pinned runtime page.
func roundWorkingSetPage(size uint64, page uint64) uint64 {
	if page == 0 || size > math.MaxUint64-page+1 {
		return math.MaxUint64
	}
	return (size + page - 1) / page * page
}

// workingSetSizing owns one deployment's complete per-request capacity
// inventory. It is immutable after construction and carries no request data.
type workingSetSizing struct {
	messageBytes        uint64
	processBodyBytes    uint64
	processBodyCapacity uint64
	readAllIntermediate uint64
	jsonDecoderCapacity uint64
	validationGeneric   uint64
	encodedMessage      uint64
	base64Decoded       uint64
	requestGeneration   uint64
	generatedRequestDTO uint64
	libraryRuntime      uint64
	unitBytes           uint64
}

// newWorkingSetSizing derives one complete inventory from the configured
// raw-message ceiling. It fails closed on an unsupported ceiling and on any
// arithmetic that cannot be proven below the process aggregate.
func newWorkingSetSizing(messageBytes int64) (workingSetSizing, error) {
	if messageBytes < 1 || messageBytes > dkim2.HardMaxRawMessageBytes {
		return workingSetSizing{}, &workingSetError{code: workingSetErrorInvariant}
	}
	raw := uint64(messageBytes)
	encoded := (raw + 2) / 3 * 4
	sizing := workingSetSizing{messageBytes: raw}
	sizing.encodedMessage = roundWorkingSetPage(encoded, workingSetPageBytes)
	sizing.base64Decoded = encoded/4*3 + 1
	sizing.processBodyBytes = 2*encoded + batchFramingOverheadBytes
	sizing.processBodyCapacity = roundWorkingSetPage(sizing.processBodyBytes, workingSetPageBytes)
	sizing.readAllIntermediate = scaleWorkingSetBytes(
		sizing.processBodyCapacity, workingSetReadAllCapacityFactor, 1,
	)
	sizing.jsonDecoderCapacity = scaleWorkingSetBytes(
		coveringPowerOfTwo(sizing.processBodyBytes),
		workingSetJSONNumerator, workingSetJSONDenominator,
	)
	sizing.validationGeneric = 2 * sizing.processBodyCapacity
	sizing.requestGeneration = raw + maximumMappingEnvelopeScratchBytes
	sizing.generatedRequestDTO = sizing.encodedMessage + maximumMappingEnvelopeScratchBytes
	sizing.libraryRuntime = 6*raw + sizing.bodyLineIndexBytes() +
		maximumLibraryHeaderBytes + maximumLibraryProtocolBytes
	unit, err := sizing.proveUnitBytes()
	if err != nil {
		return workingSetSizing{}, err
	}
	sizing.unitBytes = unit
	return sizing, nil
}

// bodyLineIndexBytes bounds the three retained BodyLine generations. A body
// cannot hold more lines than half its bytes, and the parser never records
// more than its own closed ceiling.
func (s workingSetSizing) bodyLineIndexBytes() uint64 {
	lines := min(workingSetBodyLineCeiling, s.messageBytes/2+1)
	return workingSetBodyLineGenerations * workingSetBodyLineBytes * lines
}

// validationPhaseBytes returns the generic-validation ownership high water.
func (s workingSetSizing) validationPhaseBytes() uint64 {
	return maximumFixedRequestStorageBytes + 2*s.processBodyCapacity +
		s.readAllIntermediate + s.jsonDecoderCapacity + s.validationGeneric
}

// domainPhaseBytes returns the domain-processing ownership high water.
func (s workingSetSizing) domainPhaseBytes() uint64 {
	return maximumFixedRequestStorageBytes + s.processBodyCapacity +
		s.generatedRequestDTO + 3*s.requestGeneration + s.libraryRuntime +
		maximumSuccessResponseBytes
}

// proveUnitBytes returns the per-request reservation that strictly dominates
// every phase, or fails closed when it cannot be covered by the aggregate.
func (s workingSetSizing) proveUnitBytes() (uint64, error) {
	highWater := max(s.validationPhaseBytes(), s.domainPhaseBytes())
	if highWater == 0 || highWater > processWorkingSetAggregateBytes-workingSetUnitHeadroomBytes {
		return 0, &workingSetError{code: workingSetErrorOverflow}
	}
	unit := roundWorkingSetPage(highWater+workingSetUnitHeadroomBytes, workingSetPageBytes)
	if unit <= highWater || unit > processWorkingSetAggregateBytes {
		return 0, &workingSetError{code: workingSetErrorOverflow}
	}
	return unit, nil
}

// UnitBytes returns the proven per-request working-set reservation.
func (s workingSetSizing) UnitBytes() uint64 { return s.unitBytes }

// ProcessBodyBytes returns the largest admitted request body for this ceiling.
func (s workingSetSizing) ProcessBodyBytes() int64 { return int64(s.processBodyBytes) }

// MaxInFlight returns how many concurrent requests the aggregate can own.
func (s workingSetSizing) MaxInFlight() int {
	if s.unitBytes == 0 {
		return 0
	}
	return int(min(processWorkingSetAggregateBytes/s.unitBytes, uint64(maxProcessInFlight)))
}

// coveringPowerOfTwo returns the smallest power of two at or above value.
// The JSON decoder replaces its buffer along exactly this progression. A value
// above the largest representable power of two saturates instead of wrapping
// to zero, so an unusable size can never present itself as a free capacity.
func coveringPowerOfTwo(value uint64) uint64 {
	switch {
	case value == 0:
		return 1
	case value > uint64(1)<<63:
		return math.MaxUint64
	default:
		return uint64(1) << uint(bits.Len64(value-1))
	}
}

// scaleWorkingSetBytes multiplies without overflow and always rounds upward.
func scaleWorkingSetBytes(value, numerator, denominator uint64) uint64 {
	if denominator == 0 || numerator == 0 ||
		value > (math.MaxUint64-denominator+1)/numerator {
		return math.MaxUint64
	}
	return (value*numerator + denominator - 1) / denominator
}
