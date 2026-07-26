package httpjson

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/keyresolver"
	"github.com/croessner/dkim2/internal/policy"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/service"
	"github.com/croessner/dkim2/internal/signature"
	"github.com/croessner/dkim2/internal/tagvalue"
	"github.com/croessner/dkim2/internal/verify"
)

type maximumWorkingSetCapability struct {
	value []byte
}

// Equal compares the decoded maximum-input test capability.
func (m *maximumWorkingSetCapability) Equal(value []byte) bool {
	return m != nil && bytes.Equal(m.value, value)
}

type maximumWorkingSetReadiness struct{}

// Ready keeps the maximum-input proof on the selected process path.
func (*maximumWorkingSetReadiness) Ready() bool { return true }

type maximumWorkingSetProcessor struct {
	ledger         *workingSetLedger
	snapshot       workingSetSnapshot
	rawBytes       int
	reverseBytes   int
	recipientCount int
	envelopeBytes  int
}

// Process records the production ledger at the domain seam without retaining input.
func (p *maximumWorkingSetProcessor) Process(
	ctx context.Context,
	request dkim2.VerifyRequest,
) (app.InboundResult, error) {
	ledger, ok := workingSetLedgerFromContext(ctx)
	if p == nil || !ok || ledger == nil {
		return app.InboundResult{}, &workingSetError{code: workingSetErrorInvariant}
	}
	raw := request.RawMessage()
	reverse := request.ReversePath()
	recipients := request.ForwardPaths()
	p.ledger = ledger
	p.snapshot = ledger.Snapshot()
	p.rawBytes = len(raw)
	p.reverseBytes = len(reverse)
	p.recipientCount = len(recipients)
	p.envelopeBytes = len(reverse)
	for _, recipient := range recipients {
		p.envelopeBytes += len(recipient)
	}
	return app.InboundResult{}, nil
}

// TestMaximumLegalWorkingSetProof replays every maximum-input ownership phase.
func TestMaximumLegalWorkingSetProof(t *testing.T) {
	t.Parallel()

	const (
		wantHighWater = uint64(482_651_127)
		wantMargin    = uint64(54_219_785)
	)
	if maximumLegalWorkingSetHighWaterBytes != wantHighWater ||
		maximumLegalWorkingSetMarginBytes != wantMargin {
		t.Fatal("maximum-input inventory changed without proof review")
	}
	ledger, err := newWorkingSetLedger(processWorkingSetUnitBytes)
	if err != nil {
		t.Fatal("newWorkingSetLedger() rejected the fixed reservation")
	}
	claimWorkingSet(t, ledger, workingSetFixedStorage, maximumFixedRequestStorageBytes)

	// Go 1.26 io.ReadAll retains its completed chunks while allocating the
	// exact final body snapshot. The new snapshot is claimed first so the
	// transient overlap contributes to high water.
	if err := ledger.BeginBodyRead(); err != nil {
		t.Fatal("BeginBodyRead() failed")
	}
	if live := ledger.Snapshot().Live; live != maximumFixedRequestStorageBytes+
		maximumReadAllIntermediateBytes+maximumProcessBodyCapacityBytes {
		t.Fatal("BeginBodyRead() did not charge the Go 1.26 transient")
	}
	if err := ledger.FinishBodyRead(); err != nil {
		t.Fatal("FinishBodyRead() failed")
	}

	// kin-openapi reads the same body into its own snapshot, then its generic
	// JSON decoder owns both a growth buffer and the decoded generic tree.
	if err := ledger.BeginValidation(); err != nil {
		t.Fatal("BeginValidation() failed")
	}
	if live := ledger.Snapshot().Live; live != maximumFixedRequestStorageBytes+
		maximumProcessBodyCapacityBytes+maximumReadAllIntermediateBytes+
		maximumProcessBodyCapacityBytes+maximumJSONDecoderCapacityBytes+
		maximumValidationGenericValueBytes {
		t.Fatal("BeginValidation() did not retain every validation owner")
	}
	if err := ledger.FinishValidation(); err != nil {
		t.Fatal("FinishValidation() failed")
	}

	// The generated strict decoder replays the boundary snapshot and retains
	// its protected DTO while mapping performs canonical Base64 conversion.
	if err := ledger.BeginGeneratedProcessing(); err != nil {
		t.Fatal("BeginGeneratedProcessing() failed")
	}
	if err := ledger.FinishGeneratedDecode(); err != nil {
		t.Fatal("FinishGeneratedDecode() failed")
	}
	if err := ledger.BeginRequestMapping(); err != nil {
		t.Fatal("BeginRequestMapping() failed")
	}
	mapping := ledger.Snapshot()
	if mapping.Live != maximumFixedRequestStorageBytes+
		maximumProcessBodyCapacityBytes+
		maximumGeneratedRequestDTOBytes+
		maximumEncodedMessageCapacityBytes*5+
		maximumBase64DecodedCapacityBytes+
		maximumMappingEnvelopeScratchBytes+
		maximumImmutableRequestGenerationBytes {
		t.Fatal("BeginRequestMapping() did not charge every mapping owner")
	}
	if err := ledger.BeginVerifyRequest(); err != nil {
		t.Fatal("BeginVerifyRequest() failed")
	}
	transferred := ledger.Snapshot()
	if transferred.Live != mapping.Live ||
		transferred.HighWater != mapping.HighWater ||
		transferred.OwnedSlots != mapping.OwnedSlots {
		t.Fatal("BeginVerifyRequest() duplicated opaque immutable ownership")
	}
	if err := ledger.FinishRequestMapping(); err != nil {
		t.Fatal("FinishRequestMapping() failed")
	}
	if live := ledger.Snapshot().Live; live != maximumFixedRequestStorageBytes+
		maximumProcessBodyCapacityBytes+
		maximumGeneratedRequestDTOBytes+
		maximumImmutableRequestGenerationBytes {
		t.Fatal("FinishRequestMapping() retained mapping scratch")
	}

	// Facade, service, current-only parser/canonicalization, and response
	// ownership can overlap until the complete response has been buffered.
	if err := ledger.BeginDomainProcessing(); err != nil {
		t.Fatal("BeginDomainProcessing() failed")
	}

	snapshot := ledger.Snapshot()
	if snapshot.Failed || snapshot.HighWater != maximumLegalWorkingSetHighWaterBytes {
		t.Fatalf("maximum-input proof snapshot = %+v", snapshot)
	}
	if !snapshot.ProvedBelowReservation() {
		t.Fatalf("maximum-input high water %d is not strictly below %d",
			snapshot.HighWater, snapshot.Limit)
	}
	if margin := snapshot.Limit - snapshot.HighWater; margin != maximumLegalWorkingSetMarginBytes {
		t.Fatalf("maximum-input margin = %d, want %d",
			margin, maximumLegalWorkingSetMarginBytes)
	}

	for _, slot := range []workingSetSlot{
		workingSetResponse,
		workingSetLibraryRuntime,
		workingSetServiceExtracted,
		workingSetServiceRequest,
		workingSetVerifyRequest,
		workingSetGeneratedDTO,
		workingSetBodySnapshot,
		workingSetFixedStorage,
	} {
		releaseWorkingSet(t, ledger, slot)
	}
	final := ledger.Snapshot()
	if final.Live != 0 || final.Failed || final.HighWater != snapshot.HighWater {
		t.Fatalf("released maximum-input snapshot = %+v", final)
	}
}

// TestMaximumLegalProductionWorkingSetProof drives one exact maximum JSON body
// through lexical, OpenAPI, generated, mapping, and domain-seam production code.
func TestMaximumLegalProductionWorkingSetProof(t *testing.T) {
	body := buildMaximumLegalProcessBody(t)
	if int64(len(body)) != maxProcessBodyBytes {
		t.Fatalf("maximum process body length = %d, want %d", len(body), maxProcessBodyBytes)
	}
	validator, err := NewRequestValidator()
	if err != nil {
		t.Fatal("NewRequestValidator() failed")
	}
	secret := bytes.Repeat([]byte{0xa5}, 32)
	processor := &maximumWorkingSetProcessor{}
	handler, err := NewHTTPBoundary(BoundaryConfig{
		Authority:       boundaryTestAuthority,
		RequestDeadline: 5 * time.Minute,
		MaxInFlight:     1,
		MaxWaiters:      1,
		AdmissionWait:   10 * time.Millisecond,
	}, &maximumWorkingSetCapability{value: secret}, &maximumWorkingSetReadiness{},
		processor, &boundaryFatalNotifier{}, validator)
	if err != nil {
		t.Fatal("NewHTTPBoundary() failed")
	}
	t.Cleanup(handler.Close)

	request := httptest.NewRequest(
		http.MethodPost,
		"http://"+boundaryTestAuthority+testProcessPath,
		bytes.NewReader(body),
	)
	request.Host = boundaryTestAuthority
	request.Header.Set("Content-Type", testContentTypeJSON)
	request.Header.Set(
		localCapabilityHeader,
		base64.RawURLEncoding.EncodeToString(secret),
	)
	state := newTransportState(nil)
	state.publishFacts(transportFacts{
		protoMajor: 1,
		protoMinor: 1,
		hostCount:  1,
		hostValue:  boundaryTestAuthority,
	})
	request = request.WithContext(context.WithValue(
		request.Context(),
		transportContextKey{},
		state,
	))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if processor.ledger == nil || !processor.snapshot.ProvedBelowReservation() ||
		processor.snapshot.HighWater != maximumLegalWorkingSetHighWaterBytes {
		t.Fatalf("production maximum-input snapshot = %+v", processor.snapshot)
	}
	if processor.rawBytes != dkim2.HardMaxRawMessageBytes ||
		processor.reverseBytes != maxSMTPPathBytes ||
		processor.recipientCount != dkim2.HardMaxRecipients ||
		processor.envelopeBytes != maxEnvelopeBytes {
		t.Fatal("production maximum-input owner sizes drifted")
	}
	if handler.admission.Owned() != 1 {
		t.Fatal("handler return released the working-set reservation before transport")
	}
	state.finishTransportOwnership()
	released := processor.ledger.Snapshot()
	if handler.admission.Owned() != 0 || released.Live != 0 ||
		released.HighWater != processor.snapshot.HighWater {
		t.Fatalf("terminal production snapshot = %+v", released)
	}
}

// TestGo126WorkingSetCapacityBounds derives the pinned standard-library overlaps.
func TestGo126WorkingSetCapacityBounds(t *testing.T) {
	probe := &workingSetReadAllProbe{remaining: uint64(maxProcessBodyBytes)}
	body, err := io.ReadAll(probe)
	if err != nil || len(body) != int(maxProcessBodyBytes) ||
		uint64(cap(body)) != maximumProcessBodyCapacityBytes ||
		probe.offered != maximumReadAllIntermediateBytes ||
		probe.offered+uint64(cap(body)) != 113_391_936 {
		t.Fatal("Go 1.26 io.ReadAll capacity inventory drifted")
	}
	retained, overlap := go126JSONDecoderCapacities(uint64(maxProcessBodyBytes))
	if retained != maximumJSONDecoderRetainedBytes ||
		overlap != maximumJSONDecoderCapacityBytes {
		t.Fatal("Go 1.26 encoding/json decoder capacity inventory drifted")
	}
	if roundWorkingSetPage(uint64(maxEncodedMessageBytes), 8*1024) !=
		maximumEncodedMessageCapacityBytes {
		t.Fatal("Go 1.26 Base64 allocation inventory drifted")
	}
	if decoded := base64.StdEncoding.DecodedLen(maxEncodedMessageBytes); uint64(decoded) != maximumBase64DecodedCapacityBytes ||
		decoded != dkim2.HardMaxRawMessageBytes+1 {
		t.Fatal("Go 1.26 Base64 decoded capacity inventory drifted")
	}
	if maximumValidationGenericStructureBytes/uint64(maxJSONTokens) < 5_800 {
		t.Fatal("generic OpenAPI value structural allowance drifted")
	}
	bodyLines := bytes.Repeat([]byte("\r\n"), rawmsg.HardMaxBodyLines)
	raw := append([]byte("A: b\r\n\r\n"), bodyLines...)
	message, err := rawmsg.Parse(raw)
	if err != nil {
		t.Fatal("rawmsg maximum BodyLine constructor probe failed")
	}
	lines := message.Body().Lines().Lines()
	if len(lines) != rawmsg.HardMaxBodyLines ||
		cap(lines) != rawmsg.HardMaxBodyLines ||
		maximumLibraryBodyLineIndexBytes != 7_864_320 {
		t.Fatal("Go 1.26 BodyLine capacity inventory drifted")
	}
}

// TestLibraryCurrentWorkingSetSourceBounds locks every current-only owner
// coefficient to its authoritative package limit or concrete Go object size.
func TestLibraryCurrentWorkingSetSourceBounds(t *testing.T) {
	t.Parallel()

	assertRawWorkingSetSourceBounds(t)
	assertCanonicalWorkingSetSourceBounds(t)
	assertProtocolWorkingSetSourceBounds(t)
	assertKeyWorkingSetSourceBounds(t)
	assertResultWorkingSetSourceBounds(t)
	assertWorkingSetPhaseInventory(t)
}

// assertRawWorkingSetSourceBounds checks parser limits and concrete raw-message types.
func assertRawWorkingSetSourceBounds(t testing.TB) {
	t.Helper()
	rawLimits := rawmsg.DefaultParserOptions()
	if rawLimits.MaxMessageBytes != dkim2.HardMaxRawMessageBytes ||
		rawLimits.MaxHeaderBytes != 1<<20 ||
		rawLimits.MaxHeaderFields != 2_000 ||
		rawLimits.MaxBodyLines != rawmsg.HardMaxBodyLines ||
		unsafe.Sizeof(rawmsg.HeaderField{}) != 128 ||
		unsafe.Sizeof(rawmsg.BodyLine{}) != 40 {
		t.Fatal("raw-message working-set source bounds drifted")
	}
}

// assertCanonicalWorkingSetSourceBounds checks canonicalization input limits.
func assertCanonicalWorkingSetSourceBounds(t testing.TB) {
	t.Helper()
	canonicalLimits := canonical.DefaultLimits()
	if canonicalLimits.MaxBodyInputBytes != dkim2.HardMaxRawMessageBytes ||
		canonicalLimits.MaxHeaderInputBytes != 2<<20 ||
		canonicalLimits.MaxSignatureInputBytes != 2<<20 {
		t.Fatal("canonical working-set source bounds drifted")
	}
}

// assertProtocolWorkingSetSourceBounds checks protocol extraction limits and types.
func assertProtocolWorkingSetSourceBounds(t testing.TB) {
	t.Helper()
	instanceLimits := instance.DefaultLimits()
	signatureLimits := signature.DefaultLimits()
	recipeLimits := recipe.DefaultLimits()
	if instanceLimits.MaxInstances != 128 ||
		instanceLimits.MaxHashSets != 16 ||
		signatureLimits.MaxSignatures != 128 ||
		signatureLimits.MaxRecipients != dkim2.HardMaxRecipients ||
		signatureLimits.MaxSignatureSets != 16 ||
		signatureLimits.MaxFlags != 32 ||
		signature.MaxEnvelopePathBytes != maxSMTPPathBytes ||
		recipeLimits.MaxDecodedRecipeBytes != 49_152 ||
		unsafe.Sizeof(instance.MessageInstance{}) != 120 ||
		unsafe.Sizeof(instance.HashSet{}) != 216 ||
		unsafe.Sizeof(signature.Signature{}) != 272 ||
		unsafe.Sizeof(signature.EnvelopePath{}) != 96 ||
		unsafe.Sizeof(signature.Set{}) != 112 ||
		unsafe.Sizeof(signature.Flag{}) != 24 ||
		unsafe.Sizeof(tagvalue.Tag{}) != 56 {
		t.Fatal("protocol extraction working-set source bounds drifted")
	}
}

// assertKeyWorkingSetSourceBounds checks key-resolution bounds.
func assertKeyWorkingSetSourceBounds(t testing.TB) {
	t.Helper()
	keyLimits := keyresolver.HardLimits()
	if keyLimits.MaxSelectorBytes != 253 ||
		keyLimits.MaxSigningDomainBytes != 253 ||
		keyLimits.MaxOwnerBytes != 253 ||
		keyLimits.MaxTXTRecordBytes != 64<<10 ||
		keyLimits.MaxTags != 128 ||
		keyLimits.MaxTagValueBytes != 64<<10 ||
		keyLimits.MaxDecodedKeyBytes != 64<<10 {
		t.Fatal("key-resolution working-set source bounds drifted")
	}
}

// assertResultWorkingSetSourceBounds checks result and policy bounds.
func assertResultWorkingSetSourceBounds(t testing.TB) {
	t.Helper()
	serviceLimits := service.DefaultLimits()
	policyLimits := policy.DefaultLimits()
	if serviceLimits.MaxRecipients != dkim2.HardMaxRecipients ||
		serviceLimits.MaxCheckFacts != 128 ||
		serviceLimits.MaxSignatureFacts != 16 ||
		policyLimits.MaxAuthenticatedHops != 128 ||
		policyLimits.MaxFindings != 128 ||
		unsafe.Sizeof(verify.CheckResult{}) > 256 ||
		unsafe.Sizeof(verify.SignatureSetResult{}) > 256 {
		t.Fatal("result and policy working-set source bounds drifted")
	}
}

// assertWorkingSetPhaseInventory checks the current-only ownership equations.
func assertWorkingSetPhaseInventory(t testing.TB) {
	t.Helper()
	if maximumLibraryHeaderBytes != maximumLibraryFirstHeaderGenerationBytes+
		maximumLibrarySecondHeaderGenerationBytes+
		maximumLibraryThirdHeaderGenerationBytes ||
		maximumLibraryCanonicalProtocolBytes !=
			maximumLibraryCanonicalHeaderRecordBytes+
				maximumLibraryCanonicalHeaderAggregateBytes+
				maximumLibraryCanonicalHeaderCloneBytes+
				maximumLibraryCanonicalSignatureRecordBytes+
				maximumLibraryCanonicalSignatureAggregateBytes+
				maximumLibraryCanonicalSignatureCloneBytes ||
		maximumLibraryEnvelopeBytes !=
			maximumLibraryCoreEnvelopePayloadBytes+
				maximumLibraryCoreEnvelopeSliceBytes+
				maximumLibraryCurrentEnvelopePayloadBytes+
				maximumLibraryCurrentEnvelopeSliceBytes+
				maximumLibrarySignedEnvelopeValueBytes+
				maximumLibrarySignedEnvelopeOriginalBytes+
				maximumLibrarySignedEnvelopeEncodedBytes+
				maximumLibrarySignedEnvelopeDecodedBytes+
				maximumLibrarySignedEnvelopeContainerBytes+
				maximumLibraryCanonicalRecipientBytes+
				maximumLibraryRecipientIdentityMapBytes+
				maximumLibraryEnvelopeTransientPathBytes ||
		maximumLibraryProtocolBytes != maximumLibraryInstanceBytes+
			maximumLibrarySignatureBytes+
			maximumLibraryCanonicalProtocolBytes+
			maximumLibraryEnvelopeBytes+
			maximumLibraryKeyBytes+
			maximumLibraryResultBytes+
			maximumLibraryReplayBytes+
			maximumLibraryPolicyBytes ||
		maximumLibraryParsePhaseBytes > maximumLibraryCurrentPhaseBytes ||
		maximumLibraryRuntimeBytes != maximumLibraryCurrentPhaseBytes {
		t.Fatal("current-only library phase liveness inventory drifted")
	}
}

// TestWorkingSetLedgerTransferPreservesOwnership proves zero-overlap handoff.
func TestWorkingSetLedgerTransferPreservesOwnership(t *testing.T) {
	t.Parallel()

	ledger, err := newWorkingSetLedger(4_096)
	if err != nil {
		t.Fatal("newWorkingSetLedger() failed")
	}
	if err := ledger.Claim(workingSetBodySnapshot, 2_048); err != nil {
		t.Fatal("Claim() failed")
	}
	before := ledger.Snapshot()
	if err := ledger.Transfer(workingSetBodySnapshot, workingSetValidationBodySnapshot); err != nil {
		t.Fatal("Transfer() failed")
	}
	after := ledger.Snapshot()
	if before.Live != after.Live || before.HighWater != after.HighWater ||
		after.OwnedSlots != 1 {
		t.Fatalf("transfer snapshots = before %+v, after %+v", before, after)
	}
	if err := ledger.Release(workingSetValidationBodySnapshot); err != nil {
		t.Fatal("Release() failed")
	}
}

// TestWorkingSetLedgerFailsClosed proves invariant, limit, and arithmetic closure.
func TestWorkingSetLedgerFailsClosed(t *testing.T) {
	t.Parallel()

	t.Run("reservation", func(t *testing.T) {
		ledger, err := newWorkingSetLedger(10)
		if err != nil {
			t.Fatal("newWorkingSetLedger() failed")
		}
		if err := ledger.Claim(workingSetBodySnapshot, 10); err != nil {
			t.Fatal("Claim() rejected exact accounting limit")
		}
		err = ledger.Claim(workingSetGeneratedDTO, 1)
		assertWorkingSetError(t, err, workingSetErrorReservation)
		if err := ledger.Release(workingSetBodySnapshot); err != nil {
			t.Fatal("Release() did not permit cleanup after sticky failure")
		}
		snapshot := ledger.Snapshot()
		if !snapshot.Failed || snapshot.Live != 0 {
			t.Fatal("reservation failure was not sticky through cleanup")
		}
	})

	t.Run(testDuplicateName, func(t *testing.T) {
		ledger, err := newWorkingSetLedger(10)
		if err != nil {
			t.Fatal("newWorkingSetLedger() failed")
		}
		if err := ledger.Claim(workingSetBodySnapshot, 1); err != nil {
			t.Fatal("Claim() failed")
		}
		assertWorkingSetError(t,
			ledger.Claim(workingSetBodySnapshot, 1),
			workingSetErrorInvariant,
		)
	})

	t.Run("invalid_slot", func(t *testing.T) {
		ledger, err := newWorkingSetLedger(10)
		if err != nil {
			t.Fatal("newWorkingSetLedger() failed")
		}
		assertWorkingSetError(t,
			ledger.Claim(workingSetSlotCount, 1),
			workingSetErrorInvariant,
		)
	})

	t.Run("overflow", func(t *testing.T) {
		ledger := &workingSetLedger{limit: math.MaxUint64, live: math.MaxUint64 - 1}
		assertWorkingSetError(t,
			ledger.Claim(workingSetBodySnapshot, 2),
			workingSetErrorOverflow,
		)
	})
}

// TestWorkingSetLedgerErrorsAreContentFree proves every diagnostic is constant.
func TestWorkingSetLedgerErrorsAreContentFree(t *testing.T) {
	t.Parallel()

	const marker = "DO-NOT-RETAIN-WORKING-SET"
	ledger, err := newWorkingSetLedger(1)
	if err != nil {
		t.Fatal("newWorkingSetLedger() failed")
	}
	if err := ledger.Claim(workingSetBodySnapshot, 1); err != nil {
		t.Fatal("Claim() failed")
	}
	err = ledger.Claim(workingSetGeneratedDTO, 1)
	if err == nil || err.Error() != workingSetErrorText ||
		errors.Is(err, errors.New(marker)) {
		t.Fatal("working-set diagnostic was not constant")
	}
}

// TestWorkingSetLedgerConcurrentClaims proves synchronized accounting under race.
func TestWorkingSetLedgerConcurrentClaims(t *testing.T) {
	t.Parallel()

	ledger, err := newWorkingSetLedger(processWorkingSetUnitBytes)
	if err != nil {
		t.Fatal("newWorkingSetLedger() failed")
	}
	slots := []workingSetSlot{
		workingSetBodyReadChunks,
		workingSetBodySnapshot,
		workingSetValidationReadChunks,
		workingSetValidationBodySnapshot,
		workingSetValidationDecoder,
		workingSetValidationValue,
		workingSetGeneratedDecoder,
		workingSetGeneratedDTO,
		workingSetBase64EncodedCopy,
		workingSetBase64Decoded,
		workingSetCanonicalBase64,
		workingSetDomainRequest,
		workingSetVerifyRequest,
		workingSetServiceRequest,
		workingSetServiceExtracted,
		workingSetLibraryRuntime,
	}
	start := make(chan struct{})
	claimed := make(chan error, len(slots))
	release := make(chan struct{})
	var group sync.WaitGroup
	for _, slot := range slots {
		group.Add(1)
		go func(owned workingSetSlot) {
			defer group.Done()
			<-start
			claimErr := ledger.Claim(owned, 1_024)
			claimed <- claimErr
			if claimErr != nil {
				return
			}
			<-release
			_ = ledger.Release(owned)
		}(slot)
	}
	close(start)
	var claimFailed bool
	for range slots {
		if claimErr := <-claimed; claimErr != nil {
			claimFailed = true
		}
	}
	if claimFailed {
		close(release)
		group.Wait()
		t.Fatal("concurrent Claim() failed")
	}
	snapshot := ledger.Snapshot()
	if snapshot.Live != uint64(len(slots))*1_024 ||
		snapshot.OwnedSlots != len(slots) || snapshot.Failed {
		t.Fatalf("concurrent claimed snapshot = %+v", snapshot)
	}
	close(release)
	group.Wait()
	final := ledger.Snapshot()
	if final.Live != 0 || final.OwnedSlots != 0 || final.Failed {
		t.Fatalf("concurrent released snapshot = %+v", final)
	}
}

// claimWorkingSet claims one proof slot or fails the test without exposing data.
func claimWorkingSet(
	t testing.TB,
	ledger *workingSetLedger,
	slot workingSetSlot,
	capacity uint64,
) {
	t.Helper()
	if err := ledger.Claim(slot, capacity); err != nil {
		t.Fatal("working-set proof claim failed")
	}
}

// releaseWorkingSet releases one proof slot or fails the test without exposing data.
func releaseWorkingSet(t testing.TB, ledger *workingSetLedger, slot workingSetSlot) {
	t.Helper()
	if err := ledger.Release(slot); err != nil {
		t.Fatal("working-set proof release failed")
	}
}

// assertWorkingSetError requires one closed working-set error class.
func assertWorkingSetError(
	t testing.TB,
	err error,
	code workingSetErrorCode,
) {
	t.Helper()
	var typed *workingSetError
	if !errors.As(err, &typed) || typed == nil || typed.Code() != code ||
		typed.Error() != workingSetErrorText {
		t.Fatal("unexpected working-set error classification")
	}
}

// go126JSONDecoderCapacities simulates Decoder.refill's pinned 2*cap+512 growth.
func go126JSONDecoderCapacities(size uint64) (uint64, uint64) {
	var previous uint64
	capacity := uint64(512)
	for capacity < size {
		previous = capacity
		capacity = 2*capacity + 512
	}
	return capacity, previous + capacity
}

// workingSetReadAllProbe records each actual Go 1.26 intermediate allocation.
type workingSetReadAllProbe struct {
	remaining uint64
	offered   uint64
}

// Read fills each io.ReadAll allocation and terminates with the final bytes.
func (r *workingSetReadAllProbe) Read(output []byte) (int, error) {
	if r == nil || r.remaining == 0 {
		return 0, io.EOF
	}
	r.offered += uint64(len(output))
	count := min(uint64(len(output)), r.remaining)
	clear(output[:count])
	r.remaining -= count
	if r.remaining == 0 {
		return int(count), io.EOF
	}
	return int(count), nil
}

// roundWorkingSetPage rounds one large allocation to a pinned runtime page.
func roundWorkingSetPage(size uint64, page uint64) uint64 {
	return (size + page - 1) / page * page
}

// buildMaximumLegalProcessBody constructs the exact admitted outer body limit.
func buildMaximumLegalProcessBody(t testing.TB) []byte {
	t.Helper()
	raw := make([]byte, dkim2.HardMaxRawMessageBytes)
	encoded := base64.StdEncoding.EncodeToString(raw)
	if len(encoded) != maxEncodedMessageBytes {
		t.Fatal("maximum raw message did not produce the frozen Base64 length")
	}
	escapedPath := bytes.Repeat([]byte(`\u0001`), maxSMTPPathBytes)
	var body bytes.Buffer
	body.Grow(int(maxProcessBodyBytes))
	body.WriteString(`{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","message":{"raw_rfc5322_base64":"`)
	body.WriteString(encoded)
	body.WriteString(`"},"smtp":{"mail_from":"`)
	body.Write(escapedPath)
	body.WriteString(`","rcpt_to":[`)
	for index := 0; index < dkim2.HardMaxRecipients; index++ {
		if index != 0 {
			body.WriteByte(',')
		}
		body.WriteByte('"')
		body.Write(escapedPath)
		body.WriteByte('"')
	}
	const suffix = "]}}"
	padding := int(maxProcessBodyBytes) - body.Len() - len(suffix)
	if padding < 0 {
		t.Fatal("maximum legal components exceeded the outer body limit")
	}
	body.Write(bytes.Repeat([]byte{' '}, padding))
	body.WriteString(suffix)
	return body.Bytes()
}
