package httpjson

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
)

// batchProductionAggregate is an original and three copies at a 112 MiB
// SMTP message ceiling, the production forwarding case.
const (
	batchProductionMessageBytes = 112 << 20
	batchProductionAggregate    = 4 * batchProductionMessageBytes
)

// TestBatchWorkingSetSizingCoversProductionFanout proves the dedicated batch
// sizing admits the separately padded Base64 of the configured aggregate,
// scales with it, and fails closed outside the closed ceilings.
func TestBatchWorkingSetSizingCoversProductionFanout(t *testing.T) {
	t.Parallel()

	sizing, err := newBatchWorkingSetSizing(batchProductionMessageBytes, batchProductionAggregate, maxProcessWorkingSetBytes)
	if err != nil {
		t.Fatalf("newBatchWorkingSetSizing() error = %v", err)
	}
	if sizing.ProcessBodyBytes() < int64(encodedBatchAggregateBytes(batchProductionAggregate)) ||
		sizing.ProcessBodyBytes() > maxBatchProcessBodyBytes {
		t.Fatalf("batch body %d does not carry the aggregate", sizing.ProcessBodyBytes())
	}
	shared := mustSizing(t, batchProductionMessageBytes)
	if sizing.UnitBytes() <= shared.UnitBytes() || sizing.ProcessBodyBytes() <= shared.ProcessBodyBytes() {
		t.Fatal("batch sizing does not exceed the single-message sizing")
	}
	ceiling, err := newBatchWorkingSetSizing(dkim2.HardMaxRawMessageBytes, maxBatchAggregateMessageBytes, maxProcessWorkingSetBytes)
	if err != nil || ceiling.ProcessBodyBytes() != maxBatchProcessBodyBytes || ceiling.UnitBytes() < sizing.UnitBytes() {
		t.Fatalf("closed batch ceiling body=%d error=%v", ceiling.ProcessBodyBytes(), err)
	}
	if ceiling.UnitBytes() > processWorkingSetAggregateBytes {
		t.Fatal("the closed batch ceiling no longer fits the default budget")
	}
	for _, testCase := range []struct {
		message, aggregate int64
		budget             uint64
	}{
		{batchProductionMessageBytes, batchProductionMessageBytes - 1, maxProcessWorkingSetBytes},
		{batchProductionMessageBytes, maxBatchAggregateMessageBytes + 1, maxProcessWorkingSetBytes},
		{0, batchProductionAggregate, maxProcessWorkingSetBytes},
		{batchProductionMessageBytes, batchProductionAggregate, minProcessWorkingSetBytes - 1},
		{batchProductionMessageBytes, batchProductionAggregate, maxProcessWorkingSetBytes + 1},
		{batchProductionMessageBytes, batchProductionAggregate, minProcessWorkingSetBytes},
	} {
		if _, err := newBatchWorkingSetSizing(testCase.message, testCase.aggregate, testCase.budget); err == nil {
			t.Fatalf("batch sizing accepted %+v", testCase)
		}
	}
}

// TestBatchWorkingSetSizingOverApproximatesMeasuredGrowth replays the ReadAll
// and JSON decoder probes at the production and closed batch bodies.
func TestBatchWorkingSetSizingOverApproximatesMeasuredGrowth(t *testing.T) {
	if raceDetectorEnabled || testing.Short() {
		t.Skip("the batch body probes allocate several GiB")
	}
	for _, aggregate := range []int64{batchProductionAggregate, maxBatchAggregateMessageBytes} {
		sizing, err := newBatchWorkingSetSizing(batchProductionMessageBytes, aggregate, maxProcessWorkingSetBytes)
		if err != nil {
			t.Fatal(err)
		}
		readProbe := &workingSetReadAllProbe{remaining: sizing.processBodyBytes}
		body, err := io.ReadAll(readProbe)
		if err != nil || uint64(len(body)) != sizing.processBodyBytes ||
			uint64(cap(body)) > sizing.processBodyCapacity || readProbe.offered > sizing.readAllIntermediate {
			t.Fatalf("%d aggregate: ReadAll probe exceeded the model", aggregate)
		}
		decoderProbe := &workingSetJSONProbe{remaining: sizing.processBodyBytes}
		var decoded []any
		if err := json.NewDecoder(decoderProbe).Decode(&decoded); err != nil {
			t.Fatalf("%d aggregate: JSON probe failed: %v", aggregate, err)
		}
		if overlap := decoderProbe.previous + decoderProbe.capacity; overlap != sizing.jsonDecoderCapacity {
			t.Fatalf("%d aggregate: measured JSON overlap %d is not the modelled %d",
				aggregate, overlap, sizing.jsonDecoderCapacity)
		}
		t.Logf("aggregate=%d body=%d unit=%d", aggregate, sizing.processBodyBytes, sizing.UnitBytes())
	}
}

// TestBoundaryResourcesProveJointBatchBudget proves the shared and batch
// pools must fit one budget together and that the default keeps batch on the
// shared sizing while advertising the deployment's real transport ceiling.
func TestBoundaryResourcesProveJointBatchBudget(t *testing.T) {
	t.Parallel()

	shared, err := newBoundaryResources(BoundaryConfig{MessageBytes: batchProductionMessageBytes, MaxInFlight: 1})
	if err != nil || shared.batchAdmission != nil ||
		shared.batchLimits != (batchLimits{aggregate: app.MaxBatchRevisionMessageBytes, request: shared.sizing.ProcessBodyBytes()}) {
		t.Fatalf("default resources error=%v limits=%+v", err, shared.batchLimits)
	}
	production := BoundaryConfig{
		MessageBytes: batchProductionMessageBytes, MaxInFlight: 2,
		WorkingSetBytes: 12 << 30, BatchAggregateBytes: batchProductionAggregate, BatchMaxInFlight: 1,
	}
	resources, err := newBoundaryResources(production)
	if err != nil || resources.batchAdmission == nil ||
		resources.batchLimits.aggregate != batchProductionAggregate ||
		resources.batchLimits.request != resources.batchSizing.ProcessBodyBytes() {
		t.Fatalf("production resources error=%v", err)
	}
	admission, sizing := (&HTTPBoundary{
		admission: resources.admission, sizing: resources.sizing,
		batchAdmission: resources.batchAdmission, batchSizing: resources.batchSizing,
	}).routeResources(batchRevisePath)
	if admission != resources.batchAdmission || sizing.UnitBytes() != resources.batchSizing.UnitBytes() {
		t.Fatal("the batch route does not own the dedicated pool")
	}
	for name, config := range map[string]BoundaryConfig{
		"default budget":    func() BoundaryConfig { c := production; c.WorkingSetBytes = 0; return c }(),
		"two batch permits": func() BoundaryConfig { c := production; c.BatchMaxInFlight = 2; return c }(),
		"aggregate below msg": func() BoundaryConfig {
			c := production
			c.BatchAggregateBytes = batchProductionMessageBytes - 1
			return c
		}(),
		"permits without batch": {MessageBytes: batchProductionMessageBytes, MaxInFlight: 1, BatchMaxInFlight: 1},
	} {
		if _, err := newBoundaryResources(config); err == nil {
			t.Fatalf("%s was admitted", name)
		}
	}
}

// TestBatchMappingEnforcesConfiguredAggregate proves the mapper applies the
// advertised aggregate rather than the default constant.
func TestBatchMappingEnforcesConfiguredAggregate(t *testing.T) {
	f := newBatchBoundaryFixture(t)
	original, err := f.request.Original.Message.RawRfc5322Base64.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	total := base64.StdEncoding.DecodedLen(len(original)) - bytes.Count(original, []byte("="))
	for _, branch := range f.request.Copies {
		encoded, encodedErr := branch.Message.RawRfc5322Base64.Bytes()
		if encodedErr != nil {
			t.Fatal(encodedErr)
		}
		total += base64.StdEncoding.DecodedLen(len(encoded)) - bytes.Count(encoded, []byte("="))
	}
	if _, err := mapBatchRevisionRequestWithin(f.request, total); err != nil {
		t.Fatalf("exact aggregate error = %v", err)
	}
	if _, err := mapBatchRevisionRequestWithin(f.request, total-1); !IsMappingError(err, MappingRequestTooLarge) {
		t.Fatalf("one-over aggregate error = %v", err)
	}
	for _, aggregate := range []int{0, app.HardMaxBatchRevisionMessageBytes + 1} {
		if _, err := mapBatchRevisionRequestWithin(f.request, aggregate); !IsMappingError(err, MappingInternalContract) {
			t.Fatalf("aggregate %d error = %v", aggregate, err)
		}
	}
	for _, limits := range []batchLimits{
		{aggregate: 0, request: 1}, {aggregate: 1, request: 0},
		{aggregate: app.HardMaxBatchRevisionMessageBytes + 1, request: 1},
		{aggregate: 1, request: maxBatchProcessBodyBytes + 1},
	} {
		if limits.valid() {
			t.Fatalf("batch limits %+v were valid", limits)
		}
	}
}

// TestBatchRevisionHTTPDedicatedPoolAdmitsConfiguredAggregate proves a batch
// whose body exceeds the single-message transport ceiling is refused on the
// shared sizing and admitted, signed, and advertised with a configured
// aggregate.
func TestBatchRevisionHTTPDedicatedPoolAdmitsConfiguredAggregate(t *testing.T) {
	const messageBytes = 3 << 20
	body := bytes.Repeat([]byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab\r\n"), 33_000)
	shared := newBatchBoundaryFixtureWith(t, body, 2, BoundaryConfig{MessageBytes: messageBytes})
	wire := marshalBatch(t, shared.request)
	if int64(len(wire)) <= mustSizing(t, messageBytes).ProcessBodyBytes() {
		t.Fatalf("fixture body %d does not exceed the shared ceiling", len(wire))
	}
	if status, _ := exchangeBatch(t, shared, wire, shared.capability); status != 413 {
		t.Fatalf("shared sizing status = %d, want 413", status)
	}
	dedicated := newBatchBoundaryFixtureWith(t, body, 2, BoundaryConfig{
		MessageBytes: messageBytes, BatchAggregateBytes: 12 << 20, RequestDeadline: 100 * time.Second,
	})
	status, result := exchangeBatch(t, dedicated, marshalBatch(t, dedicated.request), dedicated.capability)
	if status != 200 || result.Result != generated.BatchRevisionResponseResultPass || len(result.Outputs) != 2 {
		t.Fatalf("dedicated pool status=%d result=%s outputs=%d", status, result.Result, len(result.Outputs))
	}
	raw := rawBoundaryExchange(t, dedicated.address, "GET "+batchCapabilitiesPath+" HTTP/1.1\r\nHost: "+dedicated.address+
		"\r\n"+batchReviseCapabilityHeader+": "+dedicated.capability+"\r\nConnection: close\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), nil)
	if err != nil {
		t.Fatal("capability response malformed")
	}
	defer func() { _ = response.Body.Close() }()
	batchSizing, err := newBatchWorkingSetSizing(messageBytes, 12<<20, processWorkingSetAggregateBytes)
	if err != nil {
		t.Fatal(err)
	}
	var advertised generated.BatchRevisionCapabilities
	if json.NewDecoder(response.Body).Decode(&advertised) != nil ||
		advertised.MaxAggregateMessageBytes != 12<<20 || advertised.MaxRequestBytes != batchSizing.ProcessBodyBytes() {
		t.Fatalf("advertised capability = %+v", advertised)
	}
}

// TestServerSettingsAdmitOnlyJointlyOwnedBatchConcurrency proves the server
// configuration gate uses the same joint budget proof as the boundary.
func TestServerSettingsAdmitOnlyJointlyOwnedBatchConcurrency(t *testing.T) {
	t.Parallel()

	production := serverSettings{
		messageBytes: batchProductionMessageBytes, maxInFlight: 2, workingSetBytes: 12 << 30,
		batchAggregate: batchProductionAggregate, batchMaxInFlight: 1,
	}
	if !production.admittedConcurrency() {
		t.Fatal("the production batch settings were refused")
	}
	tooSmall := production
	tooSmall.workingSetBytes = 0
	if tooSmall.admittedConcurrency() {
		t.Fatal("the default budget admitted the production batch settings")
	}
	if batchPermits(0, 1) != 0 || batchPermits(batchProductionAggregate, 1) != 1 {
		t.Fatal("batch permits leaked into the shared configuration")
	}
}
