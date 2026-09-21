package httpjson

import (
	"encoding/json"
	"io"
	"testing"
	"unsafe"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/internal/rawmsg"
)

// sizingProbeCeilings are the deployment ceilings every sizing proof replays.
// They span a small forwarding deployment, the daemon default, the production
// SMTP ceiling and the closed library maximum. The two growth-boundary entries
// place the request body exactly on a decoder doubling step, which is where a
// ratio model would break first: a ceiling of 1,968,576 bytes yields a body of
// exactly 2^23, and 8,388,584 bytes yields exactly 2^25.
var sizingProbeCeilings = []int64{
	1 << 20,
	1_968_576,
	8_388_584,
	8 << 20,
	32 << 20,
	100 << 20,
	dkim2.HardMaxRawMessageBytes,
}

// TestWorkingSetBodyLineLiteralsMatchTheParser pins the BodyLine literals the
// deployment sizing carries against the parser ceiling and the concrete Go
// object size they stand for. Production accounting keeps literals so it does
// not depend on library internals; this probe is what makes that safe.
func TestWorkingSetBodyLineLiteralsMatchTheParser(t *testing.T) {
	t.Parallel()

	if workingSetBodyLineCeiling != uint64(rawmsg.HardMaxBodyLines) {
		t.Fatalf("BodyLine ceiling literal %d drifted from the parser %d",
			workingSetBodyLineCeiling, rawmsg.HardMaxBodyLines)
	}
	if workingSetBodyLineBytes != uint64(unsafe.Sizeof(rawmsg.BodyLine{})) {
		t.Fatalf("BodyLine size literal %d drifted from the Go object %d",
			workingSetBodyLineBytes, unsafe.Sizeof(rawmsg.BodyLine{}))
	}
	ceiling := ceilingSizing(t)
	if ceiling.bodyLineIndexBytes() != maximumLibraryBodyLineIndexBytes {
		t.Fatalf("scaled BodyLine index %d drifted from the pinned %d",
			ceiling.bodyLineIndexBytes(), maximumLibraryBodyLineIndexBytes)
	}
}

// TestWorkingSetSizingScalesWithConfiguredCeiling proves the per-request
// reservation follows server.message_bytes instead of the closed library
// maximum, so a narrower deployment may own proportionally more concurrency.
// Before this relation existed every deployment paid the 128 MiB worst case
// and the process budget admitted exactly two requests.
func TestWorkingSetSizingScalesWithConfiguredCeiling(t *testing.T) {
	t.Parallel()

	previousUnit := uint64(0)
	previousInFlight := 0
	for index, messageBytes := range sizingProbeCeilings {
		sizing := mustSizing(t, messageBytes)
		// The reservation is monotone in the ceiling and concurrency is its
		// inverse. Two ceilings that round to the same inventory share both,
		// so the relation is non-strict.
		if index > 0 {
			if sizing.UnitBytes() < previousUnit {
				t.Fatalf("%d bytes: reservation %d shrank below the narrower ceiling's %d",
					messageBytes, sizing.UnitBytes(), previousUnit)
			}
			if sizing.MaxInFlight() > previousInFlight {
				t.Fatalf("%d bytes: concurrency %d grew with the ceiling",
					messageBytes, sizing.MaxInFlight())
			}
		}
		if sizing.MaxInFlight() < 1 {
			t.Fatalf("%d bytes: no admitted concurrency", messageBytes)
		}
		if uint64(sizing.MaxInFlight())*sizing.UnitBytes() > processWorkingSetAggregateBytes {
			t.Fatalf("%d bytes: concurrency exceeds the process budget", messageBytes)
		}
		previousUnit, previousInFlight = sizing.UnitBytes(), sizing.MaxInFlight()
	}
	// The production SMTP ceiling must admit more than one request, otherwise
	// an MTA that splits one message to two recipients always defers one.
	if inFlight := mustSizing(t, 100<<20).MaxInFlight(); inFlight < 2 {
		t.Fatalf("100 MiB deployment admits only %d concurrent requests", inFlight)
	}
	// A materially narrower ceiling must reserve materially less.
	if mustSizing(t, 8<<20).UnitBytes() >= mustSizing(t, dkim2.HardMaxRawMessageBytes).UnitBytes()/2 {
		t.Fatal("an 8 MiB deployment still pays the library maximum")
	}
}

// TestWorkingSetSizingFailsClosed proves unusable ceilings are refused.
func TestWorkingSetSizingFailsClosed(t *testing.T) {
	t.Parallel()

	for _, messageBytes := range []int64{0, -1, dkim2.HardMaxRawMessageBytes + 1} {
		if _, err := newWorkingSetSizing(messageBytes); err == nil {
			t.Fatalf("newWorkingSetSizing(%d) accepted an unsupported ceiling", messageBytes)
		}
	}
}

// TestWorkingSetSizingOverApproximatesMeasuredGrowth is the safety proof for
// the two terms that are not analytic in the input size. The ReadAll growth
// series and the JSON decoder buffer replacement are measured with the same
// probes that pin the ceiling inventory, and the modelled bound must cover the
// measurement at every supported deployment ceiling. Over-approximation is the
// only safe direction: an undercut reservation would let one request own more
// memory than the process budget accounted for.
func TestWorkingSetSizingOverApproximatesMeasuredGrowth(t *testing.T) {
	for _, messageBytes := range sizingProbeCeilings {
		sizing := mustSizing(t, messageBytes)

		readProbe := &workingSetReadAllProbe{remaining: sizing.processBodyBytes}
		body, err := io.ReadAll(readProbe)
		if err != nil || uint64(len(body)) != sizing.processBodyBytes {
			t.Fatalf("%d bytes: ReadAll probe failed", messageBytes)
		}
		if uint64(cap(body)) > sizing.processBodyCapacity {
			t.Fatalf("%d bytes: measured body capacity %d exceeds modelled %d",
				messageBytes, cap(body), sizing.processBodyCapacity)
		}
		if readProbe.offered > sizing.readAllIntermediate {
			t.Fatalf("%d bytes: measured ReadAll intermediate %d exceeds modelled %d",
				messageBytes, readProbe.offered, sizing.readAllIntermediate)
		}

		decoderProbe := &workingSetJSONProbe{remaining: sizing.processBodyBytes}
		var decoded []any
		if err := json.NewDecoder(decoderProbe).Decode(&decoded); err != nil {
			t.Fatalf("%d bytes: JSON probe failed: %v", messageBytes, err)
		}
		// The decoder model is an equality, not a bound: any deviation means
		// the buffer progression itself changed.
		if overlap := decoderProbe.previous + decoderProbe.capacity; overlap != sizing.jsonDecoderCapacity {
			t.Fatalf("%d bytes: measured JSON overlap %d is not the modelled %d",
				messageBytes, overlap, sizing.jsonDecoderCapacity)
		}
		t.Logf("%10d bytes: body=%d readall=%d/%d json=%d/%d unit=%d in_flight=%d",
			messageBytes, sizing.processBodyBytes,
			readProbe.offered, sizing.readAllIntermediate,
			decoderProbe.previous+decoderProbe.capacity, sizing.jsonDecoderCapacity,
			sizing.UnitBytes(), sizing.MaxInFlight())
	}
}
