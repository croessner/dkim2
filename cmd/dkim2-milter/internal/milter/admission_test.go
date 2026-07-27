package milter

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/resource"
)

// TestExactConfiguredMaximumWorkingSetCompletesEOM proves the checked config
// boundary includes retained maximum envelope bytes through the final write.
func TestExactConfiguredMaximumWorkingSetCompletesEOM(t *testing.T) {
	const (
		messageBytes   = 4 << 20
		recipientCount = 1
	)
	maximumBytes, bounded := resource.MaximumEOMWorkingSetBytes(
		messageBytes,
		recipientCount,
	)
	if !bounded || maximumBytes != 58_919_936 {
		t.Fatalf("maximum working set = (%d,%t)", maximumBytes, bounded)
	}
	admission, err := NewAdmission(1, 1, maximumBytes)
	if err != nil {
		t.Fatal(err)
	}
	handler := &testHandler{result: Result{
		Operation: operationProcess,
		Result:    resultPass,
		Outcome:   DispositionContinue,
	}}
	session, err := NewSession(handler, admission, Limits{
		MessageBytes: messageBytes, HeaderBytes: 1, HeaderCount: 1,
		HeaderFieldBytes: 1, RecipientCount: recipientCount,
	}, time.Second, FailurePolicy{}, modeInbound, "")
	if err != nil {
		t.Fatal(err)
	}
	session.state = stateHelo
	path := []byte(
		"<" + strings.Repeat("a", 64) + "@" +
			strings.Repeat("b", 63) + "." +
			strings.Repeat("c", 63) + "." +
			strings.Repeat("d", 61) + ">",
	)
	payload := append(append([]byte{}, path...), 0)
	if len(path) != 256 {
		t.Fatalf("maximum path length = %d", len(path))
	}
	if err := session.handleMail(payload); err != nil {
		t.Fatal(err)
	}
	if err := session.handleRecipient(payload); err != nil {
		t.Fatal(err)
	}
	if err := session.handleEOH(); err != nil {
		t.Fatal(err)
	}
	if err := session.handleBody(make([]byte, messageBytes-2)); err != nil {
		t.Fatal(err)
	}
	frames, err := session.endMessage(context.Background())
	if err != nil || handler.calls != 1 {
		t.Fatalf("endMessage() frames=%x calls=%d error=%v", frames, handler.calls, err)
	}
	_, messages, retained, _ := admission.snapshot()
	if messages != 1 || retained > maximumBytes {
		t.Fatalf("pre-write snapshot messages=%d bytes=%d", messages, retained)
	}
	if err := writeFrames(io.Discard, frames); err != nil {
		t.Fatal(err)
	}
	session.resetTransaction()
	handler.message.clear()
	_, messages, retained, _ = admission.snapshot()
	if messages != 0 || retained != 0 {
		t.Fatalf("post-write snapshot messages=%d bytes=%d", messages, retained)
	}
}

// TestAdmissionAccountsAndReleasesExactlyOnce proves all three process-wide limits.
func TestAdmissionAccountsAndReleasesExactlyOnce(t *testing.T) {
	admission, err := NewAdmission(2, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	releaseOne, ok := admission.AdmitConnection()
	if !ok {
		t.Fatal("first connection was not admitted")
	}
	releaseTwo, ok := admission.AdmitConnection()
	if !ok {
		t.Fatal("second connection was not admitted")
	}
	if _, ok := admission.AdmitConnection(); ok {
		t.Fatal("connection beyond limit was admitted")
	}
	reservation, ok := admission.AdmitMessage(4)
	if !ok || !reservation.Grow(6) || reservation.Grow(1) ||
		!reservation.Shrink(3) || reservation.Shrink(8) {
		t.Fatal("message byte admission did not enforce the exact cap")
	}
	if _, ok := admission.AdmitMessage(0); ok {
		t.Fatal("message beyond in-flight limit was admitted")
	}
	connections, messages, retained, stopping := admission.snapshot()
	if connections != 2 || messages != 1 || retained != 7 || stopping {
		t.Fatalf("snapshot = (%d,%d,%d,%t)", connections, messages, retained, stopping)
	}
	reservation.Release()
	reservation.Release()
	releaseOne()
	releaseOne()
	releaseTwo()
	connections, messages, retained, _ = admission.snapshot()
	if connections != 0 || messages != 0 || retained != 0 {
		t.Fatalf("released snapshot = (%d,%d,%d)", connections, messages, retained)
	}
}

// TestDefaultAdmissionFitsOneMaximumMessageThroughEOM proves the configured
// 256 MiB default covers retained message bytes plus maximum envelope,
// Base64/JSON/HTTP request copies, and the bounded response working set for one
// 32 MiB message through its terminal Milter write.
func TestDefaultAdmissionFitsOneMaximumMessageThroughEOM(t *testing.T) {
	const (
		defaultBufferedBytes = 256 << 20
		maximumEnvelopeBytes = 256 + hardRecipientCount*256
	)
	admission, err := NewAdmission(2, 2, defaultBufferedBytes)
	if err != nil {
		t.Fatal(err)
	}
	messageReservation, ok := admission.AdmitMessage(2 * hardMessageBytes)
	if !ok {
		t.Fatal("maximum message retained-byte reservation was rejected")
	}
	transportBytes, bounded := eomTransportReservationBytes(
		hardMessageBytes,
		maximumEnvelopeBytes,
	)
	if !bounded {
		t.Fatal("maximum transport reservation overflowed")
	}
	if !messageReservation.Grow(transportBytes + resource.EOMResponseWorkingSetBytes) {
		t.Fatal("one configured maximum message was rejected at EOM")
	}
	if _, ok := admission.AdmitMessage(2 * hardMessageBytes); ok {
		t.Fatal("concurrent maximum message exceeded the process byte cap")
	}
	messageReservation.Release()
	_, messages, retained, _ := admission.snapshot()
	if messages != 0 || retained != 0 {
		t.Fatalf("released maximum snapshot = (%d,%d)", messages, retained)
	}
}

// TestAdmissionStopRejectsNewWorkAndLetsExistingReservationsDrain proves shutdown accounting.
func TestAdmissionStopRejectsNewWorkAndLetsExistingReservationsDrain(t *testing.T) {
	admission, err := NewAdmission(1, 1, 8)
	if err != nil {
		t.Fatal(err)
	}
	release, ok := admission.AdmitConnection()
	if !ok {
		t.Fatal("connection was not admitted")
	}
	reservation, ok := admission.AdmitMessage(2)
	if !ok {
		t.Fatal("message was not admitted")
	}
	admission.Stop()
	if _, ok := admission.AdmitConnection(); ok {
		t.Fatal("connection admitted after Stop")
	}
	if _, ok := admission.AdmitMessage(0); ok {
		t.Fatal("message admitted after Stop")
	}
	if !reservation.Grow(6) {
		t.Fatal("existing reservation could not finish while draining")
	}
	reservation.Release()
	release()
	connections, messages, retained, stopping := admission.snapshot()
	if connections != 0 || messages != 0 || retained != 0 || !stopping {
		t.Fatalf("drained snapshot = (%d,%d,%d,%t)", connections, messages, retained, stopping)
	}
}

// TestAdmissionConcurrentReleaseDoesNotUnderflow proves once-only accounting under races.
func TestAdmissionConcurrentReleaseDoesNotUnderflow(t *testing.T) {
	admission, err := NewAdmission(1, 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	release, ok := admission.AdmitConnection()
	if !ok {
		t.Fatal("connection was not admitted")
	}
	reservation, ok := admission.AdmitMessage(64)
	if !ok {
		t.Fatal("message was not admitted")
	}
	var group sync.WaitGroup
	for range 32 {
		group.Add(2)
		go func() {
			defer group.Done()
			release()
		}()
		go func() {
			defer group.Done()
			reservation.Release()
		}()
	}
	group.Wait()
	connections, messages, retained, _ := admission.snapshot()
	if connections != 0 || messages != 0 || retained != 0 {
		t.Fatalf("concurrent release snapshot = (%d,%d,%d)", connections, messages, retained)
	}
}

// TestAdmissionRejectsInvalidConstruction freezes closed invalid limits.
func TestAdmissionRejectsInvalidConstruction(t *testing.T) {
	for _, limits := range [][3]int64{
		{0, 1, 1},
		{1, 0, 1},
		{1, 2, 1},
		{1, 1, 0},
	} {
		if _, err := NewAdmission(int(limits[0]), int(limits[1]), limits[2]); err == nil {
			t.Fatalf("NewAdmission(%v) succeeded", limits)
		}
	}
}
