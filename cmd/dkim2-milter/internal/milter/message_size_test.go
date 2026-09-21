package milter

import (
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/resource"
	"testing"
)

// TestSMTPSizeAdmissionThroughEOM preserves aggregate memory accounting at
// an operator-selected 100 MiB message ceiling.
func TestSMTPSizeAdmissionThroughEOM(t *testing.T) {
	const messageBytes = 100 << 20
	admission, err := NewAdmission(2, 2, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	reservation, ok := admission.AdmitMessage(2 * messageBytes)
	if !ok {
		t.Fatal("message admission failed")
	}
	transport, bounded := eomTransportReservationBytes(messageBytes, 256+hardRecipientCount*256)
	if !bounded || !reservation.Grow(transport+resource.EOMResponseWorkingSetBytes) {
		t.Fatal("100 MiB EOM exceeded configured budget")
	}
	other, ok := admission.AdmitMessage(2 * messageBytes)
	if ok {
		if other.Grow(transport + resource.EOMResponseWorkingSetBytes) {
			t.Fatal("two EOMs exceeded aggregate budget")
		}
		other.Release()
	}
	reservation.Release()
	_, messages, retained, _ := admission.snapshot()
	if messages != 0 || retained != 0 {
		t.Fatal("size reservation leaked")
	}
}
