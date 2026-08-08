package rotationadmin

import (
	"bytes"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// TestPurgePlanArtifactRoundTripRejectsTampering freezes durable canonical plan recovery.
func TestPurgePlanArtifactRoundTripRejectsTampering(t *testing.T) {
	request, authority, inventory := purgeExecutionFixture(t)
	if request == nil || request.plan == nil {
		t.Fatal("purge fixture missing plan")
	}
	document, err := MarshalPurgePlanArtifact(request.plan)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := ParsePurgePlanArtifact(document)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close() //nolint:errcheck // Test cleanup has no recovery.
	if !recovered.ArtifactDigest().Equal(request.plan.ArtifactDigest()) {
		t.Fatal("artifact digest changed across round trip")
	}
	apply, err := NewPurgeApplyRequest(recovered, true)
	if err != nil {
		t.Fatal(err)
	}
	if fence, verifyErr := apply.VerifyReadback(datasourceadmin.BackendLDAP, authority, inventory); verifyErr != nil || !fence.Ready() {
		t.Fatal("recovered artifact did not retain fresh-readback fence")
	}
	tampered := bytes.Replace(document, []byte(`"current":2`), []byte(`"current":3`), 1)
	if _, err := ParsePurgePlanArtifact(tampered); err == nil {
		t.Fatal("tampered artifact accepted")
	}
	if _, err := ParsePurgePlanArtifact(append(document, '\n')); err == nil {
		t.Fatal("noncanonical artifact accepted")
	}
}
