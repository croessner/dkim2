package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/replay"
	"github.com/croessner/dkim2/internal/verify"
)

// TestServiceMapsOnlySealedPassingReplayProjection verifies the trusted verify-to-service boundary.
func TestServiceMapsOnlySealedPassingReplayProjection(t *testing.T) {
	const timestamp = uint64(1700000000)
	raw, key := signedFlaggedPolicyMessage(t, timestamp)
	config := DefaultConfig()
	config.Clock = func() time.Time { return time.Unix(int64(timestamp), 0) }
	coordinator, err := NewVerifier(passingPolicyProvider{key: key}, config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.Verify(context.Background(), NewRequest(
		raw, []byte("<>"), [][]byte{[]byte("<rcpt@EXAMPLE.TEST>")},
	))
	if err != nil || result.State() != StatePASS {
		t.Fatalf("Verify() = %q, %v", result.State(), err)
	}
	projection, ok := result.ReplayProjection()
	if !ok || !projection.Valid() || projection.Draft() != replay.DraftIdentifier ||
		projection.RecipientCount() != 1 || !projection.Exploded() {
		t.Fatalf("ReplayProjection() = valid:%t recipients:%d exploded:%t ok:%t",
			projection.Valid(), projection.RecipientCount(), projection.Exploded(), ok)
	}
	message, messagePresent := projection.MessageDigest()
	signature, signaturePresent := projection.SignatureInputDigest()
	if !messagePresent || !signaturePresent || message == ([32]byte{}) || signature == ([32]byte{}) {
		t.Fatal("service projection lost authenticated digests")
	}

	manual := mapVerificationResult(verify.NewResultWithCustody(
		verify.Target{Sequence: 1, InstanceNumber: 1},
		verify.TargetStatusPass,
		requiredPassChecks(verify.Target{Sequence: 1, InstanceNumber: 1}),
		[]verify.SignatureSetResult{{
			Index: 0, Algorithm: verify.AlgorithmRSASHA256,
			Status: verify.SignatureSetStatusPass, KeyStatus: verify.KeyStatusFound,
		}},
		verify.CustodyStatusNotPresent,
	), DefaultLimits())
	if forged, forgedOK := manual.ReplayProjection(); forgedOK || forged.Valid() {
		t.Fatal("copyable verification facts forged service replay provenance")
	}
}

// TestServiceReplayProjectionFormattingDoesNotExposePrivateFacts verifies nested service Result privacy.
func TestServiceReplayProjectionFormattingDoesNotExposePrivateFacts(t *testing.T) {
	var marker [32]byte
	copy(marker[:], []byte("TOXIC-SERVICE-REPLAY-MARKER"))
	projection := ReplayProjection{state: &replayProjectionState{
		draft:         replay.DraftIdentifier,
		messageDigest: marker, hasMessageDigest: true,
		signatureInputDigest: marker, hasSignatureInputDigest: true,
		recipientDigests: [][32]byte{marker},
		sealed:           true,
	}}
	result := Result{replayProjection: projection, hasReplayProjection: true}
	for _, value := range []any{
		projection, &projection, result, &result,
		[]Result{result}, map[string]Result{"result": result},
	} {
		formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x|%p", value, value, value, value, value, value, value)
		if strings.Contains(formatted, "TOXIC") || strings.Contains(formatted, "544f584943") ||
			strings.Contains(formatted, "84 79 88 73 67") {
			t.Fatal("formatting exposed replay facts")
		}
		encoded, err := json.Marshal(value)
		if err != nil || strings.Contains(string(encoded), "TOXIC") ||
			strings.Contains(string(encoded), "VE9YSUM") {
			t.Fatalf("json.Marshal(%T) = %s, %v", value, encoded, err)
		}
	}
}
