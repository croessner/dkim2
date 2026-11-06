package service

import (
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/replay"
)

// TestServiceReplayProjectionFormattingDoesNotExposePrivateFacts verifies nested result privacy.
func TestServiceReplayProjectionFormattingDoesNotExposePrivateFacts(t *testing.T) {
	var marker [32]byte
	copy(marker[:], []byte("TOXIC-ORIGIN-DIGEST-MARKER"))
	projection := ReplayProjection{state: &replayProjectionState{draft: replay.DraftIdentifier, originDigest: marker, hasOriginDigest: true, exploded: true, sealed: true}}
	result := Result{replayProjection: projection, hasReplayProjection: true}
	for _, value := range []string{fmt.Sprint(projection), fmt.Sprintf("%+v", projection), fmt.Sprint(result)} {
		if strings.Contains(value, "TOXIC") {
			t.Fatalf("format leaked origin fact: %q", value)
		}
	}
}

// TestServiceReplayProjectionClonesFixedOriginFact verifies immutable facade transfer.
func TestServiceReplayProjectionClonesFixedOriginFact(t *testing.T) {
	digest := [32]byte{1, 2, 3}
	projection := ReplayProjection{state: &replayProjectionState{draft: replay.DraftIdentifier, originDigest: digest, hasOriginDigest: true, sealed: true}}
	if !projection.Valid() {
		t.Fatal("projection invalid")
	}
	clone := projection.clone()
	clone.state.originDigest[0] = 9
	got, ok := projection.OriginReplayDigest()
	if !ok || got != digest {
		t.Fatal("clone mutation changed source")
	}
}
