package verify

import (
	"encoding/hex"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/replay"
)

// TestOriginReplayDigestGolden freezes the Draft-06 origin framing and digest.
func TestOriginReplayDigestGolden(t *testing.T) {
	raw, err := hex.DecodeString("46726f6d3a20616c696365406578616d706c652e746573740d0a5375626a6563743a207265706c61790d0a0d0a68656c6c6f0d0a")
	if err != nil {
		t.Fatal(err)
	}
	message, err := rawmsg.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest, ok := originReplayDigest(message)
	if !ok {
		t.Fatal("origin replay digest unavailable")
	}
	if got, want := hex.EncodeToString(digest[:]), "63519c8a3d2e4d5f6fb9e689259be264a058a3a9fbc8bb5a9a904bef0e9d9cd5"; got != want {
		t.Fatalf("origin digest = %s, want %s", got, want)
	}
}

// TestOriginReplayFrameGolden freezes the complete independently constructed frame.
func TestOriginReplayFrameGolden(t *testing.T) {
	header, _ := hex.DecodeString("66726f6d3a616c696365406578616d706c652e746573740d0a7375626a6563743a7265706c61790d0a")
	body, _ := hex.DecodeString("68656c6c6f0d0a")
	got := hex.EncodeToString(originReplayFrame(header, body))
	want := "646b696d322d7265706c61792d6f726967696e2d76310001010000001d64726166742d696574662d646b696d2d646b696d322d737065632d303602000000000000002966726f6d3a616c696365406578616d706c652e746573740d0a7375626a6563743a7265706c61790d0a03000000000000000768656c6c6f0d0a"
	if got != want {
		t.Fatalf("origin frame = %s, want %s", got, want)
	}
}

// TestReplayProjectionIsFixedSizeAndRedacted proves only sealed origin facts cross the boundary.
func TestReplayProjectionIsFixedSizeAndRedacted(t *testing.T) {
	digest := [32]byte{1, 2, 3}
	projection := newReplayProjection(digest, true)
	if !projection.Valid() || projection.Draft() != replay.DraftIdentifier || !projection.Exploded() || projection.OriginReplayAlgorithm() != originReplayAlgorithm {
		t.Fatalf("projection invalid: %v", projection)
	}
	got, ok := projection.OriginReplayDigest()
	if !ok || got != digest {
		t.Fatal("origin digest was not retained by value")
	}
	if projection.String() != replayProjectionRedactedText {
		t.Fatal("projection formatting was not redacted")
	}
}
