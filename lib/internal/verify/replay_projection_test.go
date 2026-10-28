package verify

import (
	"encoding/hex"
	"testing"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/replay"
)

// replayTestInstance parses one Message-Instance header value for replay identity tests.
func replayTestInstance(t *testing.T, value string) instance.MessageInstance {
	t.Helper()
	message, err := rawmsg.Parse([]byte("Message-Instance: " + value + "\r\n\r\n"))
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}
	parsed, err := instance.Parse(message.Headers().FieldsByName("message-instance")[0])
	if err != nil {
		t.Fatalf("instance.Parse() error = %v", err)
	}
	return parsed
}

// replayTestDigest returns the origin identity for one m=1 instance value.
func replayTestDigest(t *testing.T, value string) [32]byte {
	t.Helper()
	digest, ok := originReplayDigest(replayTestInstance(t, value))
	if !ok {
		t.Fatalf("origin replay digest unavailable for %q", value)
	}
	return digest
}

const (
	replayTestSHA256A = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	replayTestSHA256B = "sha256:AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	replayTestSHA512  = "sha512:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=="
)

// TestOriginReplayDigestGolden freezes the declaration framing and digest.
func TestOriginReplayDigestGolden(t *testing.T) {
	digest := replayTestDigest(t, "m=1; h="+replayTestSHA256A)
	if got, want := hex.EncodeToString(digest[:]), "8dafd38c8dae171b5d1a1f9a2be68a984a9844c8a7bf8ff8704ca5e407acd40e"; got != want {
		t.Fatalf("origin digest = %s, want %s", got, want)
	}
}

// TestOriginReplayFrameGolden freezes the complete independently constructed frame.
func TestOriginReplayFrameGolden(t *testing.T) {
	got := hex.EncodeToString(originReplayFrame("sha256", []byte{0xaa}, []byte{0xbb, 0xcc}))
	want := "646b696d322d7265706c61792d6f726967696e2d6465636c61726174696f6e2d76310001010000001d64726166742d696574662d646b696d2d646b696d322d737065632d303802000000067368613235360300000001aa0400000002bbcc"
	if got != want {
		t.Fatalf("origin frame = %s, want %s", got, want)
	}
}

// TestOriginReplayDigestFollowsDeclarationEquality pins the local Draft-08
// Section 15.1 equality: identical m=1 declarations group (independent of a
// Recipe or base64 folding), a changed header
// hash separates, SHA-256 is preferred so SHA-256-only and mixed sets group,
// and a SHA-512-only set never groups with a mixed set.
func TestOriginReplayDigestFollowsDeclarationEquality(t *testing.T) {
	sha256Only := replayTestDigest(t, "m=1; h="+replayTestSHA256A)
	mixed := replayTestDigest(t, "m=1; h="+replayTestSHA512+","+replayTestSHA256A)
	sha512Only := replayTestDigest(t, "m=1; h="+replayTestSHA512)
	changedHeader := replayTestDigest(t, "m=1; h="+replayTestSHA256B)
	withRecipe := replayTestDigest(t, "m=1; h="+replayTestSHA256A+"; r=eyJiIjpudWxsfQ==")
	folded := replayTestDigest(t, "m=1; h=sha256:AAAAAAAAAAAAAAAAAAAAAA\r\n AAAAAAAAAAAAAAAAAAAAA=:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
	if sha256Only != mixed || sha256Only != withRecipe || sha256Only != folded {
		t.Fatal("equal SHA-256 declarations produced distinct identities")
	}
	if sha512Only == mixed || sha512Only == sha256Only {
		t.Fatal("SHA-512-only declaration grouped with a SHA-256 declaration")
	}
	if changedHeader == sha256Only {
		t.Fatal("changed signed header hash kept the same identity")
	}
	if _, ok := originReplayDigest(replayTestInstance(t, "m=2; h="+replayTestSHA256A)); ok {
		t.Fatal("non-origin instance produced a replay identity")
	}
	if _, ok := originReplayDigest(replayTestInstance(t, "m=1; h=sha3:AA==:AA==")); ok {
		t.Fatal("unknown-only declaration produced a replay identity")
	}
}

// TestReplayProjectionIsFixedSizeAndRedacted proves only sealed origin facts cross the boundary.
func TestReplayProjectionIsFixedSizeAndRedacted(t *testing.T) {
	digest := [32]byte{1, 2, 3}
	projection := newReplayProjection(digest, true, true)
	if !projection.Valid() || projection.Draft() != replay.DraftIdentifier || !projection.Exploded() || !projection.ReplayEligible() || projection.OriginReplayAlgorithm() != originReplayAlgorithm {
		t.Fatalf("projection invalid: %v", projection)
	}
	got, ok := projection.OriginReplayDigest()
	if !ok || got != digest {
		t.Fatal("origin digest was not retained by value")
	}
	if projection.String() != replayProjectionRedactedText {
		t.Fatal("projection formatting was not redacted")
	}
	if newReplayProjection(digest, false, false).ReplayEligible() {
		t.Fatal("single-signature projection reported replay eligibility")
	}
}
