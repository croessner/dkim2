package evidence

import (
	"bytes"
	"testing"
)

// TestReadinessRoundTripRejectsImpossibleAuthority proves the fixed marker
// authenticates every field and rejects structurally impossible signed roots.
func TestReadinessRoundTripRejectsImpossibleAuthority(t *testing.T) {
	key := bytes.Repeat([]byte{0x4d}, KeyBytes)
	defer clear(key)
	snapshot := readinessSnapshot{
		state: readinessClean, generation: 7,
		root: rootFingerprint{
			device: 1, inode: 2,
			mtimeSec: 3, mtimeNsec: 4,
			ctimeSec: 5, ctimeNsec: 6,
		},
		stats: Stats{Records: 1, Bytes: 100},
	}
	encoded, err := encodeReadiness(snapshot, key)
	if err != nil {
		t.Fatal("valid readiness encoding failed")
	}
	defer clear(encoded)
	decoded, err := decodeReadiness(encoded, key)
	if err != nil || decoded != snapshot {
		t.Fatal("valid readiness round trip changed authority")
	}
	for _, index := range []int{0, 5, 8, 16, 40, 72, readinessBytes - 1} {
		forged := bytes.Clone(encoded)
		forged[index] ^= 1
		if _, err := decodeReadiness(forged, key); err == nil {
			clear(forged)
			t.Fatal("forged readiness field was accepted")
		}
		clear(forged)
	}
	impossible := snapshot
	impossible.root.device = 0
	signedImpossible, err := encodeReadiness(impossible, key)
	if err != nil {
		t.Fatal("impossible readiness fixture encoding failed")
	}
	defer clear(signedImpossible)
	if _, err = decodeReadiness(signedImpossible, key); err == nil {
		t.Fatal("signed impossible readiness root was accepted")
	}
}

// FuzzDecodeReadiness exercises fixed-width structure, domain-separated HMAC,
// numeric bounds, and exact EOF with arbitrary marker and key bytes.
func FuzzDecodeReadiness(f *testing.F) {
	key := bytes.Repeat([]byte{0x4d}, KeyBytes)
	snapshot := readinessSnapshot{
		state: readinessClean, generation: 1,
		root: rootFingerprint{
			device: 1, inode: 2,
			mtimeSec: 3, mtimeNsec: 4,
			ctimeSec: 5, ctimeNsec: 6,
		},
		stats: Stats{Records: 1, Bytes: 100},
	}
	encoded, _ := encodeReadiness(snapshot, key)
	f.Add(encoded, key)
	f.Add([]byte("DXR1"), []byte("short"))
	clear(encoded)
	clear(key)
	f.Fuzz(func(_ *testing.T, marker, candidateKey []byte) {
		if len(marker) > readinessBytes+1 || len(candidateKey) > KeyBytes+1 {
			return
		}
		_, _ = decodeReadiness(marker, candidateKey)
	})
}
