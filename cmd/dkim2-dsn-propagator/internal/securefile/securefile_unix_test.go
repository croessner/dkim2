//go:build linux || darwin

package securefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/testsupport"
)

// secureFileFixture creates one file below repository-owned trusted ancestry.
func secureFileFixture(t *testing.T, data []byte, mode os.FileMode) string {
	t.Helper()
	absolute := testsupport.TrustedTempDirectory(t)
	path := filepath.Join(absolute, "value")
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestOpenClonesRulesBeforeObserver proves caller mutation cannot weaken policy.
func TestOpenClonesRulesBeforeObserver(t *testing.T) {
	const expectedBytes = 4
	path := secureFileFixture(t, []byte("safe"), 0o600)
	modes := []uint32{0o600}
	observed := false
	handle, err := Open(
		path,
		Rules{
			EffectiveUID: uint32(os.Geteuid()), FileModes: modes,
			MinimumBytes: expectedBytes, MaximumBytes: expectedBytes,
			RequiredFileLinkCount: 1,
		},
		func(event Event) {
			if event == EventBeforeFinalOpen {
				observed = true
				modes[0] = 0o666
			}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	if !observed {
		t.Fatal("observer seam was not reached")
	}
	data, err := handle.Read()
	if err != nil || !bytes.Equal(data, []byte("safe")) {
		t.Fatal("caller-owned rule mutation changed the accepted policy")
	}
	clear(data)
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal("second close was not idempotent")
	}
}

// TestOpenRejectsInvalidIndependentBounds freezes the public primitive limits.
func TestOpenRejectsInvalidIndependentBounds(t *testing.T) {
	const maximumConfigurationBytes = 256 * 1024
	path := secureFileFixture(t, []byte("x"), 0o600)
	tests := []Rules{
		{EffectiveUID: uint32(os.Geteuid()), FileModes: []uint32{0o600}, MinimumBytes: 0, MaximumBytes: 1, RequiredFileLinkCount: 1},
		{EffectiveUID: uint32(os.Geteuid()), FileModes: []uint32{0o600}, MinimumBytes: 1, MaximumBytes: maximumConfigurationBytes + 1, RequiredFileLinkCount: 1},
		{EffectiveUID: uint32(os.Geteuid()), FileModes: []uint32{0o600}, MinimumBytes: 1, MaximumBytes: 1, RequiredFileLinkCount: 0},
		{EffectiveUID: uint32(os.Geteuid()), FileModes: make([]uint32, 9), MinimumBytes: 1, MaximumBytes: 1, RequiredFileLinkCount: 1},
	}
	for _, rules := range tests {
		handle, err := Open(path, rules, nil)
		if handle != nil || !errors.Is(err, &Error{}) {
			if handle != nil {
				_ = handle.Close()
			}
			t.Fatal("invalid independent primitive bound was accepted")
		}
	}
}
