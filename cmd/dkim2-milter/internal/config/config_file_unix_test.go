//go:build linux || darwin

package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// configFileFixture creates one valid descriptor-confined configuration file.
func configFileFixture(t *testing.T) (string, []byte) {
	t.Helper()
	directory := trustedTempDirectory(t)
	data := []byte(validConfig(ModeInbound))
	path := filepath.Join(directory, "milter.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, data
}

// TestReadConfigurationRejectsSpecialLinksModesAndBounds freezes descriptor policy.
func TestReadConfigurationRejectsSpecialLinksModesAndBounds(t *testing.T) {
	const expectedMaximumConfigurationBytes = 256 * 1024
	if maxConfigurationBytes != expectedMaximumConfigurationBytes {
		t.Fatalf("configuration byte bound = %d, want %d", maxConfigurationBytes, expectedMaximumConfigurationBytes)
	}
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{
			name: "empty",
			mutate: func(t *testing.T, path string) {
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "oversized",
			mutate: func(t *testing.T, path string) {
				if err := os.WriteFile(path, make([]byte, expectedMaximumConfigurationBytes+1), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unsafe mode",
			mutate: func(t *testing.T, path string) {
				if err := os.Chmod(path, 0o666); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "group-readable mode",
			mutate: func(t *testing.T, path string) {
				if err := os.Chmod(path, 0o440); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "world-readable mode",
			mutate: func(t *testing.T, path string) {
				if err := os.Chmod(path, 0o444); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "owner-group mode",
			mutate: func(t *testing.T, path string) {
				if err := os.Chmod(path, 0o640); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hardlink",
			mutate: func(t *testing.T, path string) {
				if err := os.Link(path, path+".alias"); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink",
			mutate: func(t *testing.T, path string) {
				target := path + ".target"
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "directory",
			mutate: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "fifo",
			mutate: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, _ := configFileFixture(t)
			test.mutate(t, path)
			data, err := readConfiguration(path)
			if data != nil || !errors.Is(err, &Error{}) {
				t.Fatalf("readConfiguration() accepted %s fixture", test.name)
			}
		})
	}
}

// TestReadConfigurationAcceptsOnlyProtectedOwnerModes freezes the inherited policy.
func TestReadConfigurationAcceptsOnlyProtectedOwnerModes(t *testing.T) {
	for _, mode := range []os.FileMode{0o400, 0o600} {
		path, want := configFileFixture(t)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		got, err := readConfiguration(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("mode %04o was rejected", mode)
		}
		clear(got)
	}
}

// TestReadConfigurationRequiresExactEffectiveOwner rejects every owner exception.
func TestReadConfigurationRequiresExactEffectiveOwner(t *testing.T) {
	path, _ := configFileFixture(t)
	data, err := readConfigurationObservedWithUID(
		path,
		nil,
		uint32(os.Geteuid()+1),
	)
	if data != nil || !errors.Is(err, &Error{}) {
		t.Fatal("configuration owner distinct from the captured euid was accepted")
	}
}

// TestReadConfigurationRejectsWritableAncestry proves trusted-parent policy.
func TestReadConfigurationRejectsWritableAncestry(t *testing.T) {
	path, _ := configFileFixture(t)
	parent := filepath.Dir(path)
	if err := os.Chmod(parent, 0o770); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	data, err := readConfiguration(path)
	if data != nil || !errors.Is(err, &Error{}) {
		t.Fatal("writable configuration ancestry was accepted")
	}
}

// TestReadConfigurationRejectsPathAndContentRaces proves retained state checks.
func TestReadConfigurationRejectsPathAndContentRaces(t *testing.T) {
	t.Run("pre-open replacement", func(t *testing.T) {
		path, data := configFileFixture(t)
		observed := false
		result, err := readConfigurationObserved(path, func(event configFileEvent) {
			if event != configFileBeforeFinalOpen || observed {
				return
			}
			observed = true
			if renameErr := os.Rename(path, path+".old"); renameErr != nil {
				t.Fatal(renameErr)
			}
			if writeErr := os.WriteFile(path, data, 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
		})
		if !observed || result != nil || !errors.Is(err, &Error{}) {
			t.Fatal("pre-open configuration replacement was accepted")
		}
	})
	t.Run("post-read mutation", func(t *testing.T) {
		path, data := configFileFixture(t)
		observed := false
		result, err := readConfigurationObserved(path, func(event configFileEvent) {
			if event != configFileAfterRead || observed {
				return
			}
			observed = true
			replacement := append([]byte(nil), data...)
			replacement[len(replacement)-1] ^= 1
			if writeErr := os.WriteFile(path, replacement, 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
		})
		if !observed || result != nil || !errors.Is(err, &Error{}) {
			t.Fatal("post-read configuration mutation was accepted")
		}
	})
	t.Run("stable snapshot", func(t *testing.T) {
		path, want := configFileFixture(t)
		got, err := readConfiguration(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("stable configuration snapshot was not retained")
		}
	})
}
