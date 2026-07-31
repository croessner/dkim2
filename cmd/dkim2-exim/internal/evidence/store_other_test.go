//go:build !linux

package evidence

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// TestUnsupportedStoreFailsClosed proves no weaker publication fallback exists.
func TestUnsupportedStoreFailsClosed(t *testing.T) {
	store, err := NewStore(
		"/protected/evidence", bytes.Repeat([]byte{1}, KeyBytes), time.Now,
	)
	if store != nil || !errors.Is(err, ErrNotReady) {
		t.Fatal("unsupported platform accepted evidence store")
	}
	key, err := LoadKeyFile("/protected/evidence.key")
	if key != nil || !errors.Is(err, ErrNotReady) {
		t.Fatal("unsupported platform accepted protected key")
	}
}
