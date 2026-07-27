//go:build !linux && !darwin

package daemon

import (
	"errors"
	"testing"
)

// TestLoadCapabilityFailsClosedOnUnsupportedPlatforms freezes the platform boundary.
func TestLoadCapabilityFailsClosedOnUnsupportedPlatforms(t *testing.T) {
	capability, err := LoadCapability("/protected/capability")
	if capability != nil || !errors.Is(err, &Error{}) {
		t.Fatal("unsupported platform accepted protected material")
	}
}
