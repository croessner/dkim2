//go:build !linux && !darwin

package config

import (
	"errors"
	"testing"
)

// TestReadConfigurationFailsClosedOnUnsupportedPlatforms freezes the platform boundary.
func TestReadConfigurationFailsClosedOnUnsupportedPlatforms(t *testing.T) {
	data, err := readConfiguration("/protected/dkim2-milter.yaml")
	if data != nil || !errors.Is(err, &Error{}) {
		t.Fatal("unsupported platform accepted configuration material")
	}
}
