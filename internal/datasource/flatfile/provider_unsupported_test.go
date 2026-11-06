//go:build !darwin && !linux

package flatfile

import (
	"testing"

	"github.com/croessner/dkim2/internal/datasource"
)

// TestProviderReportsUnsupportedPlatformWithoutAccessingTheBorrowedDescriptor verifies portability.
func TestProviderReportsUnsupportedPlatformWithoutAccessingTheBorrowedDescriptor(t *testing.T) {
	t.Parallel()

	provider, err := New(0, flatfileProviderName, datasource.DefaultLimits())
	if provider != nil ||
		datasource.ErrorCodeOf(err) != datasource.ErrorCodeUnsupportedPlatform {
		t.Fatalf("New(unsupported platform) nonnil=%t code=%s",
			provider != nil, datasource.ErrorCodeOf(err))
	}
}
