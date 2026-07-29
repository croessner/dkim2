package command

import (
	"context"
	"errors"
	"testing"
)

// TestProbeFailsClosedWithoutDaemon proves the fixed probe has no fallback.
func TestProbeFailsClosedWithoutDaemon(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(runProbe(ctx), errCommandRuntime) {
		t.Fatal("cancelled readiness probe did not fail closed")
	}
}
