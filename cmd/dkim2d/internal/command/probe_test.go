package command

import (
	"context"
	"errors"
	"path/filepath"
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

// TestProbeOptionsRejectTransportDowngrades freezes the loopback and private-TLS boundary.
func TestProbeOptionsRejectTransportDowngrades(t *testing.T) {
	t.Parallel()
	const privateAddress = "10.73.0.2"
	tests := []probeOptions{
		{port: 8080, connectAddress: privateAddress},
		{port: 8443, connectAddress: privateAddress, tlsServerName: "dkim2d-inbound"},
		{port: 8443, connectAddress: probeLoopbackAddress, tlsServerName: "dkim2d-inbound", tlsCAFile: filepath.Join(t.TempDir(), "ca.pem")},
		{port: 8443, connectAddress: privateAddress, tlsServerName: "DKIM2D-INBOUND", tlsCAFile: filepath.Join(t.TempDir(), "ca.pem")},
		{port: 8443, connectAddress: privateAddress, tlsCAFile: filepath.Join(t.TempDir(), "ca.pem")},
	}
	for _, options := range tests {
		if !errors.Is(runProbeWithOptions(context.Background(), options), errCommandRuntime) {
			t.Fatal("invalid probe transport options did not fail closed")
		}
	}
}
