//go:build linux || darwin

package app_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson"
)

const smokeGeneration = "0123456789abcdef0123456789abcdef"

// TestProductionDaemonDisabledBackendSmoke crosses protected load, Fx, bind, readiness, and stop.
func TestProductionDaemonDisabledBackendSmoke(t *testing.T) {
	listen := reserveCanonicalLoopback(t)
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("smoke fixture path resolution failed")
	}
	generation := filepath.Join(base, smokeGeneration)
	if err := os.Mkdir(generation, 0o700); err != nil {
		t.Fatal("smoke generation creation failed")
	}
	t.Cleanup(func() { _ = os.Chmod(generation, 0o700) })
	capability := filepath.Join(generation, "capability")
	writeSmokeFile(t, capability, bytes.Repeat([]byte{0xa5}, 32), 0o600)
	if err := os.Chmod(generation, 0o500); err != nil {
		t.Fatal("smoke generation seal failed")
	}
	document := fmt.Sprintf(`config:
  version: dkim2d-config-v1
protected:
  generation: %s
server:
  listen: %s
  capability_file: %s
replay:
  backend: disabled
`, smokeGeneration, listen, capability)
	configPath := filepath.Join(base, "dkim2d.yaml")
	writeSmokeFile(t, configPath, []byte(document), 0o600)

	owner, err := config.LoadProtected(configPath, config.FlagValues{})
	if err != nil {
		if owner != nil {
			_ = owner.Close()
		}
		t.Fatalf("protected load failed with code %s", config.CodeOf(err))
	}
	stopTimeout, err := app.LifecycleStopTimeout(
		owner.Snapshot().Server().ShutdownTimeout(),
	)
	if err != nil {
		_ = owner.Close()
		t.Fatal("smoke stop timeout derivation failed")
	}
	application, err := app.NewApplication(
		owner,
		httpjson.NewServerFactory(),
		stopTimeout,
	)
	if err != nil {
		_ = owner.Close()
		t.Fatal("pure production Fx assembly failed")
	}
	startContext, startCancel := context.WithTimeout(
		context.Background(),
		app.LifecycleStartTimeout,
	)
	if err := application.Start(startContext); err != nil {
		startCancel()
		_ = owner.Close()
		t.Fatal("production daemon startup failed")
	}
	startCancel()

	client := &http.Client{Timeout: time.Second}
	var stopOnce sync.Once
	var stopErr error
	stopApplication := func() error {
		stopOnce.Do(func() {
			client.CloseIdleConnections()
			stopContext, stopCancel := context.WithTimeout(
				context.Background(),
				stopTimeout,
			)
			stopErr = application.Stop(stopContext)
			stopCancel()
		})
		return stopErr
	}
	t.Cleanup(func() { _ = stopApplication() })
	assertSmokeEndpoint(t, client, "http://"+listen+"/healthz")
	assertSmokeEndpoint(t, client, "http://"+listen+"/readyz")

	if err := stopApplication(); err != nil {
		t.Fatal("production daemon clean stop failed")
	}
}

// reserveCanonicalLoopback returns one currently available canonical authority.
func reserveCanonicalLoopback(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("loopback reservation failed")
	}
	authority := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal("loopback reservation close failed")
	}
	return authority
}

// writeSmokeFile creates one protected smoke fixture with an exact mode.
func writeSmokeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal("smoke fixture write failed")
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal("smoke fixture mode failed")
	}
}

// assertSmokeEndpoint proves one real bound endpoint is ready and bounded.
func assertSmokeEndpoint(t *testing.T, client *http.Client, endpoint string) {
	t.Helper()
	response, err := client.Get(endpoint)
	if err != nil {
		t.Fatal("production daemon endpoint request failed")
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("production daemon endpoint status = %d", response.StatusCode)
	}
}
