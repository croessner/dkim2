//go:build linux

package runtime

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/securefile"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/testsupport"
)

// TestUnixgramSinkProtectedLifecycle proves verified open, bounded write, privacy, and close.
func TestUnixgramSinkProtectedLifecycle(t *testing.T) {
	parent := testsupport.TrustedTempDirectory(t)
	path := filepath.Join(parent, "telemetry.sock")
	listener, err := net.ListenUnixgram(unixgramNetwork, &net.UnixAddr{Name: path, Net: unixgramNetwork})
	if err != nil {
		t.Fatal("unixgram listener setup failed")
	}
	defer func() { _ = listener.Close() }()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal("unixgram socket mode setup failed")
	}
	sink, _, err := openUnixgramSink(path)
	if err != nil {
		t.Fatal("protected unixgram sink was rejected")
	}
	for _, value := range []any{*sink, sink} {
		if rendered := fmt.Sprintf("%+v", value); !strings.Contains(rendered, "redacted") {
			t.Fatal("unixgram sink formatting escaped")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("unixgram sink JSON serialization succeeded")
		}
	}
	payload := []byte("{\"event\":\"test\"}\n")
	if err := sink.Write(payload); err != nil {
		t.Fatal("bounded unixgram write failed")
	}
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal("unixgram read deadline failed")
	}
	buffer := make([]byte, 128)
	count, _, err := listener.ReadFromUnix(buffer)
	if err != nil || string(buffer[:count]) != string(payload) {
		t.Fatal("unixgram payload changed")
	}
	if err := sink.Close(); err != nil {
		t.Fatal("unixgram close failed")
	}
	if err := sink.Close(); err != nil {
		t.Fatal("unixgram close was not idempotent")
	}
}

// TestUnixgramSinkAcceptsSeparateSameIdentityPeer proves real collector interoperability.
func TestUnixgramSinkAcceptsSeparateSameIdentityPeer(t *testing.T) {
	parent := testsupport.TrustedTempDirectory(t)
	path := filepath.Join(parent, "telemetry.sock")
	ready := filepath.Join(parent, "ready")
	command := exec.Command(
		os.Args[0],
		"-test.run=^TestUnixgramSinkCollectorProcess$",
	)
	command.Env = append(
		os.Environ(),
		"DKIM2_EXIM_UNIXGRAM_HELPER="+path,
		"DKIM2_EXIM_UNIXGRAM_READY="+ready,
	)
	if err := command.Start(); err != nil {
		t.Fatal("separate Unix-datagram collector did not start")
	}
	defer func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
	}()
	for attempts := 0; attempts < 100; attempts++ {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(ready); err != nil {
		t.Fatal("separate Unix-datagram collector did not become ready")
	}
	sink, _, err := openUnixgramSink(path)
	if err != nil {
		t.Fatal("separate same-identity Unix-datagram collector was rejected")
	}
	if err := sink.Write([]byte("{\"event\":\"test\"}\n")); err != nil {
		t.Fatal("separate Unix-datagram collector write failed")
	}
	if err := sink.Close(); err != nil {
		t.Fatal("separate Unix-datagram collector close failed")
	}
	if err := command.Wait(); err != nil {
		t.Fatal("separate Unix-datagram collector failed")
	}
	command.Process = nil
}

// TestUnixgramSinkCollectorProcess receives one bounded separate-process probe.
func TestUnixgramSinkCollectorProcess(t *testing.T) {
	path := os.Getenv("DKIM2_EXIM_UNIXGRAM_HELPER")
	ready := os.Getenv("DKIM2_EXIM_UNIXGRAM_READY")
	if path == "" || ready == "" {
		return
	}
	listener, err := net.ListenUnixgram(
		unixgramNetwork,
		&net.UnixAddr{Name: path, Net: unixgramNetwork},
	)
	if err != nil {
		t.Fatal("collector listener setup failed")
	}
	defer func() { _ = listener.Close() }()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal("collector socket mode setup failed")
	}
	if err := os.WriteFile(ready, []byte("ready\n"), 0o600); err != nil {
		t.Fatal("collector readiness publication failed")
	}
	if err := listener.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal("collector read deadline failed")
	}
	buffer := make([]byte, 128)
	count, _, err := listener.ReadFromUnix(buffer)
	if err != nil || string(buffer[:count]) != "{\"event\":\"test\"}\n" {
		t.Fatal("collector payload changed")
	}
}

// TestUnixgramSinkRejectsReplacementAndCloseFailure proves identity is stable.
func TestUnixgramSinkRejectsReplacementAndCloseFailure(t *testing.T) {
	parent := testsupport.TrustedTempDirectory(t)
	path := filepath.Join(parent, "telemetry.sock")
	original, err := net.ListenUnixgram(unixgramNetwork, &net.UnixAddr{Name: path, Net: unixgramNetwork})
	if err != nil {
		t.Fatal("original unixgram listener setup failed")
	}
	defer func() { _ = original.Close() }()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal("original unixgram mode setup failed")
	}
	var replacement *net.UnixConn
	replace := func() {
		backup := path + ".old"
		if os.Rename(path, backup) != nil {
			return
		}
		replacement, _ = net.ListenUnixgram(unixgramNetwork, &net.UnixAddr{Name: path, Net: unixgramNetwork})
		if replacement != nil {
			_ = os.Chmod(path, 0o600)
		}
	}
	if sink, _, err := openUnixgramSinkWith(path, replace, func(handle *securefile.DirectoryHandle) error {
		return handle.Close()
	}); err == nil {
		_ = sink.Close()
		t.Fatal("unixgram pathname replacement was accepted")
	}
	if replacement != nil {
		_ = replacement.Close()
	}
	_ = os.Remove(path)
	_ = os.Rename(path+".old", path)
	if sink, _, err := openUnixgramSinkWith(path, nil, func(handle *securefile.DirectoryHandle) error {
		_ = handle.Close()
		return errRuntime
	}); err == nil || sink != nil {
		t.Fatal("protected parent close failure was accepted")
	}
}

// TestUnixgramSinkRejectsUnsafeMetadata proves exact parent and socket modes.
func TestUnixgramSinkRejectsUnsafeMetadata(t *testing.T) {
	parent := testsupport.TrustedTempDirectory(t)
	path := filepath.Join(parent, "telemetry.sock")
	listener, err := net.ListenUnixgram(unixgramNetwork, &net.UnixAddr{Name: path, Net: unixgramNetwork})
	if err != nil {
		t.Fatal("unixgram listener setup failed")
	}
	defer func() { _ = listener.Close() }()
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal("unsafe socket mode setup failed")
	}
	if sink, _, err := openUnixgramSink(path); err == nil {
		_ = sink.Close()
		t.Fatal("unsafe unixgram socket mode was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil || os.Chmod(parent, 0o750) != nil {
		t.Fatal("unsafe parent setup failed")
	}
	if sink, _, err := openUnixgramSink(path); err == nil {
		_ = sink.Close()
		t.Fatal("unsafe unixgram parent mode was accepted")
	}
}
