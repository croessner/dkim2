// Package runtime owns protected one-shot Exim adapter runtime inputs.
package runtime

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/securefile"
)

var errRuntime = errors.New("exim runtime failure")

// Config contains the bounded authority required by one daemon operation.
type Config struct {
	Endpoint string
	Timeout  time.Duration
}

// String keeps daemon authority diagnostics content-free.
func (Config) String() string { return "dkim2_exim_runtime_config{redacted}" }

// GoString keeps daemon authority Go diagnostics content-free.
func (c Config) GoString() string { return c.String() }

// Format prevents formatting from traversing daemon authority.
func (c Config) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, c.String()) }

// MarshalJSON rejects serialization of daemon authority.
func (Config) MarshalJSON() ([]byte, error) { return nil, errRuntime }

// MarshalText rejects textual serialization of daemon authority.
func (Config) MarshalText() ([]byte, error) { return nil, errRuntime }

// Validate rejects proxyable, non-loopback, or unbounded daemon configuration.
func (c Config) Validate() error {
	if c.Timeout < 100*time.Millisecond || c.Timeout > 10*time.Second {
		return errRuntime
	}
	parsed, err := url.Parse(c.Endpoint)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return errRuntime
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil || port == "" {
		return errRuntime
	}
	address := net.ParseIP(host)
	if address == nil || !address.IsLoopback() {
		return errRuntime
	}
	return nil
}

// ReadProtectedFile reads one bounded direct regular file and closes it before return.
func ReadProtectedFile(path string, maximum int) ([]byte, error) {
	data, _, err := readProtectedIdentity(path, maximum)
	if err != nil {
		clear(data)
		return nil, errRuntime
	}
	return data, nil
}

// readProtectedIdentity loads one bounded resource and retains only its opaque alias token.
func readProtectedIdentity(path string, maximum int) ([]byte, securefile.Identity, error) {
	if maximum < 1 {
		return nil, securefile.Identity{}, errRuntime
	}
	data, identity, err := securefile.Read(path, 1, int64(maximum))
	if err != nil {
		clear(data)
		return nil, securefile.Identity{}, errRuntime
	}
	return data, identity, nil
}

// Clear erases an owned protected runtime value after request construction.
func Clear(value []byte) { clear(value) }
