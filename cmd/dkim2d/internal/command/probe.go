package command

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/spf13/cobra"
)

const (
	probeTimeout         = 2 * time.Second
	probeCAMax           = 1 << 20
	probeLoopbackAddress = "127.0.0.1"
)

type probeOptions struct {
	tlsServerName  string
	tlsCAFile      string
	port           uint16
	connectAddress string
}

// newProbeCommand constructs the fixed local non-mutating readiness probe.
func newProbeCommand() *cobra.Command {
	options := probeOptions{port: 8080, connectAddress: probeLoopbackAddress}
	command := &cobra.Command{
		Use:           probeCommandName,
		Short:         "Check local daemon readiness",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(command *cobra.Command, _ []string) error {
			return runProbeWithOptions(command.Context(), options)
		},
	}
	command.Flags().StringVar(&options.tlsServerName, "tls-server-name", "", "verify the private-network TLS server identity")
	command.Flags().StringVar(&options.tlsCAFile, "tls-ca-file", "", "read the internal-PKI trust roots from this absolute path")
	command.Flags().Uint16Var(&options.port, "port", 8080, "local daemon readiness port")
	command.Flags().StringVar(&options.connectAddress, "connect-address", probeLoopbackAddress, "exact local daemon listener IP")
	return command
}

// runProbe checks only the fixed canonical-loopback readiness endpoint.
func runProbe(parent context.Context) error {
	return runProbeWithOptions(parent, probeOptions{port: 8080, connectAddress: probeLoopbackAddress})
}

// runProbeWithOptions checks loopback while optionally verifying the private-network TLS identity.
func runProbeWithOptions(parent context.Context, options probeOptions) error {
	if parent == nil {
		return errCommandRuntime
	}
	connectAddress, err := netip.ParseAddr(options.connectAddress)
	tlsEnabled := options.tlsServerName != ""
	if options.port == 0 || err != nil || connectAddress.Is4In6() || connectAddress.String() != options.connectAddress ||
		(tlsEnabled && !connectAddress.IsPrivate()) || (!tlsEnabled && !connectAddress.IsLoopback()) ||
		(tlsEnabled && !config.ValidTLSServerName(options.tlsServerName)) ||
		(options.tlsServerName == "") != (options.tlsCAFile == "") {
		return errCommandRuntime
	}
	ctx, cancel := context.WithTimeout(parent, probeTimeout)
	defer cancel()
	authority := net.JoinHostPort(options.connectAddress, strconv.FormatUint(uint64(options.port), 10))
	endpoint := "http://" + authority + "/readyz"
	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout: probeTimeout,
		}).DialContext,
	}
	if options.tlsServerName != "" {
		roots, err := probeRoots(options.tlsCAFile)
		if err != nil {
			return errCommandRuntime
		}
		transport.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			RootCAs:    roots,
			ServerName: options.tlsServerName,
			NextProtos: []string{"http/1.1"},
		}
		endpoint = "https://" + options.tlsServerName + ":" + strconv.FormatUint(uint64(options.port), 10) + "/readyz"
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: probeTimeout}).DialContext(
				ctx,
				"tcp",
				authority,
			)
		}
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errCommandRuntime
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return errCommandRuntime
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK {
		return errCommandRuntime
	}
	return nil
}

// probeRoots reads one bounded absolute internal-PKI trust document.
func probeRoots(path string) (*x509.CertPool, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errCommandRuntime
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errCommandRuntime
	}
	defer func() { _ = file.Close() }()
	document, err := io.ReadAll(io.LimitReader(file, probeCAMax+1))
	if err != nil || len(document) == 0 || len(document) > probeCAMax {
		return nil, errCommandRuntime
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(document) {
		return nil, errCommandRuntime
	}
	return pool, nil
}
