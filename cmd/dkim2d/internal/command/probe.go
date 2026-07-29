package command

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

const (
	probeEndpoint = "http://127.0.0.1:8080/readyz"
	probeTimeout  = 2 * time.Second
)

// newProbeCommand constructs the fixed local non-mutating readiness probe.
func newProbeCommand() *cobra.Command {
	return &cobra.Command{
		Use:           probeCommandName,
		Short:         "Check local daemon readiness",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(command *cobra.Command, _ []string) error {
			return runProbe(command.Context())
		},
	}
}

// runProbe checks only the fixed canonical-loopback readiness endpoint.
func runProbe(parent context.Context) error {
	if parent == nil {
		return errCommandRuntime
	}
	ctx, cancel := context.WithTimeout(parent, probeTimeout)
	defer cancel()
	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout: probeTimeout,
		}).DialContext,
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, probeEndpoint, nil)
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
