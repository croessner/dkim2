// Package inbound owns the Exim local-scan IPC projection boundary.
package inbound

import (
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/ipc"
)

// ProjectRequest converts one admitted primitive IPC request into immutable
// adapter evidence without retaining the IPC-owned caller buffers.
func ProjectRequest(request ipc.Request) (adapter.LocalScanRequest, error) {
	buildID := request.BuildID()
	peer := request.Peer()
	helo := request.HELO()
	protocol := request.ReceivedProtocol()
	mailFrom := request.MailFrom()
	recipients := request.Recipients()
	headers := request.Headers()
	body := request.Body()
	defer clearProjection(buildID, peer, helo, protocol, mailFrom, recipients, headers, body)
	return adapter.NewLocalScanRequest(
		buildID, adapter.SessionClass(request.Session()), peer, request.PeerPort(), helo,
		protocol, mailFrom, recipients, headers, body,
	)
}

// clearProjection erases temporary copies returned by immutable IPC accessors.
func clearProjection(
	buildID, peer, helo, protocol, mailFrom []byte,
	recipients, headers [][]byte,
	body []byte,
) {
	clear(buildID)
	clear(peer)
	clear(helo)
	clear(protocol)
	clear(mailFrom)
	for index := range recipients {
		clear(recipients[index])
	}
	for index := range headers {
		clear(headers[index])
	}
	clear(body)
}
