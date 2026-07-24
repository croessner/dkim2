package valkey

import (
	dkim2 "github.com/croessner/dkim2"
)

// newCommandStore constructs the package-private command-boundary test seam.
func newCommandStore(client commandClient) (*Store, error) {
	if nilInterface(client) {
		return nil, dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	store := &Store{
		storeCore: &storeCore{
			client: client,
			gate:   newAdmissionGate(1024, 1024),
		},
	}
	return store, nil
}
