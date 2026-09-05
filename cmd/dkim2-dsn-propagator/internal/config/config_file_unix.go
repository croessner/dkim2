//go:build linux || darwin

package config

import (
	"os"

	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/securefile"
)

// configFileEvent identifies one content-free deterministic race-test phase.
type configFileEvent uint8

const (
	configFileBeforeFinalOpen configFileEvent = iota + 1
	configFileAfterRead
)

// configFileObserver receives no path, metadata, provenance, or content.
type configFileObserver func(configFileEvent)

// readConfiguration performs one descriptor-confined stable bounded read.
func readConfiguration(path string) ([]byte, error) {
	return readConfigurationObserved(path, nil)
}

// readConfigurationObserved exposes only content-free phases to local tests.
func readConfigurationObserved(
	path string,
	observe configFileObserver,
) (data []byte, resultErr error) {
	return readConfigurationObservedWithUID(path, observe, uint32(os.Geteuid()))
}

// readConfigurationObservedWithUID performs one read against one captured authority.
func readConfigurationObservedWithUID(
	path string,
	observe configFileObserver,
	effectiveUID uint32,
) (data []byte, resultErr error) {
	handle, err := securefile.Open(
		path,
		securefile.Rules{
			EffectiveUID: effectiveUID,
			FileModes:    []uint32{0o400, 0o600},
			MinimumBytes: 1, MaximumBytes: maxConfigurationBytes,
			RequiredFileLinkCount: 1,
		},
		adaptConfigFileObserver(observe),
	)
	if err != nil {
		return nil, &Error{}
	}
	defer func() {
		if closeErr := handle.Close(); closeErr != nil && resultErr == nil {
			clear(data)
			data = nil
			resultErr = &Error{}
		}
	}()
	data, err = handle.Read()
	if err != nil {
		clear(data)
		return nil, &Error{}
	}
	return data, nil
}

// adaptConfigFileObserver maps shared phases into the config-local vocabulary.
func adaptConfigFileObserver(observe configFileObserver) securefile.Observer {
	if observe == nil {
		return nil
	}
	return func(event securefile.Event) {
		switch event {
		case securefile.EventBeforeFinalOpen:
			observe(configFileBeforeFinalOpen)
		case securefile.EventAfterRead:
			observe(configFileAfterRead)
		}
	}
}
