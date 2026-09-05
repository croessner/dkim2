//go:build linux || darwin

package daemon

import (
	"os"

	"github.com/croessner/dkim2/cmd/dkim2-dsn-propagator/internal/securefile"
)

const (
	capabilityBytes        = 32
	protectedDirectoryMode = 0o500
)

// capabilityLoadEvent identifies a content-free deterministic test seam.
type capabilityLoadEvent uint8

const (
	capabilityBeforeFinalOpen capabilityLoadEvent = iota + 1
	capabilityAfterRead
)

// capabilityLoadObserver receives no path, identity, or protected content.
type capabilityLoadObserver func(capabilityLoadEvent)

// LoadCapability descriptor-confines one exact protected direct child.
func LoadCapability(path string) (*Capability, error) {
	return loadCapabilityObserved(path, nil)
}

// loadCapabilityObserved exposes only content-free race phases to local tests.
func loadCapabilityObserved(
	path string,
	observe capabilityLoadObserver,
) (*Capability, error) {
	return loadCapabilityObservedWithUID(path, observe, uint32(os.Geteuid()))
}

// loadCapabilityObservedWithUID performs one load against one captured authority.
func loadCapabilityObservedWithUID(
	path string,
	observe capabilityLoadObserver,
	effectiveUID uint32,
) (capability *Capability, resultErr error) {
	handle, err := securefile.Open(
		path,
		securefile.Rules{
			EffectiveUID: effectiveUID, ExactParent: true,
			ParentMode: protectedDirectoryMode, FileModes: []uint32{0o400, 0o600},
			MinimumBytes: capabilityBytes, MaximumBytes: capabilityBytes,
			RequiredFileLinkCount: 1,
		},
		adaptCapabilityObserver(observe),
	)
	if err != nil {
		return nil, &Error{}
	}
	defer func() {
		if closeErr := handle.Close(); closeErr != nil && resultErr == nil {
			if capability != nil {
				_ = capability.Close()
				capability = nil
			}
			resultErr = &Error{}
		}
	}()
	data, err := handle.Read()
	if err != nil || len(data) != capabilityBytes {
		clear(data)
		return nil, &Error{}
	}
	defer clear(data)
	var value [capabilityBytes]byte
	copy(value[:], data)
	defer clear(value[:])
	return newCapability(value)
}

// adaptCapabilityObserver maps shared phases into the role-local test vocabulary.
func adaptCapabilityObserver(observe capabilityLoadObserver) securefile.Observer {
	if observe == nil {
		return nil
	}
	return func(event securefile.Event) {
		switch event {
		case securefile.EventBeforeFinalOpen:
			observe(capabilityBeforeFinalOpen)
		case securefile.EventAfterRead:
			observe(capabilityAfterRead)
		}
	}
}
