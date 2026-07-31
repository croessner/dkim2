//go:build !linux

package evidence

import (
	"context"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/securefile"
)

// Store is unavailable where Linux no-replace evidence publication is absent.
type Store struct{}

// NewStore fails closed without Linux descriptor-native no-replace support.
func NewStore(string, []byte, func() time.Time) (*Store, error) {
	return nil, ErrNotReady
}

// NewStoreWithLimits fails closed without the required Linux primitives.
func NewStoreWithLimits(string, []byte, func() time.Time, Limits) (*Store, error) {
	return nil, ErrNotReady
}

// NewStoreWithReadiness fails closed without the required Linux primitives.
func NewStoreWithReadiness(
	string,
	[]byte,
	string,
	func() time.Time,
	Limits,
) (*Store, error) {
	return nil, ErrNotReady
}

// NewStoreWithReadinessKeyPath fails closed without Linux descriptor-native support.
func NewStoreWithReadinessKeyPath(string, string, string, func() time.Time, Limits, ...securefile.Identity) (*Store, error) {
	return nil, ErrNotReady
}

// NewStoreWithReadinessKeyPathContext fails closed without Linux descriptor-native support.
func NewStoreWithReadinessKeyPathContext(context.Context, string, string, string, func() time.Time, Limits, ...securefile.Identity) (*Store, error) {
	return nil, ErrNotReady
}

// ConflictsProtectedIdentity fails closed where a store cannot retain protected descriptors.
func (*Store) ConflictsProtectedIdentity(securefile.Identity) bool { return true }

// LoadKeyFile fails closed without the required descriptor-native platform.
func LoadKeyFile(string) ([]byte, error) { return nil, ErrNotReady }

// Close is a no-op for an unavailable platform store.
func (*Store) Close() error { return nil }

// readyError reports the unsupported store as unavailable.
func (*Store) readyError() error { return ErrNotReady }

// publishContext fails closed without the required Linux primitives.
func (*Store) publishContext(context.Context, time.Duration, adapter.IncomingEvidence) (Record, error) {
	return Record{}, ErrNotReady
}

// loadContext fails closed without the required Linux primitives.
func (*Store) loadContext(context.Context, string) (Record, error) {
	return Record{}, ErrNotReady
}

// collectContext fails closed without the required Linux primitives.
func (*Store) collectContext(context.Context) error { return ErrNotReady }

// storeStats fails closed without the required Linux primitives.
func (*Store) storeStats() (Stats, error) { return Stats{}, ErrNotReady }
