//go:build !linux && !darwin

package securefile

import (
	"fmt"
	"io"
)

// Error is one content-free unsupported protected-file failure.
type Error struct{}

// Error returns a secret-safe protected-file diagnostic.
func (*Error) Error() string { return "protected file access failure" }

// Is recognizes a protected-file failure.
func (*Error) Is(target error) bool { _, ok := target.(*Error); return ok }

// Identity is unavailable on unsupported production platforms.
type Identity struct{}

// DirectoryRules declares an unavailable directory policy.
type DirectoryRules struct {
	EffectiveUID uint32
	Mode         uint32
}

// DirectoryHandle is unavailable outside supported Unix platforms.
type DirectoryHandle struct{}

// OpenDirectory fails closed outside supported Unix platforms.
func OpenDirectory(string, DirectoryRules) (*DirectoryHandle, error) { return nil, &Error{} }

// Descriptor reports no available descriptor.
func (*DirectoryHandle) Descriptor() int { return -1 }

// Validate fails closed outside supported Unix platforms.
func (*DirectoryHandle) Validate() error { return &Error{} }

// Close has no unsupported-platform resource to release.
func (*DirectoryHandle) Close() error { return nil }

// NewIdentity returns an unavailable identity on unsupported platforms.
func NewIdentity(uint64, uint64, uint64, uint64) Identity { return Identity{} }

// Equal never aliases unsupported descriptor identities.
func (Identity) Equal(Identity) bool { return false }

// SameParent never aliases unsupported descriptor identities.
func (Identity) SameParent(Identity) bool { return false }

// MatchesDirectory never aliases unsupported descriptor identities.
func (Identity) MatchesDirectory(uint64, uint64) bool { return false }

// String prevents filesystem identity disclosure.
func (Identity) String() string { return "securefile.Identity{redacted}" }

// GoString prevents filesystem identity disclosure.
func (Identity) GoString() string { return "securefile.Identity{redacted}" }

// Format prevents formatter traversal into filesystem identity state.
func (Identity) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "securefile.Identity{redacted}")
}

// MarshalJSON rejects filesystem identity serialization.
func (Identity) MarshalJSON() ([]byte, error) { return nil, &Error{} }

// Read fails closed outside the supported Unix platforms.
func Read(string, int64, int64) ([]byte, Identity, error) { return nil, Identity{}, &Error{} }

// ReadCapability fails closed outside supported Unix platforms.
func ReadCapability(string) ([]byte, Identity, error) { return nil, Identity{}, &Error{} }
