//go:build linux || darwin

package securefile

import "os"

// Read opens, reads, and closes one generic protected direct child.
func Read(path string, minimum, maximum int64) (data []byte, identity Identity, resultErr error) {
	handle, err := Open(path, Rules{EffectiveUID: uint32(os.Geteuid()), FileModes: []uint32{0o400, 0o600}, MinimumBytes: minimum, MaximumBytes: maximum, RequiredFileLinkCount: 1}, nil)
	if err != nil {
		return nil, Identity{}, &Error{}
	}
	defer func() {
		if closeErr := handle.Close(); closeErr != nil && resultErr == nil {
			clear(data)
			data = nil
			identity = Identity{}
			resultErr = &Error{}
		}
	}()
	data, err = handle.Read()
	if err != nil {
		clear(data)
		return nil, Identity{}, &Error{}
	}
	return data, handle.Identity(), nil
}

// ReadCapability loads one exact 32-byte route capability from an exact protected parent.
func ReadCapability(path string) (data []byte, identity Identity, resultErr error) {
	handle, err := Open(path, Rules{EffectiveUID: uint32(os.Geteuid()), ExactParent: true, ParentMode: 0o500, FileModes: []uint32{0o400, 0o600}, MinimumBytes: 32, MaximumBytes: 32, RequiredFileLinkCount: 1}, nil)
	if err != nil {
		return nil, Identity{}, &Error{}
	}
	defer func() {
		if closeErr := handle.Close(); closeErr != nil && resultErr == nil {
			clear(data)
			data = nil
			identity = Identity{}
			resultErr = &Error{}
		}
	}()
	data, err = handle.Read()
	if err != nil {
		clear(data)
		return nil, Identity{}, &Error{}
	}
	return data, handle.Identity(), nil
}
