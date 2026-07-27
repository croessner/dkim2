//go:build !linux && !darwin

package signingstore

type fileState struct{}
type retainedChild struct {
	data []byte
}

// protectedRootState fails closed on unsupported platforms.
func protectedRootState(int) (fileState, error) {
	return fileState{}, &Error{}
}

// openRetainedChild fails closed on unsupported platforms.
func openRetainedChild(int, string, int, fileState) (*retainedChild, error) {
	return nil, &Error{}
}

// validateCompoundGeneration fails closed on unsupported platforms.
func validateCompoundGeneration(int, fileState, []*retainedChild) error {
	return &Error{}
}

// closeRetainedChild is inert on unsupported platforms.
func closeRetainedChild(*retainedChild) error { return &Error{} }
