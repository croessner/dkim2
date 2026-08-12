//go:build linux || darwin

package signingstore

import "golang.org/x/sys/unix"

// openRegistrySourceParent retains the owned private generations directory.
func openRegistrySourceParent(generationFD int) (int, error) {
	fd, err := unix.Openat(
		generationFD, "..",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, &Error{}
	}
	state, stateErr := descriptorState(fd)
	if stateErr != nil || !validRegistryParentState(state) {
		_ = unix.Close(fd)
		return -1, &Error{}
	}
	return fd, nil
}

// openRegistryGeneration opens one numeric direct child without following links.
func openRegistryGeneration(parentFD int, generation string) (int, error) {
	if !validChildName(generation) {
		return -1, &Error{}
	}
	fd, err := unix.Openat(
		parentFD, generation,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return -1, &Error{}
	}
	state, stateErr := descriptorState(fd)
	if stateErr != nil || !validRootState(state) {
		_ = unix.Close(fd)
		return -1, &Error{}
	}
	return fd, nil
}

// validRegistryParentState enforces the mutable publication-container policy.
func validRegistryParentState(state fileState) bool {
	const (
		typeMask      = uint32(0170000)
		directoryType = uint32(0040000)
	)
	return state.mode&typeMask == directoryType &&
		state.uid == uint32(unix.Geteuid()) &&
		state.mode&07777 == 0700
}
