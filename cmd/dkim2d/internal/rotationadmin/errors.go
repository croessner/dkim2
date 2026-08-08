package rotationadmin

import "errors"

var (
	errInvalid  = errors.New("rotation_admin_invalid")
	errConflict = errors.New("rotation_admin_conflict")
	errLimit    = errors.New("rotation_admin_limit")
	errBackend  = errors.New("rotation_admin_backend")
)
