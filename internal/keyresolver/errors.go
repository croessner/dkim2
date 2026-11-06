package keyresolver

import "errors"

// ErrorClass identifies a bounded resolver contract or permanent input failure.
type ErrorClass string

const (
	// ErrorClassContract identifies zero, unknown, malformed, or contradictory injected state.
	ErrorClassContract ErrorClass = "contract"
	// ErrorClassPermanent identifies a valid query whose canonical DNS owner cannot be represented safely.
	ErrorClassPermanent ErrorClass = "permanent"
)

// Known reports whether the class belongs to the closed resolver vocabulary.
func (c ErrorClass) Known() bool {
	switch c {
	case ErrorClassContract, ErrorClassPermanent:
		return true
	default:
		return false
	}
}

type resolverError struct{ class ErrorClass }

// Error returns a bounded diagnostic without query or DNS data.
func (e *resolverError) Error() string {
	return "dns key resolver failure"
}

// ErrorClass returns the closed resolver failure class.
func (e *resolverError) ErrorClass() ErrorClass {
	if e == nil {
		return ""
	}
	return e.class
}

type classifiedResolverError interface {
	error
	ErrorClass() ErrorClass
}

// newResolverError constructs one cause-free resolver failure.
func newResolverError(class ErrorClass) error {
	if !class.Known() {
		class = ErrorClassContract
	}
	return &resolverError{class: class}
}

// IsErrorClass reports whether err carries the requested known resolver class.
func IsErrorClass(err error, class ErrorClass) bool {
	if !class.Known() {
		return false
	}
	var classified classifiedResolverError
	return errors.As(err, &classified) && classified.ErrorClass() == class
}
