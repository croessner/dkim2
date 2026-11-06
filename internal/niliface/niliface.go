// Package niliface detects unusable nil-backed interface dependencies.
package niliface

import "reflect"

// IsNil reports whether value is nil or contains a nil reference-like dynamic value.
func IsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
