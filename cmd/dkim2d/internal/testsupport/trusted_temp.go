// Package testsupport owns shared test-only infrastructure.
package testsupport

import "testing"

// RunWithTrustedTemp is retained as a compatibility wrapper for package TestMain functions.
func RunWithTrustedTemp(suite *testing.M) int {
	return suite.Run()
}
