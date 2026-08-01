//go:build race

package httpjson

// raceDetectorEnabled marks builds whose instrumentation changes the
// production allocation and timing model used by the maximum-input proof.
const raceDetectorEnabled = true
