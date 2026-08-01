//go:build !race

package httpjson

// raceDetectorEnabled marks ordinary builds that preserve the production
// allocation and timing model used by the maximum-input proof.
const raceDetectorEnabled = false
