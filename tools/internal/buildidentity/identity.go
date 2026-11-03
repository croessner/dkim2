// Package buildidentity owns the exact first-party compiler identity used by evidence validators.
package buildidentity

// GoVersion is the exact version the pinned compiler embeds; builds use no
// Go experiments, so the value carries no "-X:" suffix.
const GoVersion = "go1.27.3"
