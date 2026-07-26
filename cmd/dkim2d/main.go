// Package main provides the dkim2d process entry point.
package main

import (
	"os"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/command"
)

// main runs the dkim2d command with stable process exits.
func main() {
	os.Exit(command.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
