// Package main provides the dkim2-milter process entry point.
package main

import (
	"os"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/command"
)

// main runs the adapter command with stable process exits.
func main() {
	os.Exit(command.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
