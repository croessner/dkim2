// Command dkim2ctl provides the bounded DKIM2 daemon conformance client.
package main

import (
	"os"

	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/command"
)

// main executes the single command-to-exit-code boundary.
func main() {
	os.Exit(command.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
