// Command externalvectors validates retained public-only external vector corpora.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/croessner/dkim2/tools/internal/externalvectors"
)

// main reports only bounded validation state for one repository-owned operation.
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "external vectors failed:", err)
		os.Exit(1)
	}
}

// run validates arguments before checking the fixed local corpus.
func run(arguments []string) error {
	flags := flag.NewFlagSet("externalvectors", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 1 || flags.Arg(0) != "check" {
		return errors.New("arguments")
	}
	return externalvectors.CheckRepository(*root)
}
