// Command interop validates and runs closed external implementation evidence.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/croessner/dkim2/tools/internal/interop"
)

var publicDiagnosticPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// main dispatches only repository-owned interoperability operations.
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "interop failed:", publicDiagnostic(err))
		os.Exit(1)
	}
}

// run validates arguments before executing one closed operation.
func run(arguments []string) error {
	flags := flag.NewFlagSet("interop", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 1 {
		return errors.New("arguments")
	}
	switch flags.Arg(0) {
	case "check":
		return interop.CheckRepository(*root)
	case "inspect-candidates":
		identities, err := interop.InspectCandidateArchives(*root)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(identities)
	case "current":
		return interop.RunCurrent(*root, time.Now())
	default:
		return errors.New("arguments")
	}
}

// publicDiagnostic maps internal errors to one bounded content-free class.
func publicDiagnostic(err error) string {
	if err != nil && publicDiagnosticPattern.MatchString(err.Error()) {
		return err.Error()
	}
	return "unknown"
}
