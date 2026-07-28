// Command security runs the closed DKIM2 security evidence profile.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"

	"github.com/croessner/dkim2/tools/internal/security"
)

const (
	fuzzReportPath          = ".artifacts/security/fuzz.json"
	raceReportPath          = ".artifacts/security/race.json"
	vulnerabilityReportPath = ".artifacts/security/vulnerability.json"
	securityReportPath      = ".artifacts/security/report.json"
	operationFuzz           = "fuzz"
	unknownDiagnostic       = "unknown"
)

var publicErrorPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// main executes one closed security operation.
func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "security failed:", publicError(err))
		os.Exit(1)
	}
}

// run validates the repository root and dispatches one non-extensible operation.
func run(arguments []string) error {
	flags := flag.NewFlagSet("security", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 1 {
		return errors.New("arguments")
	}
	switch flags.Arg(0) {
	case "check":
		return security.ValidateInventory(*root)
	case operationFuzz:
		_, err := security.RunFuzz(*root, fuzzReportPath)
		return err
	case "race":
		_, err := security.RunRace(*root, raceReportPath)
		return err
	case "vulnerability":
		_, err := security.RunVulnerabilityScan(*root, vulnerabilityReportPath)
		return err
	case "report":
		_, err := security.BuildReport(
			*root,
			fuzzReportPath,
			raceReportPath,
			vulnerabilityReportPath,
			securityReportPath,
		)
		return err
	default:
		return errors.New("arguments")
	}
}

// publicError exposes only one bounded closed failure class.
func publicError(err error) string {
	if err == nil {
		return unknownDiagnostic
	}
	value := err.Error()
	if len(value) > 64 || !publicErrorPattern.MatchString(value) {
		return unknownDiagnostic
	}
	return value
}
