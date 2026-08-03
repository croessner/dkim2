// Command reference validates release-reference and candidate evidence.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	referencecheck "github.com/croessner/dkim2/tools/internal/reference"
)

var publicDiagnosticPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// main dispatches only closed repository-owned reference operations.
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "reference failed:", publicDiagnostic(err))
		os.Exit(1)
	}
}

// run validates command arguments before selecting one closed operation.
func run(arguments []string) error {
	flags := flag.NewFlagSet("reference", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 1 {
		return errors.New("arguments")
	}
	switch flags.Arg(0) {
	case "api":
		manifest, _, err := referencecheck.GenerateAPIManifest(*root)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(manifest)
		return err
	case "check-api":
		return referencecheck.CheckAPI(*root)
	case "check-issues":
		return referencecheck.CheckIssues(*root)
	case "check-current-issues":
		return referencecheck.CheckCurrentIssueEvidence(*root, time.Now())
	case "check-release":
		return referencecheck.CheckReleasePlan(*root)
	case "check-datasource-report":
		content, err := readDatasourceReport()
		if err != nil {
			return err
		}
		return referencecheck.CheckDatasourceIntegrationReport(*root, content)
	case "check-workspace":
		return referencecheck.CheckWorkspaceMetadata(*root)
	case "check-vendor":
		return referencecheck.CheckVendorTree(*root)
	case "harden-vendor":
		return referencecheck.HardenVendorTree(*root)
	case "vendor":
		return referencecheck.WriteVendorTree(*root)
	case "module-proxy":
		proof, _, cleanup, err := referencecheck.BuildPrivateProxy(*root)
		if err != nil {
			return err
		}
		defer func() {
			_ = cleanup()
		}()
		return writeJSON(proof)
	case "module-proof":
		proof, err := referencecheck.RunModuleProof(*root)
		if err != nil {
			return err
		}
		return writeJSON(proof)
	case "report":
		report, err := referencecheck.WriteCandidateReport(*root, time.Now())
		if err != nil {
			return err
		}
		return writeJSON(report)
	default:
		return errors.New("arguments")
	}
}

// readDatasourceReport reads one bounded report candidate from standard input.
func readDatasourceReport() ([]byte, error) {
	const maximum = int64(1 << 20)
	content, err := io.ReadAll(io.LimitReader(os.Stdin, maximum+1))
	if err != nil || int64(len(content)) > maximum {
		return nil, errors.New("report_evidence_schema")
	}
	return content, nil
}

// writeJSON emits one deterministic bounded command result.
func writeJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return errors.New("output")
	}
	return nil
}

// publicDiagnostic maps arbitrary internal errors to one bounded class.
func publicDiagnostic(err error) string {
	if err != nil && publicDiagnosticPattern.MatchString(err.Error()) {
		return err.Error()
	}
	return "unknown"
}
