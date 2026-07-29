// Command containerownership validates one exact project-scoped engine object.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/croessner/dkim2/tools/internal/containerownership"
)

// main validates one bounded Docker inspect document from standard input.
func main() {
	var kind string
	var identity string
	var runID string
	var sourceTag string
	flag.StringVar(&kind, "kind", "", "closed engine object kind")
	flag.StringVar(&identity, "identity", "", "exact object identity")
	flag.StringVar(&runID, "run", "", "exact runtime run identity")
	flag.StringVar(&sourceTag, "source-tag", "", "unique policy-verified source image tag")
	flag.Parse()
	if flag.NArg() != 0 || kind == "" || identity == "" ||
		(runID == "" && sourceTag == "") || (runID != "" && sourceTag != "") {
		os.Exit(2)
	}
	content, err := io.ReadAll(io.LimitReader(os.Stdin, (1<<20)+1))
	if err != nil || len(content) == 0 || len(content) > 1<<20 {
		fmt.Fprintln(os.Stderr, "engine object ownership rejected")
		os.Exit(1)
	}
	if sourceTag != "" {
		if kind != "image" ||
			containerownership.ValidateSourceImage(identity, sourceTag, content) != nil {
			fmt.Fprintln(os.Stderr, "engine object ownership rejected")
			os.Exit(1)
		}
		return
	}
	if containerownership.ValidateInspect(kind, identity, runID, content) != nil {
		fmt.Fprintln(os.Stderr, "engine object ownership rejected")
		os.Exit(1)
	}
}
