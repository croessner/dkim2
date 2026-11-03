// Command mangen renders the operator manual pages under docs/man from their
// man(7) templates, embedding the real Cobra help text of the built product
// binaries so that synopses and flag lists cannot drift from the commands.
package main

import (
	"flag"
	"fmt"
	"os"
)

// main parses the closed flag surface and runs one generation or check pass.
func main() {
	var rootPath string
	var binDir string
	var check bool
	flag.StringVar(&rootPath, "root", "", "repository root")
	flag.StringVar(&binDir, "bin", "", "absolute directory holding the built product binaries")
	flag.BoolVar(&check, "check", false, "fail when a committed page differs from its rendering")
	flag.Parse()
	if flag.NArg() != 0 || rootPath == "" || binDir == "" {
		flag.Usage()
		os.Exit(2)
	}
	generator, err := newPageGenerator(rootPath, binDir)
	if err == nil {
		if check {
			err = generator.check()
		} else {
			err = generator.write()
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "mangen: %v\n", err)
		os.Exit(1)
	}
}
