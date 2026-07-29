// Command candidateid prints the exact empty-index durable candidate identity.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/croessner/dkim2/tools/internal/conformance"
)

// main prints one bounded candidate digest for repository-owned evidence scripts.
func main() {
	var root string
	flag.StringVar(&root, "root", "", "repository root")
	flag.Parse()
	if flag.NArg() != 0 || root == "" {
		os.Exit(2)
	}
	revision, err := conformance.CurrentRevision(root)
	if err != nil {
		fail()
	}
	snapshot, err := conformance.ProduceSnapshot(root, revision)
	if err != nil {
		fail()
	}
	fmt.Println(snapshot.SHA256)
}

// fail emits one fixed content-free candidate failure.
func fail() {
	fmt.Fprintln(os.Stderr, "candidate identity unavailable")
	os.Exit(1)
}
