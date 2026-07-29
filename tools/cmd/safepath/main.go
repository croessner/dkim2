// Command safepath prepares and validates confined repository artifact paths.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	var rootPath string
	var directory string
	var file string
	var source string
	var target string
	var executable bool
	var replace bool
	flag.StringVar(&rootPath, "root", "", "trusted repository root")
	flag.StringVar(&directory, "directory", "", "relative directory to prepare")
	flag.StringVar(&file, "file", "", "relative regular file to validate")
	flag.StringVar(&source, "install", "", "relative temporary file to install")
	flag.StringVar(&target, "target", "", "relative target file")
	flag.BoolVar(&executable, "executable", false, "install an owner-executable file")
	flag.BoolVar(&replace, "replace", false, "atomically replace a validated target")
	flag.Parse()
	if flag.NArg() != 0 || rootPath == "" ||
		(directory == "" && file == "" && (source == "" || target == "")) ||
		countNonempty(directory, file, source) != 1 ||
		(source != "" && target == "") ||
		(source == "" && target != "") ||
		((executable || replace) && source == "") {
		os.Exit(2)
	}
	root, err := openSafeRoot(rootPath)
	if err != nil {
		fail()
	}
	defer root.close()
	switch {
	case directory != "":
		err = root.prepareDirectory(directory)
	case file != "":
		err = root.validateFile(file)
	default:
		if replace {
			err = root.replaceFile(source, target, executable)
		} else {
			err = root.installFile(source, target, executable)
		}
	}
	if err != nil {
		fail()
	}
}

// countNonempty counts mutually exclusive operation selectors.
func countNonempty(values ...string) int {
	count := 0
	for _, value := range values {
		if value != "" {
			count++
		}
	}
	return count
}

// fail emits one fixed content-free path failure.
func fail() {
	fmt.Fprintln(os.Stderr, "artifact path rejected")
	os.Exit(1)
}
