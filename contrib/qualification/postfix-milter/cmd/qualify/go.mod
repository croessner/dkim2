// The Postfix qualification helper is compiled only through explicit file
// arguments from the repository workspace (make test-postfix-qualification-helper
// and ../../Dockerfile), which resolves the library through go.work. This
// go.mod only keeps the helper outside the root library module; it is
// intentionally not part of go.work and declares no requirements of its own.
module github.com/croessner/dkim2/contrib/qualification/postfix-milter/cmd/qualify

go 1.27

toolchain go1.27.3
