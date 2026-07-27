ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
PRODUCT_MODULES := ./lib ./cmd/dkim2d ./cmd/dkim2-milter ./cmd/dkim2ctl
TOOL_MODULES := ./tools
MODULES := $(PRODUCT_MODULES) $(TOOL_MODULES)
OPENAPI_DIR := $(ROOT)/docs/specs/openapi
OPENAPI_SOURCE := $(OPENAPI_DIR)/dkim2d.yaml
OPENAPI_SERVER_CONFIG := $(OPENAPI_DIR)/oapi-codegen.server.yml
OPENAPI_CLIENT_CONFIG := $(OPENAPI_DIR)/oapi-codegen.client.yml
OPENAPI_MILTER_CONFIG := $(OPENAPI_DIR)/oapi-codegen.milter-client.yml
OPENAPI_MILTER_TEST_SERVER_CONFIG := $(OPENAPI_DIR)/oapi-codegen.milter-test-server.yml
OPENAPI_SERVER_OUTPUT := $(ROOT)/cmd/dkim2d/internal/httpjson/generated/server.gen.go
OPENAPI_CLIENT_OUTPUT := $(ROOT)/cmd/dkim2ctl/internal/testclient/generated/client.gen.go
OPENAPI_MILTER_OUTPUT := $(ROOT)/cmd/dkim2-milter/internal/daemon/generated/client.gen.go
OPENAPI_MILTER_TEST_SERVER_OUTPUT := $(ROOT)/cmd/dkim2-milter/internal/integration/generated/server.gen.go
OPENAPI_SERVER_WIRE := $(ROOT)/cmd/dkim2d/internal/httpjson/wire/protected_string.gen.go
OPENAPI_CLIENT_WIRE := $(ROOT)/cmd/dkim2ctl/internal/testclient/wire/protected_string.gen.go
OPENAPI_MILTER_WIRE := $(ROOT)/cmd/dkim2-milter/internal/daemon/wire/protected_string.gen.go
VENDOR_LF_PATHS := github.com/vmware-labs/yaml-jsonpath/LICENSE github.com/vmware-labs/yaml-jsonpath/NOTICE
# OTLP's x/net graph makes Go 1.26 synchronize dkim2ctl's pruned module sums.
WORKSPACE_SYNC_FILES := go.work go.work.sum lib/go.mod lib/go.sum cmd/dkim2d/go.mod cmd/dkim2d/go.sum cmd/dkim2-milter/go.mod cmd/dkim2-milter/go.sum cmd/dkim2ctl/go.mod cmd/dkim2ctl/go.sum tools/go.mod tools/go.sum
WORKSPACE_ABSENT_SUM_FILES :=

.PHONY: help
help:
	@printf '%s\n' \
		'Targets:' \
		'  make fmt          format Go files' \
		'  make test         run unit tests for all workspace modules' \
		'  make race         run race tests for all workspace modules' \
		'  make vet          run go vet for all workspace modules' \
		'  make lint         run golangci-lint' \
		'  make test-valkey  run mandatory hermetic Valkey 9.1.0 integration tests' \
		'  make govulncheck  run govulncheck for all workspace modules' \
		'  make generate-openapi regenerate OpenAPI and protected wire artifacts' \
		'  make check-openapi verify generated OpenAPI and wire artifacts' \
		'  make check-workspace verify synchronized workspace module metadata' \
		'  make check-protected-platforms verify protected-loader build tags' \
		'  make vendor       regenerate the workspace vendor tree' \
		'  make check-vendor  verify reproducible workspace vendoring' \
		'  make guardrails   run the local quality gate'

.PHONY: fmt
fmt:
	@gofmt -w lib cmd tools

.PHONY: test
test:
	@set -e; for module in $(MODULES); do \
		echo "==> go test $$module/..."; \
		(cd $$module && go test ./...); \
	done

.PHONY: race
race:
	@set -e; for module in $(MODULES); do \
		echo "==> go test -race $$module/..."; \
		(cd $$module && go test -race ./...); \
	done

.PHONY: vet
vet:
	@set -e; for module in $(MODULES); do \
		echo "==> go vet $$module/..."; \
		(cd $$module && go vet ./...); \
	done

.PHONY: lint
lint:
	@set -e; for module in $(MODULES); do \
		echo "==> golangci-lint $$module/..."; \
		(cd $$module && golangci-lint run ./...); \
	done

.PHONY: test-valkey
test-valkey:
	@scripts/test-valkey.sh

.PHONY: govulncheck
govulncheck:
	@set -e; for module in $(MODULES); do \
		echo "==> govulncheck $$module/..."; \
		(cd $$module && govulncheck ./...); \
	done

.PHONY: generate-openapi
generate-openapi:
	@set -eu; \
	cache="$$(mktemp -d /tmp/dkim2-openapi-generate-cache.XXXXXX)"; \
	chmod 0700 "$$cache"; \
	trap 'rm -rf "$$cache"' 0 1 2 15; \
	export GOCACHE="$$cache"; \
	go -C tools run ./cmd/wiregen -package wire -output "$(OPENAPI_SERVER_WIRE)"; \
	go -C tools run ./cmd/wiregen -package wire -output "$(OPENAPI_CLIENT_WIRE)"; \
	go -C tools run ./cmd/wiregen -package wire -output "$(OPENAPI_MILTER_WIRE)"; \
	go -C tools tool oapi-codegen -config "$(OPENAPI_SERVER_CONFIG)" -o "$(OPENAPI_SERVER_OUTPUT)" "$(OPENAPI_SOURCE)"; \
	go -C tools tool oapi-codegen -config "$(OPENAPI_CLIENT_CONFIG)" -o "$(OPENAPI_CLIENT_OUTPUT)" "$(OPENAPI_SOURCE)"; \
	go -C tools tool oapi-codegen -config "$(OPENAPI_MILTER_CONFIG)" -o "$(OPENAPI_MILTER_OUTPUT)" "$(OPENAPI_SOURCE)"; \
	go -C tools tool oapi-codegen -config "$(OPENAPI_MILTER_TEST_SERVER_CONFIG)" -o "$(OPENAPI_MILTER_TEST_SERVER_OUTPUT)" "$(OPENAPI_SOURCE)"

.PHONY: check-openapi
check-openapi: check-workspace
	@set -eu; \
	output="$$(mktemp -d /tmp/dkim2-openapi-check.XXXXXX)"; \
	chmod 0700 "$$output"; \
	trap 'rm -rf "$$output"' 0 1 2 15; \
	mkdir -m 0700 "$$output/cache"; \
	: > "$$output/caller-cache"; \
	GOCACHE="$$output/caller-cache" $(MAKE) generate-openapi \
		OPENAPI_SERVER_WIRE="$$output/server-wire.go" \
		OPENAPI_CLIENT_WIRE="$$output/client-wire.go" \
		OPENAPI_MILTER_WIRE="$$output/milter-wire.go" \
		OPENAPI_SERVER_OUTPUT="$$output/server.gen.go" \
		OPENAPI_CLIENT_OUTPUT="$$output/client.gen.go" \
		OPENAPI_MILTER_OUTPUT="$$output/milter.gen.go" \
		OPENAPI_MILTER_TEST_SERVER_OUTPUT="$$output/milter-test-server.gen.go"; \
	export GOCACHE="$$output/cache"; \
	cmp "$(OPENAPI_SERVER_WIRE)" "$$output/server-wire.go"; \
	cmp "$(OPENAPI_CLIENT_WIRE)" "$$output/client-wire.go"; \
	cmp "$(OPENAPI_MILTER_WIRE)" "$$output/milter-wire.go"; \
	cmp "$(OPENAPI_SERVER_OUTPUT)" "$$output/server.gen.go"; \
	cmp "$(OPENAPI_CLIENT_OUTPUT)" "$$output/client.gen.go"; \
	cmp "$(OPENAPI_MILTER_OUTPUT)" "$$output/milter.gen.go"; \
	cmp "$(OPENAPI_MILTER_TEST_SERVER_OUTPUT)" "$$output/milter-test-server.gen.go"; \
	! rg -q '^output:' "$(OPENAPI_SERVER_CONFIG)" "$(OPENAPI_CLIENT_CONFIG)" "$(OPENAPI_MILTER_CONFIG)" "$(OPENAPI_MILTER_TEST_SERVER_CONFIG)"; \
	rg -q '^[[:space:]]*(require[[:space:]]+)?github.com/getkin/kin-openapi v0\.135\.0$$' tools/go.mod; \
	rg -q '^[[:space:]]*(require[[:space:]]+)?github.com/getkin/kin-openapi v0\.135\.0$$' cmd/dkim2d/go.mod; \
	rg -q '^[[:space:]]*github.com/oapi-codegen/oapi-codegen/v2 v2\.7\.1( // indirect)?$$' tools/go.mod; \
	! rg -q 'github.com/oapi-codegen/runtime' cmd/dkim2d/go.mod cmd/dkim2ctl/go.mod cmd/dkim2-milter/go.mod; \
	! rg -q 'github.com/oapi-codegen/runtime' cmd/dkim2d cmd/dkim2ctl cmd/dkim2-milter --glob '*.go'; \
	! rg -q 'oapi-codegen|kin-openapi' lib/go.mod lib --glob '*.go' --glob '!*_test.go'; \
	! rg -q 'oapi-codegen/(nethttp|middleware)' --glob 'go.mod' .; \
	go -C tools test ./cmd/wiregen; \
	go -C cmd/dkim2d test ./internal/httpjson/...; \
	go -C cmd/dkim2ctl test ./internal/testclient/...; \
	go -C cmd/dkim2-milter test ./internal/daemon/...

.PHONY: check-workspace
check-workspace:
	@set -eu; \
	output="$$(mktemp -d /tmp/dkim2-workspace-check.XXXXXX)"; \
	chmod 0700 "$$output"; \
	trap 'rm -rf "$$output"' 0 1 2 15; \
	mkdir -m 0700 "$$output/repo"; \
	tar -cf - --exclude=.git --exclude=temp --exclude=vendor . | \
		tar -xf - -C "$$output/repo"; \
	(cd "$$output/repo" && GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" GOFLAGS= go work sync); \
	for file in $(WORKSPACE_ABSENT_SUM_FILES); do \
		test ! -s "$$output/repo/$$file"; \
		rm -f "$$output/repo/$$file"; \
		test ! -e "$$file"; \
	done; \
	for file in $(WORKSPACE_SYNC_FILES); do \
		cmp "$$file" "$$output/repo/$$file"; \
	done

.PHONY: vendor
vendor:
	@set -eu; \
	GOFLAGS= go work vendor; \
	for path in $(VENDOR_LF_PATHS); do \
		source="vendor/$$path"; \
		normalized="$$source.lf"; \
		tr -d '\r' < "$$source" > "$$normalized"; \
		chmod 0644 "$$normalized"; \
		mv "$$normalized" "$$source"; \
	done

.PHONY: check-vendor
check-vendor:
	@set -eu; \
	output="$$(mktemp -d /tmp/dkim2-vendor-check.XXXXXX)"; \
	trap 'rm -rf "$$output"' 0 1 2 15; \
	GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" GOFLAGS= go work vendor -o "$$output"; \
	for path in $(VENDOR_LF_PATHS); do \
		source="$$output/$$path"; \
		normalized="$$source.lf"; \
		tr -d '\r' < "$$source" > "$$normalized"; \
		chmod 0644 "$$normalized"; \
		mv "$$normalized" "$$source"; \
	done; \
	diff -qr vendor "$$output"

.PHONY: check-protected-platforms
check-protected-platforms:
	@set -eu; \
	output="$$(mktemp -d /tmp/dkim2-protected-platforms.XXXXXX)"; \
	trap 'rm -rf "$$output"' 0 1 2 15; \
	mkdir -m 0700 "$$output/cache"; \
	GOCACHE="$$output/cache" GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		go test -c -o "$$output/linux-amd64.test" ./cmd/dkim2d/internal/config; \
	GOCACHE="$$output/cache" GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
		go test -c -o "$$output/linux-arm64.test" ./cmd/dkim2d/internal/config; \
	GOCACHE="$$output/cache" GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 \
		go test -c -o "$$output/freebsd-amd64.test" ./cmd/dkim2d/internal/config; \
	GOCACHE="$$output/cache" GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
		go test -c -o "$$output/windows-amd64.test.exe" ./cmd/dkim2d/internal/config; \
	GOCACHE="$$output/cache" GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		go test -c -o "$$output/dkim2ctl-linux-amd64.test" ./cmd/dkim2ctl/internal/testclient; \
	GOCACHE="$$output/cache" GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
		go test -c -o "$$output/dkim2ctl-linux-arm64.test" ./cmd/dkim2ctl/internal/testclient; \
	GOCACHE="$$output/cache" GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 \
		go test -c -o "$$output/dkim2ctl-freebsd-amd64.test" ./cmd/dkim2ctl/internal/testclient; \
	GOCACHE="$$output/cache" GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
		go test -c -o "$$output/dkim2ctl-windows-amd64.test.exe" ./cmd/dkim2ctl/internal/testclient; \
	GOCACHE="$$output/cache" GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		go build -o "$$output/dkim2-milter-linux-amd64" ./cmd/dkim2-milter; \
	GOCACHE="$$output/cache" GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
		go build -o "$$output/dkim2-milter-linux-arm64" ./cmd/dkim2-milter; \
	GOCACHE="$$output/cache" GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 \
		go test -c -o "$$output/dkim2-milter-freebsd-amd64.test" ./cmd/dkim2-milter/internal/config; \
	GOCACHE="$$output/cache" GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
		go test -c -o "$$output/dkim2-milter-windows-amd64.test.exe" ./cmd/dkim2-milter/internal/config; \
	if test "$$(go env GOOS)" = darwin; then \
		GOCACHE="$$output/cache" CGO_ENABLED=1 go test ./cmd/dkim2d/internal/config; \
		GOCACHE="$$output/cache" CGO_ENABLED=0 go test ./cmd/dkim2d/internal/config; \
		GOCACHE="$$output/cache" CGO_ENABLED=1 go test ./cmd/dkim2-milter/internal/config ./cmd/dkim2-milter/internal/securefile; \
		GOCACHE="$$output/cache" CGO_ENABLED=0 go build -o "$$output/dkim2-milter-darwin-nocgo" ./cmd/dkim2-milter; \
		GOCACHE="$$output/cache" CGO_ENABLED=0 go test -run '^TestDarwinNoCGOProtectedLoadingFailsClosed$$' ./cmd/dkim2-milter/internal/securefile; \
	fi

.PHONY: guardrails
guardrails: fmt vet lint test race check-protected-platforms check-openapi check-vendor govulncheck
