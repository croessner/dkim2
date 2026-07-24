MODULES := ./lib ./cmd/dkim2d ./cmd/dkim2-milter ./cmd/dkim2ctl

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
		'  make check-openapi validate OpenAPI files exist' \
		'  make check-vendor  verify reproducible workspace vendoring' \
		'  make guardrails   run the local quality gate'

.PHONY: fmt
fmt:
	@gofmt -w lib cmd

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

.PHONY: check-openapi
check-openapi:
	@test -s docs/specs/openapi/dkim2d.yaml
	@test -s docs/specs/openapi/oapi-codegen.server.yml
	@test -s docs/specs/openapi/oapi-codegen.client.yml

.PHONY: check-vendor
check-vendor:
	@set -eu; \
	output="$$(mktemp -d /tmp/dkim2-vendor-check.XXXXXX)"; \
	trap 'rm -rf "$$output"' 0 1 2 15; \
	GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" GOFLAGS= go work vendor -o "$$output"; \
	diff -qr vendor "$$output"

.PHONY: guardrails
guardrails: fmt vet lint test race check-openapi check-vendor govulncheck
