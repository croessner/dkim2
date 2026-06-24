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
		'  make govulncheck  run govulncheck for all workspace modules' \
		'  make check-openapi validate OpenAPI files exist' \
		'  make guardrails   run the local quality gate'

.PHONY: fmt
fmt:
	@gofmt -w lib cmd

.PHONY: test
test:
	@for module in $(MODULES); do \
		echo "==> go test $$module/..."; \
		(cd $$module && go test ./...); \
	done

.PHONY: race
race:
	@for module in $(MODULES); do \
		echo "==> go test -race $$module/..."; \
		(cd $$module && go test -race ./...); \
	done

.PHONY: vet
vet:
	@for module in $(MODULES); do \
		echo "==> go vet $$module/..."; \
		(cd $$module && go vet ./...); \
	done

.PHONY: lint
lint:
	@golangci-lint run ./lib/... ./cmd/dkim2d/... ./cmd/dkim2-milter/... ./cmd/dkim2ctl/...

.PHONY: govulncheck
govulncheck:
	@for module in $(MODULES); do \
		echo "==> govulncheck $$module/..."; \
		(cd $$module && govulncheck ./...); \
	done

.PHONY: check-openapi
check-openapi:
	@test -s docs/specs/openapi/dkim2d.yaml
	@test -s docs/specs/openapi/oapi-codegen.server.yml
	@test -s docs/specs/openapi/oapi-codegen.client.yml

.PHONY: guardrails
guardrails: fmt vet lint test race check-openapi

