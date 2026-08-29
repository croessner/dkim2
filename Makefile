ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
PRODUCT_MODULES := ./lib ./cmd/dkim2d ./cmd/dkim2-milter ./cmd/dkim2-exim ./cmd/dkim2ctl
TOOL_MODULES := ./tools
MODULES := $(PRODUCT_MODULES) $(TOOL_MODULES)
OPENAPI_DIR := $(ROOT)/docs/specs/openapi
OPENAPI_SOURCE := $(OPENAPI_DIR)/dkim2d.yaml
OPENAPI_SERVER_CONFIG := $(OPENAPI_DIR)/oapi-codegen.server.yml
OPENAPI_CLIENT_CONFIG := $(OPENAPI_DIR)/oapi-codegen.client.yml
OPENAPI_MILTER_CONFIG := $(OPENAPI_DIR)/oapi-codegen.milter-client.yml
OPENAPI_MILTER_TEST_SERVER_CONFIG := $(OPENAPI_DIR)/oapi-codegen.milter-test-server.yml
OPENAPI_EXIM_CONFIG := $(OPENAPI_DIR)/oapi-codegen.exim-client.yml
OPENAPI_EXIM_TEST_SERVER_CONFIG := $(OPENAPI_DIR)/oapi-codegen.exim-test-server.yml
OPENAPI_SERVER_OUTPUT := $(ROOT)/cmd/dkim2d/internal/httpjson/generated/server.gen.go
OPENAPI_CLIENT_OUTPUT := $(ROOT)/cmd/dkim2ctl/internal/testclient/generated/client.gen.go
OPENAPI_MILTER_OUTPUT := $(ROOT)/cmd/dkim2-milter/internal/daemon/generated/client.gen.go
OPENAPI_MILTER_TEST_SERVER_OUTPUT := $(ROOT)/cmd/dkim2-milter/internal/integration/generated/server.gen.go
OPENAPI_EXIM_OUTPUT := $(ROOT)/cmd/dkim2-exim/internal/daemon/generated/client.gen.go
OPENAPI_EXIM_TEST_SERVER_OUTPUT := $(ROOT)/cmd/dkim2-exim/internal/integration/generated/server.gen.go
OPENAPI_SERVER_WIRE := $(ROOT)/cmd/dkim2d/internal/httpjson/wire/protected_string.gen.go
OPENAPI_CLIENT_WIRE := $(ROOT)/cmd/dkim2ctl/internal/testclient/wire/protected_string.gen.go
OPENAPI_MILTER_WIRE := $(ROOT)/cmd/dkim2-milter/internal/daemon/wire/protected_string.gen.go
OPENAPI_EXIM_WIRE := $(ROOT)/cmd/dkim2-exim/internal/daemon/wire/protected_string.gen.go
OPENAPI_GO_TOOLCHAIN := go1.26.0
VENDOR_LF_PATHS := github.com/vmware-labs/yaml-jsonpath/LICENSE github.com/vmware-labs/yaml-jsonpath/NOTICE
# OTLP's x/net graph makes Go 1.26 synchronize dkim2ctl's pruned module sums.
WORKSPACE_SYNC_FILES := go.work go.work.sum lib/go.mod lib/go.sum cmd/dkim2d/go.mod cmd/dkim2d/go.sum cmd/dkim2-milter/go.mod cmd/dkim2-milter/go.sum cmd/dkim2-exim/go.mod cmd/dkim2-exim/go.sum cmd/dkim2ctl/go.mod cmd/dkim2ctl/go.sum tools/go.mod tools/go.sum
WORKSPACE_ABSENT_SUM_FILES :=
EXIM_C_DIR := $(ROOT)/cmd/dkim2-exim/exim
EXIM_PROBE_CONTRACT := $(EXIM_C_DIR)/generated/probe-contract-v1.txt
EXIM_BUILD_HEADER := $(EXIM_C_DIR)/generated/build-id-v1.h
EXIM_COMPAT_MANIFEST := $(EXIM_C_DIR)/generated/compatibility-manifest-v1.txt
EXIM_SOURCE_MANIFEST := $(EXIM_C_DIR)/fixtures/upstream-4.99.5/source-manifest-v1.txt
EXIM_MATRIX_ROWS := upstream-4.99.5 debian-4.98.2-1+deb13u3 debian-4.98.2-1+deb13u4 ubuntu-4.99.1-1ubuntu1.3 ubuntu-4.99.1-1ubuntu1.4

.PHONY: help
help:
	@printf '%s\n' \
		'Targets:' \
		'  make fix                     modernize Go source' \
		'  make fmt                     format Go source' \
		'  make vet                     run Go vet' \
		'  make lint                    run golangci-lint' \
		'  make test                    run Go unit tests only' \
		'  make race                    run race-enabled Go unit tests only' \
		'  make build-check             build all product surfaces' \
		'  make check-generated         verify generated OpenAPI and adapter artifacts' \
		'  make check-conformance       verify conformance contracts' \
		'  make conformance             run portable protocol conformance' \
		'  make integration-valkey      run Valkey integration' \
		'  make integration-datasources run LDAP and SQL service integration' \
		'  make integration-postfix     run real Postfix/Milter qualification' \
		'  make integration-exim        run Linux Exim adapter integration' \
		'  make qualification-exim      run source-matched Exim version qualification' \
		'  make container-smoke         build images and run hardened runtime smoke' \
		'  make guardrails              run normal product quality once' \
		'  make release-guardrails      run release quality and conformance'

.PHONY: check-datasource-schema
check-datasource-schema:
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C cmd/dkim2d test ./internal/datasource/ldap
	@set -eu; \
	if command -v slaptest >/dev/null 2>&1; then \
		work="$$(mktemp -d /tmp/dkim2-slaptest.XXXXXX)"; \
		trap 'rm -rf "$$work"' 0 1 2 15; \
		core=""; \
		for candidate in /etc/ldap/schema/core.schema /etc/openldap/schema/core.schema /usr/local/etc/openldap/schema/core.schema /opt/homebrew/etc/openldap/schema/core.schema; do \
			if test -f "$$candidate"; then core="$$candidate"; break; fi; \
		done; \
		test -n "$$core"; \
		cp contrib/schema/ldap/rnsdkim2.schema "$$work/rnsdkim2.schema"; \
		cp contrib/schema/ldap/acl.conf "$$work/acl.conf"; \
		sed -e "s|@CORE_SCHEMA@|$$core|" \
			-e "s|include rnsdkim2.schema|include $$work/rnsdkim2.schema|" \
			-e "s|include acl.conf|include $$work/acl.conf|" \
			contrib/schema/ldap/slapd.conf > "$$work/slapd.conf"; \
		slaptest -u -f "$$work/slapd.conf" >/dev/null; \
		if command -v ldapadd >/dev/null 2>&1; then \
			ldapadd -n -f contrib/schema/ldap/layout.ldif >/dev/null; \
		fi; \
	fi

.PHONY: check-datasource-postgresql
check-datasource-postgresql:
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C cmd/dkim2d test ./internal/datasource/postgresql

.PHONY: check-datasource-mysql
check-datasource-mysql:
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C cmd/dkim2d test \
			./internal/datasource/mysql ./internal/datasource/sqlsnapshot

.PHONY: test-datasource-ldap-acl
test-datasource-ldap-acl:
	@scripts/test-datasource-ldap-acl.sh

.PHONY: test-datasource-ldap
test-datasource-ldap: check-datasource-schema test-datasource-ldap-acl
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C cmd/dkim2d test -race ./internal/datasource/ldap

.PHONY: test-datasource-postgresql
test-datasource-postgresql: check-datasource-postgresql
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C cmd/dkim2d test -race ./internal/datasource/postgresql

.PHONY: test-datasource-mysql
test-datasource-mysql: check-datasource-mysql
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C cmd/dkim2d test -race \
			./internal/datasource/mysql ./internal/datasource/sqlsnapshot

.PHONY: test-datasource-services
test-datasource-services:
	@scripts/test-datasource-services.sh

.PHONY: test-opendkim-bootstrap
test-opendkim-bootstrap:
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C cmd/dkim2d test -race \
			./internal/migration ./internal/signingstore ./internal/command

.PHONY: fmt
fmt:
	@gofmt -w lib cmd tools

.PHONY: fmt-check
fmt-check:
	@test -z "$$(gofmt -l lib cmd tools)" || { \
		gofmt -l lib cmd tools; \
		exit 1; \
	}

.PHONY: fix
fix:
	@set -e; for module in $(PRODUCT_MODULES); do \
		echo "==> go fix $$module/..."; \
		(cd $$module && go fix ./...); \
	done

.PHONY: test-postfix-qualification-helper
test-postfix-qualification-helper:
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go test contrib/qualification/postfix-milter/cmd/qualify/main.go \
			contrib/qualification/postfix-milter/cmd/qualify/main_test.go

.PHONY: test
test: test-postfix-qualification-helper
	@set -e; for module in $(PRODUCT_MODULES); do \
		echo "==> go test $$module/..."; \
		(cd $$module && go test ./...); \
	done

.PHONY: test-exim-local-scan
test-exim-local-scan:
	@cmd/dkim2-exim/exim/tests/run-local-scan-harness.sh

.PHONY: check-exim-upstream-patch
check-exim-upstream-patch:
	@EXIM_UPSTREAM_SOURCE="$(EXIM_UPSTREAM_SOURCE)" \
		cmd/dkim2-exim/exim/tests/check-upstream-patch.sh

.PHONY: check-exim-transport-filter-source-patch
check-exim-transport-filter-source-patch:
	@cmd/dkim2-exim/exim/tests/check-transport-filter-source-patch.sh

.PHONY: test-exim-packaging
test-exim-packaging:
	@cmd/dkim2-exim/packaging/tests/test-validator.sh
	@cmd/dkim2-exim/packaging/tests/test-package-hook.sh

.PHONY: generate-exim-row-builds
generate-exim-row-builds:
	@set -eu; for row in $(EXIM_MATRIX_ROWS); do \
		fixture="$(EXIM_C_DIR)/fixtures/$$row"; \
		version="$$(awk -F= '$$1 == "exim_version" { print $$2 }' "$$fixture/source-manifest-v1.txt")"; \
		go run ./cmd/dkim2-exim/exim/buildid \
			-exim-version "$$version" \
			-source "$$fixture/source-manifest-v1.txt" \
			-probe-contract "$$fixture/probe-contract-v1.txt" \
			-header-output "$$fixture/build-id-v1.h" \
			-manifest-output "$$fixture/compatibility-manifest-v1.txt"; \
	done

.PHONY: check-exim-row-builds
check-exim-row-builds:
	@set -eu; \
	output="$$(mktemp -d /tmp/dkim2-exim-row-builds.XXXXXX)"; \
	chmod 0700 "$$output"; \
	trap 'rm -rf "$$output"' 0 1 2 15; \
	for row in $(EXIM_MATRIX_ROWS); do \
		fixture="$(EXIM_C_DIR)/fixtures/$$row"; \
		version="$$(awk -F= '$$1 == "exim_version" { print $$2 }' "$$fixture/source-manifest-v1.txt")"; \
		go run ./cmd/dkim2-exim/exim/buildid \
			-exim-version "$$version" \
			-source "$$fixture/source-manifest-v1.txt" \
			-probe-contract "$$fixture/probe-contract-v1.txt" \
			-header-output "$$output/$$row.h" \
			-manifest-output "$$output/$$row.manifest"; \
		cmp "$$fixture/build-id-v1.h" "$$output/$$row.h"; \
		cmp "$$fixture/compatibility-manifest-v1.txt" "$$output/$$row.manifest"; \
		awk -F= '$$1 == "build_id" { print $$2 }' "$$output/$$row.manifest" >> "$$output/build-ids"; \
	done; \
	sort -u "$$output/build-ids" -o "$$output/unique-build-ids"; \
	test "$$(wc -l < "$$output/unique-build-ids")" -eq 5

.PHONY: check-exim-matrix-prep
check-exim-matrix-prep: check-exim-build check-exim-row-builds test-exim-packaging test-exim-real-matrix-helper test-exim-real-matrix-verifier

.PHONY: check-exim-real-matrix-evidence-schema
check-exim-real-matrix-evidence-schema: test-exim-real-matrix-helper test-exim-real-matrix-verifier
	@set -eu; \
	cmd/dkim2-exim/exim/tests/run-real-matrix.sh

	@set -eu; \
	for row in $(EXIM_MATRIX_ROWS); do \
		test -s "$(EXIM_C_DIR)/fixtures/$$row/source-manifest-v1.txt"; \
		test -s "$(EXIM_C_DIR)/fixtures/$$row/probe-contract-v1.txt"; \
		test -s "$(EXIM_C_DIR)/fixtures/$$row/provenance-v1.txt"; \
		test -s "$(EXIM_C_DIR)/fixtures/$$row/build-id-v1.h"; \
		test -s "$(EXIM_C_DIR)/fixtures/$$row/compatibility-manifest-v1.txt"; \
		grep -Eq '^format=dkim2-exim-source-manifest-v1$$' "$(EXIM_C_DIR)/fixtures/$$row/source-manifest-v1.txt"; \
		grep -Eq '^source_sha256=[0-9a-f]{64}$$' "$(EXIM_C_DIR)/fixtures/$$row/source-manifest-v1.txt"; \
		grep -Eq '^retrieved_at=2026-07-27$$' "$(EXIM_C_DIR)/fixtures/$$row/provenance-v1.txt"; \
		grep -Eq '^license=GPL-2.0-or-later$$' "$(EXIM_C_DIR)/fixtures/$$row/provenance-v1.txt"; \
	done; \
	test -s "$(EXIM_C_DIR)/fixtures/debian-4.98.2-1+deb13u3/local_scan.patch"; \
	test -s "$(EXIM_C_DIR)/fixtures/ubuntu-4.99.1-1ubuntu1.3/include/local_scan.h"; \
	test -s "$(EXIM_C_DIR)/fixtures/ubuntu-4.99.1-1ubuntu1.4/include/local_scan.h"; \
	test -s "$(ROOT)/cmd/dkim2-exim/packaging/exim/Local.Makefile"; \
	grep -Eq '^HAVE_LOCAL_SCAN=yes$$' "$(ROOT)/cmd/dkim2-exim/packaging/exim/Local.Makefile"; \
	grep -Eq '^LOCAL_SCAN_SOURCE=Local/dkim2_local_scan\.c$$' "$(ROOT)/cmd/dkim2-exim/packaging/exim/Local.Makefile"; \
	grep -Eq '^LOCAL_SCAN_HAS_OPTIONS=yes$$' "$(ROOT)/cmd/dkim2-exim/packaging/exim/Local.Makefile"; \
	test -s "$(ROOT)/cmd/dkim2-exim/packaging/debian/exim4-dkim2-build.patch"; \
	test -s "$(ROOT)/cmd/dkim2-exim/packaging/ubuntu/exim4-dkim2-build.patch"; \
	patch --dry-run -s -p1 -d "$(ROOT)/cmd/dkim2-exim/packaging/tests/fixtures/debian" < "$(ROOT)/cmd/dkim2-exim/packaging/debian/exim4-dkim2-build.patch"; \
	patch --dry-run -s -p1 -d "$(ROOT)/cmd/dkim2-exim/packaging/tests/fixtures/ubuntu" < "$(ROOT)/cmd/dkim2-exim/packaging/ubuntu/exim4-dkim2-build.patch"
	@set -eu; \
	patch_file="$(ROOT)/cmd/dkim2-exim/packaging/exim/dkim2-transport-filter-return-path.patch"; \
	if command -v sha256sum >/dev/null 2>&1; then patch_sha="$$(sha256sum "$$patch_file" | awk '{ print $$1 }')"; else patch_sha="$$(shasum -a 256 "$$patch_file" | awk '{ print $$1 }')"; fi; \
	for row in $(EXIM_MATRIX_ROWS); do \
		fixture="$(EXIM_C_DIR)/fixtures/$$row"; \
		grep -Fqx "transport_filter_patch_sha256=$$patch_sha" "$$fixture/source-manifest-v1.txt"; \
		grep -Fqx "transport_filter_patch_sha256=$$patch_sha" "$$fixture/probe-contract-v1.txt"; \
	done

.PHONY: test-exim-real-matrix
test-exim-real-matrix:
	@cmd/dkim2-exim/exim/tests/run-real-matrix-linux.sh

.PHONY: test-exim-real-matrix-verifier
test-exim-real-matrix-verifier:
	@cmd/dkim2-exim/exim/tests/test-real-matrix-verifier.sh

.PHONY: test-exim-real-matrix-helper
test-exim-real-matrix-helper:
	@python3 -B cmd/dkim2-exim/exim/tests/test_real_matrix_service.py

.PHONY: check-exim-c-linux-cross
check-exim-c-linux-cross:
	@cmd/dkim2-exim/exim/tests/run-linux-cross-compile.sh

.PHONY: check-exim-c-linux-native
check-exim-c-linux-native:
	@cmd/dkim2-exim/exim/tests/run-linux-native-compile.sh

.PHONY: generate-exim-build
generate-exim-build: test-exim-local-scan
	@set -eu; \
	cp "$(EXIM_C_DIR)/fixtures/upstream-4.99.5/probe-contract-v1.txt" \
		"$(EXIM_PROBE_CONTRACT)"; \
	go run ./cmd/dkim2-exim/exim/buildid \
		-exim-version 4.99.5 \
		-source "$(EXIM_SOURCE_MANIFEST)"

.PHONY: check-exim-build
check-exim-build:
	@set -eu; \
	output="$$(mktemp -d /tmp/dkim2-exim-build-check.XXXXXX)"; \
	chmod 0700 "$$output"; \
	trap 'rm -rf "$$output"' 0 1 2 15; \
	cmp "$(EXIM_C_DIR)/fixtures/upstream-4.99.5/probe-contract-v1.txt" \
		"$(EXIM_PROBE_CONTRACT)"; \
	go run ./cmd/dkim2-exim/exim/buildid \
		-exim-version 4.99.5 \
		-source "$(EXIM_SOURCE_MANIFEST)" \
		-header-output "$$output/build-id-v1.h" \
		-manifest-output "$$output/compatibility-manifest-v1.txt"; \
	cmp "$(EXIM_BUILD_HEADER)" "$$output/build-id-v1.h"; \
	cmp "$(EXIM_COMPAT_MANIFEST)" "$$output/compatibility-manifest-v1.txt"

.PHONY: race
race:
	@set -e; for module in $(PRODUCT_MODULES); do \
		echo "==> go test -race $$module/..."; \
		(cd $$module && go test -race ./...); \
	done

.PHONY: vet
vet:
	@set -e; for module in $(PRODUCT_MODULES); do \
		echo "==> go vet $$module/..."; \
		(cd $$module && go vet ./...); \
	done

.PHONY: lint
lint:
	@set -e; for module in $(PRODUCT_MODULES); do \
		echo "==> golangci-lint $$module/..."; \
		(cd $$module && golangci-lint run ./...); \
	done

.PHONY: build-check
build-check:
	@set -e; for module in $(PRODUCT_MODULES); do \
		echo "==> go build $$module/..."; \
		(cd $$module && go build ./...); \
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

.PHONY: check-ci
check-ci:
	@scripts/check-ci.sh

.PHONY: generate-openapi
generate-openapi:
	@set -eu; \
	cache="$$(mktemp -d /tmp/dkim2-openapi-generate-cache.XXXXXX)"; \
	chmod 0700 "$$cache"; \
	trap 'rm -rf "$$cache"' 0 1 2 15; \
	export GOCACHE="$$cache"; \
	export GOTOOLCHAIN="$(OPENAPI_GO_TOOLCHAIN)"; \
	go -C tools run ./cmd/wiregen -package wire -output "$(OPENAPI_SERVER_WIRE)"; \
	go -C tools run ./cmd/wiregen -package wire -output "$(OPENAPI_CLIENT_WIRE)"; \
	go -C tools run ./cmd/wiregen -package wire -output "$(OPENAPI_MILTER_WIRE)"; \
	go -C tools run ./cmd/wiregen -package wire -output "$(OPENAPI_EXIM_WIRE)"; \
	go -C tools tool oapi-codegen -config "$(OPENAPI_SERVER_CONFIG)" -o "$(OPENAPI_SERVER_OUTPUT)" "$(OPENAPI_SOURCE)"; \
	go -C tools tool oapi-codegen -config "$(OPENAPI_CLIENT_CONFIG)" -o "$(OPENAPI_CLIENT_OUTPUT)" "$(OPENAPI_SOURCE)"; \
	go -C tools tool oapi-codegen -config "$(OPENAPI_MILTER_CONFIG)" -o "$(OPENAPI_MILTER_OUTPUT)" "$(OPENAPI_SOURCE)"; \
	go -C tools tool oapi-codegen -config "$(OPENAPI_MILTER_TEST_SERVER_CONFIG)" -o "$(OPENAPI_MILTER_TEST_SERVER_OUTPUT)" "$(OPENAPI_SOURCE)"; \
	go -C tools tool oapi-codegen -config "$(OPENAPI_EXIM_CONFIG)" -o "$(OPENAPI_EXIM_OUTPUT)" "$(OPENAPI_SOURCE)"; \
	go -C tools tool oapi-codegen -config "$(OPENAPI_EXIM_TEST_SERVER_CONFIG)" -o "$(OPENAPI_EXIM_TEST_SERVER_OUTPUT)" "$(OPENAPI_SOURCE)"

.PHONY: generate-openapi-check-output
generate-openapi-check-output: override OPENAPI_SERVER_WIRE = $(OPENAPI_CHECK_OUTPUT)/server-wire.go
generate-openapi-check-output: override OPENAPI_CLIENT_WIRE = $(OPENAPI_CHECK_OUTPUT)/client-wire.go
generate-openapi-check-output: override OPENAPI_MILTER_WIRE = $(OPENAPI_CHECK_OUTPUT)/milter-wire.go
generate-openapi-check-output: override OPENAPI_EXIM_WIRE = $(OPENAPI_CHECK_OUTPUT)/exim-wire.go
generate-openapi-check-output: override OPENAPI_SERVER_OUTPUT = $(OPENAPI_CHECK_OUTPUT)/server.gen.go
generate-openapi-check-output: override OPENAPI_CLIENT_OUTPUT = $(OPENAPI_CHECK_OUTPUT)/client.gen.go
generate-openapi-check-output: override OPENAPI_MILTER_OUTPUT = $(OPENAPI_CHECK_OUTPUT)/milter.gen.go
generate-openapi-check-output: override OPENAPI_MILTER_TEST_SERVER_OUTPUT = $(OPENAPI_CHECK_OUTPUT)/milter-test-server.gen.go
generate-openapi-check-output: override OPENAPI_EXIM_OUTPUT = $(OPENAPI_CHECK_OUTPUT)/exim.gen.go
generate-openapi-check-output: override OPENAPI_EXIM_TEST_SERVER_OUTPUT = $(OPENAPI_CHECK_OUTPUT)/exim-test-server.gen.go
ifneq ($(strip $(OPENAPI_CHECK_OUTPUT)),)
generate-openapi-check-output: generate-openapi
else
generate-openapi-check-output:
	@printf '%s\n' 'OPENAPI_CHECK_OUTPUT is required' >&2; exit 1
endif

.PHONY: check-openapi
check-openapi:
	@set -eu; \
	make_flags="$${MAKEFLAGS-}"; \
	for make_flag in $$make_flags; do \
		case "$$make_flag" in --|*=*) break ;; -*) ;; *n*) exit 0 ;; esac; \
	done; \
	output="$$(mktemp -d /tmp/dkim2-openapi-check.XXXXXX)"; \
	chmod 0700 "$$output"; \
	trap 'rm -rf "$$output"' 0 1 2 15; \
	mkdir -m 0700 "$$output/cache"; \
	: > "$$output/caller-cache"; \
	GOCACHE="$$output/caller-cache" $(MAKE) generate-openapi-check-output \
		OPENAPI_CHECK_OUTPUT="$$output"; \
	export GOCACHE="$$output/cache"; \
	cmp "$(OPENAPI_SERVER_WIRE)" "$$output/server-wire.go"; \
	cmp "$(OPENAPI_CLIENT_WIRE)" "$$output/client-wire.go"; \
	cmp "$(OPENAPI_MILTER_WIRE)" "$$output/milter-wire.go"; \
	cmp "$(OPENAPI_EXIM_WIRE)" "$$output/exim-wire.go"; \
	cmp "$(OPENAPI_SERVER_OUTPUT)" "$$output/server.gen.go"; \
	cmp "$(OPENAPI_CLIENT_OUTPUT)" "$$output/client.gen.go"; \
	cmp "$(OPENAPI_MILTER_OUTPUT)" "$$output/milter.gen.go"; \
	cmp "$(OPENAPI_MILTER_TEST_SERVER_OUTPUT)" "$$output/milter-test-server.gen.go"; \
	cmp "$(OPENAPI_EXIM_OUTPUT)" "$$output/exim.gen.go"; \
	cmp "$(OPENAPI_EXIM_TEST_SERVER_OUTPUT)" "$$output/exim-test-server.gen.go"; \
	! grep -Eq '^output:' "$(OPENAPI_SERVER_CONFIG)" "$(OPENAPI_CLIENT_CONFIG)" "$(OPENAPI_MILTER_CONFIG)" "$(OPENAPI_MILTER_TEST_SERVER_CONFIG)" "$(OPENAPI_EXIM_CONFIG)" "$(OPENAPI_EXIM_TEST_SERVER_CONFIG)"; \
	grep -Eq '^[[:space:]]*(require[[:space:]]+)?github.com/getkin/kin-openapi v0\.149\.0$$' tools/go.mod; \
	grep -Eq '^[[:space:]]*(require[[:space:]]+)?github.com/getkin/kin-openapi v0\.149\.0$$' cmd/dkim2d/go.mod; \
	grep -Eq '^[[:space:]]*github.com/oapi-codegen/oapi-codegen/v2 v2\.8\.0( // indirect)?$$' tools/go.mod; \
	for module in cmd/dkim2ctl/go.mod cmd/dkim2-milter/go.mod cmd/dkim2-exim/go.mod; do grep -Eq '^[[:space:]]*github.com/oapi-codegen/runtime v1\.7\.0$$' "$$module"; done; \
	! grep -Eq 'github.com/oapi-codegen/runtime' cmd/dkim2d/go.mod lib/go.mod; \
	! grep -REq --include='*.go' 'github.com/oapi-codegen/runtime' cmd/dkim2d lib; \
	! grep -Eq 'oapi-codegen|kin-openapi' lib/go.mod; \
	! grep -REq --include='*.go' --exclude='*_test.go' 'oapi-codegen|kin-openapi' lib; \
	! grep -REq --include='go.mod' 'oapi-codegen/(nethttp|middleware)' .; \
	go -C tools test ./cmd/wiregen; \
	go -C cmd/dkim2d test ./internal/httpjson/...; \
	go -C cmd/dkim2ctl test ./internal/testclient/...; \
	go -C cmd/dkim2-milter test ./internal/daemon/...; \
	go -C cmd/dkim2-exim test ./internal/daemon/...

.PHONY: check-generated
check-generated: check-openapi check-exim-build check-exim-row-builds

.PHONY: check-workspace
check-workspace:
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools run ./cmd/reference -root .. check-workspace

.PHONY: check-boundaries
check-boundaries:
	@set -eu; \
	! go list -deps ./lib/... | grep -Eq 'github.com/croessner/dkim2/cmd/|oapi-codegen|cobra|viper|fx|prometheus'; \
	! go -C cmd/dkim2-exim list -deps ./... | grep -Eq 'github.com/croessner/dkim2/cmd/dkim2-milter|github.com/croessner/dkim2/cmd/dkim2d/internal'; \
	! grep -REq --include='*.go' 'cmd/dkim2-milter|cmd/dkim2d/internal|\"C\"' cmd/dkim2-exim; \
	scripts/check-securefile-parity.sh

.PHONY: vendor
vendor:
	GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		GOFLAGS=-mod=vendor \
		go -C tools run ./cmd/reference -root .. vendor

.PHONY: check-vendor
check-vendor:
	@set -eu; for module in $(MODULES); do \
		echo "==> go list -mod=vendor $$module/..."; \
		(cd $$module && GOFLAGS=-mod=vendor go list -deps ./... >/dev/null); \
	done

.PHONY: check-platform-builds
check-platform-builds:
	@set -eu; \
	output="$$(mktemp -d /tmp/dkim2-platform-builds.XXXXXX)"; \
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
	GOCACHE="$$output/cache" GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		go build -o "$$output/dkim2-exim-linux-amd64" ./cmd/dkim2-exim; \
	GOCACHE="$$output/cache" GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
		go build -o "$$output/dkim2-exim-linux-arm64" ./cmd/dkim2-exim; \
	GOCACHE="$$output/cache" GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		go test -c -o "$$output/dkim2-exim-inbound-linux-amd64.test" ./cmd/dkim2-exim/internal/inbound; \
	GOCACHE="$$output/cache" GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
		go test -c -o "$$output/dkim2-exim-evidence-linux-arm64.test" ./cmd/dkim2-exim/internal/evidence; \
	GOCACHE="$$output/cache" GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 \
		go test -c -o "$$output/dkim2-milter-freebsd-amd64.test" ./cmd/dkim2-milter/internal/config; \
	GOCACHE="$$output/cache" GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
		go test -c -o "$$output/dkim2-milter-windows-amd64.test.exe" ./cmd/dkim2-milter/internal/config

.PHONY: check-admin-contract
check-admin-contract:
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C lib test -count=1 ./admincontract

.PHONY: check-conformance
check-conformance: check-admin-contract
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools run ./cmd/conformance -root .. check

.PHONY: generate-conformance-manifest
generate-conformance-manifest:
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools run ./cmd/conformance -root .. refresh-manifest

.PHONY: conformance
conformance:
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools run ./cmd/conformance -root .. -profile portable report

.PHONY: conformance-postfix
conformance-postfix:
	@contrib/qualification/postfix-milter/run.sh .artifacts/conformance-postfix

.PHONY: conformance-all
conformance-all:
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools run ./cmd/conformance -root .. -profile full report

.PHONY: check-security
check-security:
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools test ./internal/security ./cmd/security
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools run ./cmd/security -root .. check

.PHONY: fuzz-security
fuzz-security: check-security
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools run ./cmd/security -root .. fuzz

.PHONY: vulnerability-security
vulnerability-security:
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools run ./cmd/security -root .. vulnerability

.PHONY: race-security
race-security:
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools run ./cmd/security -root .. race

.PHONY: security
security: check-security fuzz-security race-security vulnerability-security conformance conformance-postfix conformance-all
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools run ./cmd/security -root .. report

.PHONY: integration-valkey
integration-valkey: test-valkey

.PHONY: integration-datasources
integration-datasources: test-datasource-services

.PHONY: integration-postfix
integration-postfix: conformance-postfix

.PHONY: integration-exim
integration-exim: test-exim-local-scan check-exim-matrix-prep check-exim-c-linux-native

.PHONY: qualification-exim
qualification-exim: integration-exim check-exim-c-linux-cross test-exim-real-matrix

.PHONY: guardrails
guardrails: check-ci fmt-check vet lint test race build-check check-generated check-vendor check-platform-builds check-boundaries check-operator-docs

.PHONY: product-binaries
product-binaries:
	@scripts/build-products.sh

.PHONY: check-images
check-images: product-binaries
	@scripts/check-images.sh
	@scripts/test-build-contract.sh

.PHONY: images images-multiarch
images: images-multiarch
images-multiarch: check-images
	@scripts/build-images.sh

.PHONY: publish-dev-images
publish-dev-images:
	@scripts/publish-dev-images.sh

.PHONY: image-sbom
image-sbom:
	@scripts/image-evidence.sh sbom

.PHONY: image-tools
image-tools:
	@scripts/fetch-image-tools.sh

.PHONY: image-inspect
image-inspect:
	@scripts/inspect-images.sh check

.PHONY: image-runtime
image-runtime:
	@scripts/test-image-runtime.sh

.PHONY: container-smoke
container-smoke: check-images image-runtime

.PHONY: image-provenance
image-provenance:
	@scripts/image-evidence.sh provenance

.PHONY: image-vulnerability
image-vulnerability:
	@scripts/image-evidence.sh vulnerability

.PHONY: image-reproducibility
image-reproducibility:
	@scripts/inspect-images.sh reproducibility

.PHONY: image-evidence
image-evidence:
	@scripts/image-evidence.sh check

.PHONY: image-release-evidence
image-release-evidence:
	@$(MAKE) image-tools
	@$(MAKE) images-multiarch
	@$(MAKE) image-inspect
	@$(MAKE) image-runtime
	@$(MAKE) image-sbom
	@$(MAKE) image-provenance
	@$(MAKE) image-vulnerability
	@$(MAKE) image-reproducibility
	@$(MAKE) image-evidence

.PHONY: check-deployment
check-deployment: check-images
	@scripts/check-deployment.sh

.PHONY: deployment-postfix
deployment-postfix: check-deployment conformance-postfix
	@$(MAKE) images-multiarch
	@$(MAKE) image-inspect
	@$(MAKE) image-runtime
	@scripts/test-postfix-deployment.sh

.PHONY: deployment-security
deployment-security: image-release-evidence deployment-postfix
	@scripts/test-privacy-evidence.sh

.PHONY: check-operator-docs
check-operator-docs:
	@tools/check-operator-docs.sh

.PHONY: check-container-release
check-container-release: product-binaries check-images check-operator-docs check-workspace check-vendor check-openapi check-conformance check-security
	@$(MAKE) image-release-evidence

.PHONY: check-release
check-release: guardrails check-reference check-container-release

.PHONY: release-guardrails
release-guardrails: guardrails govulncheck check-conformance conformance

.PHONY: check-interop
check-interop:
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools run ./cmd/interop -root .. check

.PHONY: interop
interop: check-interop
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools run ./cmd/interop -root .. current

.PHONY: check-reference
check-reference: check-interop check-openapi check-operator-docs
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools run ./cmd/reference -root .. check-api
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools run ./cmd/reference -root .. check-issues
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools run ./cmd/reference -root .. check-release
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools run ./cmd/reference -root .. module-proxy >/dev/null

.PHONY: reference-module-proof
reference-module-proof: check-reference
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools run ./cmd/reference -root .. module-proof

.PHONY: reference-report
reference-report: check-reference
	@GOCACHE="$${GOCACHE:-/tmp/dkim2-go-build-cache}" \
		go -C tools run ./cmd/reference -root .. report

.PHONY: release-candidate
release-candidate:
	@$(MAKE) check-reference
	@$(MAKE) interop
	@$(MAKE) conformance
	@$(MAKE) conformance-postfix
	@$(MAKE) conformance-all
	@$(MAKE) security
	@$(MAKE) deployment-security
	@$(MAKE) test-datasource-services
	@$(MAKE) test-opendkim-bootstrap
	@$(MAKE) reference-module-proof
	@$(MAKE) reference-report
