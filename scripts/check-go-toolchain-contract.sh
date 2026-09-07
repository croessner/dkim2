#!/bin/sh
set -eu
export GOEXPERIMENT=runtimesecret
export GOTOOLCHAIN=go1.27.0
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
case $(go version) in
  'go version go1.27.0 '*) ;;
  *) echo 'exact Go 1.27.0 is required' >&2; exit 1 ;;
esac
python3 scripts/test_go_toolchain_contract.py
