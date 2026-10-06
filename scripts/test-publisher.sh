#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
MANIFEST=host/verifier/Cargo.toml

cargo fmt --check --manifest-path "$MANIFEST"
cargo test --offline --locked -j2 --manifest-path "$MANIFEST"
cargo build --offline --locked -j2 --manifest-path "$MANIFEST"
cargo build --release --offline --locked -j2 --manifest-path "$MANIFEST"
cargo build --offline --locked -j2 --manifest-path "$MANIFEST" --example synthetic-signer
python3 -m py_compile \
  host/release_contract.py \
  host/publish_remote.py \
  host/lapkb-pickup.py \
  scripts/publish_artifact.py \
  scripts/release_github.py \
  scripts/release_desktop.py \
  scripts/prepare_bundle.py \
  tests/test_release_automation.py \
  tests/support.py \
  tests/test_publisher.py \
  tests/test_pickup.py \
  tests/test_local_publisher.py
python3 -m unittest discover -s host -p 'test_windows_contract.py' -v
python3 -m unittest discover -s tests -p 'test_*.py' -v
