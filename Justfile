set shell := ["bash", "-cu"]
set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]

default: help

help:
    @just --list

setup:
    @./scripts/bootstrap.sh

build:
    @cargo build --workspace

build-release:
    @cargo build --workspace --release

run *ARGS:
    @cargo run --release --bin myownmesh -- {{ARGS}}

fmt:
    @cargo fmt --all

lint:
    @cargo clippy --workspace --all-targets -- -D warnings

test:
    @cargo test --workspace --no-fail-fast

check:
    @cargo fmt --all --check
    @cargo clippy --workspace --all-targets -- -D warnings
    @cargo test --workspace --no-fail-fast

release VERSION:
    @./scripts/bump-version.sh {{VERSION}}
    @git add -A
    @git commit -m "chore(release): {{VERSION}}"
    @git tag v{{VERSION}}
    @git push --follow-tags
