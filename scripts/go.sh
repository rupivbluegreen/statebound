#!/usr/bin/env bash
# scripts/go.sh — runs `go` inside an official golang Docker image so contributors
# without a local Go install can build, test, vet, and format. Used by the Makefile.
#
# Usage:
#   ./scripts/go.sh build ./...
#   ./scripts/go.sh test ./...
#   ./scripts/go.sh fmt ./...
#
# Override the image with STATEBOUND_GO_IMAGE if you need a different version.
set -euo pipefail

image="${STATEBOUND_GO_IMAGE:-golang:1.25-alpine}"
project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

exec docker run --rm \
  -v "${project_root}:/work" \
  -w /work \
  -u "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e GOCACHE=/tmp/.gocache \
  -e GOMODCACHE=/tmp/.gomodcache \
  -e GOFLAGS="-buildvcs=false" \
  "${image}" go "$@"
