# Statebound — top-level Makefile.
#
# Targets are documented in the project spec §25. All Go invocations go through
# scripts/go.sh, which runs `go` inside golang:1.23-alpine so contributors
# without a local Go install still get `make test` etc. The only direct
# host dependencies are docker, make, and a POSIX shell.
#
# Override the database DSN by exporting STATEBOUND_DB_DSN in your shell
# or by editing deploy/docker-compose/.env.
STATEBOUND_DB_DSN ?= postgres://statebound:statebound@localhost:5432/statebound?sslmode=disable

GO          := ./scripts/go.sh
COMPOSE     := docker compose -f deploy/docker-compose/docker-compose.yml

# Goose runs via `go run` inside the same golang container scripts/go.sh uses.
# This avoids depending on a separate goose Docker image whose registry path
# moves around (ghcr.io/pressly/goose has been gated for some users). Migrations
# live in /migrations relative to the repo root.
GOOSE_VERSION := v3.27.0
GOOSE_RUN := docker run --rm \
  -v $(CURDIR):/work -w /work \
  -u $(shell id -u):$(shell id -g) \
  -e HOME=/tmp -e GOCACHE=/tmp/.gocache -e GOMODCACHE=/tmp/.gomodcache \
  --network host \
  golang:1.25-alpine go run github.com/pressly/goose/v3/cmd/goose@$(GOOSE_VERSION)

.PHONY: help dev test fmt lint migrate-up migrate-down run-api run-tui \
        policy-test authz-sync-bundle docker-up docker-down build clean

help:
	@echo "Statebound development targets:"
	@echo ""
	@echo "  make dev           Bring up local Postgres (alias for docker-up)"
	@echo "  make test          Run Go test suite via scripts/go.sh"
	@echo "  make fmt           gofmt the tree via scripts/go.sh"
	@echo "  make lint          go vet via scripts/go.sh (real linter lands in Phase 8)"
	@echo "  make migrate-up    Apply Goose migrations against the running compose Postgres"
	@echo "  make migrate-down  Roll back the most recent migration"
	@echo "  make run-api       Phase 0: runs 'statebound version' (Phase 2+ swaps in 'api')"
	@echo "  make run-tui       Run the TUI via 'go run' (real TTY required, not Docker)"
	@echo "  make policy-test   Phase 0 stub for Rego unit tests (the project spec §15)"
	@echo "  make docker-up     Start local Postgres in docker-compose"
	@echo "  make docker-down   Stop and remove local Postgres"
	@echo "  make build         Build ./bin/statebound"
	@echo "  make clean         Remove build outputs"

# `dev` is the developer convenience target: bring the stack up. Add more
# steps here as later phases introduce auxiliary services.
dev: docker-up

test:
	$(GO) test -count=1 ./...

fmt:
	$(GO) fmt ./...

# Phase 0 ships `go vet` only. The full linter (golangci-lint with a curated
# rule set) arrives in Phase 8 alongside core hardening.
lint:
	$(GO) vet ./...

migrate-up:
	$(GOOSE_RUN) -dir migrations postgres "$(STATEBOUND_DB_DSN)" up

migrate-down:
	$(GOOSE_RUN) -dir migrations postgres "$(STATEBOUND_DB_DSN)" down

# Phase 0: there is no `api` subcommand yet, so this target invokes
# `version` to keep the demo green. Phase 2+ replaces this with
# `$(GO) run ./cmd/statebound api` once the HTTP server lands.
run-api:
	$(GO) run ./cmd/statebound version

# run-tui invokes the TUI; works only with `go run` against a real TTY,
# not via Docker. Building the binary with `make build` and running
# `./bin/statebound tui` from your terminal is the supported way to use
# the TUI for real. The target below is here for convenience and will
# fail under non-interactive Docker because Bubble Tea needs a TTY.
run-tui:
	$(GO) run ./cmd/statebound tui

# Runs the OPA tester library against `policies/builtin` (rules) and
# `policies/tests` (test files). The runner lives under `tools/opa-test/`
# so we don't drag the CLI's init wiring or DB connection into a Rego
# unit test loop. STATEBOUND_REGO_BUNDLE/TESTS env vars override the paths.
policy-test: authz-sync-bundle
	$(GO) run ./tools/opa-test

# authz-sync-bundle copies the authoritative Rego rule files from
# policies/builtin/ into internal/authz/bundle/, where Go's //go:embed
# directive picks them up. Embed forbids parent-relative paths, so we
# duplicate at build time. The bundle/ files are gitignored.
authz-sync-bundle:
	@cp policies/builtin/*.rego internal/authz/bundle/

docker-up:
	$(COMPOSE) up -d

docker-down:
	$(COMPOSE) down

# scripts/go.sh mounts the repo at /work inside the container, so the
# binary written to /work/bin/statebound shows up on the host as
# ./bin/statebound.
build: authz-sync-bundle
	$(GO) build -o /work/bin/statebound ./cmd/statebound

clean:
	rm -rf bin dist
