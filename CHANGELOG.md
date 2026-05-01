# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.0] - 2026-05-01

### Added

- Go module skeleton (`go.mod` declared, no source code yet).
- Cobra CLI skeleton with `version` and `tui` subcommands.
- Bubble Tea placeholder TUI.
- PostgreSQL `docker-compose` for local development.
- Initial database migration creating `products` and `audit_events`.
- Storage interface with a Postgres implementation skeleton (`pgx`).
- Makefile with `dev`, `test`, `fmt`, `lint`, `migrate-up`,
  `migrate-down`, `run-api`, `run-tui`, `policy-test`, `docker-up`,
  `docker-down` targets.
- README quickstart.
- ADR 0001: reasoning is an add-on, not a dependency.
- ADR 0002: product name "Statebound" adopted as the working name
  pending formal trademark clearance.
