# syntax=docker/dockerfile:1.7
#
# Statebound core image — multi-stage build producing a static, distroless
# binary suitable for Kubernetes and Docker Compose deployments.
#
# The build mirrors the canonical CI flow:
#   1. Sync policies/builtin/*.rego into internal/authz/bundle/ so the
#      go:embed directive in internal/authz can pick the rules up.
#   2. Sync schemas/openapi.yaml into internal/api/openapi.yaml so the
#      go:embed directive in internal/api can serve it from /openapi.yaml.
#   3. CGO_ENABLED=0 -trimpath build with -s -w and version metadata
#      injected via -ldflags.
# The final stage is gcr.io/distroless/static-debian12:nonroot which has
# no shell, package manager, or libc, so the attack surface is the
# statebound binary itself.

ARG GO_VERSION=1.25-alpine

FROM golang:${GO_VERSION} AS builder

WORKDIR /src

# Cache the dependency graph as its own layer so source-only edits do
# not invalidate the module download.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Sync the embed bundle from canonical sources before the build (mirrors
# the CI step + Makefile authz-sync-bundle target).
RUN cp policies/builtin/*.rego internal/authz/bundle/ \
 && cp schemas/openapi.yaml internal/api/openapi.yaml

ARG VERSION=v1.0.0
ARG COMMIT=docker
ARG BUILD_DATE=unknown

ENV CGO_ENABLED=0
RUN go build -trimpath \
    -ldflags="-s -w \
        -X 'statebound.dev/statebound/internal/cli.Version=${VERSION}' \
        -X 'statebound.dev/statebound/internal/cli.Commit=${COMMIT}' \
        -X 'statebound.dev/statebound/internal/cli.BuildDate=${BUILD_DATE}'" \
    -o /out/statebound ./cmd/statebound

# Distroless static gives us a CA bundle, /etc/passwd with a `nonroot`
# user, and nothing else. Statebound is a static binary so this is all
# we need.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="statebound"
LABEL org.opencontainers.image.description="Terminal-native, open-source desired-state authorization governance platform."
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/rupivbluegreen/statebound"

COPY --from=builder /out/statebound /usr/local/bin/statebound

USER nonroot:nonroot

ENV STATEBOUND_API_LISTEN=:8080
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/statebound"]
CMD ["api", "serve"]
