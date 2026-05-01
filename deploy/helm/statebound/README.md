# statebound Helm chart

This chart deploys the deterministic Statebound core (`statebound`
binary, v1.0) into a Kubernetes cluster.

The chart **does not bundle PostgreSQL**. Operators bring their own
PostgreSQL instance (RDS, CloudSQL, an in-cluster operator, etc.) and
wire it via `values.database`.

## Versioning

| Field        | Value   | Meaning                                           |
| ------------ | ------- | ------------------------------------------------- |
| `version`    | `0.1.0` | Helm chart semver. Bumped per chart change.       |
| `appVersion` | `1.0.0` | The `statebound` binary version this chart pins. |

The gap between chart `version` and `appVersion` is intentional: the
chart is brand-new at v1.0 of the binary, so chart-only fixes can ship
without re-releasing the binary.

## Quickstart (dev mode, in-cluster Postgres operator already running)

```bash
# Generate a dev token. This is a single-tenant bearer token with
# full operator privileges. NEVER use in production.
DEV_TOKEN=$(head -c 32 /dev/urandom | base64)

helm install statebound deploy/helm/statebound \
  --set api.devToken=$DEV_TOKEN \
  --set api.devActor=human:dev \
  --set database.dsn=postgres://statebound:statebound@my-postgres:5432/statebound?sslmode=require \
  --set signing.devSkip=true   # only acceptable in dev clusters

# Tail the logs while the migrations Job runs and the Deployment rolls.
kubectl logs -f -l app.kubernetes.io/name=statebound

# Exercise the API
kubectl port-forward svc/statebound 8080:8080
curl -fsS http://localhost:8080/healthz
curl -fsS -H "Authorization: Bearer $DEV_TOKEN" http://localhost:8080/v1/products
```

## Production install

```bash
helm install statebound deploy/helm/statebound \
  --namespace statebound --create-namespace \
  --values values-prod.yaml
```

`values-prod.yaml`:

```yaml
image:
  tag: "1.0.0"

api:
  oidc:
    issuer: https://login.example.com/realms/platform
    audience: statebound

database:
  host: pg-primary.db.svc.cluster.local
  database: statebound
  user: statebound
  sslmode: require
  passwordSecretRef:
    name: statebound-db
    key: password

signing:
  keyId: prod-2026-q1
  privateKeySecretRef:
    name: statebound-signing
    key: private_key.pem

telemetry:
  exporter: otlp-grpc
  endpoint: otel-collector.observability.svc:4317

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: statebound.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - hosts: [statebound.example.com]
      secretName: statebound-tls
```

The chart **fails to render** if neither `api.oidc.issuer` nor
`api.devToken` is set, and **fails to render** if `signing.devSkip=true`
and OIDC is configured (a cluster with real OIDC should not be quietly
shipping unsigned plans).

## Values

The full schema lives in [`values.yaml`](./values.yaml). Highlights:

| Key                                       | Default                                       | Notes                                                                       |
| ----------------------------------------- | --------------------------------------------- | --------------------------------------------------------------------------- |
| `image.repository`                        | `ghcr.io/rupivbluegreen/statebound`           | Multi-stage distroless image.                                               |
| `image.tag`                               | `""` (falls back to `appVersion` `1.0.0`)     |                                                                             |
| `api.oidc.issuer`                         | `""`                                          | Set this OR `api.devToken`.                                                 |
| `api.devToken`                            | `""`                                          | Local-only single-tenant bearer.                                            |
| `database.passwordSecretRef.name`         | `""`                                          | Required when `database.dsn` is empty.                                      |
| `signing.privateKeySecretRef.name`        | `""`                                          | Mounts the Ed25519 private key at `/etc/statebound/signing/private_key.pem`. |
| `signing.devSkip`                         | `false`                                       | Skip plan signing — DEV ONLY.                                               |
| `migrations.enabled`                      | `true`                                        | One-shot pre-install / pre-upgrade Job.                                     |
| `networkPolicy.enabled`                   | `true`                                        | Default-deny ingress to anything outside the namespace.                     |
| `containerSecurityContext.readOnlyRootFilesystem` | `true`                                | Distroless image needs nothing writable.                                    |

## Verifying

```bash
helm lint deploy/helm/statebound \
  --set api.devToken=local \
  --set database.host=localhost \
  --set signing.devSkip=true

helm template statebound deploy/helm/statebound \
  --set api.devToken=local \
  --set database.host=localhost \
  --set signing.devSkip=true \
  | kubectl --dry-run=client apply -f -

helm test statebound          # runs the curl-against-/healthz test pod
```

## Migrations gap (v0.1 chart only)

The `pre-install` migrations Job uses the upstream
`ghcr.io/pressly/goose:3.27.0-alpine` image. That image does **not**
contain Statebound's migrations on its own — operators must either:

1. Build a thin wrapper image based on `goose` that ADDs
   `migrations/` to `/migrations`, then set
   `migrations.image.repository`/`tag` to that image; or
2. Mount `migrations/` into the Job via a ConfigMap they pre-create
   (`kubectl create configmap statebound-migrations
   --from-file=migrations/`); the chart accepts an extraVolumes
   override on the Job in a future release.

Option (1) is the recommended path. Future chart versions will
publish a dedicated `statebound-migrations` image bundled with the
canonical migrations and remove this gap.

## Test harness

```bash
helm test statebound
```

The test pod `curlimages/curl` hits `/healthz` and `/readyz` against
the in-cluster Service. It does not authenticate to the API
(both endpoints are public).
