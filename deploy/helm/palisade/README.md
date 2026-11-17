# Palisade Helm chart

Runs Palisade as one pod with its SQLite database on a PersistentVolumeClaim.

## Install

```sh
helm install waf oci://ghcr.io/sinhaparth5/charts/palisade -n palisade --create-namespace
# or from the classic repository
helm repo add palisade https://sinhaparth5.github.io/palisade-waf
helm install waf palisade/palisade -n palisade --create-namespace
```

The chart version is the Palisade version, so `--version 3.4.0` installs
Palisade 3.4.0 and `helm upgrade waf <chart> --version <next>` upgrades both.
The examples below use `./deploy/helm/palisade` from a checkout; any of the
three works. `examples/production.yaml` is a starting point for production
(Ingress with TLS, your own DB key, NetworkPolicy, metrics); the other
examples cover the TLS setups.

Every `palisade` serve flag is set under `flags:` in `values.yaml`
(`--trusted-proxies` becomes `flags.trusted-proxies`). Anything else goes in
`extraArgs`.

### One replica

Palisade keeps its state in one SQLite file on a `ReadWriteOnce` volume, and
rate limits, autoban, the waiting room and the verdict cache in memory. Two
pods can't share either, so the chart always runs exactly one, with the
`Recreate` strategy: an upgrade stops the old pod before the new one starts,
so requests fail until the new pod is ready (the startup probe). Scale it with CPU instead of
replicas: with the full CRS on every request, a pod with 8 threads handled
about 2,600 requests a second in BENCHMARKS.md.
Running several replicas with shared config is palisade-pro.

## Secrets

Nothing secret goes in `values.yaml`; the chart only takes Secret names.

```sh
kubectl -n palisade create secret generic palisade-admin --from-literal=password='at-least-12-characters'
helm install waf ./deploy/helm/palisade -n palisade \
  --set admin.email=you@example.com --set admin.existingSecret=palisade-admin
```

- **DB key** (`--db-key-file`, seals TOTP secrets and webhook/email tokens):
  the chart creates `<release>-palisade-db-key` on first install, copies it
  forward on every upgrade and keeps it on uninstall. Back it up with the
  volume; without it those secrets can't be read. To bring your own, create a
  Secret with at least 32 bytes (`openssl rand -hex 32`) and set
  `dbKey.existingSecret`. Do that with Argo CD or `helm template`, which
  can't see the cluster and would render a new key each time.
- **First admin**: the `setup` init container creates `admin.email` as owner
  with the password from `admin.existingSecret`, only while the database has
  no admin. Changing the Secret later does nothing. Reset a password by hand:

  ```sh
  kubectl -n palisade exec -i deploy/waf-palisade -- /palisade setup --db /data/waf.db --admin-email you@example.com --reset-password
  ```
- **TLS certificate** (`tls.existingSecret`, a `kubernetes.io/tls` Secret):
  see [TLS](#tls).

## Client IP

IP rules, autoban, rate limits and the threat score key on the client's
address. Palisade has to see the real one, not the proxy or the node.

**LoadBalancer Service straight to Palisade.** Keep the source address with
`externalTrafficPolicy: Local`; without it the node rewrites it to its own:

```sh
helm upgrade waf ./deploy/helm/palisade --reuse-values \
  --set service.type=LoadBalancer --set service.externalTrafficPolicy=Local
```

**Behind an Ingress controller.** The controller's own Service needs
`externalTrafficPolicy: Local`, and Palisade has to trust the controller's
`X-Forwarded-For`. Pod IPs change, so trust the cluster's pod CIDR:

```sh
kubectl get nodes -o jsonpath='{.items[*].spec.podCIDR}'   # one range per node
gcloud container clusters describe <cluster> --format='value(clusterIpv4Cidr)'   # GKE: the whole range

# ingress-nginx
helm install ingress-nginx ingress-nginx/ingress-nginx -n ingress-nginx --create-namespace \
  --set controller.service.externalTrafficPolicy=Local
# or Traefik
helm install traefik traefik/traefik -n traefik --create-namespace \
  --set service.spec.externalTrafficPolicy=Local

helm upgrade waf ./deploy/helm/palisade --reuse-values --set flags.trusted-proxies=10.0.0.0/14
kubectl -n palisade create ingress palisade --class=nginx --rule="/*=waf-palisade:80"   # or --class=traefik
```

Both controllers ignore an `X-Forwarded-For` from the client by default and
send the address they saw, so a client can't spoof it. Turning on
`use-forwarded-headers` (ingress-nginx) or `forwardedHeaders.insecure`
(Traefik) would let it, unless the controller only trusts the load balancer.
Any pod in the cluster can reach Palisade from a trusted address; use a
NetworkPolicy to limit that.

**PROXY protocol** isn't supported. A load balancer that only passes the
client address that way (DigitalOcean, Hetzner, AWS NLB with instance
targets) should send it to an Ingress controller, which reads it
(`use-proxy-protocol` in ingress-nginx, `proxyProtocol.trustedIPs` on a
Traefik entry point) and passes the address on in `X-Forwarded-For`.
Where the load balancer supports it, `externalTrafficPolicy: Local` without
PROXY protocol works too.

## Backends

Point a service's Backend (admin UI, Services) at the backend's Kubernetes
Service by its DNS name, `http://<service>.<namespace>.svc.cluster.local:<port>`,
e.g. `http://shop.shop.svc.cluster.local:8080`. The name stays the same
when pods are replaced, and kube-proxy spreads requests over the ready pods.
Shorter forms (`shop.shop`, `shop.shop.svc`) also resolve through the pod's
DNS search list; the full name doesn't depend on it. Don't use pod IPs: they
change with every restart. A ClusterIP works but changes if the Service is
recreated.

To have Palisade balance and health-check pods itself (Extra backends,
`least_conn`, Health path), make the Service headless (`clusterIP: None`)
and list each pod of a StatefulSet by name,
`http://<pod>.<service>.<namespace>.svc.cluster.local:<port>`. Behind a
Deployment, one ClusterIP Service is simpler.

With `networkPolicy.egress` set, allow the backends' namespaces
([NetworkPolicy](#networkpolicy)).

## Admin UI

By default the admin UI, its API and `/admin/metrics` listen only on
`admin.port` (9090, `--admin-listen`) behind the ClusterIP Service
`<release>-palisade-admin`. On the public Service, `/admin` goes through the
proxy pipeline like any other path, so it reaches a backend or a 404, never
the login page. Reach it with a port-forward, which needs nothing else open:

```sh
kubectl -n palisade port-forward svc/waf-palisade-admin 9090:9090
# then http://127.0.0.1:9090/admin
```

The admin port is plain HTTP. To use it from a browser without a
port-forward, give it its own Ingress, for example on an internal ingress
class, a host only reachable over the VPN, or behind an SSO proxy
(`admin.ingress`, routes only `/admin`). Over that Ingress, the controller's
`X-Forwarded-Proto` keeps the session cookies `Secure`, and
`flags.trusted-proxies` lets the login throttle and `admin.allow` see the
real client IP ([Client IP](#client-ip)). `admin.allow` (`--admin-allow`)
then limits who may use it by IP. `admin.port: 0` puts the admin UI back on
the public port.

### NetworkPolicy

`networkPolicy.enabled` adds one NetworkPolicy for the pod. It needs a CNI
that enforces it (GKE Dataplane V2, Calico, Cilium):

```yaml
networkPolicy:
  enabled: true
  # The public ports only from the ingress controller (empty: anyone; a
  # LoadBalancer Service needs that)
  publicFrom:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: ingress-nginx}}
  # The admin port only from the internal ingress controller (empty: nobody)
  adminFrom:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: ingress-internal}}
  # Outbound only to DNS, the backends' namespace and Let's Encrypt (empty: anywhere)
  egress:
    - to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: shop}}}]
    - to: [{ipBlock: {cidr: 0.0.0.0/0, except: [10.0.0.0/8, 169.254.0.0/16]}}]
      ports: [{port: 443}]
```

`kubectl port-forward` isn't subject to it, so the admin UI stays reachable
that way with `adminFrom` empty. Restricting egress, remember everything
Palisade calls out to: the backends, Let's Encrypt, `api.pwnedpasswords.com`
(password checks), webhooks, the email API, JWKS URLs and threat feeds.

## TLS

Pick one of three setups. Each has a values file in `examples/`.

|                          | 1. Ingress terminates | 2. Palisade, built-in ACME | 3. Palisade, cert-manager Secret |
|--------------------------|-----------------------|----------------------------|----------------------------------|
| Values                   | `tls-ingress.yaml`    | `tls-acme.yaml`            | `tls-cert-manager.yaml`          |
| Service                  | ClusterIP + Ingress   | LoadBalancer               | LoadBalancer                     |
| JA4 fingerprints         | no                    | yes                        | yes                              |
| HTTP/3                   | no                    | yes (`tls.http3`)          | yes (`tls.http3`)                |
| Per-service mTLS         | no                    | yes                        | yes                              |
| ACME and uploaded certs from the admin UI | no   | yes                        | yes                              |

**1. The Ingress terminates TLS.** cert-manager issues the certificate for
the Ingress (`ingress.annotations`), and the controller sends plain HTTP to
Palisade. Palisade never sees the TLS handshake, so it loses everything that
comes from it: JA4 fingerprints (and the JA4 reputation built on them),
HTTP/3, per-service client certificates (mTLS), and certificates managed in
the admin UI. It still learns that the client used HTTPS from the
controller's `X-Forwarded-Proto`, so session and hardened service cookies
keep the `Secure` flag. Set `flags.trusted-proxies` as in
[Client IP](#client-ip). The chart refuses `ingress.enabled` together with
Palisade's own TLS: plain HTTP would only redirect, in a loop.

**2. Palisade terminates TLS with its built-in ACME.** The `setup` init
container stores `tls.acme.domain` as the primary domain, with the contact
address, on every start. Other services get certificates by turning on ACME
in the admin UI. Let's Encrypt checks the HTTP-01 challenge on port 80 of
the Service (the container's 8080), so keep that port reachable from the
internet, `loadBalancerSourceRanges` included, or issuing and renewing fail.
Certificates are cached in `/data/certs` on the volume, so a restart doesn't
issue new ones (Let's Encrypt rate-limits that).

**3. Palisade terminates TLS with a cert-manager certificate.** Point
`tls.existingSecret` at the Certificate's Secret. Palisade serves it for
every name that has no ACME or uploaded certificate. When cert-manager
renews it, the kubelet updates the mounted files (within about a minute) and
Palisade rereads them at the next check (within another minute), with no
restart. Don't remount the Secret with `subPath` in `extraVolumeMounts`:
those mounts never update. Palisade is the edge here, so cert-manager's
HTTP-01 solver, which routes the challenge through an Ingress, can't answer;
use a DNS-01 issuer.

In setups 2 and 3, plain HTTP only redirects to HTTPS and answers ACME, and
the probes switch to HTTPS. Without `tls.existingSecret`, an init container
makes a self-signed certificate at every start for clients that send no
server name, such as the kubelet's probes or someone browsing by IP.

**HTTP/3** (`tls.http3: true`) adds a UDP port to the Service with the same
number as the HTTPS port and advertises it to browsers in `Alt-Svc`
(`--h3-advertise-port`). Services opt in in the admin UI. The load balancer
has to carry UDP and TCP on one IP. On GKE that needs the backend
service-based load balancer (`service.annotations`:
`cloud.google.com/l4-rbs: enabled`, set when the Service is created);
the default one refuses the Service with "mixed protocol is not supported".

## Varnish

`varnish.enabled: true` runs varnishd (the official `varnish` image) as a
sidecar for the per-service Cache. Containers in a pod share the loopback
interface, so nothing changes in Palisade: varnishd listens on
`127.0.0.1:6081` and fetches misses from Palisade's cache-return listener on
`127.0.0.1:6082`, both unreachable from outside the pod. The VCL is
`files/default.vcl`, a copy of `deploy/varnish/default.vcl`, with the same
raised header limits as `install.sh`. Then, in the admin UI, turn on
Settings → Varnish Cache and Cache on each service.

`varnish.size` is the cache memory (`-s malloc`). Raise
`varnish.resources.limits.memory` with it: the default 512Mi fits the default
256m plus varnishd itself. The sidecar runs as the image's `varnish` user
with a read-only root filesystem.

Varnish failing never takes the site down: while varnishd is starting or
has stopped, Palisade serves cached services straight from the backend and
logs the cache status as `ERROR`. A crashed varnishd is restarted inside the
container, so the pod stays Ready meanwhile. The cache is in memory and
starts empty with every pod.

The Services page's "Cache performance" card needs `varnishstat`, which the
Palisade image doesn't have, so it shows an error; the per-service hit
ratio from the request log works. For Varnish's own counters:

```sh
kubectl -n palisade exec deploy/waf-palisade -c varnish -- varnishstat -1 -f MAIN.cache_hit -f MAIN.cache_miss
```

## Metrics

With the [kube-prometheus-stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack)
(Prometheus Operator and Grafana) in the cluster, the chart can add a
ServiceMonitor, a Grafana dashboard and alerts. Prometheus scrapes
`/admin/api/v1/metrics` on the admin port with an API key:

1. In the admin UI, Settings → API keys, create a read-only key.
2. Store it in the release namespace:

   ```sh
   kubectl -n palisade create secret generic palisade-metrics --from-literal=token=cwaf_...
   ```

3. Turn it on (`release` is the label kube-prometheus-stack selects
   ServiceMonitors and rules by: its own release name):

   ```yaml
   metrics:
     serviceMonitor:
       enabled: true
       existingSecret: palisade-metrics
       labels: {release: kube-prometheus-stack}
     dashboard:
       enabled: true
     prometheusRule:
       enabled: true
       labels: {release: kube-prometheus-stack}
   ```

A replaced key in the Secret reaches Prometheus within a few minutes,
when the operator next syncs it; no restart needed.

The dashboard (`files/grafana-dashboard.json`) shows traffic, blocks by
stage, latency per pipeline stage, the WAF verdict cache, body inspection,
the request log queue, backend health and Varnish results. Its ConfigMap
carries `grafana_dashboard: "1"`, which Grafana's dashboard sidecar picks
up; if the sidecar only watches its own namespace, set
`metrics.dashboard.namespace` to it. Without the sidecar, import the JSON
file in Grafana (Dashboards → New → Import).

The alerts: `PalisadeDown` (no successful scrape for 5 minutes, which also
catches a wrong key), `PalisadeBlockRateHigh` (more than `blockRatio` of
requests blocked or rate limited for 10 minutes, at over `minRate`
requests per second) and `PalisadeBackendDown` (a backend out of rotation
for 5 minutes).

With `networkPolicy.enabled`, add Prometheus's namespace to `adminFrom`;
with `admin.allow`, add the pod CIDR Prometheus runs in.

## Access log

```yaml
accessLog:
  stdout: true
```

Every request is written to stdout as one nginx combined line, so `kubectl logs` and a node agent (Fluent Bit, Promtail, Vector) pick it up. Nothing is rotated or written under `/data`. Server messages go to stderr and start with a date instead of a client IP, so a shipper can tell them apart by stream or format:

```
203.0.113.7 - - [17/Nov/2026:10:04:12 +0000] "GET /?q=x HTTP/1.1" 403 - "-" "curl/8.11.1"
2026/11/17 10:04:15 palisade listening on [::]:8080 (plain HTTP, waf=true, apps=1)
```

`kubectl logs` merges both; read only the access lines with `kubectl logs deploy/<release>-palisade -c palisade | grep -v '^[0-9]\{4\}/'`.

## GitOps

Keep services and rules in Git (Argo CD, Flux) as a `palisade config export` file. An init container imports it before the server starts.

```sh
palisade config export --db waf.db --db-key-file db.key > config.json
kubectl -n palisade create secret generic palisade-config --from-file=config.json
```

```yaml
config:
  existingSecret: palisade-config   # or existingConfigMap
  mode: seed
```

- **`seed`** (default): imports only into a database with no configuration, so a new install starts from the file and later changes made in the admin UI survive upgrades. Once the database has config the import is skipped (`config import: skipped` in the init container's log).
- **`replace`**: empties the config tables and imports the file at every pod start, so Git is the only source and UI edits last until the next restart. A changed Secret or ConfigMap doesn't restart the pod by itself: bump a `podAnnotations` value with it, or use a tool that restarts on change.

The file covers settings (`meta`), admin users and SSO identities, API keys, services with every per-service tab (OpenAPI, mTLS, MCP, JWT, rate rules, backend CA, maintenance, CSP, cookies, request policy), certificate records, IP and geo rules, WAF rule exceptions and custom rules, threat intel sources, the webhook and threat scores. It never holds request logs, the audit log, sessions or passkeys. Users that the file gives a different id lose their sessions and passkeys on a `replace` import. Uploaded certificate files live under `/data/certs`, not in the file; upload them again or use `tls.existingSecret`.

An export made with `--db-key-file` keeps its secrets (TOTP, webhook and email tokens, the challenge secret) sealed under that key, so the release must use the same key: put it in the Secret named by `dbKey.existingSecret`. The import refuses a sealed file with a different key and changes nothing. Without a key file the export leaves secrets out, and TOTP users enroll again.

The setup init container runs after the import and creates `admin.email` only when the file brought no admin.

## Your data

Everything Palisade stores lives in `/data` on the PVC `<release>-palisade-data`:

- **Pod restart, `helm upgrade`, `helm rollback`**: the pod is replaced, the
  PVC is not. `strategy: Recreate` stops the old pod before the new one
  mounts the volume.
- **`helm uninstall`**: the PVC is kept (`helm.sh/resource-policy: keep`).
  `helm install` with the same release name and namespace picks it up again.
  Under a different name, point the new release at it with
  `persistence.existingClaim=<old release>-palisade-data`.
- **Deleting it on purpose**: `kubectl delete pvc <release>-palisade-data`.

### Backups

Before the server starts, an init container runs
`palisade backup --dir /data/backups --keep 5`. It copies `waf.db` to
`/data/backups/waf-<UTC time>.db` and removes the oldest copies beyond
`backup.keep`. This runs on every pod start, so every upgrade leaves a copy
of the database as the previous version left it, taken before the new
version migrates the schema. Turn it off with `backup.enabled=false`.

For a copy outside the cluster:

```sh
kubectl -n palisade exec deploy/waf-palisade -- /palisade backup --db /data/waf.db --out /data/manual.db
kubectl -n palisade exec deploy/waf-palisade -- /palisade config export --db /data/waf.db --db-key-file /etc/palisade/key/db.key > palisade-config.json
```

The image has no shell, so `kubectl cp` doesn't work against it. `config
export` writes to stdout and needs no shell. It holds the configuration
(services, rules, users, keys) but not the request logs, with secrets sealed
under the DB key. The chart always runs with a key, and `config export`
without it fails.

### Restoring a backup

```sh
kubectl -n palisade scale deploy/waf-palisade --replicas 0
kubectl -n palisade run restore --rm -i --restart Never --image busybox:1.37 \
  --overrides '{"spec":{"securityContext":{"runAsUser":65532,"runAsGroup":65532},
    "volumes":[{"name":"d","persistentVolumeClaim":{"claimName":"waf-palisade-data"}}],
    "containers":[{"name":"restore","image":"busybox:1.37","stdin":true,
    "command":["sh","-c","ls -l /data/backups && cp /data/backups/$0 /data/waf.db && rm -f /data/waf.db-wal /data/waf.db-shm","waf-20260101T000000Z.db"],
    "volumeMounts":[{"name":"d","mountPath":"/data"}]}]}}'
kubectl -n palisade scale deploy/waf-palisade --replicas 1
```

If you are going back to the version the backup came from, `helm rollback`
first, so the older binary doesn't open a database migrated by the newer one.

### Moving to another cluster

```sh
# old cluster (secrets stay sealed under the DB key)
kubectl -n palisade exec deploy/waf-palisade -- /palisade config export --db /data/waf.db --db-key-file /etc/palisade/key/db.key > palisade-config.json
kubectl -n palisade get secret waf-palisade-db-key -o yaml > db-key.yaml
# new cluster: create the key first so the chart reuses it, then helm install
kubectl -n palisade apply -f db-key.yaml
kubectl -n palisade exec -i deploy/waf-palisade -- /palisade config import --db /data/waf.db --db-key-file /etc/palisade/key/db.key --replace /dev/stdin < palisade-config.json
kubectl -n palisade rollout restart deploy/waf-palisade
```

### Migrating from Docker or the systemd install

Copy the database and, if there is one, the DB key onto the new release.

```sh
# 1. A consistent copy of the database; safe while the old server runs.
sudo palisade backup --db /var/lib/palisade/waf.db --out waf.db                       # systemd
docker exec palisade /palisade backup --db /data/waf.db --out /data/migrate.db \
  && docker cp palisade:/data/migrate.db waf.db                                      # Docker

# 2. The old key, so sealed secrets (TOTP, webhook and email tokens) still open.
#    systemd always has one at /etc/palisade/db.key; Docker only with --db-key-file.
kubectl create namespace palisade
kubectl -n palisade create secret generic palisade-db-key --from-file=db.key=/etc/palisade/db.key

# 3. Install with that key, stop the pod and copy the files onto the volume.
helm install waf oci://ghcr.io/sinhaparth5/charts/palisade -n palisade \
  --set dbKey.existingSecret=palisade-db-key --wait
kubectl -n palisade scale deploy/waf-palisade --replicas 0
kubectl -n palisade run copy --restart Never --image busybox:1.37 \
  --overrides '{"spec":{"securityContext":{"runAsUser":65532,"runAsGroup":65532},
    "volumes":[{"name":"d","persistentVolumeClaim":{"claimName":"waf-palisade-data"}}],
    "containers":[{"name":"copy","image":"busybox:1.37","command":["sleep","600"],
    "volumeMounts":[{"name":"d","mountPath":"/data"}]}]}}'
kubectl -n palisade wait --for condition=Ready pod/copy
kubectl -n palisade cp waf.db copy:/data/waf.db
kubectl -n palisade cp /var/lib/palisade/certs copy:/data/certs    # systemd, if you uploaded certificates
kubectl -n palisade exec copy -- rm -f /data/waf.db-wal /data/waf.db-shm
kubectl -n palisade delete pod copy
kubectl -n palisade scale deploy/waf-palisade --replicas 1
```

Without a key on the old install, skip step 2 and leave `dbKey` alone: the
chart creates a key and seals the secrets with it on first start. Users,
services, rules and the request log all come across. Certificates uploaded
in the admin UI are found again under `/data/certs` when that directory is
copied; ACME certificates are issued again if it isn't. Point DNS (or the
load balancer) at the new Service once the admin UI shows your services, and
set `flags.trusted-proxies` for the new setup ([Client IP](#client-ip)).
