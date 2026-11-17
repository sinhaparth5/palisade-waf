# Palisade Helm chart

Runs Palisade as one pod with its SQLite database on a PersistentVolumeClaim.

```sh
helm install waf ./deploy/helm/palisade -n palisade --create-namespace
```

Every `palisade` serve flag is set under `flags:` in `values.yaml`
(`--trusted-proxies` becomes `flags.trusted-proxies`). Anything else goes in
`extraArgs`.

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

**2. Palisade terminates TLS with its built-in ACME.** `tls.acme.domain` is
the admin UI's domain; the `setup` init container stores it with the contact
address on every start. Other services get certificates by turning on ACME
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
kubectl -n palisade exec deploy/waf-palisade -- /palisade config export --db /data/waf.db > palisade-config.json
```

The image has no shell, so `kubectl cp` doesn't work against it. `config
export` writes to stdout and needs no shell. It holds the configuration
(services, rules, users, keys) but not the request logs. Add
`--db-key-file` if you run with one, or sealed secrets can't be read.

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
