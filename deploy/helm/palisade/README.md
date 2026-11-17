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
kubectl -n palisade create secret tls palisade-tls --cert=tls.crt --key=tls.key   # optional
helm install waf ./deploy/helm/palisade -n palisade \
  --set admin.email=you@example.com --set admin.existingSecret=palisade-admin \
  --set tls.existingSecret=palisade-tls
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
- **TLS** (`tls.existingSecret`, a `kubernetes.io/tls` Secret): serves HTTPS
  on `tls.containerPort` (service port `service.httpsPort`) with that
  certificate as the fallback; per-service and ACME certificates still come
  from the admin UI. Plain HTTP then only redirects and answers ACME.

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
