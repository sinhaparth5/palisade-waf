# Palisade Helm chart

Runs Palisade as one pod with its SQLite database on a PersistentVolumeClaim.

```sh
helm install waf ./deploy/helm/palisade -n palisade --create-namespace
```

Every `palisade` serve flag is set under `flags:` in `values.yaml`
(`--trusted-proxies` becomes `flags.trusted-proxies`). Anything else goes in
`extraArgs`.

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
# old cluster
kubectl -n palisade exec deploy/waf-palisade -- /palisade config export --db /data/waf.db > palisade-config.json
# new cluster, after helm install
kubectl -n palisade exec -i deploy/waf-palisade -- /palisade config import --db /data/waf.db --replace /dev/stdin < palisade-config.json
kubectl -n palisade rollout restart deploy/waf-palisade
```
