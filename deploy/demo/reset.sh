#!/bin/sh
# Nightly wipe of the public demo, e.g. cron: 0 3 * * * /path/to/deploy/demo/reset.sh
set -eu
cd "$(dirname "$0")"
docker compose down -v
docker compose up -d
