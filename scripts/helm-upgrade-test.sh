#!/usr/bin/env sh
#
# Upgrade test for the Helm chart (helm.yml): install the latest published
# chart, upgrade it to the chart in this checkout running IMAGE, and check
# the database survived (the admin account and a backup taken before the new
# version started). Needs a cluster in the current kube context.
#
#   IMAGE=palisade:ci scripts/helm-upgrade-test.sh

set -eu

CHART_REPO="${CHART_REPO:-oci://ghcr.io/sinhaparth5/charts/palisade}"
IMAGE="${IMAGE:?set IMAGE=repository:tag}"
NS=upgrade-test
EMAIL=admin@example.com

prev="$(helm show chart "$CHART_REPO" 2>/dev/null | awk '/^version:/ { print $2 }')" || true
if [ -z "$prev" ]; then
	echo "no published chart at $CHART_REPO yet; skipping the upgrade test"
	exit 0
fi
echo "upgrading from chart $prev"

kubectl create namespace "$NS"
kubectl -n "$NS" create secret generic palisade-admin --from-literal=password=upgrade-test-Pw-1234
admin="--set admin.email=$EMAIL --set admin.existingSecret=palisade-admin"
# shellcheck disable=SC2086 # $admin is a list of flags
helm install waf "$CHART_REPO" --version "$prev" -n "$NS" $admin --wait --timeout 8m
# shellcheck disable=SC2086
helm upgrade waf deploy/helm/palisade -n "$NS" $admin \
	--set image.repository="${IMAGE%:*}" --set image.tag="${IMAGE##*:}" --set image.pullPolicy=Never \
	--wait --timeout 8m

users="$(kubectl -n "$NS" exec deploy/waf-palisade -c palisade -- /palisade setup --db /data/waf.db --list-users)"
echo "$users"
echo "$users" | grep -q "$EMAIL" || { echo "admin account lost in the upgrade" >&2; exit 1; }
kubectl -n "$NS" logs deploy/waf-palisade -c backup | grep -q 'backup written to' ||
	{ echo "no backup before the upgrade" >&2; exit 1; }
echo "upgrade kept the database"
