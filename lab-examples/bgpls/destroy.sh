#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/common.sh"

if [[ ${1:-} == --help ]]; then
    printf 'Usage: %s [absolute-state-directory]\nStops only this lab; retains configurations, logs, and captures.\n' "$0"
    exit 0
fi
[[ $# -le 1 ]] || bgpls_fail 'Too many arguments; use --help.'
bgpls_init_state "${1:-}"

#  Share the verifier's exclusive lifecycle claim. A stale or active
# lock is never broken, and the child cannot proceed with an unowned token.
if [[ -z ${BGPLS_LOCK_TOKEN:-} ]]; then
    exec python3 "$BGPLS_EXAMPLE_DIR/lab-state.py" locked --state "$BGPLS_STATE" -- \
        bash "$BGPLS_EXAMPLE_DIR/destroy.sh" "$BGPLS_STATE"
fi
python3 "$BGPLS_EXAMPLE_DIR/lab-state.py" assert-lock --state "$BGPLS_STATE" --token "$BGPLS_LOCK_TOKEN"
bgpls_validate_state

bgpls_validate_containers
bgpls_assert_no_namespace_holders

recorded_network=''
if current_network=$(bgpls_docker network inspect bgpls --format '{{.Id}}' 2>/dev/null); then
    [[ -f $BGPLS_STATE/.bgpls-network-id && ! -L $BGPLS_STATE/.bgpls-network-id ]] ||
        bgpls_fail 'No recorded network identity; leaving the lab untouched.'
    IFS= read -r recorded_network < "$BGPLS_STATE/.bgpls-network-id"
    [[ -n $recorded_network && $recorded_network == "$current_network" ]] ||
        bgpls_fail 'Network identity changed; leaving the lab untouched.'
fi

#  Keep the network during Containerlab cleanup; remove it ourselves only
# if its immutable ID matches this deployment. Never use --all or --cleanup.
bgpls_containerlab destroy --topo "$BGPLS_TOPOLOGY" --keep-mgmt-net --timeout 2m \
    2>&1 | tee -a "$BGPLS_STATE/destroy.log"
if current_network=$(bgpls_docker network inspect bgpls --format '{{.Id}}' 2>/dev/null); then
    [[ -n $recorded_network && $recorded_network == "$current_network" ]] ||
        bgpls_fail 'Network identity changed; leaving the bgpls network untouched.'
    bgpls_docker network rm "$recorded_network"
fi
printf 'bgpls-lab: removed only its containers and owned network. Artifacts retained: %s\n' "$BGPLS_STATE"
