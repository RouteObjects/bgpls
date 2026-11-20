#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/common.sh"

if [[ ${1:-} == --help ]]; then
    printf 'Usage: %s absolute-state-directory [down|up|flap] [flap-seconds]\n' "$0"
    printf 'With BGPLS_LAB_STATE set, omit the state-directory argument. Default: flap for 15 seconds.\n'
    exit 0
fi
if [[ ${1:-} == /* ]]; then
    bgpls_init_state "$1"
    shift
else
    bgpls_init_state
fi
action=${1:-flap}
delay=${2:-15}
[[ $# -le 2 ]] || bgpls_fail 'Too many arguments; use --help.'
case "$action" in down|up|flap) ;; *) bgpls_fail 'Expected down, up, or flap.' ;; esac
[[ $delay =~ ^([1-9]|[1-5][0-9]|60)$ ]] ||
    bgpls_fail 'Flap duration must be an integer from 1 through 60 seconds.'
bgpls_validate_state
bgpls_require_container p1
bgpls_require_container p2

set_link() {
    local result=0
    bgpls_docker exec clab-bgpls-p1 ip link set dev eth3 "$1" || result=1
    bgpls_docker exec clab-bgpls-p2 ip link set dev eth3 "$1" || result=1
    return "$result"
}

if [[ $action == flap ]]; then
    #  This is a temporary data-plane flap, not a persistent FRR config
    # edit. Restore both ends even if verification or the caller is interrupted.
    restore() {
        local result=$?
        trap - EXIT INT TERM
        set_link up || result=1
        exit "$result"
    }
    trap restore EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    set_link down
    printf 'bgpls-lab: p1:eth3 <-> p2:eth3 down for %s seconds.\n' "$delay"
    sleep "$delay"
    set_link up
    trap - EXIT INT TERM
else
    set_link "$action"
fi
printf 'bgpls-lab: p1:eth3 <-> p2:eth3 %s.\n' "${action/flap/up}"
