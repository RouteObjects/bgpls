#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

bgpls_create_owned_network() {
    [[ ! -e $BGPLS_STATE/.bgpls-network-id && ! -L $BGPLS_STATE/.bgpls-network-id ]] ||
        bgpls_fail 'The deployment already recorded a management network.' || return
    #  Claim the name atomically through Docker creation. Inspection after
    # a failed create could mistake another actor's network for our own. The
    # returned immutable ID remains authoritative even if a later node fails.
    local network_id
    network_id=$(bgpls_docker network create --driver bridge --subnet 172.31.250.0/24 \
        --label "bgpls.example.state=$BGPLS_STATE" bgpls) || return
    [[ $network_id =~ ^[0-9a-f]{64}$ ]] ||
        bgpls_fail 'Docker did not return a valid network ID; no ownership was recorded.' || return
    printf '%s\n' "$network_id" > "$BGPLS_STATE/.bgpls-network-id"
}

bgpls_parse_deploy_args() {
    BGPLS_REQUESTED_STATE=''
    BGPLS_ASN=65001
    local seen_ceos=0 seen_ipv6=0 seen_state=0 seen_asn=0
    while (($#)); do
        case "$1" in
            --ceos)
                ((seen_ceos == 0)) || bgpls_fail 'Duplicate --ceos option.' || return
                seen_ceos=1
                bgpls_set_profile ceos
                ;;
            --ipv6-transport)
                ((seen_ipv6 == 0)) || bgpls_fail 'Duplicate --ipv6-transport option.' || return
                seen_ipv6=1
                BGPLS_TRANSPORT=ipv6
                ;;
            --asn)
                ((seen_asn == 0)) || bgpls_fail 'Duplicate --asn option.' || return
                (($# >= 2)) && [[ $2 != --* ]] || bgpls_fail 'Missing --asn value.' || return
                seen_asn=1
                #  Reject malformed/reserved ASNs before runtime checks;
                # the same parser validates rendering and recorded ownership.
                BGPLS_ASN=$(python3 "$BGPLS_EXAMPLE_DIR/lab-state.py" asn --asn "$2") || return
                shift
                ;;
            --*) bgpls_fail "Unknown deployment option: $1"; return 1 ;;
            *)
                ((seen_state == 0)) || bgpls_fail 'Too many state directories; use --help.' || return
                seen_state=1
                BGPLS_REQUESTED_STATE=$1
                ;;
        esac
        shift
    done
}

bgpls_copy_deployment() {
    #  Render only fresh deployment copies; committed IPv4 templates and
    # any previous deployment remain byte-for-byte untouched.
    if [[ -d $BGPLS_STATE ]]; then
        local existing
        existing=$(find "$BGPLS_STATE" -mindepth 1 -maxdepth 1 -print -quit)
        [[ -z $existing ]] || bgpls_fail 'Deployment requires a new or empty state directory.' || return
    else
        mkdir -- "$BGPLS_STATE" || return
    fi
    cp "$BGPLS_SOURCE_TOPOLOGY" "$BGPLS_TOPOLOGY" || return
    cp -R "$BGPLS_EXAMPLE_DIR/configs" "$BGPLS_STATE/configs" || return
    if [[ $BGPLS_TRANSPORT == ipv6 ]]; then
        python3 "$BGPLS_EXAMPLE_DIR/render-ipv6.py" --state "$BGPLS_STATE" --profile "$BGPLS_PROFILE" || return
    fi
    #  Render after IPv6 peers exist, then hash the final copied inventory.
    # Every new deployment uses v4; legacy markers are never rewritten.
    python3 "$BGPLS_EXAMPLE_DIR/render-asn.py" --state "$BGPLS_STATE" --profile "$BGPLS_PROFILE" \
        --transport "$BGPLS_TRANSPORT" --asn "$BGPLS_ASN" || return
    python3 "$BGPLS_EXAMPLE_DIR/lab-state.py" write --state "$BGPLS_STATE" \
        --profile "$BGPLS_PROFILE" --transport "$BGPLS_TRANSPORT" \
        --daemon-id "$BGPLS_DAEMON_ID" --asn "$BGPLS_ASN" || return
}

# Sourcing exposes only the acquisition helper for mock-only safety tests.
if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
    return 0
fi

if [[ ${1:-} == --help ]]; then
    printf 'Usage: %s [--ceos] [--ipv6-transport] [--asn ASN] [absolute-state-directory]\nSet BGPLS_LAB_STATE instead of the argument if preferred.\n' "$0"
    printf '%s\n' '--ceos adds the locally imported ceosarm:4.36.2F ARM64 second producer.'
    printf '%s\n' '--ipv6-transport adds direct IPv6 collector peers in copied configs; IPv4 relays remain available.'
    printf '%s\n' '--asn selects one lab-wide asplain ASN (default 65001; 0 and AS_TRANS 23456 are rejected).'
    exit 0
fi
bgpls_parse_deploy_args "$@"
bgpls_init_state "$BGPLS_REQUESTED_STATE"
bgpls_check_runtime
bgpls_require_deploy_version
bgpls_require_no_collisions
if [[ $BGPLS_PROFILE == ceos ]]; then
    bgpls_require_ceos_image
fi
[[ -f $BGPLS_SOURCE_TOPOLOGY && ! -L $BGPLS_SOURCE_TOPOLOGY ]] ||
    bgpls_fail 'The selected profile topology is missing or symlinked.'

bgpls_copy_deployment

bgpls_create_owned_network
# Containerlab reuses this explicitly owned management network by name.
bgpls_containerlab deploy --topo "$BGPLS_TOPOLOGY" --timeout "$BGPLS_DEPLOY_TIMEOUT" \
    2>&1 | tee "$BGPLS_STATE/deploy.log"

for node in "${BGPLS_NODES[@]}"; do
    bgpls_require_container "$node"
done
if [[ $BGPLS_PROFILE == ceos ]]; then
    bgpls_verify_ceos_image
fi

# The Unix stats socket does not open a BGP connection or disturb the peer.
ready=0
for ((attempt = 0; attempt < 30; attempt++)); do
    if bgpls_docker exec clab-bgpls-bgpls-relay sh -c \
        "printf 'show info\\n' | socat - UNIX-CONNECT:/tmp/haproxy.sock" \
        > "$BGPLS_STATE/relay-ready.txt" 2>/dev/null &&
        grep -q '^Name: HAProxy' "$BGPLS_STATE/relay-ready.txt"; then
        ready=1
        break
    fi
    sleep 1
done
[[ $ready -eq 1 ]] || bgpls_fail "Relay did not become ready; inspect $BGPLS_STATE/deploy.log and container logs."
printf 'bgpls-lab: deployed %s profile, %s transport, ASN %s; state: %s\n' "$BGPLS_PROFILE" "$BGPLS_TRANSPORT" "$BGPLS_ASN" "$BGPLS_STATE"
printf 'FRR relay: 127.0.0.1:11790\n'
if [[ $BGPLS_PROFILE == ceos ]]; then
    printf 'cEOS relay: 127.0.0.1:11791\n'
fi
if [[ $BGPLS_TRANSPORT == ipv6 ]]; then
    printf 'Direct IPv6: verify.sh STATE --transport ipv6 --artifact ABSOLUTE_MANIFEST\n'
    printf 'The existing IPv4 path remains available with verify.sh STATE ABSOLUTE_NATIVE_BINARY.\n'
else
    printf 'Run verify.sh with this state directory and your native bgpls binary.\n'
fi
