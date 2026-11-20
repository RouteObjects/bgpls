#!/usr/bin/env bash
# Shared by the lab workflows; source this file rather than executing it.

BGPLS_EXAMPLE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
BGPLS_REPOSITORY=$(cd -- "$BGPLS_EXAMPLE_DIR/../.." && pwd -P)
BGPLS_CEOS_IMAGE=ceosarm:4.36.2F

bgpls_fail() {
    printf 'bgpls-lab: %s\n' "$*" >&2
    return 1
}

bgpls_set_profile() {
    case "$1" in
        frr)
            BGPLS_NODES=(rr1 rr2 p1 p2 edge-frr bgpls-relay)
            BGPLS_PORTS=(11790)
            BGPLS_SOURCE_TOPOLOGY="$BGPLS_EXAMPLE_DIR/bgpls.clab.yml"
            BGPLS_DEPLOY_TIMEOUT=2m
            ;;
        ceos)
            BGPLS_NODES=(rr1 rr2 p1 p2 edge-frr edge-ceos bgpls-relay)
            BGPLS_PORTS=(11790 11791)
            BGPLS_SOURCE_TOPOLOGY="$BGPLS_EXAMPLE_DIR/bgpls-ceos.clab.yml"
            #  cEOS boots systemd and EOS agents, unlike the FRR process.
            BGPLS_DEPLOY_TIMEOUT=5m
            ;;
        *) bgpls_fail "Unknown lab profile: $1"; return 1 ;;
    esac
    BGPLS_PROFILE=$1
}

bgpls_set_profile frr
BGPLS_TRANSPORT=ipv4
BGPLS_ASN=65001

bgpls_is_node() {
    local candidate
    for candidate in "${BGPLS_NODES[@]}"; do
        [[ $1 != "$candidate" ]] || return 0
    done
    return 1
}

bgpls_runtime() {
    if [[ $(uname -s) == Darwin ]]; then
        orb -m "${CLAB_MACHINE:-clab}" -u root "$@"
    else
        "$@"
    fi
}

bgpls_docker() {
    bgpls_runtime docker "$@"
}

bgpls_containerlab() {
    #  Docker is not silently switched to another daemon or run with sudo.
    # Only native Linux Containerlab needs privilege elevation for virtual links.
    if [[ $(uname -s) != Darwin && $(id -u) != 0 ]]; then
        sudo env -u CLAB_LABDIR_BASE containerlab "$@"
    else
        bgpls_runtime env -u CLAB_LABDIR_BASE containerlab "$@"
    fi
}

bgpls_hash() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        sha256sum "$1" | awk '{print $1}'
    fi
}

bgpls_init_state() {
    local requested=${1:-${BGPLS_LAB_STATE:-}}
    [[ $requested == /* ]] || bgpls_fail 'Supply an absolute state directory (or BGPLS_LAB_STATE).' || return
    [[ $requested != *$'\n'* && $requested != *$'\r'* ]] || bgpls_fail 'The state path must not contain line breaks.' || return
    [[ ! -L $requested ]] || bgpls_fail 'The state directory must not be a symbolic link.' || return
    if [[ -d $requested ]]; then
        BGPLS_STATE=$(cd -- "$requested" && pwd -P)
    else
        [[ ! -e $requested ]] || bgpls_fail 'The state path is not a directory.' || return
        local parent
        parent=$(cd -- "$(dirname -- "$requested")" && pwd -P) || return
        BGPLS_STATE="$parent/$(basename -- "$requested")"
    fi
    case "$BGPLS_STATE" in
        /|"$HOME"|"$BGPLS_REPOSITORY"|"$BGPLS_REPOSITORY"/*)
            bgpls_fail 'Use a dedicated state directory outside the repository and home-directory root.'
            return 1
            ;;
    esac
    BGPLS_TOPOLOGY="$BGPLS_STATE/bgpls.clab.yml"
    export BGPLS_STATE BGPLS_TOPOLOGY
}

bgpls_check_runtime() {
    if [[ $(uname -s) == Darwin ]]; then
        command -v orb >/dev/null || bgpls_fail 'OrbStack orb is required on macOS.' || return
    elif [[ $(uname -s) != Linux ]]; then
        bgpls_fail 'This lab requires Linux or macOS with an OrbStack Linux machine.'
        return 1
    fi
    # Containerlab's direct Docker API and the Docker CLI must select the same
    # local daemon. A remote/rootless CLI context is not this host-network lab.
    bgpls_runtime sh -c 'test -z "${DOCKER_HOST:-}" && test -z "${DOCKER_CONTEXT:-}"' ||
        bgpls_fail 'Unset Docker endpoint/context environment overrides on the Linux lab host.' || return
    local docker_endpoint
    docker_endpoint=$(bgpls_docker context inspect --format '{{.Endpoints.docker.Host}}') || return
    [[ $docker_endpoint == unix:///var/run/docker.sock ]] ||
        bgpls_fail 'Select the local /var/run/docker.sock daemon on the Linux lab host.' || return
    BGPLS_DAEMON_ID=$(bgpls_docker info --format '{{.ID}}') || return
    [[ -n $BGPLS_DAEMON_ID ]] || bgpls_fail 'Docker did not report its daemon identity.' || return
    bgpls_runtime containerlab version >/dev/null || return
    bgpls_runtime test -d "$BGPLS_STATE" || {
        # A fresh directory can be created later, but its parent must be shared.
        bgpls_runtime test -d "$(dirname -- "$BGPLS_STATE")"
    }
}

bgpls_require_deploy_version() {
    # Native FRR requires the vtysh startup fix released in 0.83.0 (PR #3555).
    # Gate only new deployments: old Linux-kind state must remain inspectable
    # and removable with its original runtime, including Containerlab 0.79.0.
    local version major minor
    version=$(bgpls_containerlab version --short) || {
        bgpls_fail 'Unable to read Containerlab version; new deployments require stable 0.83.0 or newer.'
        return 1
    }
    # Bound numeric components before Bash arithmetic; reject prerelease,
    # development, decorated, and malformed output instead of guessing.
    [[ $version =~ ^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$ ]] ||
        bgpls_fail "Unrecognized stable Containerlab version: $version; require 0.83.0 or newer." || return
    major=${BASH_REMATCH[1]}
    minor=${BASH_REMATCH[2]}
    ((major > 0 || minor >= 83)) ||
        bgpls_fail "Containerlab $version is too old; new deployments require 0.83.0 or newer." || return
}

bgpls_validate_state() {
    #  Python and shell use one strict parser, including the complete
    # generated-config inventory for v3/v4. Legacy v1-v3 retain ASN 65001.
    local identity recorded_profile recorded_daemon
    identity=$(python3 "$BGPLS_EXAMPLE_DIR/lab-state.py" read --state "$BGPLS_STATE") || return
    {
        IFS= read -r recorded_profile
        IFS= read -r BGPLS_TRANSPORT
        IFS= read -r recorded_daemon
        IFS= read -r BGPLS_ASN
    } <<< "$identity"
    bgpls_set_profile "$recorded_profile" || return
    bgpls_check_runtime || return
    [[ $recorded_daemon == "$BGPLS_DAEMON_ID" ]] ||
        bgpls_fail 'This is not the Docker daemon that deployed the lab.' || return
}

bgpls_assert_no_namespace_holders() {
    #  Inspect all containers, not just lab labels: a manually started
    # namespace-sharing collector is also an owner that destroy must respect.
    python3 "$BGPLS_EXAMPLE_DIR/lab-state.py" guard --state "$BGPLS_STATE" -- \
        bash -c 'source "$1"; shift; bgpls_docker "$@"' bgpls-state "$BGPLS_EXAMPLE_DIR/common.sh"
}

bgpls_require_container() {
    local node=$1 labels
    bgpls_is_node "$node" || bgpls_fail "Not a $BGPLS_PROFILE lab node: $node" || return
    labels=$(bgpls_docker inspect "clab-bgpls-$node" --format \
        '{{index .Config.Labels "containerlab"}}|{{index .Config.Labels "clab-topo-file"}}') || return
    [[ $labels == "bgpls|$BGPLS_TOPOLOGY" ]] ||
        bgpls_fail "Container clab-bgpls-$node does not belong to this state directory." || return
}

bgpls_validate_containers() {
    local node container_names container_name
    for node in "${BGPLS_NODES[@]}"; do
        if bgpls_docker inspect "clab-bgpls-$node" >/dev/null 2>&1; then
            bgpls_require_container "$node" || return
        fi
    done
    #  Containerlab may select by lab label while destroying. Reject
    # additional labeled nodes even when their topology label looks correct.
    container_names=$(bgpls_docker ps -a --filter label=containerlab=bgpls --format '{{.Names}}') || return
    while IFS= read -r container_name; do
        [[ -n $container_name ]] || continue
        [[ $container_name == clab-bgpls-* ]] && bgpls_is_node "${container_name#clab-bgpls-}" ||
            bgpls_fail "Unexpected container in bgpls lab: $container_name" || return
    done <<< "$container_names"
}

bgpls_require_ceos_image() {
    #  The vendor archive is user-supplied. Never fetch or redistribute
    # it, and never silently emulate an x86 image in this native ARM64 profile.
    local platform image_details
    platform=$(bgpls_docker info --format '{{.Architecture}}') || return
    case "$platform" in arm64|aarch64) ;;
        *) bgpls_fail 'The cEOS profile requires a native ARM64 Docker host.'; return 1 ;;
    esac
    image_details=$(bgpls_docker image inspect "$BGPLS_CEOS_IMAGE" --format '{{.Id}}|{{.Os}}|{{.Architecture}}') ||
        bgpls_fail "Import your cEOS ARM64 archive as $BGPLS_CEOS_IMAGE before deploying; no image will be downloaded." || return
    [[ $image_details =~ ^sha256:[0-9a-f]{64}\|linux\|arm64$ ]] ||
        bgpls_fail "$BGPLS_CEOS_IMAGE must be an imported linux/arm64 image." || return
    BGPLS_CEOS_IMAGE_ID=${image_details%%|*}
}

bgpls_verify_ceos_image() {
    local actual_image
    actual_image=$(bgpls_docker inspect clab-bgpls-edge-ceos --format '{{.Config.Image}}|{{.Image}}') || return
    [[ $actual_image == "$BGPLS_CEOS_IMAGE|$BGPLS_CEOS_IMAGE_ID" ]] ||
        bgpls_fail 'The deployed cEOS container does not use the image qualified before deployment.' || return
}

bgpls_require_no_collisions() {
    local containers node networks
    containers=$(bgpls_docker ps -aq --filter label=containerlab=bgpls) || return
    [[ -z $containers ]] || bgpls_fail 'A bgpls lab already exists on this Docker daemon.' || return
    for node in "${BGPLS_NODES[@]}"; do
        if bgpls_docker inspect "clab-bgpls-$node" >/dev/null 2>&1; then
            bgpls_fail "Container name already exists: clab-bgpls-$node"
            return 1
        fi
    done
    networks=$(bgpls_docker network ls --format '{{.Name}}') || return
    if printf '%s\n' "$networks" | grep -Fxq bgpls; then
        bgpls_fail 'A Docker network named bgpls already exists; do not reuse or remove it blindly.'
        return 1
    fi
    local port listeners
    for port in "${BGPLS_PORTS[@]}"; do
        if [[ $(uname -s) == Darwin ]] && lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
            bgpls_fail "TCP port $port is already listening on macOS."
            return 1
        fi
        listeners=$(bgpls_runtime ss -H -ltn "sport = :$port") || return
        [[ -z $listeners ]] || bgpls_fail "TCP port $port is already listening on the Linux lab host." || return
    done
}
