#!/usr/bin/env bash
set -euo pipefail

example_dir=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
source "$example_dir/common.sh"

#  Guard tests substitute only runtime functions. They never contact
# Docker, Containerlab, OrbStack, a router, or a collector, even beside a live lab.
test_root=$(mktemp -d "${TMPDIR:-/tmp}/bgpls-workflow-tests.XXXXXX")
test_root=$(cd -- "$test_root" && pwd -P)
mkdir -- "$test_root/state"
cleanup() {
    local result=$?
    trap - EXIT INT TERM
    # Remove only the known test artifacts, not a recursive directory tree.
    rm -f -- "$test_root/state-link" "$test_root/state/bgpls.clab.yml" \
        "$test_root/state/.bgpls-lab-state" "$test_root/state/.bgpls-network-id" \
        "$test_root/state/destroy.log" "$test_root/mock-runtime.log" "$test_root/mock-output.log" \
        "$test_root/state/.bgpls-verification-lock/owner.json"
    if [[ -d $test_root/state/.bgpls-verification-lock ]]; then
        rmdir -- "$test_root/state/.bgpls-verification-lock"
    fi
    rmdir -- "$test_root/state" "$test_root"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

checks=0
expect_failure() {
    if "$@" >/dev/null 2>&1; then
        printf 'FAIL: unexpected success: %s\n' "$*" >&2
        exit 1
    fi
    checks=$((checks + 1))
}
expect_success() {
    if ! "$@" >/dev/null 2>&1; then
        printf 'FAIL: unexpected failure: %s\n' "$*" >&2
        exit 1
    fi
    checks=$((checks + 1))
}

expect_failure bgpls_init_state relative
expect_failure bgpls_init_state /
expect_failure bgpls_init_state "$HOME"
expect_failure bgpls_init_state "$BGPLS_REPOSITORY"
expect_failure bgpls_init_state "$BGPLS_REPOSITORY/generated"
expect_failure bgpls_init_state "$test_root/line"$'\n'"break"
ln -s "$test_root/state" "$test_root/state-link"
expect_failure bgpls_init_state "$test_root/state-link"
expect_success bgpls_init_state "$test_root/new-state"
expect_success bgpls_init_state "$test_root/state"
expect_success test "$BGPLS_STATE" = "$test_root/state"

bgpls_check_runtime() { BGPLS_DAEMON_ID=mock-daemon; }
expect_failure bgpls_validate_state
printf 'name: bgpls\n' > "$BGPLS_TOPOLOGY"
printf '%s\n' bgpls-frr-lab-v1 "$BGPLS_STATE" mock-daemon \
    "$(bgpls_hash "$BGPLS_TOPOLOGY")" > "$BGPLS_STATE/.bgpls-lab-state"
expect_success bgpls_validate_state

# The profile cannot be selected by an extra sidecar, unknown marker value, or
# appended line. Old four-line records remain the FRR profile.
expect_success test "$BGPLS_PROFILE" = frr
expect_success test "$BGPLS_ASN" = 65001
expect_failure bgpls_set_profile unknown
printf '%s\n' unknown-schema "$BGPLS_STATE" mock-daemon \
    "$(bgpls_hash "$BGPLS_TOPOLOGY")" > "$BGPLS_STATE/.bgpls-lab-state"
expect_failure bgpls_validate_state
printf '%s\n' bgpls-lab-v2 "$BGPLS_STATE" mock-daemon \
    "$(bgpls_hash "$BGPLS_TOPOLOGY")" > "$BGPLS_STATE/.bgpls-lab-state"
expect_failure bgpls_validate_state
printf '%s\n' bgpls-lab-v2 "$BGPLS_STATE" mock-daemon \
    "$(bgpls_hash "$BGPLS_TOPOLOGY")" unknown > "$BGPLS_STATE/.bgpls-lab-state"
expect_failure bgpls_validate_state
printf '%s\n' bgpls-lab-v2 "$BGPLS_STATE" mock-daemon \
    "$(bgpls_hash "$BGPLS_TOPOLOGY")" ceos > "$BGPLS_STATE/.bgpls-lab-state"
expect_success bgpls_validate_state
expect_success test "$BGPLS_PROFILE" = ceos
expect_success test "${#BGPLS_NODES[@]}" = 7
expect_success test "${BGPLS_PORTS[*]}" = '11790 11791'
expect_success test "$BGPLS_DEPLOY_TIMEOUT" = 5m
printf 'ceos\n' >> "$BGPLS_STATE/.bgpls-lab-state"
expect_failure bgpls_validate_state
printf '%s\n' bgpls-frr-lab-v1 "$BGPLS_STATE" mock-daemon \
    "$(bgpls_hash "$BGPLS_TOPOLOGY")" ceos > "$BGPLS_STATE/.bgpls-lab-state"
expect_failure bgpls_validate_state
printf '%s\n' bgpls-frr-lab-v1 "$BGPLS_STATE" mock-daemon \
    "$(bgpls_hash "$BGPLS_TOPOLOGY")" > "$BGPLS_STATE/.bgpls-lab-state"
printf 'unterminated-extra' >> "$BGPLS_STATE/.bgpls-lab-state"
expect_failure bgpls_validate_state
printf '%s\n' bgpls-frr-lab-v1 "$BGPLS_STATE" mock-daemon \
    "$(bgpls_hash "$BGPLS_TOPOLOGY")" > "$BGPLS_STATE/.bgpls-lab-state"
expect_success bgpls_validate_state
expect_success test "$BGPLS_PROFILE" = frr
expect_success test "${#BGPLS_NODES[@]}" = 6
expect_success test "${BGPLS_PORTS[*]}" = 11790
expect_success test "$BGPLS_DEPLOY_TIMEOUT" = 2m

bgpls_check_runtime() { BGPLS_DAEMON_ID=wrong-daemon; }
expect_failure bgpls_validate_state
bgpls_check_runtime() { BGPLS_DAEMON_ID=mock-daemon; }
printf '# changed after deployment\n' >> "$BGPLS_TOPOLOGY"
expect_failure bgpls_validate_state
printf 'name: bgpls\n' > "$BGPLS_TOPOLOGY"
expect_success bgpls_validate_state

bgpls_docker() { printf 'bgpls|%s\n' "$BGPLS_TOPOLOGY"; }
expect_success bgpls_require_container p1
expect_failure bgpls_require_container smoke-router1
expect_failure bgpls_require_container edge-ceos
expect_success bgpls_set_profile ceos
expect_success bgpls_require_container edge-ceos
expect_success bgpls_set_profile frr
bgpls_docker() { printf 'smoke|%s\n' "$BGPLS_TOPOLOGY"; }
expect_failure bgpls_require_container p1

# Destroy may visit only the selected fixed node set, never extra containers
# carrying the same lab label, even when their topology labels match.
mock_container_names=$'clab-bgpls-rr1\nclab-bgpls-edge-frr'
bgpls_docker() {
    case "$1" in
        inspect) printf 'bgpls|%s\n' "$BGPLS_TOPOLOGY" ;;
        ps) printf '%s\n' "$mock_container_names" ;;
        *) return 1 ;;
    esac
}
expect_success bgpls_validate_containers
mock_container_names=clab-bgpls-edge-ceos
expect_failure bgpls_validate_containers
expect_success bgpls_set_profile ceos
expect_success bgpls_validate_containers
mock_container_names=clab-bgpls-unreviewed
expect_failure bgpls_validate_containers
mock_container_names=smoke-router1
expect_failure bgpls_validate_containers
expect_success bgpls_set_profile frr
bgpls_docker() { printf 'bgpls|%s/foreign.clab.yml\n' "$BGPLS_STATE"; }
expect_failure bgpls_require_container p1

bgpls_docker() { printf '%s\n' existing-lab; }
expect_failure bgpls_require_no_collisions
bgpls_docker() {
    case "$1" in
        ps) return 0 ;;
        inspect) return 0 ;;
        *) return 1 ;;
    esac
}
expect_failure bgpls_require_no_collisions
bgpls_docker() {
    case "$1" in
        ps) return 0 ;;
        inspect) return 1 ;;
        network) printf '%s\n' bgpls ;;
        *) return 1 ;;
    esac
}
expect_failure bgpls_require_no_collisions

# A running real lab's localhost listener must not influence these mock tests.
lsof() { return 1; }
bgpls_docker() {
    case "$1" in
        ps) return 0 ;;
        inspect) return 1 ;;
        network) printf '%s\n' unrelated-smoke-network ;;
        *) return 1 ;;
    esac
}
bgpls_runtime() { printf '%s\n' 'LISTEN 0 4096 127.0.0.1:11790'; }
expect_failure bgpls_require_no_collisions
bgpls_runtime() { return 0; }
expect_success bgpls_require_no_collisions
expect_success bgpls_set_profile ceos
bgpls_runtime() {
    if [[ ${4:-} == 'sport = :11791' ]]; then
        printf '%s\n' 'LISTEN 0 4096 127.0.0.1:11791'
    fi
}
expect_failure bgpls_require_no_collisions
bgpls_runtime() { return 0; }
bgpls_docker() {
    case "$1" in
        ps) return 0 ;;
        inspect) [[ $2 == clab-bgpls-edge-ceos ]] ;;
        network) printf '%s\n' unrelated-smoke-network ;;
        *) return 1 ;;
    esac
}
expect_failure bgpls_require_no_collisions
expect_success bgpls_set_profile frr

# Missing or non-native images are hard failures; this helper issues only
# info/image-inspect reads, never docker pull/import or a vendor download.
mock_image_id=sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
mock_platform=aarch64
mock_image_details="$mock_image_id|linux|arm64"
mock_image_exists=1
bgpls_docker() {
    case "$1" in
        info) printf '%s\n' "$mock_platform" ;;
        image)
            [[ $# -eq 5 && $2 == inspect && $3 == ceosarm:4.36.2F &&
                $4 == --format && $mock_image_exists -eq 1 ]] || return 1
            printf '%s\n' "$mock_image_details"
            ;;
        *) return 1 ;;
    esac
}
expect_success bgpls_require_ceos_image
expect_success test "$BGPLS_CEOS_IMAGE_ID" = "$mock_image_id"
mock_platform=arm64
expect_success bgpls_require_ceos_image
mock_platform=x86_64
expect_failure bgpls_require_ceos_image
mock_platform=aarch64
mock_image_exists=0
expect_failure bgpls_require_ceos_image
mock_image_exists=1
mock_image_details="$mock_image_id|linux|amd64"
expect_failure bgpls_require_ceos_image
mock_image_details="$mock_image_id|windows|arm64"
expect_failure bgpls_require_ceos_image
mock_image_details='not-an-image-id|linux|arm64'
expect_failure bgpls_require_ceos_image
mock_image_details="$mock_image_id|linux|arm64"
expect_success bgpls_require_ceos_image
bgpls_docker() { printf '%s|%s\n' ceosarm:4.36.2F "$mock_image_id"; }
expect_success bgpls_verify_ceos_image
bgpls_docker() { printf '%s|%s\n' ceos64:4.36.2F "$mock_image_id"; }
expect_failure bgpls_verify_ceos_image
bgpls_docker() { printf '%s|sha256:other-image\n' ceosarm:4.36.2F; }
expect_failure bgpls_verify_ceos_image

# Compare numeric release components, not strings (0.9 is older than 0.83).
# A failed command is not accepted even if it printed a valid-looking version.
mock_version_status=0
bgpls_containerlab() {
    [[ $# -eq 2 && $1 == version && $2 == --short ]] || return 97
    printf '%s\n' "$mock_version"
    return "$mock_version_status"
}
for mock_version in 0.83.0 0.83.1 0.84.0 0.100.0 1.0.0 2.0.0; do
    expect_success bgpls_require_deploy_version
done
for mock_version in 0.0.0 0.9.0 0.79.0 0.80.0 0.81.0 0.81.1 0.82.0 0.82.1 0.82.999999999 '' unknown \
    0.83 0.83.0.0 v0.83.0 0.083.0 0.83.00 0.83.0-rc.1 0.83.0-dev 1.0.0-dev \
    0.83.0+local ' 0.83.0' '0.83.0 ' $'0.83.0\nextra' 0.9999999999.0; do
    expect_failure bgpls_require_deploy_version
done
mock_version=0.83.0
mock_version_status=1
expect_failure bgpls_require_deploy_version
mock_version_status=0

#  Exercise the real entrypoints in child shells, not a replacement
# preflight. Every runtime command is an exported mock; even a misplaced guard
# cannot reach Docker, OrbStack, sudo, or create/copy deployment state.
run_mock_workflow() (
    workflow=$1
    shift
    export BGPLS_TEST_VERSION="$mock_version"
    export BGPLS_TEST_VERSION_STATUS="$mock_version_status"
    export BGPLS_TEST_MODE="$workflow"
    export BGPLS_TEST_TOPOLOGY="$BGPLS_TOPOLOGY"
    export BGPLS_TEST_CALLS="$test_root/mock-runtime.log"
    export BGPLS_TEST_HOLDER="${mock_namespace_holder:-none}"
    unset DOCKER_HOST DOCKER_CONTEXT CLAB_LABDIR_BASE
    : > "$BGPLS_TEST_CALLS"
    mock_call() {
        printf '%s' "$1" >> "$BGPLS_TEST_CALLS"
        shift
        printf ' %q' "$@" >> "$BGPLS_TEST_CALLS"
        printf '\n' >> "$BGPLS_TEST_CALLS"
    }
    uname() { printf 'Linux\n'; }
    id() { [[ $# -eq 1 && $1 == -u ]] || return 97; printf '0\n'; }
    env() {
        [[ $# -ge 3 && $1 == -u && $2 == CLAB_LABDIR_BASE ]] || return 97
        shift 2
        "$@"
    }
    containerlab() {
        mock_call containerlab "$@"
        case "$1" in
            version)
                if [[ $# -eq 1 ]]; then
                    printf 'version: %s\n' "$BGPLS_TEST_VERSION"
                elif [[ $# -eq 2 && $2 == --short ]]; then
                    printf '%s\n' "$BGPLS_TEST_VERSION"
                    return "$BGPLS_TEST_VERSION_STATUS"
                else
                    return 97
                fi
                ;;
            destroy) [[ $BGPLS_TEST_MODE == destroy.sh ]] ;;
            *) return 97 ;;
        esac
    }
    docker() {
        mock_call docker "$@"
        case "$1" in
            context) printf 'unix:///var/run/docker.sock\n' ;;
            info) printf 'mock-daemon\n' ;;
            ps)
                if [[ ${3:-} == --no-trunc ]]; then
                    printf '%064d\n' 1
                    [[ $BGPLS_TEST_HOLDER == none ]] || printf '%064d\n' 2
                elif [[ $BGPLS_TEST_MODE == deploy.sh ]]; then
                    # A supported version reaches this read-only collision
                    # check; stop it here instead of performing a deployment.
                    printf 'existing-lab\n'
                else
                    printf 'clab-bgpls-p1\nclab-bgpls-p2\n'
                fi
                ;;
            inspect)
                [[ $BGPLS_TEST_MODE != deploy.sh ]] || return 1
                if [[ ${2:-} == 0000000000000000000000000000000000000000000000000000000000000001 ]]; then
                    # No runtime: return exactly the Docker inventory needed
                    # by the real namespace guard in the child process.
                    printf '[{"Id":"%064d","Name":"/clab-bgpls-bgpls-relay","State":{"Running":true},"HostConfig":{"NetworkMode":"bgpls"},"Config":{"Labels":{"containerlab":"bgpls","clab-topo-file":"%s"}}}' 1 "$BGPLS_TEST_TOPOLOGY"
                    if [[ $BGPLS_TEST_HOLDER != none ]]; then
                        printf ',{"Id":"%064d","Name":"/manual-collector","State":{"Running":true},"HostConfig":{"NetworkMode":"container:clab-bgpls-bgpls-relay"}}' 2
                    fi
                    printf ']\n'
                else
                    printf 'bgpls|%s\n' "$BGPLS_TEST_TOPOLOGY"
                fi
                ;;
            network) return 1 ;;
            exec) [[ $BGPLS_TEST_MODE == churn-link.sh ]] ;;
            *) return 97 ;;
        esac
    }
    mkdir() { mock_call mkdir "$@"; return 97; }
    cp() { mock_call cp "$@"; return 97; }
    orb() { mock_call orb "$@"; return 97; }
    sudo() { mock_call sudo "$@"; return 97; }
    export -f mock_call uname id env containerlab docker mkdir cp orb sudo
    bash "$example_dir/$workflow" "$@" > "$test_root/mock-output.log" 2>&1
)

#  Malformed, missing and duplicate ASN options fail before even the
# first read-only runtime command, regardless of the selected lab profile.
for asn in '' 0 000 23456 00023456 4294967296 99999999999999999999 +65001 -1 \
    ' 65001' '65001 ' $'65001\n' AS65001 1.10 ６５００１ 12_34; do
    expect_failure run_mock_workflow deploy.sh --ceos --ipv6-transport --asn "$asn" "$test_root/new-state"
    expect_failure test -s "$test_root/mock-runtime.log"
    expect_failure test -e "$test_root/new-state"
done
expect_failure run_mock_workflow deploy.sh --asn
expect_failure test -s "$test_root/mock-runtime.log"
expect_failure run_mock_workflow deploy.sh --asn --ceos "$test_root/new-state"
expect_failure test -s "$test_root/mock-runtime.log"
expect_failure run_mock_workflow deploy.sh --asn 65001 --asn 4200000001 "$test_root/new-state"
expect_failure test -s "$test_root/mock-runtime.log"
mock_version=0.83.0
for asn in 1 65535 65536 4200000001 4294967295 00065001; do
    expect_failure run_mock_workflow deploy.sh --asn "$asn" "$test_root/new-state"
    expect_success grep -Fq 'A bgpls lab already exists' "$test_root/mock-output.log"
    expect_success grep -Fq 'docker ps ' "$test_root/mock-runtime.log"
    expect_failure test -e "$test_root/new-state"
done

for profile in frr ceos; do
    profile_args=("$test_root/new-state")
    [[ $profile != ceos ]] || profile_args=(--ceos "$test_root/new-state")
    for mock_version in 0.79.0 0.80.0 0.81.1 0.82.0 0.82.1 0.82.999999999 0.83.0-rc.1 0.83.0-dev invalid ''; do
        expect_failure run_mock_workflow deploy.sh "${profile_args[@]}"
        expect_success grep -Fq '0.83.0 or newer' "$test_root/mock-output.log"
        expect_success grep -Fxq 'containerlab version --short' "$test_root/mock-runtime.log"
        expect_failure grep -Eq '^(mkdir|cp|orb|sudo|docker (ps|network|exec)|containerlab (deploy|destroy)) ' \
            "$test_root/mock-runtime.log"
        expect_failure test -e "$test_root/new-state"
    done
    mock_version=0.83.0
    mock_version_status=1
    expect_failure run_mock_workflow deploy.sh "${profile_args[@]}"
    expect_success grep -Fq 'Unable to read Containerlab version' "$test_root/mock-output.log"
    expect_failure grep -Eq '^(mkdir|cp|orb|sudo|docker (ps|network|exec)|containerlab (deploy|destroy)) ' \
        "$test_root/mock-runtime.log"
    expect_failure test -e "$test_root/new-state"
    mock_version_status=0
    for mock_version in 0.83.0 0.83.1 0.84.0 1.0.0; do
        expect_failure run_mock_workflow deploy.sh "${profile_args[@]}"
        expect_success grep -Fq 'A bgpls lab already exists' "$test_root/mock-output.log"
        expect_success grep -Fq 'docker ps ' "$test_root/mock-runtime.log"
        expect_failure grep -Eq '^(mkdir|cp|orb|sudo|docker (network|exec)|containerlab (deploy|destroy)) ' \
            "$test_root/mock-runtime.log"
        expect_failure test -e "$test_root/new-state"
    done
done

# Namespace-sharing containers do not carry Containerlab labels. Destruction
# still refuses them, and never stops/removes a manual collector on our behalf.
mock_namespace_holder=manual
expect_failure run_mock_workflow destroy.sh "$BGPLS_STATE"
expect_success grep -Fq 'Relay namespace is held by' "$test_root/mock-output.log"
expect_failure grep -Eq '^containerlab destroy |^docker (stop|kill|rm) ' "$test_root/mock-runtime.log"
expect_failure test -e "$BGPLS_STATE/.bgpls-verification-lock"
mock_namespace_holder=none
mkdir -- "$BGPLS_STATE/.bgpls-verification-lock"
printf '{"pid":0,"token":"not-ours"}\n' > "$BGPLS_STATE/.bgpls-verification-lock/owner.json"
expect_failure run_mock_workflow destroy.sh "$BGPLS_STATE"
expect_success grep -Fq 'Lab lifecycle lock exists' "$test_root/mock-output.log"
expect_failure grep -Eq '^(docker|containerlab) ' "$test_root/mock-runtime.log"
expect_success test -f "$BGPLS_STATE/.bgpls-verification-lock/owner.json"
rm -- "$BGPLS_STATE/.bgpls-verification-lock/owner.json"
rmdir -- "$BGPLS_STATE/.bgpls-verification-lock"

#  The shared runtime check must not inherit the deployment floor.
# Both legacy ownership formats can still reach scoped destroy and link
# operations on 0.79.0; neither asks for the deployment-only short version.
mock_version=0.79.0
for profile in frr ceos; do
    if [[ $profile == frr ]]; then
        printf '%s\n' bgpls-frr-lab-v1 "$BGPLS_STATE" mock-daemon \
            "$(bgpls_hash "$BGPLS_TOPOLOGY")" > "$BGPLS_STATE/.bgpls-lab-state"
    else
        printf '%s\n' bgpls-lab-v2 "$BGPLS_STATE" mock-daemon \
            "$(bgpls_hash "$BGPLS_TOPOLOGY")" ceos > "$BGPLS_STATE/.bgpls-lab-state"
    fi
    expect_success run_mock_workflow destroy.sh "$BGPLS_STATE"
    expect_success grep -Fq 'containerlab destroy --topo ' "$test_root/mock-runtime.log"
    expect_failure grep -Fq 'containerlab version --short' "$test_root/mock-runtime.log"
    expect_success test -f "$BGPLS_STATE/.bgpls-lab-state"
    expect_success test -f "$BGPLS_TOPOLOGY"
    expect_success run_mock_workflow churn-link.sh "$BGPLS_STATE" down
    expect_success grep -Fxq 'docker exec clab-bgpls-p1 ip link set dev eth3 down' "$test_root/mock-runtime.log"
    expect_success grep -Fxq 'docker exec clab-bgpls-p2 ip link set dev eth3 down' "$test_root/mock-runtime.log"
    expect_failure grep -Fq 'containerlab version --short' "$test_root/mock-runtime.log"
done

for script in deploy.sh destroy.sh churn-link.sh; do
    expect_success "$example_dir/$script" --help
done
expect_failure "$example_dir/deploy.sh" /tmp /tmp
expect_failure "$example_dir/deploy.sh" --unknown
expect_failure "$example_dir/deploy.sh" --ceos /tmp /tmp
expect_failure "$example_dir/destroy.sh" /tmp /tmp
expect_failure "$example_dir/churn-link.sh" "$BGPLS_STATE" unknown
expect_failure "$example_dir/churn-link.sh" "$BGPLS_STATE" flap 08
expect_failure "$example_dir/churn-link.sh" "$BGPLS_STATE" flap 61
expect_failure env BGPLS_LAB_STATE="$BGPLS_STATE" "$example_dir/churn-link.sh" flap 0

# Loading the deployment helper does not run deployment or contact a runtime.
source "$example_dir/deploy.sh"
expect_success bgpls_parse_deploy_args --ipv6-transport --ceos "$test_root/new-state"
expect_success test "$BGPLS_PROFILE" = ceos
expect_success test "$BGPLS_TRANSPORT" = ipv6
expect_success test "$BGPLS_REQUESTED_STATE" = "$test_root/new-state"
expect_success bgpls_parse_deploy_args --ceos "$test_root/new-state" --ipv6-transport
expect_success bgpls_parse_deploy_args --asn 04200000001 "$test_root/new-state"
expect_success test "$BGPLS_ASN" = 4200000001
expect_success bgpls_parse_deploy_args "$test_root/new-state"
expect_success test "$BGPLS_ASN" = 65001
expect_failure bgpls_parse_deploy_args --asn
expect_failure bgpls_parse_deploy_args --asn --ceos
expect_failure bgpls_parse_deploy_args --asn 65001 --asn 4200000001
expect_failure bgpls_parse_deploy_args --asn 23456
expect_failure bgpls_parse_deploy_args --ipv6-transport --ipv6-transport
expect_failure bgpls_parse_deploy_args --ceos --ceos
expect_failure bgpls_parse_deploy_args --unknown
expect_failure bgpls_parse_deploy_args /tmp /tmp
expect_failure bgpls_copy_deployment
mock_network_id=1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
bgpls_docker() {
    [[ $# -eq 9 && $1 == network && $2 == create && $3 == --driver &&
        $4 == bridge && $5 == --subnet && $6 == 172.31.250.0/24 &&
        $7 == --label && $8 == "bgpls.example.state=$BGPLS_STATE" && $9 == bgpls ]] || return 1
    printf '%s\n' "$mock_network_id"
}
expect_success bgpls_create_owned_network
expect_success test "$(< "$BGPLS_STATE/.bgpls-network-id")" = "$mock_network_id"
expect_failure bgpls_create_owned_network
rm -- "$BGPLS_STATE/.bgpls-network-id"

bgpls_docker() {
    # A name collision must not trigger inspection or record the other network.
    [[ $1 == network && $2 == create ]] || return 2
    printf '%s\n' "$mock_network_id"
    return 1
}
expect_failure bgpls_create_owned_network
expect_failure test -e "$BGPLS_STATE/.bgpls-network-id"
bgpls_docker() { printf '%s\n' malformed-id; }
expect_failure bgpls_create_owned_network
expect_failure test -e "$BGPLS_STATE/.bgpls-network-id"

printf 'PASS: %s workflow guard checks (mock runtime; no network or container changes).\n' "$checks"
