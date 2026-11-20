#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/common.sh"
if [[ ${1:-} == --help ]] || (($# < 2)); then
    echo "Usage: $0 ABSOLUTE_STATE_DIR ABSOLUTE_BGPLS_BINARY [--churn] [--signal INT|TERM]" >&2
    echo "   or: $0 ABSOLUTE_STATE_DIR --transport ipv6 --artifact ABSOLUTE_MANIFEST [--churn]" >&2
    echo 'The FRR profile accepts --signal; the cEOS profile verifies INT and TERM across its two collectors.' >&2
    echo '--churn also tests temporary IPv6 loopback-prefix add/withdraw/re-add and restores all changes.' >&2
    echo '--attributes adds typed audits; --attribute-probes additionally changes/restores selected IS-IS metrics.' >&2
    [[ ${1:-} != --help ]] || exit 0
    exit 2
fi
bgpls_init_state "$1"
bgpls_validate_state
shift
#  Explicit transport/artifact selection cannot silently turn a native
# Mac IPv4 run into a namespace-sharing Linux collector. Legacy syntax remains.
if [[ $1 != --* ]]; then
    set -- --binary "$@"
fi
if [[ $BGPLS_PROFILE == ceos ]]; then
    exec python3 "$script_dir/verify-ceos.py" --state "$BGPLS_STATE" "$@"
else
    exec python3 "$script_dir/verify.py" --state "$BGPLS_STATE" "$@"
fi
