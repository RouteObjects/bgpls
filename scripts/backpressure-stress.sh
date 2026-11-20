#!/usr/bin/env bash
# Run only synthetic loopback cases. No deployment or vendor connection is used.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
OUTPUT=""
CASES="population-reference,population-10x,refresh-1000,refresh-10000,refresh-max,delay-1ms,delay-10ms,paused,frames-minimum,frames-maximum,peers-4,peers-16,bridge-native,copy-cost"
BASELINE=false
SKIP_BUILD=false
while (($#)); do
  case "$1" in
    --output) OUTPUT="${2:?missing --output path}"; shift 2 ;;
    --cases) CASES="${2:?missing --cases list}"; shift 2 ;;
    --baseline) PACKAGE_ROOT="${2:?missing baseline package path}"; BASELINE=true; CASES=bridge-baseline; shift 2 ;;
    --skip-build) SKIP_BUILD=true; shift ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done
if [[ "$OUTPUT" != /* || -e "$OUTPUT" ]]; then
  printf '%s\n' '--output must name a new absolute evidence directory' >&2
  exit 2
fi
python3 - "$CASES" <<'PYVALIDATE'
import sys
allowed = {'population-reference', 'population-10x', 'refresh-1000', 'refresh-10000',
           'refresh-max', 'delay-1ms', 'delay-10ms', 'paused', 'frames-minimum',
           'frames-maximum', 'peers-4', 'peers-16', 'bridge-baseline', 'bridge-native', 'smoke', 'copy-cost'}
cases = sys.argv[1].split(',')
if not cases or any(case not in allowed for case in cases) or len(set(cases)) != len(cases):
    raise SystemExit('Cases must be distinct supported names')
PYVALIDATE
mkdir -p "$OUTPUT"
SCRATCH="${BGPLS_STRESS_SCRATCH_PATH:-${PACKAGE_ROOT}/.build}"
export CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-${SCRATCH}/clang-module-cache}"
mkdir -p "$CLANG_MODULE_CACHE_PATH"
swift_test_flags=()
source "${SCRIPT_DIR}/swift-testing-support.sh"
append_swift_testing_flags_for_command_line_tools
args=(--package-path "$PACKAGE_ROOT" --scratch-path "$SCRATCH" --configuration release --disable-automatic-resolution)
# macOS Bash 3 treats expansion of an empty array as unset under nounset.
if ((${#swift_test_flags[@]})); then
  args=("${swift_test_flags[@]}" "${args[@]}")
fi
if [[ "$BASELINE" == true ]]; then
  args+=(-Xswiftc -DBGPLS_LEGACY_BASELINE)
fi
swift --version > "$OUTPUT/toolchain.txt"
if [[ "$BASELINE" == true ]]; then
  # An isolated git-archive baseline deliberately has no repository/index to mutate.
  python3 - "$PACKAGE_ROOT/.baseline-commit" "$OUTPUT/base-commit.txt" <<'PYBASELINE'
import pathlib
import re
import sys
commit = pathlib.Path(sys.argv[1]).read_text().strip()
if not re.fullmatch(r'[0-9a-f]{40}', commit):
    raise SystemExit('Baseline .baseline-commit must contain its verified source commit')
pathlib.Path(sys.argv[2]).write_text(commit + '\n')
PYBASELINE
  printf '%s\n' 'Isolated git archive with copied test-only benchmark harness; no baseline repository/index.' > "$OUTPUT/source-method.txt"
else
  git -C "$PACKAGE_ROOT" rev-parse HEAD > "$OUTPUT/base-commit.txt"
  printf '%s\n' 'Current checkout; base-commit identifies its parent, not the uncommitted patch.' > "$OUTPUT/source-method.txt"
fi
if [[ "$SKIP_BUILD" == false ]]; then
  swift test "${args[@]}" \
    --filter SessionInputStressTests.syntheticReferenceHasDistinctDirectedLinksAndDualStackPrefixes \
    > "$OUTPUT/build.log" 2>&1
fi
# A process watchdog bounds even a broken async teardown. Only this dedicated,
# filtered test process group is signalled; ordinary parallel tests are never run.
python3 - "$OUTPUT" "$CASES" "${args[@]}" <<'PY'
import json
import os
import pathlib
import signal
import subprocess
import sys
import time

output = pathlib.Path(sys.argv[1])
cases = sys.argv[2].split(',')
allowed = {'population-reference', 'population-10x', 'refresh-1000', 'refresh-10000',
           'refresh-max', 'delay-1ms', 'delay-10ms', 'paused', 'frames-minimum',
           'frames-maximum', 'peers-4', 'peers-16', 'bridge-baseline', 'bridge-native', 'smoke', 'copy-cost'}
if not cases or any(case not in allowed for case in cases) or len(set(cases)) != len(cases):
    raise SystemExit('Cases must be distinct supported names')
command = ['swift', 'test', *sys.argv[3:], '--skip-build', '--filter', 'SessionInputStressTests.selectedCase']
records = []
for name in cases:
    environment = os.environ.copy()
    environment['BGPLS_BACKPRESSURE_CASE'] = name
    environment['BGPLS_BACKPRESSURE_OUTPUT'] = str(output / (name + '.json'))
    start = time.monotonic()
    timed_out = False
    with (output / (name + '.log')).open('xb') as log:
        process = subprocess.Popen(command, env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            status = process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            status = process.wait()
    result_path = output / (name + '.json')
    result = json.loads(result_path.read_text()) if result_path.exists() else {}
    record = {'case': name, 'exitStatus': status, 'watchdogTimedOut': timed_out,
              'wallSeconds': time.monotonic() - start, 'resultPublished': result_path.exists(),
              'workloadTimedOut': result.get('timedOut'), 'failure': result.get('failure')}
    records.append(record)
    print(json.dumps(record), flush=True)
(output / 'runner-results.json').write_text(json.dumps(records, indent=2) + '\n')
raise SystemExit(any(row['exitStatus'] != 0 or not row['resultPublished']
                     or row['workloadTimedOut'] or row['failure'] for row in records))
PY
