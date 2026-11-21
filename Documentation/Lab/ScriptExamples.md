# Lab script recipes

Run commands from the repository root. `LAB_DIR` always means the external state
directory returned by a successful deployment, not the source directory. Use
that same state for inspection, verification, link control, and destruction.

## Deploy and remove

```sh
LAB_DIR="$HOME/clabs/bgpls-demo"
mkdir -p "$(dirname "$LAB_DIR")"
./lab-examples/bgpls/deploy.sh "$LAB_DIR"
```

`deploy.sh` creates routers and links. It selects the default FRR-only profile,
copies the configuration into fresh state, records ownership and configuration
hashes, and refuses conflicting resources. Optional arguments are `--ceos`,
`--ipv6-transport`, and `--asn NUMBER`. It does not repair an old deployment or
rewrite existing state. If startup fails, preserve the directory and logs for
inspection; a failed deployment is not evidence of successful convergence.

After stopping collectors, remove only the recorded deployment:

```sh
./lab-examples/bgpls/destroy.sh "$LAB_DIR"
```

Destruction checks the saved configuration, Docker daemon, node identities,
and owned management network. It retains state, logs, and captures. A mismatch
or an active verification/collector namespace holder causes refusal rather than
a broader cleanup. Do not bypass that refusal with global deletion commands.

## Optional manual capture

For a manual collector on the default FRR-only deployment, run the release
build with `--pcap-auto` to select a new capture in the current working directory.

```sh
swift build -c release --product bgpls
.build/release/bgpls run \
  --peer 127.0.0.1 --port 11790 \
  --local-as 65001 --peer-as 65001 \
  --bgp-identifier 192.0.2.101 \
  --watch --show-attributes --dump-rib --pcap-auto
```

Use a trusted working directory. The generated
name contains a UTC timestamp selected before connecting, the configured peer
address and port, and a UUID. Here `127.0.0.1:11790` identifies the lab relay,
not the producer's vendor. The escaped absolute path is printed before session
creation; the separate `writing PCAP` message confirms capture setup.
Use `--pcap FILE` instead to select an explicit path; combining the two options
fails validation. Without either option, capture is disabled. Automated
qualification continues to use its explicit evidence paths.

## Flap a link

To watch a withdrawal, first wait for the collector to show both directions of
`p1:eth3 ↔ p2:eth3` (`10.254.0.8 ↔ 10.254.0.9`). From a second Terminal
select the original guest and deployment directory, then lower both ends:

```sh
./lab-examples/bgpls/churn-link.sh "$LAB_DIR" down
```

Keep the collector running. Restore the circuit as soon as you see both
directional `WATCH withdraw link` events. If either is missing after 90
seconds, run `up` anyway. The explicit `down` persists until you restore it.

```sh
./lab-examples/bgpls/churn-link.sh "$LAB_DIR" up
```

Look for two returning upserts with the original IPv4 and IPv6 endpoints.
The converged FRR-only baseline has `5/14/10` nodes, directed links and
prefixes. The cEOS profile has `6/18/12` per producer.

For a timed physical flap, use `./lab-examples/bgpls/churn-link.sh "$LAB_DIR" flap 10`.
This restores both interfaces after ten seconds, which can be too short to see
both withdrawals. The timer accepts 1 through 60 seconds and defaults to 15.
The script attempts restoration on ordinary exit and handled signals. If the
process is killed or the runtime is unavailable, check both interfaces and
use `up` to restore them. Link operations leave startup configurations intact.

## Automated verification

Stop manual collectors first: **the verifier starts its own collectors**. It
claims the deployment's verification lock and checks ownership before proceeding.

```sh
swift build -c release --product bgpls
./lab-examples/bgpls/verify.sh "$LAB_DIR" "$PWD/.build/release/bgpls"
```

This verifies the selected profile, starts BGP sessions, captures evidence, and
shuts its collectors down. It does not flap links unless requested. For the
**FRR-only profile**, exercise topology changes and SIGTERM shutdown with:

```sh
./lab-examples/bgpls/verify.sh "$LAB_DIR" "$PWD/.build/release/bgpls" \
  --churn --signal TERM
```

`--churn` performs a physical-link flap and independent IPv6 prefix probes. It
requires exact restoration. The FRR-only default shutdown signal is `INT`;
`--signal TERM` selects `TERM`. The **paired cEOS profile** always tests `INT`
and `TERM` across its two collectors and does not accept `--signal`. To reverse
which producer stops first:

```sh
./lab-examples/bgpls/verify.sh "$LAB_DIR" "$PWD/.build/release/bgpls" \
  --churn --reverse-shutdown
```

The remaining producer must retain an independent session after the first stops.

A successful run writes `result.json` in its new verification evidence directory
only after checks and cleanup complete. A per-capture audit file alone is not a
successful live verification result. Failures retain evidence. Use
[typed-attribute verification](../../lab-examples/bgpls/ATTRIBUTES.md) to add
wire/native/Swift/CLI comparisons or explicitly requested metric probes.

## Four-byte ASNs

Render a private-use four-byte ASN into a **new deployment**:

```sh
LAB_DIR="$HOME/clabs/bgpls-as4-demo"
./lab-examples/bgpls/deploy.sh --asn 4200000001 "$LAB_DIR"
```

Ensure the parent directory already exists. Set **both** `--local-as` and
`--peer-as` to `4200000001` in manual collector commands. The verifier obtains
the ASN from recorded deployment state. Configuration remains iBGP throughout;
no neighbor `local-as` overrides are introduced. `--asn` accepts strict decimal
session identities and rejects zero and the reserved AS_TRANS placeholder
`23456`. Default deployments use `65001`.

## IPv6 session transport

The default quickstart already collects IPv6 topology. Testing **IPv6 TCP
transport** is a separate, advanced ARM64 workflow. Deploy a fresh profile with
`--ipv6-transport`; this adds IPv6 neighbors on the dedicated collector links.
Verification runs prepared Linux collectors inside the relay's network namespace,
connecting directly to the exporters. It does not use localhost HAProxy.

Collector preparation requires a committed source revision, the pinned Swift
6.3.3 Linux ARM64 image already installed on the lab daemon, and a complete
SwiftPM dependency cache matching `Package.resolved`. Preparation builds with
network access disabled; missing inputs cause a retained failure, not a network
fetch. This is a reproducible qualification workflow, not necessary to see the
default demonstration.

Given an existing Linux ARM64 SwiftPM scratch cache, select fresh external paths:

```sh
COLLECTOR_DIR="$HOME/clabs/bgpls-collector"
COLLECTOR_CACHE="$HOME/clabs/bgpls-collector-cache"
SEED_CACHE="/absolute/path/to/existing/linux-arm64-swiftpm-cache"
REVISION="$(git rev-parse --verify 'HEAD^{commit}')"
python3 lab-examples/bgpls/prepare-collector.py \
  --repository "$PWD" --revision "$REVISION" \
  --machine "${CLAB_MACHINE:-clab}" \
  --output "$COLLECTOR_DIR" --cache "$COLLECTOR_CACHE" \
  --seed-cache "$SEED_CACHE"
```

`REVISION` resolves the current commit to the full SHA required by the script.
`--machine` selects the same OrbStack machine as deployment and verification;
it has no effect on native Linux.

The script preserves the seed and writes `artifact.json` only for a verified
build. It does not include uncommitted changes. Then, after removing any previous
owned `bgpls` deployment and choosing fresh state:

```sh
LAB_DIR="$HOME/clabs/bgpls-ipv6-demo"
./lab-examples/bgpls/deploy.sh --ceos --ipv6-transport "$LAB_DIR"
./lab-examples/bgpls/verify.sh "$LAB_DIR" \
  --transport ipv6 --artifact "$COLLECTOR_DIR/artifact.json" --churn
```

Omit `--ceos` for FRR only. Image preparation is described in the
[cEOS guide](../../lab-examples/bgpls/CEOS.md). The IPv6 overlay is applied to the
fresh copy before ASN rendering, preserving the source templates. Verification
binds expectations to saved deployment state and the prepared binary's source,
image, toolchain, and checksum evidence.
