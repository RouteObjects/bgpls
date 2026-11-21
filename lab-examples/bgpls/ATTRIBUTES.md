# Inspect and verify typed BGP-LS attributes

Add `--show-attributes` to the [manual collector commands](README.md#tldr--see-it-work)
to enrich watch upserts with node names, metrics, and bandwidth. Add `--dump-rib`
when the complete enriched topology should also print at shutdown. Neither flag
changes collection or the topology's identity keys.

Missing values stay missing. `AS not-advertised` means the topology's ASN
Descriptor 512 was absent; the collector does not substitute its session ASN.
FRR and cEOS can expose different retained evidence for the same network.

## Expected values in this reference topology

| Projection | FRR-origin evidence | cEOS-origin evidence |
| --- | --- | --- |
| Node name | Router name | Router name |
| IGP link metric | `10`, one-octet encoding | `10`, three-octet encoding |
| Prefix metric | `10` | `10` |
| Maximum link bandwidth | `1250000` bytes/s | `125000000` bytes/s |
| Maximum reservable bandwidth | `1250000` bytes/s | `0` bytes/s |
| Unreserved bandwidth | Eight priorities, each `1250000` bytes/s | Eight priorities, each `0` bytes/s |

These are advertised attributes, not measured traffic utilization or guaranteed
capacity. Zero is a value, not missing data. The native cEOS CLI presents some
bandwidth in bits/s; the audit converts units before comparison. An exporter may
relay attributes originating at another router, so source-node ownership matters.

The library preserves raw type-29 evidence. Attribute-only refreshes replace the
complete observation without changing keys or counts. Unusable projections are
reported; omitted values do not retain an earlier advertisement's values.
Public API and fault-handling details are in the package documentation.

## Qualification commands

Stop manual collectors first. The verifier starts and owns its collectors,
checks the recorded deployment, and requires a complete final RIB. For native
`--attributes` qualification, use the debug build. The verifier rebuilds that
configuration and checks that the supplied executable has the same SHA-256.

```sh
swift build -c debug --product bgpls
./lab-examples/bgpls/verify.sh "$LAB_DIR" "$PWD/.build/debug/bgpls" \
  --attributes
```

This adds independent comparisons between retained wire bytes, native router
output, Swift replay, and enriched CLI output. It does not change metrics.
To request controlled metric changes as well:

```sh
./lab-examples/bgpls/verify.sh "$LAB_DIR" "$PWD/.build/debug/bgpls" \
  --attributes --attribute-probes --churn
```

The probes change a selected directional metric `10 → 20 → 10`: FRR `p1:eth3`,
and cEOS `edge-ceos:Ethernet1` when that profile is selected. They check unchanged
reverse direction, stable identities/counts, and exact restoration of the prior
running directive. `--churn` separately exercises physical-link and IPv6-prefix
withdrawal/restoration. These options **change the lab** and require exclusive
verification ownership.

For a prepared IPv6 collector, the same opt-in audit applies:

```sh
./lab-examples/bgpls/verify.sh "$LAB_DIR" \
  --transport ipv6 --artifact "$COLLECTOR_DIR/artifact.json" \
  --attributes --attribute-probes --churn
```

Follow the [IPv6 preparation recipe](../../Documentation/Lab/ScriptExamples.md#ipv6-session-transport)
first. The prepared artifact must match the current production Swift sources,
manifest, and lockfile. A stale artifact is rejected rather than treated as
qualification of the current binary.

## What constitutes a result

Success requires convergence, wire/native/Swift/CLI agreement, expected event
ordering, restoration of every probe, collector cleanup, and complete captures.
Only the enclosing verifier's final `result.json` indicates overall success;
a per-capture `audit-candidate.json` proves only that individual audit.

UPDATE-level diagnostics remain observable even for withdrawals or End-of-RIB
messages that produce no upsert record. Historical log replay accepts the older
`AS ?` label; new output must use `AS not-advertised` or a numeric ASN. Retained
fixtures and logs are not rewritten to match presentation changes.

[Previous qualification](VALIDATION.md) covers the documented ARM64 versions.
A candidate's offline replay is useful evidence but does not replace a fresh
live demonstration on that candidate.
