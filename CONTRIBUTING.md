# Contributing

`bgpls` contains a reusable `BGPLSClient` library, a foreground CLI, and a
reproducible reference lab. Keep protocol and collection behavior in the
library; process signals and presentation belong to the CLI.

## Development setup

Use Swift 6.3 or later. macOS builds require macOS 15 or later; Linux builds use
Swift's supported toolchain environment. The package declares an iOS 18 library
deployment floor; that compile check is separate from the macOS/Linux CLI.

Resolve dependencies through SwiftPM. A release qualification must use the
published dependency versions, without sibling checkouts or local package
overrides. Never commit vendor image archives, build caches, deployment copies,
or generated captures as part of a code change.

## Offline checks

Run from the repository root:

```sh
./scripts/test.sh
swift build --target BGPLSClient
swift build --target BGPLSCLI
swift build --product bgpls
swift format lint --strict --configuration .swift-format.json --recursive Sources Tests
python3 -m unittest discover -s lab-examples/bgpls/tests -p 'test_*.py'
bash lab-examples/bgpls/tests/test-workflows.sh
python3 scripts/check-public-docs.py
git diff --check
```

The Swift tests include bounded loopback sessions and retained-message fixtures;
they do not need a vendor lab. The Python and mocked workflow tests exercise lab
tooling without deploying it. Run live qualification only as an explicitly
scoped operation, following the [lab instructions](lab-examples/bgpls/README.md).

The opt-in synthetic backpressure harness is separate from ordinary unit tests.
Record the toolchain, workload, concurrency, measurement boundaries, and timeout
with any performance claim. A synthetic result is not a production capacity
guarantee.

## Review expectations

- Use Swift Testing for focused regressions. Preserve public error identities,
  accepted wire behavior, and cleanup ordering unless the change explicitly
  proposes otherwise.
- Keep protocol decisions on the event loop and application callbacks/RIB work
  on the session actor. Avoid new unchecked concurrency annotations and a task
  per UPDATE.
- Preserve raw evidence when adding a typed interpretation. Missing data is not
  zero, and topology identity is separate from the complete observation.
- Test atomic failure, withdrawals, refreshes, watch delivery, and shutdown when
  changing UPDATE processing. Exact replay assumes no subscriber event loss.
- Keep examples free of forced unwraps, forced casts, and forced `try`. Prefer
  explicit, safely constructed session configuration.
- Document limitations and reproducible validation. Do not include private
  filesystem paths, physical-network configurations, credentials, or vendor
  archives in public files or fixtures.

The first release is prepared as a source package. API changes before 1.0 need
clear migration notes. Keep unrelated cleanup separate so reviewers can assess
behavioral changes and their tests together.

See the [architecture](Documentation/Architecture.md),
[protocol scope](Documentation/ProtocolSupport.md), and [security policy](SECURITY.md)
before proposing changes to those boundaries.
