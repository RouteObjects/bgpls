# Lab prerequisites

The recommended demonstration uses macOS Terminal for a native `bgpls` process
and an OrbStack Linux machine named `clab` for Docker and Containerlab. Install
and verify the prerequisites before running the [quickstart](../../lab-examples/bgpls/README.md).
The scripts deploy the lab; they do not install host software.

## Versions and capacity

| Component | Required by the supplied workflow | Qualification boundary |
| --- | --- | --- |
| Swift | 6.3 or newer | Package tests target Swift 6.3 |
| macOS | 15 or newer | Native collector on Apple Silicon |
| Bash | Available on the script host | macOS system Bash is sufficient |
| Python | 3.9 or newer, as `python3` | Standard-library lab tooling |
| Docker | Linux daemon with local Unix socket | Native ARM64 lab validation |
| Containerlab | Stable 0.83.0 or newer for fresh deployments | 0.83.0 passed the packaged FRR-only exercise with both withdrawals, exact restoration, and scoped teardown |
| OrbStack | Linux-machine support, for macOS | Required only for the macOS lab host |
| Linux guest tools | Bash, Python 3, curl, CA certificates, and iproute2 (`ip`/`ss`) | Installed by the one-time setup guide |
| cEOS | Optional entitled ARM64 4.36.2F image | Supplied profile requires native ARM64 |

A newer Containerlab version passing the version check is not automatically a
qualified combination. See the [validation summary](../../lab-examples/bgpls/VALIDATION.md).
The minimum includes [PR #3555](https://github.com/srl-labs/containerlab/pull/3555),
which keeps `vtysh` callable while installing the configuration-save wrapper so
FRR can load its startup configuration. Existing recorded deployments remain
inspectable and removable with their original runtime; the minimum applies only
to fresh deployment.
No fixed memory minimum has been established for this example. Allow resources
for five or six routers, the relay, and Swift builds; the cEOS profile is heavier.
Package tests on AMD64 do not qualify an AMD64 vendor lab.

## macOS and OrbStack

Follow the [one-time OrbStack setup guide](OrbStackSetup.md) for the complete
Terminal procedure: check the Mac tools, create a fresh native ARM64 Ubuntu
24.04 machine, install Docker Engine inside it, and install Containerlab 0.83.0.
It includes expected results and troubleshooting. The normal machine name is
`clab`; the guide also explains how to use another name consistently.

Creating the Linux host is separate from deploying the routers. Installing a
tool on macOS or using OrbStack's separate top-level Docker engine does not
satisfy this workflow. For an already prepared host, check these versions and
the selected daemon from macOS Terminal:

```sh
orb -m "${CLAB_MACHINE:-clab}" -u root docker info --format '{{.OSType}}/{{.Architecture}}'
orb -m "${CLAB_MACHINE:-clab}" -u root docker context inspect --format '{{(index .Endpoints "docker").Host}}'
orb -m "${CLAB_MACHINE:-clab}" -u root containerlab version --short
```

Expect Linux/ARM64 (the architecture may be spelled `aarch64`), the local socket
`unix:///var/run/docker.sock`, and stable Containerlab 0.83.0 or newer. The
scripts reject `DOCKER_HOST` or `DOCKER_CONTEXT` overrides and alternate daemon
endpoints. They use [OrbStack machine commands](https://docs.orbstack.dev/machines/commands)
to target `clab`, not whichever Docker context is selected in your Mac shell.
Set `CLAB_MACHINE` consistently if you intentionally use a different machine.
Collector preparation takes a separate `--machine` option; the
[preparation recipe](ScriptExamples.md#ipv6-session-transport) forwards
`"${CLAB_MACHINE:-clab}"` explicitly.

The repository and external deployment directory must be accessible from that
machine at the same absolute paths. OrbStack shares macOS files; confirm your
chosen parent directory is accessible before deployment. Keep state outside the
repository, use a new or empty directory, and avoid symlinked paths. Reserve
localhost TCP port `11790`, plus `11791` for cEOS. Check that the documented
management, loopback, and link networks do not overlap other labs or routes.

## Native Linux alternative

Install Swift, Bash, Python, Docker, and Containerlab on the Linux host. Run the
same repository scripts directly; they automatically omit the OrbStack wrapper.
The invoking account needs local Docker access. Containerlab deployment and
removal need root or `sudo`; Docker access is not automatically elevated.

The default FRR image is multi-architecture, but live qualification here was
native ARM64. The supplied cEOS and prepared-container collector workflows
explicitly require ARM64. Do not describe emulation as native validation.

## Images

The YAML files pin FRR and HAProxy by digest. FRR uses the **Containerlab-packaged**
`containerlab-10.7.1` image with the native `frr` kind; do not replace it with a
plain FRR tag that has different startup integration. Containerlab selects the
matching platform from the pinned multi-platform manifest.

| Role | Pinned image |
| --- | --- |
| FRR | `quay.io/frrouting/frr:containerlab-10.7.1@sha256:f7d98e4faa24333c1fdb638f72678111de07a7aef90566132655dbadceca86c7` |
| TCP relay | `docker.io/library/haproxy:3.0.27-alpine@sha256:30860bc97b3a4b1e48011ce0687d4ba1e4711344af8480c4bec85e3ff8411fee` |
| Optional cEOS | Locally imported `ceosarm:4.36.2F`; never pulled automatically |

The [cEOS instructions](../../lab-examples/bgpls/CEOS.md) cover entitlement,
integrity checks, and import. Keep vendor archives and credentials outside the
repository. FRR-only operation does not require a vendor account.

## Optional VS Code view

Install VS Code with Remote–SSH on the Mac. Use OrbStack's
[SSH integration](https://docs.orbstack.dev/machines/ssh) to connect to `clab@orb`,
then install the [Containerlab extension](https://containerlab.dev/manual/gui/vsc-extension/)
**on the remote Linux host**. Open the shared deployment directory there to
view topology, open router terminals, and read container logs.

Continue deploying and destroying with the repository scripts from macOS
Terminal. Generic extension lifecycle actions bypass this project's ownership,
configuration-hash, and evidence checks. Keep the native collector in macOS
Terminal as well. No VS Code tasks, devcontainer, or editor-specific setup is
needed for the demonstration.
