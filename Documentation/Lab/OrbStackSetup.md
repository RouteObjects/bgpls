# One-time OrbStack setup

Use this walkthrough to prepare a **new Ubuntu 24.04 ARM64 machine** for the
[terminal-first lab quickstart](../../lab-examples/bgpls/README.md). Swift and
the native `bgpls` collector run on an Apple Silicon Mac with macOS 15 or newer;
Docker Engine and Containerlab run in the selected Linux machine.

Install [OrbStack](https://docs.orbstack.dev/install) and an official
[Swift toolchain](https://www.swift.org/install/macos/) first. The Mac needs
Swift 6.3 or newer, Python 3.9 or newer as `python3`, and Bash; the macOS system
Bash is sufficient. This walkthrough uses OrbStack 2.2.5 command syntax,
Ubuntu Noble, and **Containerlab 0.83.0**. Docker packages come from Docker's
stable Ubuntu repository; the verification step prints their installed versions.

The commands below create a machine, install its tools, and run Docker's small
`hello-world` check. Lab deployment is a separate step. Keep an existing machine
and its lab state intact: the creation block refuses to reuse an existing name.

## 1. Select the machine and check the Mac

In macOS Terminal, enter the `bgpls` repository root and start a dedicated Bash
shell. Run the remaining blocks in order in that same shell. A failed command
stops this shell; inspect the failure before continuing.

<!-- setup-block: host-shell -->
```sh
bash
```

The public default is `clab`. For a fresh-machine rehearsal alongside an
existing lab, set `export CLAB_MACHINE=bgpls-setup-rehearsal` before running the
next block. Keep that export in every Terminal used for the subsequent lab
commands. Each guest command below selects the machine explicitly using
[OrbStack's `-m` option](https://docs.orbstack.dev/machines/commands).

<!-- setup-block: host-preflight -->
```sh
set -euo pipefail
export CLAB_MACHINE="${CLAB_MACHINE:-clab}"
[[ "$CLAB_MACHINE" =~ ^[a-z][a-z0-9-]*$ ]]
[[ $(uname -s) == Darwin && $(uname -m) == arm64 ]]
test "$(sw_vers -productVersion | cut -d . -f 1)" -ge 15
test -f lab-examples/bgpls/common.sh

sw_vers
bash --version
python3 --version
SWIFT_VERSION=$(swift --version)
printf '%s\n' "$SWIFT_VERSION"
python3 - "$SWIFT_VERSION" <<'PY'
import re
import sys

if sys.version_info < (3, 9):
    raise SystemExit("Python 3.9 or newer is required.")
match = re.search(r"\bSwift version (\d+)\.(\d+)", sys.argv[1])
if not match or tuple(map(int, match.groups())) < (6, 3):
    raise SystemExit("Swift 6.3 or newer is required.")
PY
orb version
printf 'Selected Linux machine: %s\n' "$CLAB_MACHINE"
```

## 2. Create a fresh Ubuntu machine

The explicit `ubuntu:noble` distribution selects Ubuntu 24.04; see
[OrbStack's distribution selection](https://docs.orbstack.dev/machines/distros).
First check that the selected name is unused. A failed machine-list command
also stops setup; it is not treated as an empty inventory.

<!-- setup-block: machine-name-check -->
```sh
BGPLS_EXISTING_MACHINES=$(orb list --quiet)
if printf '%s\n' "$BGPLS_EXISTING_MACHINES" | grep -Fxq -- "$CLAB_MACHINE"; then
    printf 'Machine %s already exists; refusing to reuse it.\n' "$CLAB_MACHINE" >&2
    exit 1
fi
```

For the normal lab host, create the machine with OrbStack's default resource
settings. No fixed memory minimum has been established for the router lab.

<!-- setup-block: create-machine -->
```sh
orb create --arch arm64 ubuntu:noble "$CLAB_MACHINE"
```

For a **setup-only rehearsal**, use the following bounded creation block
**instead of** the preceding creation block. It limits memory to 4 GiB, CPU use to two CPUs,
and 32 GiB disk for `bgpls-setup-rehearsal`. These limits are not a qualification
of router-lab capacity or of the optional cEOS profile.

<!-- setup-block: create-rehearsal-machine -->
```sh
[[ "$CLAB_MACHINE" == bgpls-setup-rehearsal ]]
orb create --arch arm64 --memory 4G --cpus 2 --disk 32G \
  ubuntu:noble "$CLAB_MACHINE"
```

Check the guest before installing anything. Expect `ubuntu`, `24.04`, `noble`,
and native `aarch64`/`arm64` architecture.

<!-- setup-block: guest-preflight -->
```sh
orb -m "$CLAB_MACHINE" -u root bash -s <<'LINUX'
set -euo pipefail
. /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]]
[[ "$VERSION_CODENAME" == noble ]]
[[ $(uname -m) == aarch64 && $(dpkg --print-architecture) == arm64 ]]
printf 'Guest: %s %s (%s)\n' "$ID" "$VERSION_ID" "$VERSION_CODENAME"
uname -m
dpkg --print-architecture
LINUX
```

## 3. Install Docker Engine in the guest

This follows Docker's [signed APT repository installation for Ubuntu](https://docs.docker.com/engine/install/ubuntu/#install-using-the-apt-repository).
The additional `iproute2` and `python3` packages support the lab scripts.
All commands run as root in the selected new machine, so no Docker-group or
passwordless-sudo configuration is needed.

<!-- setup-block: install-docker -->
```sh
orb -m "$CLAB_MACHINE" -u root bash -s <<'LINUX'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl iproute2 python3
install -d -m 0755 /etc/apt/keyrings
curl --fail --silent --show-error --location \
  https://download.docker.com/linux/ubuntu/gpg \
  --output /etc/apt/keyrings/docker.asc
chmod 0644 /etc/apt/keyrings/docker.asc
cat > /etc/apt/sources.list.d/docker.sources <<'APT'
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: noble
Components: stable
Architectures: arm64
Signed-By: /etc/apt/keyrings/docker.asc
APT
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
systemctl is-active --quiet docker
LINUX
```

## 4. Install the required Containerlab release

Use the ARM64 Debian package from the official
[Containerlab 0.83.0 release](https://github.com/srl-labs/containerlab/releases/tag/v0.83.0).
It includes the native FRR startup fix from
[PR #3555](https://github.com/srl-labs/containerlab/pull/3555): `vtysh` stays
callable while Containerlab installs its configuration-save wrapper, avoiding
the startup window in which FRR could fail to load its configuration.
Fresh deployments require stable 0.83.0 or newer; this guide pins 0.83.0.
Fresh 0.83.0 installation, FRR startup, and bounded churn verification passed on
2026-11-15. The ten-second flap did not expose withdrawals, and scoped teardown
was not attempted so that run could be preserved. See the
[rehearsal results](../../lab-examples/bgpls/VALIDATION.md#2026-11-15-containerlab-0830-fresh-frr-only-rehearsal).

The block downloads that release's checksum list, verifies the selected package,
checks its metadata, and installs it. Any failed download or checksum stops the
installation. The [Containerlab installation reference](https://containerlab.dev/install/)
also documents package installation; its all-in-one setup script configures
additional host services, including SSH, and is outside this walkthrough.

<!-- setup-block: install-containerlab -->
```sh
orb -m "$CLAB_MACHINE" -u root bash -s <<'LINUX'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
CLAB_VERSION=0.83.0
CLAB_PACKAGE="containerlab_${CLAB_VERSION}_linux_arm64.deb"
CLAB_RELEASE="https://github.com/srl-labs/containerlab/releases/download/v${CLAB_VERSION}"
CLAB_DOWNLOAD_DIR=$(mktemp -d /tmp/bgpls-containerlab.XXXXXX)
chmod 0755 "$CLAB_DOWNLOAD_DIR"
cd "$CLAB_DOWNLOAD_DIR"
curl --fail --silent --show-error --location \
  "$CLAB_RELEASE/$CLAB_PACKAGE" --output "$CLAB_PACKAGE"
curl --fail --silent --show-error --location \
  "$CLAB_RELEASE/checksums.txt" --output checksums.txt
awk -v package="$CLAB_PACKAGE" \
  '$2 == package { print; matches++ } END { if (matches != 1) exit 1 }' \
  checksums.txt > selected-checksum.txt
sha256sum --check selected-checksum.txt
[[ $(dpkg-deb --field "$CLAB_PACKAGE" Package) == containerlab ]]
[[ $(dpkg-deb --field "$CLAB_PACKAGE" Version) == "$CLAB_VERSION" ]]
[[ $(dpkg-deb --field "$CLAB_PACKAGE" Architecture) == arm64 ]]
apt-get install -y "./$CLAB_PACKAGE"
[[ $(containerlab version --short) == "$CLAB_VERSION" ]]
printf 'Retained package and checksum evidence: %s\n' "$CLAB_DOWNLOAD_DIR"
LINUX
```

The package and checksum files remain in the printed guest directory for
inspection. Copy any evidence you need to retain before removing those files
or the rehearsal machine.

## 5. Verify the guest runtime

The lab scripts require the guest's local Unix socket, a nonempty daemon ID,
and no `DOCKER_HOST` or `DOCKER_CONTEXT` override in the guest. The following
checks compare the selected context's daemon ID with the daemon reached through
`unix:///var/run/docker.sock`, print the tool versions, and run Docker's
`hello-world` check. The test container is removed after it exits.

<!-- setup-block: verify-runtime -->
```sh
orb -m "$CLAB_MACHINE" -u root bash -s <<'LINUX'
set -euo pipefail
[[ -z ${DOCKER_HOST:-} && -z ${DOCKER_CONTEXT:-} ]]
test -S /var/run/docker.sock
DOCKER_ENDPOINT=$(docker context inspect --format '{{.Endpoints.docker.Host}}')
[[ "$DOCKER_ENDPOINT" == unix:///var/run/docker.sock ]]
DOCKER_DAEMON_ID=$(docker info --format '{{.ID}}')
[[ -n "$DOCKER_DAEMON_ID" ]]
[[ "$DOCKER_DAEMON_ID" == "$(docker --host unix:///var/run/docker.sock info --format '{{.ID}}')" ]]
[[ $(docker info --format '{{.OSType}}') == linux ]]
case "$(docker info --format '{{.Architecture}}')" in
    arm64|aarch64) ;;
    *) printf 'Expected a native ARM64 Docker daemon.\n' >&2; exit 1 ;;
esac
[[ $(containerlab version --short) == 0.83.0 ]]
python3 -c 'import sys; assert sys.version_info >= (3, 9)'
printf 'Docker endpoint: %s\nDaemon ID: %s\n' "$DOCKER_ENDPOINT" "$DOCKER_DAEMON_ID"
command -v docker containerlab python3 ss
docker version
docker buildx version
docker compose version
containerlab version
python3 --version
dpkg-query -W docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin containerlab
docker run --rm hello-world
LINUX
```

Expect Linux/ARM64, `unix:///var/run/docker.sock`, a nonempty daemon ID,
Containerlab `0.83.0`, and `Hello from Docker!`. If an endpoint or environment
check fails, inspect the selected guest's configuration before proceeding. The
Mac's separate Docker engine and Docker context are not used by these commands.

## 6. Verify shared absolute paths

OrbStack exposes [Mac files at their Mac absolute paths](https://docs.orbstack.dev/machines/file-sharing).
The repository and the parent of the future deployment directory must be
accessible using the **same paths** on both systems. Run this from the `bgpls`
repository root; the example prepares `$HOME/clabs` as the external parent.

<!-- setup-block: verify-shared-paths -->
```sh
BGPLS_REPOSITORY=$(pwd -P)
BGPLS_LAB_PARENT="${BGPLS_LAB_PARENT:-$HOME/clabs}"
test -f "$BGPLS_REPOSITORY/lab-examples/bgpls/common.sh"
mkdir -p "$BGPLS_LAB_PARENT"
BGPLS_LAB_PARENT=$(cd "$BGPLS_LAB_PARENT" && pwd -P)
case "$BGPLS_LAB_PARENT" in
    "$BGPLS_REPOSITORY"|"$BGPLS_REPOSITORY"/*)
        printf 'Choose a deployment parent outside the repository.\n' >&2
        exit 1
        ;;
esac
orb -m "$CLAB_MACHINE" -u root bash -s -- \
  "$BGPLS_REPOSITORY" "$BGPLS_LAB_PARENT" <<'LINUX'
set -euo pipefail
test -f "$1/Package.swift"
test -f "$1/lab-examples/bgpls/common.sh"
test -d "$2"
printf 'Shared repository: %s\nShared deployment parent: %s\n' "$1" "$2"
LINUX
```

Choose a new or empty deployment directory beneath that parent when following
the [quickstart](../../lab-examples/bgpls/README.md). Retain the exported
`CLAB_MACHINE` selection when deploying, verifying, and destroying that lab;
repeat the same export in additional Terminals. Collector preparation's
separate `--machine` option is shown in the
[IPv6 transport recipe](ScriptExamples.md#ipv6-session-transport).

A fresh-machine rehearsal uses `bgpls-setup-rehearsal` throughout these steps.
Keep its terminal logs and any later smoke-test evidence outside the repository.
Successful setup establishes the runtime prerequisites; the separate
[qualification summary](../../lab-examples/bgpls/VALIDATION.md) describes the
router and collector validation boundary.

After all checks pass, turn off setup's exit-on-error mode before using the
interactive quickstart. The collector deliberately returns `130` after Ctrl-C;
that expected status must not close this shell and lose the selected machine
and deployment variables.

<!-- setup-block: finish-setup -->
```sh
set +e
```

## Troubleshooting and existing labs

| Symptom | Check before continuing |
| --- | --- |
| Machine name already exists | Choose a fresh name and export it consistently; do not reuse or delete an existing machine as part of this walkthrough. |
| Wrong distribution or architecture | Confirm `ubuntu:noble` and `--arch arm64` were used; retain the failed machine for inspection. |
| Docker is unavailable | Check `systemctl status docker` in the selected guest and the installation output. Do not switch the Mac's Docker context to hide the failure. |
| Docker endpoint or environment check fails | Inspect the selected guest's context and environment; the lab requires its local `/var/run/docker.sock` daemon. |
| A shared path is missing | Confirm the same absolute path exists on macOS and in this machine. Do not substitute a path into another checkout or deployment. |
| Download or checksum fails | Retain the download and error output; verify the release URL and retry only after identifying the cause. |
| The Containerlab package prints `usermod: user '' does not exist` | Observed in the root-based 0.81.1 and 0.83.0 setup runs when no sudo user was present. The 0.83.0 installer returned success and all runtime checks passed. This walkthrough runs guest commands as root; check the installer exit status and complete the runtime checks. |
| Lab deployment reports a collision | An existing lab or listener owns that name, network, or port. Creating a second machine does not automatically isolate macOS localhost ports. |

The supplied bgpls profiles use localhost port `11790` and optionally `11791`.
Keep an existing lab intact during a setup-only rehearsal: do not run the
quickstart's deployment, verification, churn, or destruction commands against it.
Host setup can be checked with separately named test resources and unused ports;
the [packaged operator walkthrough](Operators/GettingStarted.md#running-alongside-an-existing-lab)
explains how to deploy in a network-isolated guest and reach its relay through a
dedicated SSH forward when another lab occupies the default Mac port. Keep
global OrbStack forwarding and networking settings as configured.
