# Security policy

## Versions to report

We accept security reports for `0.1.0` and for builds from public `main`.
Include the output of `bgpls --version` for the CLI. If you built from a Git
checkout, include the commit from `git rev-parse HEAD`.

## Report a vulnerability privately

Sign in to GitHub and use the [private vulnerability reporting form](https://github.com/RouteObjects/bgpls/security/advisories/new)
to contact the maintainers. You can also find **Report a vulnerability** on the
repository’s **Security** tab.

Include the affected version or commit, operating system, reproduction steps,
expected and observed behavior, and potential impact. Share only the evidence
needed to investigate the issue. Remove credentials and unrelated topology
from captures and logs before attaching them.

## Deployment scope

`bgpls` initiates a BGP-LS connection to a configured peer. It does not provide
TCP authentication, TLS, peer authorization infrastructure, reconnection
supervision, or an operational isolation boundary. Use network access controls
and a trusted, explicitly configured collection path.

The decoder processes peer-supplied data. Existing framing checks, bounded
pending UPDATE admission, and typed validation do not bound every resource:
topology growth, retained snapshots, capture-file growth, subscriber buffers,
and work owned by the embedding application require separate limits. Pending
PCAP data has the per-capture byte and chunk limits described below.

Packet captures, topology snapshots, and logs can disclose network structure,
addresses, node names, and peer identities. Protect their storage and review
them before sharing. The reference lab uses synthetic topology; vendor images
must be obtained under the vendor's own terms.

## Capture-file safety

`--pcap FILE`, `--pcap-auto`, and the library's `pcapPath` require a new output
file in a trusted directory. `--pcap-auto` opts into capture in the current
working directory; choose a directory you control before running it. Capture is
disabled unless one CLI option is supplied; supplying both is a validation error.
Automatic names include a UTC timestamp, the configured numeric peer address
and port, and a full UUID. The address can identify a relay rather than the
topology producer, and the filename itself can disclose that endpoint.

Creation is exclusive and does not follow the final path component:
existing files, symbolic links, directories, and special files are refused
without modification. New files request owner-only `0600` permissions, subject
to a more restrictive umask. Automatic naming does not probe for available
filenames, overwrite, or retry a collision. The escaped absolute path printed
before session creation reports selection, not successful file creation.

The sink opens the parent directory once and writes through the newly created
file descriptor. Ordinary parent-directory symlinks are supported, including
macOS `/tmp`; this does not protect against an untrusted owner of an ancestor
directory. Select a directory you control and protect its access permissions.

Creation and initial header-write failures stop setup before a TCP connection.
A failed setup can leave a newly created partial capture for inspection. Later
capture-write errors are logged and collection continues; normal session
completion is not proof of capture completeness. Review capture errors before
relying on the file as evidence.

The sink limits each capture to **8 MiB of pending encoded PCAP bytes** and
**4,096 pending chunks**, including the active write. Accepted chunks use
independent compact storage; the byte metric excludes allocator and queue
metadata, whose item count is bounded separately. These limits do not bound
the whole process or the capture file's eventual size.

Exceeding either limit rejects that entire chunk and disables capture for the
rest of the session. Accepted chunks drain and the file closes, while BGP
collection continues. The retained file contains only the capture prefix if
those writes succeed; a filesystem error can leave a partial record. The
warning identifies the incomplete capture and escapes path control characters.
It runs on the file queue before close completion, so it may wait behind
stalled I/O. No filesystem-operation or shutdown deadline is introduced.

Capture rotation, storage quotas, and a policy for terminating collection after
a capture failure remain the application's responsibility.
