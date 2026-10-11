# crun threat model

This document describes what crun considers a security vulnerability. It
expands on the security scope in [SECURITY.md](SECURITY.md), which is
authoritative.

## What crun is

crun is a low-level OCI container runtime written in C. Given an OCI runtime
configuration (`config.json`) and a root file system, it creates and configures
the Linux isolation primitives (namespaces, cgroups, capabilities, seccomp,
devices, mounts, LSM labels) and then executes the container process. It can
also be used as a library (`libcrun`), run WebAssembly workloads through
handlers, and start containers in a VM through libkrun.

crun is not a container engine or daemon (Podman, CRI-O, containerd), an image
builder or puller, an orchestrator, a hypervisor, or a network or storage
manager. It is invoked by an engine, usually on behalf of an unprivileged or
privileged user.

## Core principle

crun is responsible for correctly enforcing the isolation that the OCI
configuration asks for. If crun implements what `config.json` requests and the
container behaves as configured, there is no crun vulnerability, even if the
configuration is insecure. A vulnerability exists when untrusted content makes
crun's actual behavior weaker than the isolation it was asked to provide.

## Assets

- The host file system, processes and kernel state outside the container.
- The privileges of the user running crun (root or rootless).
- Other containers running on the same host.
- The integrity of the security policy requested for the container
  (capabilities, seccomp, LSM, masked/read-only paths, no-new-privileges).

## Trust boundaries

| Input | Trust level | Notes |
|-------|-------------|-------|
| OCI runtime configuration (`config.json`) | **Trusted** | Provided by the container engine, which is responsible for validating user input. |
| Command line, environment, `--root`, `--log`, console socket, pid file paths | **Trusted** | Provided by the engine/operator. |
| crun-specific annotations, including the ones listed under `potentiallyUnsafeConfigAnnotations` in `crun features` | **Trusted** | Callers must validate them; they intentionally weaken isolation. |
| Container rootfs contents (binaries, libraries, symlinks, device nodes, mount points, `/proc` and `/sys` content seen from inside) | **Untrusted** | Primary attacker-controlled input. |
| Processes running inside the container | **Untrusted** | They can race crun while it is setting up the container. |
| Files read from the rootfs by crun (e.g. `/etc/passwd`, `/etc/group`, `/etc/hosts` handling, `/etc/ld.so.*`, shared libraries loaded by handlers) | **Untrusted** | |
| Bundle files other than `config.json` and the rootfs | Trusted | Provided by the engine. |

## Attacker model

The attacker controls the contents of a container image/rootfs and the code
running inside the container, but does not control `config.json`, crun's
arguments, or the host. The attacker's goals are to:

1. Escape the container (read or write host files, access host processes or
   namespaces).
2. Escalate privileges (gain capabilities, bypass user namespace mappings,
   gain root on the host).
3. Bypass the security policy configured for the container (seccomp, LSM,
   capabilities, masked paths, read-only paths, cgroup limits).
4. Compromise other containers or the container engine.

## In scope (vulnerabilities)

- Symlink, bind-mount, `..` traversal, or mount-point tricks in the rootfs
  that make crun read, write, mount, chmod/chown or create files outside the
  rootfs (TOCTOU races included, e.g. against `openat2`/`O_PATH` based
  resolution, `/proc/self/fd` usage, and mount destination handling).
- Memory-safety or parsing bugs triggered by attacker-controlled rootfs data
  (e.g. when crun parses `/etc/passwd`, `/etc/group`, or other files located
  inside the container) that lead to code execution in crun's context.
- File system layouts that cause crun to apply an incorrect or weaker security
  policy than the one requested (e.g. dropped seccomp filter, missing
  capability drop, skipped masked/readonly paths, wrong LSM label).
- Leaking host file descriptors, host mounts or host namespaces into the
  container process, or leaving the container process able to reach them.
- Races between crun's setup phase and container processes that let the
  container affect crun's behavior (`/proc/<pid>` handling, `exec` into a
  running container, `crun exec` joining namespaces/cgroups, checkpoint and
  restore handling).
- Container escape through crun's own binary, e.g. re-executing a
  rootfs-controlled copy of crun (see the cloned-binary protection against
  CVE-2019-5736 style attacks).
- Privilege escalation in the rootless path (user namespace setup,
  `newuidmap`/`newgidmap` interaction, `/proc/self/uid_map` handling).

## Out of scope (not vulnerabilities)

- Anything that requires a malicious or crafted `config.json`, e.g. mounting
  host paths, granting all capabilities, disabling seccomp, mapping UID 0, or
  requesting host namespaces. These are explicit configuration requests.
- Misuse of `potentiallyUnsafeConfigAnnotations`; validating them is the
  responsibility of the caller.
- Bugs that need the attacker to already control the host, the container
  engine, crun's command line or environment, or the crun binary itself.
- Denial of service by a container against itself, or resource exhaustion that
  is bounded by the cgroup limits the engine requested. If crun fails to apply
  limits that are present in the configuration, that is in scope.
- Kernel vulnerabilities or weaknesses in kernel isolation primitives
  (namespaces, cgroups, seccomp, LSMs) that crun merely uses.
- The shared-kernel model of containers: containers run on the host kernel by
  design, and stronger isolation needs a hypervisor-based runtime.
- The content of container images (malicious binaries, vulnerable libraries,
  leaked secrets). crun does not build, pull or scan images; only a rootfs
  that tricks crun itself is in scope.
- Vulnerabilities in third-party WebAssembly runtimes, libkrun, CRIU,
  libseccomp, libcap, systemd or other dynamically loaded libraries; these
  should be reported to the respective projects unless crun misuses them.
- Issues only reproducible in unsupported or end-of-life releases (see
  "Supported Versions" in SECURITY.md).
- Findings in tests, CI configuration, documentation, fuzzing harnesses and
  build scripts (`build-aux/`, `tests/`, `contrib/`) that do not affect the
  shipped runtime binary. Supply-chain concerns about the release process are
  welcome but are tracked as ordinary issues.

## Existing mitigations

- Path resolution confined to the rootfs using `openat2`/`O_PATH` and
  descriptors rather than string paths where possible.
- Execution through a sealed memfd clone of the crun binary
  (`cloned_binary.c`) to defend against binary overwrite.
- Fuzzing (honggfuzz), AddressSanitizer runs, `clang-check` and
  `clang-format` in CI.

## Components that matter most

The code that handles the container rootfs and applies the security policy:
rootfs and mount setup, path resolution, namespace and user namespace setup,
`exec` into a running container, seccomp and capabilities, cgroup setup, and
the container state files that later crun invocations read back. The sealed
copy of the crun binary also matters.

Less important: the generated OCI JSON parser in `libocispec/` (it only reads
the trusted `config.json`), the bundled BLAKE3 code, packaging, documentation,
the bindings and `tests/`.

## How to exercise it

- Build with `./autogen.sh && ./configure && make`; the binary is `./crun`.
- `make check` (run as root, or with `unshare -r`) runs the C unit tests in
  `tests/tests_libcrun_*.c` and the Python tests `tests/test_*.py`. The tests
  build a throwaway bundle with `tests/init` as the container process; see
  `tests/tests_utils.py` for how a rootfs and a `config.json` are generated.
- To run a container by hand, create a bundle with `mkdir rootfs`, copy a
  static binary such as `tests/init` into it, run `./crun spec`, set the
  process args in the generated `config.json`, then `./crun run <id>`.
- `tests/fuzzing/` has the honggfuzz setup. `gdb` is installed.
- Only the rootfs content and the code running in the container are attacker
  controlled. A realistic proof of concept builds a malicious rootfs (for
  example one containing symlinks, odd mount points or device nodes), runs it
  through a container engine, and shows a read, write or privilege effect on
  the host. Running crun by hand, as above, is fine for development, but it
  does not by itself demonstrate a vulnerability; see "Reporting".

## How to rate severity

- Critical: a container escape or host file write/read from an unprivileged
  container with a default-like `config.json`, or code execution on the host
  as root, using only attacker-controlled rootfs content.
- High: a bypass of the requested security policy (seccomp, capabilities,
  masked or read-only paths, LSM, no-new-privileges) or a memory-safety bug
  reachable from rootfs content, without a demonstrated escape.
- Medium: an information leak from the host or from another container, or a
  local denial of service against the host or the container engine that
  crosses cgroup limits.
- Low: hardening issues, and bugs that need unusual but still trusted
  configuration.
- Anything that needs control of `config.json`, the annotations marked unsafe,
  or the command line is out of scope (see above), whatever the impact.

## Anything to leave alone

- Do not report behavior that follows directly from what `config.json` asks
  for (host mounts, added capabilities, disabled seccomp, host namespaces).
- Do not report build, packaging, CI, test or documentation issues.
- Do not report problems in the kernel, libseccomp, libcap, CRIU, systemd or
  other libraries unless crun uses them incorrectly.
- Do not report a crash that only happens when running crun as a library with
  invalid arguments from a trusted caller.

## Reporting

The proof of concept must use at least one high-level container runtime or
engine (for example Podman, CRI-O, containerd or Kubernetes) and must not
invoke crun directly. When crun is invoked directly, the reporter controls
`config.json`, which is trusted, so the issue cannot be told apart from an
explicit configuration request. If an issue can only be reproduced by running
crun directly, it is not a crun vulnerability.

Prefer a short reproducer and a small patch that matches the surrounding code
style (see `AGENTS.md`).

Report suspected vulnerabilities privately through GitHub Security Advisories:
<https://github.com/containers/crun/security>.
