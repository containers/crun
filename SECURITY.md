# **Reporting a Security Vulnerability or Incident**

Please do not report security vulnerabilities or security incidents via public channels (such as GitHub Issues or Pull Requests). To ensure coordinated disclosure, submit your findings through [GitHub Security Advisories](https://github.com/containers/crun/security).

## **Submission Guidelines**

To help us triage and resolve the issue efficiently, please include the following in your report:

- **Title**: A concise, descriptive summary of the issue.
- **Reporter Details**: Your name/handle and affiliation.
- **Technical Description**: Detailed information regarding the vulnerability.
- **Affected Versions**: The specific version(s) or range(s) of software tested.
- **Reproduction Steps**: A minimal, functional example to reproduce the issue.
- **Impact Assessment**: Potential exploit scenarios and perceived severity. (optional)
- **Suggested Fix**: Any proposed patches or mitigations (optional).
- **Disclosure Status**: Whether this has been shared with other parties or published and your plan for future sharing (e.g., at a conference).

## **Response Timeline**

We aim to provide an initial acknowledgement of your report within 3 business days.

Our goal is to assess the report, coordinate fix and disclosure as quickly as possible. All confirmed security vulnerabilities and incidents will be addressed according to severity level and impact on the project.

## **Contact Information**

Direct all security questions and vulnerability reports to:

- **GitHub**: [Security Advisories](https://github.com/containers/crun/security)

## **Security Scope**

### What is considered a security vulnerability

A security vulnerability is any issue where untrusted content can be used to escape the container sandbox, escalate privileges, or otherwise compromise the host. The primary source of untrusted content is the **container rootfs** — everything inside it (binaries, libraries, symlinks, device nodes, etc.) must be treated as potentially malicious. For example:

- A crafted symlink or mount point inside the rootfs that tricks crun into writing or reading files on the host.
- A malicious binary in the rootfs that exploits a parsing bug in crun to escape the container.
- A specially crafted file system layout that causes crun to apply incorrect security policies.

### What is NOT considered a security vulnerability

The **OCI runtime configuration** (`config.json`) is expected to come from a trusted source, such as a container engine (e.g., Podman, CRI-O, containerd). Issues that require a malicious `config.json` to exploit are **not** considered security vulnerabilities, because an attacker who controls `config.json` already has the ability to configure arbitrary namespaces, mounts, and capabilities. For example, the following are **not** security issues:

- A `config.json` that mounts sensitive host paths into the container.
- A `config.json` that grants all capabilities or disables seccomp.
- A `config.json` that sets a UID/GID mapping allowing root access.

These are expected behaviors when the configuration explicitly requests them.

### Annotations

Some crun-specific annotations are marked as **potentially unsafe** and are listed in the output of `crun features` under `potentiallyUnsafeConfigAnnotations`. These annotations intentionally accept arbitrary values and modify container behavior in ways that may weaken isolation. It is the sole responsibility of the caller (the container engine or orchestrator) to validate these values before passing them to crun. A misconfigured unsafe annotation is not a crun security vulnerability.

## **Security Policy**

### Secure Development Practices

crun adheres to secure development practices throughout its lifecycle. The codebase is subject to fuzz testing with [honggfuzz](https://github.com/google/honggfuzz), runtime analysis with AddressSanitizer, and automated code quality checks using clang-check and clang-format. These tools run as part of the CI pipeline on every pull request to detect and prevent security issues before they are merged.

### Vulnerability Management and Coordinated Disclosure

When a security vulnerability is reported, the maintainers will acknowledge receipt, assess severity, and work on a fix under embargo. We follow coordinated vulnerability disclosure (CVD) practices: fixes are developed privately, a CVE is requested when appropriate, and the fix is released alongside a public advisory. Security advisories are published at [GitHub Security Advisories](https://github.com/containers/crun/security/advisories). We coordinate with downstream distributors and affected parties before public disclosure to allow them time to prepare patches.

## **Supported Versions**

We regularly perform patch releases for the supported latest version ([latest release](https://github.com/containers/crun/releases/latest)), which contains fixes for relevant security vulnerabilities and important bugs. Prior releases might receive critical security fixes on a best-effort basis. However, we cannot guarantee that security fixes will get back-ported to these unsupported versions, unless stated otherwise in our support matrix.

## **EU Cyber Resilience Act — Open Source Steward Statement**

This project is stewarded by **Red Hat, Inc.**, an open source software steward as defined in Article 3(14) of the [EU Cyber Resilience Act (Regulation 2024/2847)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng).
Contact: [cra-steward@redhat.com](mailto:cra-steward@redhat.com)

Refer to [Red Hat's security practices and vulnerability management policy](https://access.redhat.com/security/) for detailed information.
