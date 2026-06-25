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
