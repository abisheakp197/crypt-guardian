# Security Policy

## Supported Versions

We are currently in active development. Security patches will be applied to the latest release and the `main` branch.

| Version | Supported          |
| ------- | ------------------ |
| v1.0.x  | :white_check_mark: |
| < v1.0  | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a vulnerability in `crypt-guardian` (e.g., bypasses in the FUSE3 interception, entropy evasion, or shadow buffer corruption), please report it privately to ensure the safety of the ecosystem.

### How to report:
1. Email the maintainer directly at: `abisheakp197@gmail.com`
2. Or use GitHub's built-in **Private Vulnerability Reporting** under the "Security" tab.

### What to include in your report:
* A description of the vulnerability and its potential impact.
* Exact steps to reproduce the issue (including environment details, OS version, and malicious payload used).
* Any proof-of-concept (PoC) code or logs.

### Our commitment:
* We will acknowledge receipt of your vulnerability report within **48 hours**.
* We will provide an estimated timeline for a fix.
* We will credit you in the release notes once the fix is deployed (unless you prefer to remain anonymous).

## Scope

This policy applies to the `crypt-guardian` core codebase (C++ FUSE3 filesystem interceptors, entropy analyzers, and the reversal engine). 

*Note: This project is an unmaintained prototype designed as an OS-level fail-safe for the NTI (Neutral Trust Infrastructure) standard. If you wish to fork this and integrate it into the NTI-1 specification, please open a Pull Request on the main `nti-spec` repository.*
