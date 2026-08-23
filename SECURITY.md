# Security Policy

SentinelGuard audits the security posture of Linux systems, which means
it necessarily has access to sensitive host data (permissions on
`/etc/shadow`, SSH/sudo configuration, detected secrets, etc.). We take
the security of this project seriously.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security
vulnerabilities.**

Instead, report privately via GitHub's [private vulnerability reporting](../../security/advisories/new)
feature on this repository. If that's unavailable to you, open a draft
security advisory or contact the maintainers listed in
[CODEOWNERS](./.github/CODEOWNERS).

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept if possible)
- Affected version(s)/commit

## What we consider in scope

- The Dashboard's REST API and MCP endpoint (auth bypass, injection,
  IDOR across servers/tenants, etc.)
- The Linux Agent (privilege escalation via the agent, insecure
  transport, credential handling)
- Secret Guardian false-negatives that could mask real exposed
  credentials (report as a bug, not necessarily a security advisory,
  unless it has security implications for users relying on it)

## Response process

1. We'll acknowledge receipt within a reasonable timeframe.
2. We'll investigate and determine severity/impact.
3. We'll work on a fix and coordinate disclosure timing with the
   reporter.
4. Once patched, we'll credit the reporter (unless they prefer
   anonymity) in the release notes.

## Supported versions

Security fixes are backported to the latest minor release only, while
the project is pre-1.0-stable. This policy will be revisited once
SentinelGuard reaches a stable v1.0 release.
