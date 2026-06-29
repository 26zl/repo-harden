# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub's
[private vulnerability reporting](https://github.com/26zl/repo-harden/security/advisories/new)
(Security tab → Report a vulnerability). Do not open public issues for
suspected vulnerabilities.

We aim to acknowledge reports within a few days and will keep you updated on
remediation progress. Coordinated disclosure is appreciated.

## Supported versions

This project is pre-1.0 and has no stable release line yet. Security fixes are
made on `main`; after tagged prereleases begin, only the newest prerelease will
be supported.

## Scope

`repo-harden` is a local CLI that uses a token you provide. It performs no
runtime network calls other than to the configured forge API. The token is
never written to disk; it is sent only as an authentication header to that
API over HTTPS (loopback HTTP is allowed for local Gitea/Forgejo testing).
Cross-host redirects and HTTPS-to-HTTP downgrades are rejected.

Hardening state is stored locally with mode `0600`, is bound to the forge host
and authenticated account, and contains settings metadata but no token or
secret values. Audit output hides secret and CI-variable names unless
`--show-identifiers` is explicitly requested.
