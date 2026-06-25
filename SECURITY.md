# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub's
[private vulnerability reporting](https://github.com/26zl/repo-harden/security/advisories/new)
(Security tab → Report a vulnerability). Do not open public issues for
suspected vulnerabilities.

We aim to acknowledge reports within a few days and will keep you updated on
remediation progress. Coordinated disclosure is appreciated.

## Supported versions

This project is pre-1.0; only the latest release on `main` receives security
fixes.

## Scope

`repo-harden` is a local CLI that uses a token you provide. It performs no
network calls other than to the configured forge API. It never writes or
transmits your token, and hardening changes are recorded locally so `revert`
can undo exactly what it applied.
