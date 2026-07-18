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

Prefer environment variables, `gh auth`, or `--token-stdin`. The `--token`
argument is supported for automation compatibility but can be exposed by shell
history or process listings.

## Local state and dry runs

Hardening and Actions recovery state is stored locally with mode `0600` and
contains repository/settings metadata but no token or secret values. State
schema 2 is bound to the provider, normalized host, and the authenticated
GitHub account's stable numeric ID. A login rename therefore does not make a
state file transferable to another account. Cross-host, cross-account,
wrong-kind, unknown-version, and unbound legacy state is rejected.

Schema-1 envelopes are accepted only when the recorded login still matches;
the next state-changing save upgrades them with the numeric account ID. Files
are written atomically under an exclusive lock. `--dry-run` can read an
existing state file when reconciliation requires it, but it does not create a
state directory or lock file, write state, or call a mutating forge endpoint.

## Audit data

Audit output hides secret and CI-variable names, collaborator usernames, and
deploy-key titles unless `--show-identifiers` is explicitly requested. It still
contains repository names and security-posture metadata, so treat saved JSON,
SARIF, and Markdown reports according to the sensitivity of the audited
repositories. The versioned JSON format and legacy-baseline limits are
documented in the [audit JSON contract](README.md#audit-json-contract).

## Release boundary

Build, attestation, draft creation, and publication use separate jobs with
narrow permissions. Final publication targets the protected `release`
environment after all six native smoke tests pass. The required GitHub-side
setup is summarized in the [production checklist](README.md#production-operations).
