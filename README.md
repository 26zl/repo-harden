# repo-harden

> **Audit, harden, and manage your repositories — from one static binary.**
> Read-only security posture across **GitHub, GitLab, Gitea & Forgejo** · reversible GitHub hardening · bulk GitHub Actions control.

[![CI](https://github.com/26zl/repo-harden/actions/workflows/ci.yml/badge.svg)](https://github.com/26zl/repo-harden/actions/workflows/ci.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/26zl/repo-harden)](https://goreportcard.com/report/github.com/26zl/repo-harden) ![Go 1.25+](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

```text
                       _                _
 _ _ ___ _ __  ___ ___| |_  __ _ _ _ __| |___ _ _
| '_/ -_) '_ \/ _ \___| ' \/ _' | '_/ _' / -_) ' \
|_| \___| .__/\___/   |_||_\__,_|_| \__,_\___|_||_|
        |_|
```

## What it does

Three things, no infrastructure — just a local binary and a token:

- **🔍 Audit (read-only, multi-forge).** Scan your repos against a security baseline and get a posture score. Full catalog on **GitHub** (50+ checks); a portable subset on **GitLab, Gitea, and Forgejo**. Output as table, JSON, Markdown, or SARIF.
- **🔒 Harden + revert (GitHub).** Apply the free security baseline — branch protection, read-only `GITHUB_TOKEN`, Dependabot, secret/code scanning — across every eligible repo at once. Host- and account-bound state records applied, pending, or ambiguous mutations so `revert` can restore verified changes safely. Forks and archived repos are skipped by default unless you opt in. 8 auto-fixable controls are reversible.
- **⚙️ Actions management (GitHub).** Bulk enable/disable Actions workflows — per repo or across eligible repos — when you hit free-minute limits, with saved state so you can restore.

No GitHub App, no org-admin config repo, no Terraform, no standing access.

## Quickstart

```bash
# Install
go install github.com/26zl/repo-harden/cmd/repo-harden@latest

# Authenticate before running GitHub API commands (`GITHUB_TOKEN` also works)
gh auth login

# See where eligible repos stand (read-only) — works on GitLab/Gitea/Forgejo too
repo-harden audit                          # every repo your token can reach
repo-harden audit --repo me/app,me/lib     # just these — skips the full scan, much faster
repo-harden audit --provider gitlab

# Preview the GitHub fixes, apply them, undo them
repo-harden harden --dry-run
repo-harden harden
repo-harden revert
```

## Commands

**Security audit & hardening**

| Command | What it does |
| --- | --- |
| `audit` | Read-only posture scan. Multi-forge via `--provider`. `--format table\|json\|markdown\|sarif`, `--exit-code` for CI. |
| `harden` | Apply the auto-fixable baseline controls (8 of them) and save revert state first. GitHub only. `--dry-run`, `--only`/`--skip`. |
| `revert` | Restore verified changes from host/account-bound recovery state. GitHub only. |
| `controls` | List every baseline control and whether it is auto-fixable and reversible. Offline, no token. |

**GitHub Actions management**

| Command | What it does |
| --- | --- |
| `list` / `status` | List workflows / show counts by state across eligible repos. |
| `disable-all` / `enable-all` | Disable active workflows across eligible repos (saving state) / re-enable from that saved state. |
| `enable-all-disabled` | Re-enable every currently-disabled workflow (no state file needed). |
| `disable-repo` / `enable-repo` | Toggle all workflows in a single `owner/repo`. Stateless — `disable-repo` is undone with `enable-repo`, not `enable-all`. |

## Multi-forge audit

The read-only `audit` runs beyond GitHub — point it at another forge with `--provider`:

| Provider | Audit | Harden / Actions |
| --- | :---: | :---: |
| GitHub / GHES | ✅ full catalog | ✅ |
| GitLab | ✅ portable subset | — |
| Gitea / Forgejo | ✅ portable subset | — |

```bash
repo-harden audit --provider gitlab                      # uses GITLAB_TOKEN
repo-harden audit --provider gitea --host git.example.com # uses GITEA_TOKEN
```

`harden`/`revert` and the Actions commands are GitHub-only by design: branch protection ports across forges, but the high-value scanning controls are GitHub-proprietary (or GitLab paid-tier), so a cross-forge `harden` would be mostly no-ops. `audit` gives the cross-forge visibility that matters.

## What the audit checks

A **best-effort baseline**, not an exhaustive security review (see [Not yet covered](#not-yet-covered)). On GitHub it runs 50+ checks; license-gated or inaccessible features are reported as `skipped` rather than guessed. Output includes a severity-weighted verification percentage alongside the posture score. Use `--fail-on-skipped` when an unverifiable check must fail CI.

**Auto-fixable by `harden` (8 reversible controls):** Dependabot alerts + security updates · read-only `GITHUB_TOKEN` (and barred from approving PRs) · default-branch ruleset (required PR review, conversation resolution, no force-push, linear history) · Actions set to selected GitHub-owned + verified actions (this clears any custom allowlist patterns — audit flags them for manual review first, and `revert` restores them) · secret scanning + push protection · CodeQL default setup · private vulnerability reporting.

**Read-only audit also covers (examples):** branch-protection depth (review count, status checks, signed commits), ruleset bypass actors, **evaluate-only (dry-run) rulesets** that enforce nothing, **conflicting code-scanning setups** (default setup vs. an advanced workflow), **per-workflow GITHUB_TOKEN permissions** (least-privilege), Actions SHA-pinning policy, account & org 2FA, **community health files** (issue/PR templates, CoC, contributing), outside collaborators, merge-method & fork policy, public-wiki surface, collaborator & admin hygiene, webhook TLS/staleness, deploy keys, environments, fork-PR approval, public exposure, SBOM/dependency inventory, plus org-level Actions/token/secret/webhook policy.

Two baseline controls — `SECURITY.md` and `CODEOWNERS` — are report-only: flagged by `audit` and listed by `controls`, but never auto-edited.

### Not yet covered

Known gaps (contributions welcome): dependency-review enforcement, merge queues, deeper ruleset validation for required status checks and code-owner review, artifact/SBOM attestation auditing, Dependabot private-registry secrets, self-hosted runner policy, and webhook/environment secret hygiene.

## Reversibility & state

Before applying any change, `harden` records the prior value to:

```text
$REPO_HARDEN_STATE_DIR/harden-state.json   # if REPO_HARDEN_STATE_DIR is set
~/.repo-harden/harden-state.json           # default
```

`revert` reads this file and restores changes that were recorded as applied. It re-detects every live setting first, including entries marked `applied`, and refuses to overwrite settings that have drifted since `harden`. If an API call fails ambiguously, the entry remains `pending`/`unknown`; controls that were already compliant are never recorded.

State files are versioned and bound to the GitHub host and authenticated account. A state file created for GHES cannot be replayed against GitHub.com or by a different account. Legacy array-only state from pre-release builds is rejected because it has no trustworthy host binding; move it aside and run the originating command again.

Actions bulk-disable uses a separate state file:

```text
$REPO_HARDEN_STATE_DIR/enabled-workflows.json
~/.repo-harden/enabled-workflows.json
```

Use `--state-file <path>` to override the state path for the command you are running. Give each command family its own path: `harden`/`revert` and the Actions commands use different file formats, so pointing both at the same `--state-file` is rejected rather than silently overwriting one with the other.

## CI usage

```bash
repo-harden audit --exit-code                 # fail the job on any gap or error
repo-harden audit --exit-code --fail-on-skipped # strict: also fail if a check is unverifiable
repo-harden audit --format sarif > out.sarif  # for GitHub code-scanning ingestion
```

## Flags

| Flag | Description |
| --- | --- |
| `--provider <name>` | `github` (default), `gitlab`, `gitea`, `forgejo` (audit) |
| `--host <host-or-url>` | Provider host (GHES, GitLab, Gitea/Forgejo); accepts the web root or the API URL |
| `--token <token>` | Provider token (discouraged — visible in `ps`/shell history; prefer env vars, `gh auth`, or `--token-stdin`) |
| `--token-stdin` | Read the provider token from stdin |
| `--dry-run` | Perform read-only detection and print intended mutations; API read calls still occur |
| `--owner <login>` | Only touch repos owned by this user/org |
| `--repo <owner/repo>` | Only these repos (comma-separated); fetches them directly and skips the full account scan. Owner/admin/fork/archive filters still apply. |
| `--admin-only` | Only include repos where your token has admin permission |
| `--only <keys>` / `--skip <keys>` | Run / skip specific controls (comma-separated keys) |
| `--format <fmt>` | `table` (default), `json`, `markdown`, `sarif` |
| `--all` | Audit table shows only gaps/errors by default; `--all` shows every check (compliant/skipped too) |
| `--json` | Shortcut for JSON output on `list`, `status`, and `audit` |
| `--exit-code` | Exit non-zero when `audit` finds a gap or error |
| `--fail-on-skipped` | Exit non-zero when any audit check is skipped/unverifiable |
| `--color <when>` / `--no-color` | `auto` (default), `always`, `never`; respects `NO_COLOR` |
| `--concurrency <n>` | Parallel API calls (default: 8) |
| `--include-forks` / `--include-archived` | Include forked / archived repos (skipped by default) |
| `--include-dynamic` | Include dynamic Actions workflows that are skipped by default |
| `--org-audit` | Include GitHub organization-level audit checks (default; use `--org-audit=false` to disable) |
| `--stale-days <n>` | Stale repository threshold (default: 180) |
| `--state-file <path>` | Override the default state file path |
| `--show-identifiers` | Include secret/CI-variable names in audit output (hidden by default) |

## Requirements & install

- Go 1.25+
- A token for the forge you target: [`gh`](https://cli.github.com/) logged in (`gh auth login`) or `GITHUB_TOKEN`; `GITLAB_TOKEN` / `GITEA_TOKEN` / `FORGEJO_TOKEN` for those providers

Use the least-privilege token that covers the commands you run:

| Operation | Required access |
| --- | --- |
| GitHub repository audit | Repository metadata plus read access to the security/settings endpoints being audited. Inaccessible checks are `skipped`; combine CI with `--fail-on-skipped` when full verification is required. |
| GitHub organization audit | Organization read access; admin-only policy, member-2FA, secret, and webhook endpoints require corresponding organization-owner/admin visibility. |
| `harden` / `revert` | Repository administration write access plus write access for the selected Actions/code-security settings. |
| Actions enable/disable commands | Repository Actions write access. |
| GitLab audit | A token with read API access to the selected projects and protected/security endpoints. |
| Gitea / Forgejo audit | Repository read access; admin-only endpoints require repository administration visibility. |

Classic GitHub PATs commonly use `repo` for private repositories and `read:org`/`admin:org` only when the selected organization checks require them. Prefer a fine-grained token limited to the target repositories and endpoint permissions.

```bash
go install github.com/26zl/repo-harden/cmd/repo-harden@latest
# or from source:
go build -o repo-harden ./cmd/repo-harden
```

## How it compares

| | repo-harden | Scorecard / Legitify | Allstar / safe-settings | Terraform GH provider |
| --- | :---: | :---: | :---: | :---: |
| Reports gaps | ✅ | ✅ | ✅ | n/a |
| **Applies the fix** | **✅** | ❌ | ✅ | ✅ |
| Reversible (one command) | **✅** | n/a | partial | via state |
| Multi-forge audit | **✅** | partial | ❌ | ❌ |
| Infra required | **none** | none | App + config repo | IaC + state backend |
| Single binary | **✅** | mixed | ❌ | ❌ |

## Background

repo-harden started as a hobby project — a tool I built for my own repositories because I wanted one command to audit and harden them, without installing an app or standing up infrastructure. It turned out useful enough that I'm opening it up publicly in case it helps others.

## Production operations

Repository policy, provider smoke tests, and the release checklist are
documented in [docs/PRODUCTION.md](docs/PRODUCTION.md).

## Contributing

```bash
go test ./...
go vet ./...
```

Controls live in `internal/repoharden/controls.go` (baseline, auto-fixable) and `internal/repoharden/audit_github.go` (read-only audit catalog); other-forge audits are in `internal/repoharden/audit_providers.go`. Each baseline control is a `Control{Detect, Apply, Revert}` — a good first contribution is adding a new check. Issues and PRs welcome.

## License

[MIT](LICENSE)
