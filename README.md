# repo-harden

> **Audit, harden, and manage your repositories — from one static binary.**
> Read-only security posture across **GitHub, GitLab, Gitea & Forgejo** · reversible GitHub hardening · bulk GitHub Actions control.

[![CI](https://github.com/26zl/repo-harden/actions/workflows/ci.yml/badge.svg)](https://github.com/26zl/repo-harden/actions/workflows/ci.yml) [![Go Reference](https://pkg.go.dev/badge/github.com/26zl/repo-harden.svg)](https://pkg.go.dev/github.com/26zl/repo-harden) [![Go Report Card](https://goreportcard.com/badge/github.com/26zl/repo-harden)](https://goreportcard.com/report/github.com/26zl/repo-harden) ![Go 1.25+](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

```text
                       _                _
 _ _ ___ _ __  ___ ___| |_  __ _ _ _ __| |___ _ _
| '_/ -_) '_ \/ _ \___| ' \/ _' | '_/ _' / -_) ' \
|_| \___| .__/\___/   |_||_\__,_|_| \__,_\___|_||_|
        |_|
```

## What it does

Three things, no infrastructure — just a local binary and a token:

- **🔍 Audit (read-only, multi-forge).** Scan your repos against a security baseline and get a posture score. Full catalog on **GitHub** (40+ checks); a portable subset on **GitLab, Gitea, and Forgejo**. Output as table, JSON, Markdown, or SARIF.
- **🔒 Harden + revert (GitHub).** Apply the free security baseline — branch protection, read-only `GITHUB_TOKEN`, Dependabot, secret/code scanning — across every eligible repo at once, and `revert` rolls back **exactly** what it changed. Forks and archived repos are skipped by default unless you opt in. 7 auto-fixable controls, each fully reversible.
- **⚙️ Actions management (GitHub).** Bulk enable/disable Actions workflows — per repo or across eligible repos — when you hit free-minute limits, with saved state so you can restore.

No GitHub App, no org-admin config repo, no Terraform, no standing access.

## Quickstart

```bash
# Install (needs `gh auth login`, or a GITHUB_TOKEN env var)
go install github.com/26zl/repo-harden/cmd/repo-harden@latest

# See where eligible repos stand (read-only) — works on GitLab/Gitea/Forgejo too
repo-harden audit
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
| `harden` | Apply the auto-fixable baseline controls (7 of them) and save revert state first. GitHub only. `--dry-run`, `--only`/`--skip`. |
| `revert` | Undo exactly what the last `harden` changed (replays saved state). GitHub only. |
| `controls` | List every baseline control and whether it is auto-fixable and reversible. Offline, no token. |

**GitHub Actions management**

| Command | What it does |
| --- | --- |
| `list` / `status` | List workflows / show counts by state across eligible repos. |
| `disable-all` / `enable-all` | Disable active workflows across eligible repos (saving state) / re-enable from that saved state. |
| `enable-all-disabled` | Re-enable every currently-disabled workflow (no state file needed). |
| `disable-repo` / `enable-repo` | Toggle all workflows in a single `owner/repo`. |

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

A **best-effort baseline**, not an exhaustive security review (see [Not yet covered](#not-yet-covered)). On GitHub it runs 40+ checks; license-gated features on private repos are reported as `skipped — requires license`, never a failure.

**Auto-fixable by `harden` (7 reversible controls):** Dependabot alerts + security updates · read-only `GITHUB_TOKEN` (and barred from approving PRs) · default-branch ruleset (required PR review, conversation resolution, no force-push, linear history) · Actions set to selected GitHub-owned + verified actions (custom allowlist patterns are flagged by audit for manual review) · secret scanning + push protection · CodeQL default setup.

**Read-only audit also covers (examples):** branch-protection depth (review count, status checks, signed commits), ruleset bypass actors, Actions SHA-pinning policy, account & org 2FA, collaborator & admin hygiene, webhook TLS/staleness, deploy keys, environments, fork-PR approval, public exposure, SBOM/dependency inventory, plus org-level Actions/token/secret/webhook policy.

Two baseline controls — `SECURITY.md` and `CODEOWNERS` — are report-only: flagged by `audit` and listed by `controls`, but never auto-edited.

### Not yet covered

Known gaps (contributions welcome): dependency-review enforcement, merge queues, deeper ruleset validation for required status checks and code-owner review, artifact/SBOM attestation auditing, private vulnerability reporting state, Dependabot private-registry secrets, self-hosted runner policy, and webhook/environment secret hygiene.

## Reversibility & state

Before applying any change, `harden` records the prior value to:

```text
$REPO_HARDEN_STATE_DIR/harden-state.json   # if REPO_HARDEN_STATE_DIR is set
~/.repo-harden/harden-state.json           # default
```

`revert` reads this file and restores exactly what `harden` changed — nothing more. Controls that were already compliant are never recorded, so `revert` never touches settings the tool didn't change.

Actions bulk-disable uses a separate state file:

```text
$REPO_HARDEN_STATE_DIR/enabled-workflows.json
~/.repo-harden/enabled-workflows.json
```

Use `--state-file <path>` to override the state path for the command you are running.

## CI usage

```bash
repo-harden audit --exit-code                 # fail the job on any gap or error
repo-harden audit --format sarif > out.sarif  # for GitHub code-scanning ingestion
```

## Flags

| Flag | Description |
| --- | --- |
| `--provider <name>` | `github` (default), `gitlab`, `gitea`, `forgejo` (audit) |
| `--host <host-or-url>` | Provider host (GHES, GitLab, Gitea/Forgejo) |
| `--token <token>` | Provider token; prefer env vars in scripts |
| `--dry-run` | Print intended actions without calling the API |
| `--owner <login>` | Only touch repos owned by this user/org |
| `--admin-only` | Only include repos where your token has admin permission |
| `--only <keys>` / `--skip <keys>` | Run / skip specific controls (comma-separated keys) |
| `--format <fmt>` | `table` (default), `json`, `markdown`, `sarif` |
| `--json` | Shortcut for JSON output on `list`, `status`, and `audit` |
| `--exit-code` | Exit non-zero when `audit` finds a gap or error |
| `--color <when>` / `--no-color` | `auto` (default), `always`, `never`; respects `NO_COLOR` |
| `--concurrency <n>` | Parallel API calls (default: 8) |
| `--include-forks` / `--include-archived` | Include forked / archived repos (skipped by default) |
| `--include-dynamic` | Include dynamic Actions workflows that are skipped by default |
| `--org-audit` | Include GitHub organization-level audit checks (default; use `--org-audit=false` to disable) |
| `--stale-days <n>` | Stale repository threshold (default: 180) |
| `--state-file <path>` | Override the default state file path |

## Requirements & install

- Go 1.25+
- A token for the forge you target: [`gh`](https://cli.github.com/) logged in (`gh auth login`) or `GITHUB_TOKEN` (with `repo` + `admin:org` scope for the controls you run); `GITLAB_TOKEN` / `GITEA_TOKEN` / `FORGEJO_TOKEN` for those providers

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

## Contributing

```bash
go test ./...
go vet ./...
```

Controls live in `internal/repoharden/controls.go` (baseline, auto-fixable) and `internal/repoharden/audit_github.go` (read-only audit catalog); other-forge audits are in `internal/repoharden/audit_providers.go`. Each baseline control is a `Control{Detect, Apply, Revert}` — a good first contribution is adding a new check. Issues and PRs welcome.

## License

[MIT](LICENSE)
