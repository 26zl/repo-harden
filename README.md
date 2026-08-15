# repo-harden

> **Audit, harden, and manage your repositories — from one static binary.**
> Read-only security posture across **GitHub, GitLab, Gitea & Forgejo** · reversible GitHub hardening · bulk GitHub Actions control.

[![CI](https://github.com/26zl/repo-harden/actions/workflows/ci.yml/badge.svg)](https://github.com/26zl/repo-harden/actions/workflows/ci.yml) [![Go Reference](https://pkg.go.dev/badge/github.com/26zl/repo-harden.svg)](https://pkg.go.dev/github.com/26zl/repo-harden) ![Go 1.25.12+](https://img.shields.io/badge/Go-1.25.12%2B-00ADD8?logo=go&logoColor=white) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

```text
                       _                _
 _ _ ___ _ __  ___ ___| |_  __ _ _ _ __| |___ _ _
| '_/ -_) '_ \/ _ \___| ' \/ _' | '_/ _' / -_) ' \
|_| \___| .__/\___/   |_||_\__,_|_| \__,_\___|_||_|
        |_|
```

## What it does

Three things, no infrastructure — just a local binary and a token:

- **Audit (read-only, multi-forge).** Scan your repos against a security baseline and get a posture score. Full catalog on **GitHub** (65+ checks, including workflow supply-chain, release provenance, runner hygiene, and cloud-OIDC trust); a portable subset — with pipeline supply-chain checks — on **GitLab, Gitea, and Forgejo**. Output as table, JSON, Markdown, SARIF, or a shields.io score badge, with OpenSSF Scorecard/SLSA/CIS framework references attached.
- **Harden + revert (GitHub).** Apply the free security baseline — branch protection, read-only `GITHUB_TOKEN`, Dependabot, secret/code scanning — across every eligible repo at once. Host- and account-bound state records applied, pending, or ambiguous mutations so `revert` can restore verified changes safely. Forks and archived repos are skipped by default unless you opt in. 8 auto-fixable controls are reversible.
- **Actions management (GitHub).** Bulk enable/disable Actions workflows — per repo or across eligible repos — when you hit free-minute limits, with saved state so you can restore.

No GitHub App, no org-admin config repo, no Terraform required, no standing access. (Moving to IaC anyway? `codify` emits the baseline as Terraform/OpenTofu HCL.)

## Quickstart

```bash
# Install
go install github.com/26zl/repo-harden/cmd/repo-harden@latest

# Authenticate before running GitHub API commands (`GITHUB_TOKEN` also works)
gh auth login

# See where eligible repos stand (read-only) — works on GitLab/Gitea/Forgejo too
repo-harden audit                          # eligible affiliated repos visible to the token
repo-harden audit --repo me/app,me/lib     # just these — skips the full scan, much faster
repo-harden audit --provider gitlab

# Preview the GitHub fixes, apply them, undo them
repo-harden harden --dry-run
repo-harden harden
repo-harden revert
```

## Commands

### Security audit and hardening

| Command | What it does |
| --- | --- |
| `audit` | Read-only posture scan. Multi-forge via `--provider`. `--format table\|json\|markdown\|sarif\|badge`, `--exit-code`/`--fail-below`/`--diff` for CI. |
| `harden` | Apply the auto-fixable baseline controls (8 of them) and save revert state first. GitHub only. `--dry-run`, `--only`/`--skip`. |
| `revert` | Restore verified changes from host/account-bound recovery state. GitHub only. |
| `codify` | Emit the provider-supported subset of the baseline as Terraform/OpenTofu HCL with import blocks. GitHub only. |
| `controls` | List every baseline control and whether it is auto-fixable and reversible. Offline, no token. |
| `version` / `help` | Print version and build info / show usage. Offline, no token. |

### GitHub Actions management

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
| GitLab | ✅ portable subset + `pipeline-supply-chain` (unpinned images, floating includes) | — |
| Gitea / Forgejo | ✅ portable subset + the workflow supply-chain checks (`.gitea`, `.forgejo`, and `.github` workflow dirs) | — |
| Bitbucket Cloud | ✅ portable subset + `pipeline-supply-chain` (unpinned images and pipes in `bitbucket-pipelines.yml`) | — |

```bash
repo-harden audit --provider gitlab                      # uses GITLAB_TOKEN
repo-harden audit --provider gitea --host git.example.com # uses GITEA_TOKEN
repo-harden audit --provider bitbucket --owner myworkspace # uses BITBUCKET_TOKEN
```

Bitbucket support targets Bitbucket Cloud (`api.bitbucket.org`); Server/Data
Center instances expose a different API and are not supported. Set
`BITBUCKET_TOKEN` to a repository/project/workspace access token or OAuth
bearer token, or to `email:api_token` for an Atlassian API token (sent as
HTTP basic authentication).

`harden`/`revert` and the Actions commands are GitHub-only by design: branch protection ports across forges, but the high-value scanning controls are GitHub-proprietary (or GitLab paid-tier), so a cross-forge `harden` would be mostly no-ops. `audit` gives the cross-forge visibility that matters.

## Codify: from click-ops to IaC

`codify` emits the provider-supported baseline as Terraform/OpenTofu HCL with
import blocks for settings that already exist:

```bash
repo-harden codify --repo me/app > baseline.tf
terraform init && terraform plan   # the plan IS your posture gap; apply = harden via IaC
```

Review the first plan: importing adopts existing resources but does not promise
a no-op. Controls without dedicated provider resources remain with `harden`.
`codify` fails instead of guessing when existing policy cannot be inspected or
would be overwritten.

## What the audit checks

A best-effort baseline, not an exhaustive security review. GitHub gets the full
catalog; GitLab, Gitea, Forgejo, and Bitbucket Cloud get the portable subset. Inaccessible or
license-gated checks are `skipped`, never guessed. Use `--fail-on-skipped` when
unverifiable results must fail CI.

`harden` applies eight reversible GitHub controls: Dependabot alerts and
security updates, least-privilege workflow tokens, a default-branch ruleset, a
restricted Actions policy, secret scanning and push protection, CodeQL default
setup, and private vulnerability reporting.

The read-only catalog also covers workflow supply-chain risks, OIDC trust,
release provenance, runner exposure, tag protection, organization policy,
collaborator and webhook hygiene, repository exposure, declared repository
licenses, community files, and dependency inventory. JSON, SARIF, and Markdown rows include best-effort
OpenSSF Scorecard, SLSA, and CIS Software Supply Chain Security references.

Two baseline controls — `SECURITY.md` and `CODEOWNERS` — are report-only: flagged by `audit` and listed by `controls`, but never auto-edited.

Known gaps include full cryptographic statement verification, Dependabot
private-registry secrets, and webhook/environment secret hygiene.

## Reversibility & state

Before applying any change, `harden` records the prior value to:

```text
$REPO_HARDEN_STATE_DIR/harden-state.json   # if REPO_HARDEN_STATE_DIR is set
~/.repo-harden/harden-state.json           # default
```

`revert` reads this file and restores changes that were recorded as applied. It
re-detects live settings, refuses to overwrite drift, and verifies each result.
Ambiguous outcomes remain `pending`/`unknown`; settings the tool did not change
are never reverted.

State schema 2 binds files to the provider, normalized host, and stable account
ID. Cross-host, cross-account, wrong-kind, and unbound legacy files are
rejected. Matching schema-1 files are upgraded on the next state-changing save.

Actions bulk-disable uses a separate state file:

```text
$REPO_HARDEN_STATE_DIR/enabled-workflows.json
~/.repo-harden/enabled-workflows.json
```

Use `--state-file <path>` to override a path. Hardening and Actions state are
different kinds and cannot share a file. Dry runs may read existing state but
do not create directories or locks, write state, or mutate a forge.

## CI usage

```bash
repo-harden audit --exit-code                 # fail the job on any gap or error (info-severity gaps don't count)
repo-harden audit --exit-code --fail-on-skipped # strict: also fail if a check is unverifiable
repo-harden audit --fail-below 80             # posture-score gate instead of any-gap
repo-harden audit --format sarif > out.sarif  # for GitHub code-scanning ingestion
repo-harden audit --format badge > badge.json # shields.io endpoint JSON for a README badge

# Drift gate: fail only when posture REGRESSES, not on known accepted gaps
repo-harden audit --format json > today.json
repo-harden audit --diff yesterday.json --exit-code
```

### Audit JSON contract

`audit --format json` emits a versioned `repo-harden-audit` envelope. Consumers
must check `version` and `kind`; the published
[JSON Schema](audit-report.schema.json) is the machine-readable contract
and is included in binary release archives. A minimal report looks like this:

```json
{
  "version": 1,
  "kind": "repo-harden-audit",
  "scope": {
    "provider": "github",
    "host": "github.com",
    "owner": "acme",
    "repositories": ["acme/app"],
    "controls": ["public-exposure"],
    "selection": {
      "requested_repositories": [],
      "include_forks": false,
      "include_archived": false,
      "admin_only": false,
      "include_dynamic": false,
      "organization_audit": true,
      "stale_days": 180
    }
  },
  "repository_count": 1,
  "rows": [
    {
      "provider": "github",
      "scope": "repo",
      "repo": "acme/app",
      "control": "public-exposure",
      "status": "compliant"
    }
  ]
}
```

Diff baselines are scope-bound: provider, normalized host, owner, selection,
repository universe, and control universe must still match. Missing rows, new
unverifiable rows, transitions to `skipped`, and new non-info gaps or errors are
regressions. `--exit-code` turns them into a failing exit; `--fail-on-skipped`
and `--fail-below` remain independent gates. The posture score behind
`--fail-below` counts info-severity rows at minimal weight, so it can react to
advisory findings that `--exit-code` ignores. Unknown fields and unsupported
versions are rejected.

Legacy top-level row arrays can be inspected during migration, but they cannot
prove host or owner scope. They warn and always fail with `--exit-code` until a
new versioned baseline replaces them. Incompatible contract or drift-semantics
changes require a new report version.

## Flags

Run `repo-harden help` or `repo-harden <command> --help` for the complete flag
reference. Common selectors are `--provider`, `--host`, `--owner`, `--repo`,
`--only`, and `--skip`. Mutation commands support `--dry-run`; audit gates use
`--exit-code`, `--fail-on-skipped`, `--fail-below`, and
[`--diff`](#audit-json-contract). Prefer environment tokens, `gh auth`, or
`--token-stdin` because `--token` can be exposed in process listings and shell
history.

## Requirements & install

- Go 1.25.12+ (declared in `go.mod`; with the default `GOTOOLCHAIN=auto` the right toolchain is fetched automatically)
- A token for the forge you target: [`gh`](https://cli.github.com/) logged in (`gh auth login`) or `GITHUB_TOKEN`; `GITLAB_TOKEN` / `GITEA_TOKEN` / `FORGEJO_TOKEN` (Forgejo falls back to `GITEA_TOKEN`) / `BITBUCKET_TOKEN` for those providers

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

## Background

repo-harden started as a hobby project — a tool I built for my own repositories
because I wanted one command to audit and harden them, without installing an
app or standing up infrastructure. It turned out useful enough that I opened it
up publicly in case it helps others.

## Production operations

Changes to `main` go through pull requests. The branch ruleset blocks direct,
deleting, and non-fast-forward updates and requires the CI, cross-platform,
dependency-review, and CodeQL checks to pass.
Require a green latest `main` run before tagging a release.

The CLI's `branch-protection` hardening control can establish the structural
pull-request safeguards. Repository-specific status-check names and signed
commit enforcement must also be configured in the GitHub branch ruleset by
hand.

Before a production release, verify the GitHub-side settings that repository
files cannot enforce: protect `main` with pull requests and the documented
checks, protect `v*` tags, enable immutable releases, restrict Actions and the
default workflow token, and require approval for the `release` and `acceptance`
environments.

Before the first production release, run the manual
[acceptance workflow](https://github.com/26zl/repo-harden/actions/workflows/acceptance.yml) against disposable
instances for each claimed provider, then publish a prerelease and verify all
archives, checksums, SBOMs, attestations, native smoke tests, and environment
approval. External-provider behavior cannot be proven by CI mocks alone.

## Contributing

See
[CONTRIBUTING.md](https://github.com/26zl/repo-harden/blob/main/CONTRIBUTING.md)
for the local checks and change-specific test expectations.

## License

[MIT](LICENSE). Binary release archives also include the consolidated
[third-party licenses and notices](THIRD_PARTY_LICENSES.txt).
