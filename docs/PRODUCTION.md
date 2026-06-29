# Production operations

## Repository policy

The public GitHub repository is expected to keep these settings enabled:

- An active `repo-harden` branch ruleset on the default branch:
  - pull requests with one approval, code-owner review, last-push approval, and
    resolved conversations;
  - required `test` status check with strict branch freshness;
  - signed commits, linear history, and blocked force-push/deletion.
- An active tag ruleset for `refs/tags/v*` that restricts creation, update, and
  deletion to the repository owner/release operator.
- GitHub Actions restricted to GitHub-owned and verified actions, with
  full-length commit SHA pinning required.
- Read-only default `GITHUB_TOKEN` permissions with pull-request approval off.
- Dependabot security updates, secret scanning, push protection, CodeQL, and
  private vulnerability reporting enabled.

Verify these settings before each release with:

```bash
gh api repos/26zl/repo-harden/rulesets
gh api repos/26zl/repo-harden/actions/permissions
gh api repos/26zl/repo-harden/actions/permissions/workflow
gh api repos/26zl/repo-harden/code-scanning/default-setup
gh api repos/26zl/repo-harden/private-vulnerability-reporting
```

## Provider smoke tests

Before a tagged prerelease, run read-only audit smoke tests against disposable
GitHub.com, GHES, GitLab, Gitea, and Forgejo projects. For GitHub.com, also run
`harden --dry-run`, then apply and revert on a disposable repository while
checking partial-failure state recovery.

These tests require external instances and credentials and are intentionally
not part of pull-request CI. Record the provider versions and sanitized command
output in the release issue.

## Release checklist

1. Confirm the release commit is on protected `main` and all required checks
   pass.
2. Confirm `CHANGELOG.md` describes the release.
3. Run the provider smoke tests above.
4. Create the protected SemVer tag from the verified `main` commit.
5. Verify the GitHub Release contains all Linux, macOS, and Windows archives,
   `checksums.txt`, per-archive SBOMs, and build-provenance attestations.
6. Install one archive on each supported operating-system family and run
   `repo-harden version`, `controls`, and a read-only audit.
