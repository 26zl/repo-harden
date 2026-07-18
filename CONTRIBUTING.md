# Contributing

Issues and pull requests are welcome. For security vulnerabilities, use the
private process in [SECURITY.md](SECURITY.md) instead of a public issue.

Submit changes through a pull request. The protected `main` branch requires the
CI, cross-platform, dependency-review, and CodeQL checks to pass before merge.
Require a green latest `main` run before tagging a release.

## Development

Use the Go version declared in `go.mod`. For the full local CI-equivalent check,
run:

```bash
gofmt -w .
git diff --check
go mod verify
go mod tidy -diff
go vet ./...
REPO_HARDEN_TERRAFORM_TEST=1 go test -race -coverprofile=coverage.out ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
goreleaser check
```

Use GoReleaser 2.17.0, matching CI. CI fails when the total coverage recorded
in `coverage.out` is below 70.0%. Release validation allows only the listed
permissive dependency licenses, and release archives include
`THIRD_PARTY_LICENSES.txt`. Review that file whenever runtime dependencies
change.

Actionlint 1.7.12 predates GitHub's `concurrency.queue` syntax. The scoped
pattern in `.github/actionlint.yaml` suppresses only that known parser false
positive; remove it when a pinned actionlint release supports the field.

Changes to hardening controls must include tests for detection, apply, partial
failure, drift-safe revert, and command-level state persistence. Provider audit
changes should include both unavailable and weak-policy responses so a missing
API field cannot become a false compliant result. Paginated code must test
progress and upper bounds; security-relevant parse failures must remain
`skipped` or `error`, not compliant.

Changes to audit JSON fields or drift semantics must update the
[README contract](README.md#audit-json-contract), the
[schema](audit-report.schema.json), and legacy-baseline tests.
Changes to state formats require an explicit version and migration or rejection
test. Dry-run tests must assert that neither remote mutations nor local
state/lock writes occur.

Workflow changes must keep third-party actions on full commit SHAs and use the
smallest job-level permissions. A pull request cannot prove provider or release
behavior against external systems: before a release, run the manual
[acceptance workflow](.github/workflows/acceptance.yml) against disposable
targets and follow the production checklist in
[README](README.md#production-operations).

Keep pull requests focused and update README/SECURITY documentation when
commands, state formats, token handling, or supported providers change.
