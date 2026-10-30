# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
No release has been tagged yet, so everything below is unreleased.

## [Unreleased]

### Added

- `.editorconfig` matching the repository's existing formatting (tabs in Go
  and `go.mod`, two-space indentation elsewhere, LF line endings).
- This changelog.

### Changed

- Require Go 1.26.10 (`go.mod`, README) to pick up the standard-library fixes
  for GO-2026-6809 (`crypto/x509`) and GO-2026-6617 (`net/http`) reported by
  govulncheck in CI.
- Align the tool versions listed in CONTRIBUTING.md with CI (govulncheck
  v1.7.0, GoReleaser 2.17.1).

### Fixed

- `THIRD_PARTY_LICENSES.txt` lists the runtime module versions that are
  actually built (`github.com/cli/go-gh/v2 v2.16.2`, `golang.org/x/sync
  v0.24.0`) and the Go 1.26.10 standard library, so the CI license policy
  check passes again.

[Unreleased]: https://github.com/26zl/repo-harden/commits/main
