# Contributing

Issues and pull requests are welcome. For security vulnerabilities, use the
private process in [SECURITY.md](SECURITY.md) instead of a public issue.

## Development

Use the Go version declared in `go.mod`, then run:

```bash
gofmt -w .
go vet ./...
go test -race ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.5.0 ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
go run github.com/goreleaser/goreleaser/v2@v2.16.0 check
```

Changes to hardening controls must include tests for detection, apply, partial
failure, drift-safe revert, and command-level state persistence. Provider audit
changes should include both unavailable and weak-policy responses so a missing
API field cannot become a false compliant result.

Keep pull requests focused and update README/SECURITY documentation when
commands, state formats, token handling, or supported providers change.
