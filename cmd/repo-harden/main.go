package main

import "github.com/26zl/repo-harden/internal/repoharden"

// set by GoReleaser via -ldflags -X main.version=...
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	repoharden.Version = version
	repoharden.Commit = commit
	repoharden.Date = date
	repoharden.Main()
}
