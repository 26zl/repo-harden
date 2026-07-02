package main

import "github.com/26zl/repo-harden/internal/repoharden"

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
