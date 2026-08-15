package repoharden

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/go-github/v88/github"
)

func runAudit(ctx context.Context, c *github.Client, o *opts) ([]auditRow, []string, error) {
	switch o.provider {
	case "github":
		repos, err := listRepos(ctx, c, o)
		if err != nil {
			return nil, nil, err
		}
		rows, err := collectAudit(ctx, c, o, repos)
		if err != nil {
			return nil, nil, err
		}
		extra, err := collectGitHubExtendedAudit(ctx, c, o, repos)
		if err != nil {
			return nil, nil, err
		}
		rows = append(rows, extra...)
		return filterAuditRows(rows, o), githubRepositoryNames(repos), nil
	case "gitlab":
		rows, repositories, err := collectGitLabAudit(ctx, o)
		return filterAuditRows(rows, o), repositories, err
	case "gitea", "forgejo":
		rows, repositories, err := collectGiteaAudit(ctx, o)
		return filterAuditRows(rows, o), repositories, err
	case "bitbucket":
		rows, repositories, err := collectBitbucketAudit(ctx, o)
		return filterAuditRows(rows, o), repositories, err
	default:
		return nil, nil, fmt.Errorf("unsupported provider %q", o.provider)
	}
}

func githubRepositoryNames(repositories []*github.Repository) []string {
	names := make([]string, 0, len(repositories))
	for _, repository := range repositories {
		if repository != nil && strings.TrimSpace(repository.GetFullName()) != "" {
			names = append(names, repository.GetFullName())
		}
	}
	sort.Strings(names)
	return names
}

func wantFunc(o *opts) func(string) bool {
	onlySet := splitSet(o.only)
	skipSet := splitSet(o.skip)
	return func(key string) bool {
		if len(onlySet) > 0 && !onlySet[key] {
			return false
		}
		return !skipSet[key]
	}
}

func filterAuditRows(rows []auditRow, o *opts) []auditRow {
	onlySet := splitSet(o.only)
	skipSet := splitSet(o.skip)
	if len(onlySet) == 0 && len(skipSet) == 0 {
		return rows
	}
	out := rows[:0]
	for _, row := range rows {
		if len(onlySet) > 0 && !onlySet[row.Control] {
			continue
		}
		if skipSet[row.Control] {
			continue
		}
		out = append(out, row)
	}
	return out
}

// auditHasFindings drives --exit-code; info-severity gaps are optional hardening and do not count.
func auditHasFindings(rows []auditRow) bool {
	for _, row := range rows {
		if row.Status == string(StatusError) {
			return true
		}
		if row.Status == string(StatusGap) && strings.ToLower(row.Severity) != "info" {
			return true
		}
	}
	return false
}

func auditHasSkipped(rows []auditRow) bool {
	for _, row := range rows {
		if ControlStatus(row.Status) == StatusSkipped {
			return true
		}
	}
	return false
}
