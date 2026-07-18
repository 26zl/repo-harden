package repoharden

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/go-github/v88/github"
)

func auditGitHubOrgRunnerGroups(ctx context.Context, c *github.Client, org string, showIdentifiers bool) auditRow {
	const (
		key   = "org-runner-groups"
		title = "Runner groups exclude public repositories"
		rem   = "Disable 'Allow public repositories' on self-hosted runner groups — fork pull requests from public repos can execute code on the runners."
	)
	opts := &github.ListOrgRunnerGroupOptions{ListOptions: github.ListOptions{PerPage: 100}}
	var all []*github.RunnerGroup
	total := 0
	var pager githubPager
	for {
		groups, resp, err := c.Actions.ListOrganizationRunnerGroups(ctx, org, opts)
		if err != nil {
			return githubOrgAuditErr(org, key, title, "high", err, rem)
		}
		if groups == nil {
			return githubOrgAuditRow(org, key, title, "high", StatusSkipped, "runner-group visibility unavailable", rem)
		}
		if groups.TotalCount > total {
			total = groups.TotalCount
		}
		all = append(all, groups.RunnerGroups...)
		next, done, pageErr := pager.next(resp)
		if pageErr != nil {
			return githubOrgAuditRow(org, key, title, "high", StatusError, pageErr.Error(), rem)
		}
		if done {
			break
		}
		opts.Page = next
	}
	if total == 0 {
		total = len(all)
	}
	if len(all) < total {
		return githubOrgAuditRow(org, key, title, "high", StatusError,
			fmt.Sprintf("runner-group pagination returned only %d of %d advertised groups", len(all), total), rem)
	}
	if total == 0 {
		return githubOrgAuditRow(org, key, title, "high", StatusCompliant, "no self-hosted runner groups", rem)
	}
	var open []string
	for _, group := range all {
		if group.GetAllowsPublicRepositories() {
			open = append(open, group.GetName())
		}
	}
	if len(open) == 0 {
		return githubOrgAuditRow(org, key, title, "high", StatusCompliant,
			fmt.Sprintf("none of %d runner group(s) allow public repositories", total), rem)
	}
	sort.Strings(open)
	detail := fmt.Sprintf("%d runner group(s) allow public repositories", len(open))
	if showIdentifiers {
		detail += ": " + strings.Join(limitStrings(open, maxDetailItems), ", ")
	}
	return githubOrgAuditRow(org, key, title, "high", StatusGap, detail, rem)
}
