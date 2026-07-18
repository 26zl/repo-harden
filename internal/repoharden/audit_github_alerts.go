package repoharden

import (
	"context"
	"fmt"

	"github.com/google/go-github/v88/github"
)

func auditGitHubVulnerabilityCounts(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	alerts, err := listGitHubDependabotAlerts(ctx, c, owner, name)
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, "vulnerability-alert-count", "Open Dependabot alerts are triaged", "high", StatusSkipped, "Dependabot alerts unavailable", "Triage or dismiss open Dependabot alerts.")
		}
		return githubAuditRow(repo, "vulnerability-alert-count", "Open Dependabot alerts are triaged", "high", StatusError, err.Error(), "Triage or dismiss open Dependabot alerts.")
	}
	if len(alerts) > 0 {
		return githubAuditRow(repo, "vulnerability-alert-count", "Open Dependabot alerts are triaged", "high", StatusGap, fmt.Sprintf("%d open Dependabot alerts", len(alerts)), "Triage or dismiss open Dependabot alerts.")
	}
	return githubAuditRow(repo, "vulnerability-alert-count", "Open Dependabot alerts are triaged", "high", StatusCompliant, "0 open Dependabot alerts", "Triage or dismiss open Dependabot alerts.")
}

func auditGitHubCodeScanningCounts(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	alerts, err := listGitHubCodeScanningAlerts(ctx, c, owner, name)
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, "code-scanning-alert-count", "Open code scanning alerts are triaged", "high", StatusSkipped, "code scanning alerts unavailable", "Triage open code scanning alerts.")
		}
		return githubAuditRow(repo, "code-scanning-alert-count", "Open code scanning alerts are triaged", "high", StatusError, err.Error(), "Triage open code scanning alerts.")
	}
	if len(alerts) > 0 {
		return githubAuditRow(repo, "code-scanning-alert-count", "Open code scanning alerts are triaged", "high", StatusGap, fmt.Sprintf("%d open code scanning alerts", len(alerts)), "Triage open code scanning alerts.")
	}
	return githubAuditRow(repo, "code-scanning-alert-count", "Open code scanning alerts are triaged", "high", StatusCompliant, "0 open code scanning alerts", "Triage open code scanning alerts.")
}

func auditGitHubSecretScanningCounts(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	alerts, err := listGitHubSecretScanningAlerts(ctx, c, owner, name)
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, "secret-scanning-alert-count", "Open secret scanning alerts are triaged", "critical", StatusSkipped, "secret scanning alerts unavailable", "Triage open secret scanning alerts.")
		}
		return githubAuditRow(repo, "secret-scanning-alert-count", "Open secret scanning alerts are triaged", "critical", StatusError, err.Error(), "Triage open secret scanning alerts.")
	}
	if len(alerts) > 0 {
		return githubAuditRow(repo, "secret-scanning-alert-count", "Open secret scanning alerts are triaged", "critical", StatusGap, fmt.Sprintf("%d open secret scanning alerts", len(alerts)), "Triage open secret scanning alerts.")
	}
	return githubAuditRow(repo, "secret-scanning-alert-count", "Open secret scanning alerts are triaged", "critical", StatusCompliant, "0 open secret scanning alerts", "Triage open secret scanning alerts.")
}

func auditGitHubArchivedActiveRisk(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	if !repo.GetArchived() {
		return githubAuditRow(repo, "archived-active-risk", "Archived repositories have no active workflows", "low", StatusCompliant, "repository is not archived", "Disable active workflows before archiving repositories.")
	}
	wfs, err := listWorkflows(ctx, c, owner, name)
	if err != nil {
		return githubAuditErr(repo, "archived-active-risk", "Archived repositories have no active workflows", "low", err, "Disable active workflows before archiving repositories.")
	}
	active := 0
	for _, wf := range wfs {
		if wf.GetState() == "active" {
			active++
		}
	}
	if active > 0 {
		return githubAuditRow(repo, "archived-active-risk", "Archived repositories have no active workflows", "low", StatusGap, fmt.Sprintf("%d active workflows in archived repo", active), "Disable active workflows before archiving repositories.")
	}
	return githubAuditRow(repo, "archived-active-risk", "Archived repositories have no active workflows", "low", StatusCompliant, "archived with no active workflows", "Disable active workflows before archiving repositories.")
}

func auditGitHubReleases(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	releases, _, err := c.Repositories.ListReleases(ctx, owner, name, &github.ListOptions{PerPage: 10})
	if err != nil {
		return githubAuditErr(repo, "releases", "Releases are reviewed", "low", err, "Use releases for distributed artifacts and review draft/prerelease state.")
	}
	if len(releases) == 0 {
		return githubAuditRow(repo, "releases", "Releases are reviewed", "low", StatusSkipped, "no releases", "Use releases for distributed artifacts and review draft/prerelease state.")
	}
	var draftOrPre int
	for _, rel := range releases {
		if rel.GetDraft() || rel.GetPrerelease() {
			draftOrPre++
		}
	}
	if draftOrPre > 0 {
		return githubAuditRow(repo, "releases", "Releases are reviewed", "low", StatusGap, fmt.Sprintf("%d draft/prerelease entries in first %d releases", draftOrPre, len(releases)), "Review release hygiene, draft/prerelease state, and attached artifacts.")
	}
	return githubAuditRow(repo, "releases", "Releases are reviewed", "low", StatusCompliant, fmt.Sprintf("%d recent releases reviewed", len(releases)), "Use releases for distributed artifacts and review draft/prerelease state.")
}

func auditGitHubSelfHostedRunners(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	const (
		key   = "self-hosted-runners"
		title = "No self-hosted runners on public repositories"
		rem   = "Do not attach self-hosted runners to public repositories — fork pull requests can execute code on your infrastructure. Use GitHub-hosted or ephemeral runners."
	)
	runners, _, err := c.Actions.ListRunners(ctx, owner, name, &github.ListRunnersOptions{ListOptions: github.ListOptions{PerPage: 100}})
	if err != nil {
		return githubAuditErr(repo, key, title, "high", err, rem)
	}
	if runners == nil {
		return githubAuditRow(repo, key, title, "high", StatusSkipped, "runner visibility unavailable", rem)
	}
	if runners.TotalCount == 0 {
		return githubAuditRow(repo, key, title, "high", StatusCompliant, "no self-hosted runners", rem)
	}
	if !repo.GetPrivate() {
		return githubAuditRow(repo, key, title, "high", StatusGap,
			fmt.Sprintf("%d self-hosted runner(s) attached to a public repository", runners.TotalCount), rem)
	}
	return githubAuditRow(repo, key, title, "high", StatusCompliant,
		fmt.Sprintf("%d self-hosted runner(s) on a private repository", runners.TotalCount), rem)
}
