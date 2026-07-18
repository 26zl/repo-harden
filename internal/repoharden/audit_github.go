package repoharden

import (
	"context"
	"sync"

	"github.com/google/go-github/v88/github"
	"golang.org/x/sync/errgroup"
)

func collectGitHubExtendedAudit(ctx context.Context, c *github.Client, o *opts, repos []*github.Repository) ([]auditRow, error) {
	want := wantFunc(o)
	var rows []auditRow
	var mu sync.Mutex
	pc := &githubPackageCache{m: map[string]*githubPackageCacheEntry{}}
	if want("token-scopes") {
		rows = append(rows, auditGitHubTokenScopes(ctx, c)...)
	}
	if want("account-2fa") {
		rows = append(rows, auditGitHubAccountTwoFactor(ctx, c))
	}
	if o.orgAudit {
		rows = append(rows, auditGitHubOrganizations(ctx, c, repos, want, o.showIdentifiers)...)
	}
	limit := o.concurrency
	if limit < 1 {
		limit = 1
	}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(limit)
	for _, repo := range repos {
		g.Go(func() error {
			ctx := gctx
			owner, name := splitRepo(repo.GetFullName())
			wc := &workflowFileCache{}
			rc := &rulesetListCache{}
			checks := []struct {
				key string
				run func() auditRow
			}{
				{"public-exposure", func() auditRow { return auditGitHubPublicExposure(repo) }},
				{"stale-repo", func() auditRow { return auditGitHubStaleRepo(repo, o.staleDays) }},
				{"default-branch", func() auditRow { return auditGitHubDefaultBranch(repo) }},
				{"merge-hygiene", func() auditRow { return auditGitHubMergeHygiene(repo) }},
				{"branch-protection-full", func() auditRow { return auditGitHubBranchProtection(ctx, c, owner, name, repo, rc) }},
				{"signed-commits", func() auditRow { return auditGitHubSignedCommits(ctx, c, owner, name, repo, rc) }},
				{"required-workflows", func() auditRow { return auditGitHubRequiredWorkflows(ctx, c, owner, name, repo, rc) }},
				{"actions-fork-pr-permissions", func() auditRow { return auditGitHubForkPRPolicy(ctx, c, owner, name, repo) }},
				{"environment-protection", func() auditRow { return auditGitHubEnvironments(ctx, c, owner, name, repo) }},
				{"repo-secrets", func() auditRow {
					return auditGitHubRepoSecrets(ctx, c, owner, name, repo, o.staleDays, o.showIdentifiers)
				}},
				{"deploy-keys", func() auditRow { return auditGitHubDeployKeys(ctx, c, owner, name, repo, o.showIdentifiers) }},
				{"webhooks", func() auditRow { return auditGitHubWebhooks(ctx, c, owner, name, repo) }},
				{"collaborators", func() auditRow { return auditGitHubCollaborators(ctx, c, owner, name, repo) }},
				{"vulnerability-alert-count", func() auditRow { return auditGitHubVulnerabilityCounts(ctx, c, owner, name, repo) }},
				{"code-scanning-alert-count", func() auditRow { return auditGitHubCodeScanningCounts(ctx, c, owner, name, repo) }},
				{"secret-scanning-alert-count", func() auditRow { return auditGitHubSecretScanningCounts(ctx, c, owner, name, repo) }},
				{"archived-active-risk", func() auditRow { return auditGitHubArchivedActiveRisk(ctx, c, owner, name, repo) }},
				{"releases", func() auditRow { return auditGitHubReleases(ctx, c, owner, name, repo) }},
				{"packages", func() auditRow { return auditGitHubPackages(ctx, c, owner, repo, pc) }},
				{"dependency-sbom", func() auditRow { return auditGitHubSBOM(ctx, c, owner, name, repo) }},
				{"repository-license", func() auditRow { return auditGitHubRepositoryLicense(ctx, c, owner, name, repo) }},
				{"dependabot-open-alerts", func() auditRow { return auditGitHubDependabotOpenAlerts(ctx, c, owner, name, repo) }},
				{"ruleset-bypass", func() auditRow { return auditGitHubRulesetBypass(ctx, c, owner, name, repo, rc) }},
				{"open-security-advisories", func() auditRow { return auditGitHubOpenSecurityAdvisories(ctx, c, owner, name, repo) }},
				{"workflow-access-level", func() auditRow { return auditGitHubWorkflowAccessLevel(ctx, c, owner, name, repo) }},
				{"actions-sha-pinning", func() auditRow { return auditGitHubActionsShaPinning(ctx, c, owner, name, repo) }},
				{"community-health", func() auditRow { return auditGitHubCommunityHealth(ctx, c, owner, name, repo) }},
				{"code-scanning-conflict", func() auditRow { return auditGitHubCodeScanningConflict(ctx, c, owner, name, repo, wc) }},
				{"ruleset-evaluate-only", func() auditRow { return auditGitHubRulesetEvaluateOnly(ctx, c, owner, name, repo, rc) }},
				{"workflow-token-permissions", func() auditRow { return auditGitHubWorkflowTokenPermissions(ctx, c, owner, name, repo, wc) }},
				{"workflow-unpinned-actions", func() auditRow { return auditGitHubWorkflowUnpinnedActions(ctx, c, owner, name, repo, wc) }},
				{"workflow-pwn-request", func() auditRow { return auditGitHubWorkflowPwnRequest(ctx, c, owner, name, repo, wc) }},
				{"workflow-injection", func() auditRow { return auditGitHubWorkflowInjection(ctx, c, owner, name, repo, wc) }},
				{"oidc-cloud-trust", func() auditRow { return auditGitHubOIDCCloudTrust(ctx, c, owner, name, repo, wc) }},
				{"dependency-review", func() auditRow { return auditGitHubDependencyReview(ctx, c, owner, name, repo, wc) }},
				{"release-provenance", func() auditRow { return auditGitHubReleaseProvenance(ctx, c, owner, name, repo) }},
				{"self-hosted-runners", func() auditRow { return auditGitHubSelfHostedRunners(ctx, c, owner, name, repo) }},
				{"merge-queue", func() auditRow { return auditGitHubMergeQueue(ctx, c, owner, name, repo, rc) }},
				{"tag-protection", func() auditRow { return auditGitHubTagProtection(ctx, c, owner, name, repo, rc) }},
				{"push-ruleset", func() auditRow { return auditGitHubPushRuleset(ctx, c, owner, name, repo, rc) }},
				{"no-merge-method", func() auditRow { return auditGitHubMergeMethods(repo) }},
				{"fork-policy", func() auditRow { return auditGitHubForkPolicy(repo) }},
				{"wiki-attack-surface", func() auditRow { return auditGitHubWikiSurface(repo) }},
				{"dependabot-config", func() auditRow { return auditGitHubDependabotConfig(ctx, c, owner, name, repo) }},
			}
			var local []auditRow
			for _, ch := range checks {
				if want(ch.key) {
					local = append(local, ch.run())
				}
			}
			mu.Lock()
			rows = append(rows, local...)
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return rows, nil
}

func githubAuditRow(repo *github.Repository, key, title, severity string, status ControlStatus, detail, remediation string) auditRow {
	return auditRow{
		Provider:    "github",
		Scope:       "repo",
		Repo:        repo.GetFullName(),
		Control:     key,
		Title:       title,
		Severity:    severity,
		Status:      string(status),
		Detail:      detail,
		Remediation: remediation,
	}
}

func githubAuditErr(repo *github.Repository, key, title, severity string, err error, remediation string) auditRow {
	if endpointUnavailable(err) {
		return githubAuditRow(repo, key, title, severity, StatusSkipped, "unavailable (needs admin access, or feature is off)", remediation)
	}
	return githubAuditRow(repo, key, title, severity, StatusError, err.Error(), remediation)
}

func githubOrgAuditRow(org, key, title, severity string, status ControlStatus, detail, remediation string) auditRow {
	return auditRow{
		Provider:    "github",
		Scope:       "org",
		Repo:        "org/" + org,
		Control:     key,
		Title:       title,
		Severity:    severity,
		Status:      string(status),
		Detail:      detail,
		Remediation: remediation,
	}
}

func githubOrgAuditErr(org, key, title, severity string, err error, remediation string) auditRow {
	if endpointUnavailable(err) {
		return githubOrgAuditRow(org, key, title, severity, StatusSkipped, "unavailable (needs organization admin access, or feature is off)", remediation)
	}
	return githubOrgAuditRow(org, key, title, severity, StatusError, err.Error(), remediation)
}

func githubGlobalAuditRow(key, title, severity string, status ControlStatus, detail, remediation string) auditRow {
	return auditRow{
		Provider:    "github",
		Scope:       "token",
		Repo:        "authenticated-token",
		Control:     key,
		Title:       title,
		Severity:    severity,
		Status:      string(status),
		Detail:      detail,
		Remediation: remediation,
	}
}
