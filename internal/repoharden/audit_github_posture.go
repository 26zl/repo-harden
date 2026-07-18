package repoharden

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-github/v88/github"
)

func auditGitHubDependabotOpenAlerts(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	const (
		key   = "dependabot-open-alerts"
		title = "No open critical/high Dependabot alerts"
		rem   = "Triage and resolve open critical and high Dependabot alerts."
	)
	alerts, err := listGitHubDependabotAlerts(ctx, c, owner, name)
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, key, title, "high", StatusSkipped, "Dependabot alerts unavailable (private without GHAS, or disabled)", rem)
		}
		return githubAuditRow(repo, key, title, "high", StatusError, err.Error(), rem)
	}
	crit, high := 0, 0
	for _, a := range alerts {
		switch a.GetSecurityAdvisory().GetSeverity() {
		case "critical":
			crit++
		case "high":
			high++
		}
	}
	if crit+high > 0 {
		return githubAuditRow(repo, key, title, "high", StatusGap, fmt.Sprintf("%d critical, %d high open alerts", crit, high), rem)
	}
	return githubAuditRow(repo, key, title, "high", StatusCompliant, fmt.Sprintf("%d open alerts, none critical/high", len(alerts)), rem)
}

func auditGitHubRulesetBypass(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository, rc *rulesetListCache) auditRow {
	const (
		key   = "ruleset-bypass"
		title = "Branch rulesets have no bypass actors"
		rem   = "Remove or tighten ruleset bypass actors that let roles skip branch protection."
	)
	sets, err := rc.get(ctx, c, owner, name)
	if err != nil {
		return githubAuditErr(repo, key, title, "medium", err, rem)
	}
	if len(sets) == 0 {
		return githubAuditRow(repo, key, title, "medium", StatusSkipped, "no branch rulesets", rem)
	}
	var withBypass []string
	unresolved := 0
	for _, rs := range sets {
		t := rs.GetTarget()
		if t == nil || *t != github.RulesetTargetBranch || rs.Enforcement != github.RulesetEnforcementActive {
			continue
		}
		full, err := rc.detail(ctx, c, owner, name, rs.GetID())
		if err != nil {
			if endpointUnavailable(err) {
				unresolved++
				continue
			}
			return githubAuditRow(repo, key, title, "medium", StatusError, fmt.Sprintf("read ruleset %d: %s", rs.GetID(), err), rem)
		}
		if full == nil {
			unresolved++
			continue
		}
		if len(full.BypassActors) > 0 {
			withBypass = append(withBypass, rs.Name)
		}
	}
	if len(withBypass) > 0 {
		return githubAuditRow(repo, key, title, "medium", StatusGap, "rulesets with bypass actors: "+strings.Join(limitStrings(withBypass, maxDetailItems), ", "), rem)
	}
	if unresolved > 0 {
		return githubAuditRow(repo, key, title, "medium", StatusSkipped, fmt.Sprintf("could not verify %d ruleset(s) for bypass actors (unavailable or insufficient access)", unresolved), rem)
	}
	return githubAuditRow(repo, key, title, "medium", StatusCompliant, "no bypass actors on active branch rulesets", rem)
}

func auditGitHubOpenSecurityAdvisories(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	const (
		key   = "open-security-advisories"
		title = "No unresolved repository security advisories"
		rem   = "Triage and resolve open repository security advisories (Security tab → Advisories)."
	)
	type triageAdvisory struct {
		GHSAID   string `json:"ghsa_id"`
		Severity string `json:"severity"`
	}
	const perPage = 100
	const maxPages = 20
	var advisories []triageAdvisory
	complete := false
	for page := 1; page <= maxPages; page++ {
		var batch []triageAdvisory
		path := fmt.Sprintf("repos/%s/%s/security-advisories?per_page=%d&state=triage&page=%d", owner, name, perPage, page)
		if err := githubRawGet(ctx, c, path, &batch); err != nil {
			if endpointUnavailable(err) {
				return githubAuditRow(repo, key, title, "high", StatusSkipped, "security advisories API unavailable", rem)
			}
			return githubAuditRow(repo, key, title, "high", StatusError, err.Error(), rem)
		}
		advisories = append(advisories, batch...)
		if len(batch) < perPage {
			complete = true
			break
		}
	}
	if !complete {
		return githubAuditRow(repo, key, title, "high", StatusError, fmt.Sprintf("security advisory pagination exceeded %d pages", maxPages), rem)
	}
	var urgent []string
	for _, a := range advisories {
		if a.Severity == "high" || a.Severity == "critical" {
			urgent = append(urgent, a.GHSAID)
		}
	}
	if len(urgent) > 0 {
		return githubAuditRow(repo, key, title, "high", StatusGap, "unresolved high/critical advisories: "+strings.Join(limitStrings(urgent, maxDetailItems), ", "), rem)
	}
	return githubAuditRow(repo, key, title, "high", StatusCompliant, fmt.Sprintf("%d advisories in triage, none high/critical", len(advisories)), rem)
}

func auditGitHubWorkflowAccessLevel(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	const (
		key   = "workflow-access-level"
		title = "Actions access from outside the repository is limited"
		rem   = "Set Actions access level to 'none' unless other repositories must reuse this repo's workflows."
	)
	var out struct {
		AccessLevel *string `json:"access_level"`
	}
	if err := githubRawGet(ctx, c, fmt.Sprintf("repos/%s/%s/actions/permissions/access", owner, name), &out); err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, key, title, "low", StatusSkipped, "Actions access API unavailable", rem)
		}
		return githubAuditRow(repo, key, title, "low", StatusError, err.Error(), rem)
	}
	if out.AccessLevel == nil || strings.TrimSpace(*out.AccessLevel) == "" {
		return githubAuditRow(repo, key, title, "low", StatusSkipped, "Actions access level is not visible", rem)
	}
	level := strings.TrimSpace(*out.AccessLevel)
	if level == "none" {
		return githubAuditRow(repo, key, title, "low", StatusCompliant, "access level: none", rem)
	}
	switch level {
	case "user", "organization", "enterprise":
		return githubAuditRow(repo, key, title, "low", StatusGap, "access level: "+level+" (other repos can reuse this repo's actions; tighten to none unless intended)", rem)
	default:
		return githubAuditRow(repo, key, title, "low", StatusError, "unknown Actions access level: "+level, rem)
	}
}

func auditGitHubActionsShaPinning(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	const (
		key   = "actions-sha-pinning"
		title = "Actions are required to be pinned to a full commit SHA"
		rem   = "Enable 'Require actions to be pinned to a full-length commit SHA' in Actions settings."
	)
	p, _, err := c.Repositories.GetActionsPermissions(ctx, owner, name)
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, key, title, "medium", StatusSkipped, "Actions permissions API unavailable", rem)
		}
		return githubAuditRow(repo, key, title, "medium", StatusError, err.Error(), rem)
	}
	if p == nil || p.Enabled == nil {
		return githubAuditRow(repo, key, title, "medium", StatusSkipped, "Actions enabled setting not visible", rem)
	}
	if !p.GetEnabled() {
		return githubAuditRow(repo, key, title, "medium", StatusSkipped, "Actions disabled for this repository", rem)
	}
	if p.SHAPinningRequired == nil {
		return githubAuditRow(repo, key, title, "medium", StatusSkipped, "SHA pinning setting not visible (older API or insufficient access)", rem)
	}
	if p.GetSHAPinningRequired() {
		return githubAuditRow(repo, key, title, "medium", StatusCompliant, "actions must be pinned to a full SHA", rem)
	}
	return githubAuditRow(repo, key, title, "medium", StatusGap, "actions may use mutable tags (SHA pinning not required)", rem)
}

func auditGitHubCommunityHealth(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	const (
		key   = "community-health"
		title = "Community health files are present"
		rem   = "Add the missing community files: issue templates, a PR template, CONTRIBUTING, and a code of conduct."
	)
	m, _, err := c.Repositories.GetCommunityHealthMetrics(ctx, owner, name)
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, key, title, "low", StatusSkipped, "community profile API unavailable", rem)
		}
		return githubAuditRow(repo, key, title, "low", StatusError, err.Error(), rem)
	}
	if m == nil || m.Files == nil {
		return githubAuditRow(repo, key, title, "low", StatusSkipped, "community profile not available", rem)
	}
	if m.GetHealthPercentage() == 100 {
		return githubAuditRow(repo, key, title, "low", StatusCompliant, "community health 100%", rem)
	}
	f := m.Files
	var missing []string
	if f.IssueTemplate == nil {
		missing = append(missing, "issue template")
	}
	if f.PullRequestTemplate == nil {
		missing = append(missing, "PR template")
	}
	if f.Contributing == nil {
		missing = append(missing, "CONTRIBUTING")
	}
	if f.CodeOfConduct == nil {
		missing = append(missing, "code of conduct")
	}
	if len(missing) > 0 {
		return githubAuditRow(repo, key, title, "low", StatusGap, fmt.Sprintf("missing: %s (health %d%%)", strings.Join(missing, ", "), m.GetHealthPercentage()), rem)
	}
	return githubAuditRow(repo, key, title, "low", StatusCompliant, fmt.Sprintf("community health %d%%", m.GetHealthPercentage()), rem)
}

func auditGitHubRulesetEvaluateOnly(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository, rc *rulesetListCache) auditRow {
	const (
		key   = "ruleset-evaluate-only"
		title = "Default-branch rulesets are enforced, not evaluate-only"
		rem   = "Switch evaluate-only (dry-run) rulesets to Active so they actually enforce protection."
	)
	branch := repo.GetDefaultBranch()
	if branch == "" {
		return githubAuditRow(repo, key, title, "high", StatusSkipped, "no default branch", rem)
	}
	sets, err := rc.get(ctx, c, owner, name)
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, key, title, "high", StatusSkipped, "rulesets API unavailable", rem)
		}
		return githubAuditRow(repo, key, title, "high", StatusError, err.Error(), rem)
	}
	var evalOnly []string
	for _, rs := range sets {
		if rs.Enforcement != github.RulesetEnforcementEvaluate {
			continue
		}
		if t := rs.GetTarget(); t == nil || *t != github.RulesetTargetBranch {
			continue
		}
		full, err := rc.detail(ctx, c, owner, name, rs.GetID())
		if err != nil {
			if endpointUnavailable(err) {
				return githubAuditRow(repo, key, title, "high", StatusSkipped, "could not read evaluate-only ruleset details", rem)
			}
			return githubAuditRow(repo, key, title, "high", StatusError, err.Error(), rem)
		}
		if full == nil {
			return githubAuditRow(repo, key, title, "high", StatusSkipped, "empty evaluate-only ruleset response", rem)
		}
		if !rulesetTargetsBranch(full, branch) {
			continue
		}
		evalOnly = append(evalOnly, rs.Name)
	}
	if len(evalOnly) > 0 {
		return githubAuditRow(repo, key, title, "high", StatusGap, "evaluate-only (dry-run) rulesets on default branch enforce nothing: "+strings.Join(limitStrings(evalOnly, maxDetailItems), ", "), rem)
	}
	return githubAuditRow(repo, key, title, "high", StatusCompliant, "no evaluate-only rulesets on the default branch", rem)
}

func auditGitHubMergeMethods(repo *github.Repository) auditRow {
	const (
		key   = "no-merge-method"
		title = "At least one pull-request merge method is enabled"
		rem   = "Enable at least one of merge commit, squash, or rebase so pull requests can be merged."
	)
	if repo.AllowMergeCommit == nil || repo.AllowSquashMerge == nil || repo.AllowRebaseMerge == nil {
		return githubAuditRow(repo, key, title, "medium", StatusSkipped, "merge-method settings not visible", rem)
	}
	if !*repo.AllowMergeCommit && !*repo.AllowSquashMerge && !*repo.AllowRebaseMerge {
		return githubAuditRow(repo, key, title, "medium", StatusGap, "all merge methods disabled — no pull request can be merged", rem)
	}
	return githubAuditRow(repo, key, title, "medium", StatusCompliant, "a merge method is enabled", rem)
}

func auditGitHubForkPolicy(repo *github.Repository) auditRow {
	const (
		key   = "fork-policy"
		title = "Forking is disabled on private repositories"
		rem   = "Disable forking on private/internal repos to reduce the risk of code leaving controlled repositories."
	)
	if repo.Private == nil {
		return githubAuditRow(repo, key, title, "low", StatusSkipped, "repository visibility not visible", rem)
	}
	if !repo.GetPrivate() {
		return githubAuditRow(repo, key, title, "low", StatusCompliant, "public repository (forking policy n/a)", rem)
	}
	if repo.AllowForking == nil {
		return githubAuditRow(repo, key, title, "low", StatusSkipped, "private repository forking setting not visible", rem)
	}
	if repo.GetAllowForking() {
		return githubAuditRow(repo, key, title, "low", StatusGap, "private repository allows forking", rem)
	}
	return githubAuditRow(repo, key, title, "low", StatusCompliant, "private repository forking disabled", rem)
}

func auditGitHubWikiSurface(repo *github.Repository) auditRow {
	const (
		key   = "wiki-attack-surface"
		title = "Public repository wiki surface is reviewed"
		rem   = "Disable the wiki on public repos, or restrict who can edit it, to remove a low-visibility editable surface."
	)
	if repo.Private == nil || repo.HasWiki == nil {
		return githubAuditRow(repo, key, title, "low", StatusSkipped, "repository visibility or wiki setting not visible", rem)
	}
	if !repo.GetPrivate() && repo.GetHasWiki() {
		return githubAuditRow(repo, key, title, "low", StatusGap, "public repository has an open, editable wiki", rem)
	}
	return githubAuditRow(repo, key, title, "low", StatusCompliant, "no public open wiki", rem)
}
