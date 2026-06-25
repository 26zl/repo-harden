package repoharden

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/go-github/v88/github"
	"gopkg.in/yaml.v3"
)

func collectGitHubExtendedAudit(ctx context.Context, c *github.Client, o *opts, repos []*github.Repository) ([]auditRow, error) {
	// gate each check by --only/--skip before the API call so we skip the work, not just the row
	want := wantFunc(o)
	var rows []auditRow
	packageCache := map[string]githubPackageListResult{}
	if want("token-scopes") {
		rows = append(rows, auditGitHubTokenScopes(ctx, c)...)
	}
	if want("account-2fa") {
		rows = append(rows, auditGitHubAccountTwoFactor(ctx, c))
	}
	if o.orgAudit {
		rows = append(rows, auditGitHubOrganizations(ctx, c, repos, want)...)
	}
	for _, repo := range repos {
		owner, name := splitRepo(repo.GetFullName())
		checks := []struct {
			key string
			run func() auditRow
		}{
			{"public-exposure", func() auditRow { return auditGitHubPublicExposure(repo) }},
			{"stale-repo", func() auditRow { return auditGitHubStaleRepo(repo, o.staleDays) }},
			{"default-branch", func() auditRow { return auditGitHubDefaultBranch(repo) }},
			{"merge-hygiene", func() auditRow { return auditGitHubMergeHygiene(repo) }},
			{"branch-protection-full", func() auditRow { return auditGitHubBranchProtection(ctx, c, owner, name, repo) }},
			{"signed-commits", func() auditRow { return auditGitHubSignedCommits(ctx, c, owner, name, repo) }},
			{"required-workflows", func() auditRow { return auditGitHubRequiredWorkflows(ctx, c, owner, name, repo) }},
			{"actions-fork-pr-permissions", func() auditRow { return auditGitHubForkPRPolicy(ctx, c, owner, name, repo) }},
			{"environment-protection", func() auditRow { return auditGitHubEnvironments(ctx, c, owner, name, repo) }},
			{"repo-secrets", func() auditRow { return auditGitHubRepoSecrets(ctx, c, owner, name, repo, o.staleDays) }},
			{"deploy-keys", func() auditRow { return auditGitHubDeployKeys(ctx, c, owner, name, repo) }},
			{"webhooks", func() auditRow { return auditGitHubWebhooks(ctx, c, owner, name, repo) }},
			{"collaborators", func() auditRow { return auditGitHubCollaborators(ctx, c, owner, name, repo) }},
			{"vulnerability-alert-count", func() auditRow { return auditGitHubVulnerabilityCounts(ctx, c, owner, name, repo) }},
			{"code-scanning-alert-count", func() auditRow { return auditGitHubCodeScanningCounts(ctx, c, owner, name, repo) }},
			{"secret-scanning-alert-count", func() auditRow { return auditGitHubSecretScanningCounts(ctx, c, owner, name, repo) }},
			{"archived-active-risk", func() auditRow { return auditGitHubArchivedActiveRisk(ctx, c, owner, name, repo) }},
			{"releases", func() auditRow { return auditGitHubReleases(ctx, c, owner, name, repo) }},
			{"packages", func() auditRow { return auditGitHubPackages(ctx, c, owner, repo, packageCache) }},
			{"dependency-sbom", func() auditRow { return auditGitHubSBOM(ctx, c, owner, name, repo) }},
			{"dependabot-open-alerts", func() auditRow { return auditGitHubDependabotOpenAlerts(ctx, c, owner, name, repo) }},
			{"ruleset-bypass", func() auditRow { return auditGitHubRulesetBypass(ctx, c, owner, name, repo) }},
			{"open-security-advisories", func() auditRow { return auditGitHubOpenSecurityAdvisories(ctx, c, owner, name, repo) }},
			{"workflow-access-level", func() auditRow { return auditGitHubWorkflowAccessLevel(ctx, c, owner, name, repo) }},
			{"actions-sha-pinning", func() auditRow { return auditGitHubActionsShaPinning(ctx, c, owner, name, repo) }},
			{"community-health", func() auditRow { return auditGitHubCommunityHealth(ctx, c, owner, name, repo) }},
			{"code-scanning-conflict", func() auditRow { return auditGitHubCodeScanningConflict(ctx, c, owner, name, repo) }},
			{"ruleset-evaluate-only", func() auditRow { return auditGitHubRulesetEvaluateOnly(ctx, c, owner, name, repo) }},
			{"workflow-token-permissions", func() auditRow { return auditGitHubWorkflowTokenPermissions(ctx, c, owner, name, repo) }},
			{"no-merge-method", func() auditRow { return auditGitHubMergeMethods(repo) }},
			{"fork-policy", func() auditRow { return auditGitHubForkPolicy(repo) }},
			{"wiki-attack-surface", func() auditRow { return auditGitHubWikiSurface(repo) }},
			{"dependabot-config", func() auditRow { return auditGitHubDependabotConfig(ctx, c, owner, name, repo) }},
		}
		for _, ch := range checks {
			if want(ch.key) {
				rows = append(rows, ch.run())
			}
		}
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

// returns a Skipped row if the endpoint is just unavailable (no admin access or feature off), else Error.
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

func auditGitHubPublicExposure(repo *github.Repository) auditRow {
	if repo.GetPrivate() {
		return githubAuditRow(repo, "public-exposure", "Repository visibility reviewed", "medium", StatusCompliant, "private repository", "Review public repositories and make unintended public repos private.")
	}
	return githubAuditRow(repo, "public-exposure", "Repository visibility reviewed", "medium", StatusGap, "public repository", "Confirm the repository is intentionally public and contains no private assets or secrets.")
}

func auditGitHubStaleRepo(repo *github.Repository, staleDays int) auditRow {
	pushed := repo.GetPushedAt()
	if pushed.IsZero() {
		return githubAuditRow(repo, "stale-repo", "Repository activity is recent", "low", StatusSkipped, "no pushed_at timestamp", "Archive, transfer, or refresh stale repositories.")
	}
	age := time.Since(pushed.Time)
	if age > time.Duration(staleDays)*24*time.Hour {
		return githubAuditRow(repo, "stale-repo", "Repository activity is recent", "low", StatusGap, fmt.Sprintf("last push %d days ago", int(age.Hours()/24)), "Archive or refresh stale repositories and remove unused secrets, hooks, and deploy keys.")
	}
	return githubAuditRow(repo, "stale-repo", "Repository activity is recent", "low", StatusCompliant, fmt.Sprintf("last push %d days ago", int(age.Hours()/24)), "Archive or refresh stale repositories and remove unused secrets, hooks, and deploy keys.")
}

func auditGitHubDefaultBranch(repo *github.Repository) auditRow {
	if repo.GetDefaultBranch() == "" {
		return githubAuditRow(repo, "default-branch", "Default branch is set", "medium", StatusGap, "no default branch", "Set a default branch before enabling branch and ruleset protections.")
	}
	return githubAuditRow(repo, "default-branch", "Default branch is set", "medium", StatusCompliant, "default branch: "+repo.GetDefaultBranch(), "Set a default branch before enabling branch and ruleset protections.")
}

func auditGitHubMergeHygiene(repo *github.Repository) auditRow {
	const (
		key   = "merge-hygiene"
		title = "Merge settings follow hygiene defaults"
		rem   = "Enable 'automatically delete head branches'; only use auto-merge with required reviews and status checks."
	)
	var issues []string
	if !repo.GetDeleteBranchOnMerge() {
		issues = append(issues, "delete-branch-on-merge off")
	}
	if repo.GetAllowAutoMerge() {
		issues = append(issues, "auto-merge enabled (require reviews/checks)")
	}
	if len(issues) > 0 {
		return githubAuditRow(repo, key, title, "low", StatusGap, strings.Join(issues, "; "), rem)
	}
	return githubAuditRow(repo, key, title, "low", StatusCompliant, "delete-branch-on-merge on; auto-merge off", rem)
}

func auditGitHubBranchProtection(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	branch := repo.GetDefaultBranch()
	if branch == "" {
		return githubAuditRow(repo, "branch-protection-full", "Default branch protection is complete", "high", StatusSkipped, "no default branch", "Protect the default branch with PR reviews, status checks, admin enforcement, signed commits, and no force pushes.")
	}
	rules, rulesErr := githubActiveRuleTypes(ctx, c, owner, name, branch)
	p, _, err := c.Repositories.GetBranchProtection(ctx, owner, name, branch)
	if err != nil {
		if errors.Is(err, github.ErrBranchNotProtected) || githubStatus(err) == http.StatusNotFound {
			if rulesErr != nil {
				if endpointUnavailable(rulesErr) {
					return githubAuditRow(repo, "branch-protection-full", "Default branch protection is complete", "high", StatusSkipped, "branch not protected and rulesets unavailable", "Protect the default branch with PR reviews, status checks, admin enforcement, signed commits, and no force pushes.")
				}
				return githubAuditRow(repo, "branch-protection-full", "Default branch protection is complete", "high", StatusError, rulesErr.Error(), "Protect the default branch with PR reviews, status checks, admin enforcement, signed commits, and no force pushes.")
			}
			// rulesErr is nil here (handled above)
			missing := branchProtectionMissing(nil, rules)
			if len(missing) == 0 {
				return githubAuditRow(repo, "branch-protection-full", "Default branch protection is complete", "high", StatusCompliant, "active rulesets enforce core default-branch safeguards", "Protect the default branch with PR reviews, status checks, admin enforcement, signed commits, and no force pushes.")
			}
			detail := "default branch is not protected"
			if len(missing) > 0 {
				detail = "missing: " + strings.Join(missing, ", ")
			}
			return githubAuditRow(repo, "branch-protection-full", "Default branch protection is complete", "high", StatusGap, detail, "Protect the default branch with PR reviews, status checks, admin enforcement, signed commits, and no force pushes.")
		}
		return githubAuditRow(repo, "branch-protection-full", "Default branch protection is complete", "high", StatusError, err.Error(), "Protect the default branch with PR reviews, status checks, admin enforcement, signed commits, and no force pushes.")
	}
	missing := branchProtectionMissing(p, rules)
	if len(missing) > 0 {
		return githubAuditRow(repo, "branch-protection-full", "Default branch protection is complete", "high", StatusGap, "missing: "+strings.Join(missing, ", "), "Protect the default branch with PR reviews, status checks, admin enforcement, signed commits, and no force pushes.")
	}
	return githubAuditRow(repo, "branch-protection-full", "Default branch protection is complete", "high", StatusCompliant, "default branch protection has core safeguards", "Protect the default branch with PR reviews, status checks, admin enforcement, signed commits, and no force pushes.")
}

func auditGitHubSignedCommits(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	branch := repo.GetDefaultBranch()
	if branch == "" {
		return githubAuditRow(repo, "signed-commits", "Signed commits required on default branch", "medium", StatusSkipped, "no default branch", "Require signed commits through branch protection or rulesets.")
	}
	p, _, err := c.Repositories.GetBranchProtection(ctx, owner, name, branch)
	if err != nil {
		if errors.Is(err, github.ErrBranchNotProtected) || githubStatus(err) == http.StatusNotFound {
			rules, ruleErr := githubActiveRuleTypes(ctx, c, owner, name, branch)
			if ruleErr != nil {
				if endpointUnavailable(ruleErr) {
					return githubAuditRow(repo, "signed-commits", "Signed commits required on default branch", "medium", StatusSkipped, "branch not protected and rulesets unavailable", "Require signed commits through branch protection or rulesets.")
				}
				return githubAuditRow(repo, "signed-commits", "Signed commits required on default branch", "medium", StatusError, ruleErr.Error(), "Require signed commits through branch protection or rulesets.")
			}
			if rules["required_signatures"] {
				return githubAuditRow(repo, "signed-commits", "Signed commits required on default branch", "medium", StatusCompliant, "required signatures enforced by ruleset", "Require signed commits through branch protection or rulesets.")
			}
			return githubAuditRow(repo, "signed-commits", "Signed commits required on default branch", "medium", StatusGap, "default branch is not protected", "Require signed commits through branch protection or rulesets.")
		}
		return githubAuditRow(repo, "signed-commits", "Signed commits required on default branch", "medium", StatusError, err.Error(), "Require signed commits through branch protection or rulesets.")
	}
	if p != nil && p.RequiredSignatures != nil && p.RequiredSignatures.GetEnabled() {
		return githubAuditRow(repo, "signed-commits", "Signed commits required on default branch", "medium", StatusCompliant, "required signatures enabled", "Require signed commits through branch protection or rulesets.")
	}
	rules, err := githubActiveRuleTypes(ctx, c, owner, name, branch)
	if err == nil && rules["required_signatures"] {
		return githubAuditRow(repo, "signed-commits", "Signed commits required on default branch", "medium", StatusCompliant, "required signatures enforced by ruleset", "Require signed commits through branch protection or rulesets.")
	}
	return githubAuditRow(repo, "signed-commits", "Signed commits required on default branch", "medium", StatusGap, "signed commits not required", "Require signed commits through branch protection or rulesets.")
}

func auditGitHubRequiredWorkflows(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	rules, err := githubActiveRuleTypes(ctx, c, owner, name, repo.GetDefaultBranch())
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, "required-workflows", "Required workflows are enforced", "medium", StatusSkipped, "rulesets API unavailable", "Use organization or repository rulesets to require critical workflows.")
		}
		return githubAuditRow(repo, "required-workflows", "Required workflows are enforced", "medium", StatusError, err.Error(), "Use organization or repository rulesets to require critical workflows.")
	}
	if rules["workflows"] {
		return githubAuditRow(repo, "required-workflows", "Required workflows are enforced", "medium", StatusCompliant, "required workflows ruleset present", "Use organization or repository rulesets to require critical workflows.")
	}
	return githubAuditRow(repo, "required-workflows", "Required workflows are enforced", "medium", StatusGap, "no required workflow rule found", "Use organization or repository rulesets to require critical workflows.")
}

// returns the rule types active rulesets enforce on the branch.
// the list endpoint drops rules/conditions, so we fetch each ruleset's detail and
// only count ones whose ref conditions actually cover this branch.
func githubActiveRuleTypes(ctx context.Context, c *github.Client, owner, name, branch string) (map[string]bool, error) {
	sets, _, err := c.Repositories.GetAllRulesets(ctx, owner, name, &github.RepositoryListRulesetsOptions{IncludesParents: github.Ptr(true)})
	if err != nil {
		return nil, err
	}
	rules := map[string]bool{}
	for _, summary := range sets {
		if summary.Enforcement != github.RulesetEnforcementActive {
			continue
		}
		if t := summary.GetTarget(); t == nil || *t != github.RulesetTargetBranch {
			continue // only branch rulesets protect a branch
		}
		full, _, err := c.Repositories.GetRuleset(ctx, owner, name, summary.GetID(), true)
		if err != nil || full == nil || full.Rules == nil || !rulesetTargetsBranch(full, branch) {
			continue
		}
		r := full.Rules
		if r.PullRequest != nil && r.PullRequest.RequiredApprovingReviewCount >= 1 {
			rules["pull_request"] = true
		}
		if r.PullRequest != nil && r.PullRequest.RequiredReviewThreadResolution {
			rules["thread_resolution"] = true
		}
		if r.RequiredStatusChecks != nil && len(r.RequiredStatusChecks.RequiredStatusChecks) > 0 {
			rules["required_status_checks"] = true
		}
		if r.NonFastForward != nil {
			rules["non_fast_forward"] = true
		}
		if r.Deletion != nil {
			rules["deletion"] = true
		}
		if r.RequiredLinearHistory != nil {
			rules["required_linear_history"] = true
		}
		if r.RequiredSignatures != nil {
			rules["required_signatures"] = true
		}
		if r.Workflows != nil {
			rules["workflows"] = true
		}
	}
	return rules, nil
}

// does the ruleset's ref conditions cover this branch?
func rulesetTargetsBranch(rs *github.RepositoryRuleset, branch string) bool {
	if rs.Conditions == nil || rs.Conditions.RefName == nil {
		return true // no ref condition, so applies to all refs
	}
	ref := "refs/heads/" + branch
	cond := rs.Conditions.RefName
	included := false
	for _, p := range cond.Include {
		if refPatternMatches(p, ref, branch) {
			included = true
			break
		}
	}
	if !included {
		return false
	}
	for _, p := range cond.Exclude {
		if refPatternMatches(p, ref, branch) {
			return false
		}
	}
	return true
}

// matches a GitHub ruleset ref pattern against a branch ref.
func refPatternMatches(pattern, ref, branch string) bool {
	switch pattern {
	case "~ALL", "~DEFAULT_BRANCH":
		return true
	}
	if branch == "" {
		return false
	}
	return globMatch(pattern, ref)
}

// GitHub fnmatch-style ref matching: "*" stays in a segment, "**" crosses "/", "?" is one non-"/" char.
func globMatch(pattern, s string) bool {
	if pattern == "" {
		return s == ""
	}
	switch pattern[0] {
	case '*':
		if len(pattern) > 1 && pattern[1] == '*' {
			rest := pattern[2:]
			for i := 0; i <= len(s); i++ { // ** eats anything, including "/"
				if globMatch(rest, s[i:]) {
					return true
				}
			}
			return false
		}
		for i := 0; i <= len(s); i++ { // * doesn't cross "/"
			if globMatch(pattern[1:], s[i:]) {
				return true
			}
			if i < len(s) && s[i] == '/' {
				break
			}
		}
		return false
	case '?':
		if s == "" || s[0] == '/' {
			return false
		}
		return globMatch(pattern[1:], s[1:])
	default:
		if s == "" || s[0] != pattern[0] {
			return false
		}
		return globMatch(pattern[1:], s[1:])
	}
}

func branchProtectionMissing(p *github.Protection, rules map[string]bool) []string {
	var missing []string
	if (p == nil || p.RequiredPullRequestReviews == nil || p.RequiredPullRequestReviews.RequiredApprovingReviewCount < 1) && !rules["pull_request"] {
		missing = append(missing, "review")
	}
	if (p == nil || p.RequiredStatusChecks == nil || (len(p.RequiredStatusChecks.GetContexts()) == 0 && len(p.RequiredStatusChecks.GetChecks()) == 0)) && !rules["required_status_checks"] {
		missing = append(missing, "status checks")
	}
	if p != nil && (p.EnforceAdmins == nil || !p.EnforceAdmins.Enabled) {
		missing = append(missing, "admin enforcement")
	}
	// a ruleset can satisfy these too, so it's only missing when both legacy
	// protection and the ruleset lack it (same as the review/status checks above).
	if (p == nil || p.RequiredConversationResolution == nil || !p.RequiredConversationResolution.Enabled) && !rules["thread_resolution"] {
		missing = append(missing, "conversation resolution")
	}
	if (p == nil || (p.AllowForcePushes != nil && p.AllowForcePushes.Enabled)) && !rules["non_fast_forward"] {
		missing = append(missing, "force-push disabled")
	}
	if (p == nil || (p.AllowDeletions != nil && p.AllowDeletions.Enabled)) && !rules["deletion"] {
		missing = append(missing, "deletion disabled")
	}
	if (p == nil || p.RequireLinearHistory == nil || !p.RequireLinearHistory.Enabled) && !rules["required_linear_history"] {
		missing = append(missing, "linear history")
	}
	return missing
}

func auditGitHubForkPRPolicy(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	var out struct {
		ApprovalPolicy string `json:"approval_policy"`
	}
	if err := githubRawGet(ctx, c, fmt.Sprintf("repos/%s/%s/actions/permissions/fork-pr-contributor-approval", owner, name), &out); err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, "actions-fork-pr-permissions", "Fork PR approval policy is restrictive", "medium", StatusSkipped, "fork PR approval API unavailable", "Require approval before running workflows from fork pull requests.")
		}
		return githubAuditRow(repo, "actions-fork-pr-permissions", "Fork PR approval policy is restrictive", "medium", StatusError, err.Error(), "Require approval before running workflows from fork pull requests.")
	}
	switch out.ApprovalPolicy {
	case "first_time_contributors_new_to_github", "first_time_contributors":
		return githubAuditRow(repo, "actions-fork-pr-permissions", "Fork PR approval policy is restrictive", "medium", StatusCompliant, "approval policy: "+out.ApprovalPolicy, "Require approval before running workflows from fork pull requests.")
	default:
		return githubAuditRow(repo, "actions-fork-pr-permissions", "Fork PR approval policy is restrictive", "medium", StatusGap, "approval policy: "+out.ApprovalPolicy, "Require approval before running workflows from fork pull requests.")
	}
}

func auditGitHubEnvironments(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	envs, err := listGitHubEnvironments(ctx, c, owner, name)
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, "environment-protection", "Deployment environments are protected", "medium", StatusSkipped, "environments API unavailable", "Add required reviewers or branch policies to production-like environments.")
		}
		return githubAuditErr(repo, "environment-protection", "Deployment environments are protected", "medium", err, "Add required reviewers or branch policies to production-like environments.")
	}
	if len(envs) == 0 {
		return githubAuditRow(repo, "environment-protection", "Deployment environments are protected", "medium", StatusCompliant, "no deployment environments", "Add required reviewers or branch policies to production-like environments.")
	}
	var weak []string
	for _, env := range envs {
		name := strings.ToLower(env.GetName())
		prodLike := strings.Contains(name, "prod") || strings.Contains(name, "stage") || strings.Contains(name, "deploy")
		protected := len(env.ProtectionRules) > 0 || len(env.Reviewers) > 0 || env.DeploymentBranchPolicy != nil || env.GetWaitTimer() > 0
		if prodLike && !protected {
			weak = append(weak, env.GetName())
		}
	}
	if len(weak) > 0 {
		return githubAuditRow(repo, "environment-protection", "Deployment environments are protected", "medium", StatusGap, "unprotected production-like environments: "+strings.Join(weak, ", "), "Add required reviewers or branch policies to production-like environments.")
	}
	return githubAuditRow(repo, "environment-protection", "Deployment environments are protected", "medium", StatusCompliant, fmt.Sprintf("%d environments reviewed", len(envs)), "Add required reviewers or branch policies to production-like environments.")
}

func auditGitHubRepoSecrets(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository, staleDays int) auditRow {
	secrets, total, err := listGitHubRepoSecrets(ctx, c, owner, name)
	if err != nil {
		return githubAuditErr(repo, "repo-secrets", "Repository secrets are reviewed and rotated", "medium", err, "Rotate stale secrets and move shared secrets to org or environment scope where possible.")
	}
	var stale []string
	cutoff := time.Now().Add(-time.Duration(staleDays) * 24 * time.Hour)
	for _, secret := range secrets {
		if secret.UpdatedAt.Time.Before(cutoff) {
			stale = append(stale, secret.Name)
		}
	}
	if len(stale) > 0 {
		return githubAuditRow(repo, "repo-secrets", "Repository secrets are reviewed and rotated", "medium", StatusGap, fmt.Sprintf("%d stale secrets: %s", len(stale), strings.Join(limitStrings(stale, maxDetailItems), ", ")), "Rotate stale secrets and move shared secrets to org or environment scope where possible.")
	}
	return githubAuditRow(repo, "repo-secrets", "Repository secrets are reviewed and rotated", "medium", StatusCompliant, fmt.Sprintf("%d repository secrets", total), "Rotate stale secrets and move shared secrets to org or environment scope where possible.")
}

func auditGitHubDeployKeys(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	keys, err := listGitHubDeployKeys(ctx, c, owner, name)
	if err != nil {
		return githubAuditErr(repo, "deploy-keys", "Deploy keys are read-only or absent", "high", err, "Remove unused deploy keys and make remaining keys read-only.")
	}
	var writable []string
	for _, key := range keys {
		if !key.GetReadOnly() {
			writable = append(writable, key.GetTitle())
		}
	}
	if len(writable) > 0 {
		return githubAuditRow(repo, "deploy-keys", "Deploy keys are read-only or absent", "high", StatusGap, "writable deploy keys: "+strings.Join(limitStrings(writable, maxDetailItems), ", "), "Remove unused deploy keys and make remaining keys read-only.")
	}
	return githubAuditRow(repo, "deploy-keys", "Deploy keys are read-only or absent", "high", StatusCompliant, fmt.Sprintf("%d deploy keys, none writable", len(keys)), "Remove unused deploy keys and make remaining keys read-only.")
}

func auditGitHubWebhooks(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	hooks, err := listGitHubHooks(ctx, c, owner, name)
	if err != nil {
		return githubAuditErr(repo, "webhooks", "Repository webhooks use TLS and active hooks are reviewed", "medium", err, "Remove stale webhooks, require HTTPS, and avoid insecure SSL.")
	}
	var weak []string
	for _, hook := range hooks {
		if !hook.GetActive() {
			continue
		}
		url := ""
		insecure := ""
		if hook.Config != nil {
			url = hook.Config.GetURL()
			insecure = hook.Config.GetInsecureSSL()
		}
		if !strings.HasPrefix(strings.ToLower(url), "https://") || insecure == "1" {
			weak = append(weak, fmt.Sprintf("%d", hook.GetID()))
		}
	}
	if len(weak) > 0 {
		return githubAuditRow(repo, "webhooks", "Repository webhooks use TLS and active hooks are reviewed", "medium", StatusGap, "weak active webhooks: "+strings.Join(weak, ", "), "Remove stale webhooks, require HTTPS, and avoid insecure SSL.")
	}
	return githubAuditRow(repo, "webhooks", "Repository webhooks use TLS and active hooks are reviewed", "medium", StatusCompliant, fmt.Sprintf("%d webhooks reviewed", len(hooks)), "Remove stale webhooks, require HTTPS, and avoid insecure SSL.")
}

func auditGitHubCollaborators(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	outside, err := listGitHubCollaborators(ctx, c, owner, name, github.ListCollaboratorsOptions{Affiliation: "outside"})
	if err != nil {
		if githubStatus(err) == http.StatusUnprocessableEntity {
			return githubAuditRow(repo, "collaborators", "Outside collaborators are minimized", "medium", StatusSkipped, "outside collaborators only applies to organization repos", "Remove stale outside collaborators and review direct admin access.")
		}
		return githubAuditErr(repo, "collaborators", "Outside collaborators are minimized", "medium", err, "Remove stale outside collaborators and review direct admin access.")
	}
	admins, adminErr := listGitHubCollaborators(ctx, c, owner, name, github.ListCollaboratorsOptions{Permission: "admin"})
	if adminErr != nil {
		return githubAuditRow(repo, "collaborators", "Outside collaborators are minimized", "medium", StatusError, adminErr.Error(), "Remove stale outside collaborators and review direct admin access.")
	}
	if len(outside) > 0 {
		return githubAuditRow(repo, "collaborators", "Outside collaborators are minimized", "medium", StatusGap, fmt.Sprintf("%d outside collaborators, %d admins", len(outside), len(admins)), "Remove stale outside collaborators and review direct admin access.")
	}
	return githubAuditRow(repo, "collaborators", "Outside collaborators are minimized", "medium", StatusCompliant, fmt.Sprintf("0 outside collaborators, %d admins", len(admins)), "Remove stale outside collaborators and review direct admin access.")
}

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

type githubPackageListResult struct {
	packages      []*github.Package
	skippedDetail string
	err           error
}

var githubPackageTypes = []string{"container", "docker", "npm", "maven", "nuget", "rubygems"}

func auditGitHubPackages(ctx context.Context, c *github.Client, owner string, repo *github.Repository, cache map[string]githubPackageListResult) auditRow {
	ownerType := repo.GetOwner().GetType()
	cacheKey := ownerType + "/" + owner
	result, ok := cache[cacheKey]
	if !ok {
		result = listGitHubOwnerPackages(ctx, c, owner, ownerType == "Organization")
		cache[cacheKey] = result
	}
	if result.err != nil {
		return githubAuditRow(repo, "packages", "GitHub Packages are inventoried", "low", StatusError, result.err.Error(), "Review package visibility, stale versions, and repository package permissions.")
	}
	if result.skippedDetail != "" {
		return githubAuditRow(repo, "packages", "GitHub Packages are inventoried", "low", StatusSkipped, result.skippedDetail, "Review package visibility, stale versions, and repository package permissions.")
	}

	var linked []string
	var publicLinked []string
	for _, pkg := range result.packages {
		if !strings.EqualFold(pkg.GetRepository().GetFullName(), repo.GetFullName()) {
			continue
		}
		label := pkg.GetPackageType() + "/" + pkg.GetName()
		linked = append(linked, label)
		if repo.GetPrivate() && pkg.GetVisibility() == "public" {
			publicLinked = append(publicLinked, label)
		}
	}
	if len(publicLinked) > 0 {
		return githubAuditRow(repo, "packages", "GitHub Packages are inventoried", "low", StatusGap, "public packages linked to private repo: "+strings.Join(limitStrings(publicLinked, maxDetailItems), ", "), "Review package visibility, stale versions, and repository package permissions.")
	}
	if len(linked) == 0 {
		return githubAuditRow(repo, "packages", "GitHub Packages are inventoried", "low", StatusCompliant, "0 linked packages visible", "Review package visibility, stale versions, and repository package permissions.")
	}
	return githubAuditRow(repo, "packages", "GitHub Packages are inventoried", "low", StatusCompliant, fmt.Sprintf("%d linked packages: %s", len(linked), strings.Join(limitStrings(linked, maxDetailItems), ", ")), "Review package visibility, stale versions, and repository package permissions.")
}

func listGitHubOwnerPackages(ctx context.Context, c *github.Client, owner string, org bool) githubPackageListResult {
	var all []*github.Package
	unavailable := 0
	for _, packageType := range githubPackageTypes {
		opts := &github.PackageListOptions{
			PackageType: github.Ptr(packageType),
			State:       github.Ptr("active"),
			ListOptions: github.ListOptions{PerPage: 100},
		}
		for {
			var (
				packages []*github.Package
				resp     *github.Response
				err      error
			)
			if org {
				packages, resp, err = c.Organizations.ListPackages(ctx, owner, opts)
			} else {
				packages, resp, err = c.Users.ListPackages(ctx, owner, opts)
			}
			if err != nil {
				if endpointUnavailable(err) {
					unavailable++
					break
				}
				return githubPackageListResult{err: err}
			}
			all = append(all, packages...)
			if resp == nil || resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
		}
	}
	if unavailable == len(githubPackageTypes) {
		return githubPackageListResult{skippedDetail: "GitHub Packages API unavailable"}
	}
	return githubPackageListResult{packages: all}
}

func auditGitHubSBOM(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	var out map[string]any
	if err := githubRawGet(ctx, c, fmt.Sprintf("repos/%s/%s/dependency-graph/sbom", owner, name), &out); err != nil {
		if githubStatus(err) == http.StatusNotFound {
			return githubAuditRow(repo, "dependency-sbom", "Dependency graph SBOM is available", "medium", StatusGap, "SBOM endpoint unavailable", "Enable dependency graph/SBOM support and commit lockfiles where relevant.")
		}
		return githubAuditRow(repo, "dependency-sbom", "Dependency graph SBOM is available", "medium", StatusError, err.Error(), "Enable dependency graph/SBOM support and commit lockfiles where relevant.")
	}
	return githubAuditRow(repo, "dependency-sbom", "Dependency graph SBOM is available", "medium", StatusCompliant, "SBOM endpoint returned data", "Enable dependency graph/SBOM support and commit lockfiles where relevant.")
}

func auditGitHubTokenScopes(ctx context.Context, c *github.Client) []auditRow {
	_, resp, err := c.Users.Get(ctx, "")
	if err != nil {
		return []auditRow{githubGlobalAuditRow("token-scopes", "Token scopes are visible and not excessive", "medium", StatusError, err.Error(), "Use least-privilege fine-grained tokens where possible.")}
	}
	scopes := ""
	if resp != nil && resp.Response != nil {
		scopes = resp.Response.Header.Get("X-OAuth-Scopes")
	}
	if scopes == "" {
		return []auditRow{githubGlobalAuditRow("token-scopes", "Token scopes are visible and not excessive", "medium", StatusSkipped, "OAuth scopes header unavailable (fine-grained token or GitHub App token)", "Use least-privilege fine-grained tokens where possible.")}
	}
	if strings.Contains(scopes, "admin:org") || strings.Contains(scopes, "delete_repo") {
		return []auditRow{githubGlobalAuditRow("token-scopes", "Token scopes are visible and not excessive", "medium", StatusGap, "broad token scopes: "+scopes, "Use least-privilege fine-grained tokens where possible.")}
	}
	return []auditRow{githubGlobalAuditRow("token-scopes", "Token scopes are visible and not excessive", "medium", StatusCompliant, "token scopes: "+scopes, "Use least-privilege fine-grained tokens where possible.")}
}

func auditGitHubAccountTwoFactor(ctx context.Context, c *github.Client) auditRow {
	const (
		key   = "account-2fa"
		title = "Authenticated account has two-factor authentication enabled"
		rem   = "Enable two-factor authentication on your account (Settings -> Password and authentication)."
	)
	u, _, err := c.Users.Get(ctx, "")
	if err != nil {
		return githubGlobalAuditRow(key, title, "high", StatusError, err.Error(), rem)
	}
	if u == nil || u.TwoFactorAuthentication == nil {
		return githubGlobalAuditRow(key, title, "high", StatusSkipped, "2FA status not visible (token needs read:user scope)", rem)
	}
	if u.GetTwoFactorAuthentication() {
		return githubGlobalAuditRow(key, title, "high", StatusCompliant, "account 2FA enabled", rem)
	}
	return githubGlobalAuditRow(key, title, "high", StatusGap, "account 2FA disabled", rem)
}

func auditGitHubDependabotConfig(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	const (
		key   = "dependabot-config"
		title = "Dependabot version updates are configured"
		rem   = "Add .github/dependabot.yml to enable Dependabot version updates."
	)
	ok, err := fileExists(ctx, c, owner, name, ".github/dependabot.yml", ".github/dependabot.yaml")
	if err != nil {
		return githubAuditRow(repo, key, title, "low", StatusError, err.Error(), rem)
	}
	if ok {
		return githubAuditRow(repo, key, title, "low", StatusCompliant, ".github/dependabot.yml present", rem)
	}
	return githubAuditRow(repo, key, title, "low", StatusGap, "no .github/dependabot.yml (report-only)", rem)
}

func auditGitHubOrganizations(ctx context.Context, c *github.Client, repos []*github.Repository, want func(string) bool) []auditRow {
	orgs := map[string]bool{}
	for _, repo := range repos {
		owner := repo.GetOwner()
		if owner.GetType() == "Organization" {
			orgs[owner.GetLogin()] = true
		}
	}
	var names []string
	for org := range orgs {
		names = append(names, org)
	}
	sort.Strings(names)
	var rows []auditRow
	for _, org := range names {
		if want("org-actions-policy") {
			rows = append(rows, auditGitHubOrgActionsPolicy(ctx, c, org))
		}
		if want("org-token-policy") {
			rows = append(rows, auditGitHubOrgTokenPolicy(ctx, c, org))
		}
		if want("org-secrets") {
			rows = append(rows, auditGitHubOrgSecrets(ctx, c, org))
		}
		if want("org-webhooks") {
			rows = append(rows, auditGitHubOrgWebhooks(ctx, c, org))
		}
		if want("org-2fa") || want("org-base-permission") {
			info, _, infoErr := c.Organizations.Get(ctx, org)
			if want("org-2fa") {
				rows = append(rows, auditGitHubOrg2FA(org, info, infoErr))
			}
			if want("org-base-permission") {
				rows = append(rows, auditGitHubOrgBasePermission(org, info, infoErr))
			}
		}
		if want("org-2fa-disabled-members") {
			rows = append(rows, auditGitHubOrg2FADisabledMembers(ctx, c, org))
		}
		if want("org-outside-collaborators") {
			rows = append(rows, auditGitHubOrgOutsideCollaborators(ctx, c, org))
		}
	}
	return rows
}

func auditGitHubOrg2FA(org string, info *github.Organization, err error) auditRow {
	const (
		key   = "org-2fa"
		title = "Organization requires two-factor authentication"
		rem   = "Require two-factor authentication for all organization members."
	)
	if err != nil {
		return githubOrgAuditRow(org, key, title, "high", StatusError, err.Error(), rem)
	}
	if info == nil {
		return githubOrgAuditRow(org, key, title, "high", StatusSkipped, "organization details unavailable", rem)
	}
	if info.TwoFactorRequirementEnabled == nil {
		return githubOrgAuditRow(org, key, title, "high", StatusSkipped, "2FA requirement not visible (needs org admin)", rem)
	}
	if info.GetTwoFactorRequirementEnabled() {
		return githubOrgAuditRow(org, key, title, "high", StatusCompliant, "2FA required for all members", rem)
	}
	return githubOrgAuditRow(org, key, title, "high", StatusGap, "2FA not required org-wide", rem)
}

func auditGitHubOrgBasePermission(org string, info *github.Organization, err error) auditRow {
	const (
		key   = "org-base-permission"
		title = "Organization base permission and repo creation are restricted"
		rem   = "Set base permissions to read or none and restrict public repository creation by members."
	)
	if err != nil {
		return githubOrgAuditRow(org, key, title, "medium", StatusError, err.Error(), rem)
	}
	if info == nil {
		return githubOrgAuditRow(org, key, title, "medium", StatusSkipped, "organization details unavailable", rem)
	}
	if info.DefaultRepoPermission == nil {
		return githubOrgAuditRow(org, key, title, "medium", StatusSkipped, "org settings not visible (needs org admin)", rem)
	}
	var issues []string
	if perm := info.GetDefaultRepoPermission(); perm == "write" || perm == "admin" {
		issues = append(issues, "base permission: "+perm)
	}
	if info.GetMembersCanCreatePublicRepos() {
		issues = append(issues, "members can create public repos")
	}
	if len(issues) > 0 {
		return githubOrgAuditRow(org, key, title, "medium", StatusGap, strings.Join(issues, "; "), rem)
	}
	return githubOrgAuditRow(org, key, title, "medium", StatusCompliant, "base permission: "+info.GetDefaultRepoPermission(), rem)
}

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

func auditGitHubRulesetBypass(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	const (
		key   = "ruleset-bypass"
		title = "Branch rulesets have no bypass actors"
		rem   = "Remove or tighten ruleset bypass actors that let roles skip branch protection."
	)
	sets, _, err := c.Repositories.GetAllRulesets(ctx, owner, name, &github.RepositoryListRulesetsOptions{IncludesParents: github.Ptr(true)})
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
		full, _, err := c.Repositories.GetRuleset(ctx, owner, name, rs.GetID(), true)
		if err != nil || full == nil {
			unresolved++ // can't check bypass state, so don't call it compliant
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
		return githubAuditRow(repo, key, title, "medium", StatusSkipped, fmt.Sprintf("could not verify %d ruleset(s) for bypass actors (insufficient access)", unresolved), rem)
	}
	return githubAuditRow(repo, key, title, "medium", StatusCompliant, "no bypass actors on active branch rulesets", rem)
}

func auditGitHubOrg2FADisabledMembers(ctx context.Context, c *github.Client, org string) auditRow {
	const (
		key   = "org-2fa-disabled-members"
		title = "No organization members with 2FA disabled"
		rem   = "Require 2FA org-wide and remove or remediate members with 2FA disabled."
	)
	opts := &github.ListMembersOptions{Filter: "2fa_disabled", ListOptions: github.ListOptions{PerPage: 100}}
	total := 0
	for {
		members, resp, err := c.Organizations.ListMembers(ctx, org, opts)
		if err != nil {
			if endpointUnavailable(err) {
				return githubOrgAuditRow(org, key, title, "high", StatusSkipped, "member 2FA list not visible (needs org admin)", rem)
			}
			return githubOrgAuditRow(org, key, title, "high", StatusError, err.Error(), rem)
		}
		total += len(members)
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	if total > 0 {
		return githubOrgAuditRow(org, key, title, "high", StatusGap, fmt.Sprintf("%d members with 2FA disabled", total), rem)
	}
	return githubOrgAuditRow(org, key, title, "high", StatusCompliant, "no members with 2FA disabled", rem)
}

func auditGitHubOrgActionsPolicy(ctx context.Context, c *github.Client, org string) auditRow {
	const rem = "Restrict the org Actions policy: avoid allowing all actions, prefer a GitHub-owned + verified allowlist, and require SHA pinning."
	p, _, err := c.Actions.GetActionsPermissions(ctx, org)
	if err != nil {
		return githubOrgAuditRow(org, "org-actions-policy", "Organization Actions policy is restricted", "high", StatusError, err.Error(), rem)
	}
	if p == nil {
		return githubOrgAuditRow(org, "org-actions-policy", "Organization Actions policy is restricted", "high", StatusSkipped, "org Actions policy not visible", rem)
	}
	var issues []string
	switch p.GetAllowedActions() {
	case "all":
		issues = append(issues, "all actions allowed (no allowlist)")
	case "selected":
		if allowed, _, aerr := c.Actions.GetActionsAllowed(ctx, org); aerr == nil {
			if !allowed.GetGithubOwnedAllowed() || !allowed.GetVerifiedAllowed() {
				issues = append(issues, "allowlist does not require GitHub-owned + verified")
			}
			if len(allowed.PatternsAllowed) > 0 {
				issues = append(issues, "allowlist includes custom patterns")
			}
		}
	}
	if p.GetEnabledRepositories() == "all" {
		issues = append(issues, "actions enabled on all repositories")
	}
	if p.SHAPinningRequired != nil && !p.GetSHAPinningRequired() {
		issues = append(issues, "SHA pinning not required")
	}
	if len(issues) > 0 {
		return githubOrgAuditRow(org, "org-actions-policy", "Organization Actions policy is restricted", "high", StatusGap, strings.Join(limitStrings(issues, maxDetailItems), "; "), rem)
	}
	return githubOrgAuditRow(org, "org-actions-policy", "Organization Actions policy is restricted", "high", StatusCompliant, fmt.Sprintf("repos=%s actions=%s", p.GetEnabledRepositories(), p.GetAllowedActions()), rem)
}

func auditGitHubOrgTokenPolicy(ctx context.Context, c *github.Client, org string) auditRow {
	p, _, err := c.Actions.GetDefaultWorkflowPermissionsInOrganization(ctx, org)
	if err != nil {
		return githubOrgAuditRow(org, "org-token-policy", "Organization default GITHUB_TOKEN is read-only", "high", StatusError, err.Error(), "Set organization default workflow token permissions to read and prevent PR approval.")
	}
	if p.GetDefaultWorkflowPermissions() == "read" && !p.GetCanApprovePullRequestReviews() {
		return githubOrgAuditRow(org, "org-token-policy", "Organization default GITHUB_TOKEN is read-only", "high", StatusCompliant, "default token is read-only", "Set organization default workflow token permissions to read and prevent PR approval.")
	}
	return githubOrgAuditRow(org, "org-token-policy", "Organization default GITHUB_TOKEN is read-only", "high", StatusGap, fmt.Sprintf("token=%s can_approve_pr=%v", p.GetDefaultWorkflowPermissions(), p.GetCanApprovePullRequestReviews()), "Set organization default workflow token permissions to read and prevent PR approval.")
}

func auditGitHubOrgSecrets(ctx context.Context, c *github.Client, org string) auditRow {
	secrets, total, err := listGitHubOrgSecrets(ctx, c, org)
	if err != nil {
		return githubOrgAuditRow(org, "org-secrets", "Organization secrets are scoped narrowly", "medium", StatusError, err.Error(), "Scope org secrets to selected repositories and rotate stale secrets.")
	}
	var allRepo []string
	for _, secret := range secrets {
		if secret.Visibility == "all" {
			allRepo = append(allRepo, secret.Name)
		}
	}
	if len(allRepo) > 0 {
		return githubOrgAuditRow(org, "org-secrets", "Organization secrets are scoped narrowly", "medium", StatusGap, "secrets visible to all repos: "+strings.Join(limitStrings(allRepo, maxDetailItems), ", "), "Scope org secrets to selected repositories and rotate stale secrets.")
	}
	return githubOrgAuditRow(org, "org-secrets", "Organization secrets are scoped narrowly", "medium", StatusCompliant, fmt.Sprintf("%d org secrets reviewed", total), "Scope org secrets to selected repositories and rotate stale secrets.")
}

func auditGitHubOrgWebhooks(ctx context.Context, c *github.Client, org string) auditRow {
	hooks, err := listGitHubOrgHooks(ctx, c, org)
	if err != nil {
		return githubOrgAuditRow(org, "org-webhooks", "Organization webhooks are reviewed", "medium", StatusError, err.Error(), "Remove stale org webhooks and require HTTPS.")
	}
	var weak []string
	for _, hook := range hooks {
		if !hook.GetActive() {
			continue
		}
		url := ""
		insecure := ""
		if hook.Config != nil {
			url = hook.Config.GetURL()
			insecure = hook.Config.GetInsecureSSL()
		}
		if !strings.HasPrefix(strings.ToLower(url), "https://") || insecure == "1" {
			weak = append(weak, fmt.Sprintf("%d", hook.GetID()))
		}
	}
	if len(weak) > 0 {
		return githubOrgAuditRow(org, "org-webhooks", "Organization webhooks are reviewed", "medium", StatusGap, "weak active webhooks: "+strings.Join(weak, ", "), "Remove stale org webhooks and require HTTPS.")
	}
	return githubOrgAuditRow(org, "org-webhooks", "Organization webhooks are reviewed", "medium", StatusCompliant, fmt.Sprintf("%d org webhooks reviewed", len(hooks)), "Remove stale org webhooks and require HTTPS.")
}

func githubRawGet(ctx context.Context, c *github.Client, path string, out any) error {
	req, err := c.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if _, err := c.Do(req, out); err != nil {
		return err
	}
	return nil
}

func auditGitHubOpenSecurityAdvisories(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	const (
		key   = "open-security-advisories"
		title = "No unresolved repository security advisories"
		rem   = "Triage and resolve open repository security advisories (Security tab → Advisories)."
	)
	var advisories []struct {
		GHSAID   string `json:"ghsa_id"`
		Severity string `json:"severity"`
	}
	if err := githubRawGet(ctx, c, fmt.Sprintf("repos/%s/%s/security-advisories?per_page=100&state=triage", owner, name), &advisories); err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, key, title, "high", StatusSkipped, "security advisories API unavailable", rem)
		}
		return githubAuditRow(repo, key, title, "high", StatusError, err.Error(), rem)
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
		AccessLevel string `json:"access_level"`
	}
	if err := githubRawGet(ctx, c, fmt.Sprintf("repos/%s/%s/actions/permissions/access", owner, name), &out); err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, key, title, "low", StatusSkipped, "Actions access API unavailable", rem)
		}
		return githubAuditRow(repo, key, title, "low", StatusError, err.Error(), rem)
	}
	if out.AccessLevel == "" {
		out.AccessLevel = "none"
	}
	if out.AccessLevel == "none" {
		return githubAuditRow(repo, key, title, "low", StatusCompliant, "access level: none", rem)
	}
	return githubAuditRow(repo, key, title, "low", StatusGap, "access level: "+out.AccessLevel+" (other repos can reuse this repo's actions; tighten to none unless intended)", rem)
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

func auditGitHubCodeScanningConflict(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	const (
		key   = "code-scanning-conflict"
		title = "No conflicting code-scanning setups"
		rem   = "Use either CodeQL default setup OR an advanced workflow, not both — GitHub rejects advanced SARIF uploads when default setup is on."
	)
	cfg, _, err := c.CodeScanning.GetDefaultSetupConfiguration(ctx, owner, name)
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, key, title, "medium", StatusSkipped, "code scanning API unavailable", rem)
		}
		return githubAuditRow(repo, key, title, "medium", StatusError, err.Error(), rem)
	}
	if cfg.GetState() != "configured" {
		return githubAuditRow(repo, key, title, "medium", StatusCompliant, "default setup not enabled (no conflict possible)", rem)
	}
	uses, err := workflowsUsingCodeQL(ctx, c, owner, name, repo.GetDefaultBranch())
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, key, title, "medium", StatusSkipped, "default setup on; workflows not readable", rem)
		}
		return githubAuditRow(repo, key, title, "medium", StatusError, err.Error(), rem)
	}
	if len(uses) > 0 {
		return githubAuditRow(repo, key, title, "medium", StatusGap, "default setup on AND advanced workflow(s) run codeql-action: "+strings.Join(limitStrings(uses, maxDetailItems), ", ")+" (their SARIF uploads will be rejected)", rem)
	}
	return githubAuditRow(repo, key, title, "medium", StatusCompliant, "default setup on; no conflicting advanced workflow", rem)
}

// returns filename->content for each *.yml/*.yaml under .github/workflows.
func listWorkflowFiles(ctx context.Context, c *github.Client, owner, name, branch string) (map[string]string, error) {
	var opt *github.RepositoryContentGetOptions
	if branch != "" {
		opt = &github.RepositoryContentGetOptions{Ref: branch}
	}
	_, dir, _, err := c.Repositories.GetContents(ctx, owner, name, ".github/workflows", opt)
	if err != nil {
		if githubStatus(err) == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	out := map[string]string{}
	for _, entry := range dir {
		if entry.GetType() != "file" {
			continue
		}
		lower := strings.ToLower(entry.GetName())
		if !strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".yaml") {
			continue
		}
		file, _, _, err := c.Repositories.GetContents(ctx, owner, name, entry.GetPath(), opt)
		if err != nil || file == nil {
			continue
		}
		if content, err := file.GetContent(); err == nil {
			out[entry.GetName()] = content
		}
	}
	return out, nil
}

// returns workflow filenames that reference github/codeql-action.
func workflowsUsingCodeQL(ctx context.Context, c *github.Client, owner, name, branch string) ([]string, error) {
	files, err := listWorkflowFiles(ctx, c, owner, name, branch)
	if err != nil {
		return nil, err
	}
	var found []string
	for fname, content := range files {
		if strings.Contains(content, "github/codeql-action") {
			found = append(found, fname)
		}
	}
	return found, nil
}

func auditGitHubWorkflowTokenPermissions(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	const (
		key   = "workflow-token-permissions"
		title = "Workflows set least-privilege GITHUB_TOKEN permissions"
		rem   = "Add a top-level `permissions:` block (e.g. `contents: read`) to each workflow so GITHUB_TOKEN is least-privilege, not the broad default."
	)
	files, err := listWorkflowFiles(ctx, c, owner, name, repo.GetDefaultBranch())
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, key, title, "high", StatusSkipped, "workflows not readable", rem)
		}
		return githubAuditRow(repo, key, title, "high", StatusError, err.Error(), rem)
	}
	if len(files) == 0 {
		return githubAuditRow(repo, key, title, "high", StatusCompliant, "no Actions workflows", rem)
	}
	var weak []string
	for fname, content := range files {
		if issue := workflowPermissionIssue(content); issue != "" {
			weak = append(weak, fname+" ("+issue+")")
		}
	}
	if len(weak) > 0 {
		sort.Strings(weak)
		return githubAuditRow(repo, key, title, "high", StatusGap, "workflows without least-privilege token permissions: "+strings.Join(limitStrings(weak, maxDetailItems), ", "), rem)
	}
	return githubAuditRow(repo, key, title, "high", StatusCompliant, fmt.Sprintf("all %d workflow(s) declare explicit token permissions", len(files)), rem)
}

// returns "" if the workflow keeps GITHUB_TOKEN least-privilege, else what's wrong (or "unparseable").
func workflowPermissionIssue(content string) string {
	var wf struct {
		Permissions any `yaml:"permissions"`
		Jobs        map[string]struct {
			Permissions any `yaml:"permissions"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(content), &wf); err != nil {
		return "unparseable"
	}
	if wf.Permissions != nil {
		return permTooBroad(wf.Permissions) // explicit top-level permissions
	}
	// no top-level permissions, so every job has to set its own
	if len(wf.Jobs) == 0 {
		return "no explicit permissions"
	}
	for _, j := range wf.Jobs {
		if j.Permissions == nil {
			return "no explicit permissions"
		}
		if issue := permTooBroad(j.Permissions); issue != "" {
			return issue
		}
	}
	return ""
}

// returns "" if the permissions value is least-privilege, else why it's too broad.
func permTooBroad(p any) string {
	switch v := p.(type) {
	case string:
		if v == "write-all" {
			return "write-all token"
		}
		return "" // read-all / none
	case map[string]any:
		for k, val := range v {
			if s, ok := val.(string); ok && s == "write" {
				return "write permission: " + k
			}
		}
		return ""
	default:
		return ""
	}
}

func auditGitHubRulesetEvaluateOnly(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	const (
		key   = "ruleset-evaluate-only"
		title = "Default-branch rulesets are enforced, not evaluate-only"
		rem   = "Switch evaluate-only (dry-run) rulesets to Active so they actually enforce protection."
	)
	branch := repo.GetDefaultBranch()
	if branch == "" {
		return githubAuditRow(repo, key, title, "high", StatusSkipped, "no default branch", rem)
	}
	sets, _, err := c.Repositories.GetAllRulesets(ctx, owner, name, &github.RepositoryListRulesetsOptions{IncludesParents: github.Ptr(true)})
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
		full, _, err := c.Repositories.GetRuleset(ctx, owner, name, rs.GetID(), true)
		if err != nil || full == nil || !rulesetTargetsBranch(full, branch) {
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
	// nil means the field wasn't returned, so don't false-flag
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
	if !repo.GetPrivate() {
		return githubAuditRow(repo, key, title, "low", StatusCompliant, "public repository (forking policy n/a)", rem)
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
	if !repo.GetPrivate() && repo.GetHasWiki() {
		return githubAuditRow(repo, key, title, "low", StatusGap, "public repository has an open, editable wiki", rem)
	}
	return githubAuditRow(repo, key, title, "low", StatusCompliant, "no public open wiki", rem)
}

func auditGitHubOrgOutsideCollaborators(ctx context.Context, c *github.Client, org string) auditRow {
	const (
		key   = "org-outside-collaborators"
		title = "Outside collaborators are reviewed"
		rem   = "Review outside collaborators; prefer org membership/teams and remove unneeded external access."
	)
	opts := &github.ListOutsideCollaboratorsOptions{ListOptions: github.ListOptions{PerPage: 100}}
	var names []string
	for {
		cols, resp, err := c.Organizations.ListOutsideCollaborators(ctx, org, opts)
		if err != nil {
			if endpointUnavailable(err) {
				return githubOrgAuditRow(org, key, title, "medium", StatusSkipped, "outside collaborators not visible (needs org admin)", rem)
			}
			return githubOrgAuditRow(org, key, title, "medium", StatusError, err.Error(), rem)
		}
		for _, u := range cols {
			names = append(names, u.GetLogin())
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	if len(names) > 0 {
		return githubOrgAuditRow(org, key, title, "medium", StatusGap, fmt.Sprintf("%d outside collaborator(s) to review: %s", len(names), strings.Join(limitStrings(names, maxDetailItems), ", ")), rem)
	}
	return githubOrgAuditRow(org, key, title, "medium", StatusCompliant, "no outside collaborators", rem)
}

// max items a detail string lists before "+N more".
const maxDetailItems = 5

func limitStrings(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	out := append([]string{}, in[:n]...)
	out = append(out, fmt.Sprintf("+%d more", len(in)-n))
	return out
}

func listGitHubEnvironments(ctx context.Context, c *github.Client, owner, name string) ([]*github.Environment, error) {
	var all []*github.Environment
	opts := &github.EnvironmentListOptions{ListOptions: github.ListOptions{PerPage: 100}}
	for {
		envs, resp, err := c.Repositories.ListEnvironments(ctx, owner, name, opts)
		if err != nil {
			return nil, err
		}
		if envs != nil {
			all = append(all, envs.Environments...)
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

func listGitHubRepoSecrets(ctx context.Context, c *github.Client, owner, name string) ([]*github.Secret, int, error) {
	var all []*github.Secret
	total := 0
	opts := &github.ListOptions{PerPage: 100}
	for {
		secrets, resp, err := c.Actions.ListRepoSecrets(ctx, owner, name, opts)
		if err != nil {
			return nil, 0, err
		}
		if secrets != nil {
			total = secrets.TotalCount
			all = append(all, secrets.Secrets...)
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	if total == 0 {
		total = len(all)
	}
	return all, total, nil
}

func listGitHubDeployKeys(ctx context.Context, c *github.Client, owner, name string) ([]*github.Key, error) {
	var all []*github.Key
	opts := &github.ListOptions{PerPage: 100}
	for {
		keys, resp, err := c.Repositories.ListKeys(ctx, owner, name, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, keys...)
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

func listGitHubHooks(ctx context.Context, c *github.Client, owner, name string) ([]*github.Hook, error) {
	var all []*github.Hook
	opts := &github.ListOptions{PerPage: 100}
	for {
		hooks, resp, err := c.Repositories.ListHooks(ctx, owner, name, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, hooks...)
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

func listGitHubCollaborators(ctx context.Context, c *github.Client, owner, name string, base github.ListCollaboratorsOptions) ([]*github.User, error) {
	var all []*github.User
	opts := base
	opts.ListOptions = github.ListOptions{PerPage: 100}
	for {
		users, resp, err := c.Repositories.ListCollaborators(ctx, owner, name, &opts)
		if err != nil {
			return nil, err
		}
		all = append(all, users...)
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}
	return all, nil
}

func listGitHubDependabotAlerts(ctx context.Context, c *github.Client, owner, name string) ([]*github.DependabotAlert, error) {
	var all []*github.DependabotAlert
	opts := &github.ListAlertsOptions{State: github.Ptr("open"), ListOptions: github.ListOptions{PerPage: 100}}
	for {
		alerts, resp, err := c.Dependabot.ListRepoAlerts(ctx, owner, name, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, alerts...)
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}
	return all, nil
}

func listGitHubCodeScanningAlerts(ctx context.Context, c *github.Client, owner, name string) ([]*github.Alert, error) {
	var all []*github.Alert
	opts := &github.AlertListOptions{State: "open", ListOptions: github.ListOptions{PerPage: 100}}
	for {
		alerts, resp, err := c.CodeScanning.ListAlertsForRepo(ctx, owner, name, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, alerts...)
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}
	return all, nil
}

func listGitHubSecretScanningAlerts(ctx context.Context, c *github.Client, owner, name string) ([]*github.SecretScanningAlert, error) {
	var all []*github.SecretScanningAlert
	opts := &github.SecretScanningAlertListOptions{State: "open", ListOptions: github.ListOptions{PerPage: 100}}
	for {
		alerts, resp, err := c.SecretScanning.ListAlertsForRepo(ctx, owner, name, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, alerts...)
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}
	return all, nil
}

func listGitHubOrgSecrets(ctx context.Context, c *github.Client, org string) ([]*github.Secret, int, error) {
	var all []*github.Secret
	total := 0
	opts := &github.ListOptions{PerPage: 100}
	for {
		secrets, resp, err := c.Actions.ListOrgSecrets(ctx, org, opts)
		if err != nil {
			return nil, 0, err
		}
		if secrets != nil {
			total = secrets.TotalCount
			all = append(all, secrets.Secrets...)
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	if total == 0 {
		total = len(all)
	}
	return all, total, nil
}

func listGitHubOrgHooks(ctx context.Context, c *github.Client, org string) ([]*github.Hook, error) {
	var all []*github.Hook
	opts := &github.ListOptions{PerPage: 100}
	for {
		hooks, resp, err := c.Organizations.ListHooks(ctx, org, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, hooks...)
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}
