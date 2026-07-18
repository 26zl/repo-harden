package repoharden

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-github/v88/github"
)

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

func auditGitHubBranchProtection(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository, rc *rulesetListCache) auditRow {
	branch := repo.GetDefaultBranch()
	allowZeroApprovals := strings.EqualFold(repo.GetOwner().GetType(), "User")
	if branch == "" {
		return githubAuditRow(repo, "branch-protection-full", "Default branch protection is complete", "high", StatusSkipped, "no default branch", "Protect the default branch with PR reviews, status checks, admin enforcement, signed commits, and no force pushes.")
	}
	rules, rulesErr := githubActiveRuleTypes(ctx, c, owner, name, branch, rc)
	p, _, err := c.Repositories.GetBranchProtection(ctx, owner, name, branch)
	if err != nil {
		if errors.Is(err, github.ErrBranchNotProtected) || githubStatus(err) == http.StatusNotFound {
			if rulesErr != nil {
				if endpointUnavailable(rulesErr) {
					return githubAuditRow(repo, "branch-protection-full", "Default branch protection is complete", "high", StatusSkipped, "branch not protected and rulesets unavailable", "Protect the default branch with PR reviews, status checks, admin enforcement, signed commits, and no force pushes.")
				}
				return githubAuditRow(repo, "branch-protection-full", "Default branch protection is complete", "high", StatusError, rulesErr.Error(), "Protect the default branch with PR reviews, status checks, admin enforcement, signed commits, and no force pushes.")
			}
			missing := branchProtectionMissing(nil, rules, allowZeroApprovals)
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
	missing := branchProtectionMissing(p, rules, allowZeroApprovals)
	if len(missing) > 0 && rulesErr != nil {
		if definite := branchProtectionMissing(p, allRuleTypes, allowZeroApprovals); len(definite) > 0 {
			return githubAuditRow(repo, "branch-protection-full", "Default branch protection is complete", "high", StatusGap, "missing: "+strings.Join(definite, ", "), "Protect the default branch with PR reviews, status checks, admin enforcement, signed commits, and no force pushes.")
		}
		if endpointUnavailable(rulesErr) {
			return githubAuditRow(repo, "branch-protection-full", "Default branch protection is complete", "high", StatusSkipped, "branch protection present but rulesets unavailable", "Protect the default branch with PR reviews, status checks, admin enforcement, signed commits, and no force pushes.")
		}
		return githubAuditRow(repo, "branch-protection-full", "Default branch protection is complete", "high", StatusError, rulesErr.Error(), "Protect the default branch with PR reviews, status checks, admin enforcement, signed commits, and no force pushes.")
	}
	if len(missing) > 0 {
		return githubAuditRow(repo, "branch-protection-full", "Default branch protection is complete", "high", StatusGap, "missing: "+strings.Join(missing, ", "), "Protect the default branch with PR reviews, status checks, admin enforcement, signed commits, and no force pushes.")
	}
	return githubAuditRow(repo, "branch-protection-full", "Default branch protection is complete", "high", StatusCompliant, "default branch protection has core safeguards", "Protect the default branch with PR reviews, status checks, admin enforcement, signed commits, and no force pushes.")
}

func auditGitHubSignedCommits(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository, rc *rulesetListCache) auditRow {
	branch := repo.GetDefaultBranch()
	if branch == "" {
		return githubAuditRow(repo, "signed-commits", "Signed commits required on default branch", "medium", StatusSkipped, "no default branch", "Require signed commits through branch protection or rulesets.")
	}
	p, _, err := c.Repositories.GetBranchProtection(ctx, owner, name, branch)
	if err != nil {
		if errors.Is(err, github.ErrBranchNotProtected) || githubStatus(err) == http.StatusNotFound {
			rules, ruleErr := githubActiveRuleTypes(ctx, c, owner, name, branch, rc)
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
	rules, ruleErr := githubActiveRuleTypes(ctx, c, owner, name, branch, rc)
	if ruleErr != nil {
		if endpointUnavailable(ruleErr) {
			return githubAuditRow(repo, "signed-commits", "Signed commits required on default branch", "medium", StatusSkipped, "signatures absent from branch protection and rulesets unavailable", "Require signed commits through branch protection or rulesets.")
		}
		return githubAuditRow(repo, "signed-commits", "Signed commits required on default branch", "medium", StatusError, ruleErr.Error(), "Require signed commits through branch protection or rulesets.")
	}
	if rules["required_signatures"] {
		return githubAuditRow(repo, "signed-commits", "Signed commits required on default branch", "medium", StatusCompliant, "required signatures enforced by ruleset", "Require signed commits through branch protection or rulesets.")
	}
	return githubAuditRow(repo, "signed-commits", "Signed commits required on default branch", "medium", StatusGap, "signed commits not required", "Require signed commits through branch protection or rulesets.")
}

func auditGitHubRequiredWorkflows(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository, rc *rulesetListCache) auditRow {
	if repo.GetOwner().GetType() != "Organization" {
		return githubAuditRow(repo, "required-workflows", "Required workflows are enforced", "medium", StatusSkipped, "ruleset workflows are only configurable at organization or enterprise level; require CI status checks instead", "For organization repositories, use an organization ruleset to require critical workflows.")
	}
	rules, err := githubActiveRuleTypes(ctx, c, owner, name, repo.GetDefaultBranch(), rc)
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
