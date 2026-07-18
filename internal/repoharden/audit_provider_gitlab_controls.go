package repoharden

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func auditGitLabBranchProtection(ctx context.Context, c *restClient, p gitlabProject) auditRow {
	if p.DefaultBranch == "" {
		return providerRow("gitlab", "repo", p.PathWithNamespace, "branch-protection-full", "Default branch is protected", "high", StatusSkipped, "no default branch", "Protect the default branch and require merge requests.")
	}
	var out struct {
		AllowForcePush   bool `json:"allow_force_push"`
		PushAccessLevels []struct {
			AccessLevel int  `json:"access_level"`
			UserID      *int `json:"user_id"`
			GroupID     *int `json:"group_id"`
			DeployKeyID *int `json:"deploy_key_id"`
		} `json:"push_access_levels"`
	}
	_, err := c.get(ctx, gitlabProjectPath(p, "/protected_branches/"+url.PathEscape(p.DefaultBranch)), nil, &out)
	if err != nil {
		if httpNotFound(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "branch-protection-full", "Default branch is protected", "high", StatusGap, "default branch is not protected", "Protect the default branch and require merge requests.")
		}
		if httpPermissionDenied(err) || httpUnsupported(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "branch-protection-full", "Default branch is protected", "high", StatusSkipped, "branch protection could not be verified with this token/API", "Protect the default branch and require merge requests.")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "branch-protection-full", "Default branch is protected", "high", StatusError, err.Error(), "Protect the default branch and require merge requests.")
	}
	var issues []string
	if out.AllowForcePush {
		issues = append(issues, "force push allowed")
	}
	for _, access := range out.PushAccessLevels {
		if access.AccessLevel > 0 || access.UserID != nil || access.GroupID != nil || access.DeployKeyID != nil {
			issues = append(issues, "direct push access remains")
			break
		}
	}
	if len(issues) > 0 {
		return providerRow("gitlab", "repo", p.PathWithNamespace, "branch-protection-full", "Default branch protection is complete", "high", StatusGap, strings.Join(issues, "; "), "Disallow direct/force pushes and require at least one merge-request approval.")
	}
	approvalRules, err := gitlabPaged[gitlabApprovalRule](ctx, c, gitlabProjectPath(p, "/approval_rules"), nil)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "branch-protection-full", "Default branch protection is complete", "high", StatusSkipped, "push protection exists, but merge-request approvals could not be verified", "Require at least one merge-request approval.")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "branch-protection-full", "Default branch protection is complete", "high", StatusError, err.Error(), "Require at least one merge-request approval.")
	}
	for _, rule := range approvalRules {
		if rule.ApprovalsRequired > 0 && gitlabApprovalRuleAppliesToBranch(rule, p.DefaultBranch) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "branch-protection-full", "Default branch protection is complete", "high", StatusCompliant, "direct/force pushes disabled and merge-request approval required", "Protect the default branch and require merge requests.")
		}
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "branch-protection-full", "Default branch protection is complete", "high", StatusGap, "no required merge-request approval rule applies to the default branch", "Require at least one merge-request approval.")
}

func auditGitLabSignedCommits(ctx context.Context, c *restClient, p gitlabProject) auditRow {
	var out struct {
		RejectUnsignedCommits bool `json:"reject_unsigned_commits"`
	}
	_, err := c.get(ctx, gitlabProjectPath(p, "/push_rule"), nil, &out)
	if err != nil {
		if httpNotFound(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "signed-commits", "Unsigned commits are rejected", "medium", StatusSkipped, "no push rule configured, or push rules unavailable (GitLab Premium feature)", "Enable push rules that reject unsigned commits.")
		}
		if httpPermissionDenied(err) || httpUnsupported(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "signed-commits", "Unsigned commits are rejected", "medium", StatusSkipped, "push rules unavailable", "Enable push rules that reject unsigned commits.")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "signed-commits", "Unsigned commits are rejected", "medium", StatusError, err.Error(), "Enable push rules that reject unsigned commits.")
	}
	if out.RejectUnsignedCommits {
		return providerRow("gitlab", "repo", p.PathWithNamespace, "signed-commits", "Unsigned commits are rejected", "medium", StatusCompliant, "reject_unsigned_commits enabled", "Enable push rules that reject unsigned commits.")
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "signed-commits", "Unsigned commits are rejected", "medium", StatusGap, "unsigned commits are allowed", "Enable push rules that reject unsigned commits.")
}

func auditGitLabRequiredWorkflows(ctx context.Context, c *restClient, p gitlabProject) auditRow {
	if p.DefaultBranch == "" {
		return providerRow("gitlab", "repo", p.PathWithNamespace, "required-workflows", "CI configuration exists", "medium", StatusSkipped, "no default branch", "Add .gitlab-ci.yml and required approval/status policies.")
	}
	content, err := c.getText(ctx, gitlabProjectPath(p, "/repository/files/"+url.PathEscape(".gitlab-ci.yml")+"/raw"), url.Values{"ref": []string{p.DefaultBranch}})
	if err != nil {
		if httpNotFound(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "required-workflows", "CI configuration exists", "medium", StatusGap, "no .gitlab-ci.yml on default branch", "Add .gitlab-ci.yml and required approval/status policies.")
		}
		if httpPermissionDenied(err) || httpUnsupported(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "required-workflows", "CI configuration exists", "medium", StatusSkipped, "CI configuration could not be read with this token/API", "Add .gitlab-ci.yml and required approval/status policies.")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "required-workflows", "CI configuration exists", "medium", StatusError, err.Error(), "Add .gitlab-ci.yml and required approval/status policies.")
	}
	if _, err := parseGitLabCI(content); err != nil {
		return providerRow("gitlab", "repo", p.PathWithNamespace, "required-workflows", "CI configuration exists", "medium", StatusGap, "invalid .gitlab-ci.yml: "+err.Error(), "Add a non-empty, valid .gitlab-ci.yml and required approval/status policies.")
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "required-workflows", "CI configuration exists", "medium", StatusCompliant, ".gitlab-ci.yml is readable and valid YAML", "Add .gitlab-ci.yml and required approval/status policies.")
}

func auditGitLabEnvironments(ctx context.Context, c *restClient, p gitlabProject) auditRow {
	var envs []map[string]any
	_, err := c.get(ctx, gitlabProjectPath(p, "/protected_environments"), url.Values{"per_page": []string{"100"}}, &envs)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "environment-protection", "Protected environments are configured", "medium", StatusSkipped, "protected environments API unavailable", "Protect production-like environments.")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "environment-protection", "Protected environments are configured", "medium", StatusError, err.Error(), "Protect production-like environments.")
	}
	if len(envs) == 0 {
		return providerRow("gitlab", "repo", p.PathWithNamespace, "environment-protection", "Protected environments are configured", "medium", StatusGap, "no protected environments", "Protect production-like environments.")
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "environment-protection", "Protected environments are configured", "medium", StatusCompliant, fmt.Sprintf("%d protected environments", len(envs)), "Protect production-like environments.")
}

func auditGitLabVariables(ctx context.Context, c *restClient, p gitlabProject, showIdentifiers bool) auditRow {
	const rem = "Protect and mask CI/CD variables where possible."
	var weak []string
	total, page := 0, 1
	for page <= maxProviderPages {
		var vars []struct {
			Key       string `json:"key"`
			Protected bool   `json:"protected"`
			Masked    bool   `json:"masked"`
		}
		resp, err := c.get(ctx, gitlabProjectPath(p, "/variables"),
			url.Values{"per_page": []string{"100"}, "page": []string{strconv.Itoa(page)}}, &vars)
		if err != nil {
			if httpUnavailable(err) {
				return providerRow("gitlab", "repo", p.PathWithNamespace, "repo-secrets", "CI variables are protected and masked", "medium", StatusSkipped, "CI variables API unavailable", rem)
			}
			return providerRow("gitlab", "repo", p.PathWithNamespace, "repo-secrets", "CI variables are protected and masked", "medium", StatusError, err.Error(), rem)
		}
		total += len(vars)
		for _, v := range vars {
			if !v.Protected || !v.Masked {
				weak = append(weak, v.Key)
			}
		}
		next, done, nextErr := gitlabNextPage(resp.Header.Get("X-Next-Page"), page)
		if nextErr != nil {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "repo-secrets", "CI variables are protected and masked", "medium", StatusError, nextErr.Error(), rem)
		}
		if done {
			break
		}
		page = next
	}
	if page > maxProviderPages {
		return providerRow("gitlab", "repo", p.PathWithNamespace, "repo-secrets", "CI variables are protected and masked", "medium", StatusError, fmt.Sprintf("GitLab variable pagination exceeded %d pages", maxProviderPages), rem)
	}
	if len(weak) > 0 {
		detail := fmt.Sprintf("%d CI variables are unprotected or unmasked", len(weak))
		if showIdentifiers {
			detail += ": " + strings.Join(limitStrings(weak, maxDetailItems), ", ")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "repo-secrets", "CI variables are protected and masked", "medium", StatusGap, detail, rem)
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "repo-secrets", "CI variables are protected and masked", "medium", StatusCompliant, fmt.Sprintf("%d variables reviewed", total), rem)
}

type gitlabDeployKey struct {
	Title   string `json:"title"`
	CanPush bool   `json:"can_push"`
}

type gitlabHook struct {
	ID                    int    `json:"id"`
	URL                   string `json:"url"`
	EnableSSLVerification bool   `json:"enable_ssl_verification"`
}

type gitlabMember struct {
	Username    string `json:"username"`
	AccessLevel int    `json:"access_level"`
}

func auditGitLabDeployKeys(ctx context.Context, c *restClient, p gitlabProject, showIdentifiers bool) auditRow {
	keys, err := gitlabPaged[gitlabDeployKey](ctx, c, gitlabProjectPath(p, "/deploy_keys"), nil)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "deploy-keys", "Deploy keys are read-only or absent", "high", StatusSkipped, "deploy keys API unavailable", "Remove unused deploy keys and disable write access.")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "deploy-keys", "Deploy keys are read-only or absent", "high", StatusError, err.Error(), "Remove unused deploy keys and disable write access.")
	}
	var writable []string
	for _, key := range keys {
		if key.CanPush {
			writable = append(writable, key.Title)
		}
	}
	if len(writable) > 0 {
		detail := fmt.Sprintf("%d writable deploy keys", len(writable))
		if showIdentifiers {
			detail += ": " + strings.Join(limitStrings(writable, maxDetailItems), ", ")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "deploy-keys", "Deploy keys are read-only or absent", "high", StatusGap, detail, "Remove unused deploy keys and disable write access.")
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "deploy-keys", "Deploy keys are read-only or absent", "high", StatusCompliant, fmt.Sprintf("%d deploy keys, none writable", len(keys)), "Remove unused deploy keys and disable write access.")
}

func auditGitLabWebhooks(ctx context.Context, c *restClient, p gitlabProject) auditRow {
	hooks, err := gitlabPaged[gitlabHook](ctx, c, gitlabProjectPath(p, "/hooks"), nil)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "webhooks", "Webhooks use TLS and SSL verification", "medium", StatusSkipped, "webhooks API unavailable", "Require HTTPS and SSL verification for webhooks.")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "webhooks", "Webhooks use TLS and SSL verification", "medium", StatusError, err.Error(), "Require HTTPS and SSL verification for webhooks.")
	}
	var weak []string
	for _, hook := range hooks {
		if !strings.HasPrefix(strings.ToLower(hook.URL), "https://") || !hook.EnableSSLVerification {
			weak = append(weak, strconv.Itoa(hook.ID))
		}
	}
	if len(weak) > 0 {
		return providerRow("gitlab", "repo", p.PathWithNamespace, "webhooks", "Webhooks use TLS and SSL verification", "medium", StatusGap, "weak webhooks: "+strings.Join(weak, ", "), "Require HTTPS and SSL verification for webhooks.")
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "webhooks", "Webhooks use TLS and SSL verification", "medium", StatusCompliant, fmt.Sprintf("%d webhooks reviewed", len(hooks)), "Require HTTPS and SSL verification for webhooks.")
}

// gitlabMaintainer is GitLab's access_level for Maintainer; >= this is privileged.
const gitlabMaintainer = 40

func auditGitLabCollaborators(ctx context.Context, c *restClient, p gitlabProject, showIdentifiers bool) auditRow {
	members, err := gitlabPaged[gitlabMember](ctx, c, gitlabProjectPath(p, "/members"), nil)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "collaborators", "Direct maintainers/owners are reviewed", "medium", StatusSkipped, "members API unavailable", "Prefer group-managed access and remove stale direct maintainers.")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "collaborators", "Direct maintainers/owners are reviewed", "medium", StatusError, err.Error(), "Prefer group-managed access and remove stale direct maintainers.")
	}
	var privileged []string
	for _, member := range members {
		if member.AccessLevel >= gitlabMaintainer {
			privileged = append(privileged, member.Username)
		}
	}
	if len(privileged) > 0 {
		detail := fmt.Sprintf("%d direct maintainers/owners", len(privileged))
		if showIdentifiers {
			detail += ": " + strings.Join(limitStrings(privileged, maxDetailItems), ", ")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "collaborators", "Direct maintainers/owners are reviewed", "medium", StatusGap, detail, "Prefer group-managed access and remove stale direct maintainers.")
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "collaborators", "Direct maintainers/owners are reviewed", "medium", StatusCompliant, "no direct maintainers/owners listed", "Prefer group-managed access and remove stale direct maintainers.")
}

func auditGitLabVulnerabilities(ctx context.Context, c *restClient, p gitlabProject) auditRow {
	vulns, err := gitlabPaged[map[string]any](ctx, c, gitlabProjectPath(p, "/vulnerability_findings"), url.Values{"state": []string{"detected"}})
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "vulnerability-alert-count", "Open vulnerability findings are triaged", "high", StatusSkipped, "vulnerability findings API unavailable", "Enable GitLab security scanning and triage findings.")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "vulnerability-alert-count", "Open vulnerability findings are triaged", "high", StatusError, err.Error(), "Enable GitLab security scanning and triage findings.")
	}
	if len(vulns) > 0 {
		return providerRow("gitlab", "repo", p.PathWithNamespace, "vulnerability-alert-count", "Open vulnerability findings are triaged", "high", StatusGap, fmt.Sprintf("%d detected vulnerability findings", len(vulns)), "Enable GitLab security scanning and triage findings.")
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "vulnerability-alert-count", "Open vulnerability findings are triaged", "high", StatusCompliant, "0 detected vulnerability findings", "Enable GitLab security scanning and triage findings.")
}

func auditGitLabReleases(ctx context.Context, c *restClient, p gitlabProject) auditRow {
	var releases []map[string]any
	_, err := c.get(ctx, gitlabProjectPath(p, "/releases"), url.Values{"per_page": []string{"10"}}, &releases)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "releases", "Releases are reviewed", "low", StatusSkipped, "releases API unavailable", "Review release artifacts and publishing hygiene.")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "releases", "Releases are reviewed", "low", StatusError, err.Error(), "Review release artifacts and publishing hygiene.")
	}
	if len(releases) == 0 {
		return providerRow("gitlab", "repo", p.PathWithNamespace, "releases", "Releases are reviewed", "low", StatusSkipped, "no releases", "Review release artifacts and publishing hygiene.")
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "releases", "Releases are reviewed", "low", StatusCompliant, fmt.Sprintf("%d recent releases reviewed", len(releases)), "Review release artifacts and publishing hygiene.")
}

func auditGitLabPackages(ctx context.Context, c *restClient, p gitlabProject) auditRow {
	packages, err := gitlabPaged[map[string]any](ctx, c, gitlabProjectPath(p, "/packages"), nil)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "packages", "Packages are inventoried", "low", StatusSkipped, "packages API unavailable", "Review package visibility and remove stale package versions.")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "packages", "Packages are inventoried", "low", StatusError, err.Error(), "Review package visibility and remove stale package versions.")
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "packages", "Packages are inventoried", "low", StatusCompliant, fmt.Sprintf("%d packages visible", len(packages)), "Review package visibility and remove stale package versions.")
}

func auditGitLabDependencies(ctx context.Context, c *restClient, p gitlabProject) auditRow {
	deps, err := gitlabPaged[map[string]any](ctx, c, gitlabProjectPath(p, "/dependencies"), nil)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "dependency-sbom", "Dependency inventory/SBOM is available", "medium", StatusSkipped, "dependency inventory API unavailable", "Enable dependency scanning or SBOM export.")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "dependency-sbom", "Dependency inventory/SBOM is available", "medium", StatusError, err.Error(), "Enable dependency scanning or SBOM export.")
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "dependency-sbom", "Dependency inventory/SBOM is available", "medium", StatusCompliant, fmt.Sprintf("%d dependencies visible", len(deps)), "Enable dependency scanning or SBOM export.")
}
