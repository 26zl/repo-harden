package repoharden

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

type gitlabProject struct {
	ID                int       `json:"id"`
	PathWithNamespace string    `json:"path_with_namespace"`
	DefaultBranch     string    `json:"default_branch"`
	Visibility        string    `json:"visibility"`
	Archived          bool      `json:"archived"`
	LastActivityAt    time.Time `json:"last_activity_at"`
	ForkedFromProject *struct{} `json:"forked_from_project"`
	Permissions       *struct {
		ProjectAccess *struct {
			AccessLevel int `json:"access_level"`
		} `json:"project_access"`
		GroupAccess *struct {
			AccessLevel int `json:"access_level"`
		} `json:"group_access"`
	} `json:"permissions"`
}

const maxProviderPages = 1000

func gitlabNextPage(respHeader string, current int) (next int, done bool, err error) {
	if respHeader == "" {
		return 0, true, nil
	}
	next, err = strconv.Atoi(respHeader)
	if err != nil || next <= current {
		return 0, false, fmt.Errorf("invalid GitLab X-Next-Page %q after page %d", respHeader, current)
	}
	return next, false, nil
}

func collectGitLabAudit(ctx context.Context, o *opts) ([]auditRow, int, error) {
	client, err := newRestClient("gitlab", o)
	if err != nil {
		return nil, 0, err
	}
	projects, err := listGitLabProjects(ctx, client, o)
	if err != nil {
		return nil, 0, err
	}
	want := wantFunc(o)
	var rows []auditRow
	if want("token-scopes") {
		rows = append(rows, providerRow("gitlab", "token", "authenticated-token", "token-scopes", "Token scopes are least privilege", "medium", StatusSkipped, "GitLab token scopes are not exposed by this API", "Use a least-privilege project/group access token."))
	}
	var mu sync.Mutex
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(max(1, o.concurrency))
	for _, p := range projects {
		group.Go(func() error {
			if err := groupCtx.Err(); err != nil {
				return err
			}
			target := p.PathWithNamespace
			checks := []struct {
				key string
				run func() auditRow
			}{
				{"public-exposure", func() auditRow { return auditGenericVisibility("gitlab", target, p.Visibility == "public") }},
				{"stale-repo", func() auditRow { return auditGenericStale("gitlab", target, p.LastActivityAt, o.staleDays) }},
				{"default-branch", func() auditRow { return gitlabDefaultBranchRow(p) }},
				{"branch-protection-full", func() auditRow { return auditGitLabBranchProtection(groupCtx, client, p) }},
				{"signed-commits", func() auditRow { return auditGitLabSignedCommits(groupCtx, client, p) }},
				{"required-workflows", func() auditRow { return auditGitLabRequiredWorkflows(groupCtx, client, p) }},
				{"environment-protection", func() auditRow { return auditGitLabEnvironments(groupCtx, client, p) }},
				{"repo-secrets", func() auditRow {
					return auditGitLabVariables(groupCtx, client, p, o.showIdentifiers)
				}},
				{"deploy-keys", func() auditRow { return auditGitLabDeployKeys(groupCtx, client, p) }},
				{"webhooks", func() auditRow { return auditGitLabWebhooks(groupCtx, client, p) }},
				{"collaborators", func() auditRow { return auditGitLabCollaborators(groupCtx, client, p) }},
				{"vulnerability-alert-count", func() auditRow { return auditGitLabVulnerabilities(groupCtx, client, p) }},
				{"releases", func() auditRow { return auditGitLabReleases(groupCtx, client, p) }},
				{"packages", func() auditRow { return auditGitLabPackages(groupCtx, client, p) }},
				{"dependency-sbom", func() auditRow { return auditGitLabDependencies(groupCtx, client, p) }},
				{"archived-active-risk", func() auditRow { return gitlabArchivedRow(p) }},
			}
			var local []auditRow
			for _, check := range checks {
				if want(check.key) {
					local = append(local, check.run())
				}
			}
			mu.Lock()
			rows = append(rows, local...)
			mu.Unlock()
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return rows, len(projects), err
	}
	return rows, len(projects), nil
}

func gitlabDefaultBranchRow(p gitlabProject) auditRow {
	if p.DefaultBranch == "" {
		return providerRow("gitlab", "repo", p.PathWithNamespace, "default-branch", "Default branch is set", "medium", StatusGap, "no default branch", "Set a default branch and protect it.")
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "default-branch", "Default branch is set", "medium", StatusCompliant, "default branch: "+p.DefaultBranch, "Set a default branch and protect it.")
}

func gitlabArchivedRow(p gitlabProject) auditRow {
	if p.Archived {
		return providerRow("gitlab", "repo", p.PathWithNamespace, "archived-active-risk", "Archived repositories are reviewed", "low", StatusGap, "archived project included in audit", "Disable schedules/tokens/webhooks before archiving.")
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "archived-active-risk", "Archived repositories are reviewed", "low", StatusCompliant, "project is not archived", "Disable schedules/tokens/webhooks before archiving.")
}

func listGitLabProjects(ctx context.Context, c *restClient, o *opts) ([]gitlabProject, error) {
	var all []gitlabProject
	page := 1
	for page <= maxProviderPages {
		var projects []gitlabProject
		q := url.Values{
			"membership": []string{"true"},
			"per_page":   []string{"100"},
			"page":       []string{strconv.Itoa(page)},
		}
		if !o.includeArchived {
			q.Set("archived", "false")
		}
		if o.adminOnly {
			q.Set("min_access_level", strconv.Itoa(gitlabMaintainer))
		}
		resp, err := c.get(ctx, "/api/v4/projects", q, &projects)
		if err != nil {
			return nil, err
		}
		for _, p := range projects {
			if o.owner != "" && !strings.HasPrefix(strings.ToLower(p.PathWithNamespace), strings.ToLower(o.owner)+"/") {
				continue
			}
			if p.ForkedFromProject != nil && !o.includeForks {
				continue
			}
			if o.adminOnly && p.Permissions != nil {
				level := 0
				if p.Permissions != nil && p.Permissions.ProjectAccess != nil {
					level = p.Permissions.ProjectAccess.AccessLevel
				}
				if p.Permissions != nil && p.Permissions.GroupAccess != nil && p.Permissions.GroupAccess.AccessLevel > level {
					level = p.Permissions.GroupAccess.AccessLevel
				}
				if level < gitlabMaintainer {
					continue
				}
			}
			all = append(all, p)
		}
		next, done, err := gitlabNextPage(resp.Header.Get("X-Next-Page"), page)
		if err != nil {
			return nil, err
		}
		if done {
			return all, nil
		}
		page = next
	}
	return nil, fmt.Errorf("GitLab repository pagination exceeded %d pages", maxProviderPages)
}

func gitlabProjectPath(p gitlabProject, suffix string) string {
	return "/api/v4/projects/" + strconv.Itoa(p.ID) + suffix
}

func auditGenericVisibility(provider, target string, public bool) auditRow {
	if public {
		return providerRow(provider, "repo", target, "public-exposure", "Repository visibility reviewed", "medium", StatusGap, "public repository", "Confirm the repository is intentionally public and contains no private assets or secrets.")
	}
	return providerRow(provider, "repo", target, "public-exposure", "Repository visibility reviewed", "medium", StatusCompliant, "private/internal repository", "Confirm public repositories are intentional.")
}

func auditGenericStale(provider, target string, last time.Time, staleDays int) auditRow {
	if last.IsZero() {
		return providerRow(provider, "repo", target, "stale-repo", "Repository activity is recent", "low", StatusSkipped, "no activity timestamp", "Archive or refresh stale repositories and remove unused credentials.")
	}
	age := time.Since(last)
	if age > time.Duration(staleDays)*24*time.Hour {
		return providerRow(provider, "repo", target, "stale-repo", "Repository activity is recent", "low", StatusGap, fmt.Sprintf("last activity %d days ago", int(age.Hours()/24)), "Archive or refresh stale repositories and remove unused credentials.")
	}
	return providerRow(provider, "repo", target, "stale-repo", "Repository activity is recent", "low", StatusCompliant, fmt.Sprintf("last activity %d days ago", int(age.Hours()/24)), "Archive or refresh stale repositories and remove unused credentials.")
}

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
		if httpUnavailable(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "branch-protection-full", "Default branch is protected", "high", StatusGap, "default branch is not protected", "Protect the default branch and require merge requests.")
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
	var approvalRules []struct {
		ApprovalsRequired int `json:"approvals_required"`
	}
	approvalRules, err = gitlabPaged[struct {
		ApprovalsRequired int `json:"approvals_required"`
	}](ctx, c, gitlabProjectPath(p, "/approval_rules"), nil)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "branch-protection-full", "Default branch protection is complete", "high", StatusSkipped, "push protection exists, but merge-request approvals could not be verified", "Require at least one merge-request approval.")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "branch-protection-full", "Default branch protection is complete", "high", StatusError, err.Error(), "Require at least one merge-request approval.")
	}
	for _, rule := range approvalRules {
		if rule.ApprovalsRequired > 0 {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "branch-protection-full", "Default branch protection is complete", "high", StatusCompliant, "direct/force pushes disabled and merge-request approval required", "Protect the default branch and require merge requests.")
		}
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "branch-protection-full", "Default branch protection is complete", "high", StatusGap, "no merge-request approval rule found", "Require at least one merge-request approval.")
}

func auditGitLabSignedCommits(ctx context.Context, c *restClient, p gitlabProject) auditRow {
	var out struct {
		RejectUnsignedCommits bool `json:"reject_unsigned_commits"`
	}
	_, err := c.get(ctx, gitlabProjectPath(p, "/push_rule"), nil, &out)
	if err != nil {
		if httpUnavailable(err) {
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
	_, err := c.get(ctx, gitlabProjectPath(p, "/repository/files/"+url.PathEscape(".gitlab-ci.yml")+"/raw"), url.Values{"ref": []string{p.DefaultBranch}}, nil)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "required-workflows", "CI configuration exists", "medium", StatusGap, "no .gitlab-ci.yml on default branch", "Add .gitlab-ci.yml and required approval/status policies.")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "required-workflows", "CI configuration exists", "medium", StatusError, err.Error(), "Add .gitlab-ci.yml and required approval/status policies.")
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "required-workflows", "CI configuration exists", "medium", StatusCompliant, ".gitlab-ci.yml found", "Add .gitlab-ci.yml and required approval/status policies.")
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

// gitlabPaged grabs all pages of a GitLab list endpoint (X-Next-Page header).
// otherwise we'd only see the first 100 items and report a false "compliant".
func gitlabPaged[T any](ctx context.Context, c *restClient, path string, extra url.Values) ([]T, error) {
	var all []T
	page := 1
	for page <= maxProviderPages {
		q := url.Values{"per_page": []string{"100"}, "page": []string{strconv.Itoa(page)}}
		for k, v := range extra {
			q[k] = v
		}
		var batch []T
		resp, err := c.get(ctx, path, q, &batch)
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
		next, done, err := gitlabNextPage(resp.Header.Get("X-Next-Page"), page)
		if err != nil {
			return nil, err
		}
		if done {
			return all, nil
		}
		page = next
	}
	return nil, fmt.Errorf("GitLab pagination for %s exceeded %d pages", path, maxProviderPages)
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

func auditGitLabDeployKeys(ctx context.Context, c *restClient, p gitlabProject) auditRow {
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
		return providerRow("gitlab", "repo", p.PathWithNamespace, "deploy-keys", "Deploy keys are read-only or absent", "high", StatusGap, "writable deploy keys: "+strings.Join(limitStrings(writable, maxDetailItems), ", "), "Remove unused deploy keys and disable write access.")
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

func auditGitLabCollaborators(ctx context.Context, c *restClient, p gitlabProject) auditRow {
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
		return providerRow("gitlab", "repo", p.PathWithNamespace, "collaborators", "Direct maintainers/owners are reviewed", "medium", StatusGap, "direct maintainers/owners: "+strings.Join(limitStrings(privileged, maxDetailItems), ", "), "Prefer group-managed access and remove stale direct maintainers.")
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

type giteaRepo struct {
	FullName      string    `json:"full_name"`
	Name          string    `json:"name"`
	Private       bool      `json:"private"`
	Fork          bool      `json:"fork"`
	Archived      bool      `json:"archived"`
	DefaultBranch string    `json:"default_branch"`
	UpdatedAt     time.Time `json:"updated_at"`
	Owner         struct {
		Login    string `json:"login"`
		UserName string `json:"username"`
	} `json:"owner"`
	Permissions *struct {
		Admin bool `json:"admin"`
	} `json:"permissions"`
}

func collectGiteaAudit(ctx context.Context, o *opts) ([]auditRow, int, error) {
	client, err := newRestClient(o.provider, o)
	if err != nil {
		return nil, 0, err
	}
	repos, err := listGiteaRepos(ctx, client, o)
	if err != nil {
		return nil, 0, err
	}
	want := wantFunc(o)
	prov := o.provider
	var rows []auditRow
	if want("token-scopes") {
		rows = append(rows, providerRow(prov, "token", "authenticated-token", "token-scopes", "Token scopes are least privilege", "medium", StatusSkipped, "token scopes are not exposed by this API", "Use least-privilege tokens."))
	}
	var mu sync.Mutex
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(max(1, o.concurrency))
	for _, repo := range repos {
		group.Go(func() error {
			if err := groupCtx.Err(); err != nil {
				return err
			}
			checks := []struct {
				key string
				run func() auditRow
			}{
				{"public-exposure", func() auditRow { return auditGenericVisibility(prov, repo.FullName, !repo.Private) }},
				{"stale-repo", func() auditRow { return auditGenericStale(prov, repo.FullName, repo.UpdatedAt, o.staleDays) }},
				{"default-branch", func() auditRow {
					if repo.DefaultBranch == "" {
						return providerRow(prov, "repo", repo.FullName, "default-branch", "Default branch is set", "medium", StatusGap, "no default branch", "Set and protect the default branch.")
					}
					return providerRow(prov, "repo", repo.FullName, "default-branch", "Default branch is set", "medium", StatusCompliant, "default branch: "+repo.DefaultBranch, "Set and protect the default branch.")
				}},
				{"branch-protection-full", func() auditRow {
					return auditGiteaBranchProtection(groupCtx, client, prov, repo)
				}},
				{"required-workflows", func() auditRow { return auditGiteaWorkflows(groupCtx, client, prov, repo) }},
				{"repo-secrets", func() auditRow { return auditGiteaSecrets(groupCtx, client, prov, repo) }},
				{"deploy-keys", func() auditRow { return auditGiteaDeployKeys(groupCtx, client, prov, repo) }},
				{"webhooks", func() auditRow { return auditGiteaWebhooks(groupCtx, client, prov, repo) }},
				{"collaborators", func() auditRow { return auditGiteaCollaborators(groupCtx, client, prov, repo) }},
				{"releases", func() auditRow { return auditGiteaReleases(groupCtx, client, prov, repo) }},
				{"signed-commits", func() auditRow {
					return providerRow(prov, "repo", repo.FullName, "signed-commits", "Signed commits required", "medium", StatusSkipped, "no portable signed-commit API found", "Use branch protection/rulesets if your instance supports signed commits.")
				}},
				{"environment-protection", func() auditRow {
					return providerRow(prov, "repo", repo.FullName, "environment-protection", "Deployment environments are protected", "medium", StatusSkipped, "no portable environment protection API found", "Protect production-like environments when supported.")
				}},
				{"vulnerability-alert-count", func() auditRow {
					return providerRow(prov, "repo", repo.FullName, "vulnerability-alert-count", "Vulnerability alerts are triaged", "high", StatusSkipped, "no portable vulnerability alert API found", "Enable dependency/security scanning on the instance or CI.")
				}},
				{"packages", func() auditRow {
					return providerRow(prov, "repo", repo.FullName, "packages", "Packages are inventoried", "low", StatusSkipped, "packages are instance/user scoped in Gitea/Forgejo", "Review package visibility and stale versions.")
				}},
				{"dependency-sbom", func() auditRow {
					return providerRow(prov, "repo", repo.FullName, "dependency-sbom", "Dependency SBOM is available", "medium", StatusSkipped, "no portable SBOM API found", "Generate SBOMs in CI.")
				}},
				{"archived-active-risk", func() auditRow {
					if repo.Archived {
						return providerRow(prov, "repo", repo.FullName, "archived-active-risk", "Archived repositories are reviewed", "low", StatusGap, "archived repository included in audit", "Disable actions/hooks/keys before archiving.")
					}
					return providerRow(prov, "repo", repo.FullName, "archived-active-risk", "Archived repositories are reviewed", "low", StatusCompliant, "repository is not archived", "Disable actions/hooks/keys before archiving.")
				}},
			}
			var local []auditRow
			for _, check := range checks {
				if want(check.key) {
					local = append(local, check.run())
				}
			}
			mu.Lock()
			rows = append(rows, local...)
			mu.Unlock()
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return rows, len(repos), err
	}
	return rows, len(repos), nil
}

func listGiteaRepos(ctx context.Context, c *restClient, o *opts) ([]giteaRepo, error) {
	var all []giteaRepo
	const maxPages = 1000
	for page := 1; page <= maxPages; page++ {
		var repos []giteaRepo
		_, err := c.get(ctx, "/api/v1/user/repos", url.Values{"limit": []string{"50"}, "page": []string{strconv.Itoa(page)}}, &repos)
		if err != nil {
			return nil, err
		}
		for _, repo := range repos {
			if o.owner != "" && !strings.EqualFold(repo.Owner.Login, o.owner) && !strings.EqualFold(repo.Owner.UserName, o.owner) {
				continue
			}
			if repo.Archived && !o.includeArchived {
				continue
			}
			if repo.Fork && !o.includeForks {
				continue
			}
			if o.adminOnly && (repo.Permissions == nil || !repo.Permissions.Admin) {
				continue
			}
			all = append(all, repo)
		}
		if len(repos) < 50 {
			break
		}
		if page == maxPages {
			return nil, fmt.Errorf("gitea repository pagination exceeded %d pages", maxPages)
		}
	}
	return all, nil
}

func giteaRepoParts(repo giteaRepo) (string, string) {
	owner, name := splitRepo(repo.FullName)
	return owner, name
}

func giteaRepoPath(repo giteaRepo, suffix string) string {
	owner, name := giteaRepoParts(repo)
	return "/api/v1/repos/" + escapedPath(owner, name) + suffix
}

func auditGiteaBranchProtection(ctx context.Context, c *restClient, provider string, repo giteaRepo) auditRow {
	if repo.DefaultBranch == "" {
		return providerRow(provider, "repo", repo.FullName, "branch-protection-full", "Default branch is protected", "high", StatusSkipped, "no default branch", "Protect the default branch.")
	}
	type protection struct {
		RuleName          string `json:"rule_name"`
		BranchName        string `json:"branch_name"`
		EnablePush        bool   `json:"enable_push"`
		EnableForcePush   bool   `json:"enable_force_push"`
		RequiredApprovals int    `json:"required_approvals"`
	}
	protections, err := giteaPaged[protection](ctx, c, giteaRepoPath(repo, "/branch_protections"))
	if err != nil {
		if httpUnavailable(err) {
			return providerRow(provider, "repo", repo.FullName, "branch-protection-full", "Default branch is protected", "high", StatusSkipped, "branch protection API unavailable", "Protect the default branch.")
		}
		return providerRow(provider, "repo", repo.FullName, "branch-protection-full", "Default branch is protected", "high", StatusError, err.Error(), "Protect the default branch.")
	}
	for _, p := range protections {
		for _, ruleName := range []string{p.RuleName, p.BranchName} {
			if ruleName == "" {
				continue
			}
			if ruleName == repo.DefaultBranch || globMatch(ruleName, repo.DefaultBranch) {
				var issues []string
				if p.EnablePush {
					issues = append(issues, "direct push enabled")
				}
				if p.EnableForcePush {
					issues = append(issues, "force push enabled")
				}
				if p.RequiredApprovals < 1 {
					issues = append(issues, "no required approval")
				}
				if len(issues) > 0 {
					return providerRow(provider, "repo", repo.FullName, "branch-protection-full", "Default branch protection is complete", "high", StatusGap, strings.Join(issues, "; "), "Disable direct/force pushes and require at least one approval.")
				}
				return providerRow(provider, "repo", repo.FullName, "branch-protection-full", "Default branch protection is complete", "high", StatusCompliant, "direct/force pushes disabled and approval required", "Protect the default branch.")
			}
		}
	}
	return providerRow(provider, "repo", repo.FullName, "branch-protection-full", "Default branch is protected", "high", StatusGap, "no default branch protection found", "Protect the default branch.")
}

func auditGiteaWorkflows(ctx context.Context, c *restClient, provider string, repo giteaRepo) auditRow {
	if repo.DefaultBranch == "" {
		return providerRow(provider, "repo", repo.FullName, "required-workflows", "Actions workflow configuration exists", "medium", StatusSkipped, "no default branch", "Add required CI workflows.")
	}
	var firstErr error
	for _, p := range []string{".gitea/workflows", ".forgejo/workflows", ".github/workflows"} {
		var out any
		_, err := c.get(ctx, giteaRepoPath(repo, "/contents/"+escapedFilePath(p)), url.Values{"ref": []string{repo.DefaultBranch}}, &out)
		if err == nil {
			return providerRow(provider, "repo", repo.FullName, "required-workflows", "Actions workflow configuration exists", "medium", StatusCompliant, p+" found", "Add required CI workflows.")
		}
		if !httpUnavailable(err) && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return providerRow(provider, "repo", repo.FullName, "required-workflows", "Actions workflow configuration exists", "medium", StatusError, firstErr.Error(), "Add required CI workflows.")
	}
	return providerRow(provider, "repo", repo.FullName, "required-workflows", "Actions workflow configuration exists", "medium", StatusGap, "no workflow directory found", "Add required CI workflows.")
}

func auditGiteaSecrets(ctx context.Context, c *restClient, provider string, repo giteaRepo) auditRow {
	var secrets []map[string]any
	_, err := c.get(ctx, giteaRepoPath(repo, "/actions/secrets"), nil, &secrets)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow(provider, "repo", repo.FullName, "repo-secrets", "Action secrets are reviewed", "medium", StatusSkipped, "actions secrets API unavailable", "Review and rotate repository action secrets.")
		}
		return providerRow(provider, "repo", repo.FullName, "repo-secrets", "Action secrets are reviewed", "medium", StatusError, err.Error(), "Review and rotate repository action secrets.")
	}
	return providerRow(provider, "repo", repo.FullName, "repo-secrets", "Action secrets are reviewed", "medium", StatusCompliant, fmt.Sprintf("%d action secrets visible", len(secrets)), "Review and rotate repository action secrets.")
}

// giteaPaged grabs all pages of a Gitea/Forgejo list endpoint, stops on a short page.
func giteaPaged[T any](ctx context.Context, c *restClient, path string) ([]T, error) {
	var all []T
	const limit = 50
	const maxPages = 1000 // cap against a server that never returns a short page
	for page := 1; page <= maxPages; page++ {
		var batch []T
		_, err := c.get(ctx, path, url.Values{"limit": []string{strconv.Itoa(limit)}, "page": []string{strconv.Itoa(page)}}, &batch)
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) < limit {
			return all, nil
		}
	}
	return nil, fmt.Errorf("gitea pagination for %s exceeded %d pages", path, maxPages)
}

type giteaDeployKey struct {
	Title    string `json:"title"`
	ReadOnly bool   `json:"read_only"`
}

type giteaHook struct {
	ID     int  `json:"id"`
	Active bool `json:"active"`
	Config struct {
		URL                 string `json:"url"`
		HTTPMethod          string `json:"http_method"`
		SkipTLSVerify       bool   `json:"skip_tls_verify"`
		AuthorizationHeader string `json:"authorization_header"`
	} `json:"config"`
}

type giteaCollab struct {
	Login      string `json:"login"`
	Permission string `json:"permission"`
}

func auditGiteaDeployKeys(ctx context.Context, c *restClient, provider string, repo giteaRepo) auditRow {
	keys, err := giteaPaged[giteaDeployKey](ctx, c, giteaRepoPath(repo, "/keys"))
	if err != nil {
		if httpUnavailable(err) {
			return providerRow(provider, "repo", repo.FullName, "deploy-keys", "Deploy keys are read-only or absent", "high", StatusSkipped, "deploy keys API unavailable", "Remove unused deploy keys and disable write access.")
		}
		return providerRow(provider, "repo", repo.FullName, "deploy-keys", "Deploy keys are read-only or absent", "high", StatusError, err.Error(), "Remove unused deploy keys and disable write access.")
	}
	var writable []string
	for _, key := range keys {
		if !key.ReadOnly {
			writable = append(writable, key.Title)
		}
	}
	if len(writable) > 0 {
		return providerRow(provider, "repo", repo.FullName, "deploy-keys", "Deploy keys are read-only or absent", "high", StatusGap, "writable deploy keys: "+strings.Join(limitStrings(writable, maxDetailItems), ", "), "Remove unused deploy keys and disable write access.")
	}
	return providerRow(provider, "repo", repo.FullName, "deploy-keys", "Deploy keys are read-only or absent", "high", StatusCompliant, fmt.Sprintf("%d deploy keys, none writable", len(keys)), "Remove unused deploy keys and disable write access.")
}

func auditGiteaWebhooks(ctx context.Context, c *restClient, provider string, repo giteaRepo) auditRow {
	hooks, err := giteaPaged[giteaHook](ctx, c, giteaRepoPath(repo, "/hooks"))
	if err != nil {
		if httpUnavailable(err) {
			return providerRow(provider, "repo", repo.FullName, "webhooks", "Webhooks use TLS and active hooks are reviewed", "medium", StatusSkipped, "webhooks API unavailable", "Require HTTPS and TLS verification for webhooks.")
		}
		return providerRow(provider, "repo", repo.FullName, "webhooks", "Webhooks use TLS and active hooks are reviewed", "medium", StatusError, err.Error(), "Require HTTPS and TLS verification for webhooks.")
	}
	var weak []string
	for _, hook := range hooks {
		if hook.Active && (!strings.HasPrefix(strings.ToLower(hook.Config.URL), "https://") || hook.Config.SkipTLSVerify) {
			weak = append(weak, strconv.Itoa(hook.ID))
		}
	}
	if len(weak) > 0 {
		return providerRow(provider, "repo", repo.FullName, "webhooks", "Webhooks use TLS and active hooks are reviewed", "medium", StatusGap, "weak active webhooks: "+strings.Join(weak, ", "), "Require HTTPS and TLS verification for webhooks.")
	}
	return providerRow(provider, "repo", repo.FullName, "webhooks", "Webhooks use TLS and active hooks are reviewed", "medium", StatusCompliant, fmt.Sprintf("%d webhooks reviewed", len(hooks)), "Require HTTPS and TLS verification for webhooks.")
}

func auditGiteaCollaborators(ctx context.Context, c *restClient, provider string, repo giteaRepo) auditRow {
	collabs, err := giteaPaged[giteaCollab](ctx, c, giteaRepoPath(repo, "/collaborators"))
	if err != nil {
		if httpUnavailable(err) {
			return providerRow(provider, "repo", repo.FullName, "collaborators", "Collaborators are reviewed", "medium", StatusSkipped, "collaborators API unavailable", "Review direct collaborators and remove stale admins.")
		}
		return providerRow(provider, "repo", repo.FullName, "collaborators", "Collaborators are reviewed", "medium", StatusError, err.Error(), "Review direct collaborators and remove stale admins.")
	}
	var admins []string
	for _, c := range collabs {
		if c.Permission == "admin" || c.Permission == "owner" {
			admins = append(admins, c.Login)
		}
	}
	if len(admins) > 0 {
		return providerRow(provider, "repo", repo.FullName, "collaborators", "Collaborators are reviewed", "medium", StatusGap, "direct admins/owners: "+strings.Join(limitStrings(admins, maxDetailItems), ", "), "Review direct collaborators and remove stale admins.")
	}
	return providerRow(provider, "repo", repo.FullName, "collaborators", "Collaborators are reviewed", "medium", StatusCompliant, fmt.Sprintf("%d collaborators reviewed", len(collabs)), "Review direct collaborators and remove stale admins.")
}

func auditGiteaReleases(ctx context.Context, c *restClient, provider string, repo giteaRepo) auditRow {
	var releases []map[string]any
	_, err := c.get(ctx, giteaRepoPath(repo, "/releases"), url.Values{"limit": []string{"10"}}, &releases)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow(provider, "repo", repo.FullName, "releases", "Releases are reviewed", "low", StatusSkipped, "releases API unavailable", "Review release artifacts and publishing hygiene.")
		}
		return providerRow(provider, "repo", repo.FullName, "releases", "Releases are reviewed", "low", StatusError, err.Error(), "Review release artifacts and publishing hygiene.")
	}
	if len(releases) == 0 {
		return providerRow(provider, "repo", repo.FullName, "releases", "Releases are reviewed", "low", StatusSkipped, "no releases", "Review release artifacts and publishing hygiene.")
	}
	return providerRow(provider, "repo", repo.FullName, "releases", "Releases are reviewed", "low", StatusCompliant, fmt.Sprintf("%d recent releases reviewed", len(releases)), "Review release artifacts and publishing hygiene.")
}
