package repoharden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type restClient struct {
	baseURL string
	token   string
	header  string
	prefix  string
	client  *http.Client
}

func newRestClient(provider string, o *opts) (*restClient, error) {
	token := strings.TrimSpace(o.token)
	if token == "" {
		token = tokenFromEnv(provider)
	}
	if token == "" {
		return nil, fmt.Errorf("no %s token found for %s", provider, o.host)
	}
	header := "Authorization"
	prefix := "Bearer "
	switch provider {
	case "gitlab":
		header = "PRIVATE-TOKEN"
		prefix = ""
	case "gitea", "forgejo":
		prefix = "token "
	}
	base := providerBaseURL(provider, o.host)
	if err := requireSecureURL(base); err != nil {
		return nil, err
	}
	return &restClient{
		baseURL: base,
		token:   token,
		header:  header,
		prefix:  prefix,
		client: &http.Client{
			Timeout: 30 * time.Second,
			// don't follow a redirect to another host — it would leak the token
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > 0 && req.URL.Host != via[0].URL.Host {
					return fmt.Errorf("refusing cross-host redirect to %s", req.URL.Host)
				}
				if len(via) >= 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				return nil
			},
		},
	}, nil
}

type restError struct {
	method     string
	path       string
	statusCode int
	status     string
}

func (e *restError) Error() string {
	return fmt.Sprintf("%s %s: %s", e.method, e.path, e.status)
}

func (c *restClient) get(ctx context.Context, path string, query url.Values, out any) (*http.Response, error) {
	u := strings.TrimRight(c.baseURL, "/") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set(c.header, c.prefix+c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp, &restError{method: http.MethodGet, path: path, statusCode: resp.StatusCode, status: resp.Status}
	}
	if out == nil {
		return resp, nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return resp, err
	}
	return resp, nil
}

func providerRow(provider, scope, target, key, title, severity string, status ControlStatus, detail, remediation string) auditRow {
	return auditRow{
		Provider:    provider,
		Scope:       scope,
		Repo:        target,
		Control:     key,
		Title:       title,
		Severity:    severity,
		Status:      string(status),
		Detail:      detail,
		Remediation: remediation,
	}
}

func httpUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var restErr *restError
	if errors.As(err, &restErr) {
		switch restErr.statusCode {
		case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusGone:
			return true
		}
	}
	return false
}

// requireSecureURL rejects sending a token in cleartext over http to a non-loopback host.
func requireSecureURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme == "http" {
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1", "":
		default:
			return fmt.Errorf("refusing to send token over cleartext http to %s; use https", u.Host)
		}
	}
	return nil
}

func escapedPath(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, url.PathEscape(part))
	}
	return strings.Join(out, "/")
}

func escapedFilePath(path string) string {
	parts := strings.Split(path, "/")
	return escapedPath(parts...)
}

type gitlabProject struct {
	ID                int       `json:"id"`
	PathWithNamespace string    `json:"path_with_namespace"`
	DefaultBranch     string    `json:"default_branch"`
	Visibility        string    `json:"visibility"`
	Archived          bool      `json:"archived"`
	LastActivityAt    time.Time `json:"last_activity_at"`
	ForkedFromProject *struct{} `json:"forked_from_project"`
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
	var rows []auditRow
	rows = append(rows, providerRow("gitlab", "token", "authenticated-token", "token-scopes", "Token scopes are least privilege", "medium", StatusSkipped, "GitLab token scopes are not exposed by this API", "Use a least-privilege project/group access token."))
	for _, p := range projects {
		target := p.PathWithNamespace
		rows = append(rows, auditGenericVisibility("gitlab", target, p.Visibility == "public"))
		rows = append(rows, auditGenericStale("gitlab", target, p.LastActivityAt, o.staleDays))
		if p.DefaultBranch == "" {
			rows = append(rows, providerRow("gitlab", "repo", target, "default-branch", "Default branch is set", "medium", StatusGap, "no default branch", "Set a default branch and protect it."))
		} else {
			rows = append(rows, providerRow("gitlab", "repo", target, "default-branch", "Default branch is set", "medium", StatusCompliant, "default branch: "+p.DefaultBranch, "Set a default branch and protect it."))
		}
		rows = append(rows, auditGitLabBranchProtection(ctx, client, p))
		rows = append(rows, auditGitLabSignedCommits(ctx, client, p))
		rows = append(rows, auditGitLabRequiredWorkflows(ctx, client, p))
		rows = append(rows, auditGitLabEnvironments(ctx, client, p))
		rows = append(rows, auditGitLabVariables(ctx, client, p))
		rows = append(rows, auditGitLabDeployKeys(ctx, client, p))
		rows = append(rows, auditGitLabWebhooks(ctx, client, p))
		rows = append(rows, auditGitLabCollaborators(ctx, client, p))
		rows = append(rows, auditGitLabVulnerabilities(ctx, client, p))
		rows = append(rows, auditGitLabReleases(ctx, client, p))
		rows = append(rows, auditGitLabPackages(ctx, client, p))
		rows = append(rows, auditGitLabDependencies(ctx, client, p))
		if p.Archived {
			rows = append(rows, providerRow("gitlab", "repo", target, "archived-active-risk", "Archived repositories are reviewed", "low", StatusGap, "archived project included in audit", "Disable schedules/tokens/webhooks before archiving."))
		} else {
			rows = append(rows, providerRow("gitlab", "repo", target, "archived-active-risk", "Archived repositories are reviewed", "low", StatusCompliant, "project is not archived", "Disable schedules/tokens/webhooks before archiving."))
		}
	}
	return rows, len(projects), nil
}

func listGitLabProjects(ctx context.Context, c *restClient, o *opts) ([]gitlabProject, error) {
	var all []gitlabProject
	page := 1
	for {
		var projects []gitlabProject
		q := url.Values{
			"membership": []string{"true"},
			"per_page":   []string{"100"},
			"page":       []string{strconv.Itoa(page)},
		}
		if !o.includeArchived {
			q.Set("archived", "false")
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
			all = append(all, p)
		}
		next := resp.Header.Get("X-Next-Page")
		if next == "" {
			break
		}
		n, err := strconv.Atoi(next)
		if err != nil || n <= page {
			break
		}
		page = n
	}
	return all, nil
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
	var out map[string]any
	_, err := c.get(ctx, gitlabProjectPath(p, "/protected_branches/"+url.PathEscape(p.DefaultBranch)), nil, &out)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "branch-protection-full", "Default branch is protected", "high", StatusGap, "default branch is not protected", "Protect the default branch and require merge requests.")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "branch-protection-full", "Default branch is protected", "high", StatusError, err.Error(), "Protect the default branch and require merge requests.")
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "branch-protection-full", "Default branch is protected", "high", StatusCompliant, "default branch protection exists", "Protect the default branch and require merge requests.")
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

func auditGitLabVariables(ctx context.Context, c *restClient, p gitlabProject) auditRow {
	var vars []struct {
		Key       string `json:"key"`
		Protected bool   `json:"protected"`
		Masked    bool   `json:"masked"`
	}
	_, err := c.get(ctx, gitlabProjectPath(p, "/variables"), url.Values{"per_page": []string{"100"}}, &vars)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "repo-secrets", "CI variables are protected and masked", "medium", StatusSkipped, "CI variables API unavailable", "Protect and mask CI/CD variables where possible.")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "repo-secrets", "CI variables are protected and masked", "medium", StatusError, err.Error(), "Protect and mask CI/CD variables where possible.")
	}
	var weak []string
	for _, v := range vars {
		if !v.Protected || !v.Masked {
			weak = append(weak, v.Key)
		}
	}
	if len(weak) > 0 {
		return providerRow("gitlab", "repo", p.PathWithNamespace, "repo-secrets", "CI variables are protected and masked", "medium", StatusGap, "unprotected/unmasked variables: "+strings.Join(limitStrings(weak, maxDetailItems), ", "), "Protect and mask CI/CD variables where possible.")
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "repo-secrets", "CI variables are protected and masked", "medium", StatusCompliant, fmt.Sprintf("%d variables reviewed", len(vars)), "Protect and mask CI/CD variables where possible.")
}

func auditGitLabDeployKeys(ctx context.Context, c *restClient, p gitlabProject) auditRow {
	var keys []struct {
		Title   string `json:"title"`
		CanPush bool   `json:"can_push"`
	}
	_, err := c.get(ctx, gitlabProjectPath(p, "/deploy_keys"), url.Values{"per_page": []string{"100"}}, &keys)
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
	var hooks []struct {
		ID                    int    `json:"id"`
		URL                   string `json:"url"`
		EnableSSLVerification bool   `json:"enable_ssl_verification"`
	}
	_, err := c.get(ctx, gitlabProjectPath(p, "/hooks"), url.Values{"per_page": []string{"100"}}, &hooks)
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

func auditGitLabCollaborators(ctx context.Context, c *restClient, p gitlabProject) auditRow {
	var members []struct {
		Username    string `json:"username"`
		AccessLevel int    `json:"access_level"`
	}
	_, err := c.get(ctx, gitlabProjectPath(p, "/members"), url.Values{"per_page": []string{"100"}}, &members)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "collaborators", "Direct maintainers/owners are reviewed", "medium", StatusSkipped, "members API unavailable", "Prefer group-managed access and remove stale direct maintainers.")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "collaborators", "Direct maintainers/owners are reviewed", "medium", StatusError, err.Error(), "Prefer group-managed access and remove stale direct maintainers.")
	}
	var privileged []string
	for _, member := range members {
		if member.AccessLevel >= 40 {
			privileged = append(privileged, member.Username)
		}
	}
	if len(privileged) > 0 {
		return providerRow("gitlab", "repo", p.PathWithNamespace, "collaborators", "Direct maintainers/owners are reviewed", "medium", StatusGap, "direct maintainers/owners: "+strings.Join(limitStrings(privileged, maxDetailItems), ", "), "Prefer group-managed access and remove stale direct maintainers.")
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "collaborators", "Direct maintainers/owners are reviewed", "medium", StatusCompliant, "no direct maintainers/owners listed", "Prefer group-managed access and remove stale direct maintainers.")
}

func auditGitLabVulnerabilities(ctx context.Context, c *restClient, p gitlabProject) auditRow {
	var vulns []map[string]any
	_, err := c.get(ctx, gitlabProjectPath(p, "/vulnerability_findings"), url.Values{"state": []string{"detected"}, "per_page": []string{"100"}}, &vulns)
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
	var packages []map[string]any
	_, err := c.get(ctx, gitlabProjectPath(p, "/packages"), url.Values{"per_page": []string{"100"}}, &packages)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "packages", "Packages are inventoried", "low", StatusSkipped, "packages API unavailable", "Review package visibility and remove stale package versions.")
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "packages", "Packages are inventoried", "low", StatusError, err.Error(), "Review package visibility and remove stale package versions.")
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "packages", "Packages are inventoried", "low", StatusCompliant, fmt.Sprintf("%d packages visible", len(packages)), "Review package visibility and remove stale package versions.")
}

func auditGitLabDependencies(ctx context.Context, c *restClient, p gitlabProject) auditRow {
	var deps []map[string]any
	_, err := c.get(ctx, gitlabProjectPath(p, "/dependencies"), url.Values{"per_page": []string{"100"}}, &deps)
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
	var rows []auditRow
	rows = append(rows, providerRow(o.provider, "token", "authenticated-token", "token-scopes", "Token scopes are least privilege", "medium", StatusSkipped, "token scopes are not exposed by this API", "Use least-privilege tokens."))
	for _, repo := range repos {
		rows = append(rows, auditGenericVisibility(o.provider, repo.FullName, !repo.Private))
		rows = append(rows, auditGenericStale(o.provider, repo.FullName, repo.UpdatedAt, o.staleDays))
		if repo.DefaultBranch == "" {
			rows = append(rows, providerRow(o.provider, "repo", repo.FullName, "default-branch", "Default branch is set", "medium", StatusGap, "no default branch", "Set and protect the default branch."))
		} else {
			rows = append(rows, providerRow(o.provider, "repo", repo.FullName, "default-branch", "Default branch is set", "medium", StatusCompliant, "default branch: "+repo.DefaultBranch, "Set and protect the default branch."))
		}
		rows = append(rows, auditGiteaBranchProtection(ctx, client, o.provider, repo))
		rows = append(rows, auditGiteaWorkflows(ctx, client, o.provider, repo))
		rows = append(rows, auditGiteaSecrets(ctx, client, o.provider, repo))
		rows = append(rows, auditGiteaDeployKeys(ctx, client, o.provider, repo))
		rows = append(rows, auditGiteaWebhooks(ctx, client, o.provider, repo))
		rows = append(rows, auditGiteaCollaborators(ctx, client, o.provider, repo))
		rows = append(rows, auditGiteaReleases(ctx, client, o.provider, repo))
		rows = append(rows, providerRow(o.provider, "repo", repo.FullName, "signed-commits", "Signed commits required", "medium", StatusSkipped, "no portable signed-commit API found", "Use branch protection/rulesets if your instance supports signed commits."))
		rows = append(rows, providerRow(o.provider, "repo", repo.FullName, "environment-protection", "Deployment environments are protected", "medium", StatusSkipped, "no portable environment protection API found", "Protect production-like environments when supported."))
		rows = append(rows, providerRow(o.provider, "repo", repo.FullName, "vulnerability-alert-count", "Vulnerability alerts are triaged", "high", StatusSkipped, "no portable vulnerability alert API found", "Enable dependency/security scanning on the instance or CI."))
		rows = append(rows, providerRow(o.provider, "repo", repo.FullName, "packages", "Packages are inventoried", "low", StatusSkipped, "packages are instance/user scoped in Gitea/Forgejo", "Review package visibility and stale versions."))
		rows = append(rows, providerRow(o.provider, "repo", repo.FullName, "dependency-sbom", "Dependency SBOM is available", "medium", StatusSkipped, "no portable SBOM API found", "Generate SBOMs in CI."))
		if repo.Archived {
			rows = append(rows, providerRow(o.provider, "repo", repo.FullName, "archived-active-risk", "Archived repositories are reviewed", "low", StatusGap, "archived repository included in audit", "Disable actions/hooks/keys before archiving."))
		} else {
			rows = append(rows, providerRow(o.provider, "repo", repo.FullName, "archived-active-risk", "Archived repositories are reviewed", "low", StatusCompliant, "repository is not archived", "Disable actions/hooks/keys before archiving."))
		}
	}
	return rows, len(repos), nil
}

func listGiteaRepos(ctx context.Context, c *restClient, o *opts) ([]giteaRepo, error) {
	var all []giteaRepo
	page := 1
	for {
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
			all = append(all, repo)
		}
		if len(repos) < 50 {
			break
		}
		page++
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
	var protections []map[string]any
	_, err := c.get(ctx, giteaRepoPath(repo, "/branch_protections"), nil, &protections)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow(provider, "repo", repo.FullName, "branch-protection-full", "Default branch is protected", "high", StatusSkipped, "branch protection API unavailable", "Protect the default branch.")
		}
		return providerRow(provider, "repo", repo.FullName, "branch-protection-full", "Default branch is protected", "high", StatusError, err.Error(), "Protect the default branch.")
	}
	for _, p := range protections {
		if fmt.Sprint(p["branch_name"]) == repo.DefaultBranch || fmt.Sprint(p["rule_name"]) == repo.DefaultBranch {
			return providerRow(provider, "repo", repo.FullName, "branch-protection-full", "Default branch is protected", "high", StatusCompliant, "default branch protection exists", "Protect the default branch.")
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

func auditGiteaDeployKeys(ctx context.Context, c *restClient, provider string, repo giteaRepo) auditRow {
	var keys []struct {
		Title    string `json:"title"`
		ReadOnly bool   `json:"read_only"`
	}
	_, err := c.get(ctx, giteaRepoPath(repo, "/keys"), nil, &keys)
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
	var hooks []struct {
		ID     int  `json:"id"`
		Active bool `json:"active"`
		Config struct {
			URL                 string `json:"url"`
			HTTPMethod          string `json:"http_method"`
			SkipTLSVerify       bool   `json:"skip_tls_verify"`
			AuthorizationHeader string `json:"authorization_header"`
		} `json:"config"`
	}
	_, err := c.get(ctx, giteaRepoPath(repo, "/hooks"), nil, &hooks)
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
	var collabs []struct {
		Login      string `json:"login"`
		Permission string `json:"permission"`
	}
	_, err := c.get(ctx, giteaRepoPath(repo, "/collaborators"), nil, &collabs)
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
