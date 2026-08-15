package repoharden

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
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

func collectGitLabAudit(ctx context.Context, o *opts) ([]auditRow, []string, error) {
	client, err := newRestClient("gitlab", o)
	if err != nil {
		return nil, nil, err
	}
	projects, err := listGitLabProjects(ctx, client, o)
	if err != nil {
		return nil, nil, err
	}
	repositories := make([]string, 0, len(projects))
	for _, project := range projects {
		repositories = append(repositories, project.PathWithNamespace)
	}
	sort.Strings(repositories)
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
				{"pipeline-supply-chain", func() auditRow { return auditGitLabPipelineSupplyChain(groupCtx, client, p) }},
				{"environment-protection", func() auditRow { return auditGitLabEnvironments(groupCtx, client, p) }},
				{"repo-secrets", func() auditRow {
					return auditGitLabVariables(groupCtx, client, p, o.showIdentifiers)
				}},
				{"deploy-keys", func() auditRow { return auditGitLabDeployKeys(groupCtx, client, p, o.showIdentifiers) }},
				{"webhooks", func() auditRow { return auditGitLabWebhooks(groupCtx, client, p) }},
				{"collaborators", func() auditRow { return auditGitLabCollaborators(groupCtx, client, p, o.showIdentifiers) }},
				{"vulnerability-alert-count", func() auditRow { return auditGitLabVulnerabilities(groupCtx, client, p) }},
				{"releases", func() auditRow { return auditGitLabReleases(groupCtx, client, p) }},
				{"packages", func() auditRow { return auditGitLabPackages(groupCtx, client, p) }},
				{"dependency-sbom", func() auditRow { return auditGitLabDependencies(groupCtx, client, p) }},
				{"repository-license", func() auditRow { return auditGitLabRepositoryLicense(groupCtx, client, p) }},
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
		return rows, repositories, err
	}
	return rows, repositories, nil
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
	return nil, fmt.Errorf("gitlab repository pagination exceeded %d pages", maxProviderPages)
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

func collectGiteaAudit(ctx context.Context, o *opts) ([]auditRow, []string, error) {
	client, err := newRestClient(o.provider, o)
	if err != nil {
		return nil, nil, err
	}
	repos, err := listGiteaRepos(ctx, client, o)
	if err != nil {
		return nil, nil, err
	}
	repositories := make([]string, 0, len(repos))
	for _, repo := range repos {
		repositories = append(repositories, repo.FullName)
	}
	sort.Strings(repositories)
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
			var wfOnce sync.Once
			var wfFiles map[string]string
			var wfErr error
			getWorkflows := func() (map[string]string, error) {
				wfOnce.Do(func() { wfFiles, wfErr = listGiteaWorkflowFiles(groupCtx, client, repo) })
				return wfFiles, wfErr
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
				{"required-workflows", func() auditRow { return auditGiteaWorkflows(prov, repo, getWorkflows) }},
				{"workflow-unpinned-actions", func() auditRow {
					return giteaWorkflowSupplyChainRow(prov, repo.FullName, "workflow-unpinned-actions",
						"Third-party actions pinned to commit SHAs", "medium",
						"third-party actions not SHA-pinned: ", "no unpinned third-party actions",
						"Pin third-party actions to full commit SHAs so a moved tag cannot inject code into your builds.",
						getWorkflows, workflowUnpinnedUses)
				}},
				{"workflow-pwn-request", func() auditRow {
					return giteaWorkflowSupplyChainRow(prov, repo.FullName, "workflow-pwn-request",
						"No pull_request_target checkout of PR head", "high",
						"pull_request_target workflows check out the PR head: ", "no privileged PR-head checkouts",
						"Do not check out attacker-controlled PR code in privileged pull_request_target workflows.",
						getWorkflows, workflowPwnRequestJobs)
				}},
				{"workflow-injection", func() auditRow {
					return giteaWorkflowSupplyChainRow(prov, repo.FullName, "workflow-injection",
						"No attacker-controlled expressions in run scripts", "high",
						"attacker-controlled expressions in scripts: ", "no attacker-controlled expressions in run scripts",
						"Pass untrusted event fields into scripts via env: variables instead of interpolating ${{ … }} into run:.",
						getWorkflows, workflowInjectionContexts)
				}},
				{"repo-secrets", func() auditRow { return auditGiteaSecrets(groupCtx, client, prov, repo) }},
				{"deploy-keys", func() auditRow { return auditGiteaDeployKeys(groupCtx, client, prov, repo, o.showIdentifiers) }},
				{"webhooks", func() auditRow { return auditGiteaWebhooks(groupCtx, client, prov, repo) }},
				{"collaborators", func() auditRow { return auditGiteaCollaborators(groupCtx, client, prov, repo, o.showIdentifiers) }},
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
				{"repository-license", func() auditRow {
					return auditGiteaRepositoryLicense(groupCtx, client, prov, repo)
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
		return rows, repositories, err
	}
	return rows, repositories, nil
}

func listGiteaRepos(ctx context.Context, c *restClient, o *opts) ([]giteaRepo, error) {
	var all []giteaRepo
	const limit = 50
	page := 1
	totalSeen := 0
	for requests := 1; requests <= maxProviderPages; requests++ {
		var repos []giteaRepo
		resp, err := c.get(ctx, "/api/v1/user/repos", url.Values{"limit": []string{strconv.Itoa(limit)}, "page": []string{strconv.Itoa(page)}}, &repos)
		if err != nil {
			return nil, err
		}
		totalSeen += len(repos)
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
		next, done, err := giteaNextPage(resp, page, len(repos), totalSeen)
		if err != nil {
			return nil, err
		}
		if done {
			return all, nil
		}
		page = next
	}
	return nil, fmt.Errorf("gitea repository pagination exceeded %d pages", maxProviderPages)
}

func giteaRepoParts(repo giteaRepo) (string, string) {
	owner, name := splitRepo(repo.FullName)
	return owner, name
}

type bitbucketRepo struct {
	FullName   string    `json:"full_name"`
	IsPrivate  bool      `json:"is_private"`
	UpdatedOn  time.Time `json:"updated_on"`
	Parent     *struct{} `json:"parent"`
	Mainbranch *struct {
		Name string `json:"name"`
	} `json:"mainbranch"`
}

func bitbucketDefaultBranch(repo bitbucketRepo) string {
	if repo.Mainbranch == nil {
		return ""
	}
	return strings.TrimSpace(repo.Mainbranch.Name)
}

func bitbucketRepoPath(repo bitbucketRepo, suffix string) string {
	owner, name := splitRepo(repo.FullName)
	return "/2.0/repositories/" + escapedPath(owner, name) + suffix
}

// bitbucketSrcRef returns a ref usable in src paths: the src endpoint splits
// {commit} at the first slash, so slashed branch names must be resolved to a
// commit hash via the refs endpoint first.
func bitbucketSrcRef(ctx context.Context, c *restClient, repo bitbucketRepo) (string, error) {
	branch := bitbucketDefaultBranch(repo)
	if !strings.Contains(branch, "/") {
		return branch, nil
	}
	var out struct {
		Target struct {
			Hash string `json:"hash"`
		} `json:"target"`
	}
	if _, err := c.get(ctx, bitbucketRepoPath(repo, "/refs/branches/"+escapedFilePath(branch)), nil, &out); err != nil {
		return "", err
	}
	hash := strings.TrimSpace(out.Target.Hash)
	if hash == "" {
		return "", fmt.Errorf("branch %s did not resolve to a commit hash", branch)
	}
	return hash, nil
}

func collectBitbucketAudit(ctx context.Context, o *opts) ([]auditRow, []string, error) {
	client, err := newRestClient("bitbucket", o)
	if err != nil {
		return nil, nil, err
	}
	repos, header, err := listBitbucketRepos(ctx, client, o)
	if err != nil {
		return nil, nil, err
	}
	repositories := make([]string, 0, len(repos))
	for _, repo := range repos {
		repositories = append(repositories, repo.FullName)
	}
	sort.Strings(repositories)
	want := wantFunc(o)
	var rows []auditRow
	if want("token-scopes") {
		scopes := ""
		if header != nil {
			scopes = header.Get("X-Oauth-Scopes")
		}
		rows = append(rows, bitbucketTokenScopesRow(scopes))
	}
	var mu sync.Mutex
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(max(1, o.concurrency))
	for _, repo := range repos {
		group.Go(func() error {
			if err := groupCtx.Err(); err != nil {
				return err
			}
			var refOnce sync.Once
			var ref string
			var refErr error
			srcRef := func() (string, error) {
				refOnce.Do(func() { ref, refErr = bitbucketSrcRef(groupCtx, client, repo) })
				return ref, refErr
			}
			getYML := bitbucketPipelinesYMLFetcher(groupCtx, client, repo, srcRef)
			checks := []struct {
				key string
				run func() auditRow
			}{
				{"public-exposure", func() auditRow { return auditGenericVisibility("bitbucket", repo.FullName, !repo.IsPrivate) }},
				{"stale-repo", func() auditRow { return auditGenericStale("bitbucket", repo.FullName, repo.UpdatedOn, o.staleDays) }},
				{"default-branch", func() auditRow {
					if bitbucketDefaultBranch(repo) == "" {
						return providerRow("bitbucket", "repo", repo.FullName, "default-branch", "Default branch is set", "medium", StatusGap, "no default branch", "Set and protect the default branch.")
					}
					return providerRow("bitbucket", "repo", repo.FullName, "default-branch", "Default branch is set", "medium", StatusCompliant, "default branch: "+bitbucketDefaultBranch(repo), "Set and protect the default branch.")
				}},
				{"branch-protection-full", func() auditRow { return auditBitbucketBranchProtection(groupCtx, client, repo) }},
				{"required-workflows", func() auditRow { return auditBitbucketRequiredWorkflows(groupCtx, client, repo, getYML) }},
				{"pipeline-supply-chain", func() auditRow { return auditBitbucketPipelineSupplyChain(repo, getYML) }},
				{"environment-protection", func() auditRow { return auditBitbucketEnvironments(groupCtx, client, repo) }},
				{"repo-secrets", func() auditRow { return auditBitbucketVariables(groupCtx, client, repo, o.showIdentifiers) }},
				{"deploy-keys", func() auditRow { return auditBitbucketDeployKeys(groupCtx, client, repo) }},
				{"webhooks", func() auditRow { return auditBitbucketWebhooks(groupCtx, client, repo) }},
				{"collaborators", func() auditRow { return auditBitbucketCollaborators(groupCtx, client, repo, o.showIdentifiers) }},
				{"signed-commits", func() auditRow {
					return providerRow("bitbucket", "repo", repo.FullName, "signed-commits", "Signed commits required", "medium", StatusSkipped, "requiring signed commits is a Premium UI setting without a REST API", "Enable required signed commits in repository settings (Premium).")
				}},
				{"vulnerability-alert-count", func() auditRow {
					return providerRow("bitbucket", "repo", repo.FullName, "vulnerability-alert-count", "Vulnerability alerts are triaged", "high", StatusSkipped, "no native vulnerability alert API", "Run dependency scanning in Pipelines and review its reports.")
				}},
				{"releases", func() auditRow {
					return providerRow("bitbucket", "repo", repo.FullName, "releases", "Releases are reviewed", "low", StatusSkipped, "Bitbucket Cloud has no releases; Downloads are mutable artifacts", "Publish immutable release artifacts from CI to a registry with provenance.")
				}},
				{"packages", func() auditRow {
					return providerRow("bitbucket", "repo", repo.FullName, "packages", "Packages are inventoried", "low", StatusSkipped, "Bitbucket Packages has no REST API to audit", "Review package visibility in the workspace UI.")
				}},
				{"dependency-sbom", func() auditRow {
					return providerRow("bitbucket", "repo", repo.FullName, "dependency-sbom", "Dependency SBOM is available", "medium", StatusSkipped, "no portable SBOM API found", "Generate SBOMs in CI.")
				}},
				{"repository-license", func() auditRow { return auditBitbucketRepositoryLicense(groupCtx, client, repo, srcRef) }},
				{"archived-active-risk", func() auditRow {
					return providerRow("bitbucket", "repo", repo.FullName, "archived-active-risk", "Archived repositories are reviewed", "low", StatusSkipped, "Bitbucket Cloud has no repository archiving", "Restrict or delete inactive repositories; archiving is unavailable.")
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
		return rows, repositories, err
	}
	return rows, repositories, nil
}

func listBitbucketRepos(ctx context.Context, c *restClient, o *opts) ([]bitbucketRepo, http.Header, error) {
	var workspaces []string
	var header http.Header
	if o.owner != "" {
		workspaces = append(workspaces, o.owner)
	} else {
		list, h, err := bitbucketPaged[struct {
			Slug string `json:"slug"`
		}](ctx, c, "/2.0/workspaces", nil)
		if err != nil {
			return nil, nil, fmt.Errorf("listing workspaces failed (pass --owner <workspace> to audit a single workspace): %w", err)
		}
		header = h
		for _, workspace := range list {
			if slug := strings.TrimSpace(workspace.Slug); slug != "" {
				workspaces = append(workspaces, slug)
			}
		}
	}
	extra := url.Values{}
	if o.adminOnly {
		extra.Set("role", "admin")
	}
	var all []bitbucketRepo
	for _, workspace := range workspaces {
		repos, h, err := bitbucketPaged[bitbucketRepo](ctx, c, "/2.0/repositories/"+url.PathEscape(workspace), extra)
		if err != nil {
			return nil, nil, err
		}
		if header == nil {
			header = h
		}
		for _, repo := range repos {
			if repo.Parent != nil && !o.includeForks {
				continue
			}
			all = append(all, repo)
		}
	}
	return all, header, nil
}

func giteaRepoPath(repo giteaRepo, suffix string) string {
	owner, name := giteaRepoParts(repo)
	return "/api/v1/repos/" + escapedPath(owner, name) + suffix
}
