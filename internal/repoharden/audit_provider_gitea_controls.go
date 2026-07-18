package repoharden

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

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

func auditGiteaWorkflows(provider string, repo giteaRepo, get func() (map[string]string, error)) auditRow {
	if repo.DefaultBranch == "" {
		return providerRow(provider, "repo", repo.FullName, "required-workflows", "Actions workflow configuration exists", "medium", StatusSkipped, "no default branch", "Add required CI workflows.")
	}
	files, err := get()
	if err != nil {
		if httpUnavailable(err) {
			return providerRow(provider, "repo", repo.FullName, "required-workflows", "Actions workflow configuration exists", "medium", StatusSkipped, "workflow files are not readable", "Add required CI workflows.")
		}
		return providerRow(provider, "repo", repo.FullName, "required-workflows", "Actions workflow configuration exists", "medium", StatusError, err.Error(), "Add required CI workflows.")
	}
	if len(files) == 0 {
		return providerRow(provider, "repo", repo.FullName, "required-workflows", "Actions workflow configuration exists", "medium", StatusGap, "no readable workflow files found", "Add required CI workflows.")
	}
	valid := 0
	var invalid []string
	for path, content := range files {
		if err := validateGiteaWorkflow(content); err != nil {
			invalid = append(invalid, path+" ("+err.Error()+")")
			continue
		}
		valid++
	}
	if valid > 0 {
		return providerRow(provider, "repo", repo.FullName, "required-workflows", "Actions workflow configuration exists", "medium", StatusCompliant, fmt.Sprintf("%d semantically valid workflow file(s)", valid), "Add required CI workflows.")
	}
	sort.Strings(invalid)
	return providerRow(provider, "repo", repo.FullName, "required-workflows", "Actions workflow configuration exists", "medium", StatusGap, "no semantically valid workflow files: "+strings.Join(limitStrings(invalid, maxDetailItems), ", "), "Add required CI workflows with a trigger and executable jobs.")
}

func auditGiteaSecrets(ctx context.Context, c *restClient, provider string, repo giteaRepo) auditRow {
	secrets, err := giteaPaged[map[string]any](ctx, c, giteaRepoPath(repo, "/actions/secrets"))
	if err != nil {
		if httpUnavailable(err) {
			return providerRow(provider, "repo", repo.FullName, "repo-secrets", "Action secrets are reviewed", "medium", StatusSkipped, "actions secrets API unavailable", "Review and rotate repository action secrets.")
		}
		return providerRow(provider, "repo", repo.FullName, "repo-secrets", "Action secrets are reviewed", "medium", StatusError, err.Error(), "Review and rotate repository action secrets.")
	}
	return providerRow(provider, "repo", repo.FullName, "repo-secrets", "Action secrets are reviewed", "medium", StatusCompliant, fmt.Sprintf("%d action secrets visible", len(secrets)), "Review and rotate repository action secrets.")
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

func auditGiteaDeployKeys(ctx context.Context, c *restClient, provider string, repo giteaRepo, showIdentifiers bool) auditRow {
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
		detail := fmt.Sprintf("%d writable deploy keys", len(writable))
		if showIdentifiers {
			detail += ": " + strings.Join(limitStrings(writable, maxDetailItems), ", ")
		}
		return providerRow(provider, "repo", repo.FullName, "deploy-keys", "Deploy keys are read-only or absent", "high", StatusGap, detail, "Remove unused deploy keys and disable write access.")
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

func auditGiteaCollaborators(ctx context.Context, c *restClient, provider string, repo giteaRepo, showIdentifiers bool) auditRow {
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
		detail := fmt.Sprintf("%d direct admins/owners", len(admins))
		if showIdentifiers {
			detail += ": " + strings.Join(limitStrings(admins, maxDetailItems), ", ")
		}
		return providerRow(provider, "repo", repo.FullName, "collaborators", "Collaborators are reviewed", "medium", StatusGap, detail, "Review direct collaborators and remove stale admins.")
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
