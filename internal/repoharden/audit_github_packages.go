package repoharden

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/google/go-github/v88/github"
)

type githubPackageListResult struct {
	packages         []*github.Package
	unavailableTypes int
	skippedDetail    string
	err              error
}

type githubPackageCache struct {
	mu sync.Mutex
	m  map[string]*githubPackageCacheEntry
}

type githubPackageCacheEntry struct {
	done   chan struct{}
	result githubPackageListResult
}

func (pc *githubPackageCache) get(ctx context.Context, c *github.Client, owner string, repo *github.Repository) githubPackageListResult {
	ownerType := repo.GetOwner().GetType()
	key := ownerType + "/" + owner
	pc.mu.Lock()
	entry, ok := pc.m[key]
	if ok {
		pc.mu.Unlock()
		select {
		case <-entry.done:
			return entry.result
		case <-ctx.Done():
			return githubPackageListResult{err: ctx.Err()}
		}
	}
	entry = &githubPackageCacheEntry{done: make(chan struct{})}
	pc.m[key] = entry
	pc.mu.Unlock()

	entry.result = listGitHubOwnerPackages(ctx, c, owner, ownerType == "Organization")
	close(entry.done)
	return entry.result
}

var githubPackageTypes = []string{"container", "docker", "npm", "maven", "nuget", "rubygems"}

func auditGitHubPackages(ctx context.Context, c *github.Client, owner string, repo *github.Repository, cache *githubPackageCache) auditRow {
	result := cache.get(ctx, c, owner, repo)
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
	if result.unavailableTypes > 0 {
		return githubAuditRow(repo, "packages", "GitHub Packages are inventoried", "low", StatusSkipped, fmt.Sprintf("%d of %d package types unavailable; inventory is incomplete", result.unavailableTypes, len(githubPackageTypes)), "Review package visibility, stale versions, and repository package permissions.")
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
		var pager githubPager
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
			next, done, pageErr := pager.next(resp)
			if pageErr != nil {
				return githubPackageListResult{err: pageErr}
			}
			if done {
				break
			}
			opts.Page = next
		}
	}
	if unavailable == len(githubPackageTypes) {
		return githubPackageListResult{skippedDetail: "GitHub Packages API unavailable"}
	}
	return githubPackageListResult{packages: all, unavailableTypes: unavailable}
}

func auditGitHubSBOM(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	var out map[string]any
	if err := githubRawGet(ctx, c, fmt.Sprintf("repos/%s/%s/dependency-graph/sbom", owner, name), &out); err != nil {
		if githubStatus(err) == http.StatusForbidden {
			return githubAuditRow(repo, "dependency-sbom", "Dependency graph SBOM is available", "medium", StatusSkipped, "SBOM endpoint forbidden (needs access)", "Enable dependency graph/SBOM support and commit lockfiles where relevant.")
		}
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
		if endpointUnavailable(err) {
			return []auditRow{githubGlobalAuditRow("token-scopes", "Token scopes are visible and not excessive", "medium", StatusSkipped, "user endpoint unavailable (app or installation token)", "Use least-privilege fine-grained tokens where possible.")}
		}
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
		if endpointUnavailable(err) {
			return githubGlobalAuditRow(key, title, "high", StatusSkipped, "user endpoint unavailable (app or installation token)", rem)
		}
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
		return githubAuditErr(repo, key, title, "low", err, rem)
	}
	if ok {
		return githubAuditRow(repo, key, title, "low", StatusCompliant, ".github/dependabot.yml present", rem)
	}
	return githubAuditRow(repo, key, title, "low", StatusGap, "no .github/dependabot.yml (report-only)", rem)
}
