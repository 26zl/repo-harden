package repoharden

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/go-github/v88/github"
)

func auditGitHubOrganizations(ctx context.Context, c *github.Client, repos []*github.Repository, want func(string) bool, showIdentifiers bool) []auditRow {
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
			rows = append(rows, auditGitHubOrgSecrets(ctx, c, org, showIdentifiers))
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
			rows = append(rows, auditGitHubOrgOutsideCollaborators(ctx, c, org, showIdentifiers))
		}
		if want("org-runner-groups") {
			rows = append(rows, auditGitHubOrgRunnerGroups(ctx, c, org, showIdentifiers))
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
		return githubOrgAuditErr(org, key, title, "high", err, rem)
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
		return githubOrgAuditErr(org, key, title, "medium", err, rem)
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
	if info.MembersCanCreatePublicRepos != nil && info.GetMembersCanCreatePublicRepos() {
		issues = append(issues, "members can create public repos")
	}
	if len(issues) > 0 {
		return githubOrgAuditRow(org, key, title, "medium", StatusGap, strings.Join(issues, "; "), rem)
	}
	if info.MembersCanCreatePublicRepos == nil {
		return githubOrgAuditRow(org, key, title, "medium", StatusSkipped, "public repository creation setting not visible", rem)
	}
	return githubOrgAuditRow(org, key, title, "medium", StatusCompliant, "base permission: "+info.GetDefaultRepoPermission(), rem)
}

func auditGitHubOrg2FADisabledMembers(ctx context.Context, c *github.Client, org string) auditRow {
	const (
		key   = "org-2fa-disabled-members"
		title = "No organization members with 2FA disabled"
		rem   = "Require 2FA org-wide and remove or remediate members with 2FA disabled."
	)
	opts := &github.ListMembersOptions{Filter: "2fa_disabled", ListOptions: github.ListOptions{PerPage: 100}}
	total := 0
	var pager githubPager
	for {
		members, resp, err := c.Organizations.ListMembers(ctx, org, opts)
		if err != nil {
			if endpointUnavailable(err) {
				return githubOrgAuditRow(org, key, title, "high", StatusSkipped, "member 2FA list not visible (needs org admin)", rem)
			}
			return githubOrgAuditRow(org, key, title, "high", StatusError, err.Error(), rem)
		}
		total += len(members)
		next, done, pageErr := pager.next(resp)
		if pageErr != nil {
			return githubOrgAuditRow(org, key, title, "high", StatusError, pageErr.Error(), rem)
		}
		if done {
			break
		}
		opts.Page = next
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
		return githubOrgAuditErr(org, "org-actions-policy", "Organization Actions policy is restricted", "high", err, rem)
	}
	if p == nil {
		return githubOrgAuditRow(org, "org-actions-policy", "Organization Actions policy is restricted", "high", StatusSkipped, "org Actions policy not visible", rem)
	}
	if p.AllowedActions == nil || strings.TrimSpace(p.GetAllowedActions()) == "" ||
		p.EnabledRepositories == nil || strings.TrimSpace(p.GetEnabledRepositories()) == "" {
		return githubOrgAuditRow(org, "org-actions-policy", "Organization Actions policy is restricted", "high", StatusSkipped, "org Actions policy fields are incomplete", rem)
	}
	var issues []string
	switch p.GetAllowedActions() {
	case "all":
		issues = append(issues, "all actions allowed (no allowlist)")
	case "selected":
		allowed, _, aerr := c.Actions.GetActionsAllowed(ctx, org)
		if aerr != nil {
			return githubOrgAuditErr(org, "org-actions-policy", "Organization Actions policy is restricted", "high", aerr, rem)
		}
		if allowed == nil {
			return githubOrgAuditRow(org, "org-actions-policy", "Organization Actions policy is restricted", "high", StatusSkipped, "org Actions allowlist details are empty", rem)
		}
		if !allowed.GetGithubOwnedAllowed() || !allowed.GetVerifiedAllowed() {
			issues = append(issues, "allowlist does not require GitHub-owned + verified")
		}
		if len(allowed.PatternsAllowed) > 0 {
			issues = append(issues, "allowlist includes custom patterns")
		}
	case "local_only":
	default:
		return githubOrgAuditRow(org, "org-actions-policy", "Organization Actions policy is restricted", "high", StatusError, "unknown allowed_actions value: "+p.GetAllowedActions(), rem)
	}
	if p.GetEnabledRepositories() == "all" {
		issues = append(issues, "actions enabled on all repositories")
	}
	if p.SHAPinningRequired == nil {
		if len(issues) == 0 {
			return githubOrgAuditRow(org, "org-actions-policy", "Organization Actions policy is restricted", "high", StatusSkipped, "SHA pinning setting not visible", rem)
		}
		issues = append(issues, "SHA pinning setting not visible")
	} else if !p.GetSHAPinningRequired() {
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
		return githubOrgAuditErr(org, "org-token-policy", "Organization default GITHUB_TOKEN is read-only", "high", err, "Set organization default workflow token permissions to read and prevent PR approval.")
	}
	if p == nil {
		return githubOrgAuditRow(org, "org-token-policy", "Organization default GITHUB_TOKEN is read-only", "high", StatusSkipped, "organization workflow token policy is not visible", "Set organization default workflow token permissions to read and prevent PR approval.")
	}
	if p.GetDefaultWorkflowPermissions() == "read" && !p.GetCanApprovePullRequestReviews() {
		return githubOrgAuditRow(org, "org-token-policy", "Organization default GITHUB_TOKEN is read-only", "high", StatusCompliant, "default token is read-only", "Set organization default workflow token permissions to read and prevent PR approval.")
	}
	return githubOrgAuditRow(org, "org-token-policy", "Organization default GITHUB_TOKEN is read-only", "high", StatusGap, fmt.Sprintf("token=%s can_approve_pr=%v", p.GetDefaultWorkflowPermissions(), p.GetCanApprovePullRequestReviews()), "Set organization default workflow token permissions to read and prevent PR approval.")
}

func auditGitHubOrgSecrets(ctx context.Context, c *github.Client, org string, showIdentifiers bool) auditRow {
	secrets, total, err := listGitHubOrgSecrets(ctx, c, org)
	if err != nil {
		return githubOrgAuditErr(org, "org-secrets", "Organization secrets are scoped narrowly", "medium", err, "Scope org secrets to selected repositories and rotate stale secrets.")
	}
	var allRepo []string
	for _, secret := range secrets {
		if secret.Visibility == "all" {
			allRepo = append(allRepo, secret.Name)
		}
	}
	if len(allRepo) > 0 {
		detail := fmt.Sprintf("%d organization secrets are visible to all repositories", len(allRepo))
		if showIdentifiers {
			detail += ": " + strings.Join(limitStrings(allRepo, maxDetailItems), ", ")
		}
		return githubOrgAuditRow(org, "org-secrets", "Organization secrets are scoped narrowly", "medium", StatusGap, detail, "Scope org secrets to selected repositories and rotate stale secrets.")
	}
	return githubOrgAuditRow(org, "org-secrets", "Organization secrets are scoped narrowly", "medium", StatusCompliant, fmt.Sprintf("%d org secrets reviewed", total), "Scope org secrets to selected repositories and rotate stale secrets.")
}

func auditGitHubOrgWebhooks(ctx context.Context, c *github.Client, org string) auditRow {
	hooks, err := listGitHubOrgHooks(ctx, c, org)
	if err != nil {
		return githubOrgAuditErr(org, "org-webhooks", "Organization webhooks are reviewed", "medium", err, "Remove stale org webhooks and require HTTPS.")
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

func auditGitHubOrgOutsideCollaborators(ctx context.Context, c *github.Client, org string, showIdentifiers bool) auditRow {
	const (
		key   = "org-outside-collaborators"
		title = "Outside collaborators are reviewed"
		rem   = "Review outside collaborators; prefer org membership/teams and remove unneeded external access."
	)
	opts := &github.ListOutsideCollaboratorsOptions{ListOptions: github.ListOptions{PerPage: 100}}
	var names []string
	var pager githubPager
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
		next, done, pageErr := pager.next(resp)
		if pageErr != nil {
			return githubOrgAuditRow(org, key, title, "medium", StatusError, pageErr.Error(), rem)
		}
		if done {
			break
		}
		opts.Page = next
	}
	if len(names) > 0 {
		detail := fmt.Sprintf("%d outside collaborator(s) to review", len(names))
		if showIdentifiers {
			detail += ": " + strings.Join(limitStrings(names, maxDetailItems), ", ")
		}
		return githubOrgAuditRow(org, key, title, "medium", StatusGap, detail, rem)
	}
	return githubOrgAuditRow(org, key, title, "medium", StatusCompliant, "no outside collaborators", rem)
}
