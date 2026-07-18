package repoharden

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-github/v88/github"
)

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
	policy := strings.TrimSpace(out.ApprovalPolicy)
	switch policy {
	case "":
		return githubAuditRow(repo, "actions-fork-pr-permissions", "Fork PR approval policy is restrictive", "medium", StatusSkipped, "approval policy is not visible", "Require approval before running workflows from fork pull requests.")
	case "first_time_contributors_new_to_github", "first_time_contributors", "all_external_contributors":
		return githubAuditRow(repo, "actions-fork-pr-permissions", "Fork PR approval policy is restrictive", "medium", StatusCompliant, "approval policy: "+policy, "Require approval before running workflows from fork pull requests.")
	default:
		return githubAuditRow(repo, "actions-fork-pr-permissions", "Fork PR approval policy is restrictive", "medium", StatusGap, "unrecognized approval policy: "+policy, "Require approval before running workflows from fork pull requests.")
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
	productionLike := 0
	for _, env := range envs {
		if !githubProductionLikeEnvironment(env.GetName()) {
			continue
		}
		productionLike++
		if !githubEnvironmentProtected(env) {
			weak = append(weak, env.GetName())
		}
	}
	if len(weak) > 0 {
		return githubAuditRow(repo, "environment-protection", "Deployment environments are protected", "medium", StatusGap, "unprotected production-like environments: "+strings.Join(weak, ", "), "Add required reviewers or branch policies to production-like environments.")
	}
	if productionLike == 0 {
		return githubAuditRow(repo, "environment-protection", "Deployment environments are protected", "medium", StatusSkipped, fmt.Sprintf("%d environment(s) exist, but none have a recognizable production-like name; review them manually", len(envs)), "Add required reviewers or branch policies to production-like environments.")
	}
	return githubAuditRow(repo, "environment-protection", "Deployment environments are protected", "medium", StatusCompliant, fmt.Sprintf("%d production-like environment(s) protected", productionLike), "Add required reviewers or branch policies to production-like environments.")
}

func githubProductionLikeEnvironment(name string) bool {
	normalized := strings.NewReplacer("-", " ", "_", " ", "/", " ", ".", " ", ":", " ").Replace(strings.ToLower(name))
	for _, part := range strings.Fields(normalized) {
		switch part {
		case "prod", "production", "stage", "staging", "deploy", "deployment", "release", "live":
			return true
		}
	}
	return false
}

func auditGitHubRepoSecrets(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository, staleDays int, showIdentifiers bool) auditRow {
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
		detail := fmt.Sprintf("%d stale repository secrets", len(stale))
		if showIdentifiers {
			detail += ": " + strings.Join(limitStrings(stale, maxDetailItems), ", ")
		}
		return githubAuditRow(repo, "repo-secrets", "Repository secrets are reviewed and rotated", "medium", StatusGap, detail, "Rotate stale secrets and move shared secrets to org or environment scope where possible.")
	}
	return githubAuditRow(repo, "repo-secrets", "Repository secrets are reviewed and rotated", "medium", StatusCompliant, fmt.Sprintf("%d repository secrets", total), "Rotate stale secrets and move shared secrets to org or environment scope where possible.")
}

func auditGitHubDeployKeys(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository, showIdentifiers bool) auditRow {
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
		detail := fmt.Sprintf("%d writable deploy keys", len(writable))
		if showIdentifiers {
			detail += ": " + strings.Join(limitStrings(writable, maxDetailItems), ", ")
		}
		return githubAuditRow(repo, "deploy-keys", "Deploy keys are read-only or absent", "high", StatusGap, detail, "Remove unused deploy keys and make remaining keys read-only.")
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
		if endpointUnavailable(adminErr) {
			return githubAuditRow(repo, "collaborators", "Outside collaborators are minimized", "medium", StatusSkipped, "admin collaborators unavailable", "Remove stale outside collaborators and review direct admin access.")
		}
		return githubAuditRow(repo, "collaborators", "Outside collaborators are minimized", "medium", StatusError, adminErr.Error(), "Remove stale outside collaborators and review direct admin access.")
	}
	if len(outside) > 0 {
		return githubAuditRow(repo, "collaborators", "Outside collaborators are minimized", "medium", StatusGap, fmt.Sprintf("%d outside collaborators, %d admins", len(outside), len(admins)), "Remove stale outside collaborators and review direct admin access.")
	}
	return githubAuditRow(repo, "collaborators", "Outside collaborators are minimized", "medium", StatusCompliant, fmt.Sprintf("0 outside collaborators, %d admins", len(admins)), "Remove stale outside collaborators and review direct admin access.")
}
