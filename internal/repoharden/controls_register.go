package repoharden

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/go-github/v88/github"
)

func init() {
	baseline = append(baseline, Control{
		Key:         "dependabot-alerts",
		Title:       "Dependabot vulnerability alerts enabled",
		Severity:    "high",
		Remediation: "Enable Dependabot vulnerability alerts for the repository.",
		Detect: func(ctx context.Context, c *github.Client, owner, name string, _ *github.Repository) DetectResult {
			on, _, err := c.Repositories.GetVulnerabilityAlerts(ctx, owner, name)
			if err != nil {
				return detectErr(err)
			}
			if on {
				return DetectResult{Status: StatusCompliant, Prior: "enabled"}
			}
			return DetectResult{Status: StatusGap, Prior: "disabled"}
		},
		Apply: func(ctx context.Context, c *github.Client, owner, name string) error {
			_, err := c.Repositories.EnableVulnerabilityAlerts(ctx, owner, name)
			return err
		},
		Revert: func(ctx context.Context, c *github.Client, owner, name, prior string) error {
			if prior == "enabled" {
				return nil
			}
			_, err := c.Repositories.DisableVulnerabilityAlerts(ctx, owner, name)
			return err
		},
	})
}

func init() {
	baseline = append(baseline,
		Control{
			Key:         "dependabot-fixes",
			Title:       "Dependabot security updates enabled",
			Severity:    "medium",
			Remediation: "Enable Dependabot security updates so vulnerable manifests get automated PRs.",
			Detect: func(ctx context.Context, c *github.Client, owner, name string, _ *github.Repository) DetectResult {
				f, _, err := c.Repositories.GetAutomatedSecurityFixes(ctx, owner, name)
				if err != nil {
					return detectErr(err)
				}
				if f.GetEnabled() {
					return DetectResult{Status: StatusCompliant, Prior: "enabled"}
				}
				return DetectResult{Status: StatusGap, Prior: "disabled"}
			},
			Apply: func(ctx context.Context, c *github.Client, owner, name string) error {
				_, err := c.Repositories.EnableAutomatedSecurityFixes(ctx, owner, name)
				return err
			},
			Revert: func(ctx context.Context, c *github.Client, owner, name, prior string) error {
				if prior == "enabled" {
					return nil
				}
				_, err := c.Repositories.DisableAutomatedSecurityFixes(ctx, owner, name)
				return err
			},
		},
		Control{
			Key:         "token-readonly",
			Title:       "Default GITHUB_TOKEN is read-only and cannot approve PRs",
			Severity:    "high",
			Remediation: "Set default workflow permissions to read and disable PR approval by GitHub Actions.",
			Detect: func(ctx context.Context, c *github.Client, owner, name string, _ *github.Repository) DetectResult {
				p, _, err := c.Repositories.GetDefaultWorkflowPermissions(ctx, owner, name)
				if err != nil {
					return detectErr(err)
				}
				if p == nil {
					return DetectResult{Status: StatusError, Detail: "empty workflow-permissions response"}
				}
				if p.GetDefaultWorkflowPermissions() == "" || p.CanApprovePullRequestReviews == nil {
					return DetectResult{Status: StatusSkipped, Detail: "workflow permission fields are not fully visible"}
				}
				prior := workflowPermissionPrior{
					Default:    p.GetDefaultWorkflowPermissions(),
					CanApprove: p.CanApprovePullRequestReviews,
				}
				if p.GetDefaultWorkflowPermissions() == "read" && !p.GetCanApprovePullRequestReviews() {
					return DetectResult{Status: StatusCompliant, Prior: encodePrior(prior)}
				}
				return DetectResult{Status: StatusGap, Prior: encodePrior(prior)}
			},
			Apply: func(ctx context.Context, c *github.Client, owner, name string) error {
				_, _, err := c.Repositories.UpdateDefaultWorkflowPermissions(ctx, owner, name,
					github.DefaultWorkflowPermissionRepository{
						DefaultWorkflowPermissions:   github.Ptr("read"),
						CanApprovePullRequestReviews: github.Ptr(false),
					})
				return err
			},
			Revert: func(ctx context.Context, c *github.Client, owner, name, prior string) error {
				p := parseWorkflowPermissionPrior(prior)
				if p.Default == "" {
					return nil
				}
				req := github.DefaultWorkflowPermissionRepository{
					DefaultWorkflowPermissions:   github.Ptr(p.Default),
					CanApprovePullRequestReviews: github.Ptr(p.CanApprove != nil && *p.CanApprove),
				}
				_, _, err := c.Repositories.UpdateDefaultWorkflowPermissions(ctx, owner, name, req)
				return err
			},
		},
	)
}

func init() {
	baseline = append(baseline, Control{
		Key:         "actions-allowlist",
		Title:       "Actions policy is narrow and SHA-pinned",
		Severity:    "high",
		Remediation: "Use local-only Actions or a selected policy with full-SHA pinning. Allow GitHub-owned actions and either verified creators without custom patterns, or only explicit owner/action patterns.",
		Detect: func(ctx context.Context, c *github.Client, owner, name string, _ *github.Repository) DetectResult {
			p, _, err := c.Repositories.GetActionsPermissions(ctx, owner, name)
			if err != nil {
				return detectErr(err)
			}
			if p == nil || p.Enabled == nil {
				return DetectResult{Status: StatusSkipped, Detail: "Actions enabled setting is not visible"}
			}
			if !p.GetEnabled() {
				return DetectResult{Status: StatusSkipped, Detail: "Actions disabled for this repository"}
			}
			if p.GetAllowedActions() == "" {
				return DetectResult{Status: StatusError, Detail: "Actions allowed_actions field is missing"}
			}
			prior := actionsAllowlistPrior{Enabled: p.Enabled, AllowedActions: p.GetAllowedActions(), SHAPinningRequired: p.SHAPinningRequired}
			if p.GetAllowedActions() == "local_only" {
				return DetectResult{Status: StatusCompliant, Prior: encodePrior(prior), Detail: "only actions defined in this repository are allowed"}
			}
			if p.GetAllowedActions() != "selected" {
				return DetectResult{Status: StatusGap, Prior: encodePrior(prior)}
			}
			allowed, _, err := c.Repositories.GetActionsAllowed(ctx, owner, name)
			if err != nil {
				return detectErr(err)
			}
			if allowed == nil {
				return DetectResult{Status: StatusError, Detail: "empty actions-allowed response"}
			}
			prior.GithubOwnedAllowed = allowed.GithubOwnedAllowed
			prior.VerifiedAllowed = allowed.VerifiedAllowed
			prior.PatternsAllowed = allowed.PatternsAllowed
			if p.SHAPinningRequired == nil {
				return DetectResult{Status: StatusSkipped, Prior: encodePrior(prior), Detail: "selected policy is visible, but SHA-pinning enforcement is not reported by this host"}
			}
			if !p.GetSHAPinningRequired() {
				return DetectResult{Status: StatusGap, Prior: encodePrior(prior), Detail: "full-length commit SHA pinning is not required"}
			}
			if !allowed.GetGithubOwnedAllowed() {
				return DetectResult{Status: StatusGap, Prior: encodePrior(prior), Detail: "GitHub-owned actions are not allowed by the managed baseline"}
			}
			if ok, invalid := explicitActionPatterns(allowed.PatternsAllowed); !ok {
				return DetectResult{Status: StatusGap, Prior: encodePrior(prior), Detail: "broad or malformed custom action patterns: " + strings.Join(invalid, ", ")}
			}
			detail := "GitHub-owned actions and verified creators are allowed with full-SHA pinning"
			if len(allowed.PatternsAllowed) > 0 || !allowed.GetVerifiedAllowed() {
				detail = "GitHub-owned actions and explicit custom actions are allowed with full-SHA pinning"
			}
			return DetectResult{Status: StatusCompliant, Prior: encodePrior(prior), Detail: detail}
		},
		Apply: func(ctx context.Context, c *github.Client, owner, name string) error {
			current, _, err := c.Repositories.GetActionsPermissions(ctx, owner, name)
			if err != nil {
				return fmt.Errorf("read current Actions permissions before mutation: %w", err)
			}
			if current == nil || current.Enabled == nil || current.GetAllowedActions() == "" {
				return fmt.Errorf("read current Actions permissions before mutation: incomplete response")
			}
			desired := actionsAllowedRequest{
				GithubOwnedAllowed: github.Ptr(true),
				VerifiedAllowed:    github.Ptr(true),
			}
			if current.GetAllowedActions() == "selected" {
				allowed, _, getErr := c.Repositories.GetActionsAllowed(ctx, owner, name)
				if getErr != nil {
					return fmt.Errorf("read current selected Actions policy before mutation: %w", getErr)
				}
				if allowed == nil {
					return fmt.Errorf("read current selected Actions policy before mutation: empty response")
				}
				if safe, _ := explicitActionPatterns(allowed.PatternsAllowed); safe {
					desired.VerifiedAllowed = github.Ptr(allowed.GetVerifiedAllowed())
					desired.PatternsAllowed = append([]string(nil), allowed.PatternsAllowed...)
				}
			}
			if _, _, err := c.Repositories.UpdateActionsPermissions(ctx, owner, name,
				github.ActionsPermissionsRepository{
					Enabled:            github.Ptr(true),
					AllowedActions:     github.Ptr("selected"),
					SHAPinningRequired: github.Ptr(true),
				}); err != nil {
				return err
			}
			return editActionsAllowedExact(ctx, c, owner, name, desired)
		},
		Revert: func(ctx context.Context, c *github.Client, owner, name, prior string) error {
			p := parseActionsAllowlistPrior(prior)
			if p.AllowedActions == "" {
				return nil
			}
			_, _, err := c.Repositories.UpdateActionsPermissions(ctx, owner, name,
				github.ActionsPermissionsRepository{
					Enabled:            github.Ptr(p.Enabled == nil || *p.Enabled),
					AllowedActions:     github.Ptr(p.AllowedActions),
					SHAPinningRequired: p.SHAPinningRequired,
				})
			if err != nil || p.AllowedActions != "selected" {
				return err
			}
			return editActionsAllowedExact(ctx, c, owner, name, actionsAllowedRequest{
				GithubOwnedAllowed: p.GithubOwnedAllowed,
				VerifiedAllowed:    p.VerifiedAllowed,
				PatternsAllowed:    p.PatternsAllowed,
			})
		},
		MatchesHardened: actionsAllowlistMatchesApplied,
	})
}

func actionsAllowlistMatchesApplied(result DetectResult, prior string) bool {
	if result.Status != StatusCompliant || result.Prior == "" {
		return false
	}
	live := parseActionsAllowlistPrior(result.Prior)
	if live.AllowedActions != "selected" || live.Enabled == nil || !*live.Enabled ||
		live.SHAPinningRequired == nil || !*live.SHAPinningRequired ||
		live.GithubOwnedAllowed == nil || !*live.GithubOwnedAllowed {
		return false
	}
	expectedVerified := true
	var expectedPatterns []string
	if strings.HasPrefix(strings.TrimSpace(prior), "{") {
		captured := parseActionsAllowlistPrior(prior)
		if captured.AllowedActions == "selected" {
			if safe, _ := explicitActionPatterns(captured.PatternsAllowed); safe {
				expectedVerified = captured.VerifiedAllowed != nil && *captured.VerifiedAllowed
				expectedPatterns = captured.PatternsAllowed
			}
		}
	}
	return live.VerifiedAllowed != nil && *live.VerifiedAllowed == expectedVerified &&
		sameActionPatterns(live.PatternsAllowed, expectedPatterns)
}

func sameActionPatterns(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a = append([]string(nil), a...)
	b = append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// explicitActionPatterns rejects owner/repository wildcards; ref wildcards are safe only because callers also require GitHub's full-SHA policy.
func explicitActionPatterns(patterns []string) (bool, []string) {
	var invalid []string
	for _, pattern := range patterns {
		path, ref, ok := strings.Cut(strings.TrimSpace(pattern), "@")
		parts := strings.Split(path, "/")
		if !ok || ref == "" || len(parts) < 2 || strings.ContainsAny(path, "*?[]!{}\\") {
			invalid = append(invalid, pattern)
			continue
		}
		valid := true
		for _, part := range parts {
			if part == "" || strings.Trim(part, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != "" {
				valid = false
				break
			}
		}
		if !valid || strings.ContainsAny(ref, "@ \t\r\n") {
			invalid = append(invalid, pattern)
		}
	}
	return len(invalid) == 0, invalid
}

func init() {
	baseline = append(baseline, Control{
		Key:         "branch-protection",
		Title:       "Managed default-branch ruleset present",
		Severity:    "high",
		Remediation: "Protect the default branch with a required PR path, resolved review threads, deletion and non-fast-forward protection, and linear history. Add independent approval requirements where the repository has another eligible reviewer.",
		Detect: func(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) DetectResult {
			sets, err := allRepoRulesets(ctx, c, owner, name, false)
			if err != nil {
				return detectErr(err)
			}
			for _, rs := range sets {
				if rs.Name != controlRulesetName {
					continue
				}
				full, _, err := c.Repositories.GetRuleset(ctx, owner, name, rs.GetID(), false)
				if err != nil {
					return detectErr(err)
				}
				if full == nil {
					return DetectResult{Status: StatusError, Detail: "could not read existing ruleset named " + controlRulesetName}
				}
				if managedRulesetValid(full, repo.GetDefaultBranch()) {
					return DetectResult{Status: StatusCompliant, Prior: encodePrior(full)}
				}
				return DetectResult{Status: StatusGap, Prior: encodePrior(full), Detail: "ruleset named " + controlRulesetName + " is incomplete or inactive"}
			}
			return DetectResult{Status: StatusGap, Detail: "managed ruleset missing"}
		},
		Apply: func(ctx context.Context, c *github.Client, owner, name string) error {
			spec := managedRulesetSpec(owner, name)
			sets, err := allRepoRulesets(ctx, c, owner, name, false)
			if err != nil {
				return fmt.Errorf("confirm existing managed ruleset before mutation: %w", err)
			}
			for _, rs := range sets {
				if rs.Name == controlRulesetName {
					full, _, err := c.Repositories.GetRuleset(ctx, owner, name, rs.GetID(), false)
					if err != nil {
						return fmt.Errorf("read existing managed ruleset before merge: %w", err)
					}
					spec, err = mergeManagedRuleset(full, owner, name)
					if err != nil {
						return fmt.Errorf("refuse unsafe same-name ruleset update: %w", err)
					}
					_, _, err = c.Repositories.UpdateRuleset(ctx, owner, name, rs.GetID(), spec)
					return err
				}
			}
			_, _, err = c.Repositories.CreateRuleset(ctx, owner, name, spec)
			return err
		},
		Revert: func(ctx context.Context, c *github.Client, owner, name, prior string) error {
			sets, err := allRepoRulesets(ctx, c, owner, name, false)
			if err != nil {
				return err
			}
			id := int64(-1)
			for _, rs := range sets {
				if rs.Name == controlRulesetName {
					id = rs.GetID()
					break
				}
			}
			if id < 0 {
				return nil
			}
			if s := strings.TrimSpace(prior); s != "" && s != "null" {
				var captured github.RepositoryRuleset
				if err := json.Unmarshal([]byte(prior), &captured); err == nil && captured.Name != "" {
					_, _, err := c.Repositories.UpdateRuleset(ctx, owner, name, id, github.RepositoryRuleset{
						Name:         captured.Name,
						Source:       owner + "/" + name,
						SourceType:   github.Ptr(github.RulesetSourceTypeRepository),
						Target:       captured.Target,
						Enforcement:  captured.Enforcement,
						Conditions:   captured.Conditions,
						Rules:        captured.Rules,
						BypassActors: captured.BypassActors,
					})
					return err
				}
			}
			_, err = c.Repositories.DeleteRuleset(ctx, owner, name, id)
			return err
		},
		MatchesHardened: func(result DetectResult, prior string) bool {
			return rulesetMatchesAppliedPrior(result, prior)
		},
	})
}

func init() {
	baseline = append(baseline,
		Control{
			Key:         "secret-scanning",
			Title:       "Secret scanning + push protection enabled",
			Severity:    "critical",
			Remediation: "Enable secret scanning and push protection where the GitHub plan supports it.",
			Detect: func(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) DetectResult {
				full, _, err := c.Repositories.Get(ctx, owner, name)
				if err != nil {
					return detectErr(err)
				}
				sa := full.GetSecurityAndAnalysis()
				secretStatus := sa.GetSecretScanning().GetStatus()
				pushStatus := sa.GetSecretScanningPushProtection().GetStatus()
				if repo.GetPrivate() && secretStatus == "" && pushStatus == "" {
					return DetectResult{Status: StatusSkipped, Detail: "private repo - requires license or admin-visible security settings"}
				}
				prior := secretScanningPrior{
					SecretScanning: githubStatusOrDisabled(secretStatus),
					PushProtection: githubStatusOrDisabled(pushStatus),
				}
				if sa.GetSecretScanning().GetStatus() == "enabled" &&
					sa.GetSecretScanningPushProtection().GetStatus() == "enabled" {
					return DetectResult{Status: StatusCompliant, Prior: encodePrior(prior)}
				}
				return DetectResult{Status: StatusGap, Prior: encodePrior(prior)}
			},
			Apply: func(ctx context.Context, c *github.Client, owner, name string) error {
				_, _, err := c.Repositories.Edit(ctx, owner, name, &github.Repository{
					SecurityAndAnalysis: &github.SecurityAndAnalysis{
						SecretScanning:               &github.SecretScanning{Status: github.Ptr("enabled")},
						SecretScanningPushProtection: &github.SecretScanningPushProtection{Status: github.Ptr("enabled")},
					},
				})
				return err
			},
			Revert: func(ctx context.Context, c *github.Client, owner, name, prior string) error {
				p := parseSecretScanningPrior(prior)
				if p.SecretScanning == "enabled" && p.PushProtection == "enabled" {
					return nil
				}
				_, _, err := c.Repositories.Edit(ctx, owner, name, &github.Repository{
					SecurityAndAnalysis: &github.SecurityAndAnalysis{
						SecretScanning: &github.SecretScanning{
							Status: github.Ptr(githubStatusOrDisabled(p.SecretScanning)),
						},
						SecretScanningPushProtection: &github.SecretScanningPushProtection{
							Status: github.Ptr(githubStatusOrDisabled(p.PushProtection)),
						},
					},
				})
				return err
			},
		},
		Control{
			Key:         "code-scanning",
			Title:       "CodeQL default setup enabled",
			Severity:    "high",
			Remediation: "Enable CodeQL default setup or an equivalent code scanning workflow.",
			Detect: func(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) DetectResult {
				cfg, _, err := c.CodeScanning.GetDefaultSetupConfiguration(ctx, owner, name)
				if err != nil {
					if repo.GetPrivate() && endpointUnavailable(err) {
						return DetectResult{Status: StatusSkipped, Detail: "private repo - requires Code Security/Advanced Security availability"}
					}
					return detectErr(err)
				}
				if cfg.GetState() == "configured" {
					return DetectResult{Status: StatusCompliant, Prior: "configured"}
				}
				ref := "refs/heads/" + repo.GetDefaultBranch()
				analyses, _, aerr := c.CodeScanning.ListAnalysesForRepo(ctx, owner, name,
					&github.AnalysesListOptions{Ref: github.Ptr(ref), ListOptions: github.ListOptions{PerPage: 1}})
				if aerr != nil {
					return detectErr(aerr)
				}
				if len(analyses) > 0 {
					if time.Since(analyses[0].GetCreatedAt().Time) < codeScanningFreshness {
						return DetectResult{Status: StatusCompliant, Prior: "not-configured", Detail: "recent code scanning analysis on default branch (advanced/workflow setup)"}
					}
					return DetectResult{Status: StatusGap, Prior: "not-configured", Detail: "code scanning analyses on default branch are stale"}
				}
				return DetectResult{Status: StatusGap, Prior: "not-configured"}
			},
			Apply: func(ctx context.Context, c *github.Client, owner, name string) error {
				_, _, err := c.CodeScanning.UpdateDefaultSetupConfiguration(ctx, owner, name,
					&github.UpdateDefaultSetupConfigurationOptions{State: "configured"})
				return err
			},
			Revert: func(ctx context.Context, c *github.Client, owner, name, prior string) error {
				if prior == "configured" {
					return nil
				}
				_, _, err := c.CodeScanning.UpdateDefaultSetupConfiguration(ctx, owner, name,
					&github.UpdateDefaultSetupConfigurationOptions{State: "not-configured"})
				return err
			},
			MatchesHardened: func(result DetectResult, _ string) bool {
				return result.Status == StatusCompliant && result.Prior == "configured"
			},
		},
	)
}

func fileExists(ctx context.Context, c *github.Client, owner, name string, paths ...string) (bool, error) {
	for _, p := range paths {
		file, _, _, err := c.Repositories.GetContents(ctx, owner, name, p, nil)
		if err == nil && file != nil {
			return true, nil
		}
		if err != nil && githubStatus(err) != http.StatusNotFound {
			return false, err
		}
	}
	return false, nil
}

func init() {
	baseline = append(baseline,
		Control{
			Key:         "security-md",
			Title:       "SECURITY.md present",
			Severity:    "low",
			Remediation: "Add SECURITY.md with supported versions and vulnerability reporting instructions.",
			Detect: func(ctx context.Context, c *github.Client, owner, name string, _ *github.Repository) DetectResult {
				ok, err := fileExists(ctx, c, owner, name, "SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")
				if err != nil {
					return detectErr(err)
				}
				if ok {
					return DetectResult{Status: StatusCompliant}
				}
				return DetectResult{Status: StatusGap, Detail: "no SECURITY.md (report-only)"}
			},
		},
		Control{
			Key:         "codeowners",
			Title:       "CODEOWNERS present",
			Severity:    "medium",
			Remediation: "Add CODEOWNERS so sensitive paths have accountable reviewers.",
			Detect: func(ctx context.Context, c *github.Client, owner, name string, _ *github.Repository) DetectResult {
				ok, err := fileExists(ctx, c, owner, name, ".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
				if err != nil {
					return detectErr(err)
				}
				if ok {
					return DetectResult{Status: StatusCompliant}
				}
				return DetectResult{Status: StatusGap, Detail: "no CODEOWNERS (report-only)"}
			},
		},
	)
}

func init() {
	baseline = append(baseline, Control{
		Key:         "private-vulnerability-reporting",
		Title:       "Private vulnerability reporting enabled",
		Severity:    "medium",
		Remediation: "Enable private vulnerability reporting so researchers can report issues privately instead of in public issues.",
		Detect: func(ctx context.Context, c *github.Client, owner, name string, _ *github.Repository) DetectResult {
			on, _, err := c.Repositories.IsPrivateReportingEnabled(ctx, owner, name)
			if err != nil {
				if endpointUnavailable(err) {
					return DetectResult{Status: StatusSkipped, Detail: "private vulnerability reporting unavailable for this repo"}
				}
				return detectErr(err)
			}
			if on {
				return DetectResult{Status: StatusCompliant, Prior: "enabled"}
			}
			return DetectResult{Status: StatusGap, Prior: "disabled"}
		},
		Apply: func(ctx context.Context, c *github.Client, owner, name string) error {
			_, err := c.Repositories.EnablePrivateReporting(ctx, owner, name)
			return err
		},
		Revert: func(ctx context.Context, c *github.Client, owner, name, prior string) error {
			if prior == "enabled" {
				return nil
			}
			_, err := c.Repositories.DisablePrivateReporting(ctx, owner, name)
			return err
		},
	})
}
