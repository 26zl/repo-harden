package repoharden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/go-github/v88/github"
)

// controlRulesetName is the name of the ruleset this tool manages.
const controlRulesetName = "repo-harden"

// codeScanningFreshness is how recent an analysis must be to count as still scanning.
const codeScanningFreshness = 90 * 24 * time.Hour

type ControlStatus string

const (
	StatusCompliant ControlStatus = "compliant" // already meets the baseline
	StatusGap       ControlStatus = "gap"       // does not meet it; fixable by Apply
	StatusSkipped   ControlStatus = "skipped"   // unavailable, e.g. needs a paid license
	StatusError     ControlStatus = "error"     // detection failed
)

// DetectResult is what a control reports for one repo. Prior lets Revert put the old value back.
type DetectResult struct {
	Status ControlStatus
	Prior  string
	Detail string
}

// Control is one baseline check. Apply/Revert are nil for report-only controls.
type Control struct {
	Key           string
	Title         string
	Severity      string
	Remediation   string
	Detect        func(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) DetectResult
	Apply         func(ctx context.Context, c *github.Client, owner, name string) error
	Revert        func(ctx context.Context, c *github.Client, owner, name, prior string) error
	ValidatePrior func(prior string) error
	// MatchesHardened can narrow StatusCompliant when a control accepts multiple
	// safe configurations but revert must only undo the exact one we applied.
	MatchesHardened func(result DetectResult) bool
}

// baseline holds all the controls. the init() blocks below register them.
var baseline []Control

// selectControls applies --only / --skip (comma-separated keys) to the baseline.
func selectControls(only, skip string) []Control {
	onlySet := splitSet(only)
	skipSet := splitSet(skip)
	var out []Control
	for _, ctl := range baseline {
		if len(onlySet) > 0 && !onlySet[ctl.Key] {
			continue
		}
		if skipSet[ctl.Key] {
			continue
		}
		out = append(out, ctl)
	}
	return out
}

func selectedControls(o *opts) ([]Control, error) {
	if err := validateControlSelection(o.only, o.skip); err != nil {
		return nil, usageError{err}
	}
	controls := selectControls(o.only, o.skip)
	if len(controls) == 0 {
		return nil, usageErr("no controls selected")
	}
	return controls, nil
}

func validateControlSelection(only, skip string) error {
	known := map[string]bool{}
	for _, ctl := range baseline {
		known[ctl.Key] = true
	}
	for flag, set := range map[string]map[string]bool{"--only": splitSet(only), "--skip": splitSet(skip)} {
		var unknown []string
		for key := range set {
			if !known[key] {
				unknown = append(unknown, key)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			return fmt.Errorf("%s contains unknown control(s): %s", flag, strings.Join(unknown, ", "))
		}
	}
	return nil
}

func encodePrior(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// managedRulesetValid checks rs is an active branch ruleset on the default branch
// with the exact protections harden applies. checks the values, not just that rules exist.
func managedRulesetValid(rs *github.RepositoryRuleset, branch string) bool {
	if rs == nil || rs.Rules == nil || rs.Enforcement != github.RulesetEnforcementActive {
		return false
	}
	if t := rs.GetTarget(); t == nil || *t != github.RulesetTargetBranch {
		return false
	}
	if !rulesetTargetsBranch(rs, branch) {
		return false
	}
	pr := rs.Rules.PullRequest
	if pr == nil || pr.RequiredApprovingReviewCount < 1 || !pr.RequiredReviewThreadResolution {
		return false
	}
	return rs.Rules.NonFastForward != nil && rs.Rules.RequiredLinearHistory != nil
}

func githubStatus(err error) int {
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		return ghErr.Response.StatusCode
	}
	return 0
}

func endpointUnavailable(err error) bool {
	switch githubStatus(err) {
	case http.StatusNotFound, http.StatusUnprocessableEntity:
		return true
	case http.StatusForbidden:
		var ghErr *github.ErrorResponse
		if errors.As(err, &ghErr) && ghErr.Response != nil {
			if ghErr.Response.Header.Get("Retry-After") != "" ||
				ghErr.Response.Header.Get("X-RateLimit-Remaining") == "0" {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// detectErr returns Skipped when the endpoint is just unavailable (no admin access
// or feature off) instead of a real failure, so collaborator repos stay quiet.
func detectErr(err error) DetectResult {
	if endpointUnavailable(err) {
		return DetectResult{Status: StatusSkipped, Detail: "unavailable (needs admin access, or feature is off)"}
	}
	return DetectResult{Status: StatusError, Detail: err.Error()}
}

type workflowPermissionPrior struct {
	Default    string `json:"default_workflow_permissions"`
	CanApprove *bool  `json:"can_approve_pull_request_reviews,omitempty"`
}

func parseWorkflowPermissionPrior(prior string) workflowPermissionPrior {
	var out workflowPermissionPrior
	if json.Unmarshal([]byte(prior), &out) == nil && out.Default != "" {
		return out
	}
	return workflowPermissionPrior{Default: prior}
}

type actionsAllowlistPrior struct {
	Enabled            *bool    `json:"enabled,omitempty"`
	AllowedActions     string   `json:"allowed_actions"`
	GithubOwnedAllowed *bool    `json:"github_owned_allowed,omitempty"`
	VerifiedAllowed    *bool    `json:"verified_allowed,omitempty"`
	PatternsAllowed    []string `json:"patterns_allowed,omitempty"`
}

func parseActionsAllowlistPrior(prior string) actionsAllowlistPrior {
	var out actionsAllowlistPrior
	if json.Unmarshal([]byte(prior), &out) == nil && out.AllowedActions != "" {
		return out
	}
	return actionsAllowlistPrior{AllowedActions: prior}
}

type secretScanningPrior struct {
	SecretScanning string `json:"secret_scanning"`
	PushProtection string `json:"push_protection"`
}

func parseSecretScanningPrior(prior string) secretScanningPrior {
	var out secretScanningPrior
	if json.Unmarshal([]byte(prior), &out) == nil && (out.SecretScanning != "" || out.PushProtection != "") {
		return out
	}
	if prior == "enabled" {
		return secretScanningPrior{SecretScanning: "enabled", PushProtection: "enabled"}
	}
	return secretScanningPrior{SecretScanning: "disabled", PushProtection: "disabled"}
}

func githubStatusOrDisabled(status string) string {
	if status == "" {
		return "disabled"
	}
	return status
}

func validateControlPrior(control, prior string) error {
	enabledDisabled := func(value string) error {
		switch value {
		case "enabled", "disabled":
			return nil
		default:
			return fmt.Errorf("invalid prior value %q", value)
		}
	}

	switch control {
	case "dependabot-alerts", "dependabot-fixes", "private-vulnerability-reporting":
		return enabledDisabled(prior)
	case "token-readonly":
		var value workflowPermissionPrior
		if err := json.Unmarshal([]byte(prior), &value); err != nil {
			return fmt.Errorf("invalid workflow permission prior: %w", err)
		}
		if value.Default != "read" && value.Default != "write" {
			return fmt.Errorf("invalid default workflow permission %q", value.Default)
		}
		return nil
	case "actions-allowlist":
		var value actionsAllowlistPrior
		if err := json.Unmarshal([]byte(prior), &value); err != nil {
			return fmt.Errorf("invalid Actions allowlist prior: %w", err)
		}
		switch value.AllowedActions {
		case "all", "local_only", "selected":
			return nil
		default:
			return fmt.Errorf("invalid allowed_actions value %q", value.AllowedActions)
		}
	case "branch-protection":
		if prior == "" {
			return nil
		}
		var value github.RepositoryRuleset
		if err := json.Unmarshal([]byte(prior), &value); err != nil {
			return fmt.Errorf("invalid ruleset prior: %w", err)
		}
		if value.Name != controlRulesetName {
			return fmt.Errorf("ruleset prior has unexpected name %q", value.Name)
		}
		return nil
	case "secret-scanning":
		var value secretScanningPrior
		if err := json.Unmarshal([]byte(prior), &value); err != nil {
			return fmt.Errorf("invalid secret scanning prior: %w", err)
		}
		if err := enabledDisabled(value.SecretScanning); err != nil {
			return fmt.Errorf("secret scanning: %w", err)
		}
		if err := enabledDisabled(value.PushProtection); err != nil {
			return fmt.Errorf("push protection: %w", err)
		}
		return nil
	case "code-scanning":
		switch prior {
		case "configured", "not-configured":
			return nil
		default:
			return fmt.Errorf("invalid CodeQL prior %q", prior)
		}
	default:
		return fmt.Errorf("control %q has no prior validator", control)
	}
}

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
			if prior == "enabled" { // was already on, didn't touch it
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
				if p == nil { // empty 200 body leaves p nil; raw field reads below would panic
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
		Title:       "Actions selected-policy allows GitHub-owned + verified",
		Severity:    "high",
		Remediation: "Restrict Actions to selected actions and allow GitHub-owned plus verified marketplace actions.",
		Detect: func(ctx context.Context, c *github.Client, owner, name string, _ *github.Repository) DetectResult {
			p, _, err := c.Repositories.GetActionsPermissions(ctx, owner, name)
			if err != nil {
				return detectErr(err)
			}
			if p == nil || p.Enabled == nil {
				return DetectResult{Status: StatusSkipped, Detail: "Actions enabled setting is not visible"}
			}
			if !p.GetEnabled() {
				// actions are off for this repo, don't silently turn them on.
				return DetectResult{Status: StatusSkipped, Detail: "Actions disabled for this repository"}
			}
			if p.GetAllowedActions() == "" {
				return DetectResult{Status: StatusError, Detail: "Actions allowed_actions field is missing"}
			}
			prior := actionsAllowlistPrior{Enabled: p.Enabled, AllowedActions: p.GetAllowedActions()}
			if p.GetAllowedActions() != "selected" {
				return DetectResult{Status: StatusGap, Prior: encodePrior(prior)}
			}
			allowed, _, err := c.Repositories.GetActionsAllowed(ctx, owner, name)
			if err != nil {
				return detectErr(err)
			}
			if allowed == nil { // empty 200 body; raw field reads below would panic
				return DetectResult{Status: StatusError, Detail: "empty actions-allowed response"}
			}
			prior.GithubOwnedAllowed = allowed.GithubOwnedAllowed
			prior.VerifiedAllowed = allowed.VerifiedAllowed
			prior.PatternsAllowed = allowed.PatternsAllowed
			if allowed.GetGithubOwnedAllowed() && allowed.GetVerifiedAllowed() && len(allowed.PatternsAllowed) == 0 {
				return DetectResult{Status: StatusCompliant, Prior: encodePrior(prior)}
			}
			if len(allowed.PatternsAllowed) > 0 {
				return DetectResult{Status: StatusGap, Prior: encodePrior(prior), Detail: "extra allowlist patterns widen beyond GitHub-owned + verified: " + strings.Join(allowed.PatternsAllowed, ", ")}
			}
			return DetectResult{Status: StatusGap, Prior: encodePrior(prior)}
		},
		Apply: func(ctx context.Context, c *github.Client, owner, name string) error {
			if _, _, err := c.Repositories.UpdateActionsPermissions(ctx, owner, name,
				github.ActionsPermissionsRepository{
					Enabled:        github.Ptr(true),
					AllowedActions: github.Ptr("selected"),
				}); err != nil {
				return err
			}
			_, _, err := c.Repositories.EditActionsAllowed(ctx, owner, name,
				github.ActionsAllowed{
					GithubOwnedAllowed: github.Ptr(true),
					VerifiedAllowed:    github.Ptr(true),
				})
			return err
		},
		Revert: func(ctx context.Context, c *github.Client, owner, name, prior string) error {
			p := parseActionsAllowlistPrior(prior)
			if p.AllowedActions == "" {
				return nil
			}
			_, _, err := c.Repositories.UpdateActionsPermissions(ctx, owner, name,
				github.ActionsPermissionsRepository{
					Enabled:        github.Ptr(p.Enabled == nil || *p.Enabled),
					AllowedActions: github.Ptr(p.AllowedActions),
				})
			if err != nil || p.AllowedActions != "selected" {
				return err
			}
			_, _, err = c.Repositories.EditActionsAllowed(ctx, owner, name,
				github.ActionsAllowed{
					GithubOwnedAllowed: p.GithubOwnedAllowed,
					VerifiedAllowed:    p.VerifiedAllowed,
					PatternsAllowed:    p.PatternsAllowed,
				})
			return err
		},
	})
}

func init() {
	baseline = append(baseline, Control{
		Key:         "branch-protection",
		Title:       "Managed default-branch ruleset present",
		Severity:    "high",
		Remediation: "Protect the default branch with PR review, non-fast-forward protection, and linear history.",
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
				if full == nil { // can't safely capture/replace a ruleset we couldn't read
					return DetectResult{Status: StatusError, Detail: "could not read existing ruleset named " + controlRulesetName}
				}
				if managedRulesetValid(full, repo.GetDefaultBranch()) {
					return DetectResult{Status: StatusCompliant}
				}
				// there but not a valid managed ruleset (could be the user's own). grab it
				// so revert can put it back after harden replaces it.
				return DetectResult{Status: StatusGap, Prior: encodePrior(full), Detail: "ruleset named " + controlRulesetName + " is incomplete or inactive"}
			}
			return DetectResult{Status: StatusGap, Detail: "managed ruleset missing"}
		},
		Apply: func(ctx context.Context, c *github.Client, owner, name string) error {
			spec := github.RepositoryRuleset{
				Name:        controlRulesetName,
				Source:      owner + "/" + name,
				SourceType:  github.Ptr(github.RulesetSourceTypeRepository),
				Target:      github.Ptr(github.RulesetTargetBranch),
				Enforcement: github.RulesetEnforcementActive,
				Conditions: &github.RepositoryRulesetConditions{
					RefName: &github.RepositoryRulesetRefConditionParameters{
						Include: []string{"~DEFAULT_BRANCH"},
						Exclude: []string{},
					},
				},
				Rules: &github.RepositoryRulesetRules{
					PullRequest:           &github.PullRequestRuleParameters{RequiredApprovingReviewCount: 1, RequiredReviewThreadResolution: true},
					NonFastForward:        &github.EmptyRuleParameters{},
					RequiredLinearHistory: &github.EmptyRuleParameters{},
				},
			}
			// if a same-name ruleset exists, update in place (no delete/create gap),
			// otherwise create it. detect already grabbed the prior for revert.
			sets, err := allRepoRulesets(ctx, c, owner, name, false)
			if err != nil {
				return fmt.Errorf("confirm existing managed ruleset before mutation: %w", err)
			}
			for _, rs := range sets {
				if rs.Name == controlRulesetName {
					_, _, err := c.Repositories.UpdateRuleset(ctx, owner, name, rs.GetID(), spec)
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
				return nil // nothing of ours to undo
			}
			// if harden replaced an existing same-name ruleset, put it back; else delete ours.
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
				// default setup is off, but an advanced/workflow CodeQL setup might already
				// scan the default branch. only count it compliant if there's a recent analysis,
				// since turning on default setup would break a real advanced setup.
				ref := "refs/heads/" + repo.GetDefaultBranch()
				analyses, _, aerr := c.CodeScanning.ListAnalysesForRepo(ctx, owner, name,
					&github.AnalysesListOptions{Ref: github.Ptr(ref), ListOptions: github.ListOptions{PerPage: 1}})
				if aerr != nil {
					return detectErr(aerr)
				}
				if len(analyses) > 0 {
					if time.Since(analyses[0].GetCreatedAt().Time) < codeScanningFreshness {
						return DetectResult{Status: StatusCompliant, Detail: "recent code scanning analysis on default branch (advanced/workflow setup)"}
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
			MatchesHardened: func(result DetectResult) bool {
				return result.Status == StatusCompliant && result.Prior == "configured"
			},
		},
	)
}

// fileExists returns true if any of the paths exist. non-404 errors bubble up.
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

// cmdControls lists the baseline controls and whether they're auto-fixable/revertable.
func cmdControls(o *opts) error {
	fmt.Println(colorize(o, colorGo, "repo-harden baseline controls"))
	keyWidth := len("KEY")
	for _, ctl := range baseline {
		if len(ctl.Key) > keyWidth {
			keyWidth = len(ctl.Key)
		}
	}
	fmt.Printf("%-*s  %-9s %-12s %s\n", keyWidth, "KEY", "SEVERITY", "ACTION", "REVERSIBLE")
	for _, ctl := range baseline {
		action := "report-only"
		if ctl.Apply != nil {
			action = "auto-fix"
		}
		reversible := "no"
		if ctl.Revert != nil {
			reversible = "yes"
		}
		fmt.Printf("%-*s  %-9s %-12s %s\n", keyWidth, ctl.Key, ctl.Severity, action, reversible)
	}
	fmt.Printf("\n%d baseline controls (harden/revert). audit additionally runs %d read-only checks.\n",
		len(baseline), len(auditControlKeys())-len(baseline))
	return nil
}

func splitSet(csv string) map[string]bool {
	m := map[string]bool{}
	for _, k := range strings.Split(csv, ",") {
		if k = strings.TrimSpace(k); k != "" {
			m[k] = true
		}
	}
	return m
}
