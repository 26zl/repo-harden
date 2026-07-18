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

// DetectResult records a control's status, prior value, and detail for one repository.
type DetectResult struct {
	Status ControlStatus
	Prior  string
	Detail string
}

// Control defines a baseline check and its optional apply and revert operations.
type Control struct {
	Key           string
	Title         string
	Severity      string
	Remediation   string
	Detect        func(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) DetectResult
	Apply         func(ctx context.Context, c *github.Client, owner, name string) error
	Revert        func(ctx context.Context, c *github.Client, owner, name, prior string) error
	ValidatePrior func(prior string) error
	// MatchesHardened limits revert to the exact configuration derived from the captured prior, so revert never overwrites later drift.
	MatchesHardened func(result DetectResult, prior string) bool
}

var baseline []Control

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
	SHAPinningRequired *bool    `json:"sha_pinning_required,omitempty"`
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

type actionsAllowedRequest struct {
	GithubOwnedAllowed *bool    `json:"github_owned_allowed,omitempty"`
	VerifiedAllowed    *bool    `json:"verified_allowed,omitempty"`
	PatternsAllowed    []string `json:"patterns_allowed"`
}

// editActionsAllowedExact always sends patterns_allowed (go-github's omitempty drops empty slices, which cannot clear existing patterns).
func editActionsAllowedExact(ctx context.Context, c *github.Client, owner, name string, req actionsAllowedRequest) error {
	if req.PatternsAllowed == nil {
		req.PatternsAllowed = []string{}
	}
	httpReq, err := c.NewRequest(ctx, http.MethodPut, fmt.Sprintf("repos/%v/%v/actions/permissions/selected-actions", owner, name), req)
	if err != nil {
		return err
	}
	_, err = c.Do(httpReq, nil)
	return err
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
