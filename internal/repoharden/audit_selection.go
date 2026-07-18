package repoharden

import (
	"fmt"
	"sort"
	"strings"
)

func auditControlKeys() map[string]bool {
	keys := map[string]bool{}
	for _, ctl := range baseline {
		keys[ctl.Key] = true
	}
	for _, key := range []string{
		"actions-fork-pr-permissions",
		"archived-active-risk",
		"branch-protection-full",
		"code-scanning-alert-count",
		"collaborators",
		"default-branch",
		"dependency-sbom",
		"repository-license",
		"merge-hygiene",
		"dependabot-open-alerts",
		"ruleset-bypass",
		"open-security-advisories",
		"workflow-access-level",
		"actions-sha-pinning",
		"community-health",
		"code-scanning-conflict",
		"ruleset-evaluate-only",
		"workflow-token-permissions",
		"workflow-unpinned-actions",
		"workflow-pwn-request",
		"workflow-injection",
		"oidc-cloud-trust",
		"dependency-review",
		"release-provenance",
		"self-hosted-runners",
		"merge-queue",
		"tag-protection",
		"push-ruleset",
		"org-runner-groups",
		"pipeline-supply-chain",
		"no-merge-method",
		"fork-policy",
		"wiki-attack-surface",
		"org-outside-collaborators",
		"account-2fa",
		"dependabot-config",
		"org-2fa-disabled-members",
		"deploy-keys",
		"environment-protection",
		"org-actions-policy",
		"org-base-permission",
		"org-2fa",
		"org-secrets",
		"org-token-policy",
		"org-webhooks",
		"packages",
		"public-exposure",
		"releases",
		"repo-secrets",
		"required-workflows",
		"secret-scanning-alert-count",
		"signed-commits",
		"stale-repo",
		"token-scopes",
		"vulnerability-alert-count",
		"webhooks",
	} {
		keys[key] = true
	}
	return keys
}

func validateAuditSelection(only, skip string) error {
	known := auditControlKeys()
	for flag, set := range map[string]map[string]bool{"--only": splitSet(only), "--skip": splitSet(skip)} {
		var unknown []string
		for key := range set {
			if !known[key] {
				unknown = append(unknown, key)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			return fmt.Errorf("%s contains unknown audit control(s): %s", flag, strings.Join(unknown, ", "))
		}
	}
	return nil
}

func providerAuditControlKeys(provider string) map[string]bool {
	if provider == "github" {
		return auditControlKeys()
	}
	keys := map[string]bool{}
	switch provider {
	case "gitlab":
		keys["pipeline-supply-chain"] = true
	case "gitea", "forgejo":
		keys["workflow-unpinned-actions"] = true
		keys["workflow-pwn-request"] = true
		keys["workflow-injection"] = true
	}
	for _, key := range []string{
		"token-scopes",
		"public-exposure",
		"stale-repo",
		"default-branch",
		"branch-protection-full",
		"signed-commits",
		"required-workflows",
		"environment-protection",
		"repo-secrets",
		"deploy-keys",
		"webhooks",
		"collaborators",
		"vulnerability-alert-count",
		"releases",
		"packages",
		"dependency-sbom",
		"repository-license",
		"archived-active-risk",
	} {
		keys[key] = true
	}
	return keys
}

func validateAuditSelectionForProvider(provider, only, skip string) error {
	if err := validateAuditSelection(only, skip); err != nil {
		return err
	}
	supported := providerAuditControlKeys(provider)
	for flag, values := range map[string]map[string]bool{"--only": splitSet(only), "--skip": splitSet(skip)} {
		var unavailable []string
		for key := range values {
			if !supported[key] {
				unavailable = append(unavailable, key)
			}
		}
		if len(unavailable) > 0 {
			sort.Strings(unavailable)
			return fmt.Errorf("%s contains control(s) unsupported by provider %s: %s",
				flag, provider, strings.Join(unavailable, ", "))
		}
	}
	selected := 0
	onlySet := splitSet(only)
	skipSet := splitSet(skip)
	for key := range supported {
		if len(onlySet) > 0 && !onlySet[key] {
			continue
		}
		if !skipSet[key] {
			selected++
		}
	}
	if selected == 0 {
		return fmt.Errorf("no audit controls selected for provider %s", provider)
	}
	return nil
}

func auditScoreAvailable(rows []auditRow) bool {
	for _, row := range rows {
		if ControlStatus(row.Status) != StatusSkipped {
			return true
		}
	}
	return false
}

// auditVerification reports severity-weighted coverage of definitive audit results.
func auditVerification(rows []auditRow) int {
	total := 0
	verified := 0
	for _, row := range rows {
		weight := auditWeight(row)
		total += weight
		switch ControlStatus(row.Status) {
		case StatusCompliant, StatusGap:
			verified += weight
		}
	}
	if total == 0 {
		return 0
	}
	return verified * 100 / total
}
