package repoharden

import (
	"errors"
	"fmt"
	"strings"
)

func validateCommandInvocation(cmd string, args []string, o *opts) error {
	switch cmd {
	case "disable-repo", "enable-repo":
		if len(args) != 1 {
			if misplaced := firstFlagLikeArg(args); misplaced != "" {
				return fmt.Errorf("flag %q must come before the <owner/repo> argument", misplaced)
			}
			return fmt.Errorf("usage: repo-harden %s <owner/repo>", cmd)
		}
		if err := validateRepoSlug(args[0]); err != nil {
			return err
		}
		if o.repo != "" {
			return fmt.Errorf("%s takes a positional <owner/repo>, not --repo", cmd)
		}
	default:
		if len(args) > 0 {
			if misplaced := firstFlagLikeArg(args); misplaced != "" {
				return fmt.Errorf("flag %q must come before positional arguments", misplaced)
			}
			return fmt.Errorf("%s does not accept positional arguments", cmd)
		}
	}
	if o.failOnSkipped && cmd != "audit" {
		return errors.New("--fail-on-skipped is only supported by audit")
	}
	if failBelowEnabled(o) && cmd != "audit" {
		return errors.New("--fail-below is only supported by audit")
	}
	if o.diffBaseline != "" && cmd != "audit" {
		return errors.New("--diff is only supported by audit")
	}
	if o.formatSet && cmd != "audit" {
		return errors.New("--format is only supported by audit")
	}
	if o.exitCode && cmd != "audit" {
		return errors.New("--exit-code is only supported by audit")
	}
	if o.all && cmd != "audit" {
		return errors.New("--all is only supported by audit")
	}
	if o.showIdentifiers && cmd != "audit" {
		return errors.New("--show-identifiers is only supported by audit")
	}
	if o.orgAuditSet && cmd != "audit" {
		return errors.New("--org-audit is only supported by audit")
	}
	if o.staleDaysSet && cmd != "audit" {
		return errors.New("--stale-days is only supported by audit")
	}
	if o.stateFile != "" {
		switch cmd {
		case "harden", "revert", "disable-all", "enable-all":
		default:
			return errors.New("--state-file is only supported by harden, revert, disable-all, and enable-all")
		}
	}
	if o.jsonOut && cmd != "audit" && cmd != "list" && cmd != "status" {
		return errors.New("--json is only supported by list, status, and audit")
	}
	// Validate selections and --repo slugs before any token or network work.
	switch cmd {
	case "audit":
		if err := validateAuditSelectionForProvider(o.provider, o.only, o.skip); err != nil {
			return err
		}
	case "harden", "revert":
		if err := validateControlSelection(o.only, o.skip); err != nil {
			return err
		}
	default:
		if o.only != "" || o.skip != "" {
			return errors.New("--only/--skip are only supported by audit, harden, and revert")
		}
	}
	if o.repo != "" && o.provider == "github" {
		if _, err := requestedRepoSet(o.repo); err != nil {
			return err
		}
	}
	return nil
}

func firstFlagLikeArg(args []string) string {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && arg != "-" {
			return arg
		}
	}
	return ""
}

func normalizeOptions(o *opts) {
	o.provider = strings.ToLower(strings.TrimSpace(o.provider))
	if o.provider == "" {
		o.provider = "github"
	}
	if o.host == "" {
		o.host = defaultProviderHost(o.provider)
	}
	o.format = strings.ToLower(strings.TrimSpace(o.format))
	o.formatSet = o.format != ""
	if o.jsonOut && !o.formatSet {
		o.format = "json"
	}
	if o.format == "" {
		o.format = "table"
	}
}

func validateOptions(o *opts) error {
	switch o.provider {
	case "github", "gitlab", "gitea", "forgejo", "bitbucket":
	default:
		return fmt.Errorf("invalid --provider %q (expected github, gitlab, gitea, forgejo, or bitbucket)", o.provider)
	}
	switch o.format {
	case "table", "json", "markdown", "sarif", "badge":
	default:
		return fmt.Errorf("invalid --format %q (expected table, json, markdown, sarif, or badge)", o.format)
	}
	if o.jsonOut && o.formatSet && o.format != "json" {
		return fmt.Errorf("--json conflicts with --format %s", o.format)
	}
	if failBelowEnabled(o) && (o.failBelow < 1 || o.failBelow > 100) {
		return fmt.Errorf("--fail-below must be between 1 and 100")
	}
	if o.staleDays < 1 {
		return fmt.Errorf("--stale-days must be >= 1")
	}
	if o.staleDays > 36500 {
		return fmt.Errorf("--stale-days must be <= 36500")
	}
	if o.concurrency < 1 {
		return fmt.Errorf("--concurrency must be >= 1")
	}
	if o.concurrency > maxConcurrency {
		return fmt.Errorf("--concurrency must be <= %d", maxConcurrency)
	}
	if o.repo != "" && o.provider != "github" {
		return fmt.Errorf("--repo is only supported with --provider github")
	}
	return nil
}

func failBelowEnabled(o *opts) bool {
	return o != nil && (o.failBelowSet || o.failBelow != 0)
}
