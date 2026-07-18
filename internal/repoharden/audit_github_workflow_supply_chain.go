package repoharden

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/google/go-github/v88/github"
)

// firstPartyActionOwners are exempt from SHA-pinning: flagging every
// actions/checkout@v4 would drown the signal from third-party actions.
var firstPartyActionOwners = map[string]bool{"actions": true, "github": true}

func auditGitHubWorkflowUnpinnedActions(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository, wc *workflowFileCache) auditRow {
	const (
		key   = "workflow-unpinned-actions"
		title = "Third-party actions pinned to commit SHAs"
		rem   = "Pin third-party actions to full commit SHAs (uses: owner/action@<40-hex> plus a version comment) so a moved tag cannot inject code into your builds."
	)
	files, err := wc.get(ctx, c, owner, name, repo.GetDefaultBranch())
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, key, title, "medium", StatusSkipped, "workflows not readable", rem)
		}
		return githubAuditRow(repo, key, title, "medium", StatusError, err.Error(), rem)
	}
	if len(files) == 0 {
		return githubAuditRow(repo, key, title, "medium", StatusCompliant, "no Actions workflows", rem)
	}
	var findings []string
	for fname, content := range files {
		w, err := parseWorkflow(content)
		if err != nil {
			findings = append(findings, fname+" (unparseable)")
			continue
		}
		if refs := workflowUnpinnedUses(w); len(refs) > 0 {
			findings = append(findings, fname+" ("+strings.Join(limitStrings(refs, maxDetailItems), ", ")+")")
		}
	}
	if len(findings) > 0 {
		sort.Strings(findings)
		return githubAuditRow(repo, key, title, "medium", StatusGap, "third-party actions not SHA-pinned: "+strings.Join(limitStrings(findings, maxDetailItems), ", "), rem)
	}
	return githubAuditRow(repo, key, title, "medium", StatusCompliant, fmt.Sprintf("no unpinned third-party actions across %d workflow(s)", len(files)), rem)
}

// workflowUnpinnedUses returns third-party `uses:` references (steps and
// reusable-workflow jobs) that are not pinned to a commit SHA or image digest.
func workflowUnpinnedUses(w *parsedWorkflow) []string {
	seen := map[string]bool{}
	var out []string
	add := func(ref string) {
		if r := unpinnedActionRef(ref); r != "" && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	for _, job := range w.Jobs {
		add(job.Uses)
		for _, step := range job.Steps {
			add(step.Uses)
		}
	}
	sort.Strings(out)
	return out
}

// unpinnedActionRef returns ref when it is a third-party action reference not
// pinned to a full commit SHA (or docker digest); "" when pinned or exempt.
func unpinnedActionRef(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "./") {
		return "" // local actions ship with the commit under test
	}
	if rest, ok := strings.CutPrefix(ref, "docker://"); ok {
		if validDockerDigestReference(rest) {
			return ""
		}
		return ref
	}
	actionOwner, _, found := strings.Cut(ref, "/")
	if !found {
		return "" // not a remote action reference
	}
	if firstPartyActionOwners[strings.ToLower(actionOwner)] {
		return ""
	}
	at := strings.LastIndex(ref, "@")
	if at < 0 {
		return ref // floating default branch
	}
	if isCommitSHA(ref[at+1:]) {
		return ""
	}
	return ref
}

var dockerDigestReferencePattern = regexp.MustCompile(`^[^@\s]+@sha256:[0-9a-fA-F]{64}$`)

func validDockerDigestReference(ref string) bool {
	return dockerDigestReferencePattern.MatchString(strings.TrimSpace(ref))
}

func isCommitSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func auditGitHubWorkflowPwnRequest(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository, wc *workflowFileCache) auditRow {
	const (
		key   = "workflow-pwn-request"
		title = "No privileged checkout of untrusted PR code"
		rem   = "Do not check out attacker-controlled PR code in privileged pull_request_target/workflow_run workflows; use the pull_request trigger, or keep untrusted code away from secrets."
	)
	files, err := wc.get(ctx, c, owner, name, repo.GetDefaultBranch())
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, key, title, "high", StatusSkipped, "workflows not readable", rem)
		}
		return githubAuditRow(repo, key, title, "high", StatusError, err.Error(), rem)
	}
	if len(files) == 0 {
		return githubAuditRow(repo, key, title, "high", StatusCompliant, "no Actions workflows", rem)
	}
	var findings []string
	for fname, content := range files {
		w, err := parseWorkflow(content)
		if err != nil {
			findings = append(findings, fname+" (unparseable)")
			continue
		}
		for _, job := range workflowPwnRequestJobs(w) {
			findings = append(findings, fname+" ("+job+")")
		}
	}
	if len(findings) > 0 {
		sort.Strings(findings)
		return githubAuditRow(repo, key, title, "high", StatusGap, "privileged workflows check out untrusted PR code: "+strings.Join(limitStrings(findings, maxDetailItems), ", "), rem)
	}
	return githubAuditRow(repo, key, title, "high", StatusCompliant, "no privileged checkouts of untrusted code", rem)
}

// workflowPwnRequestJobs returns jobs that combine a privileged trigger
// (pull_request_target, workflow_run) with a checkout of attacker-controlled code.
func workflowPwnRequestJobs(w *parsedWorkflow) []string {
	triggers := workflowTriggers(w.On)
	if !triggers["pull_request_target"] && !triggers["workflow_run"] {
		return nil
	}
	var out []string
	for jobName, job := range w.Jobs {
		for _, step := range job.Steps {
			if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(step.Uses)), "actions/checkout") {
				continue
			}
			ref, _ := step.With["ref"].(string)
			repository, _ := step.With["repository"].(string)
			if untrustedCheckoutRef(ref) || untrustedCheckoutRepository(repository) {
				out = append(out, jobName)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// untrustedCheckoutRef reports whether a checkout ref resolves to attacker-controlled code.
func untrustedCheckoutRef(ref string) bool {
	for _, marker := range []string{
		"github.event.pull_request.head",
		"github.event.pull_request.merge_commit_sha",
		"github.head_ref",
		"github.event.pull_request.number",
		"github.event.number",
		"github.event.workflow_run.head",
		"refs/pull/",
	} {
		if strings.Contains(ref, marker) {
			return true
		}
	}
	return false
}

// untrustedCheckoutRepository reports whether a checkout repository: input points at the PR's (attacker-owned) fork.
func untrustedCheckoutRepository(repository string) bool {
	for _, marker := range []string{
		"github.event.pull_request.head.repo",
		"github.event.workflow_run.head_repository",
	} {
		if strings.Contains(repository, marker) {
			return true
		}
	}
	return false
}

var workflowExprPattern = regexp.MustCompile(`(?s)\$\{\{(.*?)\}\}`)

// injectionContexts is a curated list of event fields writable by outsiders.
var injectionContexts = []string{
	"github.event.issue.title", "github.event.issue.body",
	"github.event.pull_request.title", "github.event.pull_request.body",
	"github.event.comment.body", "github.event.review.body", "github.event.review_comment.body",
	"github.event.discussion.title", "github.event.discussion.body",
	"github.event.head_commit.message", "github.event.head_commit.author",
	"github.event.commits",
	"github.event.pull_request.head.ref", "github.event.pull_request.head.label",
	"github.head_ref",
	"github.event.workflow_run.head_branch", "github.event.workflow_run.display_title",
	"github.event.workflow_run.head_commit.message", "github.event.workflow_run.head_commit.author",
}

func auditGitHubWorkflowInjection(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository, wc *workflowFileCache) auditRow {
	const (
		key   = "workflow-injection"
		title = "No attacker-controlled expressions in run scripts"
		rem   = "Pass untrusted event fields into scripts via env: variables (\"$VAR\") instead of interpolating ${{ … }} directly into run: or github-script bodies."
	)
	files, err := wc.get(ctx, c, owner, name, repo.GetDefaultBranch())
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, key, title, "high", StatusSkipped, "workflows not readable", rem)
		}
		return githubAuditRow(repo, key, title, "high", StatusError, err.Error(), rem)
	}
	if len(files) == 0 {
		return githubAuditRow(repo, key, title, "high", StatusCompliant, "no Actions workflows", rem)
	}
	var findings []string
	for fname, content := range files {
		w, err := parseWorkflow(content)
		if err != nil {
			findings = append(findings, fname+" (unparseable)")
			continue
		}
		if hits := workflowInjectionContexts(w); len(hits) > 0 {
			findings = append(findings, fname+" ("+strings.Join(limitStrings(hits, maxDetailItems), ", ")+")")
		}
	}
	if len(findings) > 0 {
		sort.Strings(findings)
		return githubAuditRow(repo, key, title, "high", StatusGap, "attacker-controlled expressions in scripts: "+strings.Join(limitStrings(findings, maxDetailItems), ", "), rem)
	}
	return githubAuditRow(repo, key, title, "high", StatusCompliant, "no attacker-controlled expressions in run scripts", rem)
}

// workflowInjectionContexts returns the attacker-controlled contexts a
// workflow interpolates into run: scripts or actions/github-script bodies.
func workflowInjectionContexts(w *parsedWorkflow) []string {
	seen := map[string]bool{}
	var out []string
	scan := func(script string) {
		if script == "" {
			return
		}
		for _, match := range workflowExprPattern.FindAllStringSubmatch(script, -1) {
			for _, ctx := range injectionContexts {
				if strings.Contains(match[1], ctx) && !seen[ctx] {
					seen[ctx] = true
					out = append(out, ctx)
				}
			}
		}
	}
	for _, job := range w.Jobs {
		for _, step := range job.Steps {
			scan(step.Run)
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(step.Uses)), "actions/github-script") {
				if script, ok := step.With["script"].(string); ok {
					scan(script)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}
