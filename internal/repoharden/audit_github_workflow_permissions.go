package repoharden

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/google/go-github/v88/github"
)

func auditGitHubWorkflowTokenPermissions(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository, wc *workflowFileCache) auditRow {
	const (
		key   = "workflow-token-permissions"
		title = "Workflows set least-privilege GITHUB_TOKEN permissions"
		rem   = "Default each workflow to `permissions: contents: read` (or `none`) and grant only the named write scopes required by each individual job; never use `write-all`."
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
	var weak []string
	for fname, content := range files {
		if issue := workflowPermissionIssue(content); issue != "" {
			weak = append(weak, fname+" ("+issue+")")
		}
	}
	if len(weak) > 0 {
		sort.Strings(weak)
		return githubAuditRow(repo, key, title, "high", StatusGap, "workflows without least-privilege token permissions: "+strings.Join(limitStrings(weak, maxDetailItems), ", "), rem)
	}
	return githubAuditRow(repo, key, title, "high", StatusCompliant, fmt.Sprintf("all %d workflow(s) declare explicit token permissions", len(files)), rem)
}

func workflowPermissionIssue(content string) string {
	workflow, err := parseWorkflow(content)
	if err != nil {
		return "unparseable"
	}
	if workflow.Permissions != nil {
		if issue := permTooBroad(workflow.Permissions); issue != "" {
			return issue
		}
		if writes := permissionWriteScopes(workflow.Permissions); len(writes) > 0 {
			return "top-level write permissions must be job-scoped: " + strings.Join(writes, ", ")
		}
	}
	if len(workflow.Jobs) == 0 {
		return "no explicit permissions"
	}
	jobNames := make([]string, 0, len(workflow.Jobs))
	for name := range workflow.Jobs {
		jobNames = append(jobNames, name)
	}
	sort.Strings(jobNames)
	for _, name := range jobNames {
		job := workflow.Jobs[name]
		if workflow.Permissions == nil && job.Permissions == nil {
			return "no explicit permissions"
		}
		if job.Permissions == nil {
			continue
		}
		if issue := permTooBroad(job.Permissions); issue != "" {
			return issue
		}
		if strings.TrimSpace(job.Uses) != "" {
			continue // reusable-workflow caller: the write scopes are exercised by the called workflow's steps
		}
		if writes := unjustifiedJobWriteScopes(job, permissionWriteScopes(job.Permissions)); len(writes) > 0 {
			return "job " + name + " has write permissions without a recognized need: " + strings.Join(writes, ", ")
		}
	}
	return ""
}

var workflowPermissionAccess = map[string]map[string]bool{
	"actions":         {"read": true, "write": true, "none": true},
	"attestations":    {"read": true, "write": true, "none": true},
	"checks":          {"read": true, "write": true, "none": true},
	"contents":        {"read": true, "write": true, "none": true},
	"deployments":     {"read": true, "write": true, "none": true},
	"discussions":     {"read": true, "write": true, "none": true},
	"id-token":        {"write": true, "none": true},
	"issues":          {"read": true, "write": true, "none": true},
	"models":          {"read": true, "none": true},
	"packages":        {"read": true, "write": true, "none": true},
	"pages":           {"read": true, "write": true, "none": true},
	"pull-requests":   {"read": true, "write": true, "none": true},
	"security-events": {"read": true, "write": true, "none": true},
	"statuses":        {"read": true, "write": true, "none": true},
}

func permTooBroad(permission any) string {
	switch value := permission.(type) {
	case string:
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "write-all":
			return "write-all token"
		case "read-all":
			return "read-all token"
		case "none":
			return ""
		default:
			return "invalid permissions value"
		}
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			raw := value[key]
			access, known := workflowPermissionAccess[strings.ToLower(strings.TrimSpace(key))]
			if !known {
				return "unknown permission scope: " + key
			}
			permissionValue, ok := raw.(string)
			if !ok {
				return "invalid permission value: " + key
			}
			if !access[strings.ToLower(strings.TrimSpace(permissionValue))] {
				return "invalid permission value: " + key
			}
		}
		return ""
	default:
		return "invalid permissions value"
	}
}

func permissionWriteScopes(permission any) []string {
	value, ok := permission.(map[string]any)
	if !ok {
		return nil
	}
	var scopes []string
	for key, raw := range value {
		permissionValue, ok := raw.(string)
		if ok && strings.EqualFold(strings.TrimSpace(permissionValue), "write") {
			scopes = append(scopes, strings.ToLower(strings.TrimSpace(key)))
		}
	}
	sort.Strings(scopes)
	return scopes
}

func unjustifiedJobWriteScopes(job workflowJob, scopes []string) []string {
	var unsupported []string
	for _, scope := range scopes {
		if !jobWriteScopeJustified(job, scope) {
			unsupported = append(unsupported, scope)
		}
	}
	return unsupported
}

func jobWriteScopeJustified(job workflowJob, scope string) bool {
	for _, step := range job.Steps {
		if conditionAlwaysFalse(step.If) {
			continue
		}
		if actionJustifiesWriteScope(step, scope) || runJustifiesWriteScope(step, scope) {
			return true
		}
	}
	return false
}

func actionJustifiesWriteScope(step workflowStep, scope string) bool {
	action := normalizedActionReference(step.Uses)
	if action == "" {
		return false
	}
	switch scope {
	case "attestations":
		return strings.HasPrefix(action, "actions/attest-")
	case "id-token":
		return strings.HasPrefix(action, "actions/attest-") || action == "actions/deploy-pages" || stepUsesCloudOIDC(step) ||
			(action == "pypa/gh-action-pypi-publish" && permissionStepInput(step, "password") == "")
	case "contents":
		switch action {
		case "actions/create-release", "actions/upload-release-asset", "softprops/action-gh-release",
			"ncipollo/release-action", "googleapis/release-please-action", "changesets/action":
			return true
		case "goreleaser/goreleaser-action":
			args := strings.ToLower(permissionStepInput(step, "args"))
			return strings.Contains(args, "release") && !strings.Contains(args, "snapshot") &&
				!strings.Contains(args, "--skip=publish") && !strings.Contains(args, "--skip publish")
		}
	case "security-events":
		return action == "github/codeql-action/analyze" || action == "github/codeql-action/upload-sarif"
	case "packages":
		switch action {
		case "docker/build-push-action":
			return strings.EqualFold(permissionStepInput(step, "push"), "true")
		case "redhat-actions/push-to-registry", "pypa/gh-action-pypi-publish":
			return true
		}
	case "pages":
		return action == "actions/deploy-pages"
	case "pull-requests":
		switch action {
		case "peter-evans/create-pull-request", "googleapis/release-please-action", "changesets/action", "actions/stale":
			return true
		case "actions/dependency-review-action":
			mode := strings.ToLower(permissionStepInput(step, "comment-summary-in-pr"))
			return mode == "always" || mode == "on-failure"
		}
	case "issues":
		return action == "actions/stale" || action == "peter-evans/create-or-update-comment"
	case "checks":
		return action == "mikepenz/action-junit-report" || action == "dorny/test-reporter" ||
			action == "louisbrunner/checks-action"
	case "statuses":
		return action == "myrotvorets/set-commit-status-action" || action == "sibz/github-status-action"
	case "deployments":
		return action == "chrnorm/deployment-action" || action == "bobheadxi/deployments"
	case "actions":
		return action == "styfle/cancel-workflow-action" || action == "potiuk/cancel-workflow-runs"
	}
	return false
}

func normalizedActionReference(ref string) string {
	ref = strings.ToLower(strings.TrimSpace(ref))
	if ref == "" || strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") {
		return ""
	}
	if at := strings.LastIndex(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	return ref
}

func permissionStepInput(step workflowStep, key string) string {
	for inputKey, value := range step.With {
		if !strings.EqualFold(strings.TrimSpace(inputKey), key) || value == nil {
			continue
		}
		return strings.TrimSpace(fmt.Sprint(value))
	}
	return ""
}

var permissionRunIndicators = map[string][]*regexp.Regexp{
	"actions": {
		regexp.MustCompile(`(?im)^\s*gh\s+(?:run\s+(?:cancel|delete|rerun)|workflow\s+(?:disable|enable|run))\b`),
		regexp.MustCompile(`(?im)^\s*gh\s+api\b.*(?:--method\s+(?:POST|PUT|PATCH|DELETE)|-[Xx]\s*(?:POST|PUT|PATCH|DELETE)).*/actions/`),
	},
	"checks": {
		regexp.MustCompile(`(?im)^\s*gh\s+api\b.*(?:--method\s+(?:POST|PUT|PATCH)|-[Xx]\s*(?:POST|PUT|PATCH)).*/check-runs\b`),
	},
	"contents": {
		regexp.MustCompile(`(?im)^\s*(?:if\s+!\s+)?gh\s+release\s+(?:create|delete|edit|upload)\b`),
		regexp.MustCompile(`(?im)^\s*git\s+push\b`),
		regexp.MustCompile(`(?im)^\s*(?:goreleaser\s+release|semantic-release)\b`),
		regexp.MustCompile(`(?im)^\s*(?:if\s+!\s+)?gh\s+api\b.*(?:--method\s+(?:POST|PUT|PATCH|DELETE)|-[Xx]\s*(?:POST|PUT|PATCH|DELETE)).*/releases(?:/|\b)`),
	},
	"deployments": {
		regexp.MustCompile(`(?im)^\s*gh\s+api\b.*(?:--method\s+(?:POST|PUT|PATCH|DELETE)|-[Xx]\s*(?:POST|PUT|PATCH|DELETE)).*/deployments(?:/|\b)`),
	},
	"discussions": {
		regexp.MustCompile(`(?im)^\s*gh\s+api\s+graphql\b.*\b(?:create|update|delete)discussion\b`),
	},
	"id-token": {
		regexp.MustCompile(`(?im)^\s*(?:npm|pnpm)\s+publish\b.*--provenance\b`),
	},
	"issues": {
		regexp.MustCompile(`(?im)^\s*gh\s+issue\s+(?:close|comment|create|edit|reopen)\b`),
	},
	"packages": {
		regexp.MustCompile(`(?im)^\s*(?:npm|pnpm)\s+publish\b`),
		regexp.MustCompile(`(?im)^\s*yarn\s+npm\s+publish\b`),
		regexp.MustCompile(`(?im)^\s*docker\s+(?:buildx\s+)?push\b`),
		regexp.MustCompile(`(?im)^\s*(?:helm\s+push|twine\s+upload|cargo\s+publish|dotnet\s+nuget\s+push|mvn\s+deploy)\b`),
		regexp.MustCompile(`(?im)^\s*(?:\./)?gradlew\b.*\bpublish\b`),
	},
	"pull-requests": {
		regexp.MustCompile(`(?im)^\s*gh\s+pr\s+(?:close|comment|create|edit|merge|ready|reopen|review)\b`),
	},
	"security-events": {
		regexp.MustCompile(`(?im)^\s*gh\s+api\b.*(?:--method\s+(?:POST|PUT)|-[Xx]\s*(?:POST|PUT)).*/code-scanning/sarifs\b`),
	},
	"statuses": {
		regexp.MustCompile(`(?im)^\s*gh\s+api\b.*(?:--method\s+(?:POST|PUT)|-[Xx]\s*(?:POST|PUT)).*/statuses/`),
	},
}

var permissionGitHubScriptIndicators = map[string][]*regexp.Regexp{
	"actions": {
		regexp.MustCompile(`(?i)\bgithub\.rest\.actions\.(?:cancel|delete|disable|enable|reRun|runWorkflow)`),
	},
	"checks": {
		regexp.MustCompile(`(?i)\bgithub\.rest\.checks\.(?:create|update)`),
	},
	"contents": {
		regexp.MustCompile(`(?i)\bgithub\.rest\.repos\.(?:createRelease|deleteRelease|updateRelease|uploadReleaseAsset|createOrUpdateFileContents|deleteFile)`),
	},
	"deployments": {
		regexp.MustCompile(`(?i)\bgithub\.rest\.repos\.(?:createDeployment|createDeploymentStatus)`),
	},
	"discussions": {
		regexp.MustCompile(`(?i)\b(?:create|update|delete)discussion\b`),
	},
	"issues": {
		regexp.MustCompile(`(?i)\bgithub\.rest\.issues\.(?:addAssignees|addLabels|create|createComment|deleteComment|lock|removeLabel|setLabels|unlock|update|updateComment)`),
	},
	"packages": {
		regexp.MustCompile(`(?i)\bgithub\.rest\.packages\.deletePackageVersionFor`),
	},
	"pull-requests": {
		regexp.MustCompile(`(?i)\bgithub\.rest\.pulls\.(?:create|createReview|dismissReview|merge|requestReviewers|update|updateBranch)`),
	},
	"statuses": {
		regexp.MustCompile(`(?i)\bgithub\.rest\.repos\.createCommitStatus`),
	},
}

func runJustifiesWriteScope(step workflowStep, scope string) bool {
	run := strings.ReplaceAll(step.Run, "\\\r\n", " ")
	run = strings.ReplaceAll(run, "\\\n", " ")
	for _, pattern := range permissionRunIndicators[scope] {
		if pattern.MatchString(run) {
			return true
		}
	}
	if normalizedActionReference(step.Uses) == "actions/github-script" {
		script := permissionStepInput(step, "script")
		for _, pattern := range permissionGitHubScriptIndicators[scope] {
			if pattern.MatchString(script) {
				return true
			}
		}
	}
	return false
}
