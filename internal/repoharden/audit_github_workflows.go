package repoharden

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/google/go-github/v88/github"
	"gopkg.in/yaml.v3"
)

func auditGitHubCodeScanningConflict(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	const (
		key   = "code-scanning-conflict"
		title = "No conflicting code-scanning setups"
		rem   = "Use either CodeQL default setup OR an advanced workflow, not both — GitHub rejects advanced SARIF uploads when default setup is on."
	)
	cfg, _, err := c.CodeScanning.GetDefaultSetupConfiguration(ctx, owner, name)
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, key, title, "medium", StatusSkipped, "code scanning API unavailable", rem)
		}
		return githubAuditRow(repo, key, title, "medium", StatusError, err.Error(), rem)
	}
	if cfg.GetState() != "configured" {
		return githubAuditRow(repo, key, title, "medium", StatusCompliant, "default setup not enabled (no conflict possible)", rem)
	}
	uses, err := workflowsUsingCodeQL(ctx, c, owner, name, repo.GetDefaultBranch())
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, key, title, "medium", StatusSkipped, "default setup on; workflows not readable", rem)
		}
		return githubAuditRow(repo, key, title, "medium", StatusError, err.Error(), rem)
	}
	if len(uses) > 0 {
		return githubAuditRow(repo, key, title, "medium", StatusGap, "default setup on AND advanced workflow(s) run codeql-action: "+strings.Join(limitStrings(uses, maxDetailItems), ", ")+" (their SARIF uploads will be rejected)", rem)
	}
	return githubAuditRow(repo, key, title, "medium", StatusCompliant, "default setup on; no conflicting advanced workflow", rem)
}

func listWorkflowFiles(ctx context.Context, c *github.Client, owner, name, branch string) (map[string]string, error) {
	var opt *github.RepositoryContentGetOptions
	if branch != "" {
		opt = &github.RepositoryContentGetOptions{Ref: branch}
	}
	_, dir, _, err := c.Repositories.GetContents(ctx, owner, name, ".github/workflows", opt)
	if err != nil {
		if githubStatus(err) == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	out := map[string]string{}
	var readErrors []error
	for _, entry := range dir {
		if entry.GetType() != "file" {
			continue
		}
		lower := strings.ToLower(entry.GetName())
		if !strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".yaml") {
			continue
		}
		file, _, _, err := c.Repositories.GetContents(ctx, owner, name, entry.GetPath(), opt)
		if err != nil {
			readErrors = append(readErrors, fmt.Errorf("%s: %w", entry.GetName(), err))
			continue
		}
		if file == nil {
			readErrors = append(readErrors, fmt.Errorf("%s: empty file response", entry.GetName()))
			continue
		}
		content, err := file.GetContent()
		if err != nil {
			readErrors = append(readErrors, fmt.Errorf("%s: decode content: %w", entry.GetName(), err))
			continue
		}
		out[entry.GetName()] = content
	}
	if len(readErrors) > 0 {
		return nil, fmt.Errorf("could not read all workflow files: %w", errors.Join(readErrors...))
	}
	return out, nil
}

func workflowsUsingCodeQL(ctx context.Context, c *github.Client, owner, name, branch string) ([]string, error) {
	files, err := listWorkflowFiles(ctx, c, owner, name, branch)
	if err != nil {
		return nil, err
	}
	var found []string
	for fname, content := range files {
		uses, err := workflowUsesAction(content, "github/codeql-action/")
		if err != nil {
			return nil, fmt.Errorf("parse workflow %s: %w", fname, err)
		}
		if uses {
			found = append(found, fname)
		}
	}
	sort.Strings(found)
	return found, nil
}

func workflowUsesAction(content, actionPrefix string) (bool, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return false, err
	}
	var visit func(*yaml.Node) bool
	visit = func(node *yaml.Node) bool {
		if node.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(node.Content); i += 2 {
				key, value := node.Content[i], node.Content[i+1]
				if key.Value == "uses" && value.Kind == yaml.ScalarNode &&
					strings.HasPrefix(strings.ToLower(strings.TrimSpace(value.Value)), strings.ToLower(actionPrefix)) {
					return true
				}
				if visit(value) {
					return true
				}
			}
			return false
		}
		for _, child := range node.Content {
			if visit(child) {
				return true
			}
		}
		return false
	}
	return visit(&root), nil
}

func auditGitHubWorkflowTokenPermissions(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	const (
		key   = "workflow-token-permissions"
		title = "Workflows set least-privilege GITHUB_TOKEN permissions"
		rem   = "Add a top-level `permissions:` block (e.g. `contents: read`) to each workflow so GITHUB_TOKEN is least-privilege, not the broad default."
	)
	files, err := listWorkflowFiles(ctx, c, owner, name, repo.GetDefaultBranch())
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
	var workflow struct {
		Permissions any `yaml:"permissions"`
		Jobs        map[string]struct {
			Permissions any `yaml:"permissions"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(content), &workflow); err != nil {
		return "unparseable"
	}
	if workflow.Permissions != nil {
		if issue := permTooBroad(workflow.Permissions); issue != "" {
			return issue
		}
		// Job-level permissions replace the workflow-level default for that job,
		// so every explicit override still needs to be checked.
		for _, job := range workflow.Jobs {
			if job.Permissions == nil {
				continue
			}
			if issue := permTooBroad(job.Permissions); issue != "" {
				return issue
			}
		}
		return ""
	}
	if len(workflow.Jobs) == 0 {
		return "no explicit permissions"
	}
	for _, job := range workflow.Jobs {
		if job.Permissions == nil {
			return "no explicit permissions"
		}
		if issue := permTooBroad(job.Permissions); issue != "" {
			return issue
		}
	}
	return ""
}

func permTooBroad(permission any) string {
	switch value := permission.(type) {
	case string:
		switch value {
		case "write-all":
			return "write-all token"
		case "read-all", "none":
			return ""
		default:
			return "invalid permissions value"
		}
	case map[string]any:
		for key, raw := range value {
			permissionValue, ok := raw.(string)
			if !ok {
				return "invalid permission value: " + key
			}
			switch permissionValue {
			case "read", "write", "none":
			default:
				return "invalid permission value: " + key
			}
		}
		return ""
	default:
		return "invalid permissions value"
	}
}
