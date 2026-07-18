package repoharden

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/google/go-github/v88/github"
	"gopkg.in/yaml.v3"
)

// workflowFileCache lazily shares one .github/workflows fetch per repository
// across all workflow-file-based checks.
type workflowFileCache struct {
	once  sync.Once
	files map[string]string
	err   error
}

func (wc *workflowFileCache) get(ctx context.Context, c *github.Client, owner, name, branch string) (map[string]string, error) {
	wc.once.Do(func() {
		wc.files, wc.err = listWorkflowFiles(ctx, c, owner, name, branch)
	})
	return wc.files, wc.err
}

func auditGitHubCodeScanningConflict(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository, wc *workflowFileCache) auditRow {
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
	files, err := wc.get(ctx, c, owner, name, repo.GetDefaultBranch())
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, key, title, "medium", StatusSkipped, "default setup on; workflows not readable", rem)
		}
		return githubAuditRow(repo, key, title, "medium", StatusError, err.Error(), rem)
	}
	uses, err := workflowsUsingCodeQL(files)
	if err != nil {
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

func workflowsUsingCodeQL(files map[string]string) ([]string, error) {
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
		if node.Kind == yaml.AliasNode && node.Alias != nil {
			return visit(node.Alias)
		}
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

// parsedWorkflow is the subset of workflow YAML the supply-chain checks need.
type parsedWorkflow struct {
	On          any                    `yaml:"on"`
	Permissions any                    `yaml:"permissions"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Uses            string         `yaml:"uses"`
	RunsOn          any            `yaml:"runs-on"`
	Environment     any            `yaml:"environment"`
	If              any            `yaml:"if"`
	ContinueOnError any            `yaml:"continue-on-error"`
	Permissions     any            `yaml:"permissions"`
	Steps           []workflowStep `yaml:"steps"`
}

type workflowStep struct {
	Uses            string         `yaml:"uses"`
	Run             string         `yaml:"run"`
	If              any            `yaml:"if"`
	ContinueOnError any            `yaml:"continue-on-error"`
	With            map[string]any `yaml:"with"`
}

func parseWorkflow(content string) (*parsedWorkflow, error) {
	var w parsedWorkflow
	if err := yaml.Unmarshal([]byte(content), &w); err != nil {
		return nil, err
	}
	return &w, nil
}

// workflowTriggers normalizes `on:` (string, list, or map) into a name set.
func workflowTriggers(on any) map[string]bool {
	out := map[string]bool{}
	switch v := on.(type) {
	case string:
		out[strings.ToLower(strings.TrimSpace(v))] = true
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				out[strings.ToLower(strings.TrimSpace(s))] = true
			}
		}
	case map[string]any:
		for k := range v {
			out[strings.ToLower(strings.TrimSpace(k))] = true
		}
	}
	return out
}
