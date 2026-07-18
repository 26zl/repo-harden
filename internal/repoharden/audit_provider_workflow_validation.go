package repoharden

import (
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

type gitlabApprovalRule struct {
	ApprovalsRequired             int  `json:"approvals_required"`
	AppliesToAllProtectedBranches bool `json:"applies_to_all_protected_branches"`
	ProtectedBranches             []struct {
		Name string `json:"name"`
	} `json:"protected_branches"`
}

func gitlabApprovalRuleAppliesToBranch(rule gitlabApprovalRule, branch string) bool {
	if rule.AppliesToAllProtectedBranches || len(rule.ProtectedBranches) == 0 {
		return true
	}
	for _, protectedBranch := range rule.ProtectedBranches {
		pattern := strings.TrimSpace(protectedBranch.Name)
		if pattern == branch || (pattern != "" && globMatch(pattern, branch)) {
			return true
		}
	}
	return false
}

func parseGitLabCI(content string) (*yaml.Node, error) {
	root, err := parseSingleYAMLDocument(content)
	if err != nil {
		return nil, err
	}
	document := root.Content[0]
	if document.Kind != yaml.MappingNode || len(document.Content) == 0 {
		return nil, fmt.Errorf("top-level configuration must be a non-empty mapping")
	}
	return root, nil
}

func parseSingleYAMLDocument(content string) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(strings.NewReader(content))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("configuration is empty")
		}
		return nil, fmt.Errorf("parse YAML: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 {
		return nil, fmt.Errorf("configuration must contain one YAML document")
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("parse YAML: %w", err)
		}
		return nil, fmt.Errorf("configuration must contain one YAML document")
	}
	return &root, nil
}

func validateGiteaWorkflow(content string) error {
	root, err := parseSingleYAMLDocument(content)
	if err != nil {
		return err
	}
	if root.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("top-level workflow must be a mapping")
	}
	workflow, err := parseWorkflow(content)
	if err != nil {
		return fmt.Errorf("parse YAML: %w", err)
	}
	hasTrigger := false
	for trigger := range workflowTriggers(workflow.On) {
		if strings.TrimSpace(trigger) != "" {
			hasTrigger = true
			break
		}
	}
	if !hasTrigger {
		return fmt.Errorf("workflow has no trigger")
	}
	if len(workflow.Jobs) == 0 {
		return fmt.Errorf("workflow has no jobs")
	}
	for name, job := range workflow.Jobs {
		if strings.TrimSpace(name) == "" {
			continue
		}
		if strings.TrimSpace(job.Uses) != "" || (runsOnConfigured(job.RunsOn) && len(job.Steps) > 0) {
			return nil
		}
	}
	return fmt.Errorf("workflow has no executable job")
}
