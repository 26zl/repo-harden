package repoharden

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const pipelineSupplyChainRem = "Pin CI images to full SHA-256 digests (image@sha256:…) and include:project/component refs to full commit SHAs; avoid include:remote — moved tags or upstream changes can inject code into your pipeline."

var (
	sha256ImageRefPattern  = regexp.MustCompile(`^[^\s@]+@sha256:[0-9a-fA-F]{64}$`)
	immutableGitRefPattern = regexp.MustCompile(`^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)
)

type gitlabPipelineAnalysis struct {
	gaps         []string
	unverifiable []string
}

func auditGitLabPipelineSupplyChain(ctx context.Context, c *restClient, p gitlabProject) auditRow {
	const (
		key   = "pipeline-supply-chain"
		title = "Pipeline images and includes are pinned"
	)
	if p.DefaultBranch == "" {
		return providerRow("gitlab", "repo", p.PathWithNamespace, key, title, "medium", StatusSkipped, "no default branch", pipelineSupplyChainRem)
	}
	content, err := c.getText(ctx, gitlabProjectPath(p, "/repository/files/"+url.PathEscape(".gitlab-ci.yml")+"/raw"), url.Values{"ref": []string{p.DefaultBranch}})
	if err != nil {
		if httpNotFound(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, key, title, "medium", StatusCompliant, "no .gitlab-ci.yml on the default branch", pipelineSupplyChainRem)
		}
		if httpPermissionDenied(err) || httpUnsupported(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, key, title, "medium", StatusSkipped, "pipeline definition not readable", pipelineSupplyChainRem)
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, key, title, "medium", StatusError, err.Error(), pipelineSupplyChainRem)
	}
	analysis, err := analyzeGitLabPipeline(content)
	if err != nil {
		return providerRow("gitlab", "repo", p.PathWithNamespace, key, title, "medium", StatusGap, "unparseable .gitlab-ci.yml", pipelineSupplyChainRem)
	}
	if len(analysis.gaps) > 0 {
		return providerRow("gitlab", "repo", p.PathWithNamespace, key, title, "medium", StatusGap, strings.Join(limitStrings(analysis.gaps, maxDetailItems), ", "), pipelineSupplyChainRem)
	}
	if len(analysis.unverifiable) > 0 {
		return providerRow("gitlab", "repo", p.PathWithNamespace, key, title, "medium", StatusSkipped, "dynamic references cannot be verified statically: "+strings.Join(limitStrings(analysis.unverifiable, maxDetailItems), ", "), pipelineSupplyChainRem)
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, key, title, "medium", StatusCompliant, "images and includes pinned (or none used)", pipelineSupplyChainRem)
}

func gitlabPipelineFindings(content string) ([]string, error) {
	analysis, err := analyzeGitLabPipeline(content)
	if err != nil {
		return nil, err
	}
	out := append([]string{}, analysis.gaps...)
	out = append(out, analysis.unverifiable...)
	sort.Strings(out)
	return out, nil
}

func analyzeGitLabPipeline(content string) (gitlabPipelineAnalysis, error) {
	root, err := parseGitLabCI(content)
	if err != nil {
		return gitlabPipelineAnalysis{}, err
	}
	result := gitlabPipelineAnalysis{}
	gapSeen := map[string]bool{}
	unverifiableSeen := map[string]bool{}
	addGap := func(finding string) {
		if !gapSeen[finding] {
			gapSeen[finding] = true
			result.gaps = append(result.gaps, finding)
		}
	}
	addUnverifiable := func(finding string) {
		if !unverifiableSeen[finding] {
			unverifiableSeen[finding] = true
			result.unverifiable = append(result.unverifiable, finding)
		}
	}
	var imageRef func(*yaml.Node) string
	imageRef = func(node *yaml.Node) string {
		if node.Kind == yaml.AliasNode && node.Alias != nil {
			return imageRef(node.Alias)
		}
		if node.Kind == yaml.ScalarNode {
			return node.Value
		}
		if node.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(node.Content); i += 2 {
				if node.Content[i].Value == "name" && node.Content[i+1].Kind == yaml.ScalarNode {
					return node.Content[i+1].Value
				}
			}
		}
		return ""
	}
	checkImage := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return
		}
		if strings.Contains(ref, "$") {
			addUnverifiable("image " + ref)
			return
		}
		if !sha256ImageRefPattern.MatchString(ref) {
			addGap("image " + ref + " not pinned to a full SHA-256 digest")
		}
	}
	var checkServices func(*yaml.Node)
	checkServices = func(node *yaml.Node) {
		if node.Kind == yaml.AliasNode && node.Alias != nil {
			checkServices(node.Alias)
			return
		}
		switch node.Kind {
		case yaml.SequenceNode:
			for _, service := range node.Content {
				checkImage(imageRef(service))
			}
		case yaml.ScalarNode, yaml.MappingNode:
			checkImage(imageRef(node))
		}
	}
	resolveAlias := func(node *yaml.Node) *yaml.Node {
		for node != nil && node.Kind == yaml.AliasNode && node.Alias != nil {
			node = node.Alias
		}
		return node
	}
	checkJobLike := func(node *yaml.Node) {
		node = resolveAlias(node)
		if node == nil || node.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			switch node.Content[i].Value {
			case "image":
				checkImage(imageRef(node.Content[i+1]))
			case "services":
				checkServices(node.Content[i+1])
			}
		}
	}
	// image/services are configuration only at the top level, under default:, and on
	// job entries — nested occurrences (e.g. a variables: key named "image") are data.
	top := resolveAlias(root)
	if top != nil && top.Kind == yaml.DocumentNode && len(top.Content) > 0 {
		top = resolveAlias(top.Content[0])
	}
	if top != nil && top.Kind == yaml.MappingNode {
		checkJobLike(top)
		for i := 0; i+1 < len(top.Content); i += 2 {
			key, value := top.Content[i].Value, top.Content[i+1]
			switch key {
			case "default":
				checkJobLike(value)
			case "variables", "workflow", "cache", "stages", "include", "image", "services":
			default:
				checkJobLike(value)
			}
		}
	}

	var doc struct {
		Include any `yaml:"include"`
	}
	if err := yaml.Unmarshal([]byte(content), &doc); err == nil {
		for _, inc := range normalizeList(doc.Include) {
			switch v := inc.(type) {
			case string:
				if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
					addGap("remote include " + v)
				}
			case map[string]any:
				if remote, ok := v["remote"].(string); ok {
					addGap("remote include " + remote)
				}
				if component, ok := v["component"].(string); ok {
					at := strings.LastIndex(component, "@")
					version := ""
					if at >= 0 {
						version = strings.TrimSpace(component[at+1:])
					}
					switch {
					case strings.Contains(component, "$"):
						addUnverifiable("include component " + component)
					case version == "":
						addGap("include component " + component + " without a pinned version")
					case !immutableGitRefPattern.MatchString(version):
						addGap("include component " + component + " version " + version + " is not a full commit SHA")
					}
				}
				if project, ok := v["project"].(string); ok {
					ref, hasRef := v["ref"].(string)
					ref = strings.TrimSpace(ref)
					switch {
					case !hasRef || ref == "":
						addGap("include project " + project + " without a pinned ref")
					case strings.Contains(ref, "$"):
						addUnverifiable("include project " + project + " ref " + ref)
					case !immutableGitRefPattern.MatchString(ref):
						addGap("include project " + project + " ref " + ref + " is not a full commit SHA")
					}
				}
			}
		}
	}
	sort.Strings(result.gaps)
	sort.Strings(result.unverifiable)
	return result, nil
}

func normalizeList(v any) []any {
	switch value := v.(type) {
	case nil:
		return nil
	case []any:
		return value
	default:
		return []any{value}
	}
}

type giteaContentsEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

func listGiteaWorkflowFiles(ctx context.Context, c *restClient, repo giteaRepo) (map[string]string, error) {
	query := url.Values{}
	if repo.DefaultBranch != "" {
		query.Set("ref", repo.DefaultBranch)
	}
	out := map[string]string{}
	for _, dir := range []string{".gitea/workflows", ".forgejo/workflows", ".github/workflows"} {
		var entries []giteaContentsEntry
		if _, err := c.get(ctx, giteaRepoPath(repo, "/contents/"+escapedFilePath(dir)), query, &entries); err != nil {
			if httpNotFound(err) {
				continue
			}
			return nil, err
		}
		for _, entry := range entries {
			lower := strings.ToLower(entry.Name)
			if entry.Type != "file" || (!strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".yaml")) {
				continue
			}
			var file giteaContentsEntry
			if _, err := c.get(ctx, giteaRepoPath(repo, "/contents/"+escapedFilePath(entry.Path)), query, &file); err != nil {
				return nil, err
			}
			if !strings.EqualFold(strings.TrimSpace(file.Encoding), "base64") {
				return nil, fmt.Errorf("%s: unsupported or missing content encoding %q", entry.Path, file.Encoding)
			}
			encoded := strings.ReplaceAll(strings.TrimSpace(file.Content), "\n", "")
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				return nil, fmt.Errorf("%s: decode content: %w", entry.Path, err)
			}
			out[entry.Path] = string(decoded)
		}
	}
	return out, nil
}

func giteaWorkflowSupplyChainRow(provider, target, key, title, severity, gapPrefix, cleanDetail, rem string,
	get func() (map[string]string, error), perFile func(*parsedWorkflow) []string) auditRow {
	files, err := get()
	if err != nil {
		if httpPermissionDenied(err) || httpNotFound(err) || httpUnsupported(err) {
			return providerRow(provider, "repo", target, key, title, severity, StatusSkipped, "workflows not readable", rem)
		}
		return providerRow(provider, "repo", target, key, title, severity, StatusError, err.Error(), rem)
	}
	if len(files) == 0 {
		return providerRow(provider, "repo", target, key, title, severity, StatusCompliant, "no Actions workflows", rem)
	}
	var findings []string
	for fname, content := range files {
		w, err := parseWorkflow(content)
		if err != nil {
			findings = append(findings, fname+" (unparseable)")
			continue
		}
		if hits := perFile(w); len(hits) > 0 {
			findings = append(findings, fname+" ("+strings.Join(limitStrings(hits, maxDetailItems), ", ")+")")
		}
	}
	if len(findings) > 0 {
		sort.Strings(findings)
		return providerRow(provider, "repo", target, key, title, severity, StatusGap, gapPrefix+strings.Join(limitStrings(findings, maxDetailItems), ", "), rem)
	}
	return providerRow(provider, "repo", target, key, title, severity, StatusCompliant, cleanDetail, rem)
}
