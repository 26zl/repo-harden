package repoharden

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const bitbucketPipelineRem = "Pin build images to full SHA-256 digests (image@sha256:…) and pin pipes to exact versions; pipes cannot be digest-pinned, so review pipe version bumps."

func bitbucketTokenScopesRow(scopes string) auditRow {
	const (
		key   = "token-scopes"
		title = "Token scopes are least privilege"
		rem   = "Use a read-only access token for auditing."
	)
	trimmed := strings.TrimSpace(scopes)
	if trimmed == "" {
		return providerRow("bitbucket", "token", "authenticated-token", key, title, "medium", StatusSkipped, "token scopes are not exposed for this credential type", rem)
	}
	fields := strings.FieldsFunc(trimmed, func(r rune) bool { return r == ',' || r == ' ' })
	var excessive []string
	for _, scope := range fields {
		if bitbucketWriteScope(scope) {
			excessive = append(excessive, scope)
		}
	}
	if len(excessive) > 0 {
		return providerRow("bitbucket", "token", "authenticated-token", key, title, "medium", StatusGap,
			"write/admin scopes on the audit token: "+strings.Join(limitStrings(excessive, maxDetailItems), ", "), rem)
	}
	return providerRow("bitbucket", "token", "authenticated-token", key, title, "medium", StatusCompliant,
		"read-only scopes: "+strings.Join(limitStrings(fields, maxDetailItems), ", "), rem)
}

// bitbucketWriteScope matches both classic (repository:write) and granular
// (write:repository:bitbucket) scope styles; pipeline:variable also grants
// management of secured variables.
func bitbucketWriteScope(scope string) bool {
	for _, suffix := range []string{":write", ":admin", ":delete"} {
		if strings.HasSuffix(scope, suffix) {
			return true
		}
	}
	for _, prefix := range []string{"write:", "admin:", "delete:"} {
		if strings.HasPrefix(scope, prefix) {
			return true
		}
	}
	return scope == "pipeline:variable"
}

type bitbucketBranchRestriction struct {
	Kind            string `json:"kind"`
	BranchMatchKind string `json:"branch_match_kind"`
	Pattern         string `json:"pattern"`
	Value           *int   `json:"value"`
	Users           []struct {
		DisplayName string `json:"display_name"`
	} `json:"users"`
	Groups []struct {
		Slug string `json:"slug"`
	} `json:"groups"`
}

func auditBitbucketBranchProtection(ctx context.Context, c *restClient, repo bitbucketRepo) auditRow {
	const (
		key = "branch-protection-full"
		rem = "Restrict direct/force pushes, require merge approvals, and enable enforced merge checks (Premium) on the default branch."
	)
	branch := bitbucketDefaultBranch(repo)
	if branch == "" {
		return providerRow("bitbucket", "repo", repo.FullName, key, "Default branch is protected", "high", StatusSkipped, "no default branch", rem)
	}
	restrictions, _, err := bitbucketPaged[bitbucketBranchRestriction](ctx, c, bitbucketRepoPath(repo, "/branch-restrictions"), nil)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("bitbucket", "repo", repo.FullName, key, "Default branch is protected", "high", StatusSkipped, "branch restrictions API unavailable (requires repository admin)", rem)
		}
		return providerRow("bitbucket", "repo", repo.FullName, key, "Default branch is protected", "high", StatusError, err.Error(), rem)
	}
	if len(restrictions) == 0 {
		return providerRow("bitbucket", "repo", repo.FullName, key, "Default branch is protected", "high", StatusGap, "no branch restrictions configured", rem)
	}
	var hasPush, pushExemptions, hasForce, hasApprovals, hasEnforce bool
	exemptCount := 0
	modelRestrictions := 0
	for _, r := range restrictions {
		if r.BranchMatchKind == "branching_model" {
			modelRestrictions++
			continue
		}
		pattern := strings.TrimSpace(r.Pattern)
		if pattern == "" || (pattern != branch && !globMatch(pattern, branch)) {
			continue
		}
		switch r.Kind {
		case "push":
			hasPush = true
			if len(r.Users)+len(r.Groups) > 0 {
				pushExemptions = true
				exemptCount += len(r.Users) + len(r.Groups)
			}
		case "force":
			hasForce = true
		case "require_approvals_to_merge", "require_default_reviewer_approvals_to_merge":
			if r.Value != nil && *r.Value >= 1 {
				hasApprovals = true
			}
		case "enforce_merge_checks":
			hasEnforce = true
		}
	}
	var issues []string
	if !hasPush {
		issues = append(issues, "direct pushes are not restricted")
	} else if pushExemptions {
		issues = append(issues, fmt.Sprintf("direct push exemptions exist for %d users/groups", exemptCount))
	}
	if !hasForce {
		issues = append(issues, "force push is not prevented")
	}
	if !hasApprovals {
		issues = append(issues, "no required approval")
	} else if !hasEnforce {
		issues = append(issues, "approvals are not blocking (no enforce_merge_checks restriction; enforced merge checks are a Premium feature)")
	}
	if len(issues) == 0 {
		return providerRow("bitbucket", "repo", repo.FullName, key, "Default branch protection is complete", "high", StatusCompliant, "direct/force pushes restricted and merge approval enforced", rem)
	}
	if modelRestrictions > 0 {
		return providerRow("bitbucket", "repo", repo.FullName, key, "Default branch protection is complete", "high", StatusSkipped,
			fmt.Sprintf("%d restrictions target branching model branch types and cannot be evaluated statically; unresolved: %s", modelRestrictions, strings.Join(issues, "; ")), rem)
	}
	return providerRow("bitbucket", "repo", repo.FullName, key, "Default branch protection is complete", "high", StatusGap, strings.Join(issues, "; "), rem)
}

// bitbucketPipelinesYMLFetcher fetches bitbucket-pipelines.yml from the default
// branch once and shares the result between the checks that read it.
func bitbucketPipelinesYMLFetcher(ctx context.Context, c *restClient, repo bitbucketRepo, srcRef func() (string, error)) func() (string, error) {
	var once sync.Once
	var content string
	var err error
	return func() (string, error) {
		once.Do(func() {
			var ref string
			if ref, err = srcRef(); err != nil {
				return
			}
			content, err = c.getText(ctx, bitbucketRepoPath(repo, "/src/"+url.PathEscape(ref)+"/bitbucket-pipelines.yml"), nil)
		})
		return content, err
	}
}

func auditBitbucketRequiredWorkflows(ctx context.Context, c *restClient, repo bitbucketRepo, getYML func() (string, error)) auditRow {
	const (
		key   = "required-workflows"
		title = "CI configuration exists"
		rem   = "Add bitbucket-pipelines.yml and enable Pipelines with required merge checks."
	)
	if bitbucketDefaultBranch(repo) == "" {
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusSkipped, "no default branch", rem)
	}
	content, err := getYML()
	if err != nil {
		if httpNotFound(err) {
			return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusGap, "no bitbucket-pipelines.yml on default branch", rem)
		}
		if httpPermissionDenied(err) || httpUnsupported(err) {
			return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusSkipped, "CI configuration could not be read with this token/API", rem)
		}
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusError, err.Error(), rem)
	}
	if _, err := parseGitLabCI(content); err != nil {
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusGap, "invalid bitbucket-pipelines.yml: "+err.Error(), rem)
	}
	var config struct {
		Enabled bool `json:"enabled"`
	}
	if _, err := c.get(ctx, bitbucketRepoPath(repo, "/pipelines_config"), nil, &config); err != nil {
		// A 404 here means either "never configured" or "no permission"; neither is provable, so never pass.
		if httpUnavailable(err) {
			return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusSkipped, "bitbucket-pipelines.yml is valid, but whether Pipelines is enabled is not verifiable with this token", rem)
		}
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusError, err.Error(), rem)
	}
	if !config.Enabled {
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusGap, "bitbucket-pipelines.yml exists but Pipelines is disabled", rem)
	}
	return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusCompliant, "bitbucket-pipelines.yml is valid and Pipelines is enabled", rem)
}

func auditBitbucketPipelineSupplyChain(repo bitbucketRepo, getYML func() (string, error)) auditRow {
	const (
		key   = "pipeline-supply-chain"
		title = "Pipeline images and pipes are pinned"
	)
	if bitbucketDefaultBranch(repo) == "" {
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusSkipped, "no default branch", bitbucketPipelineRem)
	}
	content, err := getYML()
	if err != nil {
		if httpNotFound(err) {
			return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusCompliant, "no bitbucket-pipelines.yml on the default branch", bitbucketPipelineRem)
		}
		if httpPermissionDenied(err) || httpUnsupported(err) {
			return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusSkipped, "pipeline definition not readable", bitbucketPipelineRem)
		}
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusError, err.Error(), bitbucketPipelineRem)
	}
	analysis, err := analyzeBitbucketPipeline(content)
	if err != nil {
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusGap, "unparseable bitbucket-pipelines.yml", bitbucketPipelineRem)
	}
	if len(analysis.gaps) > 0 {
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusGap, strings.Join(limitStrings(analysis.gaps, maxDetailItems), ", "), bitbucketPipelineRem)
	}
	if len(analysis.unverifiable) > 0 {
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusSkipped, "dynamic references cannot be verified statically: "+strings.Join(limitStrings(analysis.unverifiable, maxDetailItems), ", "), bitbucketPipelineRem)
	}
	if len(analysis.mutablePipes) > 0 {
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusCompliant,
			fmt.Sprintf("images pinned; %d pipes pinned to version tags (digest pinning is unavailable for pipes)", len(analysis.mutablePipes)), bitbucketPipelineRem)
	}
	return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusCompliant, "images and pipes pinned (or none used)", bitbucketPipelineRem)
}

type bitbucketPipelineAnalysis struct {
	gaps         []string
	unverifiable []string
	mutablePipes []string
}

func analyzeBitbucketPipeline(content string) (bitbucketPipelineAnalysis, error) {
	root, err := parseGitLabCI(content)
	if err != nil {
		return bitbucketPipelineAnalysis{}, err
	}
	result := bitbucketPipelineAnalysis{}
	seen := map[string]bool{}
	add := func(list *[]string, finding string) {
		if !seen[finding] {
			seen[finding] = true
			*list = append(*list, finding)
		}
	}
	resolveAlias := func(node *yaml.Node) *yaml.Node {
		for node != nil && node.Kind == yaml.AliasNode && node.Alias != nil {
			node = node.Alias
		}
		return node
	}
	imageRef := func(node *yaml.Node) string {
		node = resolveAlias(node)
		if node == nil {
			return ""
		}
		if node.Kind == yaml.ScalarNode {
			return node.Value
		}
		if node.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(node.Content); i += 2 {
				if node.Content[i].Value == "name" {
					if v := resolveAlias(node.Content[i+1]); v != nil && v.Kind == yaml.ScalarNode {
						return v.Value
					}
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
			add(&result.unverifiable, "image "+ref)
			return
		}
		if !sha256ImageRefPattern.MatchString(ref) {
			add(&result.gaps, "image "+ref+" not pinned to a full SHA-256 digest")
		}
	}
	checkPipe := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return
		}
		if strings.Contains(ref, "$") {
			add(&result.unverifiable, "pipe "+ref)
			return
		}
		target := strings.TrimPrefix(ref, "docker://")
		if sha256ImageRefPattern.MatchString(target) {
			return
		}
		tag := ""
		// A colon before the last "/" is a registry port, not a tag.
		if colon := strings.LastIndex(target, ":"); colon > strings.LastIndex(target, "/") {
			tag = target[colon+1:]
		}
		if tag == "" || tag == "latest" {
			add(&result.gaps, "pipe "+ref+" not pinned to a version")
			return
		}
		add(&result.mutablePipes, "pipe "+ref)
	}
	var walk func(node *yaml.Node)
	walk = func(node *yaml.Node) {
		node = resolveAlias(node)
		if node == nil {
			return
		}
		switch node.Kind {
		case yaml.DocumentNode, yaml.SequenceNode:
			for _, child := range node.Content {
				walk(child)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(node.Content); i += 2 {
				value := node.Content[i+1]
				switch node.Content[i].Value {
				case "image":
					checkImage(imageRef(value))
				case "pipe":
					if v := resolveAlias(value); v != nil && v.Kind == yaml.ScalarNode {
						checkPipe(v.Value)
					}
				}
				walk(value)
			}
		}
	}
	walk(root)
	sort.Strings(result.gaps)
	sort.Strings(result.unverifiable)
	sort.Strings(result.mutablePipes)
	return result, nil
}

func auditBitbucketVariables(ctx context.Context, c *restClient, repo bitbucketRepo, showIdentifiers bool) auditRow {
	const (
		key   = "repo-secrets"
		title = "Pipeline variables are secured"
		rem   = "Mark sensitive pipeline variables as secured so values are hidden from logs and the API."
	)
	variables, _, err := bitbucketPaged[struct {
		Key     string `json:"key"`
		Secured bool   `json:"secured"`
	}](ctx, c, bitbucketRepoPath(repo, "/pipelines_config/variables"), nil)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusSkipped, "pipeline variables API unavailable", rem)
		}
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusError, err.Error(), rem)
	}
	var weak []string
	for _, variable := range variables {
		if !variable.Secured {
			weak = append(weak, variable.Key)
		}
	}
	if len(weak) > 0 {
		detail := fmt.Sprintf("%d unsecured pipeline variables", len(weak))
		if showIdentifiers {
			detail += ": " + strings.Join(limitStrings(weak, maxDetailItems), ", ")
		}
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusGap, detail, rem)
	}
	return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusCompliant, fmt.Sprintf("%d pipeline variables reviewed", len(variables)), rem)
}

func auditBitbucketWebhooks(ctx context.Context, c *restClient, repo bitbucketRepo) auditRow {
	const (
		key   = "webhooks"
		title = "Webhooks use TLS and active hooks are reviewed"
		rem   = "Require HTTPS and TLS verification for webhooks."
	)
	hooks, _, err := bitbucketPaged[struct {
		UUID                 string `json:"uuid"`
		URL                  string `json:"url"`
		Active               bool   `json:"active"`
		SkipCertVerification *bool  `json:"skip_cert_verification"`
	}](ctx, c, bitbucketRepoPath(repo, "/hooks"), nil)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusSkipped, "webhooks API unavailable", rem)
		}
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusError, err.Error(), rem)
	}
	var weak []string
	uncheckedTLS := 0
	for _, hook := range hooks {
		if !hook.Active {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(hook.URL), "https://") || (hook.SkipCertVerification != nil && *hook.SkipCertVerification) {
			weak = append(weak, hook.UUID)
			continue
		}
		// skip_cert_verification is undocumented, so its absence proves nothing.
		if hook.SkipCertVerification == nil {
			uncheckedTLS++
		}
	}
	if len(weak) > 0 {
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusGap, "weak active webhooks: "+strings.Join(limitStrings(weak, maxDetailItems), ", "), rem)
	}
	detail := fmt.Sprintf("%d webhooks reviewed", len(hooks))
	if uncheckedTLS > 0 {
		detail += fmt.Sprintf("; certificate verification is not exposed for %d active webhook(s)", uncheckedTLS)
	}
	return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusCompliant, detail, rem)
}

func auditBitbucketDeployKeys(ctx context.Context, c *restClient, repo bitbucketRepo) auditRow {
	const (
		key   = "deploy-keys"
		title = "Deploy keys are read-only or absent"
		rem   = "Remove unused deploy keys."
	)
	keys, _, err := bitbucketPaged[struct {
		Label string `json:"label"`
	}](ctx, c, bitbucketRepoPath(repo, "/deploy-keys"), nil)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("bitbucket", "repo", repo.FullName, key, title, "high", StatusSkipped, "deploy keys API unavailable", rem)
		}
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "high", StatusError, err.Error(), rem)
	}
	return providerRow("bitbucket", "repo", repo.FullName, key, title, "high", StatusCompliant, fmt.Sprintf("%d deploy keys; Bitbucket Cloud deploy keys are read-only", len(keys)), rem)
}

func auditBitbucketCollaborators(ctx context.Context, c *restClient, repo bitbucketRepo, showIdentifiers bool) auditRow {
	const (
		key   = "collaborators"
		title = "Collaborators are reviewed"
		rem   = "Review direct collaborators and remove stale admins."
	)
	grants, _, err := bitbucketPaged[struct {
		Permission string `json:"permission"`
		User       struct {
			DisplayName string `json:"display_name"`
		} `json:"user"`
	}](ctx, c, bitbucketRepoPath(repo, "/permissions-config/users"), nil)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusSkipped, "explicit permissions API unavailable (requires repository admin)", rem)
		}
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusError, err.Error(), rem)
	}
	var admins []string
	for _, grant := range grants {
		if grant.Permission == "admin" {
			admins = append(admins, grant.User.DisplayName)
		}
	}
	if len(admins) > 0 {
		detail := fmt.Sprintf("%d direct admin grants", len(admins))
		if showIdentifiers {
			detail += ": " + strings.Join(limitStrings(admins, maxDetailItems), ", ")
		}
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusGap, detail, rem)
	}
	return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusCompliant, fmt.Sprintf("%d explicit user permissions reviewed", len(grants)), rem)
}

func auditBitbucketEnvironments(ctx context.Context, c *restClient, repo bitbucketRepo) auditRow {
	const (
		key   = "environment-protection"
		title = "Deployment environments are protected"
		rem   = "Restrict production deployments to admins (Premium) or protect deployment branches."
	)
	environments, _, err := bitbucketPaged[struct {
		Name            string `json:"name"`
		EnvironmentType struct {
			Name string `json:"name"`
		} `json:"environment_type"`
		Restrictions *struct {
			AdminOnly *bool `json:"admin_only"`
		} `json:"restrictions"`
	}](ctx, c, bitbucketRepoPath(repo, "/environments"), nil)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusSkipped, "environments API unavailable", rem)
		}
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusError, err.Error(), rem)
	}
	if len(environments) == 0 {
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusSkipped, "no deployment environments defined", rem)
	}
	var unrestricted, unexposed []string
	production := 0
	for _, environment := range environments {
		if !strings.EqualFold(environment.EnvironmentType.Name, "production") {
			continue
		}
		production++
		if environment.Restrictions == nil || environment.Restrictions.AdminOnly == nil {
			unexposed = append(unexposed, environment.Name)
			continue
		}
		if !*environment.Restrictions.AdminOnly {
			unrestricted = append(unrestricted, environment.Name)
		}
	}
	if production == 0 {
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusSkipped, "no production-type environments", rem)
	}
	if len(unrestricted) > 0 {
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusGap, "production environments without admin-only deployments: "+strings.Join(limitStrings(unrestricted, maxDetailItems), ", "), rem)
	}
	if len(unexposed) > 0 {
		return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusSkipped, "deployment restrictions are not exposed for: "+strings.Join(limitStrings(unexposed, maxDetailItems), ", "), rem)
	}
	return providerRow("bitbucket", "repo", repo.FullName, key, title, "medium", StatusCompliant, fmt.Sprintf("%d production environments restricted to admins", production), rem)
}

func auditBitbucketRepositoryLicense(ctx context.Context, c *restClient, repo bitbucketRepo, srcRef func() (string, error)) auditRow {
	if bitbucketDefaultBranch(repo) == "" {
		return providerRow("bitbucket", "repo", repo.FullName, "repository-license", repositoryLicenseTitle, "low", StatusSkipped,
			"no default branch", repositoryLicenseRemediation)
	}
	ref, err := srcRef()
	if err == nil {
		var entries []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		}
		entries, _, err = bitbucketPaged[struct {
			Path string `json:"path"`
			Type string `json:"type"`
		}](ctx, c, bitbucketRepoPath(repo, "/src/"+url.PathEscape(ref)+"/"), nil)
		if err == nil {
			var files []string
			for _, entry := range entries {
				if entry.Type == "commit_file" && repositoryLicenseFilename(entry.Path) {
					files = append(files, entry.Path)
				}
			}
			if len(files) == 0 {
				return providerRow("bitbucket", "repo", repo.FullName, "repository-license", repositoryLicenseTitle, "low", StatusGap,
					"no repository license file found", repositoryLicenseRemediation)
			}
			sort.Strings(files)
			return providerRow("bitbucket", "repo", repo.FullName, "repository-license", repositoryLicenseTitle, "low", StatusCompliant,
				"license file present: "+strings.Join(limitStrings(files, maxDetailItems), ", ")+" (license family not identified by provider)",
				repositoryLicenseRemediation)
		}
	}
	if httpUnavailable(err) {
		return providerRow("bitbucket", "repo", repo.FullName, "repository-license", repositoryLicenseTitle, "low", StatusSkipped,
			"repository root contents are unavailable", repositoryLicenseRemediation)
	}
	return providerRow("bitbucket", "repo", repo.FullName, "repository-license", repositoryLicenseTitle, "low", StatusError,
		err.Error(), repositoryLicenseRemediation)
}
