package repoharden

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/google/go-github/v88/github"
)

func auditGitHubDependencyReview(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository, wc *workflowFileCache) auditRow {
	const (
		key   = "dependency-review"
		title = "Pull requests run dependency review"
		rem   = "Run actions/dependency-review-action in a pull_request job that handles synchronize events. Also run it on merge_group when a merge queue is used; required status-check enforcement is outside this audit's scope."
	)
	files, err := wc.get(ctx, c, owner, name, repo.GetDefaultBranch())
	if err != nil {
		if endpointUnavailable(err) {
			return githubAuditRow(repo, key, title, "low", StatusSkipped, "workflows not readable", rem)
		}
		return githubAuditRow(repo, key, title, "low", StatusError, err.Error(), rem)
	}
	if len(files) == 0 {
		return githubAuditRow(repo, key, title, "low", StatusGap, "repository has no Actions workflow that runs dependency review", rem)
	}
	var parseErrors []string
	var configured []string
	var misconfigured []string
	for fname, content := range files {
		workflow, err := parseWorkflow(content)
		if err != nil {
			parseErrors = append(parseErrors, fname)
			continue
		}
		if workflowRunsDependencyReview(workflow) {
			configured = append(configured, fname)
		} else if workflowContainsDependencyReviewAction(workflow) {
			misconfigured = append(misconfigured, fname)
		}
	}
	if len(parseErrors) > 0 {
		sort.Strings(parseErrors)
		return githubAuditRow(repo, key, title, "low", StatusError,
			"could not verify dependency review because workflow YAML is unparseable: "+strings.Join(limitStrings(parseErrors, maxDetailItems), ", "), rem)
	}
	if len(configured) > 0 {
		sort.Strings(configured)
		return githubAuditRow(repo, key, title, "low", StatusCompliant,
			"dependency review runs for pull_request updates in "+configured[0]+"; required status-check enforcement not verified", rem)
	}
	if len(misconfigured) > 0 {
		sort.Strings(misconfigured)
		return githubAuditRow(repo, key, title, "low", StatusGap,
			"dependency-review action is not in a runnable pull_request job that handles synchronize events: "+strings.Join(limitStrings(misconfigured, maxDetailItems), ", "), rem)
	}
	return githubAuditRow(repo, key, title, "low", StatusGap, "no workflow uses actions/dependency-review-action", rem)
}

func workflowContainsDependencyReviewAction(workflow *parsedWorkflow) bool {
	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if actionReferenceMatches(step.Uses, "actions/dependency-review-action") {
				return true
			}
		}
	}
	return false
}

func workflowRunsDependencyReview(workflow *parsedWorkflow) bool {
	if !workflowHasDependencyReviewTrigger(workflow.On) {
		return false
	}
	for _, job := range workflow.Jobs {
		if conditionAlwaysFalse(job.If) || conditionExcludesEvent(job.If, "pull_request") ||
			conditionAlwaysTrue(job.ContinueOnError) || !runsOnConfigured(job.RunsOn) {
			continue
		}
		for _, step := range job.Steps {
			if !conditionAlwaysFalse(step.If) && !conditionExcludesEvent(step.If, "pull_request") &&
				!conditionAlwaysTrue(step.ContinueOnError) &&
				actionReferenceMatches(step.Uses, "actions/dependency-review-action") {
				return true
			}
		}
	}
	return false
}

func workflowHasDependencyReviewTrigger(on any) bool {
	switch value := on.(type) {
	case string, []any:
		return workflowTriggers(value)["pull_request"]
	case map[string]any:
		for event, config := range value {
			if strings.EqualFold(strings.TrimSpace(event), "pull_request") && eventRunsForUpdates(config, "synchronize") {
				return true
			}
		}
	}
	return false
}

type workflowConditionTruth uint8

const (
	workflowConditionUnknown workflowConditionTruth = iota
	workflowConditionFalse
	workflowConditionTrue
)

// conditionExcludesEvent evaluates only the event-name portion of an if expression, rejecting a job only when it is provably false for the required event.
func conditionExcludesEvent(condition any, event string) bool {
	switch value := condition.(type) {
	case bool:
		return !value
	case string:
		expression := strings.TrimSpace(value)
		if strings.HasPrefix(expression, "${{") && strings.HasSuffix(expression, "}}") {
			expression = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(expression, "${{"), "}}"))
		}
		return workflowConditionValue(expression, event) == workflowConditionFalse
	default:
		return false
	}
}

func workflowConditionValue(expression, event string) workflowConditionTruth {
	expression = stripWorkflowConditionParens(strings.TrimSpace(expression))
	if expression == "" {
		return workflowConditionUnknown
	}
	if parts := splitWorkflowCondition(expression, "||"); len(parts) > 1 {
		result := workflowConditionFalse
		for _, part := range parts {
			value := workflowConditionValue(part, event)
			if value == workflowConditionTrue {
				return workflowConditionTrue
			}
			if value == workflowConditionUnknown {
				result = workflowConditionUnknown
			}
		}
		return result
	}
	if parts := splitWorkflowCondition(expression, "&&"); len(parts) > 1 {
		result := workflowConditionTrue
		for _, part := range parts {
			value := workflowConditionValue(part, event)
			if value == workflowConditionFalse {
				return workflowConditionFalse
			}
			if value == workflowConditionUnknown {
				result = workflowConditionUnknown
			}
		}
		return result
	}
	if strings.HasPrefix(expression, "!") && !strings.HasPrefix(expression, "!=") {
		switch workflowConditionValue(strings.TrimSpace(strings.TrimPrefix(expression, "!")), event) {
		case workflowConditionFalse:
			return workflowConditionTrue
		case workflowConditionTrue:
			return workflowConditionFalse
		default:
			return workflowConditionUnknown
		}
	}
	if strings.EqualFold(expression, "true") {
		return workflowConditionTrue
	}
	if strings.EqualFold(expression, "false") {
		return workflowConditionFalse
	}
	if result, ok := workflowEventComparison(expression, event); ok {
		if result {
			return workflowConditionTrue
		}
		return workflowConditionFalse
	}
	return workflowConditionUnknown
}

func workflowEventComparison(expression, event string) (bool, bool) {
	for _, operator := range []string{"==", "!="} {
		at := strings.Index(expression, operator)
		if at < 0 || strings.Contains(expression[at+len(operator):], operator) {
			continue
		}
		left := strings.TrimSpace(expression[:at])
		right := strings.TrimSpace(expression[at+len(operator):])
		var literal string
		switch {
		case strings.EqualFold(left, "github.event_name"):
			literal = workflowQuotedLiteral(right)
		case strings.EqualFold(right, "github.event_name"):
			literal = workflowQuotedLiteral(left)
		default:
			continue
		}
		if literal == "" {
			return false, false
		}
		equal := strings.EqualFold(literal, event)
		if operator == "!=" {
			equal = !equal
		}
		return equal, true
	}
	return false, false
}

func workflowQuotedLiteral(value string) string {
	if len(value) < 2 || (value[0] != '\'' && value[0] != '"') || value[len(value)-1] != value[0] {
		return ""
	}
	return strings.TrimSpace(value[1 : len(value)-1])
}

func splitWorkflowCondition(expression, operator string) []string {
	var parts []string
	start, depth := 0, 0
	var quote byte
	for i := 0; i < len(expression); i++ {
		char := expression[i]
		if quote != 0 {
			if char == quote && (i == 0 || expression[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		switch char {
		case '\'', '"':
			quote = char
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && strings.HasPrefix(expression[i:], operator) {
				parts = append(parts, expression[start:i])
				i += len(operator) - 1
				start = i + 1
			}
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return append(parts, expression[start:])
}

func stripWorkflowConditionParens(expression string) string {
	for len(expression) >= 2 && expression[0] == '(' && expression[len(expression)-1] == ')' {
		depth := 0
		var quote byte
		wraps := true
		for i := 0; i < len(expression); i++ {
			char := expression[i]
			if quote != 0 {
				if char == quote && (i == 0 || expression[i-1] != '\\') {
					quote = 0
				}
				continue
			}
			switch char {
			case '\'', '"':
				quote = char
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 && i != len(expression)-1 {
					wraps = false
				}
			}
		}
		if !wraps || depth != 0 {
			break
		}
		expression = strings.TrimSpace(expression[1 : len(expression)-1])
	}
	return expression
}

func eventRunsForUpdates(config any, requiredType string) bool {
	if config == nil {
		return true
	}
	mapping, ok := config.(map[string]any)
	if !ok {
		return false
	}
	var types any
	found := false
	for key, raw := range mapping {
		if strings.EqualFold(strings.TrimSpace(key), "types") {
			types, found = raw, true
			break
		}
	}
	if !found {
		return true
	}
	switch value := types.(type) {
	case string:
		return strings.EqualFold(strings.TrimSpace(value), requiredType)
	case []any:
		for _, raw := range value {
			if item, ok := raw.(string); ok && strings.EqualFold(strings.TrimSpace(item), requiredType) {
				return true
			}
		}
	}
	return false
}

func conditionAlwaysTrue(condition any) bool {
	switch value := condition.(type) {
	case bool:
		return value
	case string:
		value = strings.ToLower(strings.Join(strings.Fields(value), ""))
		return value == "true" || value == "${{true}}"
	default:
		return false
	}
}

func runsOnConfigured(runsOn any) bool {
	switch value := runsOn.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(value) != ""
	case []any:
		return len(value) > 0
	case map[string]any:
		return len(value) > 0
	default:
		return true
	}
}

func conditionAlwaysFalse(condition any) bool {
	switch value := condition.(type) {
	case bool:
		return !value
	case string:
		value = strings.ToLower(strings.Join(strings.Fields(value), ""))
		return value == "false" || value == "${{false}}"
	default:
		return false
	}
}

func actionReferenceMatches(ref, action string) bool {
	ref = strings.ToLower(strings.TrimSpace(ref))
	if at := strings.LastIndex(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	return ref == strings.ToLower(action)
}

func auditGitHubOIDCCloudTrust(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository, wc *workflowFileCache) auditRow {
	const (
		key   = "oidc-cloud-trust"
		title = "Cloud OIDC deploy jobs are scoped"
		rem   = "Gate cloud-auth jobs behind a protected `environment:` and/or customize the Actions OIDC subject claim so cloud trust policies can pin more than the repo name."
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
	var cloudJobs []workflowOIDCJob
	var parseErrors []string
	for fname, content := range files {
		w, err := parseWorkflow(content)
		if err != nil {
			parseErrors = append(parseErrors, fname)
			continue
		}
		for _, job := range workflowOIDCCloudJobs(w) {
			job.workflow = fname
			cloudJobs = append(cloudJobs, job)
		}
	}
	if len(parseErrors) > 0 {
		sort.Strings(parseErrors)
		return githubAuditRow(repo, key, title, "medium", StatusError,
			"could not verify cloud OIDC use because workflow YAML is unparseable: "+strings.Join(limitStrings(parseErrors, maxDetailItems), ", "), rem)
	}
	if len(cloudJobs) == 0 {
		return githubAuditRow(repo, key, title, "medium", StatusCompliant, "no cloud OIDC auth actions detected", rem)
	}

	var tokenIssues, scopeIssues, unverifiable, hardErrors []string
	environments := map[string]*github.Environment{}
	environmentErrors := map[string]error{}
	customRules := map[string][]*github.CustomDeploymentProtectionRule{}
	customRuleErrors := map[string]error{}
	for _, job := range cloudJobs {
		label := job.workflow + " (" + job.name + ")"
		if !job.idTokenWrite {
			tokenIssues = append(tokenIssues, label+" lacks id-token: write")
			continue
		}
		if !job.hasEnvironment {
			scopeIssues = append(scopeIssues, label+" has no environment")
			continue
		}
		if job.environment == "" {
			scopeIssues = append(scopeIssues, label+" uses a dynamic environment that cannot be verified")
			continue
		}
		environment, seen := environments[job.environment]
		envErr, failed := environmentErrors[job.environment]
		if !seen && !failed {
			environment, _, envErr = c.Repositories.GetEnvironment(ctx, owner, name, job.environment)
			if envErr != nil {
				environmentErrors[job.environment] = envErr
			} else {
				environments[job.environment] = environment
			}
		}
		if envErr != nil {
			switch {
			case githubStatus(envErr) == http.StatusNotFound:
				scopeIssues = append(scopeIssues, label+" references a missing environment "+job.environment)
			case endpointUnavailable(envErr):
				unverifiable = append(unverifiable, label+" environment protection is not readable")
			default:
				hardErrors = append(hardErrors, label+": "+envErr.Error())
			}
			continue
		}
		if githubEnvironmentProtected(environment) {
			continue
		}

		rules, rulesSeen := customRules[job.environment]
		rulesErr, rulesFailed := customRuleErrors[job.environment]
		if !rulesSeen && !rulesFailed {
			var response *github.ListDeploymentProtectionRuleResponse
			response, _, rulesErr = c.Repositories.GetAllDeploymentProtectionRules(ctx, owner, name, job.environment)
			if rulesErr != nil {
				customRuleErrors[job.environment] = rulesErr
			} else {
				if response != nil {
					rules = response.ProtectionRules
				}
				customRules[job.environment] = rules
			}
		}
		if rulesErr != nil {
			switch {
			case githubStatus(rulesErr) == http.StatusNotFound:
				scopeIssues = append(scopeIssues, label+" environment "+job.environment+" has no effective protection")
			case endpointUnavailable(rulesErr):
				unverifiable = append(unverifiable, label+" custom deployment protection is not readable")
			default:
				hardErrors = append(hardErrors, label+": "+rulesErr.Error())
			}
			continue
		}
		if !githubEnvironmentProtected(environment, rules) {
			scopeIssues = append(scopeIssues, label+" environment "+job.environment+" has no effective protection")
		}
	}
	if len(tokenIssues) > 0 {
		sort.Strings(tokenIssues)
		return githubAuditRow(repo, key, title, "medium", StatusGap,
			"cloud OIDC jobs without explicit token permission: "+strings.Join(limitStrings(tokenIssues, maxDetailItems), ", "), rem)
	}
	if len(scopeIssues) == 0 && len(unverifiable) == 0 && len(hardErrors) == 0 {
		return githubAuditRow(repo, key, title, "medium", StatusCompliant, "all cloud OIDC jobs use a protected environment", rem)
	}

	tmpl, _, err := c.Actions.GetRepoOIDCSubjectClaimCustomTemplate(ctx, owner, name)
	if err != nil && !endpointUnavailable(err) {
		return githubAuditErr(repo, key, title, "medium", err, rem)
	}
	if err == nil && tmpl != nil && tmpl.UseDefault != nil && !*tmpl.UseDefault {
		claims := meaningfulOIDCClaimKeys(tmpl.IncludeClaimKeys, cloudJobs)
		if len(claims) > 0 {
			return githubAuditRow(repo, key, title, "medium", StatusCompliant,
				"custom OIDC subject claim ("+strings.Join(limitStrings(claims, maxDetailItems), ", ")+") scopes cloud trust", rem)
		}
	}
	if len(hardErrors) > 0 {
		sort.Strings(hardErrors)
		return githubAuditRow(repo, key, title, "medium", StatusError,
			"could not verify environment protection: "+strings.Join(limitStrings(hardErrors, maxDetailItems), ", "), rem)
	}
	if len(unverifiable) > 0 {
		sort.Strings(unverifiable)
		return githubAuditRow(repo, key, title, "medium", StatusSkipped,
			"could not verify environment protection or a meaningful custom OIDC subject: "+strings.Join(limitStrings(unverifiable, maxDetailItems), ", "), rem)
	}
	sort.Strings(scopeIssues)
	return githubAuditRow(repo, key, title, "medium", StatusGap,
		"cloud OIDC jobs without environment protection or a meaningful custom subject: "+strings.Join(limitStrings(scopeIssues, maxDetailItems), ", "), rem)
}

type workflowOIDCJob struct {
	workflow       string
	name           string
	hasEnvironment bool
	environment    string
	idTokenWrite   bool
}

// workflowCloudAuthJobs reports whether a workflow contains an OIDC-configured
// cloud-auth action and which jobs lack a concrete environment or id-token grant.
func workflowCloudAuthJobs(w *parsedWorkflow) (bool, []string) {
	var unprotected []string
	jobs := workflowOIDCCloudJobs(w)
	for _, job := range jobs {
		if !job.hasEnvironment || job.environment == "" || !job.idTokenWrite {
			unprotected = append(unprotected, job.name)
		}
	}
	sort.Strings(unprotected)
	return len(jobs) > 0, unprotected
}

func workflowOIDCCloudJobs(w *parsedWorkflow) []workflowOIDCJob {
	var out []workflowOIDCJob
	for jobName, job := range w.Jobs {
		if conditionAlwaysFalse(job.If) {
			continue
		}
		usesOIDC := false
		for _, step := range job.Steps {
			if !conditionAlwaysFalse(step.If) && stepUsesCloudOIDC(step) {
				usesOIDC = true
				break
			}
		}
		if !usesOIDC {
			continue
		}
		environment, hasEnvironment := workflowEnvironmentName(job.Environment)
		out = append(out, workflowOIDCJob{
			name:           jobName,
			hasEnvironment: hasEnvironment,
			environment:    environment,
			idTokenWrite:   jobHasIDTokenWrite(w, job),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func stepUsesCloudOIDC(step workflowStep) bool {
	input := func(key string) string {
		for inputKey, raw := range step.With {
			if strings.EqualFold(strings.TrimSpace(inputKey), key) {
				if raw == nil {
					return ""
				}
				return strings.TrimSpace(fmt.Sprint(raw))
			}
		}
		return ""
	}
	switch {
	case actionReferenceMatches(step.Uses, "aws-actions/configure-aws-credentials"):
		return input("role-to-assume") != "" && input("aws-access-key-id") == "" && input("aws-secret-access-key") == ""
	case actionReferenceMatches(step.Uses, "google-github-actions/auth"):
		return input("workload_identity_provider") != "" && input("credentials_json") == ""
	case actionReferenceMatches(step.Uses, "azure/login"):
		return input("creds") == "" && input("client-id") != "" && input("tenant-id") != ""
	case actionReferenceMatches(step.Uses, "hashicorp/vault-action"):
		return strings.EqualFold(input("method"), "jwt")
	default:
		return false
	}
}

func jobHasIDTokenWrite(w *parsedWorkflow, job workflowJob) bool {
	permissions := w.Permissions
	if job.Permissions != nil {
		permissions = job.Permissions
	}
	switch value := permissions.(type) {
	case string:
		return strings.EqualFold(strings.TrimSpace(value), "write-all")
	case map[string]any:
		for scope, raw := range value {
			permissionValue, ok := raw.(string)
			if strings.EqualFold(strings.TrimSpace(scope), "id-token") && ok {
				return strings.EqualFold(strings.TrimSpace(permissionValue), "write")
			}
		}
	}
	return false
}

func workflowEnvironmentName(environment any) (string, bool) {
	var name string
	switch value := environment.(type) {
	case string:
		name = strings.TrimSpace(value)
	case map[string]any:
		for key, raw := range value {
			if strings.EqualFold(strings.TrimSpace(key), "name") {
				if raw == nil {
					return "", false
				}
				name = strings.TrimSpace(fmt.Sprint(raw))
				break
			}
		}
	}
	if name == "" {
		return "", false
	}
	if workflowExprPattern.MatchString(name) {
		return "", true
	}
	return name, true
}

func githubEnvironmentProtected(environment *github.Environment, customRuleSets ...[]*github.CustomDeploymentProtectionRule) bool {
	if environment == nil {
		return false
	}
	if policy := environment.DeploymentBranchPolicy; policy != nil &&
		(policy.GetProtectedBranches() || policy.GetCustomBranchPolicies()) {
		return true
	}
	for _, reviewer := range environment.Reviewers {
		if reviewer != nil && (reviewer.GetID() > 0 || strings.TrimSpace(reviewer.GetType()) != "") {
			return true
		}
	}
	for _, rule := range environment.ProtectionRules {
		if rule == nil || !strings.EqualFold(strings.TrimSpace(rule.GetType()), "required_reviewers") {
			continue
		}
		for _, reviewer := range rule.Reviewers {
			if reviewer != nil && (reviewer.Reviewer != nil || strings.TrimSpace(reviewer.GetType()) != "") {
				return true
			}
		}
	}
	for _, rules := range customRuleSets {
		for _, rule := range rules {
			if rule != nil && rule.GetEnabled() && rule.App != nil && strings.TrimSpace(rule.App.GetSlug()) != "" {
				return true
			}
		}
	}
	return false
}

func meaningfulOIDCClaimKeys(keys []string, jobs []workflowOIDCJob) []string {
	allHaveEnvironment := len(jobs) > 0
	for _, job := range jobs {
		allHaveEnvironment = allHaveEnvironment && job.hasEnvironment
	}
	var meaningful []string
	seen := map[string]bool{}
	for _, key := range keys {
		key = strings.ToLower(strings.TrimSpace(key))
		strong := key == "ref" || key == "sha" || key == "job_workflow_ref" || (key == "environment" && allHaveEnvironment)
		if strong && !seen[key] {
			seen[key] = true
			meaningful = append(meaningful, key)
		}
	}
	sort.Strings(meaningful)
	return meaningful
}
