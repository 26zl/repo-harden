package repoharden

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-github/v88/github"
)

func managedRulesetSpec(owner, name string) github.RepositoryRuleset {
	spec := github.RepositoryRuleset{
		Name:        controlRulesetName,
		Target:      github.Ptr(github.RulesetTargetBranch),
		Enforcement: github.RulesetEnforcementActive,
		Conditions: &github.RepositoryRulesetConditions{
			RefName: &github.RepositoryRulesetRefConditionParameters{
				Include: []string{"~DEFAULT_BRANCH"},
				Exclude: []string{},
			},
		},
		Rules: &github.RepositoryRulesetRules{
			PullRequest:           &github.PullRequestRuleParameters{RequiredApprovingReviewCount: 0, RequiredReviewThreadResolution: true},
			Deletion:              &github.EmptyRuleParameters{},
			NonFastForward:        &github.EmptyRuleParameters{},
			RequiredLinearHistory: &github.EmptyRuleParameters{},
		},
	}
	if owner != "" || name != "" {
		spec.Source = owner + "/" + name
		spec.SourceType = github.Ptr(github.RulesetSourceTypeRepository)
	}
	return spec
}

// mergeManagedRuleset adds the minimum requirements while preserving stronger
// rules, conditions, and bypass configuration from a same-name ruleset.
func mergeManagedRuleset(existing *github.RepositoryRuleset, owner, name string) (github.RepositoryRuleset, error) {
	if existing == nil {
		return github.RepositoryRuleset{}, errors.New("existing ruleset is empty")
	}
	if target := existing.GetTarget(); target == nil || *target != github.RulesetTargetBranch {
		return github.RepositoryRuleset{}, fmt.Errorf("ruleset %q targets %v, not branches", existing.Name, target)
	}

	var merged github.RepositoryRuleset
	data, err := json.Marshal(existing)
	if err != nil {
		return github.RepositoryRuleset{}, fmt.Errorf("copy existing ruleset: %w", err)
	}
	if err := json.Unmarshal(data, &merged); err != nil {
		return github.RepositoryRuleset{}, fmt.Errorf("copy existing ruleset: %w", err)
	}
	merged.Name = controlRulesetName
	merged.Source = owner + "/" + name
	merged.SourceType = github.Ptr(github.RulesetSourceTypeRepository)
	merged.Target = github.Ptr(github.RulesetTargetBranch)
	merged.Enforcement = github.RulesetEnforcementActive
	if merged.Conditions == nil {
		merged.Conditions = &github.RepositoryRulesetConditions{}
	}
	if merged.Conditions.RefName == nil {
		merged.Conditions.RefName = &github.RepositoryRulesetRefConditionParameters{}
	}
	if !stringSliceContains(merged.Conditions.RefName.Include, "~DEFAULT_BRANCH") {
		merged.Conditions.RefName.Include = append(merged.Conditions.RefName.Include, "~DEFAULT_BRANCH")
	}
	if merged.Conditions.RefName.Exclude == nil {
		merged.Conditions.RefName.Exclude = []string{}
	}
	if merged.Rules == nil {
		merged.Rules = &github.RepositoryRulesetRules{}
	}
	if merged.Rules.PullRequest == nil {
		merged.Rules.PullRequest = &github.PullRequestRuleParameters{}
	}
	merged.Rules.PullRequest.RequiredReviewThreadResolution = true
	if merged.Rules.Deletion == nil {
		merged.Rules.Deletion = &github.EmptyRuleParameters{}
	}
	if merged.Rules.NonFastForward == nil {
		merged.Rules.NonFastForward = &github.EmptyRuleParameters{}
	}
	if merged.Rules.RequiredLinearHistory == nil {
		merged.Rules.RequiredLinearHistory = &github.EmptyRuleParameters{}
	}
	return github.RepositoryRuleset{
		Name:         merged.Name,
		Source:       merged.Source,
		SourceType:   merged.SourceType,
		Target:       merged.Target,
		Enforcement:  merged.Enforcement,
		BypassActors: merged.BypassActors,
		Conditions:   merged.Conditions,
		Rules:        merged.Rules,
	}, nil
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func rulesetConfigEqual(a, b *github.RepositoryRuleset) bool {
	if a == nil || b == nil || a.Name != b.Name || a.Enforcement != b.Enforcement {
		return false
	}
	if at, bt := a.GetTarget(), b.GetTarget(); at == nil || bt == nil || *at != *bt {
		return false
	}
	return encodePrior(a.Conditions) == encodePrior(b.Conditions) &&
		encodePrior(a.Rules) == encodePrior(b.Rules) &&
		encodePrior(a.BypassActors) == encodePrior(b.BypassActors)
}

func rulesetMatchesAppliedPrior(result DetectResult, prior string) bool {
	if result.Status != StatusCompliant || result.Prior == "" {
		return false
	}
	var live github.RepositoryRuleset
	if json.Unmarshal([]byte(result.Prior), &live) != nil {
		return false
	}
	if strings.TrimSpace(prior) == "" || strings.TrimSpace(prior) == "null" {
		spec := managedRulesetSpec("", "")
		return rulesetConfigEqual(&live, &spec)
	}
	var captured github.RepositoryRuleset
	if json.Unmarshal([]byte(prior), &captured) != nil {
		return false
	}
	expected, err := mergeManagedRuleset(&captured, "", "")
	if err != nil {
		return false
	}
	return rulesetConfigEqual(&live, &expected)
}

func rulesetMatchesManagedSpec(rs *github.RepositoryRuleset) bool {
	if rs == nil || rs.Name != controlRulesetName || rs.Enforcement != github.RulesetEnforcementActive {
		return false
	}
	if target := rs.GetTarget(); target == nil || *target != github.RulesetTargetBranch {
		return false
	}
	if len(rs.BypassActors) != 0 {
		return false
	}
	spec := managedRulesetSpec("", "")
	return encodePrior(rs.Conditions) == encodePrior(spec.Conditions) && encodePrior(rs.Rules) == encodePrior(spec.Rules)
}

func managedRulesetValid(rs *github.RepositoryRuleset, branch string) bool {
	if rs == nil || rs.Rules == nil || rs.Enforcement != github.RulesetEnforcementActive {
		return false
	}
	if target := rs.GetTarget(); target == nil || *target != github.RulesetTargetBranch {
		return false
	}
	if !rulesetTargetsBranch(rs, branch) {
		return false
	}
	pullRequest := rs.Rules.PullRequest
	if pullRequest == nil || !pullRequest.RequiredReviewThreadResolution {
		return false
	}
	return rs.Rules.Deletion != nil && rs.Rules.NonFastForward != nil && rs.Rules.RequiredLinearHistory != nil
}
