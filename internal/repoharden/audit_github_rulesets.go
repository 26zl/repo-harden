package repoharden

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/go-github/v88/github"
)

// rulesetListCache lazily shares one ruleset-list fetch (incl. org-inherited rulesets) and per-ruleset detail fetches per repository.
type rulesetListCache struct {
	once    sync.Once
	sets    []*github.RepositoryRuleset
	err     error
	mu      sync.Mutex
	details map[int64]rulesetDetailResult
}

type rulesetDetailResult struct {
	full *github.RepositoryRuleset
	err  error
}

func (rc *rulesetListCache) get(ctx context.Context, c *github.Client, owner, name string) ([]*github.RepositoryRuleset, error) {
	rc.once.Do(func() {
		rc.sets, rc.err = allRepoRulesets(ctx, c, owner, name, true)
	})
	return rc.sets, rc.err
}

func (rc *rulesetListCache) detail(ctx context.Context, c *github.Client, owner, name string, id int64) (*github.RepositoryRuleset, error) {
	rc.mu.Lock()
	if cached, ok := rc.details[id]; ok {
		rc.mu.Unlock()
		return cached.full, cached.err
	}
	rc.mu.Unlock()
	full, _, err := c.Repositories.GetRuleset(ctx, owner, name, id, true)
	rc.mu.Lock()
	if rc.details == nil {
		rc.details = map[int64]rulesetDetailResult{}
	}
	rc.details[id] = rulesetDetailResult{full: full, err: err}
	rc.mu.Unlock()
	return full, err
}

func allRepoRulesets(ctx context.Context, c *github.Client, owner, name string, includeParents bool) ([]*github.RepositoryRuleset, error) {
	opts := &github.RepositoryListRulesetsOptions{ListOptions: github.ListOptions{PerPage: 100}}
	if includeParents {
		opts.IncludesParents = github.Ptr(true)
	}
	var all []*github.RepositoryRuleset
	var pager githubPager
	for {
		sets, resp, err := c.Repositories.GetAllRulesets(ctx, owner, name, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, sets...)
		next, done, err := pager.next(resp)
		if err != nil {
			return nil, err
		}
		if done {
			return all, nil
		}
		opts.Page = next
	}
}

func githubActiveRuleTypes(ctx context.Context, c *github.Client, owner, name, branch string, rc *rulesetListCache) (map[string]bool, error) {
	sets, err := rc.get(ctx, c, owner, name)
	if err != nil {
		return nil, err
	}
	rules := map[string]bool{}
	for _, summary := range sets {
		if summary.Enforcement != github.RulesetEnforcementActive {
			continue
		}
		if t := summary.GetTarget(); t == nil || *t != github.RulesetTargetBranch {
			continue
		}
		full, err := rc.detail(ctx, c, owner, name, summary.GetID())
		if err != nil {
			return nil, fmt.Errorf("read ruleset %d: %w", summary.GetID(), err)
		}
		if full == nil {
			return nil, fmt.Errorf("read ruleset %d: empty response", summary.GetID())
		}
		if full.Rules == nil || !rulesetTargetsBranch(full, branch) {
			continue
		}
		r := full.Rules
		if r.PullRequest != nil {
			rules["pull_request"] = true
		}
		if r.PullRequest != nil && r.PullRequest.RequiredApprovingReviewCount >= 1 {
			rules["review"] = true
		}
		if r.PullRequest != nil && r.PullRequest.RequiredReviewThreadResolution {
			rules["thread_resolution"] = true
		}
		if r.RequiredStatusChecks != nil && len(r.RequiredStatusChecks.RequiredStatusChecks) > 0 {
			rules["required_status_checks"] = true
		}
		if r.NonFastForward != nil {
			rules["non_fast_forward"] = true
		}
		if r.Deletion != nil {
			rules["deletion"] = true
		}
		if r.RequiredLinearHistory != nil {
			rules["required_linear_history"] = true
		}
		if r.RequiredSignatures != nil {
			rules["required_signatures"] = true
		}
		if r.Workflows != nil {
			rules["workflows"] = true
		}
		if r.MergeQueue != nil {
			rules["merge_queue"] = true
		}
	}
	return rules, nil
}

func rulesetTargetsBranch(rs *github.RepositoryRuleset, branch string) bool {
	if rs.Conditions == nil || rs.Conditions.RefName == nil {
		return true
	}
	ref := "refs/heads/" + branch
	cond := rs.Conditions.RefName
	included := false
	for _, p := range cond.Include {
		if refPatternMatches(p, ref, branch) {
			included = true
			break
		}
	}
	if !included {
		return false
	}
	for _, p := range cond.Exclude {
		if refPatternMatches(p, ref, branch) {
			return false
		}
	}
	return true
}

func refPatternMatches(pattern, ref, branch string) bool {
	switch pattern {
	case "~ALL":
		return true
	case "~DEFAULT_BRANCH":
		return branch != ""
	}
	if branch == "" {
		return false
	}
	return globMatch(pattern, ref)
}

// GitHub fnmatch-style ref matching: "*" stays in a segment, "**" crosses "/", "?" is one non-"/" char.
func globMatch(pattern, s string) bool {
	patternRunes := []rune(pattern)
	valueRunes := []rune(s)
	type state struct{ pattern, value int }
	memo := map[state]bool{}
	seen := map[state]bool{}
	var match func(int, int) bool
	match = func(pi, si int) bool {
		key := state{pi, si}
		if seen[key] {
			return memo[key]
		}
		seen[key] = true
		var result bool
		switch {
		case pi == len(patternRunes):
			result = si == len(valueRunes)
		case patternRunes[pi] == '*' && pi+1 < len(patternRunes) && patternRunes[pi+1] == '*':
			result = match(pi+2, si) || (si < len(valueRunes) && match(pi, si+1))
		case patternRunes[pi] == '*':
			result = match(pi+1, si) ||
				(si < len(valueRunes) && valueRunes[si] != '/' && match(pi, si+1))
		case patternRunes[pi] == '?':
			result = si < len(valueRunes) && valueRunes[si] != '/' && match(pi+1, si+1)
		default:
			result = si < len(valueRunes) && patternRunes[pi] == valueRunes[si] && match(pi+1, si+1)
		}
		memo[key] = result
		return result
	}
	return match(0, 0)
}

func branchProtectionMissing(p *github.Protection, rules map[string]bool, allowZeroApprovals bool) []string {
	var missing []string
	if (p == nil || p.RequiredPullRequestReviews == nil) && !rules["pull_request"] {
		missing = append(missing, "pull request gate")
	}
	if !allowZeroApprovals &&
		(p == nil || p.RequiredPullRequestReviews == nil || p.RequiredPullRequestReviews.RequiredApprovingReviewCount < 1) &&
		!rules["review"] {
		missing = append(missing, "approval review")
	}
	if (p == nil || p.RequiredStatusChecks == nil || (len(p.RequiredStatusChecks.GetContexts()) == 0 && len(p.RequiredStatusChecks.GetChecks()) == 0)) && !rules["required_status_checks"] {
		missing = append(missing, "status checks")
	}
	if p != nil && (p.EnforceAdmins == nil || !p.EnforceAdmins.Enabled) {
		missing = append(missing, "admin enforcement")
	}
	if (p == nil || p.RequiredConversationResolution == nil || !p.RequiredConversationResolution.Enabled) && !rules["thread_resolution"] {
		missing = append(missing, "conversation resolution")
	}
	if (p == nil || (p.AllowForcePushes != nil && p.AllowForcePushes.Enabled)) && !rules["non_fast_forward"] {
		missing = append(missing, "force-push disabled")
	}
	if (p == nil || (p.AllowDeletions != nil && p.AllowDeletions.Enabled)) && !rules["deletion"] {
		missing = append(missing, "deletion disabled")
	}
	if (p == nil || p.RequireLinearHistory == nil || !p.RequireLinearHistory.Enabled) && !rules["required_linear_history"] {
		missing = append(missing, "linear history")
	}
	return missing
}

// allRuleTypes marks every ruleset-enforceable protection as present, isolating classic-only gaps.
var allRuleTypes = map[string]bool{
	"pull_request":            true,
	"review":                  true,
	"required_status_checks":  true,
	"thread_resolution":       true,
	"non_fast_forward":        true,
	"deletion":                true,
	"required_linear_history": true,
}
