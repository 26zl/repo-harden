package repoharden

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-github/v88/github"
)

type recordedCall struct {
	method, path, body string
}

func recordingClient(calls *[]recordedCall) *github.Client {
	return mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := ""
		if req.Body != nil {
			b, _ := io.ReadAll(req.Body)
			body = string(b)
		}
		*calls = append(*calls, recordedCall{req.Method, req.URL.Path, body})
		if req.Method == http.MethodGet && req.URL.Path == "/repos/me/app/actions/permissions" {
			return jsonResponse(`{"enabled":true,"allowed_actions":"all","sha_pinning_required":false}`), nil
		}
		return jsonResponse(`{}`), nil
	})})
}

func TestActionsAllowlistApplySendsEmptyPatterns(t *testing.T) {
	var calls []recordedCall
	ctl := controlByKey(t, "actions-allowlist")
	if err := ctl.Apply(context.Background(), recordingClient(&calls), "me", "app"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 {
		t.Fatalf("apply calls = %+v, want permissions GET, permissions PUT, then selected-actions PUT", calls)
	}
	if calls[0].method != http.MethodGet || calls[0].path != "/repos/me/app/actions/permissions" {
		t.Errorf("first call = %+v, want current-policy GET", calls[0])
	}
	if calls[1].path != "/repos/me/app/actions/permissions" || !strings.Contains(calls[1].body, `"allowed_actions":"selected"`) || !strings.Contains(calls[1].body, `"sha_pinning_required":true`) {
		t.Errorf("second call = %+v, want selected policy with SHA pinning", calls[1])
	}
	if calls[2].path != "/repos/me/app/actions/permissions/selected-actions" {
		t.Errorf("third call path = %s, want selected-actions", calls[2].path)
	}
	// the PUT must carry patterns_allowed explicitly so existing custom patterns are cleared
	for _, want := range []string{`"github_owned_allowed":true`, `"verified_allowed":true`, `"patterns_allowed":[]`} {
		if !strings.Contains(calls[2].body, want) {
			t.Errorf("selected-actions body missing %s: %s", want, calls[2].body)
		}
	}
}

func TestActionsAllowlistRevertRestoresPrior(t *testing.T) {
	var calls []recordedCall
	ctl := controlByKey(t, "actions-allowlist")
	prior := `{"enabled":true,"allowed_actions":"selected","github_owned_allowed":true,"verified_allowed":false,"patterns_allowed":["acme/*"]}`
	if err := ctl.Revert(context.Background(), recordingClient(&calls), "me", "app", prior); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("revert calls = %+v, want 2", calls)
	}
	if !strings.Contains(calls[0].body, `"allowed_actions":"selected"`) {
		t.Errorf("first revert call body = %s, want selected policy", calls[0].body)
	}
	for _, want := range []string{`"github_owned_allowed":true`, `"verified_allowed":false`, `"patterns_allowed":["acme/*"]`} {
		if !strings.Contains(calls[1].body, want) {
			t.Errorf("restored allowlist body missing %s: %s", want, calls[1].body)
		}
	}
}

func TestActionsAllowlistRevertLegacyAndEmptyPrior(t *testing.T) {
	ctl := controlByKey(t, "actions-allowlist")

	var calls []recordedCall
	if err := ctl.Revert(context.Background(), recordingClient(&calls), "me", "app", "all"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || !strings.Contains(calls[0].body, `"allowed_actions":"all"`) {
		t.Fatalf("legacy string prior: calls = %+v, want one PUT restoring all", calls)
	}

	calls = nil
	if err := ctl.Revert(context.Background(), recordingClient(&calls), "me", "app", ""); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Fatalf("empty prior must not call the API, got %+v", calls)
	}
}

func TestActionsAllowlistMatchesExactAppliedPolicy(t *testing.T) {
	ctl := controlByKey(t, "actions-allowlist")
	if ctl.MatchesHardened == nil {
		t.Fatal("actions-allowlist must reject drift before revert")
	}
	policy := func(allowed string, verified bool, patterns ...string) DetectResult {
		return DetectResult{Status: StatusCompliant, Prior: encodePrior(actionsAllowlistPrior{
			Enabled: github.Ptr(true), AllowedActions: allowed, SHAPinningRequired: github.Ptr(true),
			GithubOwnedAllowed: github.Ptr(true), VerifiedAllowed: github.Ptr(verified), PatternsAllowed: patterns,
		})}
	}
	priorAll := encodePrior(actionsAllowlistPrior{Enabled: github.Ptr(true), AllowedActions: "all", SHAPinningRequired: github.Ptr(false)})
	if !ctl.MatchesHardened(policy("selected", true), priorAll) {
		t.Error("exact generic policy written from an all-actions prior must match")
	}
	if ctl.MatchesHardened(policy("local_only", false), priorAll) {
		t.Error("a later local-only policy is stricter drift and must never be overwritten")
	}
	if ctl.MatchesHardened(policy("selected", false, "acme/action@*"), priorAll) {
		t.Error("a later alternate selected policy must not match the generic applied state")
	}
	priorNarrow := encodePrior(actionsAllowlistPrior{
		Enabled: github.Ptr(true), AllowedActions: "selected", SHAPinningRequired: github.Ptr(false),
		GithubOwnedAllowed: github.Ptr(false), VerifiedAllowed: github.Ptr(false), PatternsAllowed: []string{"acme/action@*"},
	})
	if !ctl.MatchesHardened(policy("selected", false, "acme/action@*"), priorNarrow) {
		t.Error("the exact preserved narrow policy with SHA/GitHub-owned hardening must match")
	}
	if ctl.MatchesHardened(policy("selected", true, "acme/action@*"), priorNarrow) {
		t.Error("verified-creator drift must be rejected")
	}
}

func TestTokenReadonlyRevertRestoresPrior(t *testing.T) {
	ctl := controlByKey(t, "token-readonly")

	var calls []recordedCall
	prior := `{"default_workflow_permissions":"write","can_approve_pull_request_reviews":true}`
	if err := ctl.Revert(context.Background(), recordingClient(&calls), "me", "app", prior); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0].path != "/repos/me/app/actions/permissions/workflow" {
		t.Fatalf("revert calls = %+v, want one workflow-permissions PUT", calls)
	}
	for _, want := range []string{`"default_workflow_permissions":"write"`, `"can_approve_pull_request_reviews":true`} {
		if !strings.Contains(calls[0].body, want) {
			t.Errorf("restored permissions body missing %s: %s", want, calls[0].body)
		}
	}

	calls = nil
	if err := ctl.Revert(context.Background(), recordingClient(&calls), "me", "app", "read"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || !strings.Contains(calls[0].body, `"default_workflow_permissions":"read"`) ||
		!strings.Contains(calls[0].body, `"can_approve_pull_request_reviews":false`) {
		t.Fatalf("legacy bare prior: calls = %+v, want read/no-approve PUT", calls)
	}

	calls = nil
	if err := ctl.Revert(context.Background(), recordingClient(&calls), "me", "app", ""); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Fatalf("empty prior must not call the API, got %+v", calls)
	}
}

func TestValidateControlPriorTable(t *testing.T) {
	cases := []struct {
		control, prior string
		wantErr        bool
	}{
		{"dependabot-alerts", "enabled", false},
		{"dependabot-alerts", "sideways", true},
		{"dependabot-fixes", "disabled", false},
		{"private-vulnerability-reporting", "enabled", false},
		{"token-readonly", `{"default_workflow_permissions":"write","can_approve_pull_request_reviews":true}`, false},
		{"token-readonly", `{"default_workflow_permissions":"admin"}`, true},
		{"token-readonly", "not json", true},
		{"actions-allowlist", `{"allowed_actions":"selected"}`, false},
		{"actions-allowlist", `{"allowed_actions":"all"}`, false},
		{"actions-allowlist", `{"allowed_actions":"weird"}`, true},
		{"actions-allowlist", "not json", true},
		{"branch-protection", "", false},
		{"branch-protection", `{"name":"` + controlRulesetName + `"}`, false},
		{"branch-protection", `{"name":"user-ruleset"}`, true},
		{"branch-protection", "not json", true},
		{"secret-scanning", `{"secret_scanning":"enabled","push_protection":"disabled"}`, false},
		{"secret-scanning", `{"secret_scanning":"maybe","push_protection":"disabled"}`, true},
		{"code-scanning", "configured", false},
		{"code-scanning", "maybe", true},
		{"never-heard-of-it", "x", true},
	}
	for _, c := range cases {
		err := validateControlPrior(c.control, c.prior)
		if (err != nil) != c.wantErr {
			t.Errorf("validateControlPrior(%s, %q) = %v, want error=%v", c.control, c.prior, err, c.wantErr)
		}
	}
}

func TestRulesetMatchesManagedSpec(t *testing.T) {
	spec := managedRulesetSpec("me", "app")
	if !rulesetMatchesManagedSpec(&spec) {
		t.Fatal("the spec Apply writes must match itself")
	}

	stronger := managedRulesetSpec("me", "app")
	stronger.Rules.RequiredSignatures = &github.EmptyRuleParameters{}
	if rulesetMatchesManagedSpec(&stronger) {
		t.Error("a user-strengthened ruleset must not match the managed spec")
	}

	tweaked := managedRulesetSpec("me", "app")
	tweaked.Rules.PullRequest = &github.PullRequestRuleParameters{RequiredApprovingReviewCount: 2, RequiredReviewThreadResolution: true}
	if rulesetMatchesManagedSpec(&tweaked) {
		t.Error("changed pull-request parameters must not match the managed spec")
	}

	bypass := managedRulesetSpec("me", "app")
	bypass.BypassActors = []*github.BypassActor{{}}
	if rulesetMatchesManagedSpec(&bypass) {
		t.Error("bypass actors must not match the managed spec")
	}
}

func TestBranchProtectionMatchesHardened(t *testing.T) {
	ctl := controlByKey(t, "branch-protection")
	if ctl.MatchesHardened == nil {
		t.Fatal("branch-protection must define MatchesHardened")
	}
	spec := managedRulesetSpec("me", "app")
	exact := DetectResult{Status: StatusCompliant, Prior: encodePrior(spec)}
	if !ctl.MatchesHardened(exact, "") {
		t.Error("exact managed ruleset must count as hardened state")
	}
	spec.Rules.RequiredSignatures = &github.EmptyRuleParameters{}
	extended := DetectResult{Status: StatusCompliant, Prior: encodePrior(spec)}
	if ctl.MatchesHardened(extended, "") {
		t.Error("user-extended ruleset must be refused so revert cannot destroy it")
	}
	prior := managedRulesetSpec("me", "app")
	prior.Enforcement = github.RulesetEnforcementDisabled
	prior.Rules.PullRequest.RequiredApprovingReviewCount = 0
	prior.Rules.RequiredSignatures = &github.EmptyRuleParameters{}
	merged, err := mergeManagedRuleset(&prior, "me", "app")
	if err != nil {
		t.Fatal(err)
	}
	if !ctl.MatchesHardened(DetectResult{Status: StatusCompliant, Prior: encodePrior(merged)}, encodePrior(prior)) {
		t.Error("a stronger pre-existing rule preserved by merge must count as the expected applied state")
	}
	merged.Rules.Creation = &github.EmptyRuleParameters{}
	if ctl.MatchesHardened(DetectResult{Status: StatusCompliant, Prior: encodePrior(merged)}, encodePrior(prior)) {
		t.Error("post-harden rule drift must be refused")
	}
	if ctl.MatchesHardened(DetectResult{Status: StatusCompliant}, "") {
		t.Error("compliant without a captured ruleset must be refused")
	}
	if ctl.MatchesHardened(DetectResult{Status: StatusGap, Prior: encodePrior(managedRulesetSpec("me", "app"))}, "") {
		t.Error("gap status must never count as hardened state")
	}
}
