package repoharden

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-github/v88/github"
)

// mockClient builds a github.Client whose transport routes by "METHOD path".
func mockClient(routes map[string]string) *github.Client {
	return mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		key := req.Method + " " + req.URL.Path
		if body, ok := routes[key]; ok {
			return jsonResponse(body), nil
		}
		return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header),
			Body: http.NoBody}, nil
	})})
}

func controlByKey(t *testing.T, key string) Control {
	t.Helper()
	for _, c := range baseline {
		if c.Key == key {
			return c
		}
	}
	t.Fatalf("control %q not registered", key)
	return Control{}
}

func TestSecurityMdDetectErrorsOnNon404(t *testing.T) {
	ctl := controlByKey(t, "security-md")
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
	})})
	res := ctl.Detect(context.Background(), client, "me", "app", &github.Repository{})
	if res.Status != StatusError {
		t.Fatalf("non-404 GetContents error must yield StatusError, got %s (%s)", res.Status, res.Detail)
	}
}

func TestDependabotAlertsDetect(t *testing.T) {
	ctl := controlByKey(t, "dependabot-alerts")

	on := mockClient(map[string]string{"GET /repos/me/app/vulnerability-alerts": ``})
	// matched route (200) => enabled; unmatched (404) => disabled
	if got := ctl.Detect(context.Background(), on, "me", "app", &github.Repository{}); got.Status != StatusCompliant {
		t.Fatalf("enabled repo: got %s, want compliant", got.Status)
	}

	off := mockClient(map[string]string{})
	res := ctl.Detect(context.Background(), off, "me", "app", &github.Repository{})
	if res.Status != StatusGap {
		t.Fatalf("disabled repo: got %s, want gap", res.Status)
	}
	if res.Prior != "disabled" {
		t.Fatalf("prior: got %q, want disabled", res.Prior)
	}
}

func TestTokenReadonlyDetect(t *testing.T) {
	ctl := controlByKey(t, "token-readonly")

	readonly := mockClient(map[string]string{
		"GET /repos/me/app/actions/permissions/workflow": `{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}`,
	})
	if got := ctl.Detect(context.Background(), readonly, "me", "app", nil); got.Status != StatusCompliant {
		t.Fatalf("read+no-approve: got %s, want compliant", got.Status)
	}

	writable := mockClient(map[string]string{
		"GET /repos/me/app/actions/permissions/workflow": `{"default_workflow_permissions":"write","can_approve_pull_request_reviews":true}`,
	})
	res := ctl.Detect(context.Background(), writable, "me", "app", nil)
	if res.Status != StatusGap {
		t.Fatalf("write: got %s, want gap", res.Status)
	}
	var prior workflowPermissionPrior
	if err := json.Unmarshal([]byte(res.Prior), &prior); err != nil {
		t.Fatalf("prior is not json: %v", err)
	}
	if prior.Default != "write" || prior.CanApprove == nil || !*prior.CanApprove {
		t.Fatalf("prior: got %+v, want write/can-approve", prior)
	}
}

func TestDependabotFixesDetect(t *testing.T) {
	ctl := controlByKey(t, "dependabot-fixes")
	on := mockClient(map[string]string{"GET /repos/me/app/automated-security-fixes": `{"enabled":true,"paused":false}`})
	if got := ctl.Detect(context.Background(), on, "me", "app", nil); got.Status != StatusCompliant {
		t.Fatalf("enabled: got %s, want compliant", got.Status)
	}
	off := mockClient(map[string]string{"GET /repos/me/app/automated-security-fixes": `{"enabled":false,"paused":false}`})
	if got := ctl.Detect(context.Background(), off, "me", "app", nil); got.Status != StatusGap {
		t.Fatalf("disabled: got %s, want gap", got.Status)
	}
}

func TestActionsAllowlistDetect(t *testing.T) {
	ctl := controlByKey(t, "actions-allowlist")
	selected := mockClient(map[string]string{
		"GET /repos/me/app/actions/permissions":                  `{"enabled":true,"allowed_actions":"selected"}`,
		"GET /repos/me/app/actions/permissions/selected-actions": `{"github_owned_allowed":true,"verified_allowed":true}`,
	})
	if got := ctl.Detect(context.Background(), selected, "me", "app", nil); got.Status != StatusCompliant {
		t.Fatalf("selected: got %s, want compliant", got.Status)
	}
	open := mockClient(map[string]string{
		"GET /repos/me/app/actions/permissions": `{"enabled":true,"allowed_actions":"all"}`,
	})
	res := ctl.Detect(context.Background(), open, "me", "app", nil)
	var prior actionsAllowlistPrior
	if err := json.Unmarshal([]byte(res.Prior), &prior); err != nil {
		t.Fatalf("prior is not json: %v", err)
	}
	if res.Status != StatusGap || prior.AllowedActions != "all" {
		t.Fatalf("all: got status=%s prior=%+v, want gap/all", res.Status, prior)
	}
}

func TestActionsAllowlistDisabledAndPatterns(t *testing.T) {
	ctl := controlByKey(t, "actions-allowlist")
	disabled := mockClient(map[string]string{
		"GET /repos/me/app/actions/permissions": `{"enabled":false}`,
	})
	if got := ctl.Detect(context.Background(), disabled, "me", "app", nil); got.Status != StatusSkipped {
		t.Fatalf("disabled actions: got %s, want skipped", got.Status)
	}
	patterns := mockClient(map[string]string{
		"GET /repos/me/app/actions/permissions":                  `{"enabled":true,"allowed_actions":"selected"}`,
		"GET /repos/me/app/actions/permissions/selected-actions": `{"github_owned_allowed":true,"verified_allowed":true,"patterns_allowed":["my-org/*"]}`,
	})
	if got := ctl.Detect(context.Background(), patterns, "me", "app", nil); got.Status != StatusGap {
		t.Fatalf("extra patterns: got %s, want gap", got.Status)
	}
}

func TestCodeScanningCompliantViaAdvancedSetup(t *testing.T) {
	ctl := controlByKey(t, "code-scanning")
	// recent analysis -> compliant (future date keeps this deterministic)
	recent := mockClient(map[string]string{
		"GET /repos/me/app/code-scanning/default-setup": `{"state":"not-configured"}`,
		"GET /repos/me/app/code-scanning/analyses":      `[{"id":1,"created_at":"2999-01-01T00:00:00Z"}]`,
	})
	if got := ctl.Detect(context.Background(), recent, "me", "app", &github.Repository{}); got.Status != StatusCompliant {
		t.Fatalf("recent analysis: got %s (%s), want compliant", got.Status, got.Detail)
	}
	// stale analysis -> gap (one old analysis does not prove scanning still runs)
	stale := mockClient(map[string]string{
		"GET /repos/me/app/code-scanning/default-setup": `{"state":"not-configured"}`,
		"GET /repos/me/app/code-scanning/analyses":      `[{"id":1,"created_at":"2020-01-01T00:00:00Z"}]`,
	})
	if got := ctl.Detect(context.Background(), stale, "me", "app", &github.Repository{}); got.Status != StatusGap {
		t.Fatalf("stale analysis: got %s, want gap", got.Status)
	}
}

func TestBranchProtectionDetect(t *testing.T) {
	ctl := controlByKey(t, "branch-protection")
	repo := &github.Repository{DefaultBranch: github.Ptr("main")}
	has := mockClient(map[string]string{
		"GET /repos/me/app/rulesets":   `[{"id":7,"name":"repo-harden","enforcement":"active","target":"branch"}]`,
		"GET /repos/me/app/rulesets/7": `{"id":7,"name":"repo-harden","enforcement":"active","target":"branch","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"rules":[{"type":"pull_request","parameters":{"required_approving_review_count":1,"required_review_thread_resolution":true}},{"type":"non_fast_forward"},{"type":"required_linear_history"}]}`,
	})
	if got := ctl.Detect(context.Background(), has, "me", "app", repo); got.Status != StatusCompliant {
		t.Fatalf("valid ruleset: got %s (%s), want compliant", got.Status, got.Detail)
	}
	// active but weak (no thread resolution) -> not compliant
	weak := mockClient(map[string]string{
		"GET /repos/me/app/rulesets":   `[{"id":8,"name":"repo-harden","enforcement":"active","target":"branch"}]`,
		"GET /repos/me/app/rulesets/8": `{"id":8,"name":"repo-harden","enforcement":"active","target":"branch","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"rules":[{"type":"pull_request","parameters":{"required_approving_review_count":0}},{"type":"non_fast_forward"},{"type":"required_linear_history"}]}`,
	})
	if got := ctl.Detect(context.Background(), weak, "me", "app", repo); got.Status != StatusGap {
		t.Fatalf("weak ruleset (0 reviews, no thread resolution): got %s, want gap", got.Status)
	}
	none := mockClient(map[string]string{"GET /repos/me/app/rulesets": `[]`})
	if got := ctl.Detect(context.Background(), none, "me", "app", repo); got.Status != StatusGap {
		t.Fatalf("no ruleset: got %s, want gap", got.Status)
	}
	// present but inactive -> gap, not falsely compliant, AND capture it so revert can restore
	inactive := mockClient(map[string]string{
		"GET /repos/me/app/rulesets":   `[{"id":7,"name":"repo-harden","enforcement":"disabled","target":"branch"}]`,
		"GET /repos/me/app/rulesets/7": `{"id":7,"name":"repo-harden","enforcement":"disabled","target":"branch","rules":[{"type":"pull_request","parameters":{"required_approving_review_count":1}}]}`,
	})
	got := ctl.Detect(context.Background(), inactive, "me", "app", &github.Repository{})
	if got.Status != StatusGap {
		t.Fatalf("inactive ruleset: got %s, want gap", got.Status)
	}
	if got.Prior == "" {
		t.Fatal("inactive same-name ruleset should be captured in Prior for restore")
	}
}

func TestBranchProtectionApplyCreatesRuleset(t *testing.T) {
	var created bool
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost && req.URL.Path == "/repos/me/app/rulesets" {
			created = true
			return jsonResponse(`{"id":7,"name":"repo-harden"}`), nil
		}
		return &http.Response{StatusCode: 404, Header: make(http.Header), Body: http.NoBody}, nil
	})})
	ctl := controlByKey(t, "branch-protection")
	if err := ctl.Apply(context.Background(), client, "me", "app"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !created {
		t.Fatal("apply did not POST a ruleset")
	}
}

func TestBranchProtectionApplyUpdatesExistingInPlace(t *testing.T) {
	var method, path string
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/repos/me/app/rulesets":
			return jsonResponse(`[{"id":7,"name":"repo-harden"}]`), nil
		case req.URL.Path == "/repos/me/app/rulesets/7", req.URL.Path == "/repos/me/app/rulesets":
			method, path = req.Method, req.URL.Path // capture the mutating call (PUT update vs POST create)
			return jsonResponse(`{"id":7,"name":"repo-harden"}`), nil
		}
		return &http.Response{StatusCode: 404, Header: make(http.Header), Body: http.NoBody}, nil
	})})
	ctl := controlByKey(t, "branch-protection")
	if err := ctl.Apply(context.Background(), client, "me", "app"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if method != http.MethodPut || path != "/repos/me/app/rulesets/7" {
		t.Fatalf("apply should UpdateRuleset in place, got %s %s", method, path)
	}
}

func TestBranchProtectionRevertRestoresPriorInPlace(t *testing.T) {
	var updated bool
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/repos/me/app/rulesets":
			return jsonResponse(`[{"id":7,"name":"repo-harden"}]`), nil
		case req.Method == http.MethodPut && req.URL.Path == "/repos/me/app/rulesets/7":
			updated = true
			return jsonResponse(`{"id":7,"name":"repo-harden"}`), nil
		case req.Method == http.MethodDelete && req.URL.Path == "/repos/me/app/rulesets/7":
			t.Error("revert with captured prior should restore in place, not delete")
			return jsonResponse(`{}`), nil
		}
		return &http.Response{StatusCode: 404, Header: make(http.Header), Body: http.NoBody}, nil
	})})
	ctl := controlByKey(t, "branch-protection")
	prior := `{"id":99,"name":"repo-harden","enforcement":"active","target":"branch","rules":[{"type":"pull_request","parameters":{"required_approving_review_count":2}}]}`
	if err := ctl.Revert(context.Background(), client, "me", "app", prior); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if !updated {
		t.Fatal("revert with captured prior should UpdateRuleset in place")
	}
}

func TestBranchProtectionRevertDeletesWhenNoPrior(t *testing.T) {
	var deleted bool
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/repos/me/app/rulesets":
			return jsonResponse(`[{"id":7,"name":"repo-harden"}]`), nil
		case req.Method == http.MethodDelete && req.URL.Path == "/repos/me/app/rulesets/7":
			deleted = true
			return jsonResponse(`{}`), nil
		}
		return &http.Response{StatusCode: 404, Header: make(http.Header), Body: http.NoBody}, nil
	})})
	ctl := controlByKey(t, "branch-protection")
	if err := ctl.Revert(context.Background(), client, "me", "app", ""); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if !deleted {
		t.Fatal("revert with no prior should delete our ruleset")
	}
}

func TestSecretScanningSkippedOnPrivate(t *testing.T) {
	ctl := controlByKey(t, "secret-scanning")
	privateNoLicense := mockClient(map[string]string{
		"GET /repos/me/app": `{"private":true,"security_and_analysis":{}}`,
	})
	res := ctl.Detect(context.Background(), privateNoLicense, "me", "app",
		&github.Repository{Private: github.Ptr(true)})
	if res.Status != StatusSkipped {
		t.Fatalf("private repo: got %s, want skipped", res.Status)
	}
	if !strings.Contains(res.Detail, "license") {
		t.Fatalf("detail should mention license, got %q", res.Detail)
	}
}

func TestSecretScanningDetectPublic(t *testing.T) {
	ctl := controlByKey(t, "secret-scanning")
	on := mockClient(map[string]string{
		"GET /repos/me/app": `{"private":false,"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}`,
	})
	if got := ctl.Detect(context.Background(), on, "me", "app", &github.Repository{Private: github.Ptr(false)}); got.Status != StatusCompliant {
		t.Fatalf("public+on: got %s, want compliant", got.Status)
	}
}

func TestSecurityMdDetect(t *testing.T) {
	ctl := controlByKey(t, "security-md")
	if ctl.Apply != nil {
		t.Fatal("security-md must be report-only (Apply nil)")
	}
	present := mockClient(map[string]string{
		"GET /repos/me/app/contents/SECURITY.md": `{"name":"SECURITY.md","type":"file"}`,
	})
	if got := ctl.Detect(context.Background(), present, "me", "app", nil); got.Status != StatusCompliant {
		t.Fatalf("present: got %s, want compliant", got.Status)
	}
	absent := mockClient(nil) // all 404
	if got := ctl.Detect(context.Background(), absent, "me", "app", nil); got.Status != StatusGap {
		t.Fatalf("absent: got %s, want gap", got.Status)
	}
}

func TestSelectControls(t *testing.T) {
	saved := baseline
	t.Cleanup(func() { baseline = saved })
	baseline = []Control{{Key: "a"}, {Key: "b"}, {Key: "c"}}

	all := selectControls("", "")
	if len(all) != 3 {
		t.Fatalf("no filter: got %d, want 3", len(all))
	}
	only := selectControls("a,c", "")
	if len(only) != 2 || only[0].Key != "a" || only[1].Key != "c" {
		t.Fatalf("--only a,c: got %+v", only)
	}
	skip := selectControls("", "b")
	if len(skip) != 2 || skip[0].Key != "a" || skip[1].Key != "c" {
		t.Fatalf("--skip b: got %+v", skip)
	}
}

func TestValidateControlSelectionRejectsUnknown(t *testing.T) {
	saved := baseline
	t.Cleanup(func() { baseline = saved })
	baseline = []Control{{Key: "known"}}

	if err := validateControlSelection("missing", ""); err == nil {
		t.Fatal("expected unknown --only control to fail")
	}
	if err := validateControlSelection("", "missing"); err == nil {
		t.Fatal("expected unknown --skip control to fail")
	}
}
