package repoharden

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-github/v88/github"
)

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

func TestDetectSkipsOnNoAdminAccess(t *testing.T) {
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
	})})
	for _, key := range []string{"token-readonly", "actions-allowlist", "dependabot-fixes", "dependabot-alerts"} {
		ctl := controlByKey(t, key)
		if res := ctl.Detect(context.Background(), client, "me", "app", &github.Repository{}); res.Status != StatusSkipped {
			t.Errorf("%s on 403: got %s (%s), want skipped", key, res.Status, res.Detail)
		}
	}
}

func TestEndpointUnavailableDoesNotHideRateLimits(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusForbidden, Header: make(http.Header)}
	resp.Header.Set("X-RateLimit-Remaining", "0")
	err := &github.ErrorResponse{Response: resp}
	if endpointUnavailable(err) {
		t.Fatal("rate-limited 403 must be reported as an error, not skipped as unavailable")
	}
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
		"GET /repos/me/app/actions/permissions":                  `{"enabled":true,"allowed_actions":"selected","sha_pinning_required":true}`,
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
	missing := mockClient(map[string]string{
		"GET /repos/me/app/actions/permissions": `{}`,
	})
	if got := ctl.Detect(context.Background(), missing, "me", "app", nil); got.Status != StatusSkipped {
		t.Fatalf("missing enabled field: got %s, want skipped", got.Status)
	}
	disabled := mockClient(map[string]string{
		"GET /repos/me/app/actions/permissions": `{"enabled":false}`,
	})
	if got := ctl.Detect(context.Background(), disabled, "me", "app", nil); got.Status != StatusSkipped {
		t.Fatalf("disabled actions: got %s, want skipped", got.Status)
	}
	patterns := mockClient(map[string]string{
		"GET /repos/me/app/actions/permissions":                  `{"enabled":true,"allowed_actions":"selected","sha_pinning_required":true}`,
		"GET /repos/me/app/actions/permissions/selected-actions": `{"github_owned_allowed":true,"verified_allowed":true,"patterns_allowed":["my-org/*"]}`,
	})
	if got := ctl.Detect(context.Background(), patterns, "me", "app", nil); got.Status != StatusGap {
		t.Fatalf("broad patterns: got %s, want gap", got.Status)
	}
	narrow := mockClient(map[string]string{
		"GET /repos/me/app/actions/permissions":                  `{"enabled":true,"allowed_actions":"selected","sha_pinning_required":true}`,
		"GET /repos/me/app/actions/permissions/selected-actions": `{"github_owned_allowed":true,"verified_allowed":false,"patterns_allowed":["hashicorp/setup-terraform@*","goreleaser/goreleaser-action@*"]}`,
	})
	if got := ctl.Detect(context.Background(), narrow, "me", "app", nil); got.Status != StatusCompliant {
		t.Fatalf("explicit patterns with SHA enforcement: got %s detail=%q, want compliant", got.Status, got.Detail)
	}
	noPin := mockClient(map[string]string{
		"GET /repos/me/app/actions/permissions":                  `{"enabled":true,"allowed_actions":"selected","sha_pinning_required":false}`,
		"GET /repos/me/app/actions/permissions/selected-actions": `{"github_owned_allowed":true,"verified_allowed":false,"patterns_allowed":["hashicorp/setup-terraform@*"]}`,
	})
	if got := ctl.Detect(context.Background(), noPin, "me", "app", nil); got.Status != StatusGap {
		t.Fatalf("explicit patterns without SHA enforcement: got %s, want gap", got.Status)
	}
	unknownPin := mockClient(map[string]string{
		"GET /repos/me/app/actions/permissions":                  `{"enabled":true,"allowed_actions":"selected"}`,
		"GET /repos/me/app/actions/permissions/selected-actions": `{"github_owned_allowed":true,"verified_allowed":true}`,
	})
	if got := ctl.Detect(context.Background(), unknownPin, "me", "app", nil); got.Status != StatusSkipped {
		t.Fatalf("unreported SHA enforcement: got %s, want skipped", got.Status)
	}
}

func TestExplicitActionPatterns(t *testing.T) {
	for _, tc := range []struct {
		patterns []string
		want     bool
	}{
		{nil, true},
		{[]string{"actions/checkout@*", "acme/composite/subdir@" + strings.Repeat("a", 40)}, true},
		{[]string{"owner/*@*"}, false},
		{[]string{"*/action@*"}, false},
		{[]string{"owner/action"}, false},
		{[]string{"owner/action@"}, false},
		{[]string{"owner/action@v1@other"}, false},
		{[]string{"owner/action@v1 another"}, false},
	} {
		if got, _ := explicitActionPatterns(tc.patterns); got != tc.want {
			t.Errorf("explicitActionPatterns(%v)=%v, want %v", tc.patterns, got, tc.want)
		}
	}
}

func TestPrivateVulnerabilityReportingDetect(t *testing.T) {
	ctl := controlByKey(t, "private-vulnerability-reporting")
	off := mockClient(map[string]string{"GET /repos/me/app/private-vulnerability-reporting": `{"enabled":false}`})
	if got := ctl.Detect(context.Background(), off, "me", "app", &github.Repository{}); got.Status != StatusGap {
		t.Fatalf("disabled: got %s, want gap", got.Status)
	}
	on := mockClient(map[string]string{"GET /repos/me/app/private-vulnerability-reporting": `{"enabled":true}`})
	if got := ctl.Detect(context.Background(), on, "me", "app", &github.Repository{}); got.Status != StatusCompliant {
		t.Fatalf("enabled: got %s, want compliant", got.Status)
	}
}

func TestControlsOutputKeepsLongKeysSeparated(t *testing.T) {
	out := captureStdout(t, func() {
		if err := cmdControls(&opts{color: "never"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "private-vulnerability-reporting  medium") {
		t.Fatalf("long control key is not separated from severity:\n%s", out)
	}
}

func TestCodeScanningCompliantViaAdvancedSetup(t *testing.T) {
	ctl := controlByKey(t, "code-scanning")
	recent := mockClient(map[string]string{
		"GET /repos/me/app/code-scanning/default-setup": `{"state":"not-configured"}`,
		"GET /repos/me/app/code-scanning/analyses":      `[{"id":1,"created_at":"2999-01-01T00:00:00Z"}]`,
	})
	if got := ctl.Detect(context.Background(), recent, "me", "app", &github.Repository{}); got.Status != StatusCompliant || got.Prior != "not-configured" {
		t.Fatalf("recent analysis: got status=%s prior=%q (%s), want compliant/not-configured", got.Status, got.Prior, got.Detail)
	}
	stale := mockClient(map[string]string{
		"GET /repos/me/app/code-scanning/default-setup": `{"state":"not-configured"}`,
		"GET /repos/me/app/code-scanning/analyses":      `[{"id":1,"created_at":"2020-01-01T00:00:00Z"}]`,
	})
	if got := ctl.Detect(context.Background(), stale, "me", "app", &github.Repository{}); got.Status != StatusGap {
		t.Fatalf("stale analysis: got %s, want gap", got.Status)
	}
}

func TestCodeScanningAnalysisErrorDoesNotBecomeGap(t *testing.T) {
	ctl := controlByKey(t, "code-scanning")
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/repos/me/app/code-scanning/default-setup":
			return jsonResponse(`{"state":"not-configured"}`), nil
		case "/repos/me/app/code-scanning/analyses":
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Header:     make(http.Header),
				Body:       http.NoBody,
				Request:    req,
			}, nil
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
		}
	})})
	got := ctl.Detect(context.Background(), client, "me", "app", &github.Repository{DefaultBranch: github.Ptr("main")})
	if got.Status != StatusError {
		t.Fatalf("analysis API failure: got %s (%s), want error", got.Status, got.Detail)
	}
}

func TestBranchProtectionDetect(t *testing.T) {
	ctl := controlByKey(t, "branch-protection")
	repo := &github.Repository{DefaultBranch: github.Ptr("main")}
	has := mockClient(map[string]string{
		"GET /repos/me/app/rulesets":   `[{"id":7,"name":"repo-harden","enforcement":"active","target":"branch"}]`,
		"GET /repos/me/app/rulesets/7": `{"id":7,"name":"repo-harden","enforcement":"active","target":"branch","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"rules":[{"type":"pull_request","parameters":{"required_approving_review_count":1,"required_review_thread_resolution":true}},{"type":"deletion"},{"type":"non_fast_forward"},{"type":"required_linear_history"}]}`,
	})
	if got := ctl.Detect(context.Background(), has, "me", "app", repo); got.Status != StatusCompliant {
		t.Fatalf("valid ruleset: got %s (%s), want compliant", got.Status, got.Detail)
	}
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
		if req.Method == http.MethodGet && req.URL.Path == "/repos/me/app/rulesets" {
			return jsonResponse(`[]`), nil
		}
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
	var method, path, body string
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/repos/me/app/rulesets":
			return jsonResponse(`[{"id":7,"name":"repo-harden","target":"branch","enforcement":"disabled"}]`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/repos/me/app/rulesets/7":
			return jsonResponse(`{"id":7,"name":"repo-harden","target":"branch","enforcement":"disabled","conditions":{"ref_name":{"include":["refs/heads/release/*"],"exclude":[]}},"bypass_actors":[{"actor_id":1,"actor_type":"RepositoryRole","bypass_mode":"always"}],"rules":[{"type":"required_signatures"}]}`), nil
		case req.Method == http.MethodPut && req.URL.Path == "/repos/me/app/rulesets/7":
			method, path = req.Method, req.URL.Path
			b, _ := io.ReadAll(req.Body)
			body = string(b)
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
	for _, preserved := range []string{`required_signatures`, `refs/heads/release/*`, `bypass_actors`, `~DEFAULT_BRANCH`} {
		if !strings.Contains(body, preserved) {
			t.Errorf("merged ruleset dropped %q: %s", preserved, body)
		}
	}
}

func TestBranchProtectionApplyRefusesSameNameNonBranchRuleset(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /repos/me/app/rulesets":   `[{"id":7,"name":"repo-harden","target":"tag","enforcement":"active"}]`,
		"GET /repos/me/app/rulesets/7": `{"id":7,"name":"repo-harden","target":"tag","enforcement":"active"}`,
	})
	ctl := controlByKey(t, "branch-protection")
	if err := ctl.Apply(context.Background(), client, "me", "app"); err == nil {
		t.Fatal("same-name tag ruleset must be refused instead of overwritten")
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

func TestSecretScanningApplyEnables(t *testing.T) {
	var method, body string
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/repos/me/app" {
			method = req.Method
			if req.Body != nil {
				b, _ := io.ReadAll(req.Body)
				body = string(b)
			}
			return jsonResponse(`{}`), nil
		}
		return &http.Response{StatusCode: 404, Header: make(http.Header), Body: http.NoBody}, nil
	})})
	ctl := controlByKey(t, "secret-scanning")
	if err := ctl.Apply(context.Background(), client, "me", "app"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if method != http.MethodPatch {
		t.Fatalf("apply method = %s, want PATCH", method)
	}
	if !strings.Contains(body, `"secret_scanning"`) || !strings.Contains(body, `"status":"enabled"`) {
		t.Fatalf("apply did not enable secret scanning: %s", body)
	}
}

func TestSecretScanningRevertNoopWhenWasEnabled(t *testing.T) {
	patches := 0
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPatch {
			patches++
		}
		return jsonResponse(`{}`), nil
	})})
	ctl := controlByKey(t, "secret-scanning")
	prior := `{"secret_scanning":"enabled","push_protection":"enabled"}`
	if err := ctl.Revert(context.Background(), client, "me", "app", prior); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if patches != 0 {
		t.Fatalf("revert of already-enabled should make no PATCH, made %d", patches)
	}
}

func TestSecretScanningRevertRestoresDisabled(t *testing.T) {
	var body string
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPatch && req.URL.Path == "/repos/me/app" {
			b, _ := io.ReadAll(req.Body)
			body = string(b)
		}
		return jsonResponse(`{}`), nil
	})})
	ctl := controlByKey(t, "secret-scanning")
	prior := `{"secret_scanning":"disabled","push_protection":"disabled"}`
	if err := ctl.Revert(context.Background(), client, "me", "app", prior); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if !strings.Contains(body, `"status":"disabled"`) {
		t.Fatalf("revert should restore disabled, body: %s", body)
	}
}

func TestParseSecretScanningPriorRoundTrip(t *testing.T) {
	in := secretScanningPrior{SecretScanning: "enabled", PushProtection: "disabled"}
	got := parseSecretScanningPrior(encodePrior(in))
	if got != in {
		t.Fatalf("round-trip = %+v, want %+v", got, in)
	}
	if p := parseSecretScanningPrior("enabled"); p.SecretScanning != "enabled" || p.PushProtection != "enabled" {
		t.Fatalf("legacy enabled = %+v", p)
	}
	if p := parseSecretScanningPrior(""); p.SecretScanning != "disabled" || p.PushProtection != "disabled" {
		t.Fatalf("empty prior = %+v, want disabled", p)
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
	absent := mockClient(nil)
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

func TestMutationControlHTTPContracts(t *testing.T) {
	tests := []struct {
		name          string
		control       string
		operation     string
		prior         string
		wantMethod    string
		wantPath      string
		wantBodyParts []string
	}{
		{"enable vulnerability alerts", "dependabot-alerts", "apply", "", http.MethodPut, "/repos/me/app/vulnerability-alerts", nil},
		{"restore vulnerability alerts", "dependabot-alerts", "revert", "disabled", http.MethodDelete, "/repos/me/app/vulnerability-alerts", nil},
		{"enable security fixes", "dependabot-fixes", "apply", "", http.MethodPut, "/repos/me/app/automated-security-fixes", nil},
		{"restore security fixes", "dependabot-fixes", "revert", "disabled", http.MethodDelete, "/repos/me/app/automated-security-fixes", nil},
		{"set token policy", "token-readonly", "apply", "", http.MethodPut, "/repos/me/app/actions/permissions/workflow", []string{`"default_workflow_permissions":"read"`, `"can_approve_pull_request_reviews":false`}},
		{"configure CodeQL", "code-scanning", "apply", "", http.MethodPatch, "/repos/me/app/code-scanning/default-setup", []string{`"state":"configured"`}},
		{"restore CodeQL", "code-scanning", "revert", "not-configured", http.MethodPatch, "/repos/me/app/code-scanning/default-setup", []string{`"state":"not-configured"`}},
		{"enable private reporting", "private-vulnerability-reporting", "apply", "", http.MethodPut, "/repos/me/app/private-vulnerability-reporting", nil},
		{"restore private reporting", "private-vulnerability-reporting", "revert", "disabled", http.MethodDelete, "/repos/me/app/private-vulnerability-reporting", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var method, path, body string
			client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				method, path = req.Method, req.URL.Path
				if req.Body != nil {
					data, _ := io.ReadAll(req.Body)
					body = string(data)
				}
				return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
			})})
			ctl := controlByKey(t, tt.control)
			var err error
			if tt.operation == "apply" {
				err = ctl.Apply(context.Background(), client, "me", "app")
			} else {
				err = ctl.Revert(context.Background(), client, "me", "app", tt.prior)
			}
			if err != nil {
				t.Fatal(err)
			}
			if method != tt.wantMethod || path != tt.wantPath {
				t.Fatalf("request = %s %s, want %s %s", method, path, tt.wantMethod, tt.wantPath)
			}
			for _, part := range tt.wantBodyParts {
				if !strings.Contains(body, part) {
					t.Errorf("request body %q missing %q", body, part)
				}
			}
		})
	}
}

func TestMutationControlPropagatesAPIErrors(t *testing.T) {
	for _, key := range []string{"dependabot-alerts", "dependabot-fixes", "token-readonly", "code-scanning", "private-vulnerability-reporting"} {
		t.Run(key, func(t *testing.T) {
			client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Status:     "500 Internal Server Error",
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"message":"boom"}`)),
					Request:    req,
				}, nil
			})})
			if err := controlByKey(t, key).Apply(context.Background(), client, "me", "app"); err == nil {
				t.Fatal("Apply must propagate the API error")
			}
		})
	}
}

func TestMutationControlRevertPropagatesAPIErrors(t *testing.T) {
	tests := []struct {
		control string
		prior   string
	}{
		{"dependabot-alerts", "disabled"},
		{"dependabot-fixes", "disabled"},
		{"token-readonly", `{"default_workflow_permissions":"write","can_approve_pull_request_reviews":true}`},
		{"branch-protection", ""},
		{"actions-allowlist", "all"},
		{"secret-scanning", `{"secret_scanning":"disabled","push_protection":"disabled"}`},
		{"code-scanning", "not-configured"},
		{"private-vulnerability-reporting", "disabled"},
	}
	for _, tt := range tests {
		t.Run(tt.control, func(t *testing.T) {
			client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Status:     "500 Internal Server Error",
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"message":"boom"}`)),
					Request:    req,
				}, nil
			})})
			if err := controlByKey(t, tt.control).Revert(context.Background(), client, "me", "app", tt.prior); err == nil {
				t.Fatal("Revert must propagate the API error")
			}
		})
	}
}
