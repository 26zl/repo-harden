package repoharden

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-github/v88/github"
)

// Guards the hardcoded extended-key list in auditControlKeys() against drift:
// 200 + empty body for every request makes each extended-audit function run and
// emit its keyed row, and every emitted key must be a known --only/--skip key.
func TestExtendedAuditControlKeysAreRegistered(t *testing.T) {
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
	})})
	repos := []*github.Repository{
		{FullName: github.Ptr("me/app"), Owner: &github.User{Login: github.Ptr("me"), Type: github.Ptr("User")}, Private: github.Ptr(true), DefaultBranch: github.Ptr("main")},
		{FullName: github.Ptr("acme/app"), Owner: &github.User{Login: github.Ptr("acme"), Type: github.Ptr("Organization")}, DefaultBranch: github.Ptr("main")},
	}
	rows, err := collectGitHubExtendedAudit(context.Background(), client, &opts{orgAudit: true, staleDays: 180}, repos)
	if err != nil {
		t.Fatal(err)
	}
	known := auditControlKeys()
	for _, r := range rows {
		if !known[r.Control] {
			t.Errorf("emitted control %q is not in auditControlKeys(); --only/--skip would reject it", r.Control)
		}
	}
}

func TestExtendedAuditRespectsOnly(t *testing.T) {
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
	})})
	repos := []*github.Repository{{FullName: github.Ptr("me/app"), Owner: &github.User{Login: github.Ptr("me"), Type: github.Ptr("User")}, DefaultBranch: github.Ptr("main")}}
	rows, err := collectGitHubExtendedAudit(context.Background(), client, &opts{only: "stale-repo"}, repos)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Control != "stale-repo" {
		t.Fatalf("--only=stale-repo should run only that check, got %d rows", len(rows))
	}
}

func TestGitHubPackagesAuditFlagsPublicPackageLinkedToPrivateRepo(t *testing.T) {
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/users/me/packages" {
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody}, nil
		}
		if req.URL.Query().Get("package_type") == "container" {
			return jsonResponse(`[{
				"name":"app",
				"package_type":"container",
				"visibility":"public",
				"repository":{"full_name":"me/app"}
			}]`), nil
		}
		return jsonResponse(`[]`), nil
	})})
	repo := &github.Repository{
		FullName: github.Ptr("me/app"),
		Private:  github.Ptr(true),
		Owner:    &github.User{Login: github.Ptr("me"), Type: github.Ptr("User")},
	}

	row := auditGitHubPackages(context.Background(), client, "me", repo, map[string]githubPackageListResult{})
	if row.Status != string(StatusGap) {
		t.Fatalf("status = %s detail=%q, want gap", row.Status, row.Detail)
	}
	if !strings.Contains(row.Detail, "container/app") {
		t.Fatalf("detail = %q, want package label", row.Detail)
	}
}

func TestListGitHubDeployKeysPaginates(t *testing.T) {
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/repos/me/app/keys" {
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody}, nil
		}
		switch req.URL.Query().Get("page") {
		case "":
			resp := jsonResponse(`[{"id":1,"key":"ssh-rsa a","title":"first","read_only":true}]`)
			resp.Header.Set("Link", `<https://api.github.com/repos/me/app/keys?page=2>; rel="next"`)
			return resp, nil
		case "2":
			return jsonResponse(`[{"id":2,"key":"ssh-rsa b","title":"second","read_only":true}]`), nil
		default:
			return &http.Response{StatusCode: http.StatusBadRequest, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
		}
	})})

	keys, err := listGitHubDeployKeys(context.Background(), client, "me", "app")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("keys = %d, want 2", len(keys))
	}
}

func TestGitHubOpenSecurityAdvisoriesFlagsTriageHighSeverity(t *testing.T) {
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/repos/me/app/security-advisories" {
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody}, nil
		}
		return jsonResponse(`[{"ghsa_id":"GHSA-xxxx-yyyy-zzzz","severity":"critical"}]`), nil
	})})
	repo := &github.Repository{FullName: github.Ptr("me/app")}
	row := auditGitHubOpenSecurityAdvisories(context.Background(), client, "me", "app", repo)
	if row.Status != string(StatusGap) {
		t.Fatalf("status = %s detail=%q, want gap", row.Status, row.Detail)
	}
	if !strings.Contains(row.Detail, "GHSA-xxxx-yyyy-zzzz") {
		t.Fatalf("detail = %q, want GHSA id", row.Detail)
	}
}

func TestGitHubWorkflowAccessLevelStrictness(t *testing.T) {
	check := func(level string, want ControlStatus) {
		client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path != "/repos/me/app/actions/permissions/access" {
				return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody}, nil
			}
			return jsonResponse(`{"access_level":"` + level + `"}`), nil
		})})
		row := auditGitHubWorkflowAccessLevel(context.Background(), client, "me", "app", &github.Repository{FullName: github.Ptr("me/app")})
		if row.Status != string(want) {
			t.Errorf("access_level=%s: got %s, want %s", level, row.Status, want)
		}
	}
	check("none", StatusCompliant)
	check("user", StatusGap)
	check("organization", StatusGap)
}

func TestGitHubCommunityHealthFlagsMissing(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /repos/me/app/community/profile": `{"health_percentage":50,"files":{"readme":{"url":"x"},"license":{"url":"x"},"code_of_conduct":null,"contributing":null,"issue_template":null,"pull_request_template":null}}`,
	})
	row := auditGitHubCommunityHealth(context.Background(), client, "me", "app", &github.Repository{FullName: github.Ptr("me/app")})
	if row.Status != string(StatusGap) {
		t.Fatalf("status = %s detail=%q, want gap", row.Status, row.Detail)
	}
	if !strings.Contains(row.Detail, "issue template") {
		t.Fatalf("detail = %q, want missing issue template", row.Detail)
	}
}

func TestGitHubCodeScanningConflictFlagsDefaultPlusWorkflow(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /repos/me/app/code-scanning/default-setup":           `{"state":"configured"}`,
		"GET /repos/me/app/contents/.github/workflows":            `[{"type":"file","name":"codeql.yml","path":".github/workflows/codeql.yml"}]`,
		"GET /repos/me/app/contents/.github/workflows/codeql.yml": `{"type":"file","name":"codeql.yml","path":".github/workflows/codeql.yml","encoding":"base64","content":"am9iczoKICBhbmFseXplOgogICAgc3RlcHM6CiAgICAgIC0gdXNlczogZ2l0aHViL2NvZGVxbC1hY3Rpb24vaW5pdEB2Mw=="}`,
	})
	row := auditGitHubCodeScanningConflict(context.Background(), client, "me", "app", &github.Repository{FullName: github.Ptr("me/app"), DefaultBranch: github.Ptr("main")})
	if row.Status != string(StatusGap) {
		t.Fatalf("status = %s detail=%q, want gap", row.Status, row.Detail)
	}
	if !strings.Contains(row.Detail, "codeql.yml") {
		t.Fatalf("detail = %q, want conflicting workflow name", row.Detail)
	}
}

func TestGitHubRepoFieldAudits(t *testing.T) {
	if r := auditGitHubMergeMethods(&github.Repository{FullName: github.Ptr("me/app"), AllowMergeCommit: github.Ptr(false), AllowSquashMerge: github.Ptr(false), AllowRebaseMerge: github.Ptr(false)}); r.Status != string(StatusGap) {
		t.Errorf("no-merge-method all-off: got %s, want gap", r.Status)
	}
	if r := auditGitHubMergeMethods(&github.Repository{FullName: github.Ptr("me/app"), AllowMergeCommit: github.Ptr(true), AllowSquashMerge: github.Ptr(false), AllowRebaseMerge: github.Ptr(false)}); r.Status != string(StatusCompliant) {
		t.Errorf("no-merge-method one-on: got %s, want compliant", r.Status)
	}
	if r := auditGitHubMergeMethods(&github.Repository{FullName: github.Ptr("me/app")}); r.Status != string(StatusSkipped) {
		t.Errorf("no-merge-method nil fields: got %s, want skipped", r.Status)
	}
	if r := auditGitHubForkPolicy(&github.Repository{FullName: github.Ptr("me/app"), Private: github.Ptr(true), AllowForking: github.Ptr(true)}); r.Status != string(StatusGap) {
		t.Errorf("fork-policy private+fork: got %s, want gap", r.Status)
	}
	if r := auditGitHubWikiSurface(&github.Repository{FullName: github.Ptr("me/app"), Private: github.Ptr(false), HasWiki: github.Ptr(true)}); r.Status != string(StatusGap) {
		t.Errorf("wiki public+wiki: got %s, want gap", r.Status)
	}
}

func TestGitHubRulesetEvaluateOnlyFlagsDryRun(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /repos/me/app/rulesets":   `[{"id":9,"name":"dry","enforcement":"evaluate","target":"branch"}]`,
		"GET /repos/me/app/rulesets/9": `{"id":9,"name":"dry","enforcement":"evaluate","target":"branch","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"rules":[{"type":"pull_request"}]}`,
	})
	repo := &github.Repository{FullName: github.Ptr("me/app"), DefaultBranch: github.Ptr("main")}
	row := auditGitHubRulesetEvaluateOnly(context.Background(), client, "me", "app", repo)
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "dry") {
		t.Fatalf("status=%s detail=%q, want gap mentioning 'dry'", row.Status, row.Detail)
	}
}

func TestWorkflowPermissionIssue(t *testing.T) {
	cases := []struct{ name, content, want string }{
		{"top-level read map", "permissions:\n  contents: read\njobs:\n  x:\n    steps: []", ""},
		{"read-all string", "permissions: read-all\njobs:\n  x: {}", ""},
		{"write-all", "permissions: write-all\njobs:\n  x: {}", "write-all token"},
		{"top-level write map", "permissions:\n  contents: write\njobs:\n  x: {}", "write permission: contents"},
		{"no permissions", "jobs:\n  x:\n    steps: []", "no explicit permissions"},
		{"per-job read", "jobs:\n  x:\n    permissions:\n      contents: read", ""},
		{"per-job write", "jobs:\n  x:\n    permissions:\n      contents: write", "write permission: contents"},
		{"one job missing", "jobs:\n  x:\n    permissions:\n      contents: read\n  y:\n    steps: []", "no explicit permissions"},
		{"unparseable", "permissions: [oops\n  bad", "unparseable"},
	}
	for _, c := range cases {
		if got := workflowPermissionIssue(c.content); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRulesetTargetsBranch(t *testing.T) {
	mk := func(include, exclude []string) *github.RepositoryRuleset {
		return &github.RepositoryRuleset{
			Conditions: &github.RepositoryRulesetConditions{
				RefName: &github.RepositoryRulesetRefConditionParameters{Include: include, Exclude: exclude},
			},
		}
	}
	cases := []struct {
		name string
		rs   *github.RepositoryRuleset
		want bool
	}{
		{"default-branch token", mk([]string{"~DEFAULT_BRANCH"}, nil), true},
		{"all token", mk([]string{"~ALL"}, nil), true},
		{"exact ref", mk([]string{"refs/heads/main"}, nil), true},
		{"other branch only", mk([]string{"refs/heads/release"}, nil), false},
		{"glob match", mk([]string{"refs/heads/*"}, nil), true},
		{"excluded", mk([]string{"~ALL"}, []string{"refs/heads/main"}), false},
		{"no conditions", &github.RepositoryRuleset{}, true},
	}
	for _, c := range cases {
		if got := rulesetTargetsBranch(c.rs, "main"); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestBranchProtectionMissingDepth(t *testing.T) {
	if m := branchProtectionMissing(nil, map[string]bool{}); len(m) == 0 {
		t.Fatal("empty ruleset should report missing protections")
	}
	// weak ruleset: has review but lacks status checks / linear history / thread resolution
	if m := branchProtectionMissing(nil, map[string]bool{"pull_request": true}); len(m) == 0 {
		t.Fatal("partial ruleset should still report gaps")
	}
	strong := branchProtectionMissing(nil, map[string]bool{
		"pull_request": true, "required_status_checks": true, "non_fast_forward": true,
		"deletion": true, "required_linear_history": true, "thread_resolution": true,
	})
	if len(strong) != 0 {
		t.Fatalf("complete ruleset should have no gaps, got %v", strong)
	}
}

func TestGlobMatchRefPatterns(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"refs/heads/main", "refs/heads/main", true},
		{"refs/heads/*", "refs/heads/main", true},
		{"refs/heads/*", "refs/heads/a/b", false}, // * does not cross /
		{"refs/heads/**", "refs/heads/a/b", true}, // ** crosses /
		{"refs/heads/release/*", "refs/heads/release/v1", true},
		{"refs/heads/release/*", "refs/heads/main", false},
		{"qa/**/x", "qa/a/b/x", true},
		{"refs/heads/*", "refs/heads/release/v1", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.s); got != c.want {
			t.Errorf("globMatch(%q,%q)=%v want %v", c.pattern, c.s, got, c.want)
		}
	}
}
