package repoharden

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-github/v88/github"
)

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

	row := auditGitHubPackages(context.Background(), client, "me", repo, &githubPackageCache{m: map[string]*githubPackageCacheEntry{}})
	if row.Status != string(StatusGap) {
		t.Fatalf("status = %s detail=%q, want gap", row.Status, row.Detail)
	}
	if !strings.Contains(row.Detail, "container/app") {
		t.Fatalf("detail = %q, want package label", row.Detail)
	}
}

func TestGitHubPackagesAuditSkipsOnPartialTypeUnavailability(t *testing.T) {
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/users/me/packages" {
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody}, nil
		}
		if req.URL.Query().Get("package_type") == "container" {
			return &http.Response{StatusCode: http.StatusForbidden, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
		}
		return jsonResponse(`[]`), nil
	})})
	repo := &github.Repository{
		FullName: github.Ptr("me/app"),
		Owner:    &github.User{Login: github.Ptr("me"), Type: github.Ptr("User")},
	}
	row := auditGitHubPackages(context.Background(), client, "me", repo, &githubPackageCache{m: map[string]*githubPackageCacheEntry{}})
	if row.Status != string(StatusSkipped) || !strings.Contains(row.Detail, "1 of 6 package types unavailable") {
		t.Fatalf("status=%s detail=%q, want skipped with unavailable-type count", row.Status, row.Detail)
	}
}

func TestRulesetChecksShareOneListAndDetailFetch(t *testing.T) {
	listCalls, detailCalls := 0, 0
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/repos/me/app/rulesets":
			listCalls++
			return jsonResponse(`[{"id":9,"name":"base","target":"branch","enforcement":"active"}]`), nil
		case "/repos/me/app/rulesets/9":
			detailCalls++
			return jsonResponse(`{"id":9,"name":"base","target":"branch","enforcement":"active","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"rules":[{"type":"deletion"}]}`), nil
		}
		return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
	})})
	repo := &github.Repository{
		FullName:      github.Ptr("me/app"),
		DefaultBranch: github.Ptr("main"),
		Owner:         &github.User{Login: github.Ptr("me"), Type: github.Ptr("Organization")},
	}
	rc := &rulesetListCache{}
	ctx := context.Background()
	auditGitHubBranchProtection(ctx, client, "me", "app", repo, rc)
	auditGitHubSignedCommits(ctx, client, "me", "app", repo, rc)
	auditGitHubRequiredWorkflows(ctx, client, "me", "app", repo, rc)
	auditGitHubMergeQueue(ctx, client, "me", "app", repo, rc)
	auditGitHubRulesetBypass(ctx, client, "me", "app", repo, rc)
	auditGitHubRulesetEvaluateOnly(ctx, client, "me", "app", repo, rc)
	auditGitHubTagProtection(ctx, client, "me", "app", repo, rc)
	auditGitHubPushRuleset(ctx, client, "me", "app", repo, rc)
	if listCalls != 1 {
		t.Fatalf("ruleset list fetched %d times across 8 checks, want 1", listCalls)
	}
	if detailCalls != 1 {
		t.Fatalf("ruleset detail fetched %d times across 8 checks, want 1", detailCalls)
	}
}

func TestListGitHubRepoSecretsFailsOnTruncatedPagination(t *testing.T) {
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/repos/me/app/actions/secrets" {
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody}, nil
		}
		return jsonResponse(`{"total_count":3,"secrets":[{"name":"A"},{"name":"B"}]}`), nil
	})})
	if _, _, err := listGitHubRepoSecrets(context.Background(), client, "me", "app"); err == nil || !strings.Contains(err.Error(), "2 of 3 advertised") {
		t.Fatalf("truncated secrets listing must fail closed, got %v", err)
	}
}

func TestRulesetBypassErrorsOnUnreadableRulesetDetails(t *testing.T) {
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/repos/me/app/rulesets" {
			return jsonResponse(`[{"id":7,"name":"r","target":"branch","enforcement":"active"}]`), nil
		}
		return &http.Response{StatusCode: http.StatusInternalServerError, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
	})})
	repo := &github.Repository{FullName: github.Ptr("me/app")}
	row := auditGitHubRulesetBypass(context.Background(), client, "me", "app", repo, &rulesetListCache{})
	if row.Status != string(StatusError) {
		t.Fatalf("status=%s detail=%q, want error when ruleset details fail with 500", row.Status, row.Detail)
	}
}

func TestRulesetBypassSkipsOnForbiddenRulesetDetails(t *testing.T) {
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/repos/me/app/rulesets" {
			return jsonResponse(`[{"id":7,"name":"r","target":"branch","enforcement":"active"}]`), nil
		}
		return &http.Response{StatusCode: http.StatusForbidden, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
	})})
	repo := &github.Repository{FullName: github.Ptr("me/app")}
	row := auditGitHubRulesetBypass(context.Background(), client, "me", "app", repo, &rulesetListCache{})
	if row.Status != string(StatusSkipped) {
		t.Fatalf("status=%s detail=%q, want skipped when ruleset details are forbidden", row.Status, row.Detail)
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

func TestGitHubPagerRejectsNonAdvancingPage(t *testing.T) {
	pager := githubPager{}
	if _, _, err := pager.next(&github.Response{NextPage: 1}); err == nil || !strings.Contains(err.Error(), "did not advance") {
		t.Fatalf("first page pointing to itself must fail closed, got %v", err)
	}
	pager = githubPager{}
	next, done, err := pager.next(&github.Response{NextPage: 2})
	if err != nil || done || next != 2 {
		t.Fatalf("first next page: next=%d done=%v err=%v", next, done, err)
	}
	if _, _, err := pager.next(&github.Response{NextPage: 2}); err == nil || !strings.Contains(err.Error(), "did not advance") {
		t.Fatalf("repeated page must fail closed, got %v", err)
	}
}

func TestGitHubEnvironmentAuditRequiresEffectiveProtection(t *testing.T) {
	repo := &github.Repository{FullName: github.Ptr("me/app")}
	cases := []struct {
		name, response string
		want           ControlStatus
	}{
		{"empty branch policy on live", `{"total_count":1,"environments":[{"name":"live","deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":false}}]}`, StatusGap},
		{"release reviewers", `{"total_count":1,"environments":[{"name":"release-eu","protection_rules":[{"type":"required_reviewers","reviewers":[{"type":"User"}]}]}]}`, StatusCompliant},
		{"unrecognized name", `{"total_count":1,"environments":[{"name":"customer-facing"}]}`, StatusSkipped},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := mockClient(map[string]string{"GET /repos/me/app/environments": tc.response})
			row := auditGitHubEnvironments(context.Background(), client, "me", "app", repo)
			if row.Status != string(tc.want) {
				t.Fatalf("status=%s detail=%q, want %s", row.Status, row.Detail, tc.want)
			}
		})
	}
}

func TestGitHubProductionLikeEnvironmentNames(t *testing.T) {
	for _, name := range []string{"production", "prod-eu", "staging/us", "release_candidate", "live"} {
		if !githubProductionLikeEnvironment(name) {
			t.Errorf("%q should be recognized as production-like", name)
		}
	}
	for _, name := range []string{"development", "prototype", "lively-tests"} {
		if githubProductionLikeEnvironment(name) {
			t.Errorf("%q should not be recognized as production-like", name)
		}
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

	missing := mockClient(map[string]string{
		"GET /repos/me/app/actions/permissions/access": `{}`,
	})
	row := auditGitHubWorkflowAccessLevel(context.Background(), missing, "me", "app", &github.Repository{FullName: github.Ptr("me/app")})
	if row.Status != string(StatusSkipped) {
		t.Fatalf("missing access_level: got %s, want skipped", row.Status)
	}
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

func TestGitHubCommunityHealthAcceptsCompleteProfileWithIssueForm(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /repos/me/app/community/profile": `{"health_percentage":100,"files":{"readme":{"url":"x"},"license":{"url":"x"},"code_of_conduct":{"url":"x"},"contributing":{"url":"x"},"issue_template":null,"pull_request_template":{"url":"x"}}}`,
	})
	row := auditGitHubCommunityHealth(context.Background(), client, "me", "app", &github.Repository{FullName: github.Ptr("me/app")})
	if row.Status != string(StatusCompliant) {
		t.Fatalf("status = %s detail=%q, want compliant", row.Status, row.Detail)
	}
}

func TestGitHubRequiredWorkflowsSkipsPersonalRepository(t *testing.T) {
	repo := &github.Repository{
		FullName: github.Ptr("me/app"),
		Owner:    &github.User{Type: github.Ptr("User")},
	}
	row := auditGitHubRequiredWorkflows(context.Background(), nil, "me", "app", repo, &rulesetListCache{})
	if row.Status != string(StatusSkipped) || !strings.Contains(row.Detail, "organization") {
		t.Fatalf("personal required-workflows result = %+v, want skipped with availability detail", row)
	}
}

func TestGitHubOrgPoliciesDoNotTreatMissingFieldsAsCompliant(t *testing.T) {
	base := auditGitHubOrgBasePermission("acme", &github.Organization{
		DefaultRepoPermission: github.Ptr("read"),
	}, nil)
	if base.Status != string(StatusSkipped) {
		t.Fatalf("missing public-repo creation field: got %s, want skipped", base.Status)
	}

	client := mockClient(map[string]string{
		"GET /orgs/acme/actions/permissions": `{}`,
	})
	actions := auditGitHubOrgActionsPolicy(context.Background(), client, "acme")
	if actions.Status != string(StatusSkipped) {
		t.Fatalf("missing org Actions fields: got %s, want skipped", actions.Status)
	}
}

func TestGitHubCodeScanningConflictFlagsDefaultPlusWorkflow(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /repos/me/app/code-scanning/default-setup":           `{"state":"configured"}`,
		"GET /repos/me/app/contents/.github/workflows":            `[{"type":"file","name":"codeql.yml","path":".github/workflows/codeql.yml"}]`,
		"GET /repos/me/app/contents/.github/workflows/codeql.yml": `{"type":"file","name":"codeql.yml","path":".github/workflows/codeql.yml","encoding":"base64","content":"am9iczoKICBhbmFseXplOgogICAgc3RlcHM6CiAgICAgIC0gdXNlczogZ2l0aHViL2NvZGVxbC1hY3Rpb24vaW5pdEB2Mw=="}`,
	})
	row := auditGitHubCodeScanningConflict(context.Background(), client, "me", "app", &github.Repository{FullName: github.Ptr("me/app"), DefaultBranch: github.Ptr("main")}, &workflowFileCache{})
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
	if r := auditGitHubForkPolicy(&github.Repository{FullName: github.Ptr("me/app"), Private: github.Ptr(true)}); r.Status != string(StatusSkipped) {
		t.Errorf("fork-policy nil setting: got %s, want skipped", r.Status)
	}
	if r := auditGitHubWikiSurface(&github.Repository{FullName: github.Ptr("me/app"), Private: github.Ptr(false), HasWiki: github.Ptr(true)}); r.Status != string(StatusGap) {
		t.Errorf("wiki public+wiki: got %s, want gap", r.Status)
	}
	if r := auditGitHubWikiSurface(&github.Repository{FullName: github.Ptr("me/app"), Private: github.Ptr(false)}); r.Status != string(StatusSkipped) {
		t.Errorf("wiki nil setting: got %s, want skipped", r.Status)
	}
}

func TestGitHubRulesetEvaluateOnlyFlagsDryRun(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /repos/me/app/rulesets":   `[{"id":9,"name":"dry","enforcement":"evaluate","target":"branch"}]`,
		"GET /repos/me/app/rulesets/9": `{"id":9,"name":"dry","enforcement":"evaluate","target":"branch","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"rules":[{"type":"pull_request"}]}`,
	})
	repo := &github.Repository{FullName: github.Ptr("me/app"), DefaultBranch: github.Ptr("main")}
	row := auditGitHubRulesetEvaluateOnly(context.Background(), client, "me", "app", repo, &rulesetListCache{})
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "dry") {
		t.Fatalf("status=%s detail=%q, want gap mentioning 'dry'", row.Status, row.Detail)
	}
}

func TestWorkflowPermissionIssue(t *testing.T) {
	cases := []struct{ name, content, want string }{
		{"top-level read map", "permissions:\n  contents: read\njobs:\n  x:\n    steps: []", ""},
		{"read-all string", "permissions: read-all\njobs:\n  x: {}", "read-all token"},
		{"write-all", "permissions: write-all\njobs:\n  x: {}", "write-all token"},
		{"top-level scoped write", "permissions:\n  contents: write\njobs:\n  x: {}", "top-level write permissions must be job-scoped: contents"},
		{"job overrides top-level with write-all", "permissions:\n  contents: read\njobs:\n  x:\n    permissions: write-all", "write-all token"},
		{"no permissions", "jobs:\n  x:\n    steps: []", "no explicit permissions"},
		{"per-job read", "jobs:\n  x:\n    permissions:\n      contents: read", ""},
		{"per-job scoped write without evidence", "jobs:\n  x:\n    permissions:\n      contents: write", "job x has write permissions without a recognized need: contents"},
		{"per-job release write", "jobs:\n  x:\n    permissions:\n      contents: write\n    steps:\n      - run: gh release create v1 dist/*", ""},
		{"invalid permission string", "permissions: everything\njobs:\n  x: {}", "invalid permissions value"},
		{"invalid permission value", "permissions:\n  contents: yes\njobs:\n  x: {}", "invalid permission value: contents"},
		{"one job missing", "jobs:\n  x:\n    permissions:\n      contents: read\n  y:\n    steps: []", "no explicit permissions"},
		{"unparseable", "permissions: [oops\n  bad", "unparseable"},
	}
	for _, c := range cases {
		if got := workflowPermissionIssue(c.content); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestWorkflowUsesActionIgnoresComments(t *testing.T) {
	commentOnly := "name: CI\n# uses: github/codeql-action/analyze@v4\njobs:\n  test:\n    steps: []\n"
	uses, err := workflowUsesAction(commentOnly, "github/codeql-action/")
	if err != nil {
		t.Fatal(err)
	}
	if uses {
		t.Fatal("comment must not count as an action reference")
	}
	real := "jobs:\n  scan:\n    steps:\n      - uses: github/codeql-action/analyze@v4\n"
	uses, err = workflowUsesAction(real, "github/codeql-action/")
	if err != nil {
		t.Fatal(err)
	}
	if !uses {
		t.Fatal("real uses entry was not detected")
	}
}

func TestListWorkflowFilesFailsWhenAnyFileCannotBeRead(t *testing.T) {
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/repos/me/app/contents/.github/workflows":
			return jsonResponse(`[{"type":"file","name":"ci.yml","path":".github/workflows/ci.yml"}]`), nil
		case "/repos/me/app/contents/.github/workflows/ci.yml":
			return &http.Response{StatusCode: http.StatusInternalServerError, Header: make(http.Header), Body: http.NoBody}, nil
		default:
			return jsonResponse(`{}`), nil
		}
	})})
	if _, err := listWorkflowFiles(context.Background(), client, "me", "app", "main"); err == nil ||
		!strings.Contains(err.Error(), "could not read all workflow files") {
		t.Fatalf("workflow read failure should propagate, got %v", err)
	}
}

func TestRepoSecretIdentifiersAreHiddenByDefault(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /repos/me/app/actions/secrets": `{
			"total_count":1,
			"secrets":[{
				"name":"CUSTOMER_PRODUCTION_TOKEN",
				"created_at":"2020-01-01T00:00:00Z",
				"updated_at":"2020-01-01T00:00:00Z"
			}]
		}`,
	})
	repo := &github.Repository{FullName: github.Ptr("me/app")}
	hidden := auditGitHubRepoSecrets(context.Background(), client, "me", "app", repo, 30, false)
	if strings.Contains(hidden.Detail, "CUSTOMER_PRODUCTION_TOKEN") {
		t.Fatalf("secret identifier leaked by default: %q", hidden.Detail)
	}
	shown := auditGitHubRepoSecrets(context.Background(), client, "me", "app", repo, 30, true)
	if !strings.Contains(shown.Detail, "CUSTOMER_PRODUCTION_TOKEN") {
		t.Fatalf("--show-identifiers detail missing identifier: %q", shown.Detail)
	}
}

func TestDeployKeyIdentifiersAreHiddenByDefault(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /repos/me/app/keys": `[{"id":1,"key":"ssh-rsa a","title":"prod-server-key","read_only":false}]`,
	})
	repo := &github.Repository{FullName: github.Ptr("me/app")}
	hidden := auditGitHubDeployKeys(context.Background(), client, "me", "app", repo, false)
	if hidden.Status != string(StatusGap) {
		t.Fatalf("status = %s detail=%q, want gap", hidden.Status, hidden.Detail)
	}
	if strings.Contains(hidden.Detail, "prod-server-key") {
		t.Fatalf("deploy key title leaked by default: %q", hidden.Detail)
	}
	shown := auditGitHubDeployKeys(context.Background(), client, "me", "app", repo, true)
	if !strings.Contains(shown.Detail, "prod-server-key") {
		t.Fatalf("--show-identifiers detail missing key title: %q", shown.Detail)
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
	if m := branchProtectionMissing(nil, map[string]bool{}, false); len(m) == 0 {
		t.Fatal("empty ruleset should report missing protections")
	}
	if m := branchProtectionMissing(nil, map[string]bool{"pull_request": true}, false); len(m) == 0 {
		t.Fatal("partial ruleset should still report gaps")
	}
	strong := branchProtectionMissing(nil, map[string]bool{
		"pull_request": true, "review": true, "required_status_checks": true, "non_fast_forward": true,
		"deletion": true, "required_linear_history": true, "thread_resolution": true,
	}, false)
	if len(strong) != 0 {
		t.Fatalf("complete ruleset should have no gaps, got %v", strong)
	}
	singleMaintainer := branchProtectionMissing(nil, map[string]bool{
		"pull_request": true, "required_status_checks": true, "non_fast_forward": true,
		"deletion": true, "required_linear_history": true, "thread_resolution": true,
	}, true)
	if len(singleMaintainer) != 0 {
		t.Fatalf("a personal repository's PR gate may use zero approvals, got %v", singleMaintainer)
	}
}

func TestGlobMatchRefPatterns(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"refs/heads/main", "refs/heads/main", true},
		{"refs/heads/*", "refs/heads/main", true},
		{"refs/heads/*", "refs/heads/a/b", false},
		{"refs/heads/**", "refs/heads/a/b", true},
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

func unreadableRulesetsClient(protectionBody string) *github.Client {
	return mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case strings.HasSuffix(req.URL.Path, "/rulesets"):
			return &http.Response{StatusCode: http.StatusForbidden, Status: "403 Forbidden", Header: make(http.Header), Body: http.NoBody, Request: req}, nil
		case strings.HasSuffix(req.URL.Path, "/protection"):
			return jsonResponse(protectionBody), nil
		}
		return jsonResponse(`{}`), nil
	})})
}

func TestBranchProtectionSkipsWhenRulesetsUnavailable(t *testing.T) {
	body := `{"enforce_admins":{"enabled":true},"required_status_checks":{"contexts":["ci"]},"required_conversation_resolution":{"enabled":true},"allow_force_pushes":{"enabled":false},"allow_deletions":{"enabled":false},"required_linear_history":{"enabled":true}}`
	client := unreadableRulesetsClient(body)
	repo := &github.Repository{FullName: github.Ptr("me/app"), DefaultBranch: github.Ptr("main")}
	row := auditGitHubBranchProtection(context.Background(), client, "me", "app", repo, &rulesetListCache{})
	if row.Status != string(StatusSkipped) {
		t.Fatalf("status=%s detail=%q, want skipped", row.Status, row.Detail)
	}
}

func TestBranchProtectionReportsAdminGapEvenWhenRulesetsUnavailable(t *testing.T) {
	complete := `{"required_pull_request_reviews":{"required_approving_review_count":1},"required_status_checks":{"contexts":["ci"]},"required_conversation_resolution":{"enabled":true},"allow_force_pushes":{"enabled":false},"allow_deletions":{"enabled":false},"required_linear_history":{"enabled":true},"enforce_admins":{"enabled":false}}`
	client := unreadableRulesetsClient(complete)
	repo := &github.Repository{FullName: github.Ptr("me/app"), DefaultBranch: github.Ptr("main")}
	row := auditGitHubBranchProtection(context.Background(), client, "me", "app", repo, &rulesetListCache{})
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "admin enforcement") {
		t.Fatalf("status=%s detail=%q, want gap citing admin enforcement", row.Status, row.Detail)
	}
}

func TestSignedCommitsSkipsWhenRulesetsUnavailable(t *testing.T) {
	client := unreadableRulesetsClient(`{}`)
	repo := &github.Repository{FullName: github.Ptr("me/app"), DefaultBranch: github.Ptr("main")}
	row := auditGitHubSignedCommits(context.Background(), client, "me", "app", repo, &rulesetListCache{})
	if row.Status != string(StatusSkipped) {
		t.Fatalf("status=%s detail=%q, want skipped", row.Status, row.Detail)
	}
}

func TestOrgTokenPolicySkipsOnEmptyBody(t *testing.T) {
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
	})})
	row := auditGitHubOrgTokenPolicy(context.Background(), client, "myorg")
	if row.Status != string(StatusSkipped) {
		t.Fatalf("status=%s, want skipped on an empty 200 body (p==nil)", row.Status)
	}
}

func TestOpenSecurityAdvisoriesPaginates(t *testing.T) {
	page1 := "[" + strings.Repeat(`{"ghsa_id":"G","severity":"low"},`, 99) + `{"ghsa_id":"G1","severity":"high"}]`
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Query().Get("page") == "1" {
			return jsonResponse(page1), nil
		}
		return jsonResponse(`[{"ghsa_id":"G2","severity":"critical"}]`), nil
	})})
	repo := &github.Repository{FullName: github.Ptr("me/app")}
	row := auditGitHubOpenSecurityAdvisories(context.Background(), client, "me", "app", repo)
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "G2") {
		t.Fatalf("status=%s detail=%q, want gap including page-2 advisory G2", row.Status, row.Detail)
	}
}

func TestReleaseProvenance(t *testing.T) {
	repo := &github.Repository{FullName: github.Ptr("me/app")}
	cases := []struct {
		name     string
		releases string
		want     ControlStatus
	}{
		{"artifacts without digests", `[{"tag_name":"v1.0.0","draft":false,"assets":[{"name":"app_linux_amd64.tar.gz"},{"name":"checksums.txt"}]}]`, StatusSkipped},
		{"unverified sigstore sidecar", `[{"tag_name":"v1.0.0","draft":false,"assets":[{"name":"app.tar.gz"},{"name":"app.tar.gz.sigstore.json"}]}]`, StatusSkipped},
		{"unmapped intoto provenance", `[{"tag_name":"v1.0.0","draft":false,"assets":[{"name":"app.tar.gz"},{"name":"multiple.intoto.jsonl"}]}]`, StatusSkipped},
		{"source-only release", `[{"tag_name":"v1.0.0","draft":false,"assets":[]}]`, StatusSkipped},
		{"no releases", `[]`, StatusSkipped},
		{"drafts only", `[{"tag_name":"wip","draft":true,"assets":[{"name":"app.tar.gz"}]}]`, StatusSkipped},
	}
	for _, c := range cases {
		client := mockClient(map[string]string{"GET /repos/me/app/releases": c.releases})
		row := auditGitHubReleaseProvenance(context.Background(), client, "me", "app", repo)
		if row.Status != string(c.want) {
			t.Errorf("%s: status=%s detail=%q, want %s", c.name, row.Status, row.Detail, c.want)
		}
	}
}

func testNativeAttestationResponse(t *testing.T, digest, predicateType string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "app.tar.gz", "digest": map[string]string{"sha256": strings.TrimPrefix(strings.ToLower(digest), "sha256:")}}},
		"predicateType": predicateType,
		"predicate":     map[string]any{"buildDefinition": map[string]any{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := json.Marshal(map[string]any{
		"attestations": []any{map[string]any{
			"repository_id": 1,
			"bundle": map[string]any{
				"mediaType":            "application/vnd.dev.sigstore.bundle.v0.3+json",
				"verificationMaterial": map[string]any{"certificate": map[string]any{"rawBytes": "Y2VydA=="}},
				"dsseEnvelope": map[string]any{
					"payloadType": "application/vnd.in-toto+json",
					"payload":     base64.StdEncoding.EncodeToString(payload),
					"signatures":  []any{map[string]any{"sig": base64.StdEncoding.EncodeToString([]byte("signature"))}},
				},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(response)
}

func TestReleaseProvenanceUsesGitHubArtifactAttestations(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	client := mockClient(map[string]string{
		"GET /repos/me/app/releases":               `[{"tag_name":"v1.0.0","draft":false,"assets":[{"name":"app.tar.gz","digest":"` + digest + `"}]}]`,
		"GET /repos/me/app/attestations/" + digest: testNativeAttestationResponse(t, digest, "https://slsa.dev/provenance/v1"),
	})
	repo := &github.Repository{FullName: github.Ptr("me/app")}
	row := auditGitHubReleaseProvenance(context.Background(), client, "me", "app", repo)
	if row.Status != string(StatusCompliant) || !strings.Contains(row.Detail, "app.tar.gz") {
		t.Fatalf("native attestation: status=%s detail=%q, want compliant", row.Status, row.Detail)
	}
}

func TestReleaseProvenanceRejectsInvalidNativeAttestations(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	wrongDigest := "sha256:" + strings.Repeat("b", 64)
	for _, tc := range []struct {
		name     string
		response string
	}{
		{"empty bundle", `{"attestations":[{"repository_id":1,"bundle":{}}]}`},
		{"missing repository identity", strings.Replace(testNativeAttestationResponse(t, digest, "https://slsa.dev/provenance/v1"), `"repository_id":1`, `"repository_id":0`, 1)},
		{"wrong subject digest", testNativeAttestationResponse(t, wrongDigest, "https://slsa.dev/provenance/v1")},
		{"non-provenance predicate", testNativeAttestationResponse(t, digest, "https://spdx.dev/Document/v2.3")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := mockClient(map[string]string{
				"GET /repos/me/app/releases":               `[{"tag_name":"v1.0.0","draft":false,"assets":[{"name":"app.tar.gz","digest":"` + digest + `"}]}]`,
				"GET /repos/me/app/attestations/" + digest: tc.response,
			})
			repo := &github.Repository{FullName: github.Ptr("me/app")}
			row := auditGitHubReleaseProvenance(context.Background(), client, "me", "app", repo)
			if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "app.tar.gz") {
				t.Fatalf("status=%s detail=%q, want gap for unverifiable attestation", row.Status, row.Detail)
			}
		})
	}
}

func TestReleaseProvenanceGapsWhenDigestHasNoAttestation(t *testing.T) {
	digest := "sha256:" + strings.Repeat("b", 64)
	client := mockClient(map[string]string{
		"GET /repos/me/app/releases": `[{"tag_name":"v1.0.0","draft":false,"assets":[{"name":"app.tar.gz","digest":"` + digest + `"}]}]`,
	})
	repo := &github.Repository{FullName: github.Ptr("me/app")}
	row := auditGitHubReleaseProvenance(context.Background(), client, "me", "app", repo)
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "missing verifiable provenance") {
		t.Fatalf("missing native attestation: status=%s detail=%q, want gap", row.Status, row.Detail)
	}
}

func TestReleaseProvenanceRequiresEveryArtifact(t *testing.T) {
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	releases := `[{"tag_name":"v1.0.0","draft":false,"assets":[` +
		`{"name":"app-linux.tar.gz","digest":"` + digestA + `"},` +
		`{"name":"app-darwin.tar.gz","digest":"` + digestB + `"}]}]`
	repo := &github.Repository{FullName: github.Ptr("me/app")}
	one := mockClient(map[string]string{
		"GET /repos/me/app/releases":                releases,
		"GET /repos/me/app/attestations/" + digestA: testNativeAttestationResponse(t, digestA, "https://slsa.dev/provenance/v1"),
	})
	row := auditGitHubReleaseProvenance(context.Background(), one, "me", "app", repo)
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "app-darwin.tar.gz") {
		t.Fatalf("one of two attested: status=%s detail=%q, want gap naming uncovered artifact", row.Status, row.Detail)
	}
	all := mockClient(map[string]string{
		"GET /repos/me/app/releases":                releases,
		"GET /repos/me/app/attestations/" + digestA: testNativeAttestationResponse(t, digestA, "https://slsa.dev/provenance/v1"),
		"GET /repos/me/app/attestations/" + digestB: testNativeAttestationResponse(t, digestB, "https://slsa.dev/provenance/v1"),
	})
	row = auditGitHubReleaseProvenance(context.Background(), all, "me", "app", repo)
	if row.Status != string(StatusCompliant) || !strings.Contains(row.Detail, "all 2") {
		t.Fatalf("all artifacts attested: status=%s detail=%q, want compliant", row.Status, row.Detail)
	}
}

func TestReleaseProvenanceDoesNotTrustSidecarNames(t *testing.T) {
	repo := &github.Repository{FullName: github.Ptr("me/app")}
	oneSidecar := mockClient(map[string]string{
		"GET /repos/me/app/releases": `[{"tag_name":"v1.0.0","draft":false,"assets":[{"name":"linux.tar.gz"},{"name":"darwin.tar.gz"},{"name":"linux.tar.gz.sig"}]}]`,
	})
	row := auditGitHubReleaseProvenance(context.Background(), oneSidecar, "me", "app", repo)
	if row.Status != string(StatusSkipped) || !strings.Contains(row.Detail, "darwin.tar.gz") {
		t.Fatalf("one sidecar for two artifacts: status=%s detail=%q, want skipped naming unverifiable artifact", row.Status, row.Detail)
	}
}

func TestReleaseProvenanceSkipsWhenOneAttestationQueryIsUnavailable(t *testing.T) {
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	validResponse := testNativeAttestationResponse(t, digestA, "https://slsa.dev/provenance/v1")
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/repos/me/app/releases":
			return jsonResponse(`[{"tag_name":"v1.0.0","draft":false,"assets":[{"name":"linux.tar.gz","digest":"` + digestA + `"},{"name":"darwin.tar.gz","digest":"` + digestB + `"}]}]`), nil
		case "/repos/me/app/attestations/" + digestA:
			return jsonResponse(validResponse), nil
		case "/repos/me/app/attestations/" + digestB:
			return &http.Response{StatusCode: http.StatusForbidden, Status: "403 Forbidden", Header: make(http.Header), Body: http.NoBody, Request: req}, nil
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
		}
	})})
	repo := &github.Repository{FullName: github.Ptr("me/app")}
	row := auditGitHubReleaseProvenance(context.Background(), client, "me", "app", repo)
	if row.Status != string(StatusSkipped) || !strings.Contains(row.Detail, "attestations API unavailable") {
		t.Fatalf("partial API visibility: status=%s detail=%q, want skipped", row.Status, row.Detail)
	}
}

func TestSelfHostedRunners(t *testing.T) {
	public := &github.Repository{FullName: github.Ptr("me/app"), Private: github.Ptr(false)}
	private := &github.Repository{FullName: github.Ptr("me/app"), Private: github.Ptr(true)}
	withRunners := map[string]string{"GET /repos/me/app/actions/runners": `{"total_count":2,"runners":[{"id":1},{"id":2}]}`}
	none := map[string]string{"GET /repos/me/app/actions/runners": `{"total_count":0,"runners":[]}`}

	if row := auditGitHubSelfHostedRunners(context.Background(), mockClient(withRunners), "me", "app", public); row.Status != string(StatusGap) {
		t.Errorf("public repo with runners: status=%s detail=%q, want gap", row.Status, row.Detail)
	}
	if row := auditGitHubSelfHostedRunners(context.Background(), mockClient(withRunners), "me", "app", private); row.Status != string(StatusCompliant) {
		t.Errorf("private repo with runners: status=%s, want compliant", row.Status)
	}
	if row := auditGitHubSelfHostedRunners(context.Background(), mockClient(none), "me", "app", public); row.Status != string(StatusCompliant) {
		t.Errorf("no runners: status=%s, want compliant", row.Status)
	}
	// unknown route -> 404 -> needs-admin skip
	if row := auditGitHubSelfHostedRunners(context.Background(), mockClient(nil), "me", "app", public); row.Status != string(StatusSkipped) {
		t.Errorf("no admin access: status=%s, want skipped", row.Status)
	}
}

func TestOrgRunnerGroups(t *testing.T) {
	open := mockClient(map[string]string{
		"GET /orgs/acme/actions/runner-groups": `{"total_count":2,"runner_groups":[{"name":"default","allows_public_repositories":true},{"name":"safe","allows_public_repositories":false}]}`,
	})
	row := auditGitHubOrgRunnerGroups(context.Background(), open, "acme", true)
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "default") {
		t.Fatalf("open runner group: status=%s detail=%q, want gap naming the group", row.Status, row.Detail)
	}
	row = auditGitHubOrgRunnerGroups(context.Background(), open, "acme", false)
	if row.Status != string(StatusGap) || strings.Contains(row.Detail, "default") {
		t.Fatalf("identifiers hidden: detail=%q must not name groups", row.Detail)
	}
	closed := mockClient(map[string]string{
		"GET /orgs/acme/actions/runner-groups": `{"total_count":1,"runner_groups":[{"name":"safe","allows_public_repositories":false}]}`,
	})
	if row := auditGitHubOrgRunnerGroups(context.Background(), closed, "acme", false); row.Status != string(StatusCompliant) {
		t.Fatalf("closed groups: status=%s, want compliant", row.Status)
	}
}

func TestOrgRunnerGroupsPaginates(t *testing.T) {
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Query().Get("page") == "2" {
			return jsonResponse(`{"total_count":2,"runner_groups":[{"name":"unsafe-second-page","allows_public_repositories":true}]}`), nil
		}
		resp := jsonResponse(`{"total_count":2,"runner_groups":[{"name":"safe","allows_public_repositories":false}]}`)
		resp.Header.Set("Link", `<https://api.github.com/orgs/acme/actions/runner-groups?page=2>; rel="next"`)
		return resp, nil
	})})
	row := auditGitHubOrgRunnerGroups(context.Background(), client, "acme", true)
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "unsafe-second-page") {
		t.Fatalf("second-page open runner group: status=%s detail=%q, want gap", row.Status, row.Detail)
	}
}

func TestOrgRunnerGroupsRejectsTruncatedTotal(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /orgs/acme/actions/runner-groups": `{"total_count":2,"runner_groups":[{"id":1,"name":"safe","allows_public_repositories":false}]}`,
	})
	row := auditGitHubOrgRunnerGroups(context.Background(), client, "acme", false)
	if row.Status != string(StatusError) || !strings.Contains(row.Detail, "only 1 of 2") {
		t.Fatalf("truncated runner groups: status=%s detail=%q, want error", row.Status, row.Detail)
	}
}

func TestTagAndPushRulesets(t *testing.T) {
	repo := &github.Repository{FullName: github.Ptr("me/app"), DefaultBranch: github.Ptr("main")}
	tagged := mockClient(map[string]string{
		"GET /repos/me/app/rulesets":   `[{"id":1,"name":"tags","target":"tag","enforcement":"active"},{"id":2,"name":"pushes","target":"push","enforcement":"active"}]`,
		"GET /repos/me/app/rulesets/1": `{"id":1,"name":"tags","target":"tag","enforcement":"active","bypass_actors":[{"actor_id":123,"actor_type":"User","bypass_mode":"always"}],"conditions":{"ref_name":{"include":["refs/tags/v*"],"exclude":[]}},"rules":[{"type":"creation"},{"type":"deletion"},{"type":"non_fast_forward"}]}`,
		"GET /repos/me/app/rulesets/2": `{"id":2,"name":"pushes","target":"push","enforcement":"active","rules":[{"type":"max_file_size","parameters":{"max_file_size":100}}]}`,
	})
	rc := &rulesetListCache{}
	if row := auditGitHubTagProtection(context.Background(), tagged, "me", "app", repo, rc); row.Status != string(StatusCompliant) {
		t.Errorf("active tag ruleset: status=%s detail=%q, want compliant", row.Status, row.Detail)
	}
	if row := auditGitHubPushRuleset(context.Background(), tagged, "me", "app", repo, rc); row.Status != string(StatusCompliant) {
		t.Errorf("active push ruleset: status=%s, want compliant", row.Status)
	}
	incomplete := mockClient(map[string]string{
		"GET /repos/me/app/rulesets":   `[{"id":4,"name":"tags","target":"tag","enforcement":"active"},{"id":5,"name":"empty-push","target":"push","enforcement":"active"}]`,
		"GET /repos/me/app/rulesets/4": `{"id":4,"name":"tags","target":"tag","enforcement":"active","conditions":{"ref_name":{"include":["refs/tags/release-*"],"exclude":[]}},"rules":[{"type":"deletion"}]}`,
		"GET /repos/me/app/rulesets/5": `{"id":5,"name":"empty-push","target":"push","enforcement":"active","rules":[]}`,
	})
	rc = &rulesetListCache{}
	if row := auditGitHubTagProtection(context.Background(), incomplete, "me", "app", repo, rc); row.Status != string(StatusGap) {
		t.Errorf("ruleset not covering v* tags: status=%s detail=%q, want gap", row.Status, row.Detail)
	}
	if row := auditGitHubPushRuleset(context.Background(), incomplete, "me", "app", repo, rc); row.Status != string(StatusGap) {
		t.Errorf("push ruleset without restriction: status=%s detail=%q, want gap", row.Status, row.Detail)
	}
	branchOnly := mockClient(map[string]string{
		"GET /repos/me/app/rulesets": `[{"id":1,"name":"b","target":"branch","enforcement":"active"},{"id":3,"name":"dry-tags","target":"tag","enforcement":"evaluate"}]`,
	})
	rc = &rulesetListCache{}
	if row := auditGitHubTagProtection(context.Background(), branchOnly, "me", "app", repo, rc); row.Status != string(StatusGap) {
		t.Errorf("no active tag ruleset: status=%s, want gap", row.Status)
	}
	if row := auditGitHubPushRuleset(context.Background(), branchOnly, "me", "app", repo, rc); row.Status != string(StatusGap) {
		t.Errorf("no push ruleset: status=%s, want gap", row.Status)
	}
}

func TestNarrowAuditedTagBypass(t *testing.T) {
	user := github.BypassActorType("User")
	for _, tc := range []struct {
		name   string
		actors []*github.BypassActor
		want   bool
	}{
		{"user", []*github.BypassActor{{ActorID: github.Ptr(int64(1)), ActorType: &user, BypassMode: github.Ptr(github.BypassModeAlways)}}, true},
		{"integration", []*github.BypassActor{{ActorID: github.Ptr(int64(2)), ActorType: github.Ptr(github.BypassActorTypeIntegration), BypassMode: github.Ptr(github.BypassModeAlways)}}, true},
		{"team", []*github.BypassActor{{ActorID: github.Ptr(int64(3)), ActorType: github.Ptr(github.BypassActorTypeTeam), BypassMode: github.Ptr(github.BypassModeAlways)}}, true},
		{"none", nil, false},
		{"missing identity", []*github.BypassActor{{ActorType: &user, BypassMode: github.Ptr(github.BypassModeAlways)}}, false},
		{"zero identity", []*github.BypassActor{{ActorID: github.Ptr(int64(0)), ActorType: &user, BypassMode: github.Ptr(github.BypassModeAlways)}}, false},
		{"organization admin", []*github.BypassActor{{ActorID: github.Ptr(int64(1)), ActorType: github.Ptr(github.BypassActorTypeOrganizationAdmin), BypassMode: github.Ptr(github.BypassModeAlways)}}, false},
		{"deploy key", []*github.BypassActor{{ActorID: github.Ptr(int64(1)), ActorType: github.Ptr(github.BypassActorTypeDeployKey), BypassMode: github.Ptr(github.BypassModeAlways)}}, false},
		{"repository role", []*github.BypassActor{{ActorID: github.Ptr(int64(5)), ActorType: github.Ptr(github.BypassActorTypeRepositoryRole), BypassMode: github.Ptr(github.BypassModeAlways)}}, false},
		{"exempt", []*github.BypassActor{{ActorID: github.Ptr(int64(1)), ActorType: &user, BypassMode: github.Ptr(github.BypassModeExempt)}}, false},
	} {
		if got, _ := narrowAuditedTagBypass(tc.actors); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestRulesetTargetsEveryReleaseTag(t *testing.T) {
	conditions := func(include, exclude []string) *github.RepositoryRulesetConditions {
		return &github.RepositoryRulesetConditions{RefName: &github.RepositoryRulesetRefConditionParameters{Include: include, Exclude: exclude}}
	}
	for _, tc := range []struct {
		name       string
		conditions *github.RepositoryRulesetConditions
		want       bool
	}{
		{"all refs", nil, true},
		{"release wildcard", conditions([]string{"refs/tags/v*"}, nil), true},
		{"cross-segment release wildcard", conditions([]string{"refs/tags/v**"}, nil), true},
		{"all pattern", conditions([]string{"~ALL"}, nil), true},
		{"sampled versions only", conditions([]string{"refs/tags/v1*", "refs/tags/v0*"}, nil), false},
		{"release wildcard with unrelated exclusion", conditions([]string{"refs/tags/v*"}, []string{"refs/tags/v-internal*"}), false},
		{"release wildcard excluding v2", conditions([]string{"refs/tags/v*"}, []string{"refs/tags/v2*"}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ruleset := &github.RepositoryRuleset{Conditions: tc.conditions}
			if got := rulesetTargetsReleaseTags(ruleset); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMergeQueueRule(t *testing.T) {
	repo := &github.Repository{FullName: github.Ptr("me/app"), DefaultBranch: github.Ptr("main")}
	withQueue := mockClient(map[string]string{
		"GET /repos/me/app/rulesets":   `[{"id":7,"name":"mq","target":"branch","enforcement":"active"}]`,
		"GET /repos/me/app/rulesets/7": `{"id":7,"name":"mq","target":"branch","enforcement":"active","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"rules":[{"type":"merge_queue"}]}`,
	})
	if row := auditGitHubMergeQueue(context.Background(), withQueue, "me", "app", repo, &rulesetListCache{}); row.Status != string(StatusCompliant) {
		t.Errorf("merge queue rule: status=%s detail=%q, want compliant", row.Status, row.Detail)
	}
	without := mockClient(map[string]string{
		"GET /repos/me/app/rulesets":   `[{"id":7,"name":"mq","target":"branch","enforcement":"active"}]`,
		"GET /repos/me/app/rulesets/7": `{"id":7,"name":"mq","target":"branch","enforcement":"active","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"rules":[{"type":"non_fast_forward"}]}`,
	})
	if row := auditGitHubMergeQueue(context.Background(), without, "me", "app", repo, &rulesetListCache{}); row.Status != string(StatusGap) {
		t.Errorf("no merge queue: status=%s, want gap", row.Status)
	}
}

func TestComplianceRefs(t *testing.T) {
	known := auditControlKeys()
	for key := range complianceRefs {
		if !known[key] {
			t.Errorf("complianceRefs maps unknown control %q", key)
		}
	}
	rows := []auditRow{{Repo: "me/app", Control: "workflow-unpinned-actions", Status: string(StatusGap)}}
	stampComplianceRefs(rows)
	found := false
	for _, ref := range rows[0].Refs {
		if ref == "Scorecard:Pinned-Dependencies" {
			found = true
		}
	}
	if !found {
		t.Fatalf("refs = %v, want Scorecard:Pinned-Dependencies", rows[0].Refs)
	}
	sarif := auditSARIF(rows)
	runs := sarif["runs"].([]map[string]any)
	rules := runs[0]["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]map[string]any)
	props, ok := rules[0]["properties"].(map[string]any)
	if !ok || len(props["tags"].([]string)) == 0 {
		t.Fatalf("SARIF rule missing compliance tags: %+v", rules[0])
	}
}
