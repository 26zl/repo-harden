package repoharden

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-github/v88/github"
)

// workflowRoutes builds mockClient routes serving the given workflow files
// for me/app, plus any extra routes (e.g. the OIDC subject-claim endpoint).
func workflowRoutes(t *testing.T, files map[string]string, extra map[string]string) map[string]string {
	t.Helper()
	routes := map[string]string{}
	list := make([]map[string]any, 0, len(files))
	for name := range files {
		list = append(list, map[string]any{"type": "file", "name": name, "path": ".github/workflows/" + name})
		routes["GET /repos/me/app/contents/.github/workflows/"+name] = fmt.Sprintf(
			`{"type":"file","name":%q,"path":".github/workflows/%s","encoding":"base64","content":%q}`,
			name, name, base64.StdEncoding.EncodeToString([]byte(files[name])))
	}
	listJSON, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	routes["GET /repos/me/app/contents/.github/workflows"] = string(listJSON)
	for k, v := range extra {
		routes[k] = v
	}
	return routes
}

func TestUnpinnedActionRef(t *testing.T) {
	cases := []struct{ name, ref, want string }{
		{"third-party tag", "goreleaser/goreleaser-action@v7", "goreleaser/goreleaser-action@v7"},
		{"third-party branch", "someone/tool@main", "someone/tool@main"},
		{"third-party 40-hex SHA", "goreleaser/goreleaser-action@" + strings.Repeat("a", 40), ""},
		{"third-party 64-hex SHA", "someone/tool@" + strings.Repeat("0", 64), ""},
		{"short hex is not a pin", "someone/tool@abc123", "someone/tool@abc123"},
		{"first-party actions", "actions/checkout@v4", ""},
		{"first-party github", "github/codeql-action/init@v3", ""},
		{"local action", "./.github/actions/build", ""},
		{"docker digest", "docker://alpine@sha256:" + strings.Repeat("d", 64), ""},
		{"short docker digest", "docker://alpine@sha256:deadbeef", "docker://alpine@sha256:deadbeef"},
		{"docker digest with trailing data", "docker://alpine@sha256:" + strings.Repeat("d", 64) + "oops", "docker://alpine@sha256:" + strings.Repeat("d", 64) + "oops"},
		{"docker tag", "docker://alpine:3.20", "docker://alpine:3.20"},
		{"no ref at all", "someone/tool", "someone/tool"},
		{"reusable workflow", "someone/shared/.github/workflows/ci.yml@v1", "someone/shared/.github/workflows/ci.yml@v1"},
		{"not an action reference", "make build", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		if got := unpinnedActionRef(c.ref); got != c.want {
			t.Errorf("%s: unpinnedActionRef(%q) = %q, want %q", c.name, c.ref, got, c.want)
		}
	}
}

func TestWorkflowUnpinnedUses(t *testing.T) {
	content := `
on: push
jobs:
  shared:
    uses: someone/shared/.github/workflows/ci.yml@v1
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: goreleaser/goreleaser-action@v7
      - uses: goreleaser/goreleaser-action@v7
      - uses: pinned/tool@` + strings.Repeat("b", 40) + `
      - run: make build
`
	w, err := parseWorkflow(content)
	if err != nil {
		t.Fatal(err)
	}
	got := workflowUnpinnedUses(w)
	want := []string{"goreleaser/goreleaser-action@v7", "someone/shared/.github/workflows/ci.yml@v1"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("workflowUnpinnedUses = %v, want %v", got, want)
	}
}

func TestWorkflowPwnRequestJobs(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    int
	}{
		{"pull_request_target + head ref checkout", `
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`, 1},
		{"trigger list form + github.head_ref", `
on: [push, pull_request_target]
jobs:
  build:
    steps:
      - uses: actions/checkout@` + strings.Repeat("c", 40) + `
        with:
          ref: ${{ github.head_ref }}
`, 1},
		{"plain pull_request is unprivileged", `
on: pull_request
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`, 0},
		{"pull_request_target without PR-head checkout", `
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
`, 0},
	}
	for _, c := range cases {
		w, err := parseWorkflow(c.content)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := workflowPwnRequestJobs(w); len(got) != c.want {
			t.Errorf("%s: got %v, want %d job(s)", c.name, got, c.want)
		}
	}
}

func TestWorkflowInjectionContexts(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []string
	}{
		{"issue title in run", `
on: issues
jobs:
  triage:
    steps:
      - run: echo "${{ github.event.issue.title }}"
`, []string{"github.event.issue.title"}},
		{"safe contexts only", `
on: push
jobs:
  build:
    steps:
      - run: echo "${{ github.sha }} on ${{ github.ref_name }}"
`, nil},
		{"env indirection is the fix", `
on: issues
jobs:
  triage:
    steps:
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "$TITLE"
`, nil},
		{"workflow_run head branch", `
on: workflow_run
jobs:
  ci:
    steps:
      - run: echo "${{ github.event.workflow_run.head_branch }}"
`, []string{"github.event.workflow_run.head_branch"}},
		{"github-script body", `
on: issue_comment
jobs:
  reply:
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            console.log(` + "`${{ github.event.comment.body }}`" + `)
`, []string{"github.event.comment.body"}},
		{"multiline run with head ref", `
on: pull_request_target
jobs:
  build:
    steps:
      - run: |
          BRANCH="${{ github.head_ref }}"
          echo "$BRANCH"
`, []string{"github.head_ref"}},
	}
	for _, c := range cases {
		w, err := parseWorkflow(c.content)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := workflowInjectionContexts(w)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			}
		}
	}
}

func TestWorkflowCloudAuthJobs(t *testing.T) {
	deploy := `
on: push
permissions:
  id-token: write
jobs:
  deploy:
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
  test:
    steps:
      - run: make test
`
	w, err := parseWorkflow(deploy)
	if err != nil {
		t.Fatal(err)
	}
	found, unprotected := workflowCloudAuthJobs(w)
	if !found || len(unprotected) != 1 || unprotected[0] != "deploy" {
		t.Fatalf("OIDC without environment: found=%v unprotected=%v, want deploy flagged", found, unprotected)
	}

	gated := strings.Replace(deploy, "  deploy:\n", "  deploy:\n    environment: production\n", 1)
	w, err = parseWorkflow(gated)
	if err != nil {
		t.Fatal(err)
	}
	found, unprotected = workflowCloudAuthJobs(w)
	if !found || len(unprotected) != 0 {
		t.Fatalf("environment-gated cloud auth: found=%v unprotected=%v, want none unprotected", found, unprotected)
	}

	withoutPermission := strings.Replace(deploy, "permissions:\n  id-token: write\n", "", 1)
	w, err = parseWorkflow(withoutPermission)
	if err != nil {
		t.Fatal(err)
	}
	if found, unprotected = workflowCloudAuthJobs(w); !found || len(unprotected) != 1 || unprotected[0] != "deploy" {
		t.Fatalf("OIDC without token permission: found=%v unprotected=%v, want deploy flagged", found, unprotected)
	}

	staticCredentials := `
on: push
jobs:
  deploy:
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
`
	w, err = parseWorkflow(staticCredentials)
	if err != nil {
		t.Fatal(err)
	}
	if found, _ = workflowCloudAuthJobs(w); found {
		t.Fatal("static cloud credentials must not be reported as OIDC")
	}

	w, err = parseWorkflow("on: push\njobs:\n  build:\n    steps:\n      - run: make\n")
	if err != nil {
		t.Fatal(err)
	}
	if found, _ = workflowCloudAuthJobs(w); found {
		t.Fatal("no cloud steps must not report cloud auth")
	}
}

func TestStepUsesCloudOIDCModeDetection(t *testing.T) {
	cases := []struct {
		name string
		step workflowStep
		want bool
	}{
		{"AWS role federation", workflowStep{Uses: "aws-actions/configure-aws-credentials@v4", With: map[string]any{"role-to-assume": "arn:aws:iam::1:role/deploy"}}, true},
		{"AWS static credentials", workflowStep{Uses: "aws-actions/configure-aws-credentials@v4", With: map[string]any{"role-to-assume": "arn:aws:iam::1:role/deploy", "aws-access-key-id": "secret"}}, false},
		{"Google workload identity", workflowStep{Uses: "google-github-actions/auth@v3", With: map[string]any{"workload_identity_provider": "projects/1/providers/github"}}, true},
		{"Google service account key", workflowStep{Uses: "google-github-actions/auth@v3", With: map[string]any{"credentials_json": "secret"}}, false},
		{"Azure federated login", workflowStep{Uses: "azure/login@v3", With: map[string]any{"client-id": "client", "tenant-id": "tenant"}}, true},
		{"Azure client secret", workflowStep{Uses: "azure/login@v3", With: map[string]any{"creds": "secret", "client-id": "client", "tenant-id": "tenant"}}, false},
		{"Vault JWT", workflowStep{Uses: "hashicorp/vault-action@v4", With: map[string]any{"method": "jwt"}}, true},
		{"Vault token", workflowStep{Uses: "hashicorp/vault-action@v4", With: map[string]any{"method": "token"}}, false},
		{"lookalike action", workflowStep{Uses: "aws-actions/configure-aws-credentials-backdoor@v1", With: map[string]any{"role-to-assume": "role"}}, false},
		{"null role input", workflowStep{Uses: "aws-actions/configure-aws-credentials@v4", With: map[string]any{"role-to-assume": nil}}, false},
	}
	for _, test := range cases {
		if got := stepUsesCloudOIDC(test.step); got != test.want {
			t.Errorf("%s: got %v, want %v", test.name, got, test.want)
		}
	}
}

func TestGitHubEnvironmentProtected(t *testing.T) {
	cases := []struct {
		name        string
		env         *github.Environment
		customRules []*github.CustomDeploymentProtectionRule
		want        bool
	}{
		{"nil", nil, nil, false},
		{"empty", &github.Environment{}, nil, false},
		{"empty policy object", &github.Environment{DeploymentBranchPolicy: &github.BranchPolicy{}}, nil, false},
		{"both policy flags false", &github.Environment{DeploymentBranchPolicy: &github.BranchPolicy{ProtectedBranches: github.Ptr(false), CustomBranchPolicies: github.Ptr(false)}}, nil, false},
		{"protected branches", &github.Environment{DeploymentBranchPolicy: &github.BranchPolicy{ProtectedBranches: github.Ptr(true)}}, nil, true},
		{"custom branch or tag policy", &github.Environment{DeploymentBranchPolicy: &github.BranchPolicy{CustomBranchPolicies: github.Ptr(true)}}, nil, true},
		{"top-level wait timer", &github.Environment{WaitTimer: github.Ptr(10)}, nil, false},
		{"zero wait timer", &github.Environment{ProtectionRules: []*github.ProtectionRule{{Type: github.Ptr("wait_timer"), WaitTimer: github.Ptr(0)}}}, nil, false},
		{"wait timer", &github.Environment{ProtectionRules: []*github.ProtectionRule{{Type: github.Ptr("wait_timer"), WaitTimer: github.Ptr(10)}}}, nil, false},
		{"empty top-level reviewer", &github.Environment{Reviewers: []*github.EnvReviewers{nil}}, nil, false},
		{"top-level reviewer", &github.Environment{Reviewers: []*github.EnvReviewers{{Type: github.Ptr("User"), ID: github.Ptr(int64(1))}}}, nil, true},
		{"empty reviewers", &github.Environment{ProtectionRules: []*github.ProtectionRule{{Type: github.Ptr("required_reviewers")}}}, nil, false},
		{"required reviewer", &github.Environment{ProtectionRules: []*github.ProtectionRule{{Type: github.Ptr("required_reviewers"), Reviewers: []*github.RequiredReviewer{{Type: github.Ptr("User")}}}}}, nil, true},
		{"generic custom metadata", &github.Environment{ProtectionRules: []*github.ProtectionRule{{Type: github.Ptr("custom")}}}, nil, false},
		{"disabled named custom gate", &github.Environment{}, []*github.CustomDeploymentProtectionRule{{Enabled: github.Ptr(false), App: &github.CustomDeploymentProtectionRuleApp{Slug: github.Ptr("change-control")}}}, false},
		{"unnamed custom gate", &github.Environment{}, []*github.CustomDeploymentProtectionRule{{Enabled: github.Ptr(true), App: &github.CustomDeploymentProtectionRuleApp{}}}, false},
		{"enabled named custom gate", &github.Environment{}, []*github.CustomDeploymentProtectionRule{{Enabled: github.Ptr(true), App: &github.CustomDeploymentProtectionRuleApp{Slug: github.Ptr("change-control")}}}, true},
	}
	for _, test := range cases {
		if got := githubEnvironmentProtected(test.env, test.customRules); got != test.want {
			t.Errorf("%s: got %v, want %v", test.name, got, test.want)
		}
	}
}

func TestMeaningfulOIDCClaimKeys(t *testing.T) {
	withoutEnvironment := []workflowOIDCJob{{name: "deploy", hasEnvironment: false}}
	if got := meaningfulOIDCClaimKeys([]string{"repo", "repository_visibility", "environment", "REF", "ref"}, withoutEnvironment); len(got) != 1 || got[0] != "ref" {
		t.Fatalf("claims without a job environment = %v, want [ref]", got)
	}
	withEnvironment := []workflowOIDCJob{{name: "deploy", hasEnvironment: true, environment: "production"}}
	got := meaningfulOIDCClaimKeys([]string{"repo", "environment", "job_workflow_ref", "sha"}, withEnvironment)
	want := []string{"environment", "job_workflow_ref", "sha"}
	if len(got) != len(want) {
		t.Fatalf("claims with an environment = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("claims with an environment = %v, want %v", got, want)
		}
	}
}

func TestJobHasIDTokenWriteUsesEffectivePermissions(t *testing.T) {
	workflow := &parsedWorkflow{Permissions: map[string]any{"id-token": "write"}}
	if !jobHasIDTokenWrite(workflow, workflowJob{}) {
		t.Fatal("top-level id-token grant should be inherited")
	}
	if jobHasIDTokenWrite(workflow, workflowJob{Permissions: map[string]any{"contents": "read"}}) {
		t.Fatal("job permissions replace top-level permissions and must remove id-token access")
	}
	if !jobHasIDTokenWrite(&parsedWorkflow{Permissions: "none"}, workflowJob{Permissions: map[string]any{"id-token": "write"}}) {
		t.Fatal("job-scoped id-token grant should be effective")
	}
}

func TestAuditGitHubWorkflowUnpinnedActionsGap(t *testing.T) {
	client := mockClient(workflowRoutes(t, map[string]string{
		"release.yml": "on: push\njobs:\n  rel:\n    steps:\n      - uses: goreleaser/goreleaser-action@v7\n",
	}, nil))
	repo := &github.Repository{FullName: github.Ptr("me/app"), DefaultBranch: github.Ptr("main")}
	row := auditGitHubWorkflowUnpinnedActions(context.Background(), client, "me", "app", repo, &workflowFileCache{})
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "goreleaser/goreleaser-action@v7") {
		t.Fatalf("status=%s detail=%q, want gap naming the unpinned ref", row.Status, row.Detail)
	}
}

func TestAuditGitHubOIDCCloudTrust(t *testing.T) {
	deploy := "on: push\npermissions:\n  id-token: write\njobs:\n  deploy:\n    steps:\n      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n          role-to-assume: arn:aws:iam::123456789012:role/deploy\n"
	gated := "on: push\npermissions:\n  id-token: write\njobs:\n  deploy:\n    environment: production\n    steps:\n      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n          role-to-assume: arn:aws:iam::123456789012:role/deploy\n"
	repo := &github.Repository{FullName: github.Ptr("me/app"), DefaultBranch: github.Ptr("main")}

	cases := []struct {
		name     string
		workflow string
		oidc     string
		env      string
		custom   string
		want     ControlStatus
	}{
		{"unscoped cloud auth", deploy, `{"use_default":true}`, "", "", StatusGap},
		{"protected environment", gated, `{"use_default":true}`, `{"name":"production","protection_rules":[{"type":"required_reviewers","reviewers":[{"type":"User"}]}],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":false}}`, "", StatusCompliant},
		{"empty environment is not protection", gated, `{"use_default":true}`, `{"name":"production","protection_rules":[],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":false}}`, "", StatusGap},
		{"wait timer alone is not protection", gated, `{"use_default":true}`, `{"name":"production","protection_rules":[{"type":"wait_timer","wait_timer":30}]}`, `{"total_count":0,"custom_deployment_protection_rules":[]}`, StatusGap},
		{"named custom deployment gate", gated, `{"use_default":true}`, `{"name":"production","protection_rules":[]}`, `{"total_count":1,"custom_deployment_protection_rules":[{"id":3,"enabled":true,"app":{"slug":"change-control"}}]}`, StatusCompliant},
		{"custom ref claim", deploy, `{"use_default":false,"include_claim_keys":["repo","ref"]}`, "", "", StatusCompliant},
		{"repo-only claim is insufficient", deploy, `{"use_default":false,"include_claim_keys":["repo","repository_visibility"]}`, "", "", StatusGap},
		{"dynamic environment with environment claim", strings.Replace(gated, "environment: production", "environment: ${{ inputs.environment }}", 1), `{"use_default":false,"include_claim_keys":["repo","environment"]}`, "", "", StatusCompliant},
	}
	for _, c := range cases {
		extra := map[string]string{
			"GET /repos/me/app/actions/oidc/customization/sub": c.oidc,
		}
		if c.env != "" {
			extra["GET /repos/me/app/environments/production"] = c.env
		}
		if c.custom != "" {
			extra["GET /repos/me/app/environments/production/deployment_protection_rules"] = c.custom
		}
		client := mockClient(workflowRoutes(t, map[string]string{"deploy.yml": c.workflow}, extra))
		row := auditGitHubOIDCCloudTrust(context.Background(), client, "me", "app", repo, &workflowFileCache{})
		if row.Status != string(c.want) {
			t.Errorf("%s: status=%s detail=%q, want %s", c.name, row.Status, row.Detail, c.want)
		}
	}

	client := mockClient(workflowRoutes(t, map[string]string{
		"ci.yml": "on: push\njobs:\n  build:\n    steps:\n      - run: make\n",
	}, nil))
	row := auditGitHubOIDCCloudTrust(context.Background(), client, "me", "app", repo, &workflowFileCache{})
	if row.Status != string(StatusCompliant) || !strings.Contains(row.Detail, "no cloud OIDC") {
		t.Fatalf("no cloud usage: status=%s detail=%q, want compliant", row.Status, row.Detail)
	}

	missingToken := strings.Replace(deploy, "permissions:\n  id-token: write\n", "", 1)
	client = mockClient(workflowRoutes(t, map[string]string{"deploy.yml": missingToken}, map[string]string{
		"GET /repos/me/app/actions/oidc/customization/sub": `{"use_default":false,"include_claim_keys":["ref"]}`,
	}))
	row = auditGitHubOIDCCloudTrust(context.Background(), client, "me", "app", repo, &workflowFileCache{})
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "id-token: write") {
		t.Fatalf("missing id-token grant: status=%s detail=%q, want gap", row.Status, row.Detail)
	}
}

func TestWorkflowFileCacheSharesFetch(t *testing.T) {
	var listCalls atomic.Int64
	routes := workflowRoutes(t, map[string]string{
		"ci.yml": "on: push\njobs:\n  build:\n    steps:\n      - uses: someone/tool@v1\n",
	}, nil)
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/repos/me/app/contents/.github/workflows" {
			listCalls.Add(1)
		}
		if body, ok := routes[req.Method+" "+req.URL.Path]; ok {
			return jsonResponse(body), nil
		}
		return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody}, nil
	})})
	repo := &github.Repository{FullName: github.Ptr("me/app"), DefaultBranch: github.Ptr("main")}
	wc := &workflowFileCache{}
	auditGitHubWorkflowTokenPermissions(context.Background(), client, "me", "app", repo, wc)
	auditGitHubWorkflowUnpinnedActions(context.Background(), client, "me", "app", repo, wc)
	auditGitHubWorkflowInjection(context.Background(), client, "me", "app", repo, wc)
	auditGitHubWorkflowPwnRequest(context.Background(), client, "me", "app", repo, wc)
	if got := listCalls.Load(); got != 1 {
		t.Fatalf("workflow dir fetched %d times across 4 checks, want 1 (cache miss)", got)
	}
}

func TestAuditGitHubDependencyReview(t *testing.T) {
	repo := &github.Repository{FullName: github.Ptr("me/app"), DefaultBranch: github.Ptr("main")}
	with := mockClient(workflowRoutes(t, map[string]string{
		"deps.yml": "on: pull_request\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/dependency-review-action@v4\n",
	}, nil))
	row := auditGitHubDependencyReview(context.Background(), with, "me", "app", repo, &workflowFileCache{})
	if row.Status != string(StatusCompliant) || !strings.Contains(row.Detail, "deps.yml") {
		t.Fatalf("with action: status=%s detail=%q, want compliant", row.Status, row.Detail)
	}
	for field, value := range map[string]string{"title": row.Title, "detail": row.Detail, "remediation": row.Remediation} {
		if strings.Contains(strings.ToLower(value), "blocking") {
			t.Errorf("%s=%q claims blocking without checking required status checks", field, value)
		}
	}
	if !strings.Contains(row.Detail, "required status-check enforcement not verified") {
		t.Errorf("detail=%q, want explicit required-check scope", row.Detail)
	}
	without := mockClient(workflowRoutes(t, map[string]string{
		"ci.yml": "on: push\njobs:\n  build:\n    steps:\n      - run: make\n",
	}, nil))
	row = auditGitHubDependencyReview(context.Background(), without, "me", "app", repo, &workflowFileCache{})
	if row.Status != string(StatusGap) {
		t.Fatalf("without action: status=%s, want gap", row.Status)
	}

	wrongTrigger := mockClient(workflowRoutes(t, map[string]string{
		"deps.yml": "on: schedule\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/dependency-review-action@v4\n",
	}, nil))
	row = auditGitHubDependencyReview(context.Background(), wrongTrigger, "me", "app", repo, &workflowFileCache{})
	if row.Status != string(StatusGap) {
		t.Fatalf("action on schedule: status=%s, want gap", row.Status)
	}

	disabled := mockClient(workflowRoutes(t, map[string]string{
		"deps.yml": "on: merge_group\njobs:\n  review:\n    if: false\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/dependency-review-action@v4\n",
	}, nil))
	row = auditGitHubDependencyReview(context.Background(), disabled, "me", "app", repo, &workflowFileCache{})
	if row.Status != string(StatusGap) {
		t.Fatalf("disabled dependency-review job: status=%s, want gap", row.Status)
	}

	mergeQueue := mockClient(workflowRoutes(t, map[string]string{
		"deps.yml": "on: merge_group\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/dependency-review-action@v4\n",
	}, nil))
	row = auditGitHubDependencyReview(context.Background(), mergeQueue, "me", "app", repo, &workflowFileCache{})
	if row.Status != string(StatusGap) {
		t.Fatalf("merge-group-only dependency review: status=%s, want gap", row.Status)
	}

	noWorkflows := mockClient(workflowRoutes(t, nil, nil))
	row = auditGitHubDependencyReview(context.Background(), noWorkflows, "me", "app", repo, &workflowFileCache{})
	if row.Status != string(StatusGap) {
		t.Fatalf("no workflows: status=%s, want gap", row.Status)
	}
}

func TestWorkflowRunsDependencyReviewRequiresRunnablePRJob(t *testing.T) {
	cases := []struct {
		name     string
		workflow string
		want     bool
	}{
		{"pull request", "on: pull_request\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/dependency-review-action@v5\n", true},
		{"merge group only", "on: merge_group\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/dependency-review-action@v5\n", false},
		{"pull request and merge group", "on: [pull_request, merge_group]\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/dependency-review-action@v5\n", true},
		{"wrong trigger", "on: push\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/dependency-review-action@v5\n", false},
		{"PR close-only trigger", "on:\n  pull_request:\n    types: [closed]\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/dependency-review-action@v5\n", false},
		{"PR trigger omits synchronize despite merge group", "on:\n  pull_request:\n    types: [opened]\n  merge_group:\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/dependency-review-action@v5\n", false},
		{"invalid pull request config", "on:\n  pull_request: false\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/dependency-review-action@v5\n", false},
		{"PR synchronize trigger", "on:\n  pull_request:\n    types: [opened, synchronize]\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/dependency-review-action@v5\n", true},
		{"missing runner", "on: pull_request\njobs:\n  review:\n    steps:\n      - uses: actions/dependency-review-action@v5\n", false},
		{"disabled job", "on: pull_request\njobs:\n  review:\n    if: ${{ false }}\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/dependency-review-action@v5\n", false},
		{"disabled step", "on: pull_request\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - if: false\n        uses: actions/dependency-review-action@v5\n", false},
		{"job restricted to merge group", "on: [pull_request, merge_group]\njobs:\n  review:\n    if: github.event_name == 'merge_group'\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/dependency-review-action@v5\n", false},
		{"step restricted to merge group", "on: [pull_request, merge_group]\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - if: ${{ github.event_name != 'pull_request' }}\n        uses: actions/dependency-review-action@v5\n", false},
		{"job restricted to pull request", "on: [pull_request, merge_group]\njobs:\n  review:\n    if: github.event_name == 'pull_request'\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/dependency-review-action@v5\n", true},
		{"step allows PR or merge group", "on: [pull_request, merge_group]\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.event_name == 'pull_request' || github.event_name == 'merge_group'\n        uses: actions/dependency-review-action@v5\n", true},
		{"continue-on-error step", "on: pull_request\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - continue-on-error: true\n        uses: actions/dependency-review-action@v5\n", false},
		{"continue-on-error job", "on: pull_request\njobs:\n  review:\n    continue-on-error: true\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/dependency-review-action@v5\n", false},
		{"lookalike action", "on: pull_request\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/dependency-review-action-unsafe@v5\n", false},
	}
	for _, test := range cases {
		workflow, err := parseWorkflow(test.workflow)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if got := workflowRunsDependencyReview(workflow); got != test.want {
			t.Errorf("%s: got %v, want %v", test.name, got, test.want)
		}
	}
}

func TestWorkflowPermissionScopeValidation(t *testing.T) {
	cases := []struct {
		name        string
		workflow    string
		wantProblem string
	}{
		{
			name:     "three job-scoped release writes",
			workflow: "permissions:\n  contents: read\njobs:\n  release:\n    permissions:\n      contents: write\n      id-token: write\n      attestations: write\n    steps:\n      - run: gh release create v1 dist/*\n      - uses: actions/attest-build-provenance@v4\n",
		},
		{
			name:        "unknown scope",
			workflow:    "permissions:\n  everything: write\njobs:\n  x: {}\n",
			wantProblem: "unknown permission scope: everything",
		},
		{
			name:        "id-token cannot be read",
			workflow:    "permissions:\n  id-token: read\njobs:\n  x: {}\n",
			wantProblem: "invalid permission value: id-token",
		},
		{
			name:        "scalar read-all is broader than an exact map",
			workflow:    "permissions: read-all\njobs:\n  x: {}\n",
			wantProblem: "read-all token",
		},
		{
			name:        "job scalar read-all is broader than an exact map",
			workflow:    "permissions: none\njobs:\n  x:\n    permissions: read-all\n",
			wantProblem: "read-all token",
		},
		{
			name:        "multiple writes must not fan out to every job",
			workflow:    "permissions:\n  contents: write\n  packages: write\njobs:\n  x: {}\n",
			wantProblem: "top-level write permissions must be job-scoped: contents, packages",
		},
		{
			name:        "explicit write-all by enumeration",
			workflow:    "jobs:\n  x:\n    permissions:\n      actions: write\n      checks: write\n      contents: write\n      deployments: write\n      issues: write\n",
			wantProblem: "job x has write permissions without a recognized need: actions, checks, contents, deployments, issues",
		},
	}
	for _, test := range cases {
		if got := workflowPermissionIssue(test.workflow); got != test.wantProblem {
			t.Errorf("%s: got %q, want %q", test.name, got, test.wantProblem)
		}
	}
}

func TestWorkflowWritePermissionsRequireConcreteEvidence(t *testing.T) {
	workflow := func(scope, steps string) string {
		return "permissions:\n  contents: read\njobs:\n  deploy:\n    permissions:\n      " + scope + ": write\n    steps:\n" + steps
	}
	cases := []struct {
		name      string
		content   string
		wantIssue bool
	}{
		{"release contents", workflow("contents", "      - run: gh release create v1 dist/*\n"), false},
		{"release upload recovery", workflow("contents", "      - run: |\n          if ! gh release upload v1 dist/app; then\n            echo retry\n          fi\n"), false},
		{"release API recovery", workflow("contents", "      - run: |\n          if ! gh api --method PATCH repos/me/app/releases/1 -F draft=false; then\n            echo retry\n          fi\n"), false},
		{"attestation", workflow("attestations", "      - uses: actions/attest-build-provenance@v4\n"), false},
		{"attestation OIDC", workflow("id-token", "      - uses: actions/attest-build-provenance@v4\n"), false},
		{"cloud OIDC", workflow("id-token", "      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n          role-to-assume: arn:aws:iam::1:role/deploy\n"), false},
		{"CodeQL upload", workflow("security-events", "      - uses: github/codeql-action/upload-sarif@v4\n"), false},
		{"package push", workflow("packages", "      - uses: docker/build-push-action@v7\n        with:\n          push: true\n"), false},
		{"Pages deployment", workflow("pages", "      - uses: actions/deploy-pages@v4\n"), false},
		{"Pages deployment OIDC", workflow("id-token", "      - uses: actions/deploy-pages@v4\n"), false},
		{"pull request mutation", workflow("pull-requests", "      - run: gh pr create --title update --body automated\n"), false},
		{"dependency review comment", workflow("pull-requests", "      - uses: actions/dependency-review-action@v4\n        with:\n          comment-summary-in-pr: on-failure\n"), false},
		{"disabled dependency review comment", workflow("pull-requests", "      - uses: actions/dependency-review-action@v4\n        with:\n          comment-summary-in-pr: never\n"), true},
		{"issue mutation", workflow("issues", "      - run: gh issue comment 1 --body done\n"), false},
		{"check action", workflow("checks", "      - uses: dorny/test-reporter@v2\n"), false},
		{"commit status API", workflow("statuses", "      - run: gh api --method POST repos/me/app/statuses/$GITHUB_SHA\n"), false},
		{"deployment action", workflow("deployments", "      - uses: chrnorm/deployment-action@v2\n"), false},
		{"workflow cancellation", workflow("actions", "      - run: gh run cancel 123\n"), false},
		{"discussion GraphQL", workflow("discussions", "      - uses: actions/github-script@v8\n        with:\n          script: |\n            await github.graphql('mutation { createDiscussion(input: {}) { discussion { id } } }')\n"), false},
		{"unjustified write", workflow("contents", "      - run: go test ./...\n"), true},
		{"comment is not evidence", workflow("contents", "      - run: |\n          # gh release create v1 dist/*\n          echo test\n"), true},
		{"disabled action is not evidence", workflow("pages", "      - if: false\n        uses: actions/deploy-pages@v4\n"), true},
		{"dynamic package push is unverified", workflow("packages", "      - uses: docker/build-push-action@v7\n        with:\n          push: ${{ matrix.publish }}\n"), true},
		{"top-level write remains broad", "permissions:\n  contents: write\njobs:\n  release:\n    steps:\n      - run: gh release create v1 dist/*\n", true},
		{"reusable workflow caller", "permissions:\n  contents: read\njobs:\n  release:\n    permissions:\n      contents: write\n    uses: ./.github/workflows/release.yml\n", false},
	}
	for _, test := range cases {
		issue := workflowPermissionIssue(test.content)
		if got := issue != ""; got != test.wantIssue {
			t.Errorf("%s: issue=%q, wantIssue=%v", test.name, issue, test.wantIssue)
		}
	}
}

func TestWorkflowWritePermissionRejectsUnknownEvidence(t *testing.T) {
	content := `
permissions:
  contents: read
jobs:
  publish:
    permissions:
      contents: write
    steps:
      - uses: unknown/publisher@v1
      - run: echo "gh release create v1 dist/*"
`
	issue := workflowPermissionIssue(content)
	if !strings.Contains(issue, "without a recognized need: contents") {
		t.Fatalf("issue=%q, want unjustified contents write", issue)
	}
}

func TestRepositoryWorkflowsUseJustifiedTokenPermissions(t *testing.T) {
	dir := filepath.Join("..", "..", ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || (filepath.Ext(entry.Name()) != ".yml" && filepath.Ext(entry.Name()) != ".yaml") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Errorf("%s: %v", entry.Name(), err)
			continue
		}
		if issue := workflowPermissionIssue(string(content)); issue != "" {
			t.Errorf("%s: %s", entry.Name(), issue)
		}
	}
}

func TestWorkflowPwnRequestVariants(t *testing.T) {
	checkout := func(trigger, ref string) string {
		w := "on: " + trigger + "\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"
		if ref != "" {
			w += "        with:\n          ref: " + ref + "\n"
		}
		return w
	}
	cases := []struct {
		name     string
		workflow string
		flagged  bool
	}{
		{"head sha", checkout("pull_request_target", "${{ github.event.pull_request.head.sha }}"), true},
		{"head ref", checkout("pull_request_target", "${{ github.head_ref }}"), true},
		{"pull number head", checkout("pull_request_target", "refs/pull/${{ github.event.pull_request.number }}/head"), true},
		{"event number merge", checkout("pull_request_target", "refs/pull/${{ github.event.number }}/merge"), true},
		{"workflow_run head sha", checkout("workflow_run", "${{ github.event.workflow_run.head_sha }}"), true},
		{"workflow_run head branch", checkout("workflow_run", "${{ github.event.workflow_run.head_branch }}"), true},
		{"workflow_run default checkout", checkout("workflow_run", ""), false},
		{"pull_request_target default checkout", checkout("pull_request_target", ""), false},
		{"unprivileged pull_request", checkout("pull_request", "${{ github.event.pull_request.head.sha }}"), false},
		{"merge commit sha", checkout("pull_request_target", "${{ github.event.pull_request.merge_commit_sha }}"), true},
		{"attacker fork repository", "on: pull_request_target\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n", true},
		{"workflow_run head repository", "on: workflow_run\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          repository: ${{ github.event.workflow_run.head_repository.full_name }}\n", true},
	}
	for _, c := range cases {
		w, err := parseWorkflow(c.workflow)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		jobs := workflowPwnRequestJobs(w)
		if got := len(jobs) > 0; got != c.flagged {
			t.Errorf("%s: flagged=%v (%v), want %v", c.name, got, jobs, c.flagged)
		}
	}
}

func TestWorkflowChecksPinUnparseableYAMLBehavior(t *testing.T) {
	repo := &github.Repository{FullName: github.Ptr("me/app"), DefaultBranch: github.Ptr("main")}
	client := mockClient(workflowRoutes(t, map[string]string{"broken.yml": "on: ["}, nil))
	wc := &workflowFileCache{}
	ctx := context.Background()

	// the three supply-chain checks fail closed: an unparseable file is a named gap
	for name, row := range map[string]auditRow{
		"unpinned":  auditGitHubWorkflowUnpinnedActions(ctx, client, "me", "app", repo, wc),
		"pwn":       auditGitHubWorkflowPwnRequest(ctx, client, "me", "app", repo, wc),
		"injection": auditGitHubWorkflowInjection(ctx, client, "me", "app", repo, wc),
	} {
		if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "(unparseable)") {
			t.Errorf("%s on broken YAML: status=%s detail=%q, want gap naming the unparseable file", name, row.Status, row.Detail)
		}
	}

	// These checks must also fail closed: otherwise a broken file could hide the
	// only dependency-review or cloud-auth job from the control being evaluated.
	if row := auditGitHubDependencyReview(ctx, client, "me", "app", repo, wc); row.Status != string(StatusError) {
		t.Errorf("dependency-review on broken YAML: status=%s, want error", row.Status)
	}
	if row := auditGitHubOIDCCloudTrust(ctx, client, "me", "app", repo, wc); row.Status != string(StatusError) {
		t.Errorf("oidc-cloud-trust on broken YAML: status=%s, want error", row.Status)
	}
}
