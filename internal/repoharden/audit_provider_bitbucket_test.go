package repoharden

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func bitbucketTestClient(srv *httptest.Server) *restClient {
	return &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "Bearer ", client: srv.Client()}
}

func TestCollectBitbucketAuditSmoke(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/2.0/repositories/me" {
			_, _ = w.Write([]byte(`{"values":[{
				"full_name":"me/app",
				"is_private":true,
				"mainbranch":{"name":"main"}
			}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	rows, repositories, err := collectBitbucketAudit(context.Background(), &opts{
		provider: "bitbucket", host: srv.URL, token: "t", owner: "me", staleDays: 180, concurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(repositories) != 1 || repositories[0] != "me/app" || len(rows) == 0 {
		t.Fatalf("repositories=%v rows=%d, want one repo with audit rows", repositories, len(rows))
	}
	var sawVisibility bool
	for _, row := range rows {
		if row.Control == "public-exposure" && row.Repo == "me/app" {
			sawVisibility = true
			if row.Status != string(StatusCompliant) {
				t.Fatalf("private repo public-exposure = %s, want compliant", row.Status)
			}
		}
	}
	if !sawVisibility {
		t.Fatal("expected a public-exposure row for me/app")
	}
}

func TestListBitbucketReposEnumeratesWorkspacesWithoutOwner(t *testing.T) {
	var roles []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/2.0/workspaces":
			_, _ = w.Write([]byte(`{"values":[{"slug":"w1"},{"slug":"w2"}]}`))
		case "/2.0/repositories/w1":
			roles = append(roles, r.URL.Query().Get("role"))
			_, _ = w.Write([]byte(`{"values":[{"full_name":"w1/app","is_private":true}]}`))
		case "/2.0/repositories/w2":
			_, _ = w.Write([]byte(`{"values":[{"full_name":"w2/fork","is_private":true,"parent":{}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := bitbucketTestClient(srv)

	repos, _, err := listBitbucketRepos(context.Background(), client, &opts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 || repos[0].FullName != "w1/app" {
		t.Fatalf("repos = %+v, want only the non-fork w1/app", repos)
	}
	if len(roles) == 0 || roles[0] != "" {
		t.Fatalf("default listing must not filter by role, sent %v", roles)
	}

	repos, _, err = listBitbucketRepos(context.Background(), client, &opts{includeForks: true, adminOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 2 {
		t.Fatalf("with forks included got %d repos, want 2", len(repos))
	}
	if roles[len(roles)-1] != "admin" {
		t.Fatalf("--admin-only must request role=admin, sent %v", roles)
	}
}

func TestBitbucketBranchProtectionClassifies(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		want       ControlStatus
		wantDetail string
	}{
		{
			name: "complete protection",
			body: `{"values":[
				{"kind":"push","branch_match_kind":"glob","pattern":"main","users":[],"groups":[]},
				{"kind":"force","branch_match_kind":"glob","pattern":"main","users":[],"groups":[]},
				{"kind":"require_approvals_to_merge","branch_match_kind":"glob","pattern":"main","value":1},
				{"kind":"enforce_merge_checks","branch_match_kind":"glob","pattern":"main"}
			]}`,
			want: StatusCompliant,
		},
		{
			name: "force push not prevented",
			body: `{"values":[
				{"kind":"push","branch_match_kind":"glob","pattern":"main","users":[],"groups":[]},
				{"kind":"require_approvals_to_merge","branch_match_kind":"glob","pattern":"main","value":1},
				{"kind":"enforce_merge_checks","branch_match_kind":"glob","pattern":"main"}
			]}`,
			want:       StatusGap,
			wantDetail: "force push",
		},
		{
			name: "push exemptions are summed across matching restrictions",
			body: `{"values":[
				{"kind":"push","branch_match_kind":"glob","pattern":"main","users":[{"display_name":"a"},{"display_name":"b"}],"groups":[]},
				{"kind":"push","branch_match_kind":"glob","pattern":"*","users":[],"groups":[{"slug":"leads"}]},
				{"kind":"force","branch_match_kind":"glob","pattern":"main"},
				{"kind":"require_approvals_to_merge","branch_match_kind":"glob","pattern":"main","value":1},
				{"kind":"enforce_merge_checks","branch_match_kind":"glob","pattern":"main"}
			]}`,
			want:       StatusGap,
			wantDetail: "3 users/groups",
		},
		{
			name: "push exemptions remain",
			body: `{"values":[
				{"kind":"push","branch_match_kind":"glob","pattern":"main","users":[{"display_name":"x"}],"groups":[]},
				{"kind":"force","branch_match_kind":"glob","pattern":"main"},
				{"kind":"require_approvals_to_merge","branch_match_kind":"glob","pattern":"main","value":1},
				{"kind":"enforce_merge_checks","branch_match_kind":"glob","pattern":"main"}
			]}`,
			want:       StatusGap,
			wantDetail: "direct push",
		},
		{
			name: "approvals not enforced without enforce_merge_checks",
			body: `{"values":[
				{"kind":"push","branch_match_kind":"glob","pattern":"main","users":[],"groups":[]},
				{"kind":"force","branch_match_kind":"glob","pattern":"main"},
				{"kind":"require_approvals_to_merge","branch_match_kind":"glob","pattern":"main","value":1}
			]}`,
			want:       StatusGap,
			wantDetail: "enforce_merge_checks",
		},
		{
			name:       "no restrictions",
			body:       `{"values":[]}`,
			want:       StatusGap,
			wantDetail: "no branch restrictions",
		},
		{
			name: "branching model restrictions cannot be evaluated",
			body: `{"values":[
				{"kind":"push","branch_match_kind":"branching_model","branch_type":"production"}
			]}`,
			want:       StatusSkipped,
			wantDetail: "branching model",
		},
		{
			name:   "non-admin token",
			status: http.StatusForbidden,
			want:   StatusSkipped,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.status != 0 {
					http.Error(w, "denied", tc.status)
					return
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			repo := bitbucketRepo{FullName: "me/app", Mainbranch: &struct {
				Name string `json:"name"`
			}{Name: "main"}}
			row := auditBitbucketBranchProtection(context.Background(), bitbucketTestClient(srv), repo)
			if row.Status != string(tc.want) {
				t.Fatalf("status = %s detail=%q, want %s", row.Status, row.Detail, tc.want)
			}
			if tc.wantDetail != "" && !strings.Contains(row.Detail, tc.wantDetail) {
				t.Fatalf("detail %q does not mention %q", row.Detail, tc.wantDetail)
			}
		})
	}
}

func TestAnalyzeBitbucketPipeline(t *testing.T) {
	pinned := "image: ubuntu@sha256:" + strings.Repeat("a", 64) + "\npipelines:\n  default:\n    - step:\n        script: [make]\n"
	analysis, err := analyzeBitbucketPipeline(pinned)
	if err != nil || len(analysis.gaps) != 0 || len(analysis.unverifiable) != 0 {
		t.Fatalf("digest-pinned image should be clean, got %+v err=%v", analysis, err)
	}

	tagged := `
image: node:18
pipelines:
  default:
    - step:
        image:
          name: python:3.12
        script:
          - make test
    - step:
        script:
          - pipe: atlassian/aws-s3-deploy:0.4.5
          - pipe: acct/no-tag
          - pipe: docker://acct/custom:latest
          - pipe: $DYNAMIC_PIPE
`
	analysis, err = analyzeBitbucketPipeline(tagged)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(analysis.gaps, "; ")
	for _, want := range []string{"node:18", "python:3.12", "acct/no-tag", "docker://acct/custom:latest"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("gaps %q missing %q", joined, want)
		}
	}
	if strings.Contains(joined, "aws-s3-deploy") {
		t.Fatalf("version-tagged pipe must not be a gap (SHA pinning is unavailable for pipes): %q", joined)
	}
	if len(analysis.mutablePipes) != 1 || !strings.Contains(analysis.mutablePipes[0], "aws-s3-deploy") {
		t.Fatalf("mutablePipes = %v, want the version-tagged pipe", analysis.mutablePipes)
	}
	if len(analysis.unverifiable) != 1 || !strings.Contains(analysis.unverifiable[0], "$DYNAMIC_PIPE") {
		t.Fatalf("unverifiable = %v, want the dynamic pipe", analysis.unverifiable)
	}

	if _, err := analyzeBitbucketPipeline(": not yaml ["); err == nil {
		t.Fatal("unparseable YAML must error")
	}
}

func TestAnalyzeBitbucketPipelineTreatsRegistryPortAsUnpinned(t *testing.T) {
	analysis, err := analyzeBitbucketPipeline(`
pipelines:
  default:
    - step:
        script:
          - pipe: docker://registry.example.com:5000/team/deploy
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.gaps) != 1 || !strings.Contains(analysis.gaps[0], "not pinned to a version") {
		t.Fatalf("gaps = %v, want the untagged pipe flagged (registry port is not a tag)", analysis.gaps)
	}
	if len(analysis.mutablePipes) != 0 {
		t.Fatalf("mutablePipes = %v, want none", analysis.mutablePipes)
	}
}

func TestBitbucketPipelineSupplyChainRow(t *testing.T) {
	repo := bitbucketRepo{FullName: "me/app", Mainbranch: &struct {
		Name string `json:"name"`
	}{Name: "main"}}
	fromYAML := func(y string) func() (string, error) {
		return func() (string, error) { return y, nil }
	}
	step := "\npipelines:\n  default:\n    - step:\n        script: [make]\n"

	row := auditBitbucketPipelineSupplyChain(repo, fromYAML("image: node:18"+step))
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "node:18") {
		t.Fatalf("tagged image = %+v, want gap naming the image", row)
	}
	row = auditBitbucketPipelineSupplyChain(repo, fromYAML("image: $BUILD_IMAGE"+step))
	if row.Status != string(StatusSkipped) || !strings.Contains(row.Detail, "$BUILD_IMAGE") {
		t.Fatalf("dynamic image = %+v, want skipped as unverifiable", row)
	}
	row = auditBitbucketPipelineSupplyChain(repo, fromYAML("pipelines:\n  default:\n    - step:\n        script:\n          - pipe: atlassian/aws-s3-deploy:0.4.5\n"))
	if row.Status != string(StatusCompliant) || !strings.Contains(row.Detail, "version tags") {
		t.Fatalf("tagged pipe = %+v, want compliant noting mutable pipe tags", row)
	}
	row = auditBitbucketPipelineSupplyChain(repo, fromYAML("image: ubuntu@sha256:"+strings.Repeat("a", 64)+step))
	if row.Status != string(StatusCompliant) {
		t.Fatalf("digest image = %+v, want compliant", row)
	}
	row = auditBitbucketPipelineSupplyChain(repo, fromYAML(": ["))
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "unparseable") {
		t.Fatalf("bad YAML = %+v, want unparseable gap", row)
	}
	row = auditBitbucketPipelineSupplyChain(repo, func() (string, error) {
		return "", &restError{statusCode: http.StatusForbidden}
	})
	if row.Status != string(StatusSkipped) {
		t.Fatalf("403 fetch = %+v, want skipped", row)
	}
	row = auditBitbucketPipelineSupplyChain(bitbucketRepo{FullName: "me/app"}, fromYAML(""))
	if row.Status != string(StatusSkipped) || !strings.Contains(row.Detail, "no default branch") {
		t.Fatalf("branchless repo = %+v, want skipped", row)
	}
}

func TestBitbucketRequiredWorkflows(t *testing.T) {
	for _, tc := range []struct {
		name          string
		yamlStatus    int
		yaml          string
		configStatus  int
		configEnabled bool
		want          ControlStatus
		wantDetail    string
	}{
		{name: "valid and enabled", yaml: "pipelines:\n  default:\n    - step:\n        script: [make]\n", configEnabled: true, want: StatusCompliant},
		{name: "pipelines disabled", yaml: "pipelines:\n  default:\n    - step:\n        script: [make]\n", configEnabled: false, want: StatusGap, wantDetail: "disabled"},
		{name: "missing file", yamlStatus: http.StatusNotFound, want: StatusGap, wantDetail: "no bitbucket-pipelines.yml"},
		{name: "invalid yaml", yaml: ": [", configEnabled: true, want: StatusGap, wantDetail: "invalid"},
		{name: "enablement unverifiable", yaml: "pipelines:\n  default:\n    - step:\n        script: [make]\n", configStatus: http.StatusForbidden, want: StatusSkipped, wantDetail: "not verifiable"},
		{name: "pipelines config absent", yaml: "pipelines:\n  default:\n    - step:\n        script: [make]\n", configStatus: http.StatusNotFound, want: StatusSkipped, wantDetail: "not verifiable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/bitbucket-pipelines.yml"):
					if tc.yamlStatus != 0 {
						http.Error(w, "missing", tc.yamlStatus)
						return
					}
					_, _ = w.Write([]byte(tc.yaml))
				case strings.HasSuffix(r.URL.Path, "/pipelines_config"):
					if tc.configStatus != 0 {
						http.Error(w, "denied", tc.configStatus)
						return
					}
					fmt.Fprintf(w, `{"enabled":%t}`, tc.configEnabled)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			client := bitbucketTestClient(srv)
			repo := bitbucketRepo{FullName: "me/app", Mainbranch: &struct {
				Name string `json:"name"`
			}{Name: "main"}}
			row := auditBitbucketRequiredWorkflows(context.Background(), client, repo, bitbucketPipelinesYMLFetcher(context.Background(), client, repo, func() (string, error) { return "main", nil }))
			if row.Status != string(tc.want) {
				t.Fatalf("status = %s detail=%q, want %s", row.Status, row.Detail, tc.want)
			}
			if tc.wantDetail != "" && !strings.Contains(row.Detail, tc.wantDetail) {
				t.Fatalf("detail %q does not mention %q", row.Detail, tc.wantDetail)
			}
		})
	}
}

func TestBitbucketSrcRefResolvesSlashedDefaultBranch(t *testing.T) {
	var refsCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/2.0/repositories/me/app/refs/branches/release/1.0" {
			refsCalled = true
			_, _ = w.Write([]byte(`{"target":{"hash":"a3f6f5c0d9e8b7a6a5b4c3d2e1f0a9b8c7d6e5f4"}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	client := bitbucketTestClient(srv)

	plain := bitbucketRepo{FullName: "me/app", Mainbranch: &struct {
		Name string `json:"name"`
	}{Name: "main"}}
	ref, err := bitbucketSrcRef(context.Background(), client, plain)
	if err != nil || ref != "main" {
		t.Fatalf("plain branch ref = %q err=%v, want main without resolution", ref, err)
	}
	if refsCalled {
		t.Fatal("plain branch names must not hit the refs endpoint")
	}

	slashed := bitbucketRepo{FullName: "me/app", Mainbranch: &struct {
		Name string `json:"name"`
	}{Name: "release/1.0"}}
	ref, err = bitbucketSrcRef(context.Background(), client, slashed)
	if err != nil || ref != "a3f6f5c0d9e8b7a6a5b4c3d2e1f0a9b8c7d6e5f4" {
		t.Fatalf("slashed branch ref = %q err=%v, want resolved commit hash", ref, err)
	}
}

func TestBitbucketVariablesClassifies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"values":[{"key":"SAFE","secured":true},{"key":"LOOSE","secured":false}]}`))
	}))
	defer srv.Close()
	repo := bitbucketRepo{FullName: "me/app"}
	row := auditBitbucketVariables(context.Background(), bitbucketTestClient(srv), repo, true)
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "LOOSE") || strings.Contains(row.Detail, "SAFE") {
		t.Fatalf("row = %+v, want gap naming only the unsecured variable", row)
	}

	secured := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"values":[{"key":"SAFE","secured":true}]}`))
	}))
	defer secured.Close()
	row = auditBitbucketVariables(context.Background(), bitbucketTestClient(secured), repo, false)
	if row.Status != string(StatusCompliant) {
		t.Fatalf("all-secured variables = %s detail=%q, want compliant", row.Status, row.Detail)
	}
}

func TestBitbucketWebhooksClassifies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"values":[
			{"uuid":"{1}","url":"http://ci.example.com/hook","active":true},
			{"uuid":"{2}","url":"https://ok.example.com/hook","active":true,"skip_cert_verification":true},
			{"uuid":"{3}","url":"https://good.example.com/hook","active":true}
		]}`))
	}))
	defer srv.Close()
	repo := bitbucketRepo{FullName: "me/app"}
	row := auditBitbucketWebhooks(context.Background(), bitbucketTestClient(srv), repo)
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "{1}") || !strings.Contains(row.Detail, "{2}") || strings.Contains(row.Detail, "{3}") {
		t.Fatalf("row = %+v, want gap naming exactly the weak hooks", row)
	}
}

func TestBitbucketDeployKeysAreReadOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"values":[{"label":"a"},{"label":"b"}]}`))
	}))
	defer srv.Close()
	repo := bitbucketRepo{FullName: "me/app"}
	row := auditBitbucketDeployKeys(context.Background(), bitbucketTestClient(srv), repo)
	if row.Status != string(StatusCompliant) || !strings.Contains(row.Detail, "read-only") {
		t.Fatalf("row = %+v, want compliant read-only inventory", row)
	}

	denied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer denied.Close()
	row = auditBitbucketDeployKeys(context.Background(), bitbucketTestClient(denied), repo)
	if row.Status != string(StatusSkipped) {
		t.Fatalf("403 = %s, want skipped", row.Status)
	}
}

func TestBitbucketCollaboratorsClassifies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"values":[
			{"permission":"admin","user":{"display_name":"Root"}},
			{"permission":"read","user":{"display_name":"Reader"}}
		]}`))
	}))
	defer srv.Close()
	repo := bitbucketRepo{FullName: "me/app"}
	row := auditBitbucketCollaborators(context.Background(), bitbucketTestClient(srv), repo, true)
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "Root") {
		t.Fatalf("row = %+v, want gap naming the direct admin", row)
	}
}

func TestBitbucketEnvironmentsClassifies(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want ControlStatus
	}{
		{
			name: "unrestricted production",
			body: `{"values":[{"name":"Prod","environment_type":{"name":"Production"},"restrictions":{"admin_only":false}}]}`,
			want: StatusGap,
		},
		{
			name: "admin-only production",
			body: `{"values":[{"name":"Prod","environment_type":{"name":"Production"},"restrictions":{"admin_only":true}}]}`,
			want: StatusCompliant,
		},
		{name: "no environments", body: `{"values":[]}`, want: StatusSkipped},
		{
			name: "restrictions not exposed",
			body: `{"values":[{"name":"Prod","environment_type":{"name":"Production"}}]}`,
			want: StatusSkipped,
		},
		{
			name: "only test environments",
			body: `{"values":[{"name":"Test","environment_type":{"name":"Test"},"restrictions":{"admin_only":false}}]}`,
			want: StatusSkipped,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			row := auditBitbucketEnvironments(context.Background(), bitbucketTestClient(srv), bitbucketRepo{FullName: "me/app"})
			if row.Status != string(tc.want) {
				t.Fatalf("status = %s detail=%q, want %s", row.Status, row.Detail, tc.want)
			}
		})
	}
}

func TestBitbucketTokenScopesRow(t *testing.T) {
	row := bitbucketTokenScopesRow("repository, pullrequest, webhook, pipeline")
	if row.Status != string(StatusCompliant) {
		t.Fatalf("read scopes = %s detail=%q, want compliant", row.Status, row.Detail)
	}
	row = bitbucketTokenScopesRow("repository:write, pipeline")
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "repository:write") {
		t.Fatalf("write scope = %+v, want gap naming repository:write", row)
	}
	row = bitbucketTokenScopesRow("pipeline:variable")
	if row.Status != string(StatusGap) {
		t.Fatalf("pipeline:variable = %s, want gap (exposes secured variable management)", row.Status)
	}
	row = bitbucketTokenScopesRow("read:repository:bitbucket write:repository:bitbucket")
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "write:repository:bitbucket") {
		t.Fatalf("granular write scope = %+v, want gap", row)
	}
	row = bitbucketTokenScopesRow("")
	if row.Status != string(StatusSkipped) {
		t.Fatalf("absent header = %s, want skipped", row.Status)
	}
}

func TestBitbucketRepositoryLicense(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/2.0/repositories/me/app/src/main/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"values":[
			{"path":"LICENSE","type":"commit_file"},
			{"path":"docs","type":"commit_directory"}
		]}`))
	}))
	defer srv.Close()
	repo := bitbucketRepo{FullName: "me/app", Mainbranch: &struct {
		Name string `json:"name"`
	}{Name: "main"}}
	row := auditBitbucketRepositoryLicense(context.Background(), bitbucketTestClient(srv), repo, func() (string, error) { return "main", nil })
	if row.Status != string(StatusCompliant) || !strings.Contains(row.Detail, "LICENSE") {
		t.Fatalf("row = %+v, want compliant with the LICENSE file (root listing needs a trailing slash)", row)
	}

	bare := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"values":[{"path":"README.md","type":"commit_file"}]}`))
	}))
	defer bare.Close()
	row = auditBitbucketRepositoryLicense(context.Background(), bitbucketTestClient(bare), repo, func() (string, error) { return "main", nil })
	if row.Status != string(StatusGap) {
		t.Fatalf("no license file = %s, want gap", row.Status)
	}
}
