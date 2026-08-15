package repoharden

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGitlabPagedFollowsNextPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "1":
			w.Header().Set("X-Next-Page", "2")
			_, _ = w.Write([]byte(`[{"id":1},{"id":2}]`))
		case "2":
			_, _ = w.Write([]byte(`[{"id":3}]`))
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "token ", client: srv.Client()}
	got, err := gitlabPaged[map[string]any](context.Background(), client, "/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d items across pages, want 3 (would have been 2 without pagination)", len(got))
	}
}

func TestGitlabPagedRejectsNonAdvancingPagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Next-Page", r.URL.Query().Get("page"))
		_, _ = w.Write([]byte(`[{"id":1}]`))
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "token ", client: srv.Client()}
	if _, err := gitlabPaged[map[string]any](context.Background(), client, "/x", nil); err == nil ||
		!strings.Contains(err.Error(), "X-Next-Page") {
		t.Fatalf("non-advancing pagination should fail closed, got %v", err)
	}
}

func TestGiteaPagedContinuesPastShortPageUntilEmpty(t *testing.T) {
	full := "[" + strings.Repeat(`{"x":1},`, 49) + `{"x":1}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "1":
			_, _ = w.Write([]byte(full))
		case "2":
			_, _ = w.Write([]byte(`[{"x":1}]`))
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "token ", client: srv.Client()}
	got, err := giteaPaged[map[string]any](context.Background(), client, "/x")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 51 {
		t.Fatalf("got %d items, want 51 (50 + 1 across two pages)", len(got))
	}
}

func TestGiteaPagedHandlesMetadataFreeServerPageCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "1":
			_, _ = w.Write([]byte(`[{"x":1},{"x":2}]`))
		case "2":
			_, _ = w.Write([]byte(`[{"x":3}]`))
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "token ", client: srv.Client()}
	got, err := giteaPaged[map[string]any](context.Background(), client, "/x")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d items, want all 3 across capped metadata-free pages", len(got))
	}
}

func TestGiteaPagedHonorsTotalCountWhenServerCapsPageSize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Total-Count", "3")
		switch r.URL.Query().Get("page") {
		case "1":
			_, _ = w.Write([]byte(`[{"x":1},{"x":2}]`))
		case "2":
			_, _ = w.Write([]byte(`[{"x":3}]`))
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "token ", client: srv.Client()}
	got, err := giteaPaged[map[string]any](context.Background(), client, "/x")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d items, want all 3 despite a page cap below requested limit", len(got))
	}
}

func TestGiteaPagedRejectsNonAdvancingLink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://gitea.example/api/v1/x?page=1>; rel="next"`)
		_, _ = w.Write([]byte(`[{"x":1}]`))
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "token ", client: srv.Client()}
	if _, err := giteaPaged[map[string]any](context.Background(), client, "/x"); err == nil || !strings.Contains(err.Error(), "non-advancing") {
		t.Fatalf("non-advancing Link must fail closed, got %v", err)
	}
}

func TestGiteaPagedValidatesLinkEvenWithTotalCount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Total-Count", "2")
		w.Header().Set("Link", `<https://gitea.example/api/v1/x?page=1>; rel="next"`)
		_, _ = w.Write([]byte(`[{"x":1}]`))
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "token ", client: srv.Client()}
	if _, err := giteaPaged[map[string]any](context.Background(), client, "/x"); err == nil || !strings.Contains(err.Error(), "non-advancing") {
		t.Fatalf("non-advancing Link must be validated even with X-Total-Count, got %v", err)
	}
}

func TestBitbucketPagedFollowsNextURL(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "":
			fmt.Fprintf(w, `{"values":[{"x":1},{"x":2}],"next":%q}`, srvURL+"/x?page=2&pagelen=50")
		case "2":
			_, _ = w.Write([]byte(`{"values":[{"x":3}]}`))
		default:
			_, _ = w.Write([]byte(`{"values":[]}`))
		}
	}))
	defer srv.Close()
	srvURL = srv.URL
	client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "Bearer ", client: srv.Client()}
	got, _, err := bitbucketPaged[map[string]any](context.Background(), client, "/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d items across pages, want 3 (would have been 2 without following next)", len(got))
	}
}

func TestBitbucketPagedHandlesPathPrefixedHost(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bitbucket/x":
			if r.URL.Query().Get("page") == "2" {
				_, _ = w.Write([]byte(`{"values":[{"x":2}]}`))
				return
			}
			fmt.Fprintf(w, `{"values":[{"x":1}],"next":%q}`, srvURL+"/bitbucket/x?page=2")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL
	client := &restClient{baseURL: srv.URL + "/bitbucket", token: "t", header: "Authorization", prefix: "Bearer ", client: srv.Client()}
	got, _, err := bitbucketPaged[map[string]any](context.Background(), client, "/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d items, want 2 (next-page path must not double-prefix the base path)", len(got))
	}
}

func TestBitbucketPagedRefusesCrossHostNext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"values":[{"x":1}],"next":"https://evil.example/x?page=2"}`))
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "Bearer ", client: srv.Client()}
	if _, _, err := bitbucketPaged[map[string]any](context.Background(), client, "/x", nil); err == nil ||
		!strings.Contains(err.Error(), "host") {
		t.Fatalf("cross-host next URL must fail closed, got %v", err)
	}
}

func TestBitbucketPagedRejectsNonAdvancingNext(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"values":[{"x":1}],"next":%q}`, srvURL+"/x?page=2")
	}))
	defer srv.Close()
	srvURL = srv.URL
	client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "Bearer ", client: srv.Client()}
	if _, _, err := bitbucketPaged[map[string]any](context.Background(), client, "/x", nil); err == nil ||
		!strings.Contains(err.Error(), "non-advancing") {
		t.Fatalf("repeating next URL must fail closed, got %v", err)
	}
}

func TestRestClientAuthPrefixes(t *testing.T) {
	gitea, err := newRestClient("gitea", &opts{host: "https://gitea.local", token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if gitea.header != "Authorization" || gitea.prefix != "token " {
		t.Fatalf("gitea auth = %q %q, want Authorization/token", gitea.header, gitea.prefix)
	}

	gitlab, err := newRestClient("gitlab", &opts{host: "https://gitlab.local", token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if gitlab.header != "PRIVATE-TOKEN" || gitlab.prefix != "" {
		t.Fatalf("gitlab auth = %q %q, want PRIVATE-TOKEN/empty", gitlab.header, gitlab.prefix)
	}
	bitbucket, err := newRestClient("bitbucket", &opts{host: "https://api.bitbucket.org", token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if bitbucket.header != "Authorization" || bitbucket.prefix != "Bearer " {
		t.Fatalf("bitbucket auth = %q %q, want Authorization/Bearer", bitbucket.header, bitbucket.prefix)
	}
	basic, err := newRestClient("bitbucket", &opts{host: "https://api.bitbucket.org", token: "audit@example.com:tok"})
	if err != nil {
		t.Fatal(err)
	}
	wantBasic := base64.StdEncoding.EncodeToString([]byte("audit@example.com:tok"))
	if basic.prefix != "Basic " || basic.token != wantBasic {
		t.Fatalf("bitbucket email:token auth = %q %q, want Basic with base64 credentials", basic.prefix, basic.token)
	}
	if gitea.client.Timeout != 30*time.Second {
		t.Fatalf("rest client timeout = %s, want 30s", gitea.client.Timeout)
	}
}

func TestRequireSecureURL(t *testing.T) {
	if err := requireSecureURL("https://gitea.example.com"); err != nil {
		t.Fatalf("https should pass: %v", err)
	}
	if err := requireSecureURL("http://localhost:3000"); err != nil {
		t.Fatalf("http loopback should pass: %v", err)
	}
	if err := requireSecureURL("http://gitea.example.com"); err == nil {
		t.Fatal("http to non-loopback host must be refused")
	}
	for _, raw := range []string{"file:///tmp/token", "ftp://gitea.example.com", "https://user@gitea.example.com"} {
		if err := requireSecureURL(raw); err == nil {
			t.Fatalf("unsafe URL %q must be refused", raw)
		}
	}
}

func TestEscapedFilePathKeepsPathSegments(t *testing.T) {
	got := escapedFilePath(".gitea/workflows/ci yml")
	want := ".gitea/workflows/ci%20yml"
	if got != want {
		t.Fatalf("escapedFilePath = %q, want %q", got, want)
	}
}

func TestHTTPUnavailableUsesRESTStatusCode(t *testing.T) {
	// Permission and tier gates must be skipped instead of reported as audit failures.
	for _, code := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusGone} {
		if !httpUnavailable(&restError{statusCode: code}) {
			t.Fatalf("status %d should be treated as unavailable (→ skip)", code)
		}
	}
	for _, code := range []int{http.StatusUnauthorized, http.StatusBadRequest, http.StatusInternalServerError} {
		if httpUnavailable(&restError{statusCode: code}) {
			t.Fatalf("status %d should remain a real error, not unavailable", code)
		}
	}
}

func TestGiteaBranchProtectionSkippedWithoutDefaultBranch(t *testing.T) {
	row := auditGiteaBranchProtection(context.Background(), nil, "gitea", giteaRepo{FullName: "me/app"})
	if row.Status != string(StatusSkipped) {
		t.Fatalf("status = %s, want skipped", row.Status)
	}
}

func TestAuditGitLabBranchProtectionClassifies(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   ControlStatus
	}{
		{"protected", http.StatusOK, StatusCompliant},
		{"unprotected", http.StatusNotFound, StatusGap},
		{"forbidden", http.StatusForbidden, StatusSkipped},
		{"unsupported", http.StatusMethodNotAllowed, StatusSkipped},
		{"server-error", http.StatusInternalServerError, StatusError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.status == http.StatusOK {
					if strings.HasSuffix(r.URL.Path, "/approval_rules") {
						_, _ = w.Write([]byte(`[{"approvals_required":1}]`))
						return
					}
					_, _ = w.Write([]byte(`{"name":"main","allow_force_push":false,"push_access_levels":[{"access_level":0}]}`))
					return
				}
				http.Error(w, "x", tc.status)
			}))
			defer srv.Close()
			client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "token ", client: srv.Client()}
			row := auditGitLabBranchProtection(context.Background(), client, gitlabProject{PathWithNamespace: "me/app", DefaultBranch: "main"})
			if row.Status != string(tc.want) {
				t.Fatalf("status = %s, want %s", row.Status, tc.want)
			}
		})
	}
}

func TestGitLabRequiredWorkflowDistinguishesMissingFromForbidden(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   ControlStatus
	}{
		{http.StatusNotFound, StatusGap},
		{http.StatusForbidden, StatusSkipped},
		{http.StatusMethodNotAllowed, StatusSkipped},
		{http.StatusInternalServerError, StatusError},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
		}))
		client := &restClient{baseURL: srv.URL, token: "t", header: "PRIVATE-TOKEN", client: srv.Client()}
		row := auditGitLabRequiredWorkflows(context.Background(), client, gitlabProject{ID: 1, PathWithNamespace: "me/app", DefaultBranch: "main"})
		srv.Close()
		if row.Status != string(tc.want) {
			t.Errorf("status %d: got %s detail=%q, want %s", tc.status, row.Status, row.Detail, tc.want)
		}
	}
}

func TestCollectGitLabAuditSmoke(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/projects" {
			_, _ = w.Write([]byte(`[{"id":1,"path_with_namespace":"me/app","default_branch":"main","visibility":"private"}]`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	rows, repositories, err := collectGitLabAudit(context.Background(), &opts{provider: "gitlab", host: srv.URL, token: "t", staleDays: 180})
	if err != nil {
		t.Fatal(err)
	}
	if len(repositories) != 1 || repositories[0] != "me/app" {
		t.Fatalf("project universe = %v, want [me/app]", repositories)
	}
	if len(rows) == 0 {
		t.Fatal("expected audit rows for the project")
	}
}

func TestGiteaWorkflowsPreservesNonUnavailableError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/contents/.gitea/workflows") {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &restClient{
		baseURL: srv.URL,
		token:   "tok",
		header:  "Authorization",
		prefix:  "token ",
		client:  srv.Client(),
	}
	row := giteaWorkflowsRowForTest(client, giteaRepo{FullName: "me/app", DefaultBranch: "main"})
	if row.Status != string(StatusError) {
		t.Fatalf("status = %s detail=%q, want error", row.Status, row.Detail)
	}
}

func TestCollectGiteaAuditSmoke(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/user/repos" {
			if r.URL.Query().Get("page") != "1" {
				_, _ = w.Write([]byte(`[]`))
				return
			}
			_, _ = w.Write([]byte(`[{
				"full_name":"me/app",
				"default_branch":"main",
				"private":true,
				"owner":{"login":"me"},
				"permissions":{"admin":true}
			}]`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	rows, repositories, err := collectGiteaAudit(context.Background(), &opts{
		provider: "gitea", host: srv.URL, token: "t", staleDays: 180, concurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(repositories) != 1 || repositories[0] != "me/app" || len(rows) == 0 {
		t.Fatalf("repositories=%v rows=%d, want one repo with audit rows", repositories, len(rows))
	}
}

func TestGiteaBranchProtectionRequiresDepth(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want ControlStatus
	}{
		{
			name: "weak",
			body: `[{"rule_name":"main","enable_push":true,"required_approvals":0}]`,
			want: StatusGap,
		},
		{
			name: "strong",
			body: `[{"rule_name":"main","enable_push":false,"enable_force_push":false,"required_approvals":1}]`,
			want: StatusCompliant,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("page") == "1" {
					_, _ = w.Write([]byte(tc.body))
					return
				}
				_, _ = w.Write([]byte(`[]`))
			}))
			defer srv.Close()
			client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "token ", client: srv.Client()}
			row := auditGiteaBranchProtection(context.Background(), client, "gitea", giteaRepo{
				FullName: "me/app", DefaultBranch: "main",
			})
			if row.Status != string(tc.want) {
				t.Fatalf("status=%s detail=%q, want %s", row.Status, row.Detail, tc.want)
			}
		})
	}
}

func TestAuditGitLabVariablesSkipsOn403(t *testing.T) {
	// A GitLab permission or tier gate must not lower the audit score.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "PRIVATE-TOKEN", prefix: "", client: srv.Client()}
	row := auditGitLabVariables(context.Background(), client, gitlabProject{PathWithNamespace: "me/app"}, false)
	if row.Status != string(StatusSkipped) {
		t.Fatalf("status=%s detail=%q, want skipped on 403", row.Status, row.Detail)
	}
}

func TestAuditGiteaSecretsPaginates(t *testing.T) {
	full := "[" + strings.Repeat(`{"name":"S"},`, 49) + `{"name":"S"}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			_, _ = w.Write([]byte(full))
			return
		}
		if r.URL.Query().Get("page") == "2" {
			_, _ = w.Write([]byte(`[{"name":"S"}]`))
			return
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "token ", client: srv.Client()}
	row := auditGiteaSecrets(context.Background(), client, "gitea", giteaRepo{FullName: "me/app"})
	if !strings.Contains(row.Detail, "51 action secrets") {
		t.Fatalf("detail=%q, want 51 secrets counted across two pages (would be 50 without pagination)", row.Detail)
	}
}

func TestAuditGitLabBranchProtectionRequiresApplicableApprovalRule(t *testing.T) {
	tests := []struct {
		name  string
		rules string
		want  ControlStatus
	}{
		{"project-wide rule", `[{"approvals_required":1}]`, StatusCompliant},
		{"all protected branches", `[{"approvals_required":1,"applies_to_all_protected_branches":true}]`, StatusCompliant},
		{"exact default branch", `[{"approvals_required":1,"protected_branches":[{"name":"main"}]}]`, StatusCompliant},
		{"default branch pattern", `[{"approvals_required":1,"protected_branches":[{"name":"main*"}]}]`, StatusCompliant},
		{"different protected branch", `[{"approvals_required":2,"protected_branches":[{"name":"release/*"}]}]`, StatusGap},
		{"zero approvals", `[{"approvals_required":0,"applies_to_all_protected_branches":true}]`, StatusGap},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/approval_rules") {
					_, _ = w.Write([]byte(test.rules))
					return
				}
				_, _ = w.Write([]byte(`{"name":"main","allow_force_push":false,"push_access_levels":[{"access_level":0}]}`))
			}))
			defer srv.Close()
			client := &restClient{baseURL: srv.URL, token: "t", header: "PRIVATE-TOKEN", client: srv.Client()}
			project := gitlabProject{ID: 1, PathWithNamespace: "group/app", DefaultBranch: "main"}
			row := auditGitLabBranchProtection(context.Background(), client, project)
			if row.Status != string(test.want) {
				t.Fatalf("status=%s detail=%q, want %s", row.Status, row.Detail, test.want)
			}
		})
	}
}

func TestReadLimitedResponseRejectsOversize(t *testing.T) {
	got, err := readLimitedResponse(strings.NewReader("12345"), 4)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized response: data=%q err=%v, want an explicit size error", got, err)
	}
	got, err = readLimitedResponse(strings.NewReader("1234"), 4)
	if err != nil || string(got) != "1234" {
		t.Fatalf("response at limit: data=%q err=%v", got, err)
	}
}

func TestRESTClientRejectsOversizedJSONAndText(t *testing.T) {
	oversized := strings.Repeat("x", maxRESTResponseBytes+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/json" {
			_, _ = w.Write([]byte(`{"value":"` + oversized + `"}`))
			return
		}
		_, _ = w.Write([]byte(oversized))
	}))
	defer srv.Close()
	c := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", client: srv.Client()}
	var out map[string]string
	if _, err := c.get(context.Background(), "/json", nil, &out); err == nil || !strings.Contains(err.Error(), "safety limit") {
		t.Fatalf("oversized JSON error = %v", err)
	}
	if _, err := c.getText(context.Background(), "/text", nil); err == nil || !strings.Contains(err.Error(), "safety limit") {
		t.Fatalf("oversized text error = %v", err)
	}
}

func TestRESTStatusClassificationIsDisjoint(t *testing.T) {
	cases := []struct {
		code                             int
		permission, missing, unsupported bool
	}{
		{http.StatusUnauthorized, false, false, false},
		{http.StatusForbidden, true, false, false},
		{http.StatusNotFound, false, true, false},
		{http.StatusMethodNotAllowed, false, false, true},
		{http.StatusGone, false, false, true},
		{http.StatusNotImplemented, false, false, true},
	}
	for _, tc := range cases {
		err := &restError{statusCode: tc.code}
		if got := httpPermissionDenied(err); got != tc.permission {
			t.Errorf("status %d permission=%v, want %v", tc.code, got, tc.permission)
		}
		if got := httpNotFound(err); got != tc.missing {
			t.Errorf("status %d missing=%v, want %v", tc.code, got, tc.missing)
		}
		if got := httpUnsupported(err); got != tc.unsupported {
			t.Errorf("status %d unsupported=%v, want %v", tc.code, got, tc.unsupported)
		}
	}
	wrapped := errors.New("not a REST error")
	if httpUnavailable(wrapped) {
		t.Fatal("non-REST error must not be classified as an unavailable endpoint")
	}
}

func TestGitlabPipelineFindings(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []string
	}{
		{"unpinned image", "image: alpine:3.20\nbuild:\n  script: [make]\n", []string{"image alpine:3.20 not pinned to a full SHA-256 digest"}},
		{"digest-pinned image", "image: alpine@sha256:" + strings.Repeat("a", 64) + "\nbuild:\n  script: [make]\n", nil},
		{"short digest is rejected", "image: alpine@sha256:abc123\nbuild:\n  script: [make]\n", []string{"image alpine@sha256:abc123 not pinned to a full SHA-256 digest"}},
		{"malformed digest reference is rejected", "image: alpine@latest@sha256:" + strings.Repeat("a", 64) + "\n", []string{"image alpine@latest@sha256:" + strings.Repeat("a", 64) + " not pinned to a full SHA-256 digest"}},
		{"variable image is unverifiable", "image: $CI_REGISTRY_IMAGE:latest\nbuild:\n  script: [make]\n", []string{"image $CI_REGISTRY_IMAGE:latest"}},
		{"job image and named service", "build:\n  image:\n    name: golang:1.25\n  services:\n    - name: docker:dind\n  script: [make]\n",
			[]string{"image docker:dind not pinned to a full SHA-256 digest", "image golang:1.25 not pinned to a full SHA-256 digest"}},
		{"remote include", "include:\n  - remote: https://example.com/ci.yml\nbuild:\n  script: [make]\n", []string{"remote include https://example.com/ci.yml"}},
		{"remote include string form", "include: https://example.com/ci.yml\n", []string{"remote include https://example.com/ci.yml"}},
		{"project include without ref", "include:\n  - project: group/templates\n    file: ci.yml\n", []string{"include project group/templates without a pinned ref"}},
		{"project include with mutable tag", "include:\n  - project: group/templates\n    ref: v1.2.3\n    file: ci.yml\n", []string{"include project group/templates ref v1.2.3 is not a full commit SHA"}},
		{"project include with commit", "include:\n  - project: group/templates\n    ref: " + strings.Repeat("b", 40) + "\n    file: ci.yml\n", nil},
		{"local include is fine", "include:\n  - local: ci/base.yml\n", nil},
		{"component include with mutable version", "include:\n  - component: gitlab.example.com/group/comp/build@1.2.3\nbuild:\n  script: [make]\n", []string{"include component gitlab.example.com/group/comp/build@1.2.3 version 1.2.3 is not a full commit SHA"}},
		{"component include with commit", "include:\n  - component: gitlab.example.com/group/comp/build@" + strings.Repeat("c", 40) + "\n", nil},
		{"component include without version", "include:\n  - component: gitlab.example.com/group/comp/build\n", []string{"include component gitlab.example.com/group/comp/build without a pinned version"}},
		{"variables entry named image is data", "variables:\n  image: alpine:3.20\nbuild:\n  script: [make]\n", nil},
		{"default image is checked", "default:\n  image: alpine:3.20\nbuild:\n  script: [make]\n", []string{"image alpine:3.20 not pinned to a full SHA-256 digest"}},
	}
	for _, c := range cases {
		got, err := gitlabPipelineFindings(c.content)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
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

func TestAuditGitLabPipelineSupplyChain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ".gitlab-ci.yml") {
			_, _ = w.Write([]byte("image: alpine:3.20\nbuild:\n  script: [make]\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "Bearer ", client: srv.Client()}
	p := gitlabProject{ID: 1, PathWithNamespace: "group/app", DefaultBranch: "main"}
	row := auditGitLabPipelineSupplyChain(context.Background(), client, p)
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "alpine:3.20") {
		t.Fatalf("unpinned image: status=%s detail=%q, want gap", row.Status, row.Detail)
	}

	missing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer missing.Close()
	client = &restClient{baseURL: missing.URL, token: "t", header: "Authorization", prefix: "Bearer ", client: missing.Client()}
	row = auditGitLabPipelineSupplyChain(context.Background(), client, p)
	if row.Status != string(StatusCompliant) || !strings.Contains(row.Detail, "no .gitlab-ci.yml") {
		t.Fatalf("no pipeline file: status=%s detail=%q, want compliant", row.Status, row.Detail)
	}
}

func TestAuditGitLabPipelineDynamicReferenceIsUnverifiable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("image: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA\n"))
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "PRIVATE-TOKEN", client: srv.Client()}
	row := auditGitLabPipelineSupplyChain(context.Background(), client, gitlabProject{ID: 1, PathWithNamespace: "g/p", DefaultBranch: "main"})
	if row.Status != string(StatusSkipped) || !strings.Contains(row.Detail, "cannot be verified") {
		t.Fatalf("dynamic image: status=%s detail=%q, want skipped/unverifiable", row.Status, row.Detail)
	}
}

func TestGiteaWorkflowSupplyChain(t *testing.T) {
	workflow := "on: push\njobs:\n  build:\n    steps:\n      - uses: someone/tool@v1\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/repos/me/app/contents/.gitea/workflows":
			_, _ = w.Write([]byte(`[{"name":"ci.yml","path":".gitea/workflows/ci.yml","type":"file"}]`))
		case "/api/v1/repos/me/app/contents/.gitea/workflows/ci.yml":
			entry := map[string]string{
				"name": "ci.yml", "path": ".gitea/workflows/ci.yml", "type": "file",
				"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(workflow)),
			}
			_ = json.NewEncoder(w).Encode(entry)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "token ", client: srv.Client()}
	repo := giteaRepo{FullName: "me/app", DefaultBranch: "main"}
	repo.Owner.Login = "me"
	repo.Name = "app"

	files, err := listGiteaWorkflowFiles(context.Background(), client, repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("files = %v, want the .gitea/workflows file", files)
	}

	getWF := func() (map[string]string, error) { return files, nil }
	row := giteaWorkflowSupplyChainRow("gitea", repo.FullName, "workflow-unpinned-actions",
		"Third-party actions pinned to commit SHAs", "medium",
		"third-party actions not SHA-pinned: ", "no unpinned third-party actions", "rem",
		getWF, workflowUnpinnedUses)
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "someone/tool@v1") {
		t.Fatalf("gitea unpinned: status=%s detail=%q, want gap naming the ref", row.Status, row.Detail)
	}
	row = giteaWorkflowSupplyChainRow("gitea", repo.FullName, "workflow-injection",
		"No attacker-controlled expressions in run scripts", "high",
		"attacker-controlled expressions in scripts: ", "clean", "rem",
		getWF, workflowInjectionContexts)
	if row.Status != string(StatusCompliant) {
		t.Fatalf("gitea injection on clean file: status=%s, want compliant", row.Status)
	}

	empty := giteaWorkflowSupplyChainRow("gitea", repo.FullName, "workflow-unpinned-actions",
		"t", "medium", "p: ", "clean", "rem",
		func() (map[string]string, error) { return nil, nil }, workflowUnpinnedUses)
	if empty.Status != string(StatusCompliant) {
		t.Fatalf("no workflows: status=%s, want compliant", empty.Status)
	}
}

func TestListGiteaWorkflowFilesRejectsInvalidContentMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, file string
	}{
		{"missing encoding", `{"name":"ci.yml","path":".gitea/workflows/ci.yml","type":"file","content":"b246IHB1c2g="}`},
		{"invalid base64", `{"name":"ci.yml","path":".gitea/workflows/ci.yml","type":"file","encoding":"base64","content":"%%%"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/workflows") {
					_, _ = w.Write([]byte(`[{"name":"ci.yml","path":".gitea/workflows/ci.yml","type":"file"}]`))
					return
				}
				if strings.HasSuffix(r.URL.Path, "/workflows/ci.yml") {
					_, _ = w.Write([]byte(tc.file))
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer srv.Close()
			client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "token ", client: srv.Client()}
			if _, err := listGiteaWorkflowFiles(context.Background(), client, giteaRepo{FullName: "me/app", DefaultBranch: "main"}); err == nil {
				t.Fatal("invalid workflow content metadata must fail closed")
			}
		})
	}
}

func TestGitLabSignedCommitsSkipsWhenPushRulesAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "PRIVATE-TOKEN", client: srv.Client()}
	row := auditGitLabSignedCommits(context.Background(), client, gitlabProject{ID: 1, PathWithNamespace: "me/app"})
	if row.Status != string(StatusSkipped) {
		t.Fatalf("status=%s detail=%q, want skipped (404 is ambiguous: no rule configured, or CE/Free without push rules)", row.Status, row.Detail)
	}
}

func giteaWorkflowsRowForTest(client *restClient, repo giteaRepo) auditRow {
	return auditGiteaWorkflows("gitea", repo, func() (map[string]string, error) {
		return listGiteaWorkflowFiles(context.Background(), client, repo)
	})
}

func TestAuditGiteaWorkflowsRequiresAFileNotOnlyADirectory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/workflows") {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "token ", client: srv.Client()}
	row := giteaWorkflowsRowForTest(client, giteaRepo{FullName: "me/app", DefaultBranch: "main"})
	if row.Status != string(StatusGap) {
		t.Fatalf("empty workflow directories: status=%s detail=%q, want gap", row.Status, row.Detail)
	}
}

func TestListGiteaWorkflowFilesIncludesForgejoDir(t *testing.T) {
	workflow := "on: push\njobs:\n  build:\n    steps:\n      - uses: someone/tool@v1\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/repos/me/app/contents/.forgejo%2Fworkflows",
			"/api/v1/repos/me/app/contents/.forgejo/workflows":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"name": "ci.yml", "path": ".forgejo/workflows/ci.yml", "type": "file"},
			})
		case "/api/v1/repos/me/app/contents/.forgejo%2Fworkflows%2Fci.yml",
			"/api/v1/repos/me/app/contents/.forgejo/workflows/ci.yml":
			fmt.Fprintf(w, `{"name":"ci.yml","path":".forgejo/workflows/ci.yml","type":"file","encoding":"base64","content":%q}`,
				base64.StdEncoding.EncodeToString([]byte(workflow)))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "token ", client: srv.Client()}
	repo := giteaRepo{FullName: "me/app", DefaultBranch: "main"}
	repo.Owner.Login = "me"
	repo.Name = "app"

	files, err := listGiteaWorkflowFiles(context.Background(), client, repo)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files[".forgejo/workflows/ci.yml"]; !ok || len(files) != 1 {
		t.Fatalf("files = %v, want the .forgejo/workflows workflow", files)
	}
}

func TestGitLabPipelineSupplyChainSkipsWithoutDefaultBranch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no API call expected for empty default branch, got %s", r.URL.Path)
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "Bearer ", client: srv.Client()}
	row := auditGitLabPipelineSupplyChain(context.Background(), client, gitlabProject{ID: 1, PathWithNamespace: "g/p"})
	if row.Status != string(StatusSkipped) || !strings.Contains(row.Detail, "no default branch") {
		t.Fatalf("empty project: status=%s detail=%q, want skipped", row.Status, row.Detail)
	}
}

func TestGitLabPipelineSupplyChainFlagsUnparseableYAML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{{ not yaml")
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "Bearer ", client: srv.Client()}
	p := gitlabProject{ID: 1, PathWithNamespace: "g/p", DefaultBranch: "main"}
	row := auditGitLabPipelineSupplyChain(context.Background(), client, p)
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "unparseable") {
		t.Fatalf("broken pipeline YAML: status=%s detail=%q, want gap", row.Status, row.Detail)
	}
	if _, err := gitlabPipelineFindings("{{ not yaml"); err == nil {
		t.Fatal("gitlabPipelineFindings must reject invalid YAML")
	}
}

func TestGiteaWorkflowSupplyChainRowErrorClassification(t *testing.T) {
	unavailable := func() (map[string]string, error) {
		return nil, &restError{method: "GET", path: "/x", statusCode: http.StatusForbidden, status: "403"}
	}
	row := giteaWorkflowSupplyChainRow("gitea", "me/app", "workflow-unpinned-actions", "t", "medium", "gap: ", "clean", "rem", unavailable, workflowUnpinnedUses)
	if row.Status != string(StatusSkipped) {
		t.Fatalf("403 fetch: status=%s, want skipped", row.Status)
	}
	failing := func() (map[string]string, error) {
		return nil, &restError{method: "GET", path: "/x", statusCode: http.StatusInternalServerError, status: "500"}
	}
	row = giteaWorkflowSupplyChainRow("gitea", "me/app", "workflow-unpinned-actions", "t", "medium", "gap: ", "clean", "rem", failing, workflowUnpinnedUses)
	if row.Status != string(StatusError) {
		t.Fatalf("500 fetch: status=%s, want error", row.Status)
	}
}

func TestAuditGitLabRequiredWorkflowsParsesConfiguration(t *testing.T) {
	tests := []struct {
		name, content string
		want          ControlStatus
	}{
		{"job", "stages: [test]\ntest:\n  script: echo ok\n", StatusCompliant},
		{"include only", "include:\n  - local: ci/base.yml\n", StatusCompliant},
		{"empty", "", StatusGap},
		{"comment only", "# intentionally empty\n", StatusGap},
		{"empty mapping", "{}\n", StatusGap},
		{"scalar", "hello\n", StatusGap},
		{"sequence", "- test\n", StatusGap},
		{"multiple documents", "stages: [test]\n---\ntest:\n  script: echo ok\n", StatusGap},
		{"malformed", "jobs: [\n", StatusGap},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.Query().Get("ref"); got != "main" {
					t.Errorf("ref=%q, want main", got)
				}
				_, _ = w.Write([]byte(test.content))
			}))
			defer srv.Close()
			client := &restClient{baseURL: srv.URL, token: "t", header: "PRIVATE-TOKEN", client: srv.Client()}
			project := gitlabProject{ID: 1, PathWithNamespace: "group/app", DefaultBranch: "main"}
			row := auditGitLabRequiredWorkflows(context.Background(), client, project)
			if row.Status != string(test.want) {
				t.Fatalf("status=%s detail=%q, want %s", row.Status, row.Detail, test.want)
			}
		})
	}
}

func TestValidateGiteaWorkflowRequiresTriggerAndExecutableJob(t *testing.T) {
	tests := []struct {
		name, content string
		valid         bool
	}{
		{"normal job", "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n", true},
		{"reusable job", "on: workflow_dispatch\njobs:\n  shared:\n    uses: owner/repo/.gitea/workflows/build.yml@main\n", true},
		{"missing trigger", "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n", false},
		{"empty trigger", "on: []\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n", false},
		{"missing jobs", "on: push\n", false},
		{"empty jobs", "on: push\njobs: {}\n", false},
		{"non-executable job", "on: push\njobs:\n  build:\n    name: Build\n", false},
		{"multiple documents", "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n---\non: pull_request\n", false},
		{"malformed", "on: [push\n", false},
		{"empty", "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateGiteaWorkflow(test.content)
			if (err == nil) != test.valid {
				t.Fatalf("err=%v, valid=%t", err, test.valid)
			}
		})
	}
}

func TestAuditGiteaWorkflowsRequiresAtLeastOneValidFile(t *testing.T) {
	validWorkflow := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
	for _, test := range []struct {
		name     string
		contents []string
		want     ControlStatus
	}{
		{"only empty file", []string{""}, StatusGap},
		{"only invalid file", []string{"on: push\njobs: {}\n"}, StatusGap},
		{"valid and invalid files", []string{"# empty\n", validWorkflow}, StatusCompliant},
	} {
		t.Run(test.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/contents/.gitea/workflows") {
					entries := make([]map[string]string, 0, len(test.contents))
					for i := range test.contents {
						name := "ci" + string(rune('a'+i)) + ".yml"
						entries = append(entries, map[string]string{"name": name, "path": ".gitea/workflows/" + name, "type": "file"})
					}
					_ = json.NewEncoder(w).Encode(entries)
					return
				}
				for i, content := range test.contents {
					name := "ci" + string(rune('a'+i)) + ".yml"
					if strings.HasSuffix(r.URL.Path, "/contents/.gitea/workflows/"+name) {
						_ = json.NewEncoder(w).Encode(map[string]string{
							"name": name, "path": ".gitea/workflows/" + name, "type": "file",
							"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(content)),
						})
						return
					}
				}
				http.NotFound(w, r)
			}))
			defer srv.Close()
			client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "token ", client: srv.Client()}
			repo := giteaRepo{FullName: "me/app", DefaultBranch: "main"}
			row := giteaWorkflowsRowForTest(client, repo)
			if row.Status != string(test.want) {
				t.Fatalf("status=%s detail=%q, want %s", row.Status, row.Detail, test.want)
			}
		})
	}
}
