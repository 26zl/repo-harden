package repoharden

import (
	"context"
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
			_, _ = w.Write([]byte(`[{"id":3}]`)) // no X-Next-Page -> last page
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

func TestGiteaPagedStopsOnShortPage(t *testing.T) {
	full := "[" + strings.Repeat(`{"x":1},`, 49) + `{"x":1}]` // exactly 50 items
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			_, _ = w.Write([]byte(full)) // full page -> continue
		} else {
			_, _ = w.Write([]byte(`[{"x":1}]`)) // short page -> stop
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
}

func TestEscapedFilePathKeepsPathSegments(t *testing.T) {
	got := escapedFilePath(".gitea/workflows/ci yml")
	want := ".gitea/workflows/ci%20yml"
	if got != want {
		t.Fatalf("escapedFilePath = %q, want %q", got, want)
	}
}

func TestHTTPUnavailableUsesRESTStatusCode(t *testing.T) {
	if !httpUnavailable(&restError{statusCode: http.StatusNotFound, status: "404 Not Found"}) {
		t.Fatal("404 rest error should be unavailable")
	}
	if httpUnavailable(&restError{statusCode: http.StatusForbidden, status: "403 Forbidden"}) {
		t.Fatal("403 rest error should not be treated as unavailable")
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
		{"unprotected", http.StatusNotFound, StatusGap}, // 404 = unavailable = gap
		{"server-error", http.StatusInternalServerError, StatusError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.status == http.StatusOK {
					_, _ = w.Write([]byte(`{"name":"main"}`))
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

func TestCollectGitLabAuditSmoke(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/projects" {
			_, _ = w.Write([]byte(`[{"id":1,"path_with_namespace":"me/app","default_branch":"main","visibility":"private"}]`))
			return
		}
		http.NotFound(w, r) // every per-check endpoint 404s -> gap/skip, must not panic
	}))
	defer srv.Close()
	rows, count, err := collectGitLabAudit(context.Background(), &opts{provider: "gitlab", host: srv.URL, token: "t", staleDays: 180})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("project count = %d, want 1", count)
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
	row := auditGiteaWorkflows(context.Background(), client, "gitea", giteaRepo{FullName: "me/app", DefaultBranch: "main"})
	if row.Status != string(StatusError) {
		t.Fatalf("status = %s detail=%q, want error", row.Status, row.Detail)
	}
}
