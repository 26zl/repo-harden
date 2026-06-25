package repoharden

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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
