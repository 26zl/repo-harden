package repoharden

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-github/v88/github"
)

func TestGitHubRepositoryLicense(t *testing.T) {
	repo := &github.Repository{FullName: github.Ptr("me/app")}

	detected := mockClient(map[string]string{
		"GET /repos/me/app/license": `{
			"name":"LICENSE",
			"path":"LICENSE",
			"license":{"key":"mit","name":"MIT License","spdx_id":"MIT"}
		}`,
	})
	row := auditGitHubRepositoryLicense(context.Background(), detected, "me", "app", repo)
	if row.Status != string(StatusCompliant) || !strings.Contains(row.Detail, "MIT") || !strings.Contains(row.Detail, "LICENSE") {
		t.Fatalf("detected license row = %+v, want compliant MIT detail", row)
	}

	unknown := mockClient(map[string]string{
		"GET /repos/me/app/license": `{
			"path":"LICENSE.custom",
			"license":{"key":"other","name":"Other","spdx_id":"NOASSERTION"}
		}`,
	})
	row = auditGitHubRepositoryLicense(context.Background(), unknown, "me", "app", repo)
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "unknown") {
		t.Fatalf("unknown license row = %+v, want gap", row)
	}

	row = auditGitHubRepositoryLicense(context.Background(), mockClient(nil), "me", "app", repo)
	if row.Status != string(StatusGap) || !strings.Contains(row.Detail, "no recognizable") {
		t.Fatalf("missing license row = %+v, want gap", row)
	}

	forbidden := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
	})})
	row = auditGitHubRepositoryLicense(context.Background(), forbidden, "me", "app", repo)
	if row.Status != string(StatusSkipped) {
		t.Fatalf("forbidden license row = %+v, want skipped", row)
	}
}

func TestGitHubRepositoryLicenseDoesNotHideRateLimit(t *testing.T) {
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp := &http.Response{
			StatusCode: http.StatusForbidden,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"message":"rate limited"}`)),
			Request:    req,
		}
		resp.Header.Set("X-RateLimit-Remaining", "0")
		return resp, nil
	})})
	row := auditGitHubRepositoryLicense(context.Background(), client, "me", "app", &github.Repository{FullName: github.Ptr("me/app")})
	if row.Status != string(StatusError) {
		t.Fatalf("rate-limited license row = %+v, want error", row)
	}
}

func TestGitLabRepositoryLicense(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want ControlStatus
	}{
		{"detected", `{"license_url":"https://example/license","license":{"key":"mit","name":"MIT License"}}`, StatusCompliant},
		{"missing", `{"license_url":null,"license":null}`, StatusGap},
		{"unknown", `{"license_url":"https://example/license","license":{"key":"other","name":"Other"}}`, StatusGap},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v4/projects/7" || r.URL.Query().Get("license") != "true" {
					http.NotFound(w, r)
					return
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			client := &restClient{baseURL: srv.URL, token: "t", header: "PRIVATE-TOKEN", client: srv.Client()}
			row := auditGitLabRepositoryLicense(context.Background(), client, gitlabProject{ID: 7, PathWithNamespace: "me/app"})
			if row.Status != string(tc.want) {
				t.Fatalf("row = %+v, want %s", row, tc.want)
			}
		})
	}
}

func TestGitLabRepositoryLicenseUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "PRIVATE-TOKEN", client: srv.Client()}
	row := auditGitLabRepositoryLicense(context.Background(), client, gitlabProject{ID: 7, PathWithNamespace: "me/app"})
	if row.Status != string(StatusSkipped) {
		t.Fatalf("row = %+v, want skipped", row)
	}
}

func TestGiteaRepositoryLicense(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want ControlStatus
	}{
		{"present", `[{"name":"README.md","type":"file"},{"name":"LICENCE.txt","type":"file"}]`, StatusCompliant},
		{"missing", `[{"name":"README.md","type":"file"}]`, StatusGap},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/repos/me/app/contents" || r.URL.Query().Get("ref") != "main" {
					http.NotFound(w, r)
					return
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "token ", client: srv.Client()}
			row := auditGiteaRepositoryLicense(context.Background(), client, "forgejo", giteaRepo{
				FullName: "me/app", DefaultBranch: "main",
			})
			if row.Provider != "forgejo" || row.Status != string(tc.want) {
				t.Fatalf("row = %+v, want forgejo/%s", row, tc.want)
			}
		})
	}
}

func TestGiteaRepositoryLicenseUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	client := &restClient{baseURL: srv.URL, token: "t", header: "Authorization", prefix: "token ", client: srv.Client()}
	row := auditGiteaRepositoryLicense(context.Background(), client, "gitea", giteaRepo{FullName: "me/app", DefaultBranch: "main"})
	if row.Status != string(StatusSkipped) {
		t.Fatalf("row = %+v, want skipped", row)
	}
}

func TestRepositoryLicenseFilename(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"LICENSE", true},
		{"licence.md", true},
		{"COPYING-GPL", true},
		{"docs/LICENSE.txt", true},
		{"LICENSES/README.md", false},
		{"LICENSE_HEADER.go", false},
		{"NOTICE", false},
	} {
		if got := repositoryLicenseFilename(tc.path); got != tc.want {
			t.Errorf("repositoryLicenseFilename(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
