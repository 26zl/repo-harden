package repoharden

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/google/go-github/v88/github"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestGetNamedRepos(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /repos/me/app": `{"full_name":"me/app"}`,
		"GET /repos/me/lib": `{"full_name":"me/lib"}`,
	})
	repos, err := getNamedRepos(context.Background(), client, "me/app, me/lib, me/app")
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 2 {
		t.Fatalf("got %d repos, want 2 (deduped)", len(repos))
	}
	if _, err := getNamedRepos(context.Background(), client, "bad"); err == nil {
		t.Fatal("invalid owner/repo should error")
	}
	if _, err := getNamedRepos(context.Background(), client, "a/b/c"); err == nil {
		t.Fatal("owner/repo with extra segment should error")
	}
}

func TestListReposNamedHonorsEligibilityFilters(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /repos/me/fork": `{"full_name":"me/fork","owner":{"login":"me"},"fork":true,"archived":false,"permissions":{"admin":true}}`,
	})
	if _, err := listRepos(context.Background(), client, &opts{repo: "me/fork"}); err == nil || !strings.Contains(err.Error(), "--include-forks") {
		t.Fatalf("named fork without --include-forks: got %v", err)
	}
	repos, err := listRepos(context.Background(), client, &opts{repo: "me/fork", includeForks: true, adminOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 || repos[0].GetFullName() != "me/fork" {
		t.Fatalf("eligible named repos = %+v, want me/fork", repos)
	}
	if _, err := listRepos(context.Background(), client, &opts{repo: "me/fork", includeForks: true, owner: "other"}); err == nil || !strings.Contains(err.Error(), "--owner") {
		t.Fatalf("named repo outside --owner: got %v", err)
	}
}

func TestCLIGitHubPaginationFailsClosed(t *testing.T) {
	t.Run("repositories", func(t *testing.T) {
		calls := 0
		client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			resp := jsonResponse(`[]`)
			resp.Header.Set("Link", `<https://api.github.com/user/repos?per_page=100&page=1>; rel="next"`)
			return resp, nil
		})})
		if _, err := listRepos(context.Background(), client, &opts{}); err == nil || !strings.Contains(err.Error(), "did not advance") {
			t.Fatalf("non-advancing repository pagination = %v", err)
		}
		if calls != 1 {
			t.Fatalf("non-advancing repository pagination made %d calls, want 1", calls)
		}
	})

	t.Run("workflows", func(t *testing.T) {
		calls := 0
		client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			resp := jsonResponse(`{"total_count":0,"workflows":[]}`)
			resp.Header.Set("Link", `<https://api.github.com/repos/me/app/actions/workflows?per_page=100&page=1>; rel="next"`)
			return resp, nil
		})})
		if _, err := listWorkflows(context.Background(), client, "me", "app"); err == nil || !strings.Contains(err.Error(), "did not advance") {
			t.Fatalf("non-advancing workflow pagination = %v", err)
		}
		if calls != 1 {
			t.Fatalf("non-advancing workflow pagination made %d calls, want 1", calls)
		}
	})

	pager := githubPager{pages: maxGitHubPages}
	if _, _, err := pager.next(&github.Response{NextPage: 2}); err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("GitHub pagination page cap = %v", err)
	}
}

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func mustClient(hc *http.Client) *github.Client {
	c, err := github.NewClient(github.WithHTTPClient(hc))
	if err != nil {
		panic(err)
	}
	return c
}

// captureStdout swaps the process-global os.Stdout, so tests using it must not run in parallel.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = old
	}()

	// drain concurrently so output larger than the pipe buffer cannot deadlock fn
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return <-done
}

func TestSplitRepo(t *testing.T) {
	cases := []struct {
		in          string
		owner, name string
	}{
		{"foo/bar", "foo", "bar"},
		{"a/b/c", "a", "b/c"},
		{"plain", "", "plain"},
		{"", "", ""},
	}
	for _, c := range cases {
		o, n := splitRepo(c.in)
		if o != c.owner || n != c.name {
			t.Errorf("splitRepo(%q) = (%q,%q), want (%q,%q)", c.in, o, n, c.owner, c.name)
		}
	}
}

func TestValidateCommandInvocation(t *testing.T) {
	if err := validateCommandInvocation("audit", []string{"unexpected"}, &opts{}); err == nil {
		t.Fatal("audit positional argument should be rejected")
	}
	if err := validateCommandInvocation("disable-repo", []string{"me/app"}, &opts{}); err != nil {
		t.Fatalf("valid disable-repo invocation rejected: %v", err)
	}
	if err := validateCommandInvocation("disable-repo", []string{"bad"}, &opts{}); err == nil {
		t.Fatal("malformed disable-repo slug should be rejected")
	}
	if err := validateCommandInvocation("list", nil, &opts{failOnSkipped: true}); err == nil {
		t.Fatal("--fail-on-skipped outside audit should be rejected")
	}
	if err := validateCommandInvocation("list", nil, &opts{orgAuditSet: true}); err == nil {
		t.Fatal("--org-audit outside audit should be rejected")
	}
	if err := validateCommandInvocation("status", nil, &opts{staleDaysSet: true, staleDays: 5}); err == nil {
		t.Fatal("--stale-days outside audit should be rejected")
	}
	if err := validateCommandInvocation("enable-all-disabled", nil, &opts{stateFile: "x.json"}); err == nil {
		t.Fatal("--state-file on a stateless command should be rejected")
	}
	if err := validateCommandInvocation("harden", nil, &opts{stateFile: "x.json"}); err != nil {
		t.Fatalf("--state-file on harden rejected: %v", err)
	}
	if err := validateCommandInvocation("audit", nil, &opts{orgAuditSet: true, staleDaysSet: true, staleDays: 30}); err != nil {
		t.Fatalf("audit-scoped flags rejected on audit: %v", err)
	}
}

func TestSkipWorkflow(t *testing.T) {
	dyn := &github.Workflow{Path: github.Ptr("dynamic/github-code-scanning/codeql")}
	user := &github.Workflow{Path: github.Ptr(".github/workflows/ci.yml")}

	if !skipWorkflow(dyn, &opts{}) {
		t.Error("dynamic/ workflow should be skipped by default")
	}
	if skipWorkflow(dyn, &opts{includeDynamic: true}) {
		t.Error("dynamic/ should NOT be skipped with --include-dynamic")
	}
	if skipWorkflow(user, &opts{}) {
		t.Error("user workflow should never be skipped")
	}
}

func TestListReposUsesAuthenticatedReposAndOwnerFilter(t *testing.T) {
	var gotPath, gotAffiliation, gotVisibility string
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotPath = req.URL.Path
		gotAffiliation = req.URL.Query().Get("affiliation")
		gotVisibility = req.URL.Query().Get("visibility")
		return jsonResponse(`[
			{"full_name":"me/app","owner":{"login":"me"}},
			{"full_name":"org/private","owner":{"login":"org"}},
			{"full_name":"org/fork","fork":true,"owner":{"login":"org"}},
			{"full_name":"org/old","archived":true,"owner":{"login":"org"}}
		]`), nil
	})})

	repos, err := listRepos(context.Background(), client, &opts{owner: "ORG"})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/user/repos" {
		t.Fatalf("expected authenticated repos endpoint, got %q", gotPath)
	}
	if gotAffiliation != "owner,collaborator,organization_member" {
		t.Fatalf("unexpected affiliation: %q", gotAffiliation)
	}
	if gotVisibility != "all" {
		t.Fatalf("unexpected visibility: %q", gotVisibility)
	}

	got := make([]string, 0, len(repos))
	for _, r := range repos {
		got = append(got, r.GetFullName())
	}
	want := []string{"org/private"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("repos = %v, want %v", got, want)
	}
}

func TestUsageListsHardenCommands(t *testing.T) {
	out := captureStdout(t, func() { usage(os.Stdout) })
	for _, want := range []string{"audit", "harden", "revert", "--only", "--skip", "--provider", "--format", "--exit-code"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage missing %q", want)
		}
	}
}

func TestBuildMetadataFallbackUsesModuleAndVCSInfo(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.2.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abc123"},
			{Key: "vcs.time", Value: "2026-06-28T12:00:00Z"},
			{Key: "vcs.modified", Value: "true"},
		},
	}
	version, commit, date := buildMetadataFallback("dev", "none", "unknown", info)
	if version != "v0.2.0+dirty" || commit != "abc123" || date != "2026-06-28T12:00:00Z" {
		t.Fatalf("metadata = %q %q %q", version, commit, date)
	}
}

func TestProviderURLHelpers(t *testing.T) {
	if got := hostName("https://github.example.com/api/v3"); got != "github.example.com" {
		t.Fatalf("hostName = %q, want github.example.com", got)
	}
	if got := providerBaseURL("gitlab", "gitlab.example.com/"); got != "https://gitlab.example.com" {
		t.Fatalf("providerBaseURL = %q, want https://gitlab.example.com", got)
	}
	if got := providerBaseURL("gitlab", "https://gitlab.example.com/api/v4"); got != "https://gitlab.example.com" {
		t.Fatalf("GitLab API URL was not normalized: %q", got)
	}
	if got := providerBaseURL("forgejo", "https://code.example.com/api/v1"); got != "https://code.example.com" {
		t.Fatalf("Forgejo API URL was not normalized: %q", got)
	}
	if got := providerBaseURL("gitea", ""); got != "http://localhost:3000" {
		t.Fatalf("gitea default base URL = %q, want http://localhost:3000", got)
	}
	api, upload := githubEnterpriseURLs("github.example.com")
	if api != "https://github.example.com/api/v3/" || upload != "https://github.example.com/api/uploads/" {
		t.Fatalf("enterprise urls = %q %q", api, upload)
	}
}

func TestCmdDisableAllPersistsAppliedWorkflowState(t *testing.T) {
	var disabled bool
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/user/repos":
			return jsonResponse(`[{"full_name":"me/app","owner":{"login":"me"},"fork":false,"archived":false}]`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/user":
			return jsonResponse(`{"login":"tester","id":42}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/repos/me/app/actions/workflows":
			return jsonResponse(`{"total_count":1,"workflows":[{"id":1,"name":"CI","path":".github/workflows/ci.yml","state":"active"}]}`), nil
		case req.Method == http.MethodPut && req.URL.Path == "/repos/me/app/actions/workflows/1/disable":
			disabled = true
			return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
		}
	})})
	path := filepath.Join(t.TempDir(), "actions.json")
	o := &opts{host: "github.com", stateFile: path, concurrency: 1}
	_ = captureStdout(t, func() {
		if err := cmdDisableAll(context.Background(), client, o); err != nil {
			t.Fatal(err)
		}
	})
	if !disabled {
		t.Fatal("disable-all did not call the workflow disable endpoint")
	}
	entries, err := loadState(path, testStateScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != 1 || entries[0].Phase != ActionPhaseApplied {
		t.Fatalf("persisted Actions state = %+v", entries)
	}
}

func TestDisableAllDryRunDoesNotCreateStateArtifacts(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "missing-state")
	t.Setenv("REPO_HARDEN_STATE_DIR", stateDir)
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/user/repos":
			return jsonResponse(`[{"full_name":"me/app","owner":{"login":"me"}}]`), nil
		case "/user":
			return jsonResponse(`{"login":"tester","id":42}`), nil
		case "/repos/me/app/actions/workflows":
			return jsonResponse(`{"total_count":1,"workflows":[{"id":1,"name":"CI","state":"active"}]}`), nil
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody}, nil
		}
	})})
	_ = captureStdout(t, func() {
		if err := cmdDisableAll(context.Background(), client, &opts{
			dryRun: true, host: "github.com", concurrency: 1,
		}); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := os.Lstat(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry-run created or touched state directory %s: %v", stateDir, err)
	}
}

func TestEnableAllDryRunDoesNotCreateLockFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actions.json")
	entries := []StateEntry{{Repo: "me/app", ID: 1, Name: "CI", Phase: ActionPhaseApplied}}
	if err := saveState(path, testStateScope, entries); err != nil {
		t.Fatal(err)
	}
	client := mockClient(map[string]string{"GET /user": `{"login":"tester","id":42}`})
	_ = captureStdout(t, func() {
		if err := cmdEnableAll(context.Background(), client, &opts{
			dryRun: true, stateFile: path, host: "github.com", concurrency: 1,
		}); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := os.Lstat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry-run created lock file: %v", err)
	}
}

func TestCollectRowsReportsUnreadableRepos(t *testing.T) {
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/actions/workflows") {
			if strings.Contains(req.URL.Path, "good") {
				return jsonResponse(`{"total_count":1,"workflows":[{"id":1,"name":"CI","path":"p","state":"active"}]}`), nil
			}
			return &http.Response{StatusCode: http.StatusInternalServerError, Status: "500 err", Header: make(http.Header), Body: http.NoBody, Request: req}, nil
		}
		return jsonResponse(`{}`), nil
	})})
	repos := []*github.Repository{
		{FullName: github.Ptr("me/good")},
		{FullName: github.Ptr("me/bad")},
	}
	rows, repoErrors, err := collectRows(context.Background(), client, &opts{concurrency: 1}, repos)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || repoErrors != 1 {
		t.Fatalf("rows=%d repoErrors=%d, want 1 and 1", len(rows), repoErrors)
	}
}

func TestCmdStatusCountsWorkflowStates(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /user":                           `{"login":"me"}`,
		"GET /repos/me/app":                   `{"full_name":"me/app","owner":{"login":"me"}}`,
		"GET /repos/me/app/actions/workflows": `{"total_count":2,"workflows":[{"id":1,"name":"CI","path":"a","state":"active"},{"id":2,"name":"Old","path":"b","state":"disabled_manually"}]}`,
	})
	out := captureStdout(t, func() {
		if err := cmdStatus(context.Background(), client, &opts{repo: "me/app", jsonOut: true, concurrency: 1}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, `"active":1`) || !strings.Contains(out, `"disabled_manually":1`) {
		t.Fatalf("status JSON missing expected state counts: %s", out)
	}
}

func TestTokenFromEnv(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "gh")
	t.Setenv("GITLAB_TOKEN", "gl")
	t.Setenv("GITEA_TOKEN", "gt")
	t.Setenv("FORGEJO_TOKEN", "")
	if got := tokenFromEnv("github"); got != "gh" {
		t.Fatalf("github = %q", got)
	}
	if got := tokenFromEnv("gitlab"); got != "gl" {
		t.Fatalf("gitlab = %q", got)
	}
	if got := tokenFromEnv("forgejo"); got != "gt" {
		t.Fatalf("forgejo should fall back to GITEA_TOKEN, got %q", got)
	}
	t.Setenv("FORGEJO_TOKEN", "fj")
	if got := tokenFromEnv("forgejo"); got != "fj" {
		t.Fatalf("forgejo = %q, want fj", got)
	}
}

func TestResolveTokenPrefersFlagOverEnv(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "from-env")
	got, err := resolveToken(&opts{token: "from-flag"}, "gitlab.com", "gitlab")
	if err != nil {
		t.Fatal(err)
	}
	if got != "from-flag" {
		t.Fatalf("resolveToken = %q, want from-flag", got)
	}
}

func TestResolveTokenReadsStdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	go func() {
		_, _ = io.WriteString(w, "  piped-token\n")
		w.Close()
	}()
	got, err := resolveToken(&opts{tokenStdin: true}, "github.com", "github")
	if err != nil {
		t.Fatal(err)
	}
	if got != "piped-token" {
		t.Fatalf("stdin token = %q, want piped-token (trimmed)", got)
	}
}

func TestValidateOptions(t *testing.T) {
	ok := &opts{provider: "github", format: "table", staleDays: 1, concurrency: 1}
	if err := validateOptions(ok); err != nil {
		t.Fatalf("valid opts rejected: %v", err)
	}
	bad := []*opts{
		{provider: "bogus", format: "table", staleDays: 1, concurrency: 1},
		{provider: "github", format: "xml", staleDays: 1, concurrency: 1},
		{provider: "github", format: "table", staleDays: 0, concurrency: 1},
		{provider: "github", format: "table", staleDays: 36501, concurrency: 1},
		{provider: "github", format: "table", staleDays: 1, concurrency: 0},
		{provider: "github", format: "table", staleDays: 1, concurrency: maxConcurrency + 1},
		{provider: "gitlab", format: "table", staleDays: 1, repo: "me/app", concurrency: 1},
	}
	for i, o := range bad {
		if err := validateOptions(o); err == nil {
			t.Fatalf("bad opts[%d] %+v should fail", i, o)
		}
	}
}

func TestNormalizeOptions(t *testing.T) {
	o := &opts{jsonOut: true, provider: "GitHub"}
	normalizeOptions(o)
	if o.format != "json" {
		t.Fatalf("--json should force format json, got %q", o.format)
	}
	if o.provider != "github" {
		t.Fatalf("provider should be lowercased, got %q", o.provider)
	}
	if o.host != "github.com" {
		t.Fatalf("default host = %q, want github.com", o.host)
	}
}

func TestToggleRepoEnableTargetsDisabledOnly(t *testing.T) {
	puts := 0
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/repos/me/app":
			return jsonResponse(`{"full_name":"me/app","owner":{"login":"me"},"fork":false,"archived":false}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/repos/me/app/actions/workflows":
			return jsonResponse(`{"total_count":2,"workflows":[
				{"id":1,"name":"CI","path":".github/workflows/ci.yml","state":"disabled_manually"},
				{"id":2,"name":"Deploy","path":".github/workflows/deploy.yml","state":"active"}
			]}`), nil
		case req.Method == http.MethodPut:
			puts++
			return jsonResponse(`{}`), nil
		}
		return &http.Response{StatusCode: 404, Header: make(http.Header), Body: http.NoBody}, nil
	})})
	_ = captureStdout(t, func() {
		if err := cmdToggleRepo(context.Background(), client, &opts{concurrency: 1}, []string{"me/app"}, "enable"); err != nil {
			t.Fatal(err)
		}
	})
	if puts != 1 {
		t.Fatalf("enable should target only the 1 disabled workflow, made %d PUTs", puts)
	}
}

func TestToggleRepoEnforcesRepositoryScope(t *testing.T) {
	tests := []struct {
		name string
		opts *opts
		repo string
	}{
		{"owner", &opts{owner: "other"}, `{"full_name":"me/app","owner":{"login":"me"}}`},
		{"fork", &opts{}, `{"full_name":"me/app","owner":{"login":"me"},"fork":true}`},
		{"archived", &opts{}, `{"full_name":"me/app","owner":{"login":"me"},"archived":true}`},
		{"admin", &opts{adminOnly: true}, `{"full_name":"me/app","owner":{"login":"me"},"permissions":{"admin":false}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workflowReads := 0
			client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodGet && req.URL.Path == "/repos/me/app" {
					return jsonResponse(tt.repo), nil
				}
				if req.URL.Path == "/repos/me/app/actions/workflows" {
					workflowReads++
				}
				return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody}, nil
			})})
			err := cmdToggleRepo(context.Background(), client, tt.opts, []string{"me/app"}, "disable")
			if err == nil || !strings.Contains(err.Error(), "excluded") {
				t.Fatalf("scope violation = %v, want excluded error", err)
			}
			if workflowReads != 0 {
				t.Fatalf("scope violation read workflows %d time(s)", workflowReads)
			}
		})
	}
}

func TestToggleRepoRejectsBadArgs(t *testing.T) {
	if err := cmdToggleRepo(context.Background(), nil, &opts{}, nil, "disable"); err == nil {
		t.Fatal("missing repo arg should error")
	}
	if err := cmdToggleRepo(context.Background(), nil, &opts{}, []string{"noslash"}, "disable"); err == nil {
		t.Fatal("invalid owner/repo should error")
	}
}

func TestEnableAllDisabledDryRunCountsMatches(t *testing.T) {
	enableCalls := 0
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/user/repos":
			return jsonResponse(`[{"full_name":"me/repo","owner":{"login":"me"}}]`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/repos/me/repo/actions/workflows":
			return jsonResponse(`{
				"total_count": 3,
				"workflows": [
					{"id":1,"name":"CI","path":".github/workflows/ci.yml","state":"disabled_manually"},
					{"id":2,"name":"Deploy","path":".github/workflows/deploy.yml","state":"active"},
					{"id":3,"name":"CodeQL","path":"dynamic/github-code-scanning/codeql","state":"disabled_manually"}
				]
			}`), nil
		case req.Method == http.MethodPut:
			enableCalls++
			return jsonResponse(`{}`), nil
		default:
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{}`)),
			}, nil
		}
	})})

	out := captureStdout(t, func() {
		if err := cmdEnableAllDisabled(context.Background(), client, &opts{dryRun: true, concurrency: 1}); err != nil {
			t.Fatal(err)
		}
	})
	if enableCalls != 0 {
		t.Fatalf("dry-run made %d enable calls", enableCalls)
	}
	if !strings.Contains(out, "dry-run: would enable 1 workflows") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestEnableAllRespectsRepoScopeAndKeepsOtherState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actions.json")
	entries := []StateEntry{
		{Repo: "me/a", ID: 1, Name: "A", Phase: ActionPhaseApplied},
		{Repo: "me/b", ID: 2, Name: "B", Phase: ActionPhaseApplied},
		{Repo: "other/c", ID: 3, Name: "C", Phase: ActionPhaseApplied},
	}
	if err := saveState(path, testStateScope, entries); err != nil {
		t.Fatal(err)
	}
	var enabled []string
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/user":
			return jsonResponse(`{"login":"tester","id":42}`), nil
		case req.Method == http.MethodPut:
			enabled = append(enabled, req.URL.Path)
			return jsonResponse(`{}`), nil
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody}, nil
		}
	})})
	o := &opts{stateFile: path, host: "github.com", repo: "me/b", concurrency: 1}
	_ = captureStdout(t, func() {
		if err := cmdEnableAll(context.Background(), client, o); err != nil {
			t.Fatal(err)
		}
	})
	if len(enabled) != 1 || !strings.Contains(enabled[0], "/repos/me/b/") {
		t.Fatalf("enabled paths = %v, want only me/b", enabled)
	}
	got, err := loadState(path, testStateScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Repo != "me/a" || got[1].Repo != "other/c" {
		t.Fatalf("out-of-scope state not preserved: %+v", got)
	}
}

func TestEnableAllReconcilesUnknownEntryBeforeMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actions.json")
	entries := []StateEntry{{
		Repo: "me/app", ID: 7, Name: "CI", Phase: ActionPhaseUnknown,
	}}
	if err := saveState(path, testStateScope, entries); err != nil {
		t.Fatal(err)
	}
	putCalls := 0
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/user":
			return jsonResponse(`{"login":"tester","id":42}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/repos/me/app/actions/workflows/7":
			return jsonResponse(`{"id":7,"name":"CI","state":"active"}`), nil
		case req.Method == http.MethodPut:
			putCalls++
			return jsonResponse(`{}`), nil
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody}, nil
		}
	})})
	_ = captureStdout(t, func() {
		if err := cmdEnableAll(context.Background(), client, &opts{
			stateFile: path, host: "github.com", concurrency: 1,
		}); err != nil {
			t.Fatal(err)
		}
	})
	if putCalls != 0 {
		t.Fatalf("already-active unknown entry triggered %d enable calls", putCalls)
	}
	got, err := loadState(path, testStateScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("reconciled entry remained in state: %+v", got)
	}
}
