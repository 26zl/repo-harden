package repoharden

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
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
}

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// mustClient builds a test client with a custom http.Client.
func mustClient(hc *http.Client) *github.Client {
	c, err := github.NewClient(github.WithHTTPClient(hc))
	if err != nil {
		panic(err)
	}
	return c
}

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

	fn()

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
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

func TestEntryKey(t *testing.T) {
	if entryKey("foo/bar", 42) != "foo/bar#42" {
		t.Fatal("entryKey format changed")
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

func TestStateRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	want := []StateEntry{
		{Repo: "foo/bar", ID: 1, Name: "CI", Path: ".github/workflows/ci.yml"},
		{Repo: "foo/baz", ID: 2, Name: "Lint", Path: ".github/workflows/lint.yml"},
	}
	if err := saveState(path, want); err != nil {
		t.Fatalf("saveState: %v", err)
	}
	got, err := loadState(path)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("roundtrip mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

func TestLoadStateMissing(t *testing.T) {
	got, err := loadState(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if got != nil {
		t.Errorf("missing file should yield nil, got %v", got)
	}
}

func TestLoadStateMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"repo":`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(path); err == nil {
		t.Fatal("malformed state should return an error")
	} else if !strings.Contains(err.Error(), "parse state file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStateFilePathOverride(t *testing.T) {
	custom := filepath.Join(t.TempDir(), "nested", "custom.json")
	got, err := stateFilePath(&opts{stateFile: custom})
	if err != nil {
		t.Fatal(err)
	}
	if got != custom {
		t.Errorf("got %q, want %q", got, custom)
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
	out := captureStdout(t, usage)
	for _, want := range []string{"audit", "harden", "revert", "--only", "--skip", "--provider", "--format", "--exit-code"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage missing %q", want)
		}
	}
}

func TestProviderURLHelpers(t *testing.T) {
	if got := hostName("https://github.example.com/api/v3"); got != "github.example.com" {
		t.Fatalf("hostName = %q, want github.example.com", got)
	}
	if got := providerBaseURL("gitlab", "gitlab.example.com/"); got != "https://gitlab.example.com" {
		t.Fatalf("providerBaseURL = %q, want https://gitlab.example.com", got)
	}
	if got := providerBaseURL("gitea", ""); got != "http://localhost:3000" {
		t.Fatalf("gitea default base URL = %q, want http://localhost:3000", got)
	}
	api, upload := githubEnterpriseURLs("github.example.com")
	if api != "https://github.example.com/api/v3/" || upload != "https://github.example.com/api/uploads/" {
		t.Fatalf("enterprise urls = %q %q", api, upload)
	}
}

func TestAuthTransportSetsBearer(t *testing.T) {
	var got string
	at := &authTransport{token: "tok", base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		got = req.Header.Get("Authorization")
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: http.NoBody}, nil
	})}
	req, _ := http.NewRequest(http.MethodGet, "https://x/y", nil)
	if _, err := at.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if got != "Bearer tok" {
		t.Fatalf("Authorization = %q, want Bearer tok", got)
	}
}

func TestRetryTransportDoesNotRetryMutations(t *testing.T) {
	calls := 0
	rt := &retryTransport{max: 3, base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 500, Header: make(http.Header), Body: http.NoBody}, nil
	})}
	req, _ := http.NewRequest(http.MethodPost, "https://x/y", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("POST must not be retried, got %d calls", calls)
	}
}

func TestRetryTransportRetriesGETOn500(t *testing.T) {
	calls := 0
	rt := &retryTransport{max: 3, base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		code := http.StatusOK
		if calls == 1 {
			code = http.StatusInternalServerError
		}
		return &http.Response{StatusCode: code, Header: make(http.Header), Body: http.NoBody}, nil
	})}
	req, _ := http.NewRequest(http.MethodGet, "https://x/y", nil)
	resp, err := rt.RoundTrip(req) // sleeps ~1s on the one retry
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("got %v / %v, want 200/nil", resp, err)
	}
	if calls != 2 {
		t.Fatalf("expected 1 retry (2 calls), got %d", calls)
	}
}

func TestRetryTransportStopsOnCanceledContext(t *testing.T) {
	rt := &retryTransport{max: 3, base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 500, Header: make(http.Header), Body: http.NoBody}, nil
	})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://x/y", nil)
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("canceled context should abort the retry wait")
	}
}

func TestNoCrossHostRedirect(t *testing.T) {
	orig, _ := http.NewRequest(http.MethodGet, "https://api.github.com/a", nil)
	same, _ := http.NewRequest(http.MethodGet, "https://api.github.com/b", nil)
	if err := noCrossHostRedirect(same, []*http.Request{orig}); err != nil {
		t.Fatalf("same-host redirect should be allowed: %v", err)
	}
	other, _ := http.NewRequest(http.MethodGet, "https://evil.example.com/x", nil)
	if err := noCrossHostRedirect(other, []*http.Request{orig}); err == nil {
		t.Fatal("cross-host redirect must be refused (token would leak)")
	}
}

func TestGitHubClientDoesNotLeakTokenOnCrossHostRedirect(t *testing.T) {
	var leaked string
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization")
	}))
	defer attacker.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/stolen", http.StatusFound)
	}))
	defer origin.Close()

	resp, err := newGitHubHTTPClient("secret").Get(origin.URL + "/start")
	if err == nil && resp != nil {
		resp.Body.Close()
	}
	if leaked != "" {
		t.Fatalf("bearer token leaked to redirect target: %q", leaked)
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
	ok := &opts{provider: "github", format: "table", staleDays: 1}
	if err := validateOptions(ok); err != nil {
		t.Fatalf("valid opts rejected: %v", err)
	}
	bad := []*opts{
		{provider: "bogus", format: "table", staleDays: 1},
		{provider: "github", format: "xml", staleDays: 1},
		{provider: "github", format: "table", staleDays: 0},
		{provider: "gitlab", format: "table", staleDays: 1, repo: "me/app"},
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

func TestCommandNeedsGitHubClient(t *testing.T) {
	if commandNeedsGitHubClient("controls", &opts{}) {
		t.Fatal("controls needs no client")
	}
	if commandNeedsGitHubClient("audit", &opts{provider: "gitlab"}) {
		t.Fatal("gitlab audit needs no github client")
	}
	if !commandNeedsGitHubClient("audit", &opts{provider: "github"}) {
		t.Fatal("github audit needs a client")
	}
	if !commandNeedsGitHubClient("harden", &opts{provider: "github"}) {
		t.Fatal("harden needs a client")
	}
}

func TestToggleRepoEnableTargetsDisabledOnly(t *testing.T) {
	puts := 0
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
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
