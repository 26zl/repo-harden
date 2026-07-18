package repoharden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-github/v88/github"
)

func TestCommandRegistryIsCompleteAndValid(t *testing.T) {
	if err := validateCommandRegistry(commandRegistry); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"audit", "codify", "controls", "disable-all", "disable-repo", "enable-all",
		"enable-all-disabled", "enable-repo", "harden", "help", "list", "revert",
		"status", "version",
	}
	got := make([]string, 0, len(commandRegistry))
	for _, spec := range commandRegistry {
		got = append(got, spec.name)
		resolved, ok := lookupCommand(spec.name)
		if !ok || resolved.name != spec.name {
			t.Errorf("canonical command %q did not resolve to itself", spec.name)
		}
		for _, alias := range spec.aliases {
			resolved, ok := lookupCommand(alias)
			if !ok || resolved.name != spec.name {
				t.Errorf("alias %q did not resolve to %q", alias, spec.name)
			}
		}
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("registered commands = %v, want %v", got, want)
	}
	if _, ok := lookupCommand("unknown"); ok || isKnownCommand("unknown") {
		t.Fatal("unknown command must not resolve")
	}
}

func TestCommandRegistryRejectsInvalidEntries(t *testing.T) {
	handler := func(context.Context, *github.Client, *opts, []string) error { return nil }
	cases := []struct {
		name     string
		registry []commandSpec
	}{
		{"empty name", []commandSpec{{handler: handler}}},
		{"missing handler", []commandSpec{{name: "x"}}},
		{"invalid client requirement", []commandSpec{{name: "x", handler: handler, client: commandClientRequirement(99)}}},
		{"duplicate name", []commandSpec{{name: "x", handler: handler}, {name: "x", handler: handler}}},
		{"duplicate alias", []commandSpec{{name: "x", aliases: []string{"shared"}, handler: handler}, {name: "y", aliases: []string{"shared"}, handler: handler}}},
		{"alias shadows command", []commandSpec{{name: "x", aliases: []string{"y"}, handler: handler}, {name: "y", handler: handler}}},
		{"empty alias", []commandSpec{{name: "x", aliases: []string{""}, handler: handler}}},
	}
	for _, test := range cases {
		if err := validateCommandRegistry(test.registry); err == nil {
			t.Errorf("%s: expected validation error", test.name)
		}
	}
}

func TestDispatchCommandPassesDependenciesAndError(t *testing.T) {
	type contextKey string
	ctx := context.WithValue(context.Background(), contextKey("key"), "value")
	client := &github.Client{}
	o := &opts{provider: "github"}
	args := []string{"me/app"}
	wantErr := errors.New("handler failed")
	called := false
	spec := commandSpec{
		name: "test",
		handler: func(gotCtx context.Context, gotClient *github.Client, gotOpts *opts, gotArgs []string) error {
			called = true
			if gotCtx.Value(contextKey("key")) != "value" {
				t.Error("context was not passed to handler")
			}
			if gotClient != client || gotOpts != o || !reflect.DeepEqual(gotArgs, args) {
				t.Error("handler dependencies were not passed through unchanged")
			}
			return wantErr
		},
	}
	if err := dispatchCommand(ctx, spec, client, o, args); !errors.Is(err, wantErr) {
		t.Fatalf("dispatch error = %v, want %v", err, wantErr)
	}
	if !called {
		t.Fatal("registered handler was not called")
	}
	if err := dispatchCommand(ctx, commandSpec{name: "broken"}, client, o, nil); err == nil {
		t.Fatal("dispatch must reject a missing handler")
	}
}

func TestCommandClientRequirementsComeFromRegistry(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		want     bool
	}{
		{"controls", "github", false},
		{"audit", "gitlab", false},
		{"audit", "github", true},
		{"harden", "github", true},
		{"codify", "github", true},
		{"help", "github", false},
		{"version", "github", false},
		{"unknown", "github", false},
	}
	for _, test := range cases {
		if got := commandNeedsGitHubClient(test.name, &opts{provider: test.provider}); got != test.want {
			t.Errorf("%s/%s needs GitHub client = %v, want %v", test.name, test.provider, got, test.want)
		}
	}
}

func TestCommandPresentationPolicy(t *testing.T) {
	for _, spec := range commandRegistry {
		switch spec.name {
		case "help", "version":
			if spec.showBanner || spec.showSpinner {
				t.Errorf("%s must render without banner or spinner", spec.name)
			}
		case "controls":
			if !spec.showBanner || spec.showSpinner {
				t.Error("controls must show the banner without a spinner")
			}
		case "codify":
			if spec.showBanner || !spec.showSpinner {
				t.Error("codify must keep HCL stdout clean and retain the spinner")
			}
		default:
			if !spec.showBanner || !spec.showSpinner {
				t.Errorf("%s must retain the standard banner and spinner", spec.name)
			}
		}
	}
}

func TestCmdListJSONAndExitCode(t *testing.T) {
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/user/repos":
			return jsonResponse(`[{"full_name":"me/bad","owner":{"login":"me"}},{"full_name":"me/good","owner":{"login":"me"}}]`), nil
		case "/repos/me/good/actions/workflows":
			return jsonResponse(`{"total_count":1,"workflows":[{"id":1,"name":"CI","path":".github/workflows/ci.yml","state":"active"}]}`), nil
		case "/repos/me/bad/actions/workflows":
			return &http.Response{StatusCode: http.StatusInternalServerError, Header: make(http.Header), Body: http.NoBody}, nil
		}
		return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody}, nil
	})})
	o := &opts{jsonOut: true, format: "json", concurrency: 1}
	var err error
	out := captureStdout(t, func() { err = cmdList(context.Background(), client, o) })
	var rows []listRow
	if jerr := json.Unmarshal([]byte(out), &rows); jerr != nil {
		t.Fatalf("list --json stdout is not JSON: %v\n%s", jerr, out)
	}
	if len(rows) != 1 || rows[0].Repo != "me/good" || rows[0].Name != "CI" {
		t.Fatalf("list rows = %+v, want the one readable workflow", rows)
	}
	var code exitError
	if !errors.As(err, &code) || int(code) != 1 {
		t.Fatalf("unreadable repo must exit 1, got %v", err)
	}
}

func TestCmdCodifyPrintsHCL(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /user/repos":                       `[{"full_name":"me/app","owner":{"login":"me"},"private":false,"fork":false,"archived":false}]`,
		"GET /repos/me/app/rulesets":            `[]`,
		"GET /repos/me/app/actions/permissions": `{"enabled":true,"allowed_actions":"all","sha_pinning_required":false}`,
	})
	o := &opts{provider: "github", concurrency: 1}
	var err error
	out := captureStdout(t, func() { err = cmdCodify(context.Background(), client, o) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"terraform {", `resource "github_repository_ruleset" "me_app"`, `owner = "me"`} {
		if !strings.Contains(out, want) {
			t.Errorf("codify output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "to       = github_repository_ruleset.") {
		t.Error("no managed ruleset exists, so no ruleset import block should be emitted")
	}
}

func TestJSONFormatConflict(t *testing.T) {
	o := &opts{provider: "github", jsonOut: true, format: "sarif", staleDays: 180, concurrency: 8}
	normalizeOptions(o)
	if err := validateOptions(o); err == nil || !strings.Contains(err.Error(), "--json conflicts") {
		t.Fatalf("--json with --format sarif: %v, want conflict error", err)
	}
	o = &opts{provider: "github", jsonOut: true, staleDays: 180, concurrency: 8}
	normalizeOptions(o)
	if o.format != "json" {
		t.Fatalf("--json alone: format = %s, want json", o.format)
	}
	if err := validateOptions(o); err != nil {
		t.Fatal(err)
	}
	o = &opts{provider: "github", jsonOut: true, format: "json", staleDays: 180, concurrency: 8}
	normalizeOptions(o)
	if err := validateOptions(o); err != nil {
		t.Fatalf("--json with --format json must be accepted: %v", err)
	}
}

func TestCommandFlagScoping(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		o    *opts
	}{
		{"format outside audit", "list", &opts{formatSet: true, format: "json"}},
		{"exit-code outside audit", "harden", &opts{exitCode: true}},
		{"all outside audit", "harden", &opts{all: true}},
		{"show-identifiers outside audit", "list", &opts{showIdentifiers: true}},
		{"json outside list/status/audit", "harden", &opts{jsonOut: true}},
		{"only outside audit/harden/revert", "list", &opts{only: "secret-scanning"}},
		{"bad --repo slug", "audit", &opts{provider: "github", repo: "notaslug"}},
		{"unknown --only key pre-client", "audit", &opts{provider: "github", only: "bogus-key"}},
		{"repo flag on disable-repo", "disable-repo", &opts{repo: "me/app"}},
	}
	for _, c := range cases {
		args := []string(nil)
		if c.cmd == "disable-repo" {
			args = []string{"me/app"}
		}
		if err := validateCommandInvocation(c.cmd, args, c.o); err == nil {
			t.Errorf("%s: want error, got nil", c.name)
		}
	}
	if err := validateCommandInvocation("audit", nil, &opts{provider: "github", repo: "me/app", only: "secret-scanning"}); err != nil {
		t.Errorf("valid audit invocation rejected: %v", err)
	}
	err := validateCommandInvocation("disable-repo", []string{"me/app", "--dry-run"}, &opts{})
	if err == nil || !strings.Contains(err.Error(), "--dry-run") {
		t.Errorf("flag after positional must name the misplaced flag, got %v", err)
	}
}

// TestMainExitHelper re-runs the test binary as a repo-harden process; only used by TestExitCodePlumbing.
func TestMainExitHelper(t *testing.T) {
	args := os.Getenv("REPO_HARDEN_MAIN_ARGS")
	if args == "" {
		t.Skip("helper for TestExitCodePlumbing")
	}
	os.Args = append([]string{"repo-harden"}, strings.Split(args, " ")...)
	Main()
	os.Exit(0)
}

func TestExitCodePlumbing(t *testing.T) {
	cases := []struct {
		args       string
		wantCode   int
		wantStdout string
	}{
		{"version", 0, "repo-harden"},
		{"help", 0, "Usage:"},
		{"audit -h", 0, "Usage:"},
		{"frobnicate", 2, ""},
		{"audit --bogusflag", 2, ""},
		{"audit --only bogus-key", 2, ""},
		{"audit --json --format sarif", 2, ""},
		{"list --format json", 2, ""},
		{"harden --exit-code", 2, ""},
		{"audit --fail-below 0", 2, ""},
		{"audit --fail-below 150", 2, ""},
		{"audit --provider bitbucket", 2, ""},
	}
	for _, c := range cases {
		cmd := exec.Command(os.Args[0], "-test.run", "TestMainExitHelper")
		cmd.Env = append(os.Environ(),
			"REPO_HARDEN_MAIN_ARGS="+c.args,
			"GITHUB_TOKEN=", "GH_TOKEN=", "NO_COLOR=1")
		out, err := cmd.Output()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("%s: %v", c.args, err)
		}
		if code != c.wantCode {
			t.Errorf("repo-harden %s: exit %d, want %d (stderr: %s)", c.args, code, c.wantCode, exitStderr(ee))
		}
		if c.wantStdout != "" && !strings.Contains(string(out), c.wantStdout) {
			t.Errorf("repo-harden %s: stdout missing %q", c.args, c.wantStdout)
		}
	}
}

func exitStderr(ee *exec.ExitError) string {
	if ee == nil {
		return ""
	}
	return strings.TrimSpace(string(ee.Stderr))
}
