package repoharden

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-github/v88/github"
)

func testCodifyRepo(name, tfName, ownerTFName string, rulesetID int64) codifyRepo {
	return codifyRepo{
		Name: name, TFName: tfName, OwnerTFName: ownerTFName, RulesetID: rulesetID,
		ActionsEnabled: true, ActionsPolicy: "selected", ActionsSHAPinning: true,
		ActionsSelected: true, ActionsGithubOwned: true, ActionsVerified: true,
	}
}

func managedRulesetFixture(id int64, extraRule string) string {
	return fmt.Sprintf(`{"id":%d,"name":%q,"target":"branch","enforcement":"active","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"rules":[{"type":"deletion"},{"type":"non_fast_forward"},{"type":"required_linear_history"},{"type":"pull_request","parameters":{"required_approving_review_count":0,"required_review_thread_resolution":true}}%s]}`, id, controlRulesetName, extraRule)
}

func TestTFName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"repo-harden", "repo-harden"},
		{"my.repo", "my_repo"},
		{"9lives", "r_9lives"},
		{"", "r_"},
		{"Ok_Name-1", "Ok_Name-1"},
		{"æøå", "___"},
	}
	for _, c := range cases {
		if got := tfName(c.in); got != c.want {
			t.Errorf("tfName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCodifyHCLActionsDisabledRepo(t *testing.T) {
	out, err := codifyHCL(codifyData{
		Version: "test", RulesetName: controlRulesetName,
		Owners: []codifyOwner{{Login: "me", TFName: "me", Repos: []codifyRepo{{
			Name: "off", TFName: "me_off", OwnerTFName: "me",
		}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "resource \"github_actions_repository_permissions\" \"me_off\" {\n  provider   = github.me\n  repository = \"off\"\n  enabled    = false\n}"
	if !strings.Contains(out, want) {
		t.Fatalf("disabled-Actions resource block missing in:\n%s", out)
	}
	if strings.Contains(out, `allowed_actions      = ""`) {
		t.Fatal("a disabled repo must not emit an empty allowed_actions")
	}
}

func TestReadCodifyActionsPolicyDisabledIsValid(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /repos/me/off/actions/permissions": `{"enabled":false}`,
	})
	policy, err := readCodifyActionsPolicy(context.Background(), client, "me", "off")
	if err != nil {
		t.Fatalf("Actions disabled must be a codifiable state, got error: %v", err)
	}
	if policy.enabled {
		t.Fatal("policy.enabled = true, want false")
	}
}

func TestReadCodifyActionsPolicySelectedMirrorsApplyGithubOwned(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /repos/me/app/actions/permissions":                  `{"enabled":true,"allowed_actions":"selected","sha_pinning_required":false}`,
		"GET /repos/me/app/actions/permissions/selected-actions": `{"github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":["octo/tool@` + strings.Repeat("a", 40) + `"]}`,
	})
	policy, err := readCodifyActionsPolicy(context.Background(), client, "me", "app")
	if err != nil {
		t.Fatal(err)
	}
	if !policy.githubOwned {
		t.Fatal("selected policy must mirror Apply and force github_owned_allowed = true")
	}
}

func TestCodifyHCL(t *testing.T) {
	out, err := codifyHCL(codifyData{
		Version:     "test",
		RulesetName: controlRulesetName,
		Owners: []codifyOwner{
			{Login: "acme", TFName: "acme", Repos: []codifyRepo{
				testCodifyRepo("lib", "acme_lib", "acme", 0),
			}},
			{Login: "me", TFName: "me", Repos: []codifyRepo{
				testCodifyRepo("app", "me_app", "me", 42),
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`source  = "integrations/github"`,
		"provider \"github\" {\n  alias = \"acme\"\n  owner = \"acme\"\n}",
		`resource "github_actions_repository_permissions" "me_app"`,
		"patterns_allowed     = []",
		`resource "github_repository_dependabot_security_updates" "acme_lib"`,
		`resource "github_repository_vulnerability_alerts" "acme_lib"`,
		`name        = "` + controlRulesetName + `"`,
		`include = ["~DEFAULT_BRANCH"]`,
		"required_review_thread_resolution = true",
		`id       = "app:42"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("codify output missing %q", want)
		}
	}
	// only me/app has a managed ruleset, so exactly one ruleset import block
	if got := strings.Count(out, "to       = github_repository_ruleset."); got != 1 {
		t.Errorf("ruleset import blocks = %d, want 1\n%s", got, out)
	}
	if got := strings.Count(out, "to       = github_actions_repository_permissions."); got != 2 {
		t.Errorf("actions-permissions import blocks = %d, want 2", got)
	}
	if got := strings.Count(out, "to       = github_repository_vulnerability_alerts."); got != 2 {
		t.Errorf("vulnerability-alert import blocks = %d, want 2", got)
	}
}

func TestBuildCodifyData(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /repos/me/app/rulesets":                             `[{"id":42,"name":"` + controlRulesetName + `","target":"branch","enforcement":"active"}]`,
		"GET /repos/me/app/rulesets/42":                          managedRulesetFixture(42, ""),
		"GET /repos/me/app/actions/permissions":                  `{"enabled":true,"allowed_actions":"selected","sha_pinning_required":true}`,
		"GET /repos/me/app/actions/permissions/selected-actions": `{"github_owned_allowed":true,"verified_allowed":false,"patterns_allowed":["goreleaser/goreleaser-action@*","hashicorp/setup-terraform@*"]}`,
		"GET /repos/acme/lib/rulesets":                           `[]`,
		"GET /repos/acme/lib/actions/permissions":                `{"enabled":true,"allowed_actions":"all","sha_pinning_required":false}`,
	})
	repos := []*github.Repository{
		{FullName: github.Ptr("me/app")},
		{FullName: github.Ptr("acme/lib")},
	}
	data, err := buildCodifyData(context.Background(), client, &opts{concurrency: 2}, repos)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Owners) != 2 || data.Owners[0].Login != "acme" || data.Owners[1].Login != "me" {
		t.Fatalf("owners = %+v, want sorted [acme me]", data.Owners)
	}
	if data.Owners[1].Repos[0].RulesetID != 42 {
		t.Errorf("me/app RulesetID = %d, want 42 (managed ruleset exists)", data.Owners[1].Repos[0].RulesetID)
	}
	if data.Owners[0].Repos[0].RulesetID != 0 {
		t.Errorf("acme/lib RulesetID = %d, want 0 (no managed ruleset)", data.Owners[0].Repos[0].RulesetID)
	}
	app := data.Owners[1].Repos[0]
	if app.ActionsVerified || !app.ActionsSHAPinning || strings.Join(app.ActionsPatterns, ",") != "goreleaser/goreleaser-action@*,hashicorp/setup-terraform@*" {
		t.Errorf("narrow live Actions policy was not preserved: %+v", app)
	}
	lib := data.Owners[0].Repos[0]
	if lib.ActionsPolicy != "selected" || !lib.ActionsVerified || !lib.ActionsSHAPinning {
		t.Errorf("open Actions policy was not tightened to baseline: %+v", lib)
	}
}

// TestCodifyTemplateMirrorsBaseline ties the template values to the exact spec the harden Apply funcs write.
func TestCodifyTemplateMirrorsBaseline(t *testing.T) {
	spec := managedRulesetSpec("me", "app")
	if !managedRulesetValid(&spec, "main") {
		t.Fatal("managedRulesetSpec must satisfy the branch-protection Detect validator")
	}
	if !rulesetMatchesManagedSpec(&spec) {
		t.Fatal("managedRulesetSpec must satisfy the revert drift matcher")
	}
	out, err := codifyHCL(codifyData{
		Version:     "test",
		RulesetName: controlRulesetName,
		Owners: []codifyOwner{{Login: "me", TFName: "me", Repos: []codifyRepo{
			testCodifyRepo("app", "me_app", "me", 0),
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// every value the template hardcodes must equal what Apply writes (controls.go)
	for _, want := range []string{
		`allowed_actions      = "selected"`,
		"sha_pinning_required = true",
		"github_owned_allowed = true",
		"verified_allowed     = true",
		"patterns_allowed     = []",
		"enabled              = true",
		`resource "github_repository_vulnerability_alerts"`,
		`name        = "` + controlRulesetName + `"`,
		`target      = "branch"`,
		`enforcement = "active"`,
		`include = ["~DEFAULT_BRANCH"]`,
		"exclude = []",
		"deletion                = true",
		"non_fast_forward        = true",
		"required_linear_history = true",
		"required_approving_review_count   = 0",
		"required_review_thread_resolution = true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("template no longer mirrors the baseline Apply value %q", want)
		}
	}
}

func TestBuildCodifyDataFailsClosedWithoutRulesetVisibility(t *testing.T) {
	client := mockClient(map[string]string{})
	repos := []*github.Repository{{FullName: github.Ptr("me/app")}}
	if _, err := buildCodifyData(context.Background(), client, &opts{concurrency: 1}, repos); err == nil {
		t.Fatal("codify must not guess that a ruleset is absent when the endpoint is unavailable")
	}
}

func TestBuildCodifyDataRefusesUnsafeImports(t *testing.T) {
	repos := []*github.Repository{{FullName: github.Ptr("me/app")}}
	t.Run("same-name stronger ruleset", func(t *testing.T) {
		client := mockClient(map[string]string{
			"GET /repos/me/app/rulesets":    `[{"id":42,"name":"` + controlRulesetName + `","target":"branch","enforcement":"active"}]`,
			"GET /repos/me/app/rulesets/42": managedRulesetFixture(42, `,{"type":"required_signatures"}`),
		})
		if _, err := buildCodifyData(context.Background(), client, &opts{concurrency: 1}, repos); err == nil || !strings.Contains(err.Error(), "would overwrite") {
			t.Fatalf("error=%v, want refusal to overwrite a stronger ruleset", err)
		}
	})
	t.Run("broad Actions pattern", func(t *testing.T) {
		client := mockClient(map[string]string{
			"GET /repos/me/app/rulesets":                             `[]`,
			"GET /repos/me/app/actions/permissions":                  `{"enabled":true,"allowed_actions":"selected","sha_pinning_required":true}`,
			"GET /repos/me/app/actions/permissions/selected-actions": `{"github_owned_allowed":true,"verified_allowed":false,"patterns_allowed":["acme/*@*"]}`,
		})
		if _, err := buildCodifyData(context.Background(), client, &opts{concurrency: 1}, repos); err == nil || !strings.Contains(err.Error(), "broad or malformed") {
			t.Fatalf("error=%v, want refusal to codify a broad Actions pattern", err)
		}
	})
}

func TestHCLEscape(t *testing.T) {
	cases := []struct{ in, want string }{
		{`plain`, `plain`},
		{`a"b`, `a\"b`},
		{`a\b`, `a\\b`},
		{`${injected}`, `$${injected}`},
		{`%{ directive }`, `%%{ directive }`},
	}
	for _, c := range cases {
		if got := hclEscape(c.in); got != c.want {
			t.Errorf("hclEscape(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	out, err := codifyHCL(codifyData{
		Version:     "test",
		RulesetName: controlRulesetName,
		Owners: []codifyOwner{{Login: `we"ird`, TFName: "we_ird", Repos: []codifyRepo{
			testCodifyRepo("app", "we_ird_app", "we_ird", 0),
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `owner = "we\"ird"`) {
		t.Fatalf("owner value not HCL-escaped:\n%s", out)
	}
}

func TestBuildCodifyDataUniquesCollidingNames(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /repos/me/a.b/rulesets":            `[]`,
		"GET /repos/me/a.b/actions/permissions": `{"enabled":true,"allowed_actions":"all"}`,
		"GET /repos/me/a_b/rulesets":            `[]`,
		"GET /repos/me/a_b/actions/permissions": `{"enabled":true,"allowed_actions":"all"}`,
	})
	repos := []*github.Repository{
		{FullName: github.Ptr("me/a.b")},
		{FullName: github.Ptr("me/a_b")},
	}
	data, err := buildCodifyData(context.Background(), client, &opts{concurrency: 2}, repos)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Owners) != 1 || len(data.Owners[0].Repos) != 2 {
		t.Fatalf("data = %+v", data)
	}
	first, second := data.Owners[0].Repos[0].TFName, data.Owners[0].Repos[1].TFName
	if first == second {
		t.Fatalf("colliding sanitized names must be uniqued, both are %q", first)
	}
	if first != "me_a_b" || second != "me_a_b_2" {
		t.Errorf("uniqued names = %q, %q, want me_a_b and me_a_b_2", first, second)
	}
}

func TestCodifyTerraformValidate(t *testing.T) {
	if os.Getenv("REPO_HARDEN_TERRAFORM_TEST") != "1" {
		t.Skip("set REPO_HARDEN_TERRAFORM_TEST=1 to run Terraform validation")
	}
	terraform, err := exec.LookPath("terraform")
	if err != nil {
		t.Fatal("Terraform validation requested but terraform is not installed")
	}
	out, err := codifyHCL(codifyData{
		Version:     "test",
		RulesetName: controlRulesetName,
		Owners: []codifyOwner{{Login: "example", TFName: "example", Repos: []codifyRepo{
			testCodifyRepo("app", "example_app", "example", 42),
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"fmt", "-check", "-no-color", "main.tf"},
		{"init", "-backend=false", "-input=false", "-no-color"},
		{"validate", "-no-color"},
	} {
		cmd := exec.Command(terraform, args...)
		cmd.Dir = dir
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("terraform %s: %v\n%s", strings.Join(args, " "), err, output)
		}
	}
}
