package repoharden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-github/v88/github"
)

func decodeAuditReportOutput(t *testing.T, output string) auditReport {
	t.Helper()
	var report auditReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("audit JSON invalid: %v\n%s", err, output)
	}
	return report
}

func TestAuditSARIF(t *testing.T) {
	rows := []auditRow{
		{Control: "secret-scanning", Title: "Secret scanning", Severity: "critical", Status: string(StatusGap), Remediation: "Enable", Repo: "me/app", Detail: "off"},
		{Control: "ok", Status: string(StatusCompliant), Repo: "me/app"},
	}
	b, err := json.Marshal(auditSARIF(rows))
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Runs) != 1 || len(s.Runs[0].Results) != 1 || s.Runs[0].Results[0].RuleID != "secret-scanning" {
		t.Fatalf("SARIF should carry only the gap result, got %+v", s.Runs)
	}
	if len(s.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(s.Runs[0].Tool.Driver.Rules))
	}
}

func TestRenderAuditJSONRoundTrips(t *testing.T) {
	rows := []auditRow{{Provider: "github", Scope: "repo", Control: "x", Status: string(StatusGap), Repo: "me/app"}}
	out := captureStdout(t, func() {
		_ = renderAudit(rows, 1, &opts{provider: "github", host: "github.com", format: "json"})
	})
	report := decodeAuditReportOutput(t, out)
	if report.Version != auditReportSchemaVersion || report.Kind != auditReportKind {
		t.Fatalf("report envelope = version %d kind %q", report.Version, report.Kind)
	}
	if report.Scope.Provider != "github" || len(report.Scope.Repositories) != 1 || report.Scope.Repositories[0] != "me/app" {
		t.Fatalf("report scope = %+v", report.Scope)
	}
	if len(report.Rows) != 1 || report.Rows[0].Control != "x" {
		t.Fatalf("roundtrip mismatch: %+v", report.Rows)
	}
}

func TestCmdAuditRunsSelectedControlEndToEnd(t *testing.T) {
	client := mockClient(map[string]string{
		"GET /user/repos": `[{"full_name":"me/app","owner":{"login":"me"},"private":false,"fork":false,"archived":false}]`,
	})
	o := &opts{
		provider:    "github",
		host:        "github.com",
		format:      "json",
		only:        "public-exposure",
		orgAudit:    false,
		concurrency: 1,
		staleDays:   180,
	}
	out := captureStdout(t, func() {
		if err := cmdAudit(context.Background(), client, o); err != nil {
			t.Fatal(err)
		}
	})
	rows := decodeAuditReportOutput(t, out).Rows
	if len(rows) != 1 || rows[0].Control != "public-exposure" || rows[0].Status != string(StatusGap) {
		t.Fatalf("audit rows = %+v", rows)
	}
}

func TestRenderAuditMarkdownSmoke(t *testing.T) {
	rows := []auditRow{{Control: "secret-scanning", Title: "Secret scanning", Severity: "critical", Status: string(StatusGap), Repo: "me/app", Detail: "off"}}
	out := captureStdout(t, func() { renderAuditMarkdown(rows, 1) })
	if !strings.Contains(out, "secret-scanning") {
		t.Fatalf("markdown output missing control:\n%s", out)
	}
}

func TestRenderAuditTableSmoke(t *testing.T) {
	rows := []auditRow{
		{Control: "secret-scanning", Title: "Secret scanning", Severity: "critical", Status: string(StatusGap), Repo: "me/app", Detail: "off"},
		{Control: "stale-repo", Severity: "low", Status: string(StatusCompliant), Repo: "me/app"},
	}
	out := captureStdout(t, func() { renderAuditTable(rows, 1, &opts{format: "table", color: "never"}) })
	if !strings.Contains(out, "secret-scanning") {
		t.Fatalf("table output missing control:\n%s", out)
	}
	_ = captureStdout(t, func() { renderAuditTable(nil, 0, &opts{format: "table", color: "never"}) })
}

func TestAuditLessSortsCriticalGapFirst(t *testing.T) {
	critGap := auditRow{Severity: "critical", Status: string(StatusGap)}
	lowOK := auditRow{Severity: "low", Status: string(StatusCompliant)}
	if !auditLess(critGap, lowOK) {
		t.Fatal("critical/gap should sort before low/compliant")
	}
	if auditLess(lowOK, critGap) {
		t.Fatal("sort order is not symmetric")
	}
}

func TestCollectAuditReportsGapAndCompliant(t *testing.T) {
	saved := baseline
	t.Cleanup(func() { baseline = saved })
	baseline = []Control{
		{Key: "always-gap", Title: "x", Detect: func(context.Context, *github.Client, string, string, *github.Repository) DetectResult {
			return DetectResult{Status: StatusGap}
		}},
		{Key: "always-ok", Title: "y", Detect: func(context.Context, *github.Client, string, string, *github.Repository) DetectResult {
			return DetectResult{Status: StatusCompliant}
		}},
	}
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/user/repos" {
			return jsonResponse(`[{"full_name":"me/app","owner":{"login":"me"}}]`), nil
		}
		return &http.Response{StatusCode: 404, Header: make(http.Header), Body: http.NoBody}, nil
	})})

	repos, err := listRepos(context.Background(), client, &opts{})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := collectAudit(context.Background(), client, &opts{concurrency: 1}, repos)
	if err != nil {
		t.Fatal(err)
	}
	var gap, ok int
	for _, r := range rows {
		switch r.Status {
		case string(StatusGap):
			gap++
		case string(StatusCompliant):
			ok++
		}
	}
	if gap != 1 || ok != 1 {
		t.Fatalf("got gap=%d ok=%d, want 1/1 (rows=%+v)", gap, ok, rows)
	}
}

func TestFilterAuditRowsOnlyAndSkip(t *testing.T) {
	rows := []auditRow{
		{Control: "a", Status: string(StatusGap)},
		{Control: "b", Status: string(StatusCompliant)},
		{Control: "c", Status: string(StatusError)},
	}

	only := filterAuditRows(append([]auditRow{}, rows...), &opts{only: "a,c"})
	if len(only) != 2 || only[0].Control != "a" || only[1].Control != "c" {
		t.Fatalf("only filter = %+v, want a/c", only)
	}

	skip := filterAuditRows(append([]auditRow{}, rows...), &opts{skip: "b"})
	if len(skip) != 2 || skip[0].Control != "a" || skip[1].Control != "c" {
		t.Fatalf("skip filter = %+v, want a/c", skip)
	}
}

func TestActionableRows(t *testing.T) {
	rows := []auditRow{
		{Control: "a", Status: string(StatusGap)},
		{Control: "b", Status: string(StatusError)},
		{Control: "c", Status: string(StatusCompliant)},
		{Control: "d", Status: string(StatusSkipped)},
	}
	if got := actionableRows(rows); len(got) != 2 {
		t.Fatalf("got %d rows, want 2 (gap+error only)", len(got))
	}
}

func TestAuditScoreWeightsFindings(t *testing.T) {
	rows := []auditRow{
		{Severity: "high", Status: string(StatusCompliant)},
		{Severity: "high", Status: string(StatusGap)},
		{Severity: "critical", Status: string(StatusSkipped)},
	}
	if got := auditScore(rows); got != 50 {
		t.Fatalf("score = %d, want 50 (skipped controls must not affect score)", got)
	}
	if auditScoreAvailable([]auditRow{{Status: string(StatusSkipped)}}) {
		t.Fatal("all-skipped audit must report score as unavailable")
	}
	if got := auditVerification(rows); got != 50 {
		t.Fatalf("verification = %d, want 50 (the skipped critical row is unverified)", got)
	}
	if !auditHasSkipped(rows) {
		t.Fatal("skipped row was not detected")
	}
	if auditHasSkipped([]auditRow{{Status: string(StatusCompliant)}}) {
		t.Fatal("compliant-only rows must not report skipped checks")
	}
}

func TestValidateAuditSelectionRejectsUnknown(t *testing.T) {
	if err := validateAuditSelection("deploy-keys", ""); err != nil {
		t.Fatalf("known extended control rejected: %v", err)
	}
	if err := validateAuditSelection("not-a-control", ""); err == nil {
		t.Fatal("expected unknown audit control to fail")
	}
}

func TestValidateAuditSelectionRejectsUnsupportedProviderControl(t *testing.T) {
	err := validateAuditSelectionForProvider("gitlab", "code-scanning", "")
	if err == nil || !strings.Contains(err.Error(), "unsupported by provider gitlab") {
		t.Fatalf("unsupported provider control should fail, got %v", err)
	}
	if err := validateAuditSelectionForProvider("gitlab", "branch-protection-full", ""); err != nil {
		t.Fatalf("supported GitLab control rejected: %v", err)
	}
}

func gateOpts(only string) *opts {
	return &opts{
		provider:    "github",
		host:        "github.com",
		format:      "json",
		only:        only,
		orgAudit:    false,
		concurrency: 1,
		staleDays:   180,
	}
}

var gateRoutes = map[string]string{
	"GET /user/repos": `[{"full_name":"me/app","owner":{"login":"me"},"private":false,"fork":false,"archived":false}]`,
}

func runGatedAudit(t *testing.T, routes map[string]string, o *opts) (string, error) {
	t.Helper()
	client := mockClient(routes)
	var err error
	out := captureStdout(t, func() { err = cmdAudit(context.Background(), client, o) })
	return out, err
}

func wantExit1(t *testing.T, name string, err error) {
	t.Helper()
	var code exitError
	if !errors.As(err, &code) || int(code) != 1 {
		t.Errorf("%s: err = %v, want exitError(1)", name, err)
	}
}

func TestCmdAuditGates(t *testing.T) {
	dir := t.TempDir()
	writeBaseline := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	writeScopedBaseline := func(name, status, severity string) string {
		report := newAuditReport([]auditRow{{
			Provider: "github", Scope: "repo", Repo: "me/app", Control: "public-exposure",
			Severity: severity, Status: status,
		}}, 1, &opts{provider: "github", host: "github.com"})
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		return writeBaseline(name, string(data))
	}
	sameGap := writeScopedBaseline("same-gap.json", string(StatusGap), "medium")
	wasCompliant := writeScopedBaseline("was-compliant.json", string(StatusCompliant), "medium")
	legacyGap := writeBaseline("legacy-gap.json",
		`[{"provider":"github","scope":"repo","repo":"me/app","control":"public-exposure","severity":"medium","status":"gap"}]`)

	o := gateOpts("public-exposure")
	o.exitCode = true
	_, err := runGatedAudit(t, gateRoutes, o)
	wantExit1(t, "gap with --exit-code", err)

	o = gateOpts("public-exposure")
	o.exitCode = true
	o.diffBaseline = sameGap
	out, err := runGatedAudit(t, gateRoutes, o)
	if err != nil {
		t.Errorf("known gap with --diff --exit-code: err = %v, want nil", err)
	}
	var report auditReport
	if jerr := json.Unmarshal([]byte(out), &report); jerr != nil || report.Kind != auditReportKind {
		t.Errorf("--diff must keep stdout a pure audit-report JSON envelope: %v\n%s", jerr, out)
	}

	o = gateOpts("public-exposure")
	o.exitCode = true
	o.diffBaseline = legacyGap
	_, err = runGatedAudit(t, gateRoutes, o)
	wantExit1(t, "unscoped legacy baseline with --diff --exit-code", err)

	o = gateOpts("public-exposure")
	o.exitCode = true
	o.diffBaseline = wasCompliant
	_, err = runGatedAudit(t, gateRoutes, o)
	wantExit1(t, "regression with --diff --exit-code", err)

	o = gateOpts("public-exposure")
	o.exitCode = true
	o.diffBaseline = filepath.Join(dir, "missing.json")
	_, err = runGatedAudit(t, gateRoutes, o)
	var ue usageError
	if !errors.As(err, &ue) {
		t.Errorf("missing --diff baseline: err = %v, want usageError", err)
	}

	mismatchedReport := newAuditReport([]auditRow{{
		Provider: "github", Scope: "repo", Repo: "me/app", Control: "public-exposure",
		Severity: "high", Status: string(StatusCompliant),
	}}, 1, &opts{provider: "github", host: "github.example.com"})
	mismatchedJSON, marshalErr := json.Marshal(mismatchedReport)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	mismatchedPath := writeBaseline("other-host.json", string(mismatchedJSON))
	o = gateOpts("public-exposure")
	o.exitCode = true
	o.diffBaseline = mismatchedPath
	out, err = runGatedAudit(t, gateRoutes, o)
	if !errors.As(err, &ue) || !strings.Contains(err.Error(), "host") {
		t.Errorf("cross-host --diff baseline: err = %v, want host-scoped usageError", err)
	}
	if out != "" {
		t.Errorf("scope-mismatched baseline rendered audit output before rejection: %q", out)
	}

	reducedVisibilityReport := newAuditReport([]auditRow{{
		Provider: "github", Scope: "repo", Repo: "me/app", Control: "public-exposure",
		Severity: "high", Status: string(StatusCompliant),
	}}, 2, &opts{provider: "github", host: "github.com"}, []string{"me/app", "me/second"})
	reducedVisibilityJSON, marshalErr := json.Marshal(reducedVisibilityReport)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	reducedVisibilityPath := writeBaseline("more-visible-repositories.json", string(reducedVisibilityJSON))
	o = gateOpts("public-exposure")
	o.exitCode = true
	o.diffBaseline = reducedVisibilityPath
	out, err = runGatedAudit(t, gateRoutes, o)
	if !errors.As(err, &ue) || !strings.Contains(err.Error(), "cannot see baseline repositories") {
		t.Errorf("reduced repository visibility: err = %v, want fail-closed usageError", err)
	}
	if out != "" {
		t.Errorf("reduced-visibility baseline rendered audit output before rejection: %q", out)
	}

	skippedRoutes := map[string]string{
		"GET /user/repos": gateRoutes["GET /user/repos"],
		"GET /repos/me/app/actions/permissions/workflow": `{}`,
	}
	o = gateOpts("token-readonly")
	o.failOnSkipped = true
	_, err = runGatedAudit(t, skippedRoutes, o)
	wantExit1(t, "skipped with --fail-on-skipped", err)

	skippedBaseline := writeScopedBaseline("token-was-compliant.json", string(StatusCompliant), "high")
	reportData, readErr := os.ReadFile(skippedBaseline)
	if readErr != nil {
		t.Fatal(readErr)
	}
	reportData = []byte(strings.ReplaceAll(string(reportData), "public-exposure", "token-readonly"))
	if err := os.WriteFile(skippedBaseline, reportData, 0o600); err != nil {
		t.Fatal(err)
	}
	o = gateOpts("token-readonly")
	o.exitCode = true
	o.diffBaseline = skippedBaseline
	_, err = runGatedAudit(t, skippedRoutes, o)
	wantExit1(t, "compliant becoming skipped with --diff --exit-code", err)

	o = gateOpts("public-exposure")
	o.failBelow = 80
	_, err = runGatedAudit(t, gateRoutes, o)
	wantExit1(t, "score below --fail-below", err)

	compliantRoutes := map[string]string{
		"GET /user/repos": `[{"full_name":"me/app","owner":{"login":"me"},"private":true,"fork":false,"archived":false}]`,
	}
	o = gateOpts("public-exposure")
	o.exitCode = true
	o.failBelow = 80
	_, err = runGatedAudit(t, compliantRoutes, o)
	if err != nil {
		t.Errorf("compliant repo with gates: err = %v, want nil", err)
	}

	o = gateOpts("token-readonly")
	o.failBelow = 80
	_, err = runGatedAudit(t, skippedRoutes, o)
	wantExit1(t, "unavailable score with --fail-below", err)
}

func TestCmdAuditExitCodeIgnoresInfoGaps(t *testing.T) {
	routes := map[string]string{
		"GET /user/repos":            gateRoutes["GET /user/repos"],
		"GET /repos/me/app/rulesets": `[]`,
	}
	o := gateOpts("merge-queue")
	o.exitCode = true
	out, err := runGatedAudit(t, routes, o)
	if err != nil {
		t.Fatalf("info-only gaps must not trip --exit-code: err = %v\n%s", err, out)
	}
	if !auditHasFindings([]auditRow{{Status: string(StatusError), Severity: "info"}}) {
		t.Error("info-severity errors must still count as findings")
	}
	if auditHasFindings([]auditRow{{Status: string(StatusGap), Severity: "info"}}) {
		t.Error("info-severity gaps must not count as findings")
	}
}

func TestCmdAuditDiffIgnoresNewInfoGap(t *testing.T) {
	dir := t.TempDir()
	baseline := filepath.Join(dir, "baseline.json")
	report := newAuditReport([]auditRow{{
		Provider: "github", Scope: "repo", Repo: "me/app", Control: "merge-queue",
		Severity: "info", Status: string(StatusCompliant),
	}}, 1, &opts{provider: "github", host: "github.com"})
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(baseline, data, 0o600); err != nil {
		t.Fatal(err)
	}
	routes := map[string]string{
		"GET /user/repos":            gateRoutes["GET /user/repos"],
		"GET /repos/me/app/rulesets": `[]`,
	}
	o := gateOpts("merge-queue")
	o.exitCode = true
	o.diffBaseline = baseline
	if _, err := runGatedAudit(t, routes, o); err != nil {
		t.Fatalf("new info-only gap must not trip diff --exit-code: %v", err)
	}
}

func TestCmdAuditInterruptedExitsNonZero(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodGet && req.URL.Path == "/repos/me/app" {
			return jsonResponse(`{"full_name":"me/app","owner":{"login":"me"},"private":false,"fork":false,"archived":false}`), nil
		}
		cancel()
		return nil, context.Canceled
	})})
	o := gateOpts("dependabot-alerts")
	o.repo = "me/app"
	var err error
	out := captureStdout(t, func() { err = cmdAudit(ctx, client, o) })
	wantExit1(t, "interrupted audit", err)
	var report auditReport
	if jerr := json.Unmarshal([]byte(out), &report); jerr != nil || len(report.Rows) == 0 {
		t.Fatalf("interrupted audit must still render partial rows: %v\n%s", jerr, out)
	}
	if report.Rows[0].Status != string(StatusError) {
		t.Errorf("canceled check status = %s, want error", report.Rows[0].Status)
	}
}

func TestRenderAuditJSONPinsFieldNames(t *testing.T) {
	rows := []auditRow{{
		Provider: "github", Scope: "repo", Repo: "me/app",
		Control: "x", Severity: "high", Status: string(StatusGap), Detail: "d",
	}}
	out := captureStdout(t, func() { _ = renderAudit(rows, 1, &opts{format: "json"}) })
	for _, want := range []string{
		`"version":1`, `"kind":"repo-harden-audit"`, `"scope":`, `"rows":`,
		`"provider":"github"`, `"host":"github.com"`, `"scope":"repo"`, `"repo":"me/app"`,
		`"control":"x"`, `"severity":"high"`, `"status":"gap"`, `"detail":"d"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("json output missing %s (documented consumer contract):\n%s", want, out)
		}
	}
}

func TestRenderAuditMarkdownPinsHeader(t *testing.T) {
	out := captureStdout(t, func() {
		renderAuditMarkdown([]auditRow{{Control: "x", Status: string(StatusGap), Repo: "me/app"}}, 1)
	})
	if !strings.Contains(out, "| Severity | Status | Scope | Target | Control | Detail | Refs |") {
		t.Fatalf("markdown table header changed:\n%s", out)
	}
}
