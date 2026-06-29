package repoharden

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-github/v88/github"
)

func TestAuditSARIF(t *testing.T) {
	rows := []auditRow{
		{Control: "secret-scanning", Title: "Secret scanning", Severity: "critical", Status: string(StatusGap), Remediation: "Enable", Repo: "me/app", Detail: "off"},
		{Control: "ok", Status: string(StatusCompliant), Repo: "me/app"}, // excluded
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
	rows := []auditRow{{Control: "x", Status: string(StatusGap), Repo: "me/app"}}
	out := captureStdout(t, func() { _ = renderAudit(rows, 1, &opts{format: "json"}) })
	var got []auditRow
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json output invalid: %v\n%s", err, out)
	}
	if len(got) != 1 || got[0].Control != "x" {
		t.Fatalf("roundtrip mismatch: %+v", got)
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
	var rows []auditRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("audit JSON invalid: %v\n%s", err, out)
	}
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
	// default --format table is what most users see; make sure it renders a mixed
	// set (incl. empty) without panicking and shows the control.
	rows := []auditRow{
		{Control: "secret-scanning", Title: "Secret scanning", Severity: "critical", Status: string(StatusGap), Repo: "me/app", Detail: "off"},
		{Control: "stale-repo", Severity: "low", Status: string(StatusCompliant), Repo: "me/app"},
	}
	out := captureStdout(t, func() { renderAuditTable(rows, 1, &opts{format: "table", color: "never"}) })
	if !strings.Contains(out, "secret-scanning") {
		t.Fatalf("table output missing control:\n%s", out)
	}
	// empty set must not panic
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
