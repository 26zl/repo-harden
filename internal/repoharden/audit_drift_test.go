package repoharden

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditDrift(t *testing.T) {
	prev := []auditRow{
		{Repo: "me/app", Control: "secret-scanning", Status: string(StatusCompliant)},
		{Repo: "me/app", Control: "branch-protection", Status: string(StatusGap)},
		{Repo: "me/app", Control: "code-scanning", Status: string(StatusGap)},
		{Repo: "me/app", Control: "webhooks", Status: string(StatusSkipped)},
		{Repo: "me/app", Control: "releases", Status: string(StatusGap)},
	}
	current := []auditRow{
		{Repo: "me/app", Control: "secret-scanning", Status: string(StatusGap)},     // compliant -> gap: regression
		{Repo: "me/app", Control: "branch-protection", Status: string(StatusGap)},   // gap -> gap: no drift
		{Repo: "me/app", Control: "code-scanning", Status: string(StatusCompliant)}, // gap -> compliant: improvement
		{Repo: "me/app", Control: "webhooks", Status: string(StatusError)},          // skipped -> error: regression
		{Repo: "me/app", Control: "workflow-injection", Status: string(StatusGap)},  // new finding: regression
		{Repo: "me/app", Control: "releases", Status: string(StatusSkipped)},        // gap -> skipped: unverifiable regression
		{Repo: "me/other", Control: "stale-repo", Status: string(StatusCompliant)},  // new compliant: no drift
	}
	regressions, improvements := auditDrift(prev, current)
	if len(regressions) != 4 {
		t.Fatalf("regressions = %+v, want 4", regressions)
	}
	wantRegs := []string{"releases", "secret-scanning", "webhooks", "workflow-injection"}
	for i, want := range wantRegs {
		if regressions[i].Control != want {
			t.Errorf("regression[%d] = %s, want %s", i, regressions[i].Control, want)
		}
	}
	if regressions[3].From != "absent" {
		t.Errorf("new finding From = %q, want absent", regressions[3].From)
	}
	if len(improvements) != 1 || improvements[0].Control != "code-scanning" {
		t.Fatalf("improvements = %+v, want only code-scanning", improvements)
	}
}

func TestAuditDriftFailsClosedWhenVerificationIsLost(t *testing.T) {
	for _, prior := range []ControlStatus{StatusCompliant, StatusGap, StatusError} {
		prev := []auditRow{{Provider: "github", Repo: "me/app", Control: "x", Severity: "high", Status: string(prior)}}
		current := []auditRow{{Provider: "github", Repo: "me/app", Control: "x", Severity: "high", Status: string(StatusSkipped)}}
		regressions, improvements := auditDrift(prev, current)
		if len(regressions) != 1 || regressions[0].From != string(prior) || regressions[0].To != string(StatusSkipped) {
			t.Errorf("%s -> skipped: regressions=%+v", prior, regressions)
		}
		if len(improvements) != 0 {
			t.Errorf("%s -> skipped must not improve: %+v", prior, improvements)
		}
	}
}

func TestIndexAuditResultsKeepsWorstStatus(t *testing.T) {
	rows := []auditRow{
		{Provider: "github", Repo: "authenticated-token", Control: "token-scopes", Status: string(StatusCompliant)},
		{Provider: "github", Repo: "authenticated-token", Control: "token-scopes", Status: string(StatusGap)},
	}
	idx := indexAuditResults(rows)
	if idx["github\x00authenticated-token\x00token-scopes"].Status != string(StatusGap) {
		t.Fatalf("duplicate key must keep the worst status, got %q", idx["github\x00authenticated-token\x00token-scopes"].Status)
	}
}

func TestAuditDriftKeysByProvider(t *testing.T) {
	prev := []auditRow{{Provider: "gitlab", Repo: "me/app", Control: "signed-commits", Status: string(StatusCompliant)}}
	current := []auditRow{{Provider: "github", Repo: "me/app", Control: "signed-commits", Status: string(StatusGap)}}
	regressions, improvements := auditDrift(prev, current)
	if len(regressions) != 2 {
		t.Fatalf("cross-provider drift must include the new gap and missing prior provider: %+v", regressions)
	}
	missing := false
	for _, regression := range regressions {
		missing = missing || regression.To == driftStatusMissing
	}
	if !missing {
		t.Fatalf("cross-provider drift did not fail closed on missing provider: %+v", regressions)
	}
	if len(improvements) != 0 {
		t.Fatalf("cross-provider improvements = %+v, want none", improvements)
	}
	if !driftProvidersDisjoint(prev, current) {
		t.Error("disjoint providers must be reported")
	}
	if driftProvidersDisjoint(current, current) {
		t.Error("same provider must not be reported as disjoint")
	}
	if driftProvidersDisjoint([]auditRow{{Repo: "a", Control: "c", Status: "gap"}}, current) {
		t.Error("baseline rows without provider must not be reported as disjoint")
	}
}

func TestRenderAuditDrift(t *testing.T) {
	out := captureStdout(t, func() {
		renderAuditDrift(os.Stdout,
			[]driftLine{{Repo: "me/app", Control: "webhooks", From: "compliant", To: "gap"}},
			[]driftLine{{Repo: "me/app", Control: "releases", From: "gap", To: "compliant"}},
			&opts{color: "never"})
	})
	for _, want := range []string{"1 regression(s), 1 improvement(s)", "me/app webhooks: compliant -> gap", "me/app releases: gap -> compliant"} {
		if !strings.Contains(out, want) {
			t.Errorf("drift output missing %q in:\n%s", want, out)
		}
	}
}

func TestLoadAuditBaselineRows(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "audit.json")
	if err := os.WriteFile(good, []byte(`[{"repo":"me/app","control":"webhooks","status":"gap"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	baseline, err := loadAuditBaseline(good)
	rows := baseline.Rows
	if err != nil || len(rows) != 1 || rows[0].Control != "webhooks" {
		t.Fatalf("loadAuditBaseline = %+v, %v", rows, err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAuditBaseline(bad); err == nil || !strings.Contains(err.Error(), "expected audit --format json") {
		t.Fatalf("garbage baseline: got %v, want parse error", err)
	}
	if _, err := loadAuditBaseline(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing baseline file must error")
	}
	badScope := filepath.Join(dir, "bad-scope.json")
	if err := os.WriteFile(badScope, []byte(`[{"repo":"me/app","control":"webhooks","scope":"global","status":"gap"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAuditBaseline(badScope); err == nil || !strings.Contains(err.Error(), "invalid scope") {
		t.Fatalf("unknown row scope must be rejected, got %v", err)
	}

	reportPath := filepath.Join(dir, "report.json")
	report := newAuditReport([]auditRow{{
		Provider: "github", Scope: "repo", Repo: "me/app", Control: "webhooks", Status: string(StatusGap),
	}}, 1, &opts{provider: "github", host: "github.com"})
	reportJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, reportJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	versioned, err := loadAuditBaseline(reportPath)
	rows = versioned.Rows
	if err != nil || len(rows) != 1 || rows[0].Provider != "github" {
		t.Fatalf("load versioned report = %+v, %v", rows, err)
	}

	unsupported := strings.Replace(string(reportJSON), `"version":1`, `"version":99`, 1)
	if err := os.WriteFile(reportPath, []byte(unsupported), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAuditBaseline(reportPath); err == nil || !strings.Contains(err.Error(), "unsupported audit report version") {
		t.Fatalf("unsupported report version = %v", err)
	}
}

func TestPublishedAuditReportSchema(t *testing.T) {
	schemaBytes, err := os.ReadFile(filepath.Join("..", "..", "audit-report.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Schema     string                     `json:"$schema"`
		Properties map[string]json.RawMessage `json:"properties"`
		Defs       map[string]struct {
			Properties map[string]struct {
				Enum []string `json:"enum"`
			} `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatalf("published audit schema is not JSON: %v", err)
	}
	if schema.Schema == "" || schema.Properties["version"] == nil || schema.Properties["scope"] == nil || schema.Properties["rows"] == nil {
		t.Fatalf("published audit schema is missing envelope contracts: %+v", schema)
	}
	if got := strings.Join(schema.Defs["auditRow"].Properties["scope"].Enum, ","); got != "repo,org,token" {
		t.Fatalf("published row scope enum = %q, want repo,org,token", got)
	}
}

func TestLoadAuditBaselineEnforcesPublishedSchemaConstraints(t *testing.T) {
	base := newAuditReport([]auditRow{{
		Provider: "github", Scope: "repo", Repo: "me/app", Control: "webhooks",
		Severity: "high", Status: string(StatusCompliant), Refs: []string{"CIS-SSC:1 Source Code"},
	}}, 1, &opts{provider: "github", host: "github.com"})
	cases := []struct {
		name, want string
		mutate     func(*auditReport)
	}{
		{"invalid severity", "invalid severity", func(report *auditReport) { report.Rows[0].Severity = "HIGH" }},
		{"duplicate refs", "duplicate", func(report *auditReport) { report.Rows[0].Refs = []string{"x", "x"} }},
		{"duplicate controls", "duplicate", func(report *auditReport) {
			report.Scope.Controls = append(report.Scope.Controls, report.Scope.Controls[0])
		}},
		{"duplicate repositories", "duplicate", func(report *auditReport) {
			report.Scope.Repositories = append(report.Scope.Repositories, report.Scope.Repositories[0])
		}},
		{"missing selection field", "every boolean selection parameter", func(report *auditReport) { report.Scope.Selection.IncludeForks = nil }},
		{"invalid stale threshold", "stale_days", func(report *auditReport) { report.Scope.Selection.StaleDays = 0 }},
		{"repository count mismatch", "full scope.repositories universe", func(report *auditReport) { report.RepositoryCount++ }},
		{"row outside repository universe", "outside scope.repositories", func(report *auditReport) { report.Scope.Repositories = []string{"me/other"} }},
		{"unsupported provider", "supported lowercase provider", func(report *auditReport) { report.Scope.Provider = "GITHUB" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := base
			report.Scope.Controls = append([]string(nil), base.Scope.Controls...)
			report.Scope.Repositories = append([]string(nil), base.Scope.Repositories...)
			report.Rows = append([]auditRow(nil), base.Rows...)
			report.Rows[0].Refs = append([]string(nil), base.Rows[0].Refs...)
			tc.mutate(&report)
			data, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "report.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadAuditBaseline(path); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want schema-contract rejection containing %q", err, tc.want)
			}
		})
	}
}

func TestLoadAuditBaselineRetainsUniverseForNonRepositoryRows(t *testing.T) {
	report := newAuditReport([]auditRow{{
		Provider: "github", Scope: "token", Repo: "authenticated-token", Control: "token-readonly",
		Severity: "high", Status: string(StatusCompliant),
	}}, 2, &opts{provider: "github", host: "github.com", staleDays: 180}, []string{"me/a", "me/b"})
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	baseline, err := loadAuditBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Scope == nil || !sameStringSet(baseline.Scope.Repositories, []string{"me/a", "me/b"}) || baseline.RepositoryCount != 2 {
		t.Fatalf("repository universe was not retained: %+v", baseline)
	}
}

func TestValidateAuditDiffScope(t *testing.T) {
	selection := newAuditReport(nil, 0, &opts{provider: "github", host: "github.com", staleDays: 180}).Scope.Selection
	baseline := auditReportScope{Provider: "github", Host: "GITHUB.COM/", Owner: "Example", Selection: selection}
	current := auditReportScope{Provider: "github", Host: "https://github.com", Owner: "example", Selection: selection}
	if err := validateAuditDiffScope(baseline, current, 3, 3); err != nil {
		t.Fatalf("equivalent normalized scope rejected: %v", err)
	}
	for name, changed := range map[string]auditReportScope{
		"provider": {Provider: "gitlab", Host: "github.com", Owner: "example", Selection: selection},
		"host":     {Provider: "github", Host: "github.example.com", Owner: "example", Selection: selection},
		"owner":    {Provider: "github", Host: "github.com", Owner: "other", Selection: selection},
	} {
		if err := validateAuditDiffScope(baseline, changed, 3, 3); err == nil {
			t.Errorf("%s mismatch must be rejected", name)
		}
	}
	if err := validateAuditDiffScope(baseline, current, 3, 2); err == nil || !strings.Contains(err.Error(), "fewer than the baseline") {
		t.Fatalf("reduced repository visibility must be rejected, got %v", err)
	}
	if err := validateAuditDiffScope(baseline, current, 3, 4); err != nil {
		t.Fatalf("newly visible repositories must not invalidate the baseline: %v", err)
	}
	changedSelection := selection
	changedSelection.StaleDays = 36500
	current.Selection = changedSelection
	if err := validateAuditDiffScope(baseline, current, 3, 3); err == nil || !strings.Contains(err.Error(), "selection parameters") {
		t.Fatalf("changed audit semantics must invalidate the baseline, got %v", err)
	}
	baseline.Repositories = []string{"me/a"}
	baseline.Controls = []string{"webhooks"}
	current = auditReportScope{
		Provider: "github", Host: "github.com", Owner: "example", Selection: selection,
		Repositories: []string{"me/b"}, Controls: []string{"webhooks"},
	}
	if err := validateAuditDiffScope(baseline, current, 1, 1); err == nil || !strings.Contains(err.Error(), "cannot see baseline repositories") {
		t.Fatalf("same-count repository substitution must fail closed, got %v", err)
	}
	current.Repositories = []string{"me/a", "me/b"}
	current.Controls = []string{"other-control"}
	if err := validateAuditDiffScope(baseline, current, 1, 2); err == nil || !strings.Contains(err.Error(), "omitted baseline controls") {
		t.Fatalf("a reduced control universe must fail closed, got %v", err)
	}
}

func TestAuditDriftFailsClosedOnMissingBaselineRows(t *testing.T) {
	prev := []auditRow{
		{Provider: "github", Repo: "me/app", Control: "secret-scanning", Status: string(StatusCompliant)},
		{Provider: "github", Repo: "me/app", Control: "branch-protection", Status: string(StatusGap), Severity: "high"},
	}
	current := []auditRow{
		{Provider: "github", Repo: "me/app", Control: "secret-scanning", Status: string(StatusCompliant)},
	}
	regressions, _ := auditDrift(prev, current)
	if len(regressions) != 1 || regressions[0].Control != "branch-protection" || regressions[0].To != driftStatusMissing {
		t.Fatalf("missing control must be a regression: %+v", regressions)
	}
}

func TestAuditBadge(t *testing.T) {
	badge := auditBadge([]auditRow{{Severity: "high", Status: string(StatusGap)}})
	if badge["message"] != "0/100" || badge["color"] != "red" {
		t.Fatalf("all-gaps badge = %v, want 0/100 red", badge)
	}
	badge = auditBadge([]auditRow{
		{Severity: "high", Status: string(StatusGap)},
		{Severity: "high", Status: string(StatusCompliant)},
	})
	if badge["message"] != "50/100" || badge["color"] != "yellow" {
		t.Fatalf("half badge = %v, want 50/100 yellow", badge)
	}
	badge = auditBadge([]auditRow{{Severity: "high", Status: string(StatusCompliant)}})
	if badge["message"] != "100/100" || badge["color"] != "brightgreen" {
		t.Fatalf("clean badge = %v, want 100/100 brightgreen", badge)
	}
	badge = auditBadge([]auditRow{{Severity: "high", Status: string(StatusSkipped)}})
	if badge["message"] != "unknown" || badge["color"] != "lightgrey" {
		t.Fatalf("unscored badge = %v, want unknown lightgrey", badge)
	}
}

func TestValidateNewAuditFlags(t *testing.T) {
	base := func() *opts {
		return &opts{provider: "github", format: "table", staleDays: 180, concurrency: 8}
	}
	o := base()
	o.failBelow = 101
	if err := validateOptions(o); err == nil {
		t.Error("--fail-below 101 must be rejected")
	}
	o = base()
	o.failBelow = -1
	if err := validateOptions(o); err == nil {
		t.Error("--fail-below -1 must be rejected")
	}
	o = base()
	o.failBelowSet = true
	if err := validateOptions(o); err == nil {
		t.Error("explicit --fail-below 0 must be rejected")
	}
	o = base()
	o.failBelow = 80
	o.format = "badge"
	if err := validateOptions(o); err != nil {
		t.Errorf("--fail-below 80 with --format badge: %v", err)
	}
	if err := validateCommandInvocation("list", nil, &opts{failBelow: 80}); err == nil {
		t.Error("--fail-below outside audit must be rejected")
	}
	if err := validateCommandInvocation("harden", nil, &opts{diffBaseline: "x.json"}); err == nil {
		t.Error("--diff outside audit must be rejected")
	}
	if err := validateCommandInvocation("audit", nil, &opts{failBelow: 80, diffBaseline: "x.json"}); err != nil {
		t.Errorf("audit with --fail-below/--diff: %v", err)
	}
}
