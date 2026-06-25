package repoharden

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/go-github/v88/github"
)

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

func TestAuditScoreWeightsFindings(t *testing.T) {
	rows := []auditRow{
		{Severity: "high", Status: string(StatusCompliant)},
		{Severity: "high", Status: string(StatusGap)},
	}
	if got := auditScore(rows); got != 50 {
		t.Fatalf("score = %d, want 50", got)
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
