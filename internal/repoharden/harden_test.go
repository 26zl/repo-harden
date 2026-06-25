package repoharden

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/google/go-github/v88/github"
)

func TestRecorderUpdatesPriorOnReharden(t *testing.T) {
	path := filepath.Join(t.TempDir(), "harden.json")
	r := newHardenRecorder(path, nil)
	if _, err := r.record(HardenEntry{Repo: "me/app", Control: "token-readonly", Prior: "write"}); err != nil {
		t.Fatal(err)
	}
	// re-record the same control with a new prior
	if _, err := r.record(HardenEntry{Repo: "me/app", Control: "token-readonly", Prior: "fresh-prior"}); err != nil {
		t.Fatal(err)
	}
	got, err := loadHardenState(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 deduped entry, got %d", len(got))
	}
	if got[0].Prior != "fresh-prior" {
		t.Fatalf("prior not refreshed on re-harden: got %q, want fresh-prior", got[0].Prior)
	}
}

func TestScopeEntries(t *testing.T) {
	entries := []HardenEntry{
		{Repo: "me/a", Control: "branch-protection"},
		{Repo: "me/a", Control: "dependabot-alerts"},
		{Repo: "me/b", Control: "token-readonly"},
	}
	rev, kept := scopeEntries(entries, "branch-protection", "")
	if len(rev) != 1 || rev[0].Control != "branch-protection" || len(kept) != 2 {
		t.Fatalf("--only branch-protection: rev=%+v kept=%+v", rev, kept)
	}
	rev, kept = scopeEntries(entries, "", "branch-protection")
	if len(rev) != 2 || len(kept) != 1 || kept[0].Control != "branch-protection" {
		t.Fatalf("--skip branch-protection: rev=%+v kept=%+v", rev, kept)
	}
	rev, kept = scopeEntries(entries, "", "")
	if len(rev) != 3 || len(kept) != 0 {
		t.Fatalf("no scope: rev=%+v kept=%+v", rev, kept)
	}
}

func TestControlMapLookup(t *testing.T) {
	saved := baseline
	t.Cleanup(func() { baseline = saved })
	baseline = []Control{{Key: "x"}, {Key: "y"}}
	m := controlMap()
	if _, ok := m["x"]; !ok {
		t.Fatal("controlMap missing x")
	}
	if len(m) != 2 {
		t.Fatalf("controlMap size %d, want 2", len(m))
	}
}

func TestRevertCallsRevertWithPrior(t *testing.T) {
	saved := baseline
	t.Cleanup(func() { baseline = saved })
	var gotPrior string
	var calls int
	baseline = []Control{{
		Key: "x",
		Revert: func(_ context.Context, _ *github.Client, owner, name, prior string) error {
			calls++
			gotPrior = prior
			return nil
		},
	}}
	entries := revertEntries(context.Background(), nil, &opts{concurrency: 1},
		[]HardenEntry{{Repo: "me/app", Control: "x", Prior: "write"}})
	if calls != 1 || gotPrior != "write" {
		t.Fatalf("calls=%d prior=%q, want 1/write", calls, gotPrior)
	}
	if len(entries) != 0 {
		t.Fatalf("succeeded revert should clear state, got %d remaining", len(entries))
	}
}

func TestRevertKeepsFailedEntry(t *testing.T) {
	saved := baseline
	t.Cleanup(func() { baseline = saved })
	baseline = []Control{{
		Key: "x",
		Revert: func(_ context.Context, _ *github.Client, owner, name, prior string) error {
			return fmt.Errorf("revert failed")
		},
	}}
	entries := revertEntries(context.Background(), nil, &opts{concurrency: 1},
		[]HardenEntry{{Repo: "me/app", Control: "x", Prior: "write"}})
	if len(entries) != 1 {
		t.Fatalf("expected 1 remaining entry (failed revert), got %d", len(entries))
	}
}

func TestRevertKeepsUnknownControl(t *testing.T) {
	saved := baseline
	t.Cleanup(func() { baseline = saved })
	baseline = []Control{{Key: "known"}}
	entries := revertEntries(context.Background(), nil, &opts{concurrency: 1},
		[]HardenEntry{{Repo: "me/app", Control: "unknown-control", Prior: "write"}})
	if len(entries) != 1 {
		t.Fatalf("expected 1 remaining entry (unknown control), got %d", len(entries))
	}
}

func TestCollectHardenAppliesOnlyGaps(t *testing.T) {
	saved := baseline
	t.Cleanup(func() { baseline = saved })
	var applied int
	baseline = []Control{
		{
			Key: "gap-ctl",
			Detect: func(context.Context, *github.Client, string, string, *github.Repository) DetectResult {
				return DetectResult{Status: StatusGap, Prior: "off"}
			},
			Apply: func(context.Context, *github.Client, string, string) error { applied++; return nil },
		},
		{
			Key: "ok-ctl",
			Detect: func(context.Context, *github.Client, string, string, *github.Repository) DetectResult {
				return DetectResult{Status: StatusCompliant}
			},
			Apply: func(context.Context, *github.Client, string, string) error { applied++; return nil },
		},
		{
			Key: "lic-ctl",
			Detect: func(context.Context, *github.Client, string, string, *github.Repository) DetectResult {
				return DetectResult{Status: StatusSkipped}
			},
			Apply: func(context.Context, *github.Client, string, string) error { applied++; return nil },
		},
	}
	repos := []*github.Repository{{FullName: github.Ptr("me/app"), Owner: &github.User{Login: github.Ptr("me")}}}

	statePath := filepath.Join(t.TempDir(), "harden-state.json")
	recorder := newHardenRecorder(statePath, nil)
	appliedCount, skipped, failed, err := collectHarden(context.Background(),
		mustClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(`{}`), nil
		})}), &opts{concurrency: 1}, repos, recorder)
	if err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("applied %d controls, want 1 (only the gap)", applied)
	}
	if appliedCount != 1 {
		t.Fatalf("applied count %d, want 1", appliedCount)
	}
	entries, err := loadHardenState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Control != "gap-ctl" || entries[0].Prior != "off" {
		t.Fatalf("state entries wrong: %+v", entries)
	}
	if skipped != 1 || failed != 0 {
		t.Fatalf("skipped=%d failed=%d, want 1/0", skipped, failed)
	}
}

func TestCollectHardenDryRunAppliesNothing(t *testing.T) {
	saved := baseline
	t.Cleanup(func() { baseline = saved })
	var applied int
	baseline = []Control{{
		Key: "gap-ctl",
		Detect: func(context.Context, *github.Client, string, string, *github.Repository) DetectResult {
			return DetectResult{Status: StatusGap}
		},
		Apply: func(context.Context, *github.Client, string, string) error { applied++; return nil },
	}}
	repos := []*github.Repository{{FullName: github.Ptr("me/app"), Owner: &github.User{Login: github.Ptr("me")}}}
	appliedCount, _, _, err := collectHarden(context.Background(), nil, &opts{concurrency: 1, dryRun: true}, repos, nil)
	if err != nil {
		t.Fatal(err)
	}
	if applied != 0 {
		t.Fatalf("dry-run applied %d, want 0", applied)
	}
	if appliedCount != 0 {
		t.Fatalf("dry-run produced %d applied count, want 0", appliedCount)
	}
}
