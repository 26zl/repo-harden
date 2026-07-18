package repoharden

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-github/v88/github"
)

func TestRecorderRefreshesAppliedPriorOnReharden(t *testing.T) {
	path := filepath.Join(t.TempDir(), "harden.json")
	r := newHardenRecorder(path, testStateScope, nil)
	entry := HardenEntry{Repo: "me/app", Control: "token-readonly", Prior: `{"default_workflow_permissions":"write"}`}
	if _, err := r.record(entry); err != nil {
		t.Fatal(err)
	}
	if err := r.setPhase(entry, HardenPhaseApplied); err != nil {
		t.Fatal(err)
	}
	fresh := `{"default_workflow_permissions":"read","can_approve_pull_request_reviews":true}`
	if _, err := r.record(HardenEntry{Repo: "me/app", Control: "token-readonly", Prior: fresh}); err != nil {
		t.Fatal(err)
	}
	got, err := loadHardenState(path, testStateScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 deduped entry, got %d", len(got))
	}
	if got[0].Prior != fresh {
		t.Fatalf("prior not refreshed on re-harden: got %q, want %q", got[0].Prior, fresh)
	}
}

func TestRecorderPreservesAmbiguousPriorOnReharden(t *testing.T) {
	for _, phase := range []HardenPhase{HardenPhasePending, HardenPhaseUnknown} {
		t.Run(string(phase), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "harden.json")
			r := newHardenRecorder(path, testStateScope, nil)
			original := HardenEntry{Repo: "me/app", Control: "token-readonly", Prior: `{"default_workflow_permissions":"write"}`}
			if _, err := r.record(original); err != nil {
				t.Fatal(err)
			}
			if phase == HardenPhaseUnknown {
				if err := r.setPhase(original, phase); err != nil {
					t.Fatal(err)
				}
			}

			fresh := `{"default_workflow_permissions":"read","can_approve_pull_request_reviews":true}`
			if _, err := r.record(HardenEntry{Repo: original.Repo, Control: original.Control, Prior: fresh}); err == nil || !strings.Contains(err.Error(), "refusing to replace ambiguous") {
				t.Fatalf("record() error = %v, want ambiguous-state refusal", err)
			}
			got, err := loadHardenState(path, testStateScope)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].Prior != original.Prior || got[0].Phase != phase {
				t.Fatalf("ambiguous state changed: %+v", got)
			}
		})
	}
}

func TestScopeEntries(t *testing.T) {
	entries := []HardenEntry{
		{Repo: "me/a", Control: "branch-protection"},
		{Repo: "me/a", Control: "dependabot-alerts"},
		{Repo: "me/b", Control: "token-readonly"},
	}
	rev, kept, err := scopeEntries(entries, &opts{only: "branch-protection"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rev) != 1 || rev[0].Control != "branch-protection" || len(kept) != 2 {
		t.Fatalf("--only branch-protection: rev=%+v kept=%+v", rev, kept)
	}
	rev, kept, err = scopeEntries(entries, &opts{skip: "branch-protection"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rev) != 2 || len(kept) != 1 || kept[0].Control != "branch-protection" {
		t.Fatalf("--skip branch-protection: rev=%+v kept=%+v", rev, kept)
	}
	rev, kept, err = scopeEntries(entries, &opts{})
	if err != nil {
		t.Fatal(err)
	}
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
	reverted := false
	baseline = []Control{{
		Key: "x",
		Detect: func(context.Context, *github.Client, string, string, *github.Repository) DetectResult {
			if reverted {
				return DetectResult{Status: StatusGap, Prior: "write"}
			}
			return DetectResult{Status: StatusCompliant}
		},
		Revert: func(_ context.Context, _ *github.Client, owner, name, prior string) error {
			calls++
			gotPrior = prior
			reverted = true
			return nil
		},
	}}
	entries := revertEntries(context.Background(), mockClient(map[string]string{"GET /repos/me/app": `{"full_name":"me/app"}`}), &opts{concurrency: 1},
		[]HardenEntry{{Repo: "me/app", Control: "x", Prior: "write", Phase: HardenPhaseApplied}})
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
		Detect: func(context.Context, *github.Client, string, string, *github.Repository) DetectResult {
			return DetectResult{Status: StatusCompliant}
		},
		Revert: func(_ context.Context, _ *github.Client, owner, name, prior string) error {
			return fmt.Errorf("revert failed")
		},
	}}
	entries := revertEntries(context.Background(), mockClient(map[string]string{"GET /repos/me/app": `{"full_name":"me/app"}`}), &opts{concurrency: 1},
		[]HardenEntry{{Repo: "me/app", Control: "x", Prior: "write", Phase: HardenPhaseApplied}})
	if len(entries) != 1 {
		t.Fatalf("expected 1 remaining entry (failed revert), got %d", len(entries))
	}
}

func TestRevertRefusesToOverwriteDrift(t *testing.T) {
	saved := baseline
	t.Cleanup(func() { baseline = saved })
	var calls int
	baseline = []Control{{
		Key: "x",
		Detect: func(context.Context, *github.Client, string, string, *github.Repository) DetectResult {
			return DetectResult{Status: StatusGap, Prior: "manual-change", Detail: "changed after harden"}
		},
		Revert: func(context.Context, *github.Client, string, string, string) error {
			calls++
			return nil
		},
	}}
	client := mockClient(map[string]string{"GET /repos/me/app": `{"full_name":"me/app"}`})
	remaining := revertEntries(context.Background(), client, &opts{concurrency: 1},
		[]HardenEntry{{Repo: "me/app", Control: "x", Prior: "original", Phase: HardenPhaseApplied}})
	if calls != 0 {
		t.Fatalf("revert called %d times after drift, want 0", calls)
	}
	if len(remaining) != 1 {
		t.Fatalf("drifted entry should remain in state, got %+v", remaining)
	}
}

func TestRevertRefusesPendingEntryWhenLiveMatchesHardened(t *testing.T) {
	saved := baseline
	t.Cleanup(func() { baseline = saved })
	var calls int
	baseline = []Control{{
		Key: "x",
		Detect: func(context.Context, *github.Client, string, string, *github.Repository) DetectResult {
			return DetectResult{Status: StatusCompliant}
		},
		Revert: func(context.Context, *github.Client, string, string, string) error {
			calls++
			return nil
		},
	}}
	entries := revertEntries(context.Background(), mockClient(map[string]string{"GET /repos/me/app": `{"full_name":"me/app"}`}), &opts{concurrency: 1},
		[]HardenEntry{{Repo: "me/app", Control: "x", Prior: "write", Phase: HardenPhasePending}})
	if calls != 0 {
		t.Fatalf("revert ran %d times for a pending entry, want 0 (the change was never verified applied)", calls)
	}
	if len(entries) != 1 {
		t.Fatalf("pending entry must remain in state, got %d remaining", len(entries))
	}
}

func TestRevertDropsPendingEntryWhenPriorStillLive(t *testing.T) {
	saved := baseline
	t.Cleanup(func() { baseline = saved })
	var calls int
	baseline = []Control{{
		Key: "x",
		Detect: func(context.Context, *github.Client, string, string, *github.Repository) DetectResult {
			return DetectResult{Status: StatusGap, Prior: "write"}
		},
		Revert: func(context.Context, *github.Client, string, string, string) error {
			calls++
			return nil
		},
	}}
	entries := revertEntries(context.Background(), mockClient(map[string]string{"GET /repos/me/app": `{"full_name":"me/app"}`}), &opts{concurrency: 1},
		[]HardenEntry{{Repo: "me/app", Control: "x", Prior: "write", Phase: HardenPhasePending}})
	if calls != 0 || len(entries) != 0 {
		t.Fatalf("unchanged pending entry should drop cleanly: calls=%d remaining=%d", calls, len(entries))
	}
}

func TestCollectHardenRejectsReportOnlySelection(t *testing.T) {
	saved := baseline
	t.Cleanup(func() { baseline = saved })
	baseline = []Control{{Key: "security-md"}}
	_, _, _, err := collectHarden(context.Background(), nil, &opts{concurrency: 1, only: "security-md"}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "report-only") {
		t.Fatalf("err=%v, want report-only rejection", err)
	}
	var ue usageError
	if !errors.As(err, &ue) {
		t.Fatalf("err=%T, want usageError (exit 2)", err)
	}
}

func TestRevertKeepsUnknownControl(t *testing.T) {
	saved := baseline
	t.Cleanup(func() { baseline = saved })
	baseline = []Control{{Key: "known"}}
	entries := revertEntries(context.Background(), nil, &opts{concurrency: 1},
		[]HardenEntry{{Repo: "me/app", Control: "unknown-control", Prior: "write", Phase: HardenPhaseApplied}})
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
				if applied > 0 {
					return DetectResult{Status: StatusCompliant}
				}
				return DetectResult{Status: StatusGap, Prior: "off"}
			},
			Apply:  func(context.Context, *github.Client, string, string) error { applied++; return nil },
			Revert: func(context.Context, *github.Client, string, string, string) error { return nil },
			ValidatePrior: func(prior string) error {
				if prior != "off" {
					return fmt.Errorf("invalid prior")
				}
				return nil
			},
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
	recorder := newHardenRecorder(statePath, testStateScope, nil)
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
	entries, err := loadHardenState(statePath, testStateScope)
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
	if appliedCount != 1 {
		t.Fatalf("dry-run would-harden count %d, want 1 (the gap)", appliedCount)
	}
}

func TestCmdHardenPersistsAppliedState(t *testing.T) {
	saved := baseline
	t.Cleanup(func() { baseline = saved })
	applied := false
	baseline = []Control{{
		Key: "test-control",
		Detect: func(context.Context, *github.Client, string, string, *github.Repository) DetectResult {
			if applied {
				return DetectResult{Status: StatusCompliant}
			}
			return DetectResult{Status: StatusGap, Prior: "off"}
		},
		Apply: func(context.Context, *github.Client, string, string) error {
			applied = true
			return nil
		},
		Revert: func(context.Context, *github.Client, string, string, string) error { return nil },
		ValidatePrior: func(prior string) error {
			if prior != "off" {
				return fmt.Errorf("invalid prior %q", prior)
			}
			return nil
		},
	}}
	client := mockClient(map[string]string{
		"GET /user/repos": `[{"full_name":"me/app","owner":{"login":"me"},"fork":false,"archived":false}]`,
		"GET /user":       `{"login":"tester","id":42}`,
	})
	path := filepath.Join(t.TempDir(), "harden.json")
	o := &opts{host: "github.com", stateFile: path, concurrency: 1}
	_ = captureStdout(t, func() {
		if err := cmdHarden(context.Background(), client, o); err != nil {
			t.Fatal(err)
		}
	})
	if !applied {
		t.Fatal("harden command did not apply the selected gap")
	}
	entries, err := loadHardenState(path, testStateScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Control != "test-control" || entries[0].Phase != HardenPhaseApplied {
		t.Fatalf("persisted harden state = %+v", entries)
	}
}

func TestCollectHardenCompensatesPartialApplyAndClearsState(t *testing.T) {
	saved := baseline
	t.Cleanup(func() { baseline = saved })
	stage := "off"
	reverted := false
	baseline = []Control{{
		Key: "partial",
		Detect: func(context.Context, *github.Client, string, string, *github.Repository) DetectResult {
			if stage == "off" {
				return DetectResult{Status: StatusGap, Prior: "off"}
			}
			return DetectResult{Status: StatusGap, Prior: "partial"}
		},
		Apply: func(context.Context, *github.Client, string, string) error {
			stage = "partial"
			return fmt.Errorf("second API call failed")
		},
		Revert: func(_ context.Context, _ *github.Client, _, _, prior string) error {
			if prior != "off" {
				return fmt.Errorf("unexpected prior %q", prior)
			}
			stage = "off"
			reverted = true
			return nil
		},
		ValidatePrior: func(prior string) error {
			if prior != "off" {
				return fmt.Errorf("invalid prior")
			}
			return nil
		},
	}}
	repos := []*github.Repository{{FullName: github.Ptr("me/app")}}
	path := filepath.Join(t.TempDir(), "state.json")
	recorder := newHardenRecorder(path, testStateScope, nil)

	_, _, failed, err := collectHarden(context.Background(), nil, &opts{concurrency: 1}, repos, recorder)
	if err != nil {
		t.Fatal(err)
	}
	if failed != 1 || !reverted || stage != "off" {
		t.Fatalf("failed=%d reverted=%v stage=%s, want 1/true/off", failed, reverted, stage)
	}
	entries, err := loadHardenState(path, testStateScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("compensated partial apply must not remain in state: %+v", entries)
	}
}

func TestCollectHardenCompensatesRealActionsPartialFailure(t *testing.T) {
	selected := false
	shaPinned := false
	selectedWrites := 0
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/repos/me/app/actions/permissions":
			allowed := "all"
			if selected {
				allowed = "selected"
			}
			return jsonResponse(fmt.Sprintf(`{"enabled":true,"allowed_actions":%q,"sha_pinning_required":%t}`, allowed, shaPinned)), nil
		case req.Method == http.MethodGet && req.URL.Path == "/repos/me/app/actions/permissions/selected-actions":
			return jsonResponse(`{"github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":["unsafe/*"]}`), nil
		case req.Method == http.MethodPut && req.URL.Path == "/repos/me/app/actions/permissions":
			data, _ := io.ReadAll(req.Body)
			selected = strings.Contains(string(data), `"allowed_actions":"selected"`)
			shaPinned = strings.Contains(string(data), `"sha_pinning_required":true`)
			return jsonResponse(`{}`), nil
		case req.Method == http.MethodPut && req.URL.Path == "/repos/me/app/actions/permissions/selected-actions":
			selectedWrites++
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Status:     "500 Internal Server Error",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"message":"partial failure"}`)),
				Request:    req,
			}, nil
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
		}
	})})
	path := filepath.Join(t.TempDir(), "state.json")
	recorder := newHardenRecorder(path, testStateScope, nil)
	repos := []*github.Repository{{FullName: github.Ptr("me/app")}}
	_, _, failed, err := collectHarden(context.Background(), client, &opts{concurrency: 1, only: "actions-allowlist"}, repos, recorder)
	if err != nil {
		t.Fatal(err)
	}
	if failed != 1 || selectedWrites != 1 {
		t.Fatalf("failed=%d selected-writes=%d, want 1/1", failed, selectedWrites)
	}
	if selected {
		t.Fatal("compensating revert did not restore allowed_actions=all")
	}
	entries, err := loadHardenState(path, testStateScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("verified compensation must clear pending state: %+v", entries)
	}
}

func TestCollectHardenRejectsUnverifiedSuccessfulApply(t *testing.T) {
	saved := baseline
	t.Cleanup(func() { baseline = saved })
	var reverted bool
	baseline = []Control{{
		Key: "no-op",
		Detect: func(context.Context, *github.Client, string, string, *github.Repository) DetectResult {
			return DetectResult{Status: StatusGap, Prior: "off"}
		},
		Apply: func(context.Context, *github.Client, string, string) error { return nil },
		Revert: func(context.Context, *github.Client, string, string, string) error {
			reverted = true
			return nil
		},
	}}
	path := filepath.Join(t.TempDir(), "state.json")
	recorder := newHardenRecorder(path, testStateScope, nil)
	_, _, failed, err := collectHarden(context.Background(), nil, &opts{concurrency: 1}, []*github.Repository{{FullName: github.Ptr("me/app")}}, recorder)
	if err != nil {
		t.Fatal(err)
	}
	if failed != 1 || reverted {
		t.Fatalf("failed=%d reverted=%v, want 1/false for a verified no-op", failed, reverted)
	}
}

func TestPriorStateRestoredAcceptsEquivalentCompliantAlternative(t *testing.T) {
	if !priorStateRestored(DetectResult{Status: StatusCompliant, Prior: "not-configured"}, "not-configured") {
		t.Fatal("an exact restored state that remains compliant through an alternative setup must be accepted")
	}
	if priorStateRestored(DetectResult{Status: StatusCompliant}, "") {
		t.Fatal("an empty prior must not make an unrelated compliant state look restored")
	}
	if priorStateRestored(DetectResult{Status: StatusSkipped, Prior: "not-configured"}, "not-configured") {
		t.Fatal("an unverifiable result must not count as restored")
	}
}

func TestRevertEntriesAcceptsCodeScanningAdvancedSetup(t *testing.T) {
	defaultSetup := "configured"
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/repos/me/app":
			return jsonResponse(`{"full_name":"me/app","default_branch":"main"}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/repos/me/app/code-scanning/default-setup":
			return jsonResponse(fmt.Sprintf(`{"state":%q}`, defaultSetup)), nil
		case req.Method == http.MethodPatch && req.URL.Path == "/repos/me/app/code-scanning/default-setup":
			defaultSetup = "not-configured"
			return jsonResponse(`{"state":"not-configured"}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/repos/me/app/code-scanning/analyses":
			return jsonResponse(`[{"id":1,"created_at":"2999-01-01T00:00:00Z"}]`), nil
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
		}
	})})
	var remaining []HardenEntry
	_ = captureStdout(t, func() {
		remaining = revertEntries(context.Background(), client, &opts{concurrency: 1}, []HardenEntry{{
			Repo: "me/app", Control: "code-scanning", Prior: "not-configured", Phase: HardenPhaseApplied,
		}})
	})
	if len(remaining) != 0 || defaultSetup != "not-configured" {
		t.Fatalf("remaining=%+v defaultSetup=%q, want verified advanced-setup restoration", remaining, defaultSetup)
	}
}

func TestScopeEntriesIncludesRepositoryFilters(t *testing.T) {
	entries := []HardenEntry{
		{Repo: "me/a", Control: "branch-protection"},
		{Repo: "me/b", Control: "branch-protection"},
		{Repo: "other/c", Control: "branch-protection"},
	}
	selected, kept, err := scopeEntries(entries, &opts{owner: "me", repo: "me/b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 || selected[0].Repo != "me/b" || len(kept) != 2 {
		t.Fatalf("selected=%+v kept=%+v", selected, kept)
	}
}

func TestCmdRevertRespectsRepoScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "harden.json")
	entries := []HardenEntry{
		{Repo: "me/a", Control: "dependabot-alerts", Prior: "disabled", Phase: HardenPhaseApplied},
		{Repo: "me/b", Control: "dependabot-alerts", Prior: "disabled", Phase: HardenPhaseApplied},
	}
	if err := saveHardenState(path, testStateScope, entries); err != nil {
		t.Fatal(err)
	}
	var deleted []string
	alertsEnabled := true
	client := mustClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/user":
			return jsonResponse(`{"login":"tester","id":42}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/repos/me/b":
			return jsonResponse(`{"full_name":"me/b","owner":{"login":"me"}}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/repos/me/b/vulnerability-alerts":
			if !alertsEnabled {
				return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
			}
			return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
		case req.Method == http.MethodDelete:
			deleted = append(deleted, req.URL.Path)
			alertsEnabled = false
			return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody}, nil
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody}, nil
		}
	})})
	o := &opts{stateFile: path, host: "github.com", repo: "me/b", concurrency: 1}
	_ = captureStdout(t, func() {
		if err := cmdRevert(context.Background(), client, o); err != nil {
			t.Fatal(err)
		}
	})
	if len(deleted) != 1 || deleted[0] != "/repos/me/b/vulnerability-alerts" {
		t.Fatalf("deleted paths = %v, want only me/b", deleted)
	}
	got, err := loadHardenState(path, testStateScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Repo != "me/a" {
		t.Fatalf("out-of-scope harden state not preserved: %+v", got)
	}
}
