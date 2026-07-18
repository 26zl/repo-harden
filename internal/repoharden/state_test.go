package repoharden

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

var testStateScope = StateScope{
	Provider:  "github",
	Host:      "https://github.com",
	Account:   "tester",
	AccountID: 42,
}

func TestValidateRepoSlugRejectsControlCharacters(t *testing.T) {
	for _, repo := range []string{"me\x1b[31m/app", "me/app\x00x", "me/ap\u202ep", "me/app\ttab"} {
		if err := validateRepoSlug(repo); err == nil {
			t.Errorf("slug %q must be rejected", repo)
		}
	}
	if err := validateRepoSlug("me/app"); err != nil {
		t.Errorf("plain slug rejected: %v", err)
	}
}

func TestHardenStateRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "harden.json")
	want := []HardenEntry{
		{Repo: "me/app", Control: "token-readonly", Prior: `{"default_workflow_permissions":"write"}`, Phase: HardenPhaseApplied},
		{Repo: "me/app", Control: "branch-protection", Prior: "", Phase: HardenPhasePending},
	}
	if err := saveHardenState(path, testStateScope, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := loadHardenState(path, testStateScope)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("roundtrip mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

func TestHardenStateFilePathOverride(t *testing.T) {
	custom := filepath.Join(t.TempDir(), "nested", "harden.json")
	got, err := hardenStateFilePath(&opts{stateFile: custom})
	if err != nil {
		t.Fatal(err)
	}
	if got != custom {
		t.Fatalf("got %q, want %q", got, custom)
	}
}

func TestStateRejectsScopeMismatchAndLegacyFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actions.json")
	entries := []StateEntry{{Repo: "me/app", ID: 1, Name: "CI", Phase: ActionPhaseApplied}}
	if err := saveState(path, testStateScope, entries); err != nil {
		t.Fatal(err)
	}
	other := testStateScope
	other.Host = "https://github.example.com"
	if _, err := loadState(path, other); err == nil || !strings.Contains(err.Error(), "state belongs to") {
		t.Fatalf("scope mismatch should be rejected, got %v", err)
	}

	legacy := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(legacy, []byte(`[{"repo":"me/app","id":1}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(legacy, testStateScope); err == nil || !strings.Contains(err.Error(), "legacy state format") {
		t.Fatalf("legacy state should be rejected, got %v", err)
	}
}

func TestStateScopeUsesStableAccountIDAndMigratesVersionOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actions.json")
	legacyEnvelope := `{
	  "version": 1,
	  "kind": "actions-workflows",
	  "scope": {"provider":"github","host":"https://github.com","account":"tester"},
	  "entries": [{"repo":"me/app","id":1,"name":"CI","path":".github/workflows/ci.yml","phase":"applied"}]
	}`
	if err := os.WriteFile(path, []byte(legacyEnvelope), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := loadState(path, testStateScope)
	if err != nil || len(entries) != 1 {
		t.Fatalf("load version 1 state = %+v, %v", entries, err)
	}
	if err := saveState(path, testStateScope, entries); err != nil {
		t.Fatal(err)
	}
	migrated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"version": 2`, `"account_id": 42`} {
		if !strings.Contains(string(migrated), want) {
			t.Fatalf("migrated state missing %s:\n%s", want, migrated)
		}
	}

	renamed := testStateScope
	renamed.Account = "renamed-user"
	if _, err := loadState(path, renamed); err != nil {
		t.Fatalf("same stable account ID after login rename must be accepted: %v", err)
	}
	otherID := renamed
	otherID.AccountID++
	if _, err := loadState(path, otherID); err == nil || !strings.Contains(err.Error(), "state belongs to") {
		t.Fatalf("different account ID must be rejected, got %v", err)
	}
}

func TestHardenStateRejectsInvalidPrior(t *testing.T) {
	path := filepath.Join(t.TempDir(), "harden.json")
	envelope := `{
	  "version": 1,
	  "kind": "github-hardening",
	  "scope": {"provider":"github","host":"https://github.com","account":"tester"},
	  "entries": [{"repo":"me/app","control":"secret-scanning","prior":"garbage","phase":"applied"}]
	}`
	if err := os.WriteFile(path, []byte(envelope), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadHardenState(path, testStateScope); err == nil || !strings.Contains(err.Error(), "invalid secret scanning prior") {
		t.Fatalf("invalid prior should fail closed, got %v", err)
	}
}

func TestStateFileLockRejectsConcurrentWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	unlock, err := lockStateFile(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unlock() }()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := lockStateFile(ctx, path); err == nil {
		t.Fatal("second writer acquired an already-held state lock")
	}
}

func TestStateDirDoesNotChmodExistingOverride(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix directory permissions are not meaningful on Windows")
	}
	dir := filepath.Join(t.TempDir(), "shared-state")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REPO_HARDEN_STATE_DIR", dir)

	got, err := stateDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != dir {
		t.Fatalf("state dir = %q, want %q", got, dir)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if gotMode := info.Mode().Perm(); gotMode != 0o755 {
		t.Fatalf("existing override mode changed to %o, want 755", gotMode)
	}
}

func TestStateDirRejectsSymlinkOverride(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "state-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	t.Setenv("REPO_HARDEN_STATE_DIR", link)
	if _, err := stateDir(); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink override should be rejected, got %v", err)
	}
}

func TestEntryKey(t *testing.T) {
	if entryKey("foo/bar", 42) != "foo/bar#42" {
		t.Fatal("entryKey format changed")
	}
}

func TestStateRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	want := []StateEntry{
		{Repo: "foo/bar", ID: 1, Name: "CI", Path: ".github/workflows/ci.yml", Phase: ActionPhaseApplied},
		{Repo: "foo/baz", ID: 2, Name: "Lint", Path: ".github/workflows/lint.yml", Phase: ActionPhaseUnknown},
	}
	if err := saveState(path, testStateScope, want); err != nil {
		t.Fatalf("saveState: %v", err)
	}
	got, err := loadState(path, testStateScope)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("roundtrip mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

func TestLoadStateMissing(t *testing.T) {
	got, err := loadState(filepath.Join(t.TempDir(), "nope.json"), testStateScope)
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("missing file should yield no entries, got %v", got)
	}
}

func TestLoadStateMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"repo":`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(path, testStateScope); err == nil {
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
