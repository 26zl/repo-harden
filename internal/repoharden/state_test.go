package repoharden

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var testStateScope = StateScope{
	Provider: "github",
	Host:     "https://github.com",
	Account:  "tester",
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
