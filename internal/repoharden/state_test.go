package repoharden

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestHardenStateRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "harden.json")
	want := []HardenEntry{
		{Repo: "me/app", Control: "token-readonly", Prior: "write"},
		{Repo: "me/app", Control: "branch-protection", Prior: ""},
	}
	if err := saveHardenState(path, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := loadHardenState(path)
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
