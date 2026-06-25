package repoharden

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// StateEntry records one Actions workflow that disable-all turned off.
type StateEntry struct {
	Repo string `json:"repo"`
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
}

// HardenEntry records one change harden made, so revert can undo exactly it.
type HardenEntry struct {
	Repo    string `json:"repo"`
	Control string `json:"control"`
	Prior   string `json:"prior"`
}

func loadJSON[T any](path string) ([]T, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, nil
	}
	var out []T
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("parse state file %s: %w", path, err)
	}
	return out, nil
}

func saveJSON[T any](path string, v []T) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func loadState(path string) ([]StateEntry, error)        { return loadJSON[StateEntry](path) }
func saveState(path string, e []StateEntry) error        { return saveJSON(path, e) }
func loadHardenState(path string) ([]HardenEntry, error) { return loadJSON[HardenEntry](path) }
func saveHardenState(path string, e []HardenEntry) error { return saveJSON(path, e) }

// stateDir returns the directory used for both state files.
func stateDir() (string, error) {
	dir := os.Getenv("REPO_HARDEN_STATE_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".repo-harden")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func customStateFilePath(o *opts) (string, bool, error) {
	if o != nil && o.stateFile != "" {
		if dir := filepath.Dir(o.stateFile); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return "", false, err
			}
		}
		return o.stateFile, true, nil
	}
	return "", false, nil
}

func stateFilePath(o *opts) (string, error) {
	if path, ok, err := customStateFilePath(o); ok || err != nil {
		return path, err
	}
	dir, err := stateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "enabled-workflows.json"), nil
}

func hardenStateFilePath(o *opts) (string, error) {
	if path, ok, err := customStateFilePath(o); ok || err != nil {
		return path, err
	}
	dir, err := stateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "harden-state.json"), nil
}

func entryKey(repo string, id int64) string { return fmt.Sprintf("%s#%d", repo, id) }
