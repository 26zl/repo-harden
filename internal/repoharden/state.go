package repoharden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/google/go-github/v88/github"
)

const stateSchemaVersion = 1

const (
	actionsStateKind = "actions-workflows"
	hardenStateKind  = "github-hardening"
)

type StateScope struct {
	Provider string `json:"provider"`
	Host     string `json:"host"`
	Account  string `json:"account"`
}

// StateEntry is one workflow disable-all turned off.
type StateEntry struct {
	Repo  string      `json:"repo"`
	ID    int64       `json:"id"`
	Name  string      `json:"name"`
	Path  string      `json:"path"`
	Phase ActionPhase `json:"phase"`
}

type ActionPhase string

const (
	ActionPhasePending ActionPhase = "pending"
	ActionPhaseApplied ActionPhase = "applied"
	ActionPhaseUnknown ActionPhase = "unknown"
)

type HardenPhase string

const (
	HardenPhasePending HardenPhase = "pending"
	HardenPhaseApplied HardenPhase = "applied"
	HardenPhaseUnknown HardenPhase = "unknown"
)

// HardenEntry is one change harden made, so revert can undo it.
type HardenEntry struct {
	Repo    string      `json:"repo"`
	Control string      `json:"control"`
	Prior   string      `json:"prior"`
	Phase   HardenPhase `json:"phase"`
}

type stateEnvelope[T any] struct {
	Version int        `json:"version"`
	Kind    string     `json:"kind"`
	Scope   StateScope `json:"scope"`
	Entries []T        `json:"entries"`
}

func canonicalStateHost(hostOrURL string) (string, error) {
	raw := strings.TrimRight(providerBaseURL("github", hostOrURL), "/")
	raw = strings.TrimSuffix(raw, "/api/v3")
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse GitHub host: %w", err)
	}
	if err := requireSecureURL(u.String()); err != nil {
		return "", err
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.User = nil
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}

func githubStateScope(ctx context.Context, c *github.Client, o *opts) (StateScope, error) {
	host, err := canonicalStateHost(o.host)
	if err != nil {
		return StateScope{}, err
	}
	user, _, err := c.Users.Get(ctx, "")
	if err != nil {
		return StateScope{}, fmt.Errorf("resolve authenticated GitHub account for state: %w", err)
	}
	account := strings.TrimSpace(user.GetLogin())
	if account == "" {
		return StateScope{}, errors.New("authenticated GitHub account has an empty login")
	}
	return StateScope{Provider: "github", Host: host, Account: account}, nil
}

func normalizeStateScope(scope StateScope) StateScope {
	scope.Provider = strings.ToLower(strings.TrimSpace(scope.Provider))
	scope.Host = strings.TrimRight(strings.ToLower(strings.TrimSpace(scope.Host)), "/")
	scope.Account = strings.ToLower(strings.TrimSpace(scope.Account))
	return scope
}

func validateStateScope(actual, expected StateScope) error {
	actual = normalizeStateScope(actual)
	expected = normalizeStateScope(expected)
	if actual.Provider == "" || actual.Host == "" || actual.Account == "" {
		return errors.New("state scope is incomplete")
	}
	if actual != expected {
		return fmt.Errorf(
			"state belongs to %s account %s at %s, current target is %s account %s at %s",
			actual.Provider, actual.Account, actual.Host,
			expected.Provider, expected.Account, expected.Host,
		)
	}
	return nil
}

func decodeStateEnvelope[T any](path, kind string, scope StateScope) (stateEnvelope[T], error) {
	b, err := os.ReadFile(path) // #nosec G304 -- --state-file is an intentional operator-selected path.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return stateEnvelope[T]{
				Version: stateSchemaVersion,
				Kind:    kind,
				Scope:   normalizeStateScope(scope),
				Entries: []T{},
			}, nil
		}
		return stateEnvelope[T]{}, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return stateEnvelope[T]{}, fmt.Errorf("state file is empty: %s", path)
	}
	if bytes.TrimSpace(b)[0] == '[' {
		return stateEnvelope[T]{}, fmt.Errorf(
			"%s uses the unsafe legacy state format without host/account binding; move it aside and run the originating command again",
			path,
		)
	}
	var out stateEnvelope[T]
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return stateEnvelope[T]{}, fmt.Errorf("parse state file %s: %w", path, err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return stateEnvelope[T]{}, fmt.Errorf("parse state file %s: %w", path, err)
	}
	if out.Version != stateSchemaVersion {
		return stateEnvelope[T]{}, fmt.Errorf(
			"unsupported state schema version %d in %s (expected %d)",
			out.Version, path, stateSchemaVersion,
		)
	}
	if out.Kind != kind {
		return stateEnvelope[T]{}, fmt.Errorf(
			"%s contains %q state, expected %q; use a separate --state-file per command family",
			path, out.Kind, kind,
		)
	}
	if err := validateStateScope(out.Scope, scope); err != nil {
		return stateEnvelope[T]{}, fmt.Errorf("refusing state file %s: %w", path, err)
	}
	if out.Entries == nil {
		out.Entries = []T{}
	}
	return out, nil
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func saveStateEnvelope[T any](path, kind string, scope StateScope, entries []T) error {
	out := stateEnvelope[T]{
		Version: stateSchemaVersion,
		Kind:    kind,
		Scope:   normalizeStateScope(scope),
		Entries: entries,
	}
	b, err := json.MarshalIndent(out, "", "  ")
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
	if err := tmp.Sync(); err != nil { // flush contents to disk before the rename
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	// fsync the directory so the rename survives a crash right after it
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- fsync the selected state file's parent.
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func saveState(path string, scope StateScope, entries []StateEntry) error {
	if err := validateStateEntries(entries); err != nil {
		return err
	}
	return saveStateEnvelope(path, actionsStateKind, scope, entries)
}

func saveHardenState(path string, scope StateScope, entries []HardenEntry) error {
	if err := validateHardenEntries(entries); err != nil {
		return err
	}
	return saveStateEnvelope(path, hardenStateKind, scope, entries)
}

func loadState(path string, scope StateScope) ([]StateEntry, error) {
	envelope, err := decodeStateEnvelope[StateEntry](path, actionsStateKind, scope)
	if err != nil {
		return nil, err
	}
	if err := validateStateEntries(envelope.Entries); err != nil {
		return nil, fmt.Errorf("invalid Actions state in %s: %w", path, err)
	}
	return envelope.Entries, nil
}

func loadHardenState(path string, scope StateScope) ([]HardenEntry, error) {
	envelope, err := decodeStateEnvelope[HardenEntry](path, hardenStateKind, scope)
	if err != nil {
		return nil, err
	}
	if err := validateHardenEntries(envelope.Entries); err != nil {
		return nil, fmt.Errorf("invalid harden state in %s: %w", path, err)
	}
	return envelope.Entries, nil
}

func validateRepoSlug(repo string) error {
	if strings.TrimSpace(repo) != repo || strings.Count(repo, "/") != 1 {
		return fmt.Errorf("invalid repository name %q", repo)
	}
	owner, name := splitRepo(repo)
	if owner == "" || name == "" || strings.ContainsAny(repo, "\x00\r\n\t") {
		return fmt.Errorf("invalid repository name %q", repo)
	}
	return nil
}

func validateStateEntries(entries []StateEntry) error {
	seen := map[string]bool{}
	for i, entry := range entries {
		if err := validateRepoSlug(entry.Repo); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		if entry.ID <= 0 {
			return fmt.Errorf("entry %d: workflow ID must be positive", i)
		}
		switch entry.Phase {
		case ActionPhasePending, ActionPhaseApplied, ActionPhaseUnknown:
		default:
			return fmt.Errorf("entry %d: invalid Actions phase %q", i, entry.Phase)
		}
		key := entryKey(entry.Repo, entry.ID)
		if seen[key] {
			return fmt.Errorf("entry %d: duplicate workflow %s", i, key)
		}
		seen[key] = true
	}
	return nil
}

func validateHardenEntries(entries []HardenEntry) error {
	seen := map[string]bool{}
	controls := controlMap()
	for i, entry := range entries {
		if err := validateRepoSlug(entry.Repo); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		control, ok := controls[entry.Control]
		if !ok || control.Revert == nil {
			return fmt.Errorf("entry %d: unknown or non-reversible control %q", i, entry.Control)
		}
		switch entry.Phase {
		case HardenPhasePending, HardenPhaseApplied, HardenPhaseUnknown:
		default:
			return fmt.Errorf("entry %d: invalid harden phase %q", i, entry.Phase)
		}
		validatePrior := control.ValidatePrior
		if validatePrior == nil {
			validatePrior = func(prior string) error { return validateControlPrior(entry.Control, prior) }
		}
		if err := validatePrior(entry.Prior); err != nil {
			return fmt.Errorf("entry %d control %s: %w", i, entry.Control, err)
		}
		key := entry.Repo + "\x00" + entry.Control
		if seen[key] {
			return fmt.Errorf("entry %d: duplicate harden control %s on %s", i, entry.Control, entry.Repo)
		}
		seen[key] = true
	}
	return nil
}

// stateDir is the dir for both state files.
func stateDir() (string, error) {
	dir := strings.TrimSpace(os.Getenv("REPO_HARDEN_STATE_DIR"))
	managedDefault := dir == ""
	if managedDefault {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".repo-harden")
	}
	info, err := os.Lstat(dir) // #nosec G703 -- this local CLI intentionally accepts an operator-selected state directory.
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("state directory must not be a symlink: %s", dir)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("state directory path is not a directory: %s", dir)
		}
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil { // #nosec G703 -- create the validated operator-selected state directory.
			return "", err
		}
	default:
		return "", err
	}
	// ~/.repo-harden is owned by this tool, so keep it private. An explicit
	// override may be a shared parent chosen by the operator; do not silently
	// change permissions on an existing external directory.
	if managedDefault {
		if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302,G703 -- 0700 is correct for the tool-owned default directory.
			return "", err
		}
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

func lockStateFile(ctx context.Context, path string) (func() error, error) {
	lock := flock.New(path + ".lock")
	lockCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	locked, err := lock.TryLockContext(lockCtx, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("lock state file %s: %w", path, err)
	}
	if !locked {
		return nil, fmt.Errorf("state file is in use by another repo-harden process: %s", path)
	}
	return lock.Unlock, nil
}
