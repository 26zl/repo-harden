package repoharden

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/google/go-github/v88/github"
	"golang.org/x/sync/errgroup"
)

type hardenRecorder struct {
	mu      sync.Mutex
	path    string
	scope   StateScope
	entries []HardenEntry
}

func newHardenRecorder(path string, scope StateScope, entries []HardenEntry) *hardenRecorder {
	return &hardenRecorder{path: path, scope: scope, entries: entries}
}

func (r *hardenRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// record stores a pending change before the API mutation starts.
func (r *hardenRecorder) record(e HardenEntry) (wasNew bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e.Phase = HardenPhasePending
	key := e.Repo + "\x00" + e.Control
	for i, existing := range r.entries {
		if existing.Repo+"\x00"+existing.Control == key {
			if existing.Prior == e.Prior && existing.Phase == HardenPhasePending {
				return false, nil
			}
			prev := r.entries[i]
			r.entries[i] = e
			if err := saveHardenState(r.path, r.scope, r.entries); err != nil {
				r.entries[i] = prev
				return false, err
			}
			return false, nil
		}
	}
	r.entries = append(r.entries, e)
	if err := saveHardenState(r.path, r.scope, r.entries); err != nil {
		r.entries = r.entries[:len(r.entries)-1]
		return false, err
	}
	return true, nil
}

func (r *hardenRecorder) setPhase(e HardenEntry, phase HardenPhase) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := e.Repo + "\x00" + e.Control
	for i, existing := range r.entries {
		if existing.Repo+"\x00"+existing.Control == key {
			previous := r.entries[i].Phase
			r.entries[i].Phase = phase
			if err := saveHardenState(r.path, r.scope, r.entries); err != nil {
				r.entries[i].Phase = previous
				return err
			}
			return nil
		}
	}
	return fmt.Errorf("state entry disappeared for %s on %s", e.Control, e.Repo)
}

func (r *hardenRecorder) remove(e HardenEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := e.Repo + "\x00" + e.Control
	for i, existing := range r.entries {
		if existing.Repo+"\x00"+existing.Control != key {
			continue
		}
		previous := append([]HardenEntry(nil), r.entries...)
		r.entries = append(r.entries[:i], r.entries[i+1:]...)
		if err := saveHardenState(r.path, r.scope, r.entries); err != nil {
			r.entries = previous
			return err
		}
		return nil
	}
	return nil
}

func collectHarden(ctx context.Context, c *github.Client, o *opts, repos []*github.Repository, recorder *hardenRecorder) (applied, skipped, failed int, err error) {
	controls, err := selectedControls(o)
	if err != nil {
		return 0, 0, 0, err
	}
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(o.concurrency)
	for _, r := range repos {
		g.Go(func() error {
			owner, name := splitRepo(r.GetFullName())
			for _, ctl := range controls {
				if ctl.Apply == nil { // report-only, skip
					continue
				}
				res := ctl.Detect(gctx, c, owner, name, r)
				switch res.Status {
				case StatusCompliant: // already good, nothing to do
					continue
				case StatusSkipped:
					mu.Lock()
					skipped++
					fmt.Printf("%-6s %s :: %s (%s)\n", actionLabel(o, "skip"), r.GetFullName(), ctl.Key, sanitizeDetail(res.Detail))
					mu.Unlock()
					continue
				case StatusError:
					mu.Lock()
					failed++
					fmt.Fprintf(os.Stderr, "  %s %s :: %s: %s\n", actionLabel(o, "ERROR"), r.GetFullName(), ctl.Key, sanitizeDetail(res.Detail))
					mu.Unlock()
					continue
				}
				// StatusGap
				hint := ""
				if res.Prior != "" && !strings.HasPrefix(res.Prior, "{") {
					hint = "  (was: " + res.Prior + ")"
				}
				mu.Lock()
				fmt.Printf("%s %s :: %s%s\n", actionLabel(o, "harden"), r.GetFullName(), ctl.Key, hint)
				if o.dryRun {
					applied++ // count gaps that would be hardened
					mu.Unlock()
					continue
				}
				mu.Unlock()
				if recorder == nil {
					return fmt.Errorf("harden recorder is required when not in dry-run mode")
				}
				entry := HardenEntry{Repo: r.GetFullName(), Control: ctl.Key, Prior: res.Prior}
				_, rerr := recorder.record(entry)
				if rerr != nil {
					mu.Lock()
					failed++
					fmt.Fprintf(os.Stderr, "  %s %s :: %s: save state before apply: %v\n", actionLabel(o, "FAILED"), r.GetFullName(), ctl.Key, rerr)
					mu.Unlock()
					continue
				}
				if err := ctl.Apply(gctx, c, owner, name); err != nil {
					after := ctl.Detect(gctx, c, owner, name, r)
					switch {
					case after.Status == StatusCompliant:
						if serr := recorder.setPhase(entry, HardenPhaseApplied); serr != nil {
							err = errors.Join(err, fmt.Errorf("mark applied state: %w", serr))
						}
					case after.Status == StatusGap && after.Prior == entry.Prior:
						if serr := recorder.remove(entry); serr != nil {
							err = errors.Join(err, fmt.Errorf("remove unchanged pending state: %w", serr))
						}
					case after.Status == StatusGap:
						if rerr := ctl.Revert(gctx, c, owner, name, entry.Prior); rerr == nil {
							if serr := recorder.remove(entry); serr != nil {
								err = errors.Join(err, fmt.Errorf("remove compensated state: %w", serr))
							}
						} else {
							_ = recorder.setPhase(entry, HardenPhaseUnknown)
							err = errors.Join(err, fmt.Errorf("compensating rollback failed: %w", rerr))
						}
					default:
						_ = recorder.setPhase(entry, HardenPhaseUnknown)
					}
					mu.Lock()
					failed++
					fmt.Fprintf(os.Stderr, "  %s %s :: %s: %v\n", actionLabel(o, "FAILED"), r.GetFullName(), ctl.Key, err)
					mu.Unlock()
					continue
				}
				if err := recorder.setPhase(entry, HardenPhaseApplied); err != nil {
					mu.Lock()
					failed++
					fmt.Fprintf(os.Stderr, "  %s %s :: %s: mutation succeeded but state update failed: %v\n", actionLabel(o, "FAILED"), r.GetFullName(), ctl.Key, err)
					mu.Unlock()
					continue
				}
				mu.Lock()
				applied++
				mu.Unlock()
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return 0, 0, 0, err
	}
	return applied, skipped, failed, nil
}

func cmdHarden(ctx context.Context, c *github.Client, o *opts) error {
	repos, err := listRepos(ctx, c, o)
	if err != nil {
		return err
	}
	if o.dryRun {
		would, skipped, failed, err := collectHarden(ctx, c, o, repos, nil)
		if err != nil {
			return err
		}
		fmt.Printf("\ndry-run: would harden %d gaps (%d skipped, %d detection errors)\n", would, skipped, failed)
		if failed > 0 {
			return exitError(1)
		}
		return nil
	}
	path, err := hardenStateFilePath(o)
	if err != nil {
		return err
	}
	scope, err := githubStateScope(ctx, c, o)
	if err != nil {
		return err
	}
	unlock, err := lockStateFile(ctx, path)
	if err != nil {
		return err
	}
	defer func() { _ = unlock() }()
	existing, err := loadHardenState(path, scope)
	if err != nil {
		return err
	}
	recorder := newHardenRecorder(path, scope, existing)
	applied, skipped, failed, err := collectHarden(ctx, c, o, repos, recorder)
	if err != nil {
		return err
	}
	fmt.Printf("\nhardened %d settings (%d skipped, %d failed); state has %d entries: %s\n",
		applied, skipped, failed, recorder.count(), path)
	if failed > 0 {
		return exitError(1)
	}
	return nil
}

// scopeEntries splits entries into revert/keep by control and repository filters.
func scopeEntries(entries []HardenEntry, o *opts) (toRevert, kept []HardenEntry, err error) {
	onlySet := splitSet(o.only)
	skipSet := splitSet(o.skip)
	repos, err := requestedRepoSet(o.repo)
	if err != nil {
		return nil, nil, err
	}
	for _, e := range entries {
		owner, _ := splitRepo(e.Repo)
		outOfRepoScope := o.owner != "" && !strings.EqualFold(owner, o.owner)
		if len(repos) > 0 && !repos[strings.ToLower(e.Repo)] {
			outOfRepoScope = true
		}
		if outOfRepoScope || (len(onlySet) > 0 && !onlySet[e.Control]) || skipSet[e.Control] {
			kept = append(kept, e)
			continue
		}
		toRevert = append(toRevert, e)
	}
	return toRevert, kept, nil
}

func controlMap() map[string]Control {
	m := make(map[string]Control, len(baseline))
	for _, c := range baseline {
		m[c.Key] = c
	}
	return m
}

func matchesHardenedState(ctl Control, result DetectResult) bool {
	if ctl.MatchesHardened != nil {
		return ctl.MatchesHardened(result)
	}
	return result.Status == StatusCompliant
}

// revertEntries reverts each entry; returns the ones that failed so we can re-save them.
func revertEntries(ctx context.Context, c *github.Client, o *opts, entries []HardenEntry) []HardenEntry {
	cm := controlMap()
	var mu sync.Mutex
	var remaining []HardenEntry
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(o.concurrency)
	for _, e := range entries {
		g.Go(func() error {
			ctl, ok := cm[e.Control]
			owner, name := splitRepo(e.Repo)
			mu.Lock()
			fmt.Printf("%s %s :: %s\n", actionLabel(o, "revert"), e.Repo, e.Control)
			mu.Unlock()
			if !ok || ctl.Revert == nil {
				mu.Lock()
				remaining = append(remaining, e)
				fmt.Fprintf(os.Stderr, "  %s unknown/report-only control %q\n", actionLabel(o, "skip"), e.Control)
				mu.Unlock()
				return nil
			}
			repo, _, err := c.Repositories.Get(gctx, owner, name)
			if err != nil {
				mu.Lock()
				remaining = append(remaining, e)
				fmt.Fprintf(os.Stderr, "  %s %s :: %s: verify live state before revert: %v\n", actionLabel(o, "FAILED"), e.Repo, e.Control, err)
				mu.Unlock()
				return nil
			}
			current := ctl.Detect(gctx, c, owner, name, repo)
			if current.Status == StatusGap && current.Prior == e.Prior {
				return nil // already restored or the recorded mutation never took effect
			}
			if !matchesHardenedState(ctl, current) {
				mu.Lock()
				remaining = append(remaining, e)
				fmt.Fprintf(os.Stderr, "  %s %s :: %s: live setting drifted; refusing to overwrite it (%s: %s)\n",
					actionLabel(o, "FAILED"), e.Repo, e.Control, current.Status, sanitizeDetail(current.Detail))
				mu.Unlock()
				return nil
			}
			if o.dryRun {
				return nil
			}
			err = ctl.Revert(gctx, c, owner, name, e.Prior)
			mu.Lock()
			if err != nil {
				remaining = append(remaining, e)
				fmt.Fprintf(os.Stderr, "  %s %s :: %s: %v\n", actionLabel(o, "FAILED"), e.Repo, e.Control, err)
			}
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait() // goroutines never error, failures go in remaining

	return remaining
}

func cmdRevert(ctx context.Context, c *github.Client, o *opts) error {
	if err := validateControlSelection(o.only, o.skip); err != nil {
		return usageError{err}
	}
	path, err := hardenStateFilePath(o)
	if err != nil {
		return err
	}
	scope, err := githubStateScope(ctx, c, o)
	if err != nil {
		return err
	}
	unlock, err := lockStateFile(ctx, path)
	if err != nil {
		return err
	}
	defer func() { _ = unlock() }()
	entries, err := loadHardenState(path, scope)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("harden-state empty or missing: %s — run harden first", path)
	}
	toRevert, kept, err := scopeEntries(entries, o)
	if err != nil {
		return usageError{err}
	}
	if len(toRevert) == 0 {
		return usageErr("no harden-state entries match the requested repository/control scope")
	}
	remaining := revertEntries(ctx, c, o, toRevert)
	if o.dryRun {
		fmt.Printf("\ndry-run: would revert %d changes (%d blocked by drift/errors, %d kept out of scope)\n",
			len(toRevert)-len(remaining), len(remaining), len(kept))
		if len(remaining) > 0 {
			return exitError(1)
		}
		return nil
	}
	finalState := append(kept, remaining...)
	if err := saveHardenState(path, scope, finalState); err != nil {
		return err
	}
	fmt.Printf("\nreverted %d changes (%d failed, %d kept out of scope; remaining state: %d)\n",
		len(toRevert)-len(remaining), len(remaining), len(kept), len(finalState))
	if len(remaining) > 0 {
		return exitError(1)
	}
	return nil
}
