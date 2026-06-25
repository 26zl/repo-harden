package repoharden

import (
	"context"
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
	entries []HardenEntry
}

func newHardenRecorder(path string, entries []HardenEntry) *hardenRecorder {
	return &hardenRecorder{path: path, entries: entries}
}

func (r *hardenRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

func (r *hardenRecorder) record(e HardenEntry) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := e.Repo + "\x00" + e.Control
	for i, existing := range r.entries {
		if existing.Repo+"\x00"+existing.Control == key {
			// update prior so revert uses the latest pre-change value
			if existing.Prior == e.Prior {
				return true, nil
			}
			prev := r.entries[i].Prior
			r.entries[i].Prior = e.Prior
			if err := saveHardenState(r.path, r.entries); err != nil {
				r.entries[i].Prior = prev
				return false, err
			}
			return true, nil
		}
	}
	r.entries = append(r.entries, e)
	if err := saveHardenState(r.path, r.entries); err != nil {
		r.entries = r.entries[:len(r.entries)-1]
		return false, err
	}
	return true, nil
}

// remove drops a recorded entry, e.g. after Apply fails.
func (r *hardenRecorder) remove(e HardenEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := e.Repo + "\x00" + e.Control
	for i, existing := range r.entries {
		if existing.Repo+"\x00"+existing.Control == key {
			r.entries = append(r.entries[:i], r.entries[i+1:]...)
			if err := saveHardenState(r.path, r.entries); err != nil {
				// if this didn't save, state still has an entry for a change that
				// never applied; warn so a later revert doesn't act on it.
				fmt.Fprintf(os.Stderr, "warn: could not update state after rolling back %s on %s: %v\n", e.Control, e.Repo, err)
			}
			return
		}
	}
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
		r := r
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
					fmt.Printf("%-6s %s :: %s (%s)\n", actionLabel(o, "skip"), r.GetFullName(), ctl.Key, res.Detail)
					mu.Unlock()
					continue
				case StatusError:
					mu.Lock()
					failed++
					fmt.Fprintf(os.Stderr, "  %s %s :: %s: %s\n", actionLabel(o, "ERROR"), r.GetFullName(), ctl.Key, res.Detail)
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
				mu.Unlock()
				if o.dryRun {
					continue
				}
				if recorder == nil {
					return fmt.Errorf("harden recorder is required when not in dry-run mode")
				}
				entry := HardenEntry{Repo: r.GetFullName(), Control: ctl.Key, Prior: res.Prior}
				if _, err := recorder.record(entry); err != nil {
					mu.Lock()
					failed++
					fmt.Fprintf(os.Stderr, "  %s %s :: %s: save state before apply: %v\n", actionLabel(o, "FAILED"), r.GetFullName(), ctl.Key, err)
					mu.Unlock()
					continue
				}
				if err := ctl.Apply(gctx, c, owner, name); err != nil {
					recorder.remove(entry) // apply failed, drop the entry
					mu.Lock()
					failed++
					fmt.Fprintf(os.Stderr, "  %s %s :: %s: %v\n", actionLabel(o, "FAILED"), r.GetFullName(), ctl.Key, err)
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
		_, skipped, _, err := collectHarden(ctx, c, o, repos, nil)
		if err != nil {
			return err
		}
		fmt.Printf("\ndry-run: would harden gaps (%d skipped for license)\n", skipped)
		return nil
	}
	path, err := hardenStateFilePath(o)
	if err != nil {
		return err
	}
	existing, err := loadHardenState(path)
	if err != nil {
		return err
	}
	recorder := newHardenRecorder(path, existing)
	applied, skipped, failed, err := collectHarden(ctx, c, o, repos, recorder)
	if err != nil {
		return err
	}
	fmt.Printf("\nhardened %d settings (%d skipped license, %d failed); state has %d entries: %s\n",
		applied, skipped, failed, recorder.count(), path)
	if failed > 0 {
		return exitError(1)
	}
	return nil
}

// scopeEntries splits entries into revert/keep by --only/--skip.
func scopeEntries(entries []HardenEntry, only, skip string) (toRevert, kept []HardenEntry) {
	onlySet := splitSet(only)
	skipSet := splitSet(skip)
	for _, e := range entries {
		if (len(onlySet) > 0 && !onlySet[e.Control]) || skipSet[e.Control] {
			kept = append(kept, e)
			continue
		}
		toRevert = append(toRevert, e)
	}
	return toRevert, kept
}

func controlMap() map[string]Control {
	m := make(map[string]Control, len(baseline))
	for _, c := range baseline {
		m[c.Key] = c
	}
	return m
}

// revertEntries reverts each entry; returns the ones that failed so we can re-save them.
func revertEntries(ctx context.Context, c *github.Client, o *opts, entries []HardenEntry) []HardenEntry {
	cm := controlMap()
	var mu sync.Mutex
	var remaining []HardenEntry
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(o.concurrency)
	for _, e := range entries {
		e := e
		g.Go(func() error {
			ctl, ok := cm[e.Control]
			owner, name := splitRepo(e.Repo)
			mu.Lock()
			fmt.Printf("%s %s :: %s\n", actionLabel(o, "revert"), e.Repo, e.Control)
			mu.Unlock()
			if o.dryRun {
				return nil
			}
			if !ok || ctl.Revert == nil {
				mu.Lock()
				remaining = append(remaining, e)
				fmt.Fprintf(os.Stderr, "  %s unknown/report-only control %q\n", actionLabel(o, "skip"), e.Control)
				mu.Unlock()
				return nil
			}
			err := ctl.Revert(gctx, c, owner, name, e.Prior)
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
		return err
	}
	path, err := hardenStateFilePath(o)
	if err != nil {
		return err
	}
	entries, err := loadHardenState(path)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("harden-state empty or missing: %s — run harden first", path)
	}
	toRevert, kept := scopeEntries(entries, o.only, o.skip)
	remaining := revertEntries(ctx, c, o, toRevert)
	if o.dryRun {
		fmt.Printf("\ndry-run: would revert %d changes (%d kept out of scope)\n", len(toRevert), len(kept))
		return nil
	}
	finalState := append(kept, remaining...)
	if err := saveHardenState(path, finalState); err != nil {
		return err
	}
	fmt.Printf("\nreverted %d changes (%d failed, %d kept out of scope; remaining state: %d)\n",
		len(toRevert)-len(remaining), len(remaining), len(kept), len(finalState))
	if len(remaining) > 0 {
		return exitError(1)
	}
	return nil
}
