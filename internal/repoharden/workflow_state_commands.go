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

func cmdDisableAll(ctx context.Context, c *github.Client, o *opts) error {
	repos, err := listRepos(ctx, c, o)
	if err != nil {
		return err
	}
	stopSpinner()

	var statePath string
	if o.dryRun {
		statePath, err = stateFilePathReadOnly(o)
	} else {
		statePath, err = stateFilePath(o)
	}
	if err != nil {
		return err
	}
	scope, err := githubStateScope(ctx, c, o)
	if err != nil {
		return err
	}
	if !o.dryRun {
		unlock, err := lockStateFile(ctx, statePath)
		if err != nil {
			return err
		}
		defer func() { _ = unlock() }()
	}
	existing, err := loadState(statePath, scope)
	if err != nil {
		return err
	}
	have := make(map[string]bool, len(existing))
	for _, e := range existing {
		have[entryKey(e.Repo, e.ID)] = true
	}

	type target struct {
		owner, name string
		id          int64
		entry       StateEntry
	}
	var (
		mu         sync.Mutex
		targets    []target
		added      []StateEntry
		skipped    int
		repoErrors int
	)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(o.concurrency)
	for _, r := range repos {
		g.Go(func() error {
			owner, name := splitRepo(r.GetFullName())
			wfs, err := listWorkflows(gctx, c, owner, name)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: %s: %s\n", r.GetFullName(), sanitizeDetail(err.Error()))
				mu.Lock()
				repoErrors++
				mu.Unlock()
				return nil
			}
			for _, wf := range wfs {
				if wf.GetState() != "active" {
					continue
				}
				if skipWorkflow(wf, o) {
					mu.Lock()
					skipped++
					mu.Unlock()
					continue
				}
				e := StateEntry{
					Repo: r.GetFullName(), ID: wf.GetID(), Name: wf.GetName(), Path: wf.GetPath(),
					Phase: ActionPhasePending,
				}
				mu.Lock()
				targets = append(targets, target{owner, name, wf.GetID(), e})
				if !have[entryKey(e.Repo, e.ID)] {
					added = append(added, e)
					have[entryKey(e.Repo, e.ID)] = true
				}
				mu.Unlock()
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	if o.dryRun {
		fmt.Printf("\ndry-run: would disable %d workflows (%d new state entries, %d dynamic skipped, %d repos unreadable)\n",
			len(targets), len(added), skipped, repoErrors)
		if repoErrors > 0 {
			return exitError(1)
		}
		return nil
	}

	merged := append(existing, added...)
	if err := saveState(statePath, scope, merged); err != nil {
		return err
	}

	var (
		mu2      sync.Mutex
		changed  int
		failed   int
		outcomes = map[string]ActionPhase{}
	)
	g2, gctx2 := errgroup.WithContext(ctx)
	g2.SetLimit(o.concurrency)
	for _, t := range targets {
		g2.Go(func() error {
			mu2.Lock()
			fmt.Printf("%-7s %s :: %s\n", actionLabel(o, "disable"), t.entry.Repo, sanitizeDetail(t.entry.Name))
			mu2.Unlock()
			if _, err := c.Actions.DisableWorkflowByID(gctx2, t.owner, t.name, t.id); err != nil {
				mu2.Lock()
				failed++
				outcomes[entryKey(t.entry.Repo, t.entry.ID)] = ActionPhaseUnknown
				fmt.Fprintf(os.Stderr, "  FAILED: %s :: %s: %s\n", t.entry.Repo, sanitizeDetail(t.entry.Name), sanitizeDetail(err.Error()))
				mu2.Unlock()
				return nil
			}
			mu2.Lock()
			changed++
			outcomes[entryKey(t.entry.Repo, t.entry.ID)] = ActionPhaseApplied
			mu2.Unlock()
			return nil
		})
	}
	_ = g2.Wait()
	for i := range merged {
		if phase, ok := outcomes[entryKey(merged[i].Repo, merged[i].ID)]; ok {
			merged[i].Phase = phase
		}
	}
	if err := saveState(statePath, scope, merged); err != nil {
		return fmt.Errorf("workflows were processed but final state could not be saved: %w", err)
	}

	fmt.Printf("\ndisabled %d workflows (%d new state entries, %d failed, %d dynamic skipped, %d repos unreadable); state has %d entries: %s\n",
		changed, len(added), failed, skipped, repoErrors, len(merged), statePath)
	if failed > 0 || repoErrors > 0 {
		return exitError(1)
	}
	return nil
}

func cmdEnableAll(ctx context.Context, c *github.Client, o *opts) error {
	var (
		statePath string
		err       error
	)
	if o.dryRun {
		statePath, err = stateFilePathReadOnly(o)
	} else {
		statePath, err = stateFilePath(o)
	}
	if err != nil {
		return err
	}
	scope, err := githubStateScope(ctx, c, o)
	if err != nil {
		return err
	}
	if !o.dryRun {
		unlock, err := lockStateFile(ctx, statePath)
		if err != nil {
			return err
		}
		defer func() { _ = unlock() }()
	}
	entries, err := loadState(statePath, scope)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("state file empty or missing: %s — run disable-all first, or use enable-all-disabled", statePath)
	}

	repos, err := requestedRepoSet(o.repo)
	if err != nil {
		return usageError{err}
	}
	var selected, kept []StateEntry
	for _, entry := range entries {
		owner, _ := splitRepo(entry.Repo)
		if (o.owner != "" && !strings.EqualFold(owner, o.owner)) ||
			(len(repos) > 0 && !repos[strings.ToLower(entry.Repo)]) {
			kept = append(kept, entry)
			continue
		}
		selected = append(selected, entry)
	}
	if len(selected) == 0 {
		return usageErr("no Actions state entries match the requested repository scope")
	}
	stopSpinner()

	var (
		mu         sync.Mutex
		ok         int
		reconciled int
		failed     []StateEntry
	)

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(o.concurrency)
	for _, e := range selected {
		g.Go(func() error {
			owner, name := splitRepo(e.Repo)
			if e.Phase != ActionPhaseApplied {
				workflow, _, err := c.Actions.GetWorkflowByID(gctx, owner, name, e.ID)
				if err != nil {
					mu.Lock()
					failed = append(failed, e)
					fmt.Fprintf(os.Stderr, "  FAILED: reconcile %s :: %s: %s\n", e.Repo, sanitizeDetail(e.Name), sanitizeDetail(err.Error()))
					mu.Unlock()
					return nil
				}
				if workflow.GetState() == "active" {
					mu.Lock()
					reconciled++
					mu.Unlock()
					return nil
				}
				if !strings.HasPrefix(workflow.GetState(), "disabled") {
					mu.Lock()
					failed = append(failed, e)
					fmt.Fprintf(os.Stderr, "  FAILED: reconcile %s :: %s: unexpected state %q\n",
						e.Repo, sanitizeDetail(e.Name), sanitizeDetail(workflow.GetState()))
					mu.Unlock()
					return nil
				}
			}
			mu.Lock()
			fmt.Printf("%-7s %s :: %s\n", actionLabel(o, "enable"), e.Repo, sanitizeDetail(e.Name))
			mu.Unlock()
			if o.dryRun {
				return nil
			}
			_, err := c.Actions.EnableWorkflowByID(gctx, owner, name, e.ID)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				fmt.Fprintf(os.Stderr, "  FAILED: %s\n", sanitizeDetail(err.Error()))
				failed = append(failed, e)
				return nil
			}
			ok++
			return nil
		})
	}
	_ = g.Wait()

	if o.dryRun {
		fmt.Printf("\ndry-run: would enable %d workflows (%d pending entries already active, %d state entries kept out of scope)\n",
			len(selected)-reconciled-len(failed), reconciled, len(kept))
		if len(failed) > 0 {
			return exitError(1)
		}
		return nil
	}

	finalState := append(kept, failed...)
	if err := saveState(statePath, scope, finalState); err != nil {
		return err
	}
	fmt.Printf("\nenabled %d workflows (%d pending entries already active, %d failed, %d kept out of scope; remaining state: %d)\n",
		ok, reconciled, len(failed), len(kept), len(finalState))
	if len(failed) > 0 {
		return exitError(1)
	}
	return nil
}
