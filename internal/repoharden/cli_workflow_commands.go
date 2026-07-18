package repoharden

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/google/go-github/v88/github"
	"golang.org/x/sync/errgroup"
)

type listRow struct {
	State string `json:"state"`
	Repo  string `json:"repo"`
	Name  string `json:"name"`
	Path  string `json:"path"`
}

func collectRows(ctx context.Context, c *github.Client, o *opts, repos []*github.Repository) ([]listRow, int, error) {
	stopSpinner()
	var (
		mu         sync.Mutex
		rows       []listRow
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
			mu.Lock()
			for _, wf := range wfs {
				rows = append(rows, listRow{wf.GetState(), r.GetFullName(), wf.GetName(), wf.GetPath()})
			}
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, 0, err
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Repo != rows[j].Repo {
			return rows[i].Repo < rows[j].Repo
		}
		return rows[i].Name < rows[j].Name
	})
	return rows, repoErrors, nil
}

func cmdList(ctx context.Context, c *github.Client, o *opts) error {
	repos, err := listRepos(ctx, c, o)
	if err != nil {
		return err
	}
	rows, repoErrors, err := collectRows(ctx, c, o, repos)
	if err != nil {
		return err
	}
	if o.jsonOut {
		if err := json.NewEncoder(os.Stdout).Encode(rows); err != nil {
			return err
		}
		if repoErrors > 0 {
			return exitError(1)
		}
		return nil
	}
	fmt.Println("STATE\tREPO\tWORKFLOW\tPATH")
	for _, r := range rows {
		fmt.Printf("%s\t%s\t%s\t%s\n", workflowStateLabel(o, r.State), r.Repo, sanitizeDetail(r.Name), sanitizeDetail(r.Path))
	}
	if repoErrors > 0 {
		fmt.Fprintf(os.Stderr, "\n%d repo(s) could not be read\n", repoErrors)
		return exitError(1)
	}
	return nil
}

func cmdEnableAllDisabled(ctx context.Context, c *github.Client, o *opts) error {
	repos, err := listRepos(ctx, c, o)
	if err != nil {
		return err
	}
	stopSpinner()
	var (
		mu         sync.Mutex
		changed    int
		failed     int
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
				if !strings.HasPrefix(wf.GetState(), "disabled") {
					continue
				}
				if skipWorkflow(wf, o) {
					continue
				}
				fmt.Printf("%-7s %s :: %s (%s)\n", actionLabel(o, "enable"), r.GetFullName(), sanitizeDetail(wf.GetName()), workflowStateLabel(o, wf.GetState()))
				if o.dryRun {
					mu.Lock()
					changed++
					mu.Unlock()
					continue
				}
				if _, err := c.Actions.EnableWorkflowByID(gctx, owner, name, wf.GetID()); err != nil {
					fmt.Fprintf(os.Stderr, "  FAILED: %s\n", sanitizeDetail(err.Error()))
					mu.Lock()
					failed++
					mu.Unlock()
					continue
				}
				mu.Lock()
				changed++
				mu.Unlock()
			}
			return nil
		})
	}
	_ = g.Wait()
	if o.dryRun {
		fmt.Printf("\ndry-run: would enable %d workflows (%d repos unreadable)\n", changed, repoErrors)
		if repoErrors > 0 {
			return exitError(1)
		}
		return nil
	}
	fmt.Printf("\nenabled %d workflows (%d failed, %d repos unreadable)\n", changed, failed, repoErrors)
	if failed > 0 || repoErrors > 0 {
		return exitError(1)
	}
	return nil
}

func cmdToggleRepo(ctx context.Context, c *github.Client, o *opts, args []string, action string) error {
	if len(args) != 1 {
		return usageErr("usage: repo-harden %s-repo <owner/repo>", action)
	}
	owner, name := splitRepo(args[0])
	if owner == "" || name == "" {
		return usageErr("invalid repo %q (expected owner/repo)", args[0])
	}
	repo, _, err := c.Repositories.Get(ctx, owner, name)
	if err != nil {
		return fmt.Errorf("read repository %s: %w", args[0], err)
	}
	if reason := repositoryExclusionReason(repo, o); reason != "" {
		return fmt.Errorf("requested repository %s is excluded: %s", args[0], reason)
	}
	wfs, err := listWorkflows(ctx, c, owner, name)
	if err != nil {
		return err
	}
	stopSpinner()

	wantState := "active"
	if action == "enable" {
		wantState = "disabled"
	}

	count, failed := 0, 0
	for _, wf := range wfs {
		state := wf.GetState()
		match := state == wantState
		if action == "enable" {
			match = strings.HasPrefix(state, "disabled")
		}
		if !match {
			continue
		}
		if skipWorkflow(wf, o) {
			continue
		}
		fmt.Printf("%-7s %s/%s :: %s\n", actionLabel(o, action), owner, name, sanitizeDetail(wf.GetName()))
		if o.dryRun {
			count++
			continue
		}
		var apiErr error
		if action == "disable" {
			_, apiErr = c.Actions.DisableWorkflowByID(ctx, owner, name, wf.GetID())
		} else {
			_, apiErr = c.Actions.EnableWorkflowByID(ctx, owner, name, wf.GetID())
		}
		if apiErr != nil {
			fmt.Fprintf(os.Stderr, "  FAILED: %s\n", sanitizeDetail(apiErr.Error()))
			failed++
			continue
		}
		count++
	}
	if o.dryRun {
		fmt.Printf("\ndry-run: would %s %d workflows\n", action, count)
		return nil
	}
	fmt.Printf("\n%sd %d workflows (%d failed)\n", action, count, failed)
	if failed > 0 {
		return exitError(1)
	}
	return nil
}

type statusOutput struct {
	User   string         `json:"user"`
	Repos  int            `json:"repos"`
	States map[string]int `json:"states"`
}

func cmdStatus(ctx context.Context, c *github.Client, o *opts) error {
	user, _, err := c.Users.Get(ctx, "")
	if err != nil {
		return err
	}
	out := statusOutput{User: user.GetLogin(), States: map[string]int{}}

	repos, err := listRepos(ctx, c, o)
	if err != nil {
		return err
	}
	out.Repos = len(repos)
	rows, repoErrors, err := collectRows(ctx, c, o, repos)
	if err != nil {
		return err
	}
	for _, r := range rows {
		out.States[r.State]++
	}

	if o.jsonOut {
		if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
			return err
		}
		if repoErrors > 0 {
			return exitError(1)
		}
		return nil
	}

	fmt.Println("user:", out.User)
	fmt.Println()
	fmt.Printf("Repos scanned: %d\n", out.Repos)
	fmt.Println("Workflows by state:")
	keys := make([]string, 0, len(out.States))
	for k := range out.States {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-20s %d\n", workflowStateLabel(o, k)+":", out.States[k])
	}
	if repoErrors > 0 {
		fmt.Fprintf(os.Stderr, "\n%d repo(s) could not be read\n", repoErrors)
		return exitError(1)
	}
	return nil
}
