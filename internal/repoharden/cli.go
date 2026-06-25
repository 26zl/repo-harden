package repoharden

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/cli/go-gh/v2/pkg/auth"
	"github.com/google/go-github/v88/github"
	"golang.org/x/sync/errgroup"
)

const defaultConcurrency = 8

const dynamicPrefix = "dynamic/"

type opts struct {
	dryRun          bool
	owner           string
	includeForks    bool
	includeDynamic  bool
	includeArchived bool
	adminOnly       bool
	concurrency     int
	jsonOut         bool
	color           string
	noColor         bool
	provider        string
	host            string
	token           string
	format          string
	exitCode        bool
	orgAudit        bool
	staleDays       int
	stateFile       string
	only            string
	skip            string
}

func Main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	cmd := os.Args[1]

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	o := &opts{concurrency: defaultConcurrency}
	fs.BoolVar(&o.dryRun, "dry-run", false, "")
	fs.StringVar(&o.owner, "owner", "", "")
	fs.BoolVar(&o.includeForks, "include-forks", false, "")
	fs.BoolVar(&o.includeDynamic, "include-dynamic", false, "")
	fs.BoolVar(&o.includeArchived, "include-archived", false, "")
	fs.BoolVar(&o.adminOnly, "admin-only", false, "")
	fs.IntVar(&o.concurrency, "concurrency", defaultConcurrency, "")
	fs.BoolVar(&o.jsonOut, "json", false, "")
	fs.StringVar(&o.color, "color", "auto", "")
	fs.BoolVar(&o.noColor, "no-color", false, "")
	fs.StringVar(&o.provider, "provider", "github", "")
	fs.StringVar(&o.host, "host", "", "")
	fs.StringVar(&o.token, "token", "", "")
	fs.StringVar(&o.format, "format", "table", "")
	fs.BoolVar(&o.exitCode, "exit-code", false, "")
	fs.BoolVar(&o.orgAudit, "org-audit", true, "")
	fs.IntVar(&o.staleDays, "stale-days", 180, "")
	fs.StringVar(&o.stateFile, "state-file", "", "")
	fs.StringVar(&o.only, "only", "", "")
	fs.StringVar(&o.skip, "skip", "", "")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	if o.concurrency < 1 {
		o.concurrency = 1
	}
	if err := validateColorMode(o.color); err != nil {
		die(err)
	}
	normalizeOptions(o)
	if err := validateOptions(o); err != nil {
		die(err)
	}
	args := fs.Args()
	ctx := context.Background()

	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		usage()
		return
	}
	if cmd != "audit" && o.provider != "github" {
		die(fmt.Errorf("%s currently supports --provider github only; use audit for %s", cmd, o.provider))
	}

	var client *github.Client
	var err error
	if commandNeedsGitHubClient(cmd, o) {
		client, err = newClient(o)
		if err != nil {
			die(err)
		}
	}

	switch cmd {
	case "list":
		err = cmdList(ctx, client, o)
	case "disable-all":
		err = cmdDisableAll(ctx, client, o)
	case "enable-all":
		err = cmdEnableAll(ctx, client, o)
	case "enable-all-disabled":
		err = cmdEnableAllDisabled(ctx, client, o)
	case "disable-repo":
		err = cmdToggleRepo(ctx, client, o, args, "disable")
	case "enable-repo":
		err = cmdToggleRepo(ctx, client, o, args, "enable")
	case "status":
		err = cmdStatus(ctx, client, o)
	case "audit":
		err = cmdAudit(ctx, client, o)
	case "harden":
		err = cmdHarden(ctx, client, o)
	case "revert":
		err = cmdRevert(ctx, client, o)
	case "controls":
		err = cmdControls(o)
	default:
		usage()
		os.Exit(1)
	}
	if err != nil {
		var code exitError
		if errors.As(err, &code) {
			os.Exit(int(code))
		}
		die(err)
	}
}

func usage() {
	printUsageBanner()
	fmt.Print(`Usage: repo-harden <command> [options]

Commands:
  list                       List all workflows across all your repos
  disable-all                Disable every active workflow, save state file
  enable-all                 Re-enable workflows from saved state file
  enable-all-disabled        Re-enable EVERY currently-disabled workflow
  disable-repo <owner/repo>  Disable all active workflows in one repo
  enable-repo  <owner/repo>  Re-enable all disabled workflows in one repo
  status                     Show workflow counts by state across repos
  audit                      Scan all repos against the hardening baseline
  harden                     Apply the safe/free hardening, save revert state
  revert                     Undo exactly what harden changed
  controls                   List baseline controls (fixable + reversible)
  help                       Show this help

Options:
  --dry-run                  Print actions without calling the API
  --owner <login>            Only touch repos owned by this user/org
  --include-forks            Include forked repos (default: skipped)
  --include-archived         Include archived repos in audit/list operations
  --admin-only               Only repos you can administer (avoids 403 noise)
  --include-dynamic          Include dynamic/ workflows (CodeQL, Dependabot,
                             Copilot — these always 422 on toggle, so are
                             skipped by default)
  --concurrency <n>          Parallel API calls (default: 8)
  --json                     Emit JSON (list, status, audit)
  --format <fmt>             audit output: table, json, markdown, sarif
  --color <mode>             Color output: auto, always, never (default: auto)
  --no-color                 Disable color (same as --color never / NO_COLOR)
  --provider <name>          audit provider: github, gitlab, gitea, forgejo
  --host <host-or-url>       Provider host (GitHub Enterprise, GitLab, Gitea)
  --token <token>            Provider token (prefer env vars in scripts)
  --exit-code                audit exits 1 when gaps/errors are found
  --org-audit                Include GitHub organization-level checks (default)
  --stale-days <n>           Stale repository threshold (default: 180)
  --state-file <path>        Override default state file location
  --only <keys>              Only run these controls (comma-separated keys)
  --skip <keys>              Skip these controls (comma-separated keys)

Env:
  REPO_HARDEN_STATE_DIR              State directory (default: ~/.repo-harden)
  GITHUB_TOKEN               GitHub/GHES token fallback
  GITLAB_TOKEN               GitLab token fallback
  GITEA_TOKEN                Gitea token fallback
  FORGEJO_TOKEN              Forgejo token fallback
`)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func commandNeedsGitHubClient(cmd string, o *opts) bool {
	if cmd == "controls" {
		return false
	}
	if cmd == "audit" {
		return o.provider == "github"
	}
	return true
}

func normalizeOptions(o *opts) {
	o.provider = strings.ToLower(strings.TrimSpace(o.provider))
	if o.provider == "" {
		o.provider = "github"
	}
	if o.host == "" {
		o.host = defaultProviderHost(o.provider)
	}
	o.format = strings.ToLower(strings.TrimSpace(o.format))
	if o.jsonOut {
		o.format = "json"
	}
	if o.format == "" {
		o.format = "table"
	}
}

func validateOptions(o *opts) error {
	switch o.provider {
	case "github", "gitlab", "gitea", "forgejo":
	default:
		return fmt.Errorf("invalid --provider %q (expected github, gitlab, gitea, or forgejo)", o.provider)
	}
	switch o.format {
	case "table", "json", "markdown", "sarif":
	default:
		return fmt.Errorf("invalid --format %q (expected table, json, markdown, or sarif)", o.format)
	}
	if o.staleDays < 1 {
		return fmt.Errorf("--stale-days must be >= 1")
	}
	return nil
}

func defaultProviderHost(provider string) string {
	switch provider {
	case "gitlab":
		return "gitlab.com"
	case "gitea", "forgejo":
		return "http://localhost:3000"
	default:
		return "github.com"
	}
}

func tokenFromEnv(provider string) string {
	switch provider {
	case "gitlab":
		return os.Getenv("GITLAB_TOKEN")
	case "gitea":
		return os.Getenv("GITEA_TOKEN")
	case "forgejo":
		if token := os.Getenv("FORGEJO_TOKEN"); token != "" {
			return token
		}
		return os.Getenv("GITEA_TOKEN")
	default:
		return os.Getenv("GITHUB_TOKEN")
	}
}

func newClient(o *opts) (*github.Client, error) {
	host := hostName(o.host)
	token := strings.TrimSpace(o.token)
	if token == "" {
		token, _ = auth.TokenForHost(host)
	}
	if token == "" {
		token = tokenFromEnv("github")
	}
	if token == "" {
		return nil, fmt.Errorf("no GitHub token found for %s - run: gh auth login --hostname %s or set GITHUB_TOKEN", host, host)
	}
	if host == "github.com" {
		return github.NewClient(github.WithAuthToken(token))
	}
	apiURL, uploadURL := githubEnterpriseURLs(o.host)
	if err := requireSecureURL(apiURL); err != nil {
		return nil, err
	}
	return github.NewClient(github.WithAuthToken(token), github.WithEnterpriseURLs(apiURL, uploadURL))
}

func hostName(hostOrURL string) string {
	raw := strings.TrimSpace(hostOrURL)
	if raw == "" {
		return "github.com"
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.TrimPrefix(strings.TrimPrefix(hostOrURL, "https://"), "http://")
	}
	return u.Host
}

func providerBaseURL(provider, hostOrURL string) string {
	raw := strings.TrimRight(strings.TrimSpace(hostOrURL), "/")
	if raw == "" {
		raw = defaultProviderHost(provider)
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	return raw
}

func githubEnterpriseURLs(hostOrURL string) (string, string) {
	base := providerBaseURL("github", hostOrURL)
	return strings.TrimRight(base, "/") + "/api/v3/", strings.TrimRight(base, "/") + "/api/uploads/"
}

func splitRepo(fullName string) (owner, name string) {
	i := strings.IndexByte(fullName, '/')
	if i < 0 {
		return "", fullName
	}
	return fullName[:i], fullName[i+1:]
}

func skipWorkflow(wf *github.Workflow, o *opts) bool {
	if o.includeDynamic {
		return false
	}
	return strings.HasPrefix(wf.GetPath(), dynamicPrefix)
}

func listRepos(ctx context.Context, c *github.Client, o *opts) ([]*github.Repository, error) {
	var all []*github.Repository
	opts := &github.RepositoryListByAuthenticatedUserOptions{
		Affiliation: "owner,collaborator,organization_member",
		Visibility:  "all",
		ListOptions: github.ListOptions{PerPage: 100},
	}
	for {
		repos, resp, err := c.Repositories.ListByAuthenticatedUser(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("list repos: %w", err)
		}
		all = append(all, repos...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	out := all[:0]
	for _, r := range all {
		if o.owner != "" && !strings.EqualFold(r.GetOwner().GetLogin(), o.owner) {
			continue
		}
		if r.GetArchived() && !o.includeArchived {
			continue
		}
		if r.GetFork() && !o.includeForks {
			continue
		}
		if o.adminOnly && !r.GetPermissions().GetAdmin() {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetFullName() < out[j].GetFullName() })
	return out, nil
}

func listWorkflows(ctx context.Context, c *github.Client, owner, name string) ([]*github.Workflow, error) {
	var all []*github.Workflow
	opts := &github.ListOptions{PerPage: 100}
	for {
		wfs, resp, err := c.Actions.ListWorkflows(ctx, owner, name, opts)
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				return nil, nil
			}
			return nil, err
		}
		all = append(all, wfs.Workflows...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

type listRow struct {
	State string `json:"state"`
	Repo  string `json:"repo"`
	Name  string `json:"name"`
	Path  string `json:"path"`
}

func collectRows(ctx context.Context, c *github.Client, o *opts, repos []*github.Repository) ([]listRow, error) {
	var (
		mu   sync.Mutex
		rows []listRow
	)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(o.concurrency)
	for _, r := range repos {
		r := r
		g.Go(func() error {
			owner, name := splitRepo(r.GetFullName())
			wfs, err := listWorkflows(gctx, c, owner, name)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: %s: %v\n", r.GetFullName(), err)
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
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Repo != rows[j].Repo {
			return rows[i].Repo < rows[j].Repo
		}
		return rows[i].Name < rows[j].Name
	})
	return rows, nil
}

func cmdList(ctx context.Context, c *github.Client, o *opts) error {
	repos, err := listRepos(ctx, c, o)
	if err != nil {
		return err
	}
	rows, err := collectRows(ctx, c, o, repos)
	if err != nil {
		return err
	}
	if o.jsonOut {
		return json.NewEncoder(os.Stdout).Encode(rows)
	}
	fmt.Println("STATE\tREPO\tWORKFLOW\tPATH")
	for _, r := range rows {
		fmt.Printf("%s\t%s\t%s\t%s\n", workflowStateLabel(o, r.State), r.Repo, r.Name, r.Path)
	}
	return nil
}

func cmdDisableAll(ctx context.Context, c *github.Client, o *opts) error {
	repos, err := listRepos(ctx, c, o)
	if err != nil {
		return err
	}

	statePath, err := stateFilePath(o)
	if err != nil {
		return err
	}
	existing, err := loadState(statePath)
	if err != nil {
		return err
	}
	have := make(map[string]bool, len(existing))
	for _, e := range existing {
		have[entryKey(e.Repo, e.ID)] = true
	}

	var (
		mu      sync.Mutex
		added   []StateEntry
		changed int
		failed  int
		skipped int
	)

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(o.concurrency)
	for _, r := range repos {
		r := r
		g.Go(func() error {
			owner, name := splitRepo(r.GetFullName())
			wfs, err := listWorkflows(gctx, c, owner, name)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: %s: %v\n", r.GetFullName(), err)
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
				fmt.Printf("%-7s %s :: %s\n", actionLabel(o, "disable"), r.GetFullName(), wf.GetName())
				if !o.dryRun {
					if _, err := c.Actions.DisableWorkflowByID(gctx, owner, name, wf.GetID()); err != nil {
						fmt.Fprintf(os.Stderr, "  FAILED: %v\n", err)
						mu.Lock()
						failed++
						mu.Unlock()
						continue
					}
				}
				e := StateEntry{Repo: r.GetFullName(), ID: wf.GetID(), Name: wf.GetName(), Path: wf.GetPath()}
				mu.Lock()
				changed++
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
		fmt.Printf("\ndry-run: would disable %d workflows (%d new state entries, %d dynamic skipped)\n",
			changed, len(added), skipped)
		return nil
	}

	merged := append(existing, added...)
	if err := saveState(statePath, merged); err != nil {
		return err
	}
	fmt.Printf("\ndisabled %d workflows (%d new state entries, %d failed, %d dynamic skipped); state has %d entries: %s\n",
		changed, len(added), failed, skipped, len(merged), statePath)
	if failed > 0 {
		return exitError(1)
	}
	return nil
}

func cmdEnableAll(ctx context.Context, c *github.Client, o *opts) error {
	statePath, err := stateFilePath(o)
	if err != nil {
		return err
	}
	entries, err := loadState(statePath)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("state file empty or missing: %s — run disable-all first, or use enable-all-disabled", statePath)
	}

	var (
		mu     sync.Mutex
		ok     int
		failed []StateEntry
	)

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(o.concurrency)
	for _, e := range entries {
		e := e
		g.Go(func() error {
			owner, name := splitRepo(e.Repo)
			fmt.Printf("%-7s %s :: %s\n", actionLabel(o, "enable"), e.Repo, e.Name)
			if o.dryRun {
				return nil
			}
			_, err := c.Actions.EnableWorkflowByID(gctx, owner, name, e.ID)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				fmt.Fprintf(os.Stderr, "  FAILED: %v\n", err)
				failed = append(failed, e)
				return nil
			}
			ok++
			return nil
		})
	}
	_ = g.Wait()

	if o.dryRun {
		fmt.Printf("\ndry-run: would enable %d workflows\n", len(entries))
		return nil
	}

	if err := saveState(statePath, failed); err != nil {
		return err
	}
	fmt.Printf("\nenabled %d workflows (%d failed; remaining state: %d)\n", ok, len(failed), len(failed))
	if len(failed) > 0 {
		return exitError(1)
	}
	return nil
}

func cmdEnableAllDisabled(ctx context.Context, c *github.Client, o *opts) error {
	repos, err := listRepos(ctx, c, o)
	if err != nil {
		return err
	}
	var (
		mu      sync.Mutex
		changed int
		failed  int
	)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(o.concurrency)
	for _, r := range repos {
		r := r
		g.Go(func() error {
			owner, name := splitRepo(r.GetFullName())
			wfs, err := listWorkflows(gctx, c, owner, name)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: %s: %v\n", r.GetFullName(), err)
				return nil
			}
			for _, wf := range wfs {
				if !strings.HasPrefix(wf.GetState(), "disabled") {
					continue
				}
				if skipWorkflow(wf, o) {
					continue
				}
				fmt.Printf("%-7s %s :: %s (%s)\n", actionLabel(o, "enable"), r.GetFullName(), wf.GetName(), workflowStateLabel(o, wf.GetState()))
				if o.dryRun {
					mu.Lock()
					changed++
					mu.Unlock()
					continue
				}
				if _, err := c.Actions.EnableWorkflowByID(gctx, owner, name, wf.GetID()); err != nil {
					fmt.Fprintf(os.Stderr, "  FAILED: %v\n", err)
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
		fmt.Printf("\ndry-run: would enable %d workflows\n", changed)
		return nil
	}
	fmt.Printf("\nenabled %d workflows (%d failed)\n", changed, failed)
	if failed > 0 {
		return exitError(1)
	}
	return nil
}

func cmdToggleRepo(ctx context.Context, c *github.Client, o *opts, args []string, action string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: repo-harden %s-repo <owner/repo>", action)
	}
	owner, name := splitRepo(args[0])
	if owner == "" || name == "" {
		return fmt.Errorf("invalid repo %q (expected owner/repo)", args[0])
	}
	wfs, err := listWorkflows(ctx, c, owner, name)
	if err != nil {
		return err
	}

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
		fmt.Printf("%-7s %s/%s :: %s\n", actionLabel(o, action), owner, name, wf.GetName())
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
			fmt.Fprintf(os.Stderr, "  FAILED: %v\n", apiErr)
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
	rows, err := collectRows(ctx, c, o, repos)
	if err != nil {
		return err
	}
	for _, r := range rows {
		out.States[r.State]++
	}

	if o.jsonOut {
		return json.NewEncoder(os.Stdout).Encode(out)
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
	return nil
}
