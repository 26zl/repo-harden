package repoharden

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/cli/go-gh/v2/pkg/auth"
	"github.com/google/go-github/v88/github"
	"golang.org/x/sync/errgroup"
)

const (
	defaultConcurrency = 8
	maxConcurrency     = 64
)

const dynamicPrefix = "dynamic/"

// build info, overridden via -ldflags -X main.* by GoReleaser.
var (
	Version       = "dev"
	Commit        = "none"
	Date          = "unknown"
	buildInfoOnce sync.Once
)

type opts struct {
	dryRun          bool
	owner           string
	repo            string
	includeForks    bool
	includeDynamic  bool
	includeArchived bool
	adminOnly       bool
	concurrency     int
	jsonOut         bool
	all             bool
	color           string
	noColor         bool
	provider        string
	host            string
	token           string
	tokenStdin      bool
	format          string
	exitCode        bool
	failOnSkipped   bool
	orgAudit        bool
	staleDays       int
	stateFile       string
	only            string
	skip            string
	showIdentifiers bool
}

func Main() {
	hydrateBuildInfo()
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "repo-harden: no command given; run 'repo-harden help'")
		os.Exit(2)
	}
	cmd := os.Args[1]

	if cmd == "version" || cmd == "--version" || cmd == "-v" {
		fmt.Printf("repo-harden %s (commit %s, built %s)\n", Version, Commit, Date)
		return
	}

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.Usage = func() { usage(os.Stderr) }
	o := &opts{concurrency: defaultConcurrency}
	fs.BoolVar(&o.dryRun, "dry-run", false, "")
	fs.StringVar(&o.owner, "owner", "", "")
	fs.StringVar(&o.repo, "repo", "", "")
	fs.BoolVar(&o.includeForks, "include-forks", false, "")
	fs.BoolVar(&o.includeDynamic, "include-dynamic", false, "")
	fs.BoolVar(&o.includeArchived, "include-archived", false, "")
	fs.BoolVar(&o.adminOnly, "admin-only", false, "")
	fs.IntVar(&o.concurrency, "concurrency", defaultConcurrency, "")
	fs.BoolVar(&o.jsonOut, "json", false, "")
	fs.BoolVar(&o.all, "all", false, "")
	fs.StringVar(&o.color, "color", "auto", "")
	fs.BoolVar(&o.noColor, "no-color", false, "")
	fs.StringVar(&o.provider, "provider", "github", "")
	fs.StringVar(&o.host, "host", "", "")
	fs.StringVar(&o.token, "token", "", "")
	fs.BoolVar(&o.tokenStdin, "token-stdin", false, "")
	fs.StringVar(&o.format, "format", "table", "")
	fs.BoolVar(&o.exitCode, "exit-code", false, "")
	fs.BoolVar(&o.failOnSkipped, "fail-on-skipped", false, "")
	fs.BoolVar(&o.orgAudit, "org-audit", true, "")
	fs.IntVar(&o.staleDays, "stale-days", 180, "")
	fs.StringVar(&o.stateFile, "state-file", "", "")
	fs.StringVar(&o.only, "only", "", "")
	fs.StringVar(&o.skip, "skip", "", "")
	fs.BoolVar(&o.showIdentifiers, "show-identifiers", false, "")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	if o.concurrency < 1 {
		o.concurrency = 1
	}
	if err := validateColorMode(o.color); err != nil {
		dieUsage(err)
	}
	normalizeOptions(o)
	if err := validateOptions(o); err != nil {
		dieUsage(err)
	}
	args := fs.Args()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		usage(os.Stdout)
		return
	}
	if !isKnownCommand(cmd) {
		dieUsage(fmt.Errorf("unknown command %q; run 'repo-harden help'", cmd))
	}
	if cmd != "audit" && o.provider != "github" {
		dieUsage(fmt.Errorf("%s currently supports --provider github only; use audit for %s", cmd, o.provider))
	}
	if err := validateCommandInvocation(cmd, args, o); err != nil {
		dieUsage(err)
	}

	var client *github.Client
	var err error
	if commandNeedsGitHubClient(cmd, o) {
		client, err = newClient(o)
		if err != nil {
			die(err)
		}
	}

	maybePrintBanner(o)

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
		fmt.Fprintf(os.Stderr, "repo-harden: unknown command %q; run 'repo-harden help'\n", cmd)
		os.Exit(2)
	}
	if err != nil {
		var ue usageError
		if errors.As(err, &ue) {
			dieUsage(ue.err) // bad invocation / failed validation -> exit 2
		}
		var code exitError
		if errors.As(err, &code) {
			os.Exit(int(code))
		}
		die(err)
	}
}

func hydrateBuildInfo() {
	buildInfoOnce.Do(func() {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			return
		}
		Version, Commit, Date = buildMetadataFallback(Version, Commit, Date, info)
	})
}

func buildMetadataFallback(version, commit, date string, info *debug.BuildInfo) (string, string, string) {
	if version == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = info.Main.Version
	}
	settings := map[string]string{}
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if commit == "none" && settings["vcs.revision"] != "" {
		commit = settings["vcs.revision"]
	}
	if date == "unknown" && settings["vcs.time"] != "" {
		date = settings["vcs.time"]
	}
	if settings["vcs.modified"] == "true" && version != "dev" && !strings.HasSuffix(version, "+dirty") {
		version += "+dirty"
	}
	return version, commit, date
}

func isKnownCommand(cmd string) bool {
	switch cmd {
	case "list", "disable-all", "enable-all", "enable-all-disabled",
		"disable-repo", "enable-repo", "status", "audit", "harden", "revert", "controls":
		return true
	}
	return false
}

func usage(w io.Writer) {
	printUsageBanner(w)
	fmt.Fprint(w, `Usage: repo-harden <command> [options]

Commands:
  list                       List all workflows across all your repos
  disable-all                Disable every active workflow, save state file
  enable-all                 Re-enable workflows from saved state file
  enable-all-disabled        Re-enable EVERY currently-disabled workflow
  disable-repo <owner/repo>  Disable all active workflows in one repo (no state;
                             undo with enable-repo, not enable-all)
  enable-repo  <owner/repo>  Re-enable all disabled workflows in one repo (no state)
  status                     Show workflow counts by state across repos
  audit                      Scan all repos against the hardening baseline
  harden                     Apply the free baseline and save recovery state
  revert                     Restore verified changes recorded by harden
  controls                   List baseline controls (fixable + reversible)
  version                    Print version and build info
  help                       Show this help

Options:
  --dry-run                  Print actions without making changes (still reads via API)
  --owner <login>            Only touch repos owned by this user/org
  --repo <owner/repo>        Only these repos (comma-separated); skips the full scan
  --include-forks            Include forked repos (default: skipped)
  --include-archived         Include archived repos in audit/list operations
  --admin-only               Only repos you can administer (avoids 403 noise)
  --include-dynamic          Include dynamic/ workflows (CodeQL, Dependabot,
                             Copilot — these always 422 on toggle, so are
                             skipped by default)
  --concurrency <n>          Parallel API calls (default: 8)
  --json                     Emit JSON (list, status, audit)
  --format <fmt>             audit output: table, json, markdown, sarif
  --all                      audit table: show every check, not just gaps/errors
  --color <mode>             Color output: auto, always, never (default: auto)
  --no-color                 Disable color (same as --color never / NO_COLOR)
  --provider <name>          audit provider: github, gitlab, gitea, forgejo
  --host <host-or-url>       Provider host (GitHub Enterprise, GitLab, Gitea)
  --token <token>            Provider token (discouraged: visible in ps/shell history;
                             prefer env vars, gh auth, or --token-stdin)
  --token-stdin              Read the provider token from stdin
  --exit-code                audit exits 1 when gaps/errors are found
  --fail-on-skipped          audit exits 1 when any check could not be verified
  --org-audit                Include GitHub organization-level checks (default)
  --stale-days <n>           Stale repository threshold (default: 180)
  --state-file <path>        Override default state file location
  --only <keys>              Only run these controls (comma-separated keys)
  --skip <keys>              Skip these controls (comma-separated keys)
  --show-identifiers         Include secret/variable names in audit output

Env:
  REPO_HARDEN_STATE_DIR      State directory (default: ~/.repo-harden)
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

// dieUsage is for bad invocation (unknown flag/option), exit 2. die (exit 1) is
// for operations that ran but failed.
func dieUsage(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(2)
}

// exitError carries a process exit code up to Main without printing a message.
type exitError int

func (e exitError) Error() string { return "" }

// usageError marks a bad-invocation / failed-validation error so Main routes it
// through dieUsage (exit 2), keeping it distinct from ran-but-failed (exit 1).
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func usageErr(format string, a ...any) error { return usageError{fmt.Errorf(format, a...)} }

func commandNeedsGitHubClient(cmd string, o *opts) bool {
	if cmd == "controls" {
		return false
	}
	if cmd == "audit" {
		return o.provider == "github"
	}
	return true
}

func validateCommandInvocation(cmd string, args []string, o *opts) error {
	switch cmd {
	case "disable-repo", "enable-repo":
		if len(args) != 1 {
			return fmt.Errorf("usage: repo-harden %s <owner/repo>", cmd)
		}
		if err := validateRepoSlug(args[0]); err != nil {
			return err
		}
	default:
		if len(args) > 0 {
			return fmt.Errorf("%s does not accept positional arguments", cmd)
		}
	}
	if o.failOnSkipped && cmd != "audit" {
		return errors.New("--fail-on-skipped is only supported by audit")
	}
	return nil
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
	if o.staleDays > 36500 {
		return fmt.Errorf("--stale-days must be <= 36500")
	}
	if o.concurrency > maxConcurrency {
		return fmt.Errorf("--concurrency must be <= %d", maxConcurrency)
	}
	if o.repo != "" && o.provider != "github" {
		return fmt.Errorf("--repo is only supported with --provider github")
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
	token, err := resolveToken(o, host, "github")
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, fmt.Errorf("no GitHub token found for %s - run: gh auth login --hostname %s or set GITHUB_TOKEN", host, host)
	}
	hc := newGitHubHTTPClient(token)
	if host == "github.com" {
		return github.NewClient(github.WithHTTPClient(hc))
	}
	apiURL, uploadURL := githubEnterpriseURLs(o.host)
	if err := requireSecureURL(apiURL); err != nil {
		return nil, err
	}
	return github.NewClient(github.WithHTTPClient(hc), github.WithEnterpriseURLs(apiURL, uploadURL))
}

// picks the token: --token-stdin, then --token, then gh auth, then env.
func resolveToken(o *opts, host, provider string) (string, error) {
	if o.tokenStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("--token-stdin: failed to read token from stdin: %w", err)
		}
		return strings.TrimSpace(line), nil
	}
	if t := strings.TrimSpace(o.token); t != "" {
		return t, nil
	}
	if provider == "github" {
		if t, _ := auth.TokenForHost(host); t != "" {
			return t, nil
		}
	}
	return tokenFromEnv(provider), nil
}

func hostName(hostOrURL string) string {
	trimmed := strings.TrimSpace(hostOrURL)
	if trimmed == "" {
		return "github.com"
	}
	raw := trimmed
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.TrimPrefix(strings.TrimPrefix(trimmed, "https://"), "http://")
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
	switch provider {
	case "gitlab":
		raw = strings.TrimSuffix(raw, "/api/v4")
	case "gitea", "forgejo":
		raw = strings.TrimSuffix(raw, "/api/v1")
	}
	return raw
}

func githubEnterpriseURLs(hostOrURL string) (string, string) {
	base := strings.TrimRight(providerBaseURL("github", hostOrURL), "/")
	// accept either the web root or the API url
	base = strings.TrimSuffix(base, "/api/v3")
	return base + "/api/v3/", base + "/api/uploads/"
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
	// --repo given, so just grab those repos directly
	if o.repo != "" {
		repos, err := getNamedRepos(ctx, c, o.repo)
		if err != nil {
			return nil, err
		}
		for _, repo := range repos {
			if reason := repositoryExclusionReason(repo, o); reason != "" {
				return nil, fmt.Errorf("requested repository %s is excluded: %s", repo.GetFullName(), reason)
			}
		}
		return repos, nil
	}
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
		if repositoryExclusionReason(r, o) != "" {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetFullName() < out[j].GetFullName() })
	return out, nil
}

func repositoryExclusionReason(r *github.Repository, o *opts) string {
	if o.owner != "" && !strings.EqualFold(r.GetOwner().GetLogin(), o.owner) {
		return fmt.Sprintf("owner does not match --owner %q", o.owner)
	}
	if r.GetArchived() && !o.includeArchived {
		return "repository is archived (use --include-archived to include it)"
	}
	if r.GetFork() && !o.includeForks {
		return "repository is a fork (use --include-forks to include it)"
	}
	if o.adminOnly && !r.GetPermissions().GetAdmin() {
		return "token does not have admin permission required by --admin-only"
	}
	return ""
}

// fetches the repos named in a comma-separated owner/repo list. listRepos
// applies the same owner/fork/archive/admin eligibility policy afterward.
func getNamedRepos(ctx context.Context, c *github.Client, csv string) ([]*github.Repository, error) {
	var out []*github.Repository
	seen := map[string]bool{}
	for _, item := range strings.Split(csv, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if err := validateRepoSlug(item); err != nil {
			return nil, fmt.Errorf("invalid --repo value: %w", err)
		}
		owner, name := splitRepo(item)
		key := owner + "/" + name
		if seen[key] {
			continue
		}
		seen[key] = true
		r, _, err := c.Repositories.Get(ctx, owner, name)
		if err != nil {
			return nil, fmt.Errorf("get repo %s: %w", key, err)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--repo had no valid owner/repo entries")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetFullName() < out[j].GetFullName() })
	return out, nil
}

func requestedRepoSet(csv string) (map[string]bool, error) {
	repos := map[string]bool{}
	for _, item := range strings.Split(csv, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if err := validateRepoSlug(item); err != nil {
			return nil, fmt.Errorf("invalid --repo value: %w", err)
		}
		repos[strings.ToLower(item)] = true
	}
	if csv != "" && len(repos) == 0 {
		return nil, fmt.Errorf("--repo had no valid owner/repo entries")
	}
	return repos, nil
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

func collectRows(ctx context.Context, c *github.Client, o *opts, repos []*github.Repository) ([]listRow, int, error) {
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

func cmdDisableAll(ctx context.Context, c *github.Client, o *opts) error {
	repos, err := listRepos(ctx, c, o)
	if err != nil {
		return err
	}

	statePath, err := stateFilePath(o)
	if err != nil {
		return err
	}
	scope, err := githubStateScope(ctx, c, o)
	if err != nil {
		return err
	}
	unlock, err := lockStateFile(ctx, statePath)
	if err != nil {
		return err
	}
	defer func() { _ = unlock() }()
	existing, err := loadState(statePath, scope)
	if err != nil {
		return err
	}
	have := make(map[string]bool, len(existing))
	for _, e := range existing {
		have[entryKey(e.Repo, e.ID)] = true
	}

	// pass 1: find the active workflows to disable
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

	// save state before disabling so a crash mid-run can still be undone with
	// enable-all. over-recording is fine, enable is a no-op if already enabled.
	merged := append(existing, added...)
	if err := saveState(statePath, scope, merged); err != nil {
		return err
	}

	// Pass 2: disable.
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
	statePath, err := stateFilePath(o)
	if err != nil {
		return err
	}
	scope, err := githubStateScope(ctx, c, o)
	if err != nil {
		return err
	}
	unlock, err := lockStateFile(ctx, statePath)
	if err != nil {
		return err
	}
	defer func() { _ = unlock() }()
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

func cmdEnableAllDisabled(ctx context.Context, c *github.Client, o *opts) error {
	repos, err := listRepos(ctx, c, o)
	if err != nil {
		return err
	}
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
