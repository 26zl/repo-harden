package repoharden

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"

	"github.com/google/go-github/v88/github"
)

const (
	defaultConcurrency = 8
	maxConcurrency     = 64
)

const dynamicPrefix = "dynamic/"

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
	formatSet       bool
	exitCode        bool
	failOnSkipped   bool
	failBelow       int
	failBelowSet    bool
	diffBaseline    string
	orgAudit        bool
	orgAuditSet     bool
	staleDays       int
	staleDaysSet    bool
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

	if spec, ok := lookupCommand(cmd); ok && spec.skipFlagParsing {
		if err := dispatchCommand(context.Background(), spec, nil, nil, os.Args[2:]); err != nil {
			die(err)
		}
		return
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
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
	fs.StringVar(&o.format, "format", "", "")
	fs.BoolVar(&o.exitCode, "exit-code", false, "")
	fs.BoolVar(&o.failOnSkipped, "fail-on-skipped", false, "")
	fs.IntVar(&o.failBelow, "fail-below", 0, "")
	fs.StringVar(&o.diffBaseline, "diff", "", "")
	fs.BoolVar(&o.orgAudit, "org-audit", true, "")
	fs.IntVar(&o.staleDays, "stale-days", 180, "")
	fs.StringVar(&o.stateFile, "state-file", "", "")
	fs.StringVar(&o.only, "only", "", "")
	fs.StringVar(&o.skip, "skip", "", "")
	fs.BoolVar(&o.showIdentifiers, "show-identifiers", false, "")
	if err := fs.Parse(os.Args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(os.Stdout)
			return
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		usage(os.Stderr)
		os.Exit(2)
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "fail-below":
			o.failBelowSet = true
		case "org-audit":
			o.orgAuditSet = true
		case "stale-days":
			o.staleDaysSet = true
		}
	})
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
	// after the first signal, restore default handling so a second Ctrl-C force-quits
	go func() { <-ctx.Done(); stop() }()

	spec, ok := lookupCommand(cmd)
	if !ok {
		dieUsage(fmt.Errorf("unknown command %q; run 'repo-harden help'", cmd))
	}
	cmd = spec.name
	if spec.skipValidation {
		if err := dispatchCommand(ctx, spec, nil, o, args); err != nil {
			die(err)
		}
		return
	}
	if spec.githubOnly && o.provider != "github" {
		dieUsage(fmt.Errorf("%s currently supports --provider github only; use audit for %s", cmd, o.provider))
	}
	if err := validateCommandInvocation(cmd, args, o); err != nil {
		dieUsage(err)
	}

	var client *github.Client
	var err error
	if spec.needsGitHubClient(o) {
		client, err = newClient(o)
		if err != nil {
			die(err)
		}
	}

	if spec.showBanner {
		maybePrintBanner(o)
	}

	if spec.showSpinner {
		startSpinner(o, "working…")
		defer stopSpinner()
	}

	err = dispatchCommand(ctx, spec, client, o, args)
	stopSpinner()
	if err != nil {
		var ue usageError
		if errors.As(err, &ue) {
			dieUsage(ue.err)
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
  codify                     Emit the baseline as Terraform/OpenTofu HCL with
                             import blocks for settings that already exist
  version                    Print version and build info
  help                       Show this help

Options:
  --dry-run                  Print actions without making changes (still reads via API)
  --owner <login>            Only touch repos owned by this user/org
  --repo <owner/repo>        Only these repos (comma-separated); skips the full scan
  --include-forks            Include forked repos (default: skipped)
  --include-archived         Include archived repos (default: skipped)
  --admin-only               Only repos you can administer (avoids 403 noise)
  --include-dynamic          Include dynamic/ workflows (CodeQL, Dependabot,
                             Copilot — these always 422 on toggle, so are
                             skipped by default)
  --concurrency <n>          Parallel API calls (default: 8)
  --json                     Emit JSON (list, status, audit)
  --format <fmt>             audit output: table, json, markdown, sarif, badge
                             (badge = shields.io endpoint JSON with the score)
  --all                      audit table: show every check, not just gaps/errors
  --color <mode>             Color output: auto, always, never (default: auto)
  --no-color                 Disable color (same as --color never / NO_COLOR)
  --provider <name>          audit provider: github, gitlab, gitea, forgejo
  --host <host-or-url>       Provider host (GitHub Enterprise, GitLab, Gitea)
  --token <token>            Provider token (discouraged: visible in ps/shell history;
                             prefer env vars, gh auth, or --token-stdin)
  --token-stdin              Read the provider token from stdin
  --exit-code                audit exits 1 when gaps/errors are found
                             (info-severity gaps excluded; with --diff: only
                             when posture regressed)
  --fail-on-skipped          audit exits 1 when any check could not be verified
  --fail-below <n>           audit exits 1 when the posture score is below n
  --diff <path>              audit: report drift against a previous
                             'audit --format json' output
  --org-audit                audit: include GitHub organization-level checks (default)
  --stale-days <n>           audit: stale repository threshold (default: 180)
  --state-file <path>        Override the state file (harden, revert,
                             disable-all, enable-all)
  --only <keys>              Only run these controls (comma-separated keys)
  --skip <keys>              Skip these controls (comma-separated keys)
  --show-identifiers         Include secret/variable, collaborator, and
                             deploy-key names in audit output

Env:
  REPO_HARDEN_STATE_DIR      State directory (default: ~/.repo-harden)
  GITHUB_TOKEN               GitHub/GHES token fallback
  GITLAB_TOKEN               GitLab token fallback
  GITEA_TOKEN                Gitea token fallback
  FORGEJO_TOKEN              Forgejo token fallback (then GITEA_TOKEN)
`)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", friendlyError(err))
	os.Exit(1)
}

func dieUsage(err error) {
	fmt.Fprintln(os.Stderr, "error:", sanitizeDetail(err.Error()))
	os.Exit(2)
}

// friendlyError sanitizes server-derived error text and adds a hint for auth failures.
func friendlyError(err error) string {
	msg := sanitizeDetail(err.Error())
	var re *restError
	if githubStatus(err) == http.StatusUnauthorized ||
		(errors.As(err, &re) && re.statusCode == http.StatusUnauthorized) {
		msg += " — token invalid or expired; check `gh auth status` or the provider token env var"
	}
	return msg
}

type exitError int

func (e exitError) Error() string { return "" }

type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func usageErr(format string, a ...any) error { return usageError{fmt.Errorf(format, a...)} }
