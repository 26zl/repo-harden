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

type auditRow struct {
	Provider    string `json:"provider,omitempty"`
	Scope       string `json:"scope,omitempty"`
	Repo        string `json:"repo"`
	Control     string `json:"control"`
	Title       string `json:"title,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Status      string `json:"status"`
	Detail      string `json:"detail,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

func collectAudit(ctx context.Context, c *github.Client, o *opts, repos []*github.Repository) ([]auditRow, error) {
	controls := selectControls(o.only, o.skip)
	var (
		mu   sync.Mutex
		rows []auditRow
	)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(o.concurrency)
	for _, r := range repos {
		g.Go(func() error {
			owner, name := splitRepo(r.GetFullName())
			for _, ctl := range controls {
				res := ctl.Detect(gctx, c, owner, name, r)
				mu.Lock()
				rows = append(rows, auditRow{
					Provider:    "github",
					Scope:       "repo",
					Repo:        r.GetFullName(),
					Control:     ctl.Key,
					Title:       ctl.Title,
					Severity:    ctl.Severity,
					Status:      string(res.Status),
					Detail:      res.Detail,
					Remediation: ctl.Remediation,
				})
				mu.Unlock()
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return rows, nil // cmdAudit sorts these
}

func auditLess(a, b auditRow) bool {
	if severityRank(a.Severity) != severityRank(b.Severity) {
		return severityRank(a.Severity) > severityRank(b.Severity)
	}
	if statusRank(a.Status) != statusRank(b.Status) {
		return statusRank(a.Status) > statusRank(b.Status)
	}
	if a.Scope != b.Scope {
		return a.Scope < b.Scope
	}
	if a.Repo != b.Repo {
		return a.Repo < b.Repo
	}
	return a.Control < b.Control
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func statusRank(s string) int {
	switch ControlStatus(s) {
	case StatusError:
		return 4
	case StatusGap:
		return 3
	case StatusSkipped:
		return 2
	case StatusCompliant:
		return 1
	default:
		return 0
	}
}

func auditWeight(row auditRow) int {
	switch strings.ToLower(row.Severity) {
	case "critical":
		return 20
	case "high":
		return 10
	case "medium":
		return 5
	case "low":
		return 2
	default:
		return 1
	}
}

func auditScore(rows []auditRow) int {
	total := 0
	lost := 0
	for _, row := range rows {
		if ControlStatus(row.Status) == StatusSkipped {
			continue
		}
		weight := auditWeight(row)
		total += weight
		switch ControlStatus(row.Status) {
		case StatusGap, StatusError:
			lost += weight
		}
	}
	if total == 0 {
		return 0
	}
	score := 100 - (lost * 100 / total)
	if score < 0 {
		return 0
	}
	return score
}

func cmdAudit(ctx context.Context, c *github.Client, o *opts) error {
	if err := validateAuditSelectionForProvider(o.provider, o.only, o.skip); err != nil {
		return usageError{err}
	}
	rows, repoCount, err := runAudit(ctx, c, o)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return fmt.Errorf("audit produced no results; no selected controls could be evaluated")
	}
	sort.Slice(rows, func(i, j int) bool { return auditLess(rows[i], rows[j]) })
	if err := renderAudit(rows, repoCount, o); err != nil {
		return err
	}
	if o.exitCode && auditHasFindings(rows) {
		return exitError(1)
	}
	if o.failOnSkipped && auditHasSkipped(rows) {
		return exitError(1)
	}
	return nil
}

func auditControlKeys() map[string]bool {
	keys := map[string]bool{}
	for _, ctl := range baseline {
		keys[ctl.Key] = true
	}
	for _, key := range []string{
		"actions-fork-pr-permissions",
		"archived-active-risk",
		"branch-protection-full",
		"code-scanning-alert-count",
		"collaborators",
		"default-branch",
		"dependency-sbom",
		"merge-hygiene",
		"dependabot-open-alerts",
		"ruleset-bypass",
		"open-security-advisories",
		"workflow-access-level",
		"actions-sha-pinning",
		"community-health",
		"code-scanning-conflict",
		"ruleset-evaluate-only",
		"workflow-token-permissions",
		"no-merge-method",
		"fork-policy",
		"wiki-attack-surface",
		"org-outside-collaborators",
		"account-2fa",
		"dependabot-config",
		"org-2fa-disabled-members",
		"deploy-keys",
		"environment-protection",
		"org-actions-policy",
		"org-base-permission",
		"org-2fa",
		"org-secrets",
		"org-token-policy",
		"org-webhooks",
		"packages",
		"public-exposure",
		"releases",
		"repo-secrets",
		"required-workflows",
		"secret-scanning-alert-count",
		"signed-commits",
		"stale-repo",
		"token-scopes",
		"vulnerability-alert-count",
		"webhooks",
	} {
		keys[key] = true
	}
	return keys
}

func validateAuditSelection(only, skip string) error {
	known := auditControlKeys()
	for flag, set := range map[string]map[string]bool{"--only": splitSet(only), "--skip": splitSet(skip)} {
		var unknown []string
		for key := range set {
			if !known[key] {
				unknown = append(unknown, key)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			return fmt.Errorf("%s contains unknown audit control(s): %s", flag, strings.Join(unknown, ", "))
		}
	}
	return nil
}

func providerAuditControlKeys(provider string) map[string]bool {
	if provider == "github" {
		return auditControlKeys()
	}
	keys := map[string]bool{}
	for _, key := range []string{
		"token-scopes",
		"public-exposure",
		"stale-repo",
		"default-branch",
		"branch-protection-full",
		"signed-commits",
		"required-workflows",
		"environment-protection",
		"repo-secrets",
		"deploy-keys",
		"webhooks",
		"collaborators",
		"vulnerability-alert-count",
		"releases",
		"packages",
		"dependency-sbom",
		"archived-active-risk",
	} {
		keys[key] = true
	}
	return keys
}

func validateAuditSelectionForProvider(provider, only, skip string) error {
	if err := validateAuditSelection(only, skip); err != nil {
		return err
	}
	supported := providerAuditControlKeys(provider)
	for flag, values := range map[string]map[string]bool{"--only": splitSet(only), "--skip": splitSet(skip)} {
		var unavailable []string
		for key := range values {
			if !supported[key] {
				unavailable = append(unavailable, key)
			}
		}
		if len(unavailable) > 0 {
			sort.Strings(unavailable)
			return fmt.Errorf("%s contains control(s) unsupported by provider %s: %s",
				flag, provider, strings.Join(unavailable, ", "))
		}
	}
	selected := 0
	onlySet := splitSet(only)
	skipSet := splitSet(skip)
	for key := range supported {
		if len(onlySet) > 0 && !onlySet[key] {
			continue
		}
		if !skipSet[key] {
			selected++
		}
	}
	if selected == 0 {
		return fmt.Errorf("no audit controls selected for provider %s", provider)
	}
	return nil
}

func auditScoreAvailable(rows []auditRow) bool {
	for _, row := range rows {
		if ControlStatus(row.Status) != StatusSkipped {
			return true
		}
	}
	return false
}

// auditVerification reports the severity-weighted share of controls that
// produced a definite compliant or gap result. Skipped and error rows remain
// visible as unknown rather than silently inflating confidence in the score.
func auditVerification(rows []auditRow) int {
	total := 0
	verified := 0
	for _, row := range rows {
		weight := auditWeight(row)
		total += weight
		switch ControlStatus(row.Status) {
		case StatusCompliant, StatusGap:
			verified += weight
		}
	}
	if total == 0 {
		return 0
	}
	return verified * 100 / total
}

func runAudit(ctx context.Context, c *github.Client, o *opts) ([]auditRow, int, error) {
	switch o.provider {
	case "github":
		repos, err := listRepos(ctx, c, o)
		if err != nil {
			return nil, 0, err
		}
		rows, err := collectAudit(ctx, c, o, repos)
		if err != nil {
			return nil, 0, err
		}
		extra, err := collectGitHubExtendedAudit(ctx, c, o, repos)
		if err != nil {
			return nil, 0, err
		}
		rows = append(rows, extra...)
		return filterAuditRows(rows, o), len(repos), nil
	case "gitlab":
		rows, count, err := collectGitLabAudit(ctx, o)
		return filterAuditRows(rows, o), count, err
	case "gitea", "forgejo":
		rows, count, err := collectGiteaAudit(ctx, o)
		return filterAuditRows(rows, o), count, err
	default:
		return nil, 0, fmt.Errorf("unsupported provider %q", o.provider)
	}
}

// wantFunc says whether a control should run, based on --only/--skip.
// we use this to skip the API call, not just filter the output.
func wantFunc(o *opts) func(string) bool {
	onlySet := splitSet(o.only)
	skipSet := splitSet(o.skip)
	return func(key string) bool {
		if len(onlySet) > 0 && !onlySet[key] {
			return false
		}
		return !skipSet[key]
	}
}

func filterAuditRows(rows []auditRow, o *opts) []auditRow {
	onlySet := splitSet(o.only)
	skipSet := splitSet(o.skip)
	if len(onlySet) == 0 && len(skipSet) == 0 {
		return rows
	}
	out := rows[:0]
	for _, row := range rows {
		if len(onlySet) > 0 && !onlySet[row.Control] {
			continue
		}
		if skipSet[row.Control] {
			continue
		}
		out = append(out, row)
	}
	return out
}

func auditHasFindings(rows []auditRow) bool {
	for _, row := range rows {
		if row.Status == string(StatusGap) || row.Status == string(StatusError) {
			return true
		}
	}
	return false
}

func auditHasSkipped(rows []auditRow) bool {
	for _, row := range rows {
		if ControlStatus(row.Status) == StatusSkipped {
			return true
		}
	}
	return false
}

func renderAudit(rows []auditRow, repoCount int, o *opts) error {
	switch o.format {
	case "json":
		return json.NewEncoder(os.Stdout).Encode(rows)
	case "markdown":
		renderAuditMarkdown(rows, repoCount)
	case "sarif":
		return json.NewEncoder(os.Stdout).Encode(auditSARIF(rows))
	default:
		renderAuditTable(rows, repoCount, o)
	}
	return nil
}

func renderAuditTable(rows []auditRow, repoCount int, o *opts) {
	renderAuditSummary(rows, repoCount, o)
	// group by target, worst score first
	groups := map[string][]auditRow{}
	var order []string
	for _, r := range rows {
		if _, ok := groups[r.Repo]; !ok {
			order = append(order, r.Repo)
		}
		groups[r.Repo] = append(groups[r.Repo], r)
	}
	sort.Slice(order, func(i, j int) bool {
		si, sj := auditScore(groups[order[i]]), auditScore(groups[order[j]])
		if si != sj {
			return si < sj
		}
		return order[i] < order[j]
	})
	hidden := 0
	for _, target := range order {
		grp := groups[target]
		display := grp
		if !o.all {
			// default: just findings, skip clean repos
			display = actionableRows(grp)
			if len(display) == 0 {
				hidden++
				continue
			}
		}
		fmt.Printf("\n%s  %s\n",
			colorize(o, colorCyan, target),
			colorize(o, colorGray, auditScoreText(grp))) // score uses the whole group
		printAuditRows(display, o)
	}
	if hidden > 0 {
		fmt.Printf("\n%s\n", colorize(o, colorGray,
			fmt.Sprintf("%d repo(s) with no gaps or errors hidden — use --all to show every check", hidden)))
	}
	renderTopRecommendations(rows, o)
}

// actionableRows just the gap/error rows.
func actionableRows(rows []auditRow) []auditRow {
	var out []auditRow
	for _, r := range rows {
		if r.Status == string(StatusGap) || r.Status == string(StatusError) {
			out = append(out, r)
		}
	}
	return out
}

const detailColWidth = 70

func printAuditRows(rows []auditRow, o *opts) {
	type cell struct{ plain, shown string }
	var grid [][]cell
	for _, r := range rows {
		sym, _ := statusGlyph(r.Status)
		detail := truncate(sanitizeDetail(r.Detail), detailColWidth)
		grid = append(grid, []cell{
			{"  " + sym, "  " + glyph(o, r.Status)},
			{r.Severity, severityLabel(o, r.Severity)},
			{r.Status, statusLabel(o, r.Status)},
			{r.Control, r.Control},
			{detail, detail},
		})
	}
	widths := make([]int, 5)
	for _, row := range grid {
		for i, c := range row {
			if w := runeCount(c.plain); w > widths[i] {
				widths[i] = w
			}
		}
	}
	for _, row := range grid {
		var b strings.Builder
		for i, c := range row {
			b.WriteString(c.shown)
			if i < len(row)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-runeCount(c.plain)+2))
			}
		}
		fmt.Println(strings.TrimRight(b.String(), " "))
	}
}

// score colors: below scoreLow red, below scoreOK yellow, else green.
const (
	scoreLow = 50
	scoreOK  = 80
)

func renderAuditSummary(rows []auditRow, repoCount int, o *opts) {
	counts := map[string]int{}
	for _, r := range rows {
		counts[r.Status]++
	}
	if !auditScoreAvailable(rows) {
		fmt.Printf("Posture %s  verification %d%%\n",
			colorize(o, colorGray, "n/a (no controls evaluated)"), auditVerification(rows))
		fmt.Printf("  %s %d compliant   %s %d gap   %s %d skipped   %s %d error   %s\n",
			glyph(o, string(StatusCompliant)), counts[string(StatusCompliant)],
			glyph(o, string(StatusGap)), counts[string(StatusGap)],
			glyph(o, string(StatusSkipped)), counts[string(StatusSkipped)],
			glyph(o, string(StatusError)), counts[string(StatusError)],
			colorize(o, colorGray, fmt.Sprintf("(%d repos)", repoCount)))
		return
	}
	score := auditScore(rows)
	sc := colorGreen
	if score < scoreLow {
		sc = colorRed
	} else if score < scoreOK {
		sc = colorYellow
	}
	fmt.Printf("Posture %s  %s  verification %d%%\n",
		colorize(o, sc, fmt.Sprintf("%d/100", score)), scoreBar(o, score), auditVerification(rows))
	fmt.Printf("  %s %d compliant   %s %d gap   %s %d skipped   %s %d error   %s\n",
		glyph(o, string(StatusCompliant)), counts[string(StatusCompliant)],
		glyph(o, string(StatusGap)), counts[string(StatusGap)],
		glyph(o, string(StatusSkipped)), counts[string(StatusSkipped)],
		glyph(o, string(StatusError)), counts[string(StatusError)],
		colorize(o, colorGray, fmt.Sprintf("(%d repos)", repoCount)))
}

func auditScoreText(rows []auditRow) string {
	if !auditScoreAvailable(rows) {
		return fmt.Sprintf("(n/a; verified %d%%)", auditVerification(rows))
	}
	return fmt.Sprintf("(%d/100; verified %d%%)", auditScore(rows), auditVerification(rows))
}

func renderTopRecommendations(rows []auditRow, o *opts) {
	seen := map[string]bool{}
	var printed int
	fmt.Println()
	fmt.Println("Top recommendations:")
	for _, row := range rows {
		if row.Status != string(StatusGap) && row.Status != string(StatusError) {
			continue
		}
		if seen[row.Control] {
			continue
		}
		seen[row.Control] = true
		rec := row.Remediation
		if rec == "" {
			rec = row.Title
		}
		fmt.Printf("  %s %s: %s\n", severityLabel(o, row.Severity), row.Control, rec)
		printed++
		if printed == 5 {
			return
		}
	}
	if printed == 0 {
		fmt.Println("  none")
	}
}

func renderAuditMarkdown(rows []auditRow, repoCount int) {
	fmt.Printf("# repo-harden audit\n\n")
	if auditScoreAvailable(rows) {
		fmt.Printf("Score: **%d/100**  \n", auditScore(rows))
	} else {
		fmt.Printf("Score: **n/a** (no controls evaluated)  \n")
	}
	fmt.Printf("Verification: **%d%%**  \n", auditVerification(rows))
	fmt.Printf("Repositories scanned: **%d**\n\n", repoCount)
	fmt.Println("| Severity | Status | Scope | Target | Control | Detail |")
	fmt.Println("| --- | --- | --- | --- | --- | --- |")
	for _, r := range rows {
		fmt.Printf("| %s | %s | %s | %s | %s | %s |\n",
			markdownEscape(r.Severity), markdownEscape(r.Status), markdownEscape(r.Scope),
			markdownEscape(r.Repo), markdownEscape(r.Control), markdownEscape(r.Detail))
	}
}

func markdownEscape(s string) string {
	return strings.ReplaceAll(sanitizeDetail(s), "|", "\\|")
}

func auditSARIF(rows []auditRow) map[string]any {
	rules := map[string]map[string]any{}
	results := []map[string]any{} // must marshal to [] not null on a clean scan
	for _, row := range rows {
		if row.Status != string(StatusGap) && row.Status != string(StatusError) {
			continue
		}
		rules[row.Control] = map[string]any{
			"id":   row.Control,
			"name": row.Title,
			"shortDescription": map[string]string{
				"text": row.Title,
			},
			"help": map[string]string{
				"text": row.Remediation,
			},
		}
		level := "warning"
		if row.Severity == "critical" || row.Severity == "high" || row.Status == string(StatusError) {
			level = "error"
		}
		results = append(results, map[string]any{
			"ruleId":  row.Control,
			"level":   level,
			"message": map[string]string{"text": strings.TrimSpace(row.Detail)},
			"locations": []map[string]any{{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]string{"uri": row.Repo},
				},
			}},
		})
	}
	ruleList := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	sort.Slice(ruleList, func(i, j int) bool { return fmt.Sprint(ruleList[i]["id"]) < fmt.Sprint(ruleList[j]["id"]) })
	return map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]any{{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":           "repo-harden",
					"version":        Version,
					"informationUri": "https://github.com/26zl/repo-harden",
					"rules":          ruleList,
				},
			},
			"results": results,
		}},
	}
}
