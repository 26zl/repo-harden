package repoharden

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/google/go-github/v88/github"
	"golang.org/x/sync/errgroup"
)

type auditRow struct {
	Provider    string   `json:"provider,omitempty"`
	Scope       string   `json:"scope,omitempty"`
	Repo        string   `json:"repo"`
	Control     string   `json:"control"`
	Title       string   `json:"title,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Status      string   `json:"status"`
	Detail      string   `json:"detail,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Refs        []string `json:"refs,omitempty"`
}

const (
	auditReportSchemaVersion = 1
	auditReportKind          = "repo-harden-audit"
)

type auditReportScope struct {
	Provider     string               `json:"provider"`
	Host         string               `json:"host"`
	Owner        string               `json:"owner,omitempty"`
	Repositories []string             `json:"repositories"`
	Controls     []string             `json:"controls"`
	Selection    auditReportSelection `json:"selection"`
}

type auditReportSelection struct {
	RequestedRepositories []string `json:"requested_repositories"`
	IncludeForks          *bool    `json:"include_forks"`
	IncludeArchived       *bool    `json:"include_archived"`
	AdminOnly             *bool    `json:"admin_only"`
	IncludeDynamic        *bool    `json:"include_dynamic"`
	OrganizationAudit     *bool    `json:"organization_audit"`
	StaleDays             int      `json:"stale_days"`
}

type auditReport struct {
	Version         int              `json:"version"`
	Kind            string           `json:"kind"`
	Scope           auditReportScope `json:"scope"`
	RepositoryCount int              `json:"repository_count"`
	Rows            []auditRow       `json:"rows"`
}

func newAuditReport(rows []auditRow, repoCount int, o *opts, repositoryUniverse ...[]string) auditReport {
	provider, host, owner := "", "", ""
	selection := auditReportSelection{
		IncludeForks:      boolPointer(false),
		IncludeArchived:   boolPointer(false),
		AdminOnly:         boolPointer(false),
		IncludeDynamic:    boolPointer(false),
		OrganizationAudit: boolPointer(false),
		StaleDays:         180,
	}
	if o != nil {
		provider = strings.ToLower(strings.TrimSpace(o.provider))
		host = strings.TrimRight(strings.TrimSpace(o.host), "/")
		owner = strings.TrimSpace(o.owner)
		selection.RequestedRepositories = normalizedRequestedRepositories(o.repo)
		selection.IncludeForks = boolPointer(o.includeForks)
		selection.IncludeArchived = boolPointer(o.includeArchived)
		selection.AdminOnly = boolPointer(o.adminOnly)
		selection.IncludeDynamic = boolPointer(o.includeDynamic)
		selection.OrganizationAudit = boolPointer(o.orgAudit)
		if o.staleDays > 0 {
			selection.StaleDays = o.staleDays
		}
	}
	repositories := map[string]bool{}
	controls := map[string]bool{}
	for _, row := range rows {
		if provider == "" && row.Provider != "" {
			provider = strings.ToLower(strings.TrimSpace(row.Provider))
		}
		if row.Scope == "repo" && row.Repo != "" {
			repositories[row.Repo] = true
		}
		if row.Control != "" {
			controls[row.Control] = true
		}
	}
	if len(repositoryUniverse) > 0 {
		repositories = map[string]bool{}
		for _, repository := range repositoryUniverse[0] {
			if repository = strings.TrimSpace(repository); repository != "" {
				repositories[repository] = true
			}
		}
	}
	if host == "" && provider != "" {
		host = defaultProviderHost(provider)
	}
	return auditReport{
		Version: auditReportSchemaVersion,
		Kind:    auditReportKind,
		Scope: auditReportScope{
			Provider:     provider,
			Host:         host,
			Owner:        owner,
			Repositories: sortedStringSet(repositories),
			Controls:     sortedStringSet(controls),
			Selection:    selection,
		},
		RepositoryCount: repoCount,
		Rows:            rows,
	}
}

func boolPointer(value bool) *bool {
	return &value
}

func normalizedRequestedRepositories(csv string) []string {
	repositories := map[string]bool{}
	for _, item := range strings.Split(csv, ",") {
		if item = strings.ToLower(strings.TrimSpace(item)); item != "" {
			repositories[item] = true
		}
	}
	return sortedStringSet(repositories)
}

func sortedStringSet(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// complianceRefs maps control keys to framework references (Scorecard check
// names, SLSA themes, CIS-SSC categories — no section numbers, they drift).
var complianceRefs = map[string][]string{
	"branch-protection":               {"Scorecard:Branch-Protection", "CIS-SSC:1 Source Code"},
	"branch-protection-full":          {"Scorecard:Branch-Protection", "CIS-SSC:1 Source Code"},
	"merge-queue":                     {"CIS-SSC:1 Source Code"},
	"tag-protection":                  {"CIS-SSC:1 Source Code", "SLSA:source"},
	"push-ruleset":                    {"CIS-SSC:1 Source Code"},
	"signed-commits":                  {"CIS-SSC:1 Source Code", "SLSA:source"},
	"codeowners":                      {"Scorecard:Code-Review", "CIS-SSC:1 Source Code"},
	"security-md":                     {"Scorecard:Security-Policy"},
	"private-vulnerability-reporting": {"Scorecard:Security-Policy"},
	"stale-repo":                      {"Scorecard:Maintained"},
	"account-2fa":                     {"CIS-SSC:1 Source Code"},
	"org-2fa":                         {"CIS-SSC:1 Source Code"},
	"org-2fa-disabled-members":        {"CIS-SSC:1 Source Code"},
	"token-readonly":                  {"Scorecard:Token-Permissions", "CIS-SSC:2 Build Pipelines"},
	"workflow-token-permissions":      {"Scorecard:Token-Permissions", "CIS-SSC:2 Build Pipelines"},
	"actions-allowlist":               {"CIS-SSC:2 Build Pipelines"},
	"org-actions-policy":              {"CIS-SSC:2 Build Pipelines"},
	"actions-sha-pinning":             {"Scorecard:Pinned-Dependencies", "CIS-SSC:2 Build Pipelines"},
	"workflow-unpinned-actions":       {"Scorecard:Pinned-Dependencies", "CIS-SSC:2 Build Pipelines", "SLSA:build"},
	"pipeline-supply-chain":           {"Scorecard:Pinned-Dependencies", "CIS-SSC:2 Build Pipelines"},
	"workflow-pwn-request":            {"Scorecard:Dangerous-Workflow", "CIS-SSC:2 Build Pipelines"},
	"workflow-injection":              {"Scorecard:Dangerous-Workflow", "CIS-SSC:2 Build Pipelines"},
	"self-hosted-runners":             {"CIS-SSC:2 Build Pipelines"},
	"org-runner-groups":               {"CIS-SSC:2 Build Pipelines"},
	"dependabot-alerts":               {"Scorecard:Vulnerabilities", "CIS-SSC:3 Dependencies"},
	"dependabot-fixes":                {"Scorecard:Dependency-Update-Tool", "CIS-SSC:3 Dependencies"},
	"dependabot-config":               {"Scorecard:Dependency-Update-Tool", "CIS-SSC:3 Dependencies"},
	"dependabot-open-alerts":          {"Scorecard:Vulnerabilities", "CIS-SSC:3 Dependencies"},
	"vulnerability-alert-count":       {"Scorecard:Vulnerabilities", "CIS-SSC:3 Dependencies"},
	"dependency-review":               {"CIS-SSC:3 Dependencies"},
	"dependency-sbom":                 {"CIS-SSC:3 Dependencies", "SLSA:provenance"},
	"repository-license":              {"Scorecard:License"},
	"code-scanning":                   {"Scorecard:SAST", "CIS-SSC:1 Source Code"},
	"code-scanning-alert-count":       {"Scorecard:SAST"},
	"secret-scanning":                 {"CIS-SSC:1 Source Code"},
	"secret-scanning-alert-count":     {"CIS-SSC:1 Source Code"},
	"releases":                        {"CIS-SSC:4 Artifacts"},
	"release-provenance":              {"Scorecard:Signed-Releases", "SLSA:provenance", "CIS-SSC:4 Artifacts"},
	"packages":                        {"CIS-SSC:4 Artifacts"},
	"webhooks":                        {"Scorecard:Webhooks"},
	"org-webhooks":                    {"Scorecard:Webhooks"},
	"environment-protection":          {"CIS-SSC:5 Deployment"},
	"oidc-cloud-trust":                {"CIS-SSC:5 Deployment", "SLSA:build"},
}

func stampComplianceRefs(rows []auditRow) {
	for i := range rows {
		rows[i].Refs = complianceRefs[rows[i].Control]
	}
}

func collectAudit(ctx context.Context, c *github.Client, o *opts, repos []*github.Repository) ([]auditRow, error) {
	controls := selectControls(o.only, o.skip)
	var (
		mu   sync.Mutex
		rows []auditRow
	)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(max(1, o.concurrency))
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
	return rows, nil
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
	// validate the --diff baseline before the (expensive) scan
	var baseline auditBaseline
	var prevRows []auditRow
	if o.diffBaseline != "" {
		loaded, err := loadAuditBaseline(o.diffBaseline)
		if err != nil {
			return usageError{err}
		}
		baseline = loaded
		prevRows = loaded.Rows
	}
	rows, repositories, err := runAudit(ctx, c, o)
	if err != nil {
		return err
	}
	repoCount := len(repositories)
	if len(rows) == 0 {
		return fmt.Errorf("audit produced no results; no selected controls could be evaluated")
	}
	stampComplianceRefs(rows)
	sort.Slice(rows, func(i, j int) bool { return auditLess(rows[i], rows[j]) })
	currentReport := newAuditReport(rows, repoCount, o, repositories)
	legacyDiffUnscoped := false
	if o.diffBaseline != "" {
		if baseline.Scope == nil {
			legacyDiffUnscoped = true
			fmt.Fprintln(os.Stderr, "warning: legacy --diff baseline has no provider host/owner scope; --exit-code will fail closed until it is replaced with a fresh JSON audit report")
		} else if err := validateAuditDiffScope(
			*baseline.Scope,
			currentReport.Scope,
			baseline.RepositoryCount,
			currentReport.RepositoryCount,
		); err != nil {
			return usageError{err}
		}
	}
	if err := renderAudit(rows, repoCount, o, repositories); err != nil {
		return err
	}
	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "audit interrupted — results are partial")
		return exitError(1)
	}
	var regressions []driftLine
	if o.diffBaseline != "" {
		if driftProvidersDisjoint(prevRows, rows) {
			fmt.Fprintln(os.Stderr, "warning: --diff baseline was produced by a different provider; every current finding will look new")
		}
		var improvements []driftLine
		regressions, improvements = auditDrift(prevRows, rows)
		out := os.Stdout
		if o.format != "table" {
			out = os.Stderr // keep stdout machine-parseable
		}
		renderAuditDrift(out, regressions, improvements, o)
	}
	if o.exitCode {
		if o.diffBaseline != "" {
			if legacyDiffUnscoped {
				return exitError(1)
			}
			// with a baseline, fail only when posture regressed, not on known gaps
			if len(regressions) > 0 {
				return exitError(1)
			}
		} else if auditHasFindings(rows) {
			return exitError(1)
		}
	}
	if o.failOnSkipped && auditHasSkipped(rows) {
		return exitError(1)
	}
	if failBelowEnabled(o) {
		if !auditScoreAvailable(rows) {
			fmt.Fprintln(os.Stderr, "audit score unavailable; refusing to pass --fail-below")
			return exitError(1)
		}
		if auditScore(rows) < o.failBelow {
			return exitError(1)
		}
	}
	return nil
}
