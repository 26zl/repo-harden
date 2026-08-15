package repoharden

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
)

type auditBaseline struct {
	Rows            []auditRow
	Scope           *auditReportScope
	RepositoryCount int
}

// loadAuditBaseline reads the versioned JSON audit report and retains
// compatibility with the legacy top-level row array emitted before version 1.
func loadAuditBaseline(path string) (auditBaseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return auditBaseline{}, fmt.Errorf("read --diff baseline: %w", err)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return auditBaseline{}, fmt.Errorf("parse --diff baseline %s (expected audit --format json output): file is empty", path)
	}
	if trimmed[0] == '[' {
		var rows []auditRow
		if err := decodeAuditJSON(trimmed, &rows); err != nil {
			return auditBaseline{}, fmt.Errorf("parse --diff baseline %s (expected audit --format json output): %w", path, err)
		}
		if err := validateAuditBaselineRows(rows, "", true); err != nil {
			return auditBaseline{}, fmt.Errorf("parse --diff baseline %s: %w", path, err)
		}
		return auditBaseline{Rows: rows}, nil
	}
	var report auditReport
	if err := decodeAuditJSON(trimmed, &report); err != nil {
		return auditBaseline{}, fmt.Errorf("parse --diff baseline %s (expected audit --format json output): %w", path, err)
	}
	if report.Version != auditReportSchemaVersion {
		return auditBaseline{}, fmt.Errorf("parse --diff baseline %s: unsupported audit report version %d (expected %d)",
			path, report.Version, auditReportSchemaVersion)
	}
	if report.Kind != auditReportKind {
		return auditBaseline{}, fmt.Errorf("parse --diff baseline %s: kind is %q, expected %q", path, report.Kind, auditReportKind)
	}
	rawProvider := report.Scope.Provider
	report.Scope.Provider = strings.ToLower(strings.TrimSpace(rawProvider))
	if report.Scope.Provider == "" {
		return auditBaseline{}, fmt.Errorf("parse --diff baseline %s: scope.provider is required", path)
	}
	if rawProvider != report.Scope.Provider || !validAuditProvider(report.Scope.Provider) {
		return auditBaseline{}, fmt.Errorf("parse --diff baseline %s: scope.provider %q is not a supported lowercase provider", path, rawProvider)
	}
	if strings.TrimSpace(report.Scope.Host) == "" {
		return auditBaseline{}, fmt.Errorf("parse --diff baseline %s: scope.host is required", path)
	}
	if err := validateUniqueNonemptyStrings("scope.repositories", report.Scope.Repositories); err != nil {
		return auditBaseline{}, fmt.Errorf("parse --diff baseline %s: %w", path, err)
	}
	if err := validateAuditReportSelection(report.Scope.Selection); err != nil {
		return auditBaseline{}, fmt.Errorf("parse --diff baseline %s: %w", path, err)
	}
	if len(report.Scope.Controls) == 0 {
		return auditBaseline{}, fmt.Errorf("parse --diff baseline %s: scope.controls must not be empty", path)
	}
	if err := validateUniqueNonemptyStrings("scope.controls", report.Scope.Controls); err != nil {
		return auditBaseline{}, fmt.Errorf("parse --diff baseline %s: %w", path, err)
	}
	if err := validateAuditBaselineRows(report.Rows, report.Scope.Provider, false); err != nil {
		return auditBaseline{}, fmt.Errorf("parse --diff baseline %s: %w", path, err)
	}
	want := newAuditReport(report.Rows, report.RepositoryCount, &opts{
		provider: report.Scope.Provider,
		host:     report.Scope.Host,
		owner:    report.Scope.Owner,
	}, report.Scope.Repositories)
	if !sameStringSet(report.Scope.Controls, want.Scope.Controls) {
		return auditBaseline{}, fmt.Errorf("parse --diff baseline %s: scope.controls does not match report rows", path)
	}
	if report.RepositoryCount != len(report.Scope.Repositories) {
		return auditBaseline{}, fmt.Errorf("parse --diff baseline %s: repository_count does not match the full scope.repositories universe", path)
	}
	universe := make(map[string]bool, len(report.Scope.Repositories))
	for _, repository := range report.Scope.Repositories {
		universe[repository] = true
	}
	for i, row := range report.Rows {
		if row.Scope == "repo" && !universe[row.Repo] {
			return auditBaseline{}, fmt.Errorf("parse --diff baseline %s: row %d repository %q is outside scope.repositories", path, i, row.Repo)
		}
	}
	return auditBaseline{Rows: report.Rows, Scope: &report.Scope, RepositoryCount: report.RepositoryCount}, nil
}

func validateAuditReportSelection(selection auditReportSelection) error {
	if selection.IncludeForks == nil || selection.IncludeArchived == nil || selection.AdminOnly == nil ||
		selection.IncludeDynamic == nil || selection.OrganizationAudit == nil {
		return fmt.Errorf("scope.selection must include every boolean selection parameter")
	}
	if selection.StaleDays < 1 || selection.StaleDays > 36500 {
		return fmt.Errorf("scope.selection.stale_days must be between 1 and 36500")
	}
	if err := validateUniqueNonemptyStrings("scope.selection.requested_repositories", selection.RequestedRepositories); err != nil {
		return err
	}
	for _, repository := range selection.RequestedRepositories {
		if repository != strings.ToLower(repository) {
			return fmt.Errorf("scope.selection.requested_repositories must use canonical lowercase names")
		}
	}
	return nil
}

func validateAuditDiffScope(baseline, current auditReportScope, baselineRepositoryCount, currentRepositoryCount int) error {
	baselineProvider := strings.ToLower(strings.TrimSpace(baseline.Provider))
	currentProvider := strings.ToLower(strings.TrimSpace(current.Provider))
	if baselineProvider != currentProvider {
		return fmt.Errorf("--diff baseline provider %q does not match current provider %q", baselineProvider, currentProvider)
	}
	baselineHost, err := normalizeAuditScopeHost(baselineProvider, baseline.Host)
	if err != nil {
		return fmt.Errorf("invalid --diff baseline host: %w", err)
	}
	currentHost, err := normalizeAuditScopeHost(currentProvider, current.Host)
	if err != nil {
		return fmt.Errorf("invalid current audit host: %w", err)
	}
	if baselineHost != currentHost {
		return fmt.Errorf("--diff baseline host %q does not match current host %q", baselineHost, currentHost)
	}
	baselineOwner := strings.ToLower(strings.TrimSpace(baseline.Owner))
	currentOwner := strings.ToLower(strings.TrimSpace(current.Owner))
	if baselineOwner != currentOwner {
		return fmt.Errorf("--diff baseline owner scope %q does not match current owner scope %q", baselineOwner, currentOwner)
	}
	if !sameAuditReportSelection(baseline.Selection, current.Selection) {
		return fmt.Errorf("--diff baseline selection parameters do not match the current audit")
	}
	if missing := missingStrings(baseline.Repositories, current.Repositories); len(missing) > 0 {
		return fmt.Errorf("--diff current audit cannot see baseline repositories: %s", strings.Join(limitStrings(missing, maxDetailItems), ", "))
	}
	if missing := missingStrings(baseline.Controls, current.Controls); len(missing) > 0 {
		return fmt.Errorf("--diff current audit omitted baseline controls: %s", strings.Join(limitStrings(missing, maxDetailItems), ", "))
	}
	if currentRepositoryCount < baselineRepositoryCount {
		return fmt.Errorf("--diff current audit can see only %d repositories, fewer than the baseline's %d; refusing a partial comparison",
			currentRepositoryCount, baselineRepositoryCount)
	}
	return nil
}

func sameAuditReportSelection(left, right auditReportSelection) bool {
	if validateAuditReportSelection(left) != nil || validateAuditReportSelection(right) != nil {
		return false
	}
	return *left.IncludeForks == *right.IncludeForks &&
		*left.IncludeArchived == *right.IncludeArchived &&
		*left.AdminOnly == *right.AdminOnly &&
		*left.IncludeDynamic == *right.IncludeDynamic &&
		*left.OrganizationAudit == *right.OrganizationAudit &&
		left.StaleDays == right.StaleDays &&
		sameStringSet(left.RequestedRepositories, right.RequestedRepositories)
}

func missingStrings(required, actual []string) []string {
	present := make(map[string]bool, len(actual))
	for _, value := range actual {
		present[value] = true
	}
	var missing []string
	for _, value := range required {
		if !present[value] {
			missing = append(missing, value)
		}
	}
	sort.Strings(missing)
	return missing
}

func normalizeAuditScopeHost(provider, host string) (string, error) {
	if provider == "github" {
		return canonicalStateHost(host)
	}
	raw := providerBaseURL(provider, host)
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if err := requireSecureURL(u.String()); err != nil {
		return "", err
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("provider host must not contain userinfo, query, or fragment")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}

func decodeAuditJSON(data []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	return ensureJSONEOF(dec)
}

func validateAuditBaselineRows(rows []auditRow, provider string, allowMissingProvider bool) error {
	if len(rows) == 0 {
		return fmt.Errorf("audit report has no rows")
	}
	for i := range rows {
		row := &rows[i]
		rawProvider := row.Provider
		row.Provider = strings.ToLower(strings.TrimSpace(rawProvider))
		if row.Repo == "" || row.Control == "" || statusRank(row.Status) == 0 {
			return fmt.Errorf("row %d must contain repo, control, and a valid status", i)
		}
		switch row.Scope {
		case "", "repo", "org", "token":
		default:
			return fmt.Errorf("row %d has invalid scope %q", i, row.Scope)
		}
		if row.Provider == "" {
			if !allowMissingProvider {
				row.Provider = provider
			}
		} else if rawProvider != row.Provider || !validAuditProvider(row.Provider) {
			return fmt.Errorf("row %d has invalid provider %q", i, rawProvider)
		} else if provider != "" && row.Provider != provider {
			return fmt.Errorf("row %d provider %q does not match scope.provider %q", i, row.Provider, provider)
		}
		if row.Severity != "" && !validAuditSeverity(row.Severity) {
			return fmt.Errorf("row %d has invalid severity %q", i, row.Severity)
		}
		if err := validateUniqueStrings(fmt.Sprintf("row %d refs", i), row.Refs); err != nil {
			return err
		}
	}
	return nil
}

func validAuditSeverity(severity string) bool {
	switch severity {
	case "critical", "high", "medium", "low", "info":
		return true
	default:
		return false
	}
}

func validAuditProvider(provider string) bool {
	switch provider {
	case "github", "gitlab", "gitea", "forgejo", "bitbucket":
		return true
	default:
		return false
	}
}

func validateUniqueNonemptyStrings(field string, values []string) error {
	for i, value := range values {
		if value == "" {
			return fmt.Errorf("%s item %d must not be empty", field, i)
		}
	}
	return validateUniqueStrings(field, values)
}

func validateUniqueStrings(field string, values []string) error {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return fmt.Errorf("%s contains duplicate value %q", field, value)
		}
		seen[value] = true
	}
	return nil
}

func sameStringSet(a, b []string) bool {
	toSet := func(values []string) map[string]bool {
		out := make(map[string]bool, len(values))
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value != "" {
				out[value] = true
			}
		}
		return out
	}
	aSet, bSet := toSet(a), toSet(b)
	if len(aSet) != len(bSet) {
		return false
	}
	for value := range aSet {
		if !bSet[value] {
			return false
		}
	}
	return true
}

type driftLine struct {
	Provider string
	Repo     string
	Control  string
	Severity string
	From     string
	To       string
}

type indexedAuditRow struct {
	Status   string
	Severity string
}

// indexAuditResults maps provider+target+control to the worst status seen on duplicate keys.
func indexAuditResults(rows []auditRow) map[string]indexedAuditRow {
	out := map[string]indexedAuditRow{}
	for _, row := range rows {
		key := row.Provider + "\x00" + row.Repo + "\x00" + row.Control
		previous, ok := out[key]
		if !ok || statusRank(row.Status) > statusRank(previous.Status) ||
			(statusRank(row.Status) == statusRank(previous.Status) && severityRank(row.Severity) > severityRank(previous.Severity)) {
			out[key] = indexedAuditRow{Status: row.Status, Severity: strings.ToLower(row.Severity)}
		}
	}
	return out
}

// driftProvidersDisjoint reports whether the baseline and current rows share no provider.
func driftProvidersDisjoint(prev, cur []auditRow) bool {
	prevSet := map[string]bool{}
	for _, r := range prev {
		if r.Provider == "" {
			return false
		}
		prevSet[r.Provider] = true
	}
	if len(prevSet) == 0 || len(cur) == 0 {
		return false
	}
	for _, r := range cur {
		if r.Provider == "" || prevSet[r.Provider] {
			return false
		}
	}
	return true
}

const driftStatusMissing = "missing"

func driftFailure(row indexedAuditRow) bool {
	return row.Status == string(StatusError) || row.Status == string(StatusSkipped) ||
		(row.Status == string(StatusGap) && row.Severity != "info")
}

func alignLegacyAuditProvider(prev, current []auditRow) []auditRow {
	provider := ""
	for _, row := range current {
		if row.Provider == "" {
			continue
		}
		if provider != "" && provider != row.Provider {
			return prev
		}
		provider = row.Provider
	}
	if provider == "" {
		return prev
	}
	for _, row := range prev {
		if row.Provider != "" {
			return prev
		}
	}
	out := append([]auditRow(nil), prev...)
	for i := range out {
		out[i].Provider = provider
	}
	return out
}

// auditDrift classifies posture changes, treating missing baseline targets/controls as fail-closed regressions.
func auditDrift(prev, current []auditRow) (regressions, improvements []driftLine) {
	prev = alignLegacyAuditProvider(prev, current)
	prevIdx := indexAuditResults(prev)
	curIdx := indexAuditResults(current)
	for key, result := range curIdx {
		if !driftFailure(result) {
			continue
		}
		prior, existed := prevIdx[key]
		if result.Status == string(StatusSkipped) {
			if existed && prior.Status == string(StatusSkipped) {
				continue
			}
			provider, repo, control := splitDriftKey(key)
			from := "absent"
			if existed {
				from = prior.Status
			}
			regressions = append(regressions, driftLine{
				Provider: provider, Repo: repo, Control: control, Severity: result.Severity,
				From: from, To: result.Status,
			})
			continue
		}
		if existed && driftFailure(prior) && statusRank(result.Status) <= statusRank(prior.Status) {
			continue
		}
		from := prior.Status
		if !existed {
			from = "absent"
		}
		provider, repo, control := splitDriftKey(key)
		regressions = append(regressions, driftLine{
			Provider: provider, Repo: repo, Control: control, Severity: result.Severity,
			From: from, To: result.Status,
		})
	}
	for key, prior := range prevIdx {
		currentResult, exists := curIdx[key]
		if !exists {
			provider, repo, control := splitDriftKey(key)
			regressions = append(regressions, driftLine{
				Provider: provider, Repo: repo, Control: control, Severity: "error",
				From: prior.Status, To: driftStatusMissing,
			})
			continue
		}
		if !driftFailure(prior) || currentResult.Status != string(StatusCompliant) {
			continue
		}
		provider, repo, control := splitDriftKey(key)
		improvements = append(improvements, driftLine{
			Provider: provider, Repo: repo, Control: control,
			From: prior.Status, To: currentResult.Status,
		})
	}
	sortDrift := func(lines []driftLine) {
		sort.Slice(lines, func(i, j int) bool {
			if lines[i].Provider != lines[j].Provider {
				return lines[i].Provider < lines[j].Provider
			}
			if lines[i].Repo != lines[j].Repo {
				return lines[i].Repo < lines[j].Repo
			}
			return lines[i].Control < lines[j].Control
		})
	}
	sortDrift(regressions)
	sortDrift(improvements)
	return regressions, improvements
}

func splitDriftKey(key string) (provider, repo, control string) {
	provider, rest, _ := strings.Cut(key, "\x00")
	repo, control, _ = strings.Cut(rest, "\x00")
	return provider, repo, control
}

func renderAuditDrift(w io.Writer, regressions, improvements []driftLine, o *opts) {
	fmt.Fprintf(w, "\nDrift vs baseline: %d regression(s), %d improvement(s)\n", len(regressions), len(improvements))
	for _, l := range regressions {
		fmt.Fprintf(w, "  %s %s %s: %s -> %s\n", colorizeFor(w, o, colorRed, "regressed"),
			sanitizeDetail(driftTarget(l)), sanitizeDetail(l.Control), sanitizeDetail(l.From), sanitizeDetail(l.To))
	}
	for _, l := range improvements {
		fmt.Fprintf(w, "  %s  %s %s: %s -> %s\n", colorizeFor(w, o, colorGreen, "improved"),
			sanitizeDetail(driftTarget(l)), sanitizeDetail(l.Control), sanitizeDetail(l.From), sanitizeDetail(l.To))
	}
}

func driftTarget(line driftLine) string {
	if line.Provider == "" {
		return line.Repo
	}
	return line.Provider + ":" + line.Repo
}

// auditBadge builds a shields.io endpoint payload
// (https://shields.io/badges/endpoint-badge) from the posture score.
func auditBadge(rows []auditRow) map[string]any {
	payload := map[string]any{"schemaVersion": 1, "label": "security posture"}
	if !auditScoreAvailable(rows) {
		payload["message"] = "unknown"
		payload["color"] = "lightgrey"
		return payload
	}
	score := auditScore(rows)
	color := "brightgreen"
	if score < scoreLow {
		color = "red"
	} else if score < scoreOK {
		color = "yellow"
	}
	payload["message"] = fmt.Sprintf("%d/100", score)
	payload["color"] = color
	return payload
}
