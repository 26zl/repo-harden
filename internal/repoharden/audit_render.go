package repoharden

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

func renderAudit(rows []auditRow, repoCount int, o *opts, repositoryUniverse ...[]string) error {
	stopSpinner()
	switch o.format {
	case "json":
		return json.NewEncoder(os.Stdout).Encode(newAuditReport(rows, repoCount, o, repositoryUniverse...))
	case "markdown":
		renderAuditMarkdown(rows, repoCount)
	case "sarif":
		return json.NewEncoder(os.Stdout).Encode(auditSARIF(rows))
	case "badge":
		return json.NewEncoder(os.Stdout).Encode(auditBadge(rows))
	default:
		renderAuditTable(rows, repoCount, o)
	}
	return nil
}

func renderAuditTable(rows []auditRow, repoCount int, o *opts) {
	renderAuditSummary(rows, repoCount, o)
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
			display = actionableRows(grp)
			if len(display) == 0 {
				hidden++
				continue
			}
		}
		fmt.Printf("\n%s  %s\n",
			colorize(o, colorCyan, target),
			colorize(o, colorGray, auditScoreText(grp)))
		printAuditRows(display, o)
	}
	if hidden > 0 {
		fmt.Printf("\n%s\n", colorize(o, colorGray,
			fmt.Sprintf("%d repo(s) with no gaps or errors hidden — use --all to show every check", hidden)))
	}
	renderTopRecommendations(rows, o)
}

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
	fmt.Println("| Severity | Status | Scope | Target | Control | Detail | Refs |")
	fmt.Println("| --- | --- | --- | --- | --- | --- | --- |")
	for _, r := range rows {
		fmt.Printf("| %s | %s | %s | %s | %s | %s | %s |\n",
			markdownEscape(r.Severity), markdownEscape(r.Status), markdownEscape(r.Scope),
			markdownEscape(r.Repo), markdownEscape(r.Control), markdownEscape(r.Detail),
			markdownEscape(strings.Join(r.Refs, ", ")))
	}
}

func markdownEscape(s string) string {
	return strings.ReplaceAll(sanitizeDetail(s), "|", "\\|")
}

func auditSARIF(rows []auditRow) map[string]any {
	rules := map[string]map[string]any{}
	results := []map[string]any{}
	for _, row := range rows {
		if row.Status != string(StatusGap) && row.Status != string(StatusError) {
			continue
		}
		rule := map[string]any{
			"id":   row.Control,
			"name": row.Title,
			"shortDescription": map[string]string{
				"text": row.Title,
			},
			"help": map[string]string{
				"text": row.Remediation,
			},
		}
		if refs := complianceRefs[row.Control]; len(refs) > 0 {
			rule["properties"] = map[string]any{"tags": refs}
		}
		rules[row.Control] = rule
		level := "warning"
		if row.Severity == "critical" || row.Severity == "high" || row.Status == string(StatusError) {
			level = "error"
		}
		results = append(results, map[string]any{
			"ruleId":  row.Control,
			"level":   level,
			"message": map[string]string{"text": sanitizeDetail(row.Detail)},
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
