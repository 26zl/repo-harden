package repoharden

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

const (
	colorReset  = "\x1b[0m"
	colorRed    = "\x1b[31m"
	colorGreen  = "\x1b[32m"
	colorYellow = "\x1b[33m"
	colorCyan   = "\x1b[36m"
	colorGray   = "\x1b[90m"
	colorGo     = "\x1b[38;5;38m" // Go Gopher Blue (#00ADD8); 256-color for Terminal.app compat
)

const banner = `                       _                _
 _ _ ___ _ __  ___ ___| |_  __ _ _ _ __| |___ _ _
| '_/ -_) '_ \/ _ \___| ' \/ _' | '_/ _' / -_) ' \
|_| \___| .__/\___/   |_||_\__,_|_| \__,_\___|_||_|
        |_|`

// printUsageBanner prints the ASCII wordmark + tagline (color auto-gated).
func printUsageBanner() {
	fmt.Println(colorize(nil, colorGo, banner))
	fmt.Println(colorize(nil, colorGray, "  one command · every repo · reversible"))
	fmt.Println()
}

func validateColorMode(mode string) error {
	switch strings.ToLower(mode) {
	case "", "auto", "always", "never":
		return nil
	default:
		return fmt.Errorf("invalid --color %q (expected auto, always, or never)", mode)
	}
}

func useColor(o *opts) bool {
	if o != nil && (o.jsonOut || o.noColor) {
		return false
	}
	mode := "auto"
	if o != nil && o.color != "" {
		mode = strings.ToLower(o.color)
	}
	switch mode {
	case "always":
		return true
	case "never":
		return false
	}
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := os.Stdout.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func colorize(o *opts, color, s string) string {
	if !useColor(o) {
		return s
	}
	return color + s + colorReset
}

func statusLabel(o *opts, status string) string {
	switch ControlStatus(status) {
	case StatusCompliant:
		return colorize(o, colorGreen, status)
	case StatusGap:
		return colorize(o, colorYellow, status)
	case StatusSkipped:
		return colorize(o, colorGray, status)
	case StatusError:
		return colorize(o, colorRed, status)
	default:
		return status
	}
}

func severityLabel(o *opts, severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return colorize(o, colorRed, severity)
	case "medium":
		return colorize(o, colorYellow, severity)
	case "low":
		return colorize(o, colorCyan, severity)
	case "info":
		return colorize(o, colorGray, severity)
	default:
		return severity
	}
}

func workflowStateLabel(o *opts, state string) string {
	if strings.HasPrefix(state, "disabled") {
		return colorize(o, colorGray, state)
	}
	if state == "active" {
		return colorize(o, colorGreen, state)
	}
	return colorize(o, colorYellow, state)
}

func actionLabel(o *opts, action string) string {
	switch action {
	case "harden", "enable":
		return colorize(o, colorCyan, action)
	case "disable", "revert":
		return colorize(o, colorYellow, action)
	case "skip":
		return colorize(o, colorGray, action)
	case "ERROR", "FAILED":
		return colorize(o, colorRed, action)
	default:
		return action
	}
}

func statusGlyph(status string) (sym, color string) {
	switch ControlStatus(status) {
	case StatusCompliant:
		return "✓", colorGreen
	case StatusGap:
		return "✗", colorYellow
	case StatusError:
		return "!", colorRed
	case StatusSkipped:
		return "–", colorGray
	default:
		return "?", colorReset
	}
}

func glyph(o *opts, status string) string {
	sym, color := statusGlyph(status)
	return colorize(o, color, sym)
}

func scoreBar(o *opts, score int) string {
	const w = 20
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	filled := score * w / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", w-filled)
	c := colorGreen
	if score < scoreLow {
		c = colorRed
	} else if score < scoreOK {
		c = colorYellow
	}
	return colorize(o, c, bar)
}

func truncate(s string, n int) string {
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

func runeWidth(s string) int { return utf8.RuneCountInString(s) }
