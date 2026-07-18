package repoharden

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	colorReset  = "\x1b[0m"
	colorRed    = "\x1b[31m"
	colorGreen  = "\x1b[32m"
	colorYellow = "\x1b[33m"
	colorCyan   = "\x1b[36m"
	colorGray   = "\x1b[90m"
	colorGo     = "\x1b[38;5;38m"
)

const banner = `                       _                _
 _ _ ___ _ __  ___ ___| |_  __ _ _ _ __| |___ _ _
| '_/ -_) '_ \/ _ \___| ' \/ _' | '_/ _' / -_) ' \
|_| \___| .__/\___/   |_||_\__,_|_| \__,_\___|_||_|
        |_|`

func printUsageBanner(w io.Writer) {
	fmt.Fprintln(w, colorizeFor(w, nil, colorGo, banner))
	fmt.Fprintln(w, colorizeFor(w, nil, colorGray, "  one command · every repo · reversible"))
	fmt.Fprintln(w)
}

// sanitizeDetail removes terminal control sequences and invisible Unicode format
// controls from untrusted output while preserving ordinary UTF-8 text.
func sanitizeDetail(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == 0x1b:
			if i+1 >= len(s) {
				continue
			}
			switch s[i+1] {
			case '[': // CSI
				i += 2
				for i < len(s) && !(s[i] >= '@' && s[i] <= '~') {
					i++
				}
			case ']', 'P', '^', '_': // OSC/DCS/PM/APC, terminated by BEL or ST
				i += 2
				for i < len(s) {
					if s[i] == 0x07 {
						break
					}
					if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\' {
						i++
						break
					}
					i++
				}
			default:
				i++ // two-byte escape sequence
			}
		case c == '\n', c == '\r', c == '\t':
			b.WriteByte(' ')
		case c < 0x20 || c == 0x7f:
		default:
			b.WriteByte(c)
		}
	}
	var clean strings.Builder
	for _, r := range b.String() {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		clean.WriteRune(r)
	}
	return strings.TrimSpace(clean.String())
}

func maybePrintBanner(o *opts) {
	if o != nil && (o.jsonOut || o.format == "json" || o.format == "sarif" || o.format == "markdown" || o.format == "badge") {
		return
	}
	info, err := os.Stdout.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return
	}
	fmt.Println(colorize(o, colorGo, banner))
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
	if o != nil && o.jsonOut {
		return false
	}
	return useColorFor(o, os.Stdout)
}

// useColorFor decides color per stream: stdout and stderr can differ under redirection.
func useColorFor(o *opts, f *os.File) bool {
	if o != nil && o.noColor {
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
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func colorize(o *opts, color, s string) string {
	if !useColor(o) {
		return s
	}
	return color + s + colorReset
}

func colorizeErr(o *opts, color, s string) string {
	if !useColorFor(o, os.Stderr) {
		return s
	}
	return color + s + colorReset
}

func colorizeFor(w io.Writer, o *opts, color, s string) string {
	switch w {
	case os.Stdout:
		return colorize(o, color, s)
	case os.Stderr:
		return colorizeErr(o, color, s)
	default:
		return s
	}
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
	return actionLabelColor(colorize, o, action)
}

// actionLabelErr is actionLabel for text written to stderr.
func actionLabelErr(o *opts, action string) string {
	return actionLabelColor(colorizeErr, o, action)
}

func actionLabelColor(paint func(*opts, string, string) string, o *opts, action string) string {
	switch action {
	case "harden", "enable":
		return paint(o, colorCyan, action)
	case "disable", "revert":
		return paint(o, colorYellow, action)
	case "skip":
		return paint(o, colorGray, action)
	case "ERROR", "FAILED":
		return paint(o, colorRed, action)
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

func runeCount(s string) int { return utf8.RuneCountInString(s) }

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type spinner struct {
	w      io.Writer
	mu     sync.Mutex
	stop   chan struct{}
	done   chan struct{}
	active bool
}

var activeSpinner *spinner

// startSpinner shows a working indicator on stderr in an interactive terminal until stopSpinner is called.
func startSpinner(o *opts, label string) {
	if !spinnerEnabled(o) {
		return
	}
	activeSpinner = newSpinner(os.Stderr, label)
}

func stopSpinner() { activeSpinner.Stop() }

func spinnerEnabled(o *opts) bool {
	if o != nil && (o.noColor || strings.ToLower(o.color) == "never") {
		return false
	}
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := os.Stderr.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func newSpinner(w io.Writer, label string) *spinner {
	s := &spinner{w: w, stop: make(chan struct{}), done: make(chan struct{}), active: true}
	go s.run(label)
	return s
}

func (s *spinner) run(label string) {
	defer close(s.done)
	fmt.Fprint(s.w, "\x1b[?25l")
	t := time.NewTicker(90 * time.Millisecond)
	defer t.Stop()
	for i := 0; ; i++ {
		fmt.Fprintf(s.w, "\r%s%s%s %s%s%s", colorGo, spinnerFrames[i%len(spinnerFrames)], colorReset, colorGray, label, colorReset)
		select {
		case <-s.stop:
			return
		case <-t.C:
		}
	}
}

func (s *spinner) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return
	}
	s.active = false
	s.mu.Unlock()
	close(s.stop)
	<-s.done
	fmt.Fprint(s.w, "\r\x1b[K\x1b[?25h")
}
