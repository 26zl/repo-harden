package repoharden

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestColorGating(t *testing.T) {
	if got := glyph(&opts{noColor: true}, "compliant"); strings.Contains(got, "\x1b") {
		t.Errorf("--no-color glyph must contain no ANSI escape, got %q", got)
	}
	if got := glyph(&opts{color: "never"}, "compliant"); strings.Contains(got, "\x1b") {
		t.Errorf("--color never glyph must contain no ANSI escape, got %q", got)
	}
	if got := glyph(&opts{color: "always"}, "compliant"); !strings.Contains(got, colorGreen) {
		t.Errorf("--color always glyph must be colored, got %q", got)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("abcdef", 4); got != "abc…" {
		t.Errorf("truncate(abcdef,4) = %q, want abc…", got)
	}
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate no-op = %q, want short", got)
	}
}

func TestScoreBarWidth(t *testing.T) {
	// Width is constant regardless of score, and color-free with --no-color.
	for _, s := range []int{-5, 0, 49, 80, 100, 150} {
		bar := scoreBar(&opts{noColor: true}, s)
		if strings.Contains(bar, "\x1b") {
			t.Errorf("score %d: bar must be uncolored with --no-color", s)
		}
		if w := utf8.RuneCountInString(bar); w != 20 {
			t.Errorf("score %d: bar width = %d, want 20", s, w)
		}
	}
}
