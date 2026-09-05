// Package logging builds the process logger.
//
// Dev mode is human-readable at Debug; production is JSON at Info so the
// incident text (which is frequently multi-paragraph CJK) survives a log
// pipeline intact rather than being line-split.
package logging

import (
	"log/slog"
	"os"
)

// New returns the process logger and installs it as the slog default.
func New(dev bool) *slog.Logger {
	var h slog.Handler
	if dev {
		h = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	} else {
		h = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	l := slog.New(h)
	slog.SetDefault(l)
	return l
}
