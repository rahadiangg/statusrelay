package logging

import (
	"log/slog"
	"testing"
)

func TestNewInstallsDefaultAndRespectsLevel(t *testing.T) {
	for _, tc := range []struct {
		name      string
		dev       bool
		wantDebug bool
	}{
		{name: "dev enables debug", dev: true, wantDebug: true},
		{name: "prod suppresses debug", dev: false, wantDebug: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := New(tc.dev)
			if l == nil {
				t.Fatal("got nil logger, want a logger")
			}
			if slog.Default() != l {
				t.Error("New did not install the logger as the slog default")
			}
			if got := l.Enabled(t.Context(), slog.LevelDebug); got != tc.wantDebug {
				t.Errorf("debug enabled = %v, want %v", got, tc.wantDebug)
			}
		})
	}
}
