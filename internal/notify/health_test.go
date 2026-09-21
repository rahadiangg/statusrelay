package notify

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
)

func TestHealthEventsGolden(t *testing.T) {
	now := time.Date(2026, 9, 21, 10, 30, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		ev   incident.Event
	}{
		{name: "source_blind", ev: SourceBlind("huawei-intl", "fetching open incidents: incident: upstream request failed: dial tcp: i/o timeout", now.Add(-16*time.Minute), now)},
		{name: "source_recovered", ev: SourceRecovered("huawei-intl", 23*time.Minute, now)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Render(tc.ev)
			got := "Subject: " + m.Subject + "\n\n" + m.Body
			path := filepath.Join("testdata", tc.name+".golden")
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if want := string(goldenDoc(t, tc.name+".golden")); got != want {
				t.Errorf("render mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
			}
		})
	}
}

func TestHealthEventIdentity(t *testing.T) {
	now := time.Date(2026, 9, 21, 10, 30, 0, 0, time.UTC)
	since := now.Add(-time.Hour)
	a := SourceBlind("huawei-intl", "timeout", since, now)
	b := SourceBlind("huawei-intl", "timeout", since, now)
	c := SourceBlind("huawei-intl", "WAF block", since, now)
	rec := SourceRecovered("huawei-intl", time.Hour, now)

	if EventID(a) != EventID(b) {
		t.Error("same blind reason produced different ids")
	}
	if EventID(a) == EventID(c) {
		t.Error("different blind reasons produced the same id")
	}
	if ThreadID(a.Record.Key) != ThreadID(rec.Record.Key) {
		t.Error("blind and recovered do not share a thread")
	}
	if a.Record.Key.ProviderID != "statwatch" || !a.Record.Global || a.Record.Severity != incident.SeverityCritical {
		t.Errorf("health record shape wrong: %+v", a.Record)
	}
	if a.Record.Status != incident.StatusOpen || rec.Record.Status != incident.StatusResolved {
		t.Error("statuses wrong")
	}
}
