package metrics

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rahadiangg/statwatch/internal/incident"
	"github.com/rahadiangg/statwatch/internal/notify"
	"github.com/rahadiangg/statwatch/internal/poller"
)

var testEpoch = time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)

func newTestRecorder(t *testing.T) (*Recorder, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	r := New(reg, "v1.2.3", "abc123")
	r.now = func() time.Time { return testEpoch }
	r.Init([]string{"huawei-intl"}, []string{"telegram/oncall"})
	return r, reg
}

func TestInitCreatesEverySeriesAtZero(t *testing.T) {
	_, reg := newTestRecorder(t)
	for _, tc := range []struct {
		name string
		want int
	}{
		{"statwatch_polls_total", 2},
		{"statwatch_self_checks_total", 2},
		{"statwatch_snapshot_anomalies_total", len(AnomalyKinds)},
		{"statwatch_events_total", len(EventKinds)},
		{"statwatch_records", 3},
		{"statwatch_deliveries_total", 2},
		{"statwatch_incidents_open", 1},
		{"statwatch_incidents_unknown", 1},
		{"statwatch_source_blind", 1},
		{"statwatch_last_complete_snapshot_timestamp_seconds", 1},
		{"statwatch_last_poll_timestamp_seconds", 1},
		{"statwatch_consecutive_fetch_failures", 1},
		{"statwatch_snapshots_incomplete_total", 1},
		{"statwatch_provider_unresolved_count", 0}, // absent until reported
		{"statwatch_build_info", 1},
	} {
		if got := testutil.CollectAndCount(reg, tc.name); got != tc.want {
			t.Errorf("%s: got %d series, want %d", tc.name, got, tc.want)
		}
	}
	if got := testutil.ToFloat64(mustGauge(t, reg, "statwatch_source_blind")); got != 0 {
		t.Errorf("source_blind initial %v, want 0", got)
	}
}

// mustGauge finds a single-series metric family by name for ToFloat64.
func mustGauge(t *testing.T, reg *prometheus.Registry, name string) prometheus.Collector {
	t.Helper()
	fams, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() == name {
			g := prometheus.NewGauge(prometheus.GaugeOpts{Name: name})
			g.Set(f.GetMetric()[0].GetGauge().GetValue())
			return g
		}
	}
	t.Fatalf("metric %s not found", name)
	return nil
}

func TestScriptedSequenceExposition(t *testing.T) {
	r, reg := newTestRecorder(t)
	src := "huawei-intl"

	r.SelfChecked(src, nil)
	r.PollDone(src, 800*time.Millisecond, 0, nil)
	r.SnapshotSeen(src, &incident.Snapshot{Complete: true, UnresolvedCount: 1})
	r.EventsEmitted(src, []incident.Event{{Kind: incident.KindNew}, {Kind: incident.KindNew}, {Kind: notify.KindSourceBlind}})
	r.Delivered("telegram/oncall", nil)
	r.Delivered("telegram/oncall", errors.New("boom"))
	r.StateApplied(src, poller.State{
		Open: 1, Unknown: 2, Blind: true, LastComplete: testEpoch,
		Records: map[incident.Status]int{incident.StatusOpen: 1, incident.StatusResolved: 5, incident.StatusUnknown: 2},
	})
	r.PollDone(src, 2*time.Second, 3, errors.New("timeout"))
	r.SnapshotSeen(src, &incident.Snapshot{Complete: false, UnresolvedCount: -1,
		Warnings: []incident.Warning{{Kind: incident.AnomalyCountMismatch}, {Kind: incident.AnomalyCountMismatch}}})
	r.Saved(errors.New("disk full"))
	r.SelfChecked(src, errors.New("drift"))

	want := `
# HELP statwatch_consecutive_fetch_failures Fetch failures since the last success.
# TYPE statwatch_consecutive_fetch_failures gauge
statwatch_consecutive_fetch_failures{source="huawei-intl"} 3
# HELP statwatch_deliveries_total Per-sink delivery attempts after retries, by result.
# TYPE statwatch_deliveries_total counter
statwatch_deliveries_total{result="error",sink="telegram/oncall"} 1
statwatch_deliveries_total{result="ok",sink="telegram/oncall"} 1
# HELP statwatch_incidents_open Matched records the provider currently lists as open. NOT a health signal: zero also means the feed is broken. Alert on statwatch_source_blind instead.
# TYPE statwatch_incidents_open gauge
statwatch_incidents_open{source="huawei-intl"} 1
# HELP statwatch_incidents_unknown Matched records that vanished from the provider without being marked resolved. Still treated as open.
# TYPE statwatch_incidents_unknown gauge
statwatch_incidents_unknown{source="huawei-intl"} 2
# HELP statwatch_last_complete_snapshot_timestamp_seconds Unix time of the last complete snapshot; 0 until the first.
# TYPE statwatch_last_complete_snapshot_timestamp_seconds gauge
statwatch_last_complete_snapshot_timestamp_seconds{source="huawei-intl"} 1.7899848e+09
# HELP statwatch_last_poll_timestamp_seconds Unix time of the last fetch attempt, successful or not.
# TYPE statwatch_last_poll_timestamp_seconds gauge
statwatch_last_poll_timestamp_seconds{source="huawei-intl"} 1.7899848e+09
# HELP statwatch_polls_total Fetch attempts per source, by result.
# TYPE statwatch_polls_total counter
statwatch_polls_total{result="error",source="huawei-intl"} 1
statwatch_polls_total{result="ok",source="huawei-intl"} 1
# HELP statwatch_provider_unresolved_count The provider's own unresolved count from its statistics endpoint; a cross-check against incidents_open. Absent when the provider did not report one.
# TYPE statwatch_provider_unresolved_count gauge
statwatch_provider_unresolved_count{source="huawei-intl"} 1
# HELP statwatch_records All stored records per source and status, matched or not.
# TYPE statwatch_records gauge
statwatch_records{source="huawei-intl",status="open"} 1
statwatch_records{source="huawei-intl",status="resolved"} 5
statwatch_records{source="huawei-intl",status="unknown"} 2
# HELP statwatch_self_checks_total Source integrity probes, by result. A failing probe marks every later snapshot incomplete.
# TYPE statwatch_self_checks_total counter
statwatch_self_checks_total{result="error",source="huawei-intl"} 1
statwatch_self_checks_total{result="ok",source="huawei-intl"} 1
# HELP statwatch_snapshots_incomplete_total Successful fetches whose snapshot could not vouch for absence (no resolution was inferred from them).
# TYPE statwatch_snapshots_incomplete_total counter
statwatch_snapshots_incomplete_total{source="huawei-intl"} 1
# HELP statwatch_source_blind 1 when the source has produced no complete snapshot within stale_after. Alert when 1: until it clears, 'no incidents' means nothing.
# TYPE statwatch_source_blind gauge
statwatch_source_blind{source="huawei-intl"} 1
# HELP statwatch_state_save_failures_total Failed writes of the state file. State stays in memory; a restart before a later save re-delivers events.
# TYPE statwatch_state_save_failures_total counter
statwatch_state_save_failures_total 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want),
		"statwatch_consecutive_fetch_failures", "statwatch_deliveries_total", "statwatch_incidents_open",
		"statwatch_incidents_unknown", "statwatch_last_complete_snapshot_timestamp_seconds",
		"statwatch_last_poll_timestamp_seconds", "statwatch_polls_total", "statwatch_provider_unresolved_count",
		"statwatch_records", "statwatch_self_checks_total", "statwatch_snapshots_incomplete_total",
		"statwatch_source_blind", "statwatch_state_save_failures_total"); err != nil {
		t.Error(err)
	}

	// Vectors with many pre-initialised series: check the touched values only.
	if got := testutil.ToFloat64(r.events.WithLabelValues(src, "new")); got != 2 {
		t.Errorf("events new = %v, want 2", got)
	}
	if got := testutil.ToFloat64(r.events.WithLabelValues(src, "source_blind")); got != 1 {
		t.Errorf("events source_blind = %v, want 1", got)
	}
	if got := testutil.ToFloat64(r.anomalies.WithLabelValues(src, incident.AnomalyCountMismatch)); got != 2 {
		t.Errorf("anomalies count_mismatch = %v, want 2", got)
	}
	if got := testutil.CollectAndCount(reg, "statwatch_poll_duration_seconds"); got != 1 {
		t.Errorf("histogram series = %d, want 1", got)
	}
}

func TestUnresolvedCountNegativeIsNeverExposed(t *testing.T) {
	r, reg := newTestRecorder(t)
	r.SnapshotSeen("huawei-intl", &incident.Snapshot{Complete: true, UnresolvedCount: -1})
	if got := testutil.CollectAndCount(reg, "statwatch_provider_unresolved_count"); got != 0 {
		t.Errorf("got %d series after -1, want 0", got)
	}
	r.SnapshotSeen("huawei-intl", &incident.Snapshot{Complete: true, UnresolvedCount: 4})
	r.SnapshotSeen("huawei-intl", &incident.Snapshot{Complete: true, UnresolvedCount: -1})
	if got := testutil.ToFloat64(r.unresolved.WithLabelValues("huawei-intl")); got != 4 {
		t.Errorf("got %v after 4 then -1, want 4 retained", got)
	}
}

func TestLastCompleteZeroIsNotWritten(t *testing.T) {
	r, _ := newTestRecorder(t)
	r.StateApplied("huawei-intl", poller.State{Records: map[incident.Status]int{}})
	if got := testutil.ToFloat64(r.lastComplete.WithLabelValues("huawei-intl")); got != 0 {
		t.Errorf("got %v, want 0 for never-complete", got)
	}
}

func TestBuildInfoLabels(t *testing.T) {
	_, reg := newTestRecorder(t)
	want := `
# HELP statwatch_build_info Always 1; version and commit as labels.
# TYPE statwatch_build_info gauge
statwatch_build_info{commit="abc123",version="v1.2.3"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "statwatch_build_info"); err != nil {
		t.Error(err)
	}
}

func TestGoAndProcessCollectorsRegistered(t *testing.T) {
	_, reg := newTestRecorder(t)
	if testutil.CollectAndCount(reg, "go_goroutines") != 1 {
		t.Error("go collector missing")
	}
}
