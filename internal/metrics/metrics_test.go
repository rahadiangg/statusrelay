package metrics

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rahadiangg/statusrelay/internal/incident"
	"github.com/rahadiangg/statusrelay/internal/notify"
	"github.com/rahadiangg/statusrelay/internal/poller"
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
		{"statusrelay_polls_total", 2},
		{"statusrelay_self_checks_total", 2},
		{"statusrelay_snapshot_anomalies_total", len(AnomalyKinds)},
		{"statusrelay_events_total", len(EventKinds) * 5}, // x severities
		{"statusrelay_events_undelivered_total", 2},
		{"statusrelay_records", 3},
		{"statusrelay_deliveries_total", 3},
		{"statusrelay_delivery_duration_seconds", 1},
		{"statusrelay_delivery_retries_total", 1},
		{"statusrelay_last_delivery_success_timestamp_seconds", 1},
		{"statusrelay_source_using_mirror", 1},
		{"statusrelay_oldest_open_incident_started_timestamp_seconds", 1},
		{"statusrelay_incidents_open", 1},
		{"statusrelay_incidents_unknown", 1},
		{"statusrelay_source_blind", 1},
		{"statusrelay_last_complete_snapshot_timestamp_seconds", 1},
		{"statusrelay_last_poll_timestamp_seconds", 1},
		{"statusrelay_consecutive_fetch_failures", 1},
		{"statusrelay_snapshots_incomplete_total", 1},
		{"statusrelay_provider_unresolved_count", 0}, // absent until reported
		{"statusrelay_build_info", 1},
	} {
		if got := testutil.CollectAndCount(reg, tc.name); got != tc.want {
			t.Errorf("%s: got %d series, want %d", tc.name, got, tc.want)
		}
	}
	if got := testutil.ToFloat64(mustGauge(t, reg, "statusrelay_source_blind")); got != 0 {
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

// histogramCount returns the sample count of a single-series histogram.
func histogramCount(reg *prometheus.Registry, name string) (uint64, error) {
	fams, err := reg.Gather()
	if err != nil {
		return 0, err
	}
	for _, f := range fams {
		if f.GetName() == name {
			return f.GetMetric()[0].GetHistogram().GetSampleCount(), nil
		}
	}
	return 0, fmt.Errorf("metric %s not found", name)
}

func TestScriptedSequenceExposition(t *testing.T) {
	r, reg := newTestRecorder(t)
	src := "huawei-intl"

	r.SelfChecked(src, nil)
	r.PollDone(src, 800*time.Millisecond, 0, nil)
	r.SnapshotSeen(src, &incident.Snapshot{Complete: true, UnresolvedCount: 1})
	major := incident.Record{Severity: incident.SeverityMajor}
	r.EventsEmitted(src, []incident.Event{{Kind: incident.KindNew, Record: major}, {Kind: incident.KindNew, Record: major}, {Kind: notify.KindSourceBlind}})
	r.Delivered("telegram/oncall", 300*time.Millisecond, nil)
	r.Delivered("telegram/oncall", 4*time.Second, errors.New("boom"))
	r.Delivered("telegram/oncall", 0, notify.ErrFiltered)
	r.Retried("telegram/oncall")
	r.Undelivered(src, "error")
	r.StateApplied(src, poller.State{
		Open: 1, Unknown: 2, Blind: true, LastComplete: testEpoch, OldestOpen: testEpoch.Add(-time.Hour),
		Records: map[incident.Status]int{incident.StatusOpen: 1, incident.StatusResolved: 5, incident.StatusUnknown: 2},
	})
	r.PollDone(src, 2*time.Second, 3, errors.New("timeout"))
	r.SnapshotSeen(src, &incident.Snapshot{Complete: false, UnresolvedCount: -1,
		Warnings: []incident.Warning{{Kind: incident.AnomalyCountMismatch}, {Kind: incident.AnomalyCountMismatch}}})
	r.Saved(errors.New("disk full"))
	r.SelfChecked(src, errors.New("drift"))

	want := `
# HELP statusrelay_consecutive_fetch_failures Fetch failures since the last success.
# TYPE statusrelay_consecutive_fetch_failures gauge
statusrelay_consecutive_fetch_failures{source="huawei-intl"} 3
# HELP statusrelay_deliveries_total Per-sink delivery outcomes after retries: ok, error, or skipped by the sink's route.
# TYPE statusrelay_deliveries_total counter
statusrelay_deliveries_total{result="error",sink="telegram/oncall"} 1
statusrelay_deliveries_total{result="ok",sink="telegram/oncall"} 1
statusrelay_deliveries_total{result="skipped",sink="telegram/oncall"} 1
# HELP statusrelay_delivery_retries_total Retried delivery attempts. A sink that reports ok but retries every time is a flapping relay.
# TYPE statusrelay_delivery_retries_total counter
statusrelay_delivery_retries_total{sink="telegram/oncall"} 1
# HELP statusrelay_events_undelivered_total Events no sink accepted: unrouted when every sink's route skipped it, error when every attempt failed. Nobody was paged.
# TYPE statusrelay_events_undelivered_total counter
statusrelay_events_undelivered_total{reason="error",source="huawei-intl"} 1
statusrelay_events_undelivered_total{reason="unrouted",source="huawei-intl"} 0
# HELP statusrelay_incidents_open Matched records the provider currently lists as open. NOT a health signal: zero also means the feed is broken. Alert on statusrelay_source_blind instead.
# TYPE statusrelay_incidents_open gauge
statusrelay_incidents_open{source="huawei-intl"} 1
# HELP statusrelay_incidents_unknown Matched records that vanished from the provider without being marked resolved. Still treated as open.
# TYPE statusrelay_incidents_unknown gauge
statusrelay_incidents_unknown{source="huawei-intl"} 2
# HELP statusrelay_last_complete_snapshot_timestamp_seconds Unix time of the last complete snapshot; 0 until the first.
# TYPE statusrelay_last_complete_snapshot_timestamp_seconds gauge
statusrelay_last_complete_snapshot_timestamp_seconds{source="huawei-intl"} 1.7899848e+09
# HELP statusrelay_last_delivery_success_timestamp_seconds Unix time of the last successful delivery per sink; 0 until the first. The only way to notice a dead sink before an incident.
# TYPE statusrelay_last_delivery_success_timestamp_seconds gauge
statusrelay_last_delivery_success_timestamp_seconds{sink="telegram/oncall"} 1.7899848e+09
# HELP statusrelay_last_poll_timestamp_seconds Unix time of the last fetch attempt, successful or not.
# TYPE statusrelay_last_poll_timestamp_seconds gauge
statusrelay_last_poll_timestamp_seconds{source="huawei-intl"} 1.7899848e+09
# HELP statusrelay_oldest_open_incident_started_timestamp_seconds Publication time of the longest-running matched incident still open or unknown; 0 when none. Age = time() - this.
# TYPE statusrelay_oldest_open_incident_started_timestamp_seconds gauge
statusrelay_oldest_open_incident_started_timestamp_seconds{source="huawei-intl"} 1.7899812e+09
# HELP statusrelay_polls_total Fetch attempts per source, by result.
# TYPE statusrelay_polls_total counter
statusrelay_polls_total{result="error",source="huawei-intl"} 1
statusrelay_polls_total{result="ok",source="huawei-intl"} 1
# HELP statusrelay_provider_unresolved_count The provider's own unresolved count from its statistics endpoint; a cross-check against incidents_open. Absent when the provider did not report one.
# TYPE statusrelay_provider_unresolved_count gauge
statusrelay_provider_unresolved_count{source="huawei-intl"} 1
# HELP statusrelay_records All stored records per source and status, matched or not.
# TYPE statusrelay_records gauge
statusrelay_records{source="huawei-intl",status="open"} 1
statusrelay_records{source="huawei-intl",status="resolved"} 5
statusrelay_records{source="huawei-intl",status="unknown"} 2
# HELP statusrelay_self_checks_total Source integrity probes, by result. A failing probe marks every later snapshot incomplete.
# TYPE statusrelay_self_checks_total counter
statusrelay_self_checks_total{result="error",source="huawei-intl"} 1
statusrelay_self_checks_total{result="ok",source="huawei-intl"} 1
# HELP statusrelay_snapshots_incomplete_total Successful fetches whose snapshot could not vouch for absence (no resolution was inferred from them).
# TYPE statusrelay_snapshots_incomplete_total counter
statusrelay_snapshots_incomplete_total{source="huawei-intl"} 1
# HELP statusrelay_source_blind 1 when the source has produced no complete snapshot within stale_after. Alert when 1: until it clears, 'no incidents' means nothing.
# TYPE statusrelay_source_blind gauge
statusrelay_source_blind{source="huawei-intl"} 1
# HELP statusrelay_source_using_mirror 1 when the last snapshot came from the adapter's fallback host. Always 0 for adapters without a mirror.
# TYPE statusrelay_source_using_mirror gauge
statusrelay_source_using_mirror{source="huawei-intl"} 0
# HELP statusrelay_state_save_failures_total Failed writes of the state file. State stays in memory; a restart before a later save re-delivers events.
# TYPE statusrelay_state_save_failures_total counter
statusrelay_state_save_failures_total 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want),
		"statusrelay_consecutive_fetch_failures", "statusrelay_deliveries_total", "statusrelay_delivery_retries_total",
		"statusrelay_events_undelivered_total", "statusrelay_incidents_open",
		"statusrelay_incidents_unknown", "statusrelay_last_complete_snapshot_timestamp_seconds",
		"statusrelay_last_delivery_success_timestamp_seconds", "statusrelay_last_poll_timestamp_seconds",
		"statusrelay_oldest_open_incident_started_timestamp_seconds", "statusrelay_polls_total",
		"statusrelay_provider_unresolved_count", "statusrelay_records", "statusrelay_self_checks_total",
		"statusrelay_snapshots_incomplete_total", "statusrelay_source_blind", "statusrelay_source_using_mirror",
		"statusrelay_state_save_failures_total"); err != nil {
		t.Error(err)
	}

	// Vectors with many pre-initialised series: check the touched values only.
	if got := testutil.ToFloat64(r.events.WithLabelValues(src, "new", "major")); got != 2 {
		t.Errorf("events new/major = %v, want 2", got)
	}
	if got := testutil.ToFloat64(r.events.WithLabelValues(src, "source_blind", "unknown")); got != 1 {
		t.Errorf("events source_blind/unknown = %v, want 1", got)
	}
	// Two attempted deliveries were timed; the skipped one must not be.
	if got := testutil.CollectAndCount(reg, "statusrelay_delivery_duration_seconds"); got != 1 {
		t.Errorf("delivery_duration series = %d, want 1", got)
	}
	if got, err := histogramCount(reg, "statusrelay_delivery_duration_seconds"); err != nil || got != 2 {
		t.Errorf("delivery_duration observations = %d (%v), want 2", got, err)
	}
	if got := testutil.ToFloat64(r.anomalies.WithLabelValues(src, incident.AnomalyCountMismatch)); got != 2 {
		t.Errorf("anomalies count_mismatch = %v, want 2", got)
	}
	if got := testutil.CollectAndCount(reg, "statusrelay_poll_duration_seconds"); got != 1 {
		t.Errorf("histogram series = %d, want 1", got)
	}
}

func TestUnresolvedCountNegativeIsNeverExposed(t *testing.T) {
	r, reg := newTestRecorder(t)
	r.SnapshotSeen("huawei-intl", &incident.Snapshot{Complete: true, UnresolvedCount: -1})
	if got := testutil.CollectAndCount(reg, "statusrelay_provider_unresolved_count"); got != 0 {
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
# HELP statusrelay_build_info Always 1; version and commit as labels.
# TYPE statusrelay_build_info gauge
statusrelay_build_info{commit="abc123",version="v1.2.3"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "statusrelay_build_info"); err != nil {
		t.Error(err)
	}
}

func TestGoAndProcessCollectorsRegistered(t *testing.T) {
	_, reg := newTestRecorder(t)
	if testutil.CollectAndCount(reg, "go_goroutines") != 1 {
		t.Error("go collector missing")
	}
}
