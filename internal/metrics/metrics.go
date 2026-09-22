// Package metrics exposes the poller's facts as Prometheus series.
//
// It implements poller.Observer and nothing else: the poller pushes, this
// package counts. Every label value is bounded by configuration (source and
// sink names) or by a closed constant set (event kinds, anomaly kinds,
// ok/error), never by upstream data — an incident title or provider id as a
// label would grow the series set with every incident forever.
//
// Every series is pre-initialised to zero at startup. To an alert rule,
// "absent" and "zero" are different answers: rate() over a counter that does
// not exist yet returns nothing, and statusrelay_source_blind missing looks
// like "not blind" only to a human.
package metrics

import (
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/rahadiangg/statusrelay/internal/incident"
	"github.com/rahadiangg/statusrelay/internal/notify"
	"github.com/rahadiangg/statusrelay/internal/poller"
)

const ns = "statusrelay"

// EventKinds is every kind the poller can emit, for pre-initialisation. It
// is the same closed set config validates sink routes against.
var EventKinds = notify.EventKinds

var severities = []incident.Severity{
	incident.SeverityUnknown, incident.SeverityInfo, incident.SeverityMinor,
	incident.SeverityMajor, incident.SeverityCritical,
}

var deliveryResults = []string{"ok", "error", "skipped"}
var undeliveredReasons = []string{"unrouted", "error"}

// AnomalyKinds mirrors the closed set in the contract package.
var AnomalyKinds = []string{
	incident.AnomalyEmptyDescription, incident.AnomalyNullScope, incident.AnomalyDuplicateID,
	incident.AnomalyIDReuse, incident.AnomalyProgressShrank, incident.AnomalyProgressOutOfOrder,
	incident.AnomalyFutureTimestamp, incident.AnomalyBadTimestamp, incident.AnomalyUnknownSeverity,
	incident.AnomalySilentMtimeBump, incident.AnomalyCountMismatch, incident.AnomalyStatusConflict,
	incident.AnomalyUnknownStatus,
}

var statuses = []incident.Status{incident.StatusOpen, incident.StatusResolved, incident.StatusUnknown}

// Recorder is the Observer implementation.
type Recorder struct {
	polls        *prometheus.CounterVec
	pollDuration *prometheus.HistogramVec
	incomplete   *prometheus.CounterVec
	anomalies    *prometheus.CounterVec
	events       *prometheus.CounterVec
	undelivered  *prometheus.CounterVec
	deliveries   *prometheus.CounterVec
	deliveryDur  *prometheus.HistogramVec
	retries      *prometheus.CounterVec
	lastSuccess  *prometheus.GaugeVec
	selfChecks   *prometheus.CounterVec
	saveFailures prometheus.Counter

	open         *prometheus.GaugeVec
	unknown      *prometheus.GaugeVec
	records      *prometheus.GaugeVec
	blind        *prometheus.GaugeVec
	lastComplete *prometheus.GaugeVec
	lastPoll     *prometheus.GaugeVec
	failures     *prometheus.GaugeVec
	unresolved   *prometheus.GaugeVec
	mirror       *prometheus.GaugeVec
	oldestOpen   *prometheus.GaugeVec

	now func() time.Time
}

// New registers every series on reg, plus the Go and process collectors.
// The registry is the caller's, never the global default, so tests can own
// one each and the binary can choose what else to expose.
func New(reg *prometheus.Registry, version, commit string) *Recorder {
	r := &Recorder{
		polls: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "polls_total",
			Help: "Fetch attempts per source, by result."}, []string{"source", "result"}),
		pollDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: ns, Name: "poll_duration_seconds",
			Help:    "Wall time of one fetch attempt.",
			Buckets: []float64{.1, .25, .5, 1, 2.5, 5, 10, 30, 60}}, []string{"source"}),
		incomplete: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "snapshots_incomplete_total",
			Help: "Successful fetches whose snapshot could not vouch for absence (no resolution was inferred from them)."}, []string{"source"}),
		anomalies: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "snapshot_anomalies_total",
			Help: "Non-fatal oddities in upstream data, by kind."}, []string{"source", "kind"}),
		events: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "events_total",
			Help: "Transitions emitted to sinks, by kind and severity. Includes source_blind/source_recovered."}, []string{"source", "kind", "severity"}),
		undelivered: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "events_undelivered_total",
			Help: "Events no sink accepted: unrouted when every sink's route skipped it, error when every attempt failed. Nobody was paged."}, []string{"source", "reason"}),
		deliveries: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "deliveries_total",
			Help: "Per-sink delivery outcomes after retries: ok, error, or skipped by the sink's route."}, []string{"sink", "result"}),
		deliveryDur: prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: ns, Name: "delivery_duration_seconds",
			Help:    "Wall time of one delivery including retries and backoff; skipped events are not observed.",
			Buckets: []float64{.1, .25, .5, 1, 2.5, 5, 10, 30}}, []string{"sink"}),
		retries: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "delivery_retries_total",
			Help: "Retried delivery attempts. A sink that reports ok but retries every time is a flapping relay."}, []string{"sink"}),
		lastSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "last_delivery_success_timestamp_seconds",
			Help: "Unix time of the last successful delivery per sink; 0 until the first. The only way to notice a dead sink before an incident."}, []string{"sink"}),
		selfChecks: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "self_checks_total",
			Help: "Source integrity probes, by result. A failing probe marks every later snapshot incomplete."}, []string{"source", "result"}),
		saveFailures: prometheus.NewCounter(prometheus.CounterOpts{Namespace: ns, Name: "state_save_failures_total",
			Help: "Failed writes of the state file. State stays in memory; a restart before a later save re-delivers events."}),

		open: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "incidents_open",
			Help: "Matched records the provider currently lists as open. NOT a health signal: zero also means the feed is broken. Alert on statusrelay_source_blind instead."}, []string{"source"}),
		unknown: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "incidents_unknown",
			Help: "Matched records that vanished from the provider without being marked resolved. Still treated as open."}, []string{"source"}),
		records: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "records",
			Help: "All stored records per source and status, matched or not."}, []string{"source", "status"}),
		blind: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "source_blind",
			Help: "1 when the source has produced no complete snapshot within stale_after. Alert when 1: until it clears, 'no incidents' means nothing."}, []string{"source"}),
		lastComplete: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "last_complete_snapshot_timestamp_seconds",
			Help: "Unix time of the last complete snapshot; 0 until the first."}, []string{"source"}),
		lastPoll: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "last_poll_timestamp_seconds",
			Help: "Unix time of the last fetch attempt, successful or not."}, []string{"source"}),
		failures: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "consecutive_fetch_failures",
			Help: "Fetch failures since the last success."}, []string{"source"}),
		unresolved: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "provider_unresolved_count",
			Help: "The provider's own unresolved count from its statistics endpoint; a cross-check against incidents_open. Absent when the provider did not report one."}, []string{"source"}),
		mirror: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "source_using_mirror",
			Help: "1 when the last snapshot came from the adapter's fallback host. Always 0 for adapters without a mirror."}, []string{"source"}),
		oldestOpen: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "oldest_open_incident_started_timestamp_seconds",
			Help: "Publication time of the longest-running matched incident still open or unknown; 0 when none. Age = time() - this."}, []string{"source"}),
		now: time.Now,
	}
	build := prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "build_info",
		Help: "Always 1; version and commit as labels."}, []string{"version", "commit"})
	build.WithLabelValues(version, commit).Set(1)

	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		build,
		r.polls, r.pollDuration, r.incomplete, r.anomalies, r.events, r.undelivered,
		r.deliveries, r.deliveryDur, r.retries, r.lastSuccess, r.selfChecks, r.saveFailures,
		r.open, r.unknown, r.records, r.blind, r.lastComplete, r.lastPoll, r.failures, r.unresolved,
		r.mirror, r.oldestOpen,
	)
	return r
}

// Init creates every label combination at zero.
func (r *Recorder) Init(sources, sinks []string) {
	for _, s := range sources {
		for _, res := range []string{"ok", "error"} {
			r.polls.WithLabelValues(s, res)
			r.selfChecks.WithLabelValues(s, res)
		}
		r.pollDuration.WithLabelValues(s)
		r.incomplete.WithLabelValues(s)
		for _, k := range AnomalyKinds {
			r.anomalies.WithLabelValues(s, k)
		}
		for _, k := range EventKinds {
			for _, sev := range severities {
				r.events.WithLabelValues(s, string(k), sev.String())
			}
		}
		for _, reason := range undeliveredReasons {
			r.undelivered.WithLabelValues(s, reason)
		}
		for _, st := range statuses {
			r.records.WithLabelValues(s, st.String())
		}
		r.open.WithLabelValues(s)
		r.unknown.WithLabelValues(s)
		r.blind.WithLabelValues(s)
		r.lastComplete.WithLabelValues(s)
		r.lastPoll.WithLabelValues(s)
		r.failures.WithLabelValues(s)
		r.mirror.WithLabelValues(s)
		r.oldestOpen.WithLabelValues(s)
	}
	for _, k := range sinks {
		for _, res := range deliveryResults {
			r.deliveries.WithLabelValues(k, res)
		}
		r.deliveryDur.WithLabelValues(k)
		r.retries.WithLabelValues(k)
		r.lastSuccess.WithLabelValues(k)
	}
}

func result(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, notify.ErrFiltered):
		return "skipped"
	default:
		return "error"
	}
}

func (r *Recorder) PollDone(source string, d time.Duration, failures int, err error) {
	r.polls.WithLabelValues(source, result(err)).Inc()
	r.pollDuration.WithLabelValues(source).Observe(d.Seconds())
	r.lastPoll.WithLabelValues(source).Set(float64(r.now().Unix()))
	r.failures.WithLabelValues(source).Set(float64(failures))
}

func (r *Recorder) SnapshotSeen(source string, snap *incident.Snapshot) {
	if !snap.Complete {
		r.incomplete.WithLabelValues(source).Inc()
	}
	for _, w := range snap.Warnings {
		r.anomalies.WithLabelValues(source, w.Kind).Inc()
	}
	// -1 means "not reported"; a graph must never show it as a count.
	if snap.UnresolvedCount >= 0 {
		r.unresolved.WithLabelValues(source).Set(float64(snap.UnresolvedCount))
	}
	r.mirror.WithLabelValues(source).Set(b2f(snap.Mirror))
}

func (r *Recorder) EventsEmitted(source string, evs []incident.Event) {
	for _, ev := range evs {
		r.events.WithLabelValues(source, string(ev.Kind), ev.Record.Severity.String()).Inc()
	}
}

func (r *Recorder) Undelivered(source, reason string) {
	r.undelivered.WithLabelValues(source, reason).Inc()
}

func (r *Recorder) Delivered(sink string, d time.Duration, err error) {
	res := result(err)
	r.deliveries.WithLabelValues(sink, res).Inc()
	if res == "skipped" {
		// Nothing was attempted; a zero-length observation would drag the
		// latency histogram toward a number no relay ever produced.
		return
	}
	r.deliveryDur.WithLabelValues(sink).Observe(d.Seconds())
	if err == nil {
		r.lastSuccess.WithLabelValues(sink).Set(float64(r.now().Unix()))
	}
}

// Retried is the notify.OnRetry hook; it is not part of poller.Observer
// because retries happen inside the sink, below the poller's view.
func (r *Recorder) Retried(sink string) {
	r.retries.WithLabelValues(sink).Inc()
}

func (r *Recorder) StateApplied(source string, st poller.State) {
	r.open.WithLabelValues(source).Set(float64(st.Open))
	r.unknown.WithLabelValues(source).Set(float64(st.Unknown))
	for _, status := range statuses {
		r.records.WithLabelValues(source, status.String()).Set(float64(st.Records[status]))
	}
	r.blind.WithLabelValues(source).Set(b2f(st.Blind))
	if !st.LastComplete.IsZero() {
		r.lastComplete.WithLabelValues(source).Set(float64(st.LastComplete.Unix()))
	}
	oldest := 0.0
	if !st.OldestOpen.IsZero() {
		oldest = float64(st.OldestOpen.Unix())
	}
	r.oldestOpen.WithLabelValues(source).Set(oldest)
}

func (r *Recorder) SelfChecked(source string, err error) {
	r.selfChecks.WithLabelValues(source, result(err)).Inc()
}

func (r *Recorder) Saved(err error) {
	if err != nil {
		r.saveFailures.Inc()
	}
}

var _ poller.Observer = (*Recorder)(nil)

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
