package notify

import (
	"context"

	"github.com/rahadiangg/statusrelay/internal/incident"
)

// EventKinds is every kind a sink can be asked to route, in emission order.
// It is the closed set config validation checks against, so a misspelt kind
// is a startup error rather than a sink that silently never fires.
var EventKinds = []incident.EventKind{
	incident.KindNew, incident.KindUpdated, incident.KindScopeChanged, incident.KindMinorUpdated,
	incident.KindResolved, incident.KindResolvedInferred, incident.KindReopened,
	incident.KindMissedAndResolved, incident.KindUpdatedAfterResolve, incident.KindVanished,
	incident.KindScopeExited, KindSourceBlind, KindSourceRecovered,
}

// Filter is one sink's route: which events it wants. The zero value accepts
// everything, which is what a v0.1 config with no routing keys means.
type Filter struct {
	// MinSeverity is the floor. SeverityUnknown always passes, mirroring the
	// source filter: a level nobody has graded yet is exactly the one that
	// must not be dropped by a threshold.
	MinSeverity incident.Severity
	// Kinds, when non-empty, is the only kinds delivered.
	Kinds map[incident.EventKind]bool
	// Sources, when non-empty, is the only source ids delivered. Health
	// events carry their source id, so a sink scoped to one source still
	// learns when that source goes blind.
	Sources map[string]bool
}

// Accepts reports whether ev should reach the sink.
func (f Filter) Accepts(ev incident.Event) bool {
	if len(f.Kinds) > 0 && !f.Kinds[ev.Kind] {
		return false
	}
	if len(f.Sources) > 0 && !f.Sources[ev.Record.Key.SourceID] {
		return false
	}
	sev := ev.Record.Severity
	if sev != incident.SeverityUnknown && sev < f.MinSeverity {
		return false
	}
	return true
}

// Empty reports whether the filter accepts everything.
func (f Filter) Empty() bool {
	return f.MinSeverity == incident.SeverityUnknown && len(f.Kinds) == 0 && len(f.Sources) == 0
}

// WithFilter wraps n so events the route excludes return ErrFiltered without
// touching the transport. Wrap it OUTSIDE WithRetry: the sentinel is not
// transient, but a retrier should never have to know that.
func WithFilter(n Notifier, f Filter) Notifier {
	if f.Empty() {
		return n
	}
	return &filtered{n: n, f: f}
}

type filtered struct {
	n Notifier
	f Filter
}

func (w *filtered) Name() string { return w.n.Name() }

func (w *filtered) Send(ctx context.Context, ev incident.Event) error {
	if !w.f.Accepts(ev) {
		return ErrFiltered
	}
	return w.n.Send(ctx, ev)
}
