package notify

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rahadiangg/statusrelay/internal/incident"
)

func TestFilterAccepts(t *testing.T) {
	major := event13() // huawei-intl, KindNew, SeverityMajor
	unknown := event13()
	unknown.Record.Severity = incident.SeverityUnknown
	resolved := event13()
	resolved.Kind = incident.KindResolved
	blind := SourceBlind("alibaba-intl", "timeout", time.Time{}, time.Now())

	for _, tc := range []struct {
		name string
		f    Filter
		ev   incident.Event
		want bool
	}{
		{"zero filter accepts everything", Filter{}, major, true},
		{"severity at floor passes", Filter{MinSeverity: incident.SeverityMajor}, major, true},
		{"severity below floor is dropped", Filter{MinSeverity: incident.SeverityCritical}, major, false},
		{"unknown severity always passes a floor", Filter{MinSeverity: incident.SeverityCritical}, unknown, true},
		{"kind listed", Filter{Kinds: map[incident.EventKind]bool{incident.KindResolved: true}}, resolved, true},
		{"kind not listed", Filter{Kinds: map[incident.EventKind]bool{incident.KindResolved: true}}, major, false},
		{"source listed", Filter{Sources: map[string]bool{"huawei-intl": true}}, major, true},
		{"source not listed", Filter{Sources: map[string]bool{"alibaba-intl": true}}, major, false},
		// A sink scoped to one source must still hear that source go blind:
		// health events carry the source id and are critical.
		{"health event routes by its source", Filter{Sources: map[string]bool{"alibaba-intl": true}, MinSeverity: incident.SeverityCritical}, blind, true},
		{"health event excluded by kinds list", Filter{Kinds: map[incident.EventKind]bool{incident.KindNew: true}}, blind, false},
		{"all three combined", Filter{MinSeverity: incident.SeverityMinor, Kinds: map[incident.EventKind]bool{incident.KindNew: true}, Sources: map[string]bool{"huawei-intl": true}}, major, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.f.Accepts(tc.ev); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWithFilter(t *testing.T) {
	inner := &Fake{NameStr: "fake/x"}
	n := WithFilter(inner, Filter{Kinds: map[incident.EventKind]bool{incident.KindResolved: true}})

	err := n.Send(context.Background(), event13())
	if !errors.Is(err, ErrFiltered) {
		t.Errorf("got err %v, want ErrFiltered", err)
	}
	if errors.Is(err, ErrTransient) || errors.Is(err, ErrPermanent) {
		t.Error("ErrFiltered must be neither transient nor permanent, or a retrier would act on it")
	}
	if got := len(inner.Calls()); got != 0 {
		t.Errorf("inner sink called %d times for a filtered event, want 0", got)
	}

	ev := event13()
	ev.Kind = incident.KindResolved
	if err := n.Send(context.Background(), ev); err != nil {
		t.Errorf("accepted event: got err %v, want nil", err)
	}
	if got := len(inner.Calls()); got != 1 {
		t.Errorf("inner sink called %d times for an accepted event, want 1", got)
	}
	if n.Name() != "fake/x" {
		t.Errorf("got name %q, want fake/x", n.Name())
	}
	// An empty filter is a no-op wrapper: the same value comes back.
	if WithFilter(inner, Filter{}) != Notifier(inner) {
		t.Error("empty filter wrapped the sink; want it returned unchanged")
	}
}

// Every kind the poller can emit is routable, and the list has no gaps a
// config validator would reject a real event for.
func TestEventKindsCoversHealthKinds(t *testing.T) {
	seen := map[incident.EventKind]bool{}
	for _, k := range EventKinds {
		seen[k] = true
	}
	for _, k := range []incident.EventKind{KindSourceBlind, KindSourceRecovered, incident.KindNew, incident.KindScopeExited} {
		if !seen[k] {
			t.Errorf("EventKinds is missing %q", k)
		}
	}
}
