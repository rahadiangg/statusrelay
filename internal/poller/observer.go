package poller

import (
	"maps"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
)

// Observer receives the loop's facts as they happen. It is push-only so the
// poller never depends on a metrics library and a metrics package never
// reaches into poller state. Methods are called from the loop goroutine, in
// order, never concurrently.
type Observer interface {
	// PollDone follows every fetch attempt; err is nil on success and
	// failures is the consecutive failure count after this attempt.
	PollDone(source string, d time.Duration, failures int, err error)
	// SnapshotSeen follows a successful fetch, before diffing.
	SnapshotSeen(source string, snap *incident.Snapshot)
	// EventsEmitted carries the diff result, possibly empty.
	EventsEmitted(source string, evs []incident.Event)
	// Delivered is called once per sink per event.
	Delivered(sink string, err error)
	// StateApplied follows Apply with this source's counts as of this poll.
	StateApplied(source string, st State)
	SelfChecked(source string, err error)
	Saved(err error)
}

// State is what StateApplied reports.
type State struct {
	// Open and Unknown count matched records only: what is being alerted on.
	Open, Unknown int
	// Records counts every stored record for the source, matched or not.
	Records map[incident.Status]int
	Blind   bool
	// LastComplete is zero until the first complete snapshot.
	LastComplete time.Time
}

// Nop is the default Observer.
type Nop struct{}

func (Nop) PollDone(string, time.Duration, int, error) {}
func (Nop) SnapshotSeen(string, *incident.Snapshot)    {}
func (Nop) EventsEmitted(string, []incident.Event)     {}
func (Nop) Delivered(string, error)                    {}
func (Nop) StateApplied(string, State)                 {}
func (Nop) SelfChecked(string, error)                  {}
func (Nop) Saved(error)                                {}

// Health is the probe view of the loop. It is a copy; mutating it changes
// nothing.
type Health struct {
	// LastLoop is when the most recent pollAll began. A liveness probe
	// compares it to now.
	LastLoop time.Time
	Sources  map[string]SourceHealth
}

// SourceHealth is one source's readiness.
type SourceHealth struct {
	// EverComplete is false until the first complete snapshot. Before that
	// the source is not blind, but it is not ready either.
	EverComplete bool
	Blind        bool
	LastComplete time.Time
	// Failures is the consecutive fetch failure count.
	Failures int
}

// Health returns the current probe view. Safe from any goroutine.
func (p *Poller) Health() Health {
	p.hmu.RLock()
	defer p.hmu.RUnlock()
	out := Health{LastLoop: p.health.LastLoop}
	if p.health.Sources != nil {
		// nil stays nil: it is how a probe tells "not started" from
		// "started with nothing to report".
		out.Sources = make(map[string]SourceHealth, len(p.health.Sources))
		maps.Copy(out.Sources, p.health.Sources)
	}
	return out
}

// publishHealth snapshots the loop's bookkeeping for probes. Called once per
// poll and on blind transitions, from the loop goroutine.
func (p *Poller) publishHealth(lastLoop time.Time) {
	h := Health{LastLoop: lastLoop, Sources: make(map[string]SourceHealth, len(p.src))}
	for id, st := range p.src {
		h.Sources[id] = SourceHealth{
			EverComplete: st.everComplete,
			Blind:        st.blind,
			LastComplete: st.lastComplete,
			Failures:     st.failures,
		}
	}
	p.hmu.Lock()
	p.health = h
	p.hmu.Unlock()
}
