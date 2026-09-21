// Package poller runs the loop: fetch every source on a cadence, diff against
// persisted state, fan the resulting events out to sinks, persist.
//
// Two rules from the contract are enforced here rather than trusted:
//
//   - A failed fetch returns before any diff. The resolution sweep must never
//     run on a snapshot that does not exist.
//   - Events are delivered BEFORE state is saved. A crash between the two
//     re-delivers on restart (receivers dedupe on EventID); the other order
//     loses the alert forever.
//
// The poller also watches itself. A source that has produced no complete
// snapshot for StaleAfter is "blind", and that transition is delivered through
// the same sinks as an incident, because to anyone not told otherwise a blind
// watcher looks exactly like a healthy provider.
package poller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/rahadiangg/statusrelay/internal/incident"
	"github.com/rahadiangg/statusrelay/internal/notify"
	"github.com/rahadiangg/statusrelay/internal/platform/clock"
	"github.com/rahadiangg/statusrelay/internal/store"
)

// Sink is where events go. It is notify.Notifier by another name so this
// package depends on the contract, not on any transport.
type Sink interface {
	Name() string
	Send(ctx context.Context, ev incident.Event) error
}

// Store is the persistence the poller needs. *store.Store satisfies it; tests
// use a fake.
type Store interface {
	Load() (map[incident.Key]incident.Stored, error)
	Save(m map[incident.Key]incident.Stored, now time.Time) error
}

// RegionValidator is implemented by sources that can reconcile configured
// regions against a live catalogue. Checked at startup only.
type RegionValidator interface {
	ValidateRegions(ctx context.Context) error
}

// Options configures the loop.
type Options struct {
	Interval          time.Duration
	FetchTimeout      time.Duration
	SelfCheckInterval time.Duration
	StaleAfter        time.Duration
	VanishGrace       int
	// Filters is the notification filter per source id. A source with no
	// entry uses the zero Filter, which matches nothing regional and drops
	// global events — config guarantees an entry, but the fallback is the
	// quiet direction, not the noisy one.
	Filters map[string]incident.Filter

	Clock    clock.Clock
	Log      *slog.Logger
	Observer Observer
}

// Poller is one running loop.
type Poller struct {
	sources []incident.Source
	sinks   []Sink
	store   Store
	o       Options

	state map[incident.Key]incident.Stored
	src   map[string]*sourceState

	hmu    sync.RWMutex
	health Health
}

// sourceState is the poller's own bookkeeping per source.
type sourceState struct {
	coldStart     bool
	everComplete  bool
	lastComplete  time.Time
	lastSelfCheck time.Time
	failures      int    // consecutive fetch failures
	lastProblem   string // last fetch error or incompleteness reason
	blind         bool
	blindSince    time.Time
}

// New builds a Poller. Nothing runs until Run.
func New(sources []incident.Source, sinks []Sink, st Store, o Options) *Poller {
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.VanishGrace < 1 {
		o.VanishGrace = 1
	}
	if o.Observer == nil {
		o.Observer = Nop{}
	}
	return &Poller{sources: sources, sinks: sinks, store: st, o: o, src: map[string]*sourceState{}}
}

// Run loads state, validates each source, then polls until ctx is done.
// It returns nil on a clean stop and an error only for a fatal startup
// condition: unreadable state of a newer version, or a region
// misconfiguration the source could positively confirm.
func (p *Poller) Run(ctx context.Context) error {
	if err := p.start(ctx); err != nil {
		return err
	}
	p.pollAll(ctx)
	t := p.o.Clock.NewTicker(p.o.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C():
			p.pollAll(ctx)
		}
	}
}

// start loads state and runs the startup checks. Separate from Run so tests
// drive pollAll synchronously against a fake clock instead of racing a
// goroutine.
func (p *Poller) start(ctx context.Context) error {
	if err := p.loadState(); err != nil {
		return err
	}
	now := p.o.Clock.Now()
	for _, s := range p.sources {
		p.src[s.ID()] = &sourceState{
			coldStart:    !p.hasRecords(s.ID()),
			lastComplete: now,
		}
	}
	// Publish before the checks: they can take up to two fetch timeouts
	// per source, and until then a probe must see "not ready", not an empty
	// map that reads as "nothing is wrong".
	p.publishHealth(now)
	for _, s := range p.sources {
		if err := p.startupChecks(ctx, s); err != nil {
			return err
		}
	}
	p.publishHealth(now)
	return nil
}

func (p *Poller) loadState() error {
	st, err := p.store.Load()
	switch {
	case errors.Is(err, store.ErrCorrupt):
		// The file has been moved aside; starting cold re-alerts what is
		// currently open and stays quiet about history. Loud, but safe.
		p.o.Log.Error("state file corrupt; starting cold", "err", err)
		st = map[incident.Key]incident.Stored{}
	case err != nil:
		return fmt.Errorf("loading state: %w", err)
	}
	p.state = st
	return nil
}

func (p *Poller) hasRecords(sourceID string) bool {
	for k := range p.state {
		if k.SourceID == sourceID {
			return true
		}
	}
	return false
}

// startupChecks runs the self-check and, where supported, region
// reconciliation.
//
// A region mismatch is fatal: it is the highest-consequence misconfiguration
// this tool has, and it produces no error at any later layer. A catalogue
// that cannot be reached is NOT fatal: refusing to start while the vendor is
// unreachable would keep the watcher down during exactly the outage it exists
// to report.
func (p *Poller) startupChecks(ctx context.Context, s incident.Source) error {
	log := p.o.Log.With("source", s.ID())
	if rv, ok := s.(RegionValidator); ok {
		cctx, cancel := context.WithTimeout(ctx, p.o.FetchTimeout)
		err := rv.ValidateRegions(cctx)
		cancel()
		switch {
		case err == nil:
			log.Info("configured regions reconciled against live catalogue")
		case unreachable(err):
			log.Warn("could not reach catalogue to validate regions; continuing unvalidated", "err", err)
		default:
			return fmt.Errorf("source %s: region validation failed: %w", s.ID(), err)
		}
	}
	p.selfCheck(ctx, s)
	return nil
}

func unreachable(err error) bool {
	return errors.Is(err, incident.ErrUpstream) || errors.Is(err, incident.ErrBlocked) ||
		errors.Is(err, incident.ErrNotJSON) || errors.Is(err, context.DeadlineExceeded)
}

func (p *Poller) selfCheck(ctx context.Context, s incident.Source) {
	st := p.src[s.ID()]
	st.lastSelfCheck = p.o.Clock.Now()
	cctx, cancel := context.WithTimeout(ctx, p.o.FetchTimeout)
	defer cancel()
	err := s.SelfCheck(cctx)
	p.o.Observer.SelfChecked(s.ID(), err)
	if err != nil {
		// The adapter has already marked itself untrustworthy; every
		// snapshot until the next passing check will be Complete=false.
		p.o.Log.Error("self-check failed; snapshots are untrusted until it passes", "source", s.ID(), "err", err)
		return
	}
	p.o.Log.Info("self-check passed", "source", s.ID())
}

func (p *Poller) pollAll(ctx context.Context) {
	started := p.o.Clock.Now()
	// ponytail: sources polled sequentially; give each its own goroutine if
	// a second slow provider ever delays the first noticeably.
	for _, s := range p.sources {
		if ctx.Err() != nil {
			return
		}
		p.pollOne(ctx, s)
	}
	p.publishHealth(started)
}

func (p *Poller) pollOne(ctx context.Context, s incident.Source) {
	id := s.ID()
	st := p.src[id]
	log := p.o.Log.With("source", id)
	now := p.o.Clock.Now()

	if now.Sub(st.lastSelfCheck) >= p.o.SelfCheckInterval {
		p.selfCheck(ctx, s)
	}

	fctx, cancel := context.WithTimeout(ctx, p.o.FetchTimeout)
	snap, err := s.Fetch(fctx)
	cancel()
	if err != nil {
		// No diff, no apply, no save. A resolution sweep over a fetch that
		// did not happen would read every open incident as resolved.
		st.failures++
		st.lastProblem = err.Error()
		p.o.Observer.PollDone(id, p.o.Clock.Now().Sub(now), st.failures, err)
		log.Error("fetch failed", "err", err, "consecutive_failures", st.failures)
		p.checkBlind(ctx, s, now)
		return
	}
	st.failures = 0
	p.o.Observer.PollDone(id, p.o.Clock.Now().Sub(now), 0, nil)
	p.o.Observer.SnapshotSeen(id, snap)

	for _, w := range snap.Warnings {
		log.Warn("snapshot anomaly", "kind", w.Kind, "detail", w.Detail)
	}
	if snap.Complete {
		st.lastComplete = now
		st.everComplete = true
		st.lastProblem = ""
	} else {
		st.lastProblem = "snapshot incomplete: " + warningSummary(snap.Warnings)
	}

	prev := p.partition(id)
	opts := incident.DiffOpts{
		Complete:        snap.Complete,
		ColdStart:       st.coldStart,
		Filter:          p.o.Filters[id],
		VanishGrace:     p.o.VanishGrace,
		UnresolvedCount: snap.UnresolvedCount,
	}
	events := incident.Diff(prev, snap, opts)
	p.o.Observer.EventsEmitted(id, events)
	log.Info("poll", "open", len(snap.Open), "recent", len(snap.Recent), "complete", snap.Complete,
		"cold_start", st.coldStart, "events", len(events))
	for _, ev := range events {
		p.fanOut(ctx, ev)
	}

	next := incident.Apply(prev, snap, opts, now)
	p.merge(id, next)
	st.coldStart = false

	p.checkBlind(ctx, s, now)
	p.o.Observer.StateApplied(id, p.counts(next, st))
	p.save(now)
}

// counts summarises one source's records for the observer.
func (p *Poller) counts(recs map[incident.Key]incident.Stored, st *sourceState) State {
	out := State{Records: map[incident.Status]int{}, Blind: st.blind}
	if st.everComplete {
		out.LastComplete = st.lastComplete
	}
	for _, r := range recs {
		out.Records[r.Status]++
		if !r.Matched {
			continue
		}
		switch r.Status {
		case incident.StatusOpen:
			out.Open++
		case incident.StatusUnknown:
			out.Unknown++
		}
	}
	return out
}

// partition returns only this source's records. Diff's absence sweep treats
// every key in prev as "should have been seen", so handing it another
// source's records would mark them all vanished.
func (p *Poller) partition(sourceID string) map[incident.Key]incident.Stored {
	out := map[incident.Key]incident.Stored{}
	for k, v := range p.state {
		if k.SourceID == sourceID {
			out[k] = v
		}
	}
	return out
}

// merge replaces this source's records with next, leaving other sources'
// untouched.
func (p *Poller) merge(sourceID string, next map[incident.Key]incident.Stored) {
	for k := range p.state {
		if k.SourceID == sourceID {
			delete(p.state, k)
		}
	}
	maps.Copy(p.state, next)
}

// fanOut delivers one event to every sink. A failing sink is logged and
// skipped; it never prevents the next sink from seeing the event.
func (p *Poller) fanOut(ctx context.Context, ev incident.Event) {
	id := notify.EventID(ev)
	log := p.o.Log.With("event_id", id, "kind", ev.Kind, "key", ev.Record.Key.String())
	if len(p.sinks) == 0 {
		log.Info("event (no sinks configured)", "title", ev.Record.Title)
		return
	}
	// ponytail: sequential fan-out; a WaitGroup if a slow SMTP relay ever
	// delays Telegram noticeably.
	for _, sk := range p.sinks {
		sctx, cancel := context.WithTimeout(ctx, p.o.FetchTimeout)
		err := sk.Send(sctx, ev)
		cancel()
		p.o.Observer.Delivered(sk.Name(), err)
		if err != nil {
			log.Error("delivery failed", "sink", sk.Name(), "err", err)
			continue
		}
		log.Info("delivered", "sink", sk.Name())
	}
}

// checkBlind emits one event per transition between seeing and not seeing a
// source. Blind means no complete snapshot for StaleAfter, whatever the
// cause: failed fetches, a failing self-check, or an incomplete response.
func (p *Poller) checkBlind(ctx context.Context, s incident.Source, now time.Time) {
	st := p.src[s.ID()]
	blind := now.Sub(st.lastComplete) >= p.o.StaleAfter
	switch {
	case blind && !st.blind:
		st.blind, st.blindSince = true, st.lastComplete
		p.o.Log.Error("source is blind: no complete snapshot within stale_after",
			"source", s.ID(), "since", st.lastComplete, "reason", st.lastProblem)
		p.emit(ctx, s.ID(), notify.SourceBlind(s.ID(), st.lastProblem, st.lastComplete, now))
	case !blind && st.blind:
		st.blind = false
		p.o.Log.Info("source recovered", "source", s.ID(), "blind_for", now.Sub(st.blindSince))
		p.emit(ctx, s.ID(), notify.SourceRecovered(s.ID(), now.Sub(st.blindSince), now))
	}
}

// emit delivers a single poller-originated event, observed like any other.
func (p *Poller) emit(ctx context.Context, sourceID string, ev incident.Event) {
	p.o.Observer.EventsEmitted(sourceID, []incident.Event{ev})
	p.fanOut(ctx, ev)
}

func (p *Poller) save(now time.Time) {
	err := p.store.Save(p.state, now)
	p.o.Observer.Saved(err)
	if err != nil {
		// In-memory state has advanced, so this poll's events will not be
		// re-emitted while the process lives; a restart before a later Save
		// succeeds will re-deliver them, which is the safe direction.
		p.o.Log.Error("saving state failed; will retry next poll", "err", err)
	}
}

func warningSummary(ws []incident.Warning) string {
	if len(ws) == 0 {
		return "no detail"
	}
	parts := make([]string, len(ws))
	for i, w := range ws {
		parts[i] = w.Kind + ": " + w.Detail
	}
	return strings.Join(parts, "; ")
}
