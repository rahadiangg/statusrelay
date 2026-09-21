package poller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
	"github.com/rahadiangg/statwatch/internal/notify"
	"github.com/rahadiangg/statwatch/internal/platform/clock"
	"github.com/rahadiangg/statwatch/internal/store"
)

var testEpoch = time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)

// fakeStore records every Save. The shared order slice, appended to by the
// sinks as well, makes the notify-before-save invariant provable.
type fakeStore struct {
	LoadFunc func() (map[incident.Key]incident.Stored, error)
	SaveFunc func(map[incident.Key]incident.Stored, time.Time) error

	mu    sync.Mutex
	saved []map[incident.Key]incident.Stored
	order *[]string
}

func (f *fakeStore) Load() (map[incident.Key]incident.Stored, error) {
	if f.LoadFunc != nil {
		return f.LoadFunc()
	}
	return map[incident.Key]incident.Stored{}, nil
}

func (f *fakeStore) Save(m map[incident.Key]incident.Stored, now time.Time) error {
	f.mu.Lock()
	cp := make(map[incident.Key]incident.Stored, len(m))
	maps.Copy(cp, m)
	f.saved = append(f.saved, cp)
	if f.order != nil {
		*f.order = append(*f.order, "save")
	}
	f.mu.Unlock()
	if f.SaveFunc != nil {
		return f.SaveFunc(m, now)
	}
	return nil
}

func (f *fakeStore) last() map[incident.Key]incident.Stored {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.saved) == 0 {
		return nil
	}
	return f.saved[len(f.saved)-1]
}

// logCapture collects slog records so a test can assert on what was logged.
type logCapture struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }
func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	c.recs = append(c.recs, r)
	c.mu.Unlock()
	return nil
}
func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *logCapture) WithGroup(string) slog.Handler      { return c }

func (c *logCapture) count(level slog.Level, substr string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, r := range c.recs {
		if r.Level == level && strings.Contains(r.Message, substr) {
			n++
		}
	}
	return n
}

func record(source, id string, regions ...string) incident.Record {
	r := incident.Record{
		Key:       incident.Key{SourceID: source, ProviderID: id},
		Title:     "incident " + id,
		Titles:    map[string]string{"en": "incident " + id},
		Severity:  incident.SeverityMajor,
		StartedAt: testEpoch.Add(-time.Hour),
		Updates:   []incident.Update{{At: testEpoch.Add(-time.Hour), Text: "first", Hash: "h1-" + id}},
	}
	for _, rc := range regions {
		r.Scope = append(r.Scope, incident.Scope{RegionCode: rc, RegionName: strings.ToUpper(rc)})
	}
	r.FP = incident.Compute(r)
	return r
}

func withUpdate(r incident.Record, text string) incident.Record {
	r.Updates = append(append([]incident.Update(nil), r.Updates...),
		incident.Update{At: testEpoch, Text: text, Hash: "h-" + text})
	r.FP = incident.Compute(r)
	return r
}

func snap(source string, open, recent []incident.Record) *incident.Snapshot {
	return &incident.Snapshot{SourceID: source, Open: open, Recent: recent, Complete: true, UnresolvedCount: len(open)}
}

// scripted returns a FakeSource whose Fetch answers from the script in
// order; a nil snapshot is a fetch error. Past the end it returns an empty
// complete snapshot.
func scripted(id string, script ...*incident.Snapshot) *incident.FakeSource {
	i := 0
	return &incident.FakeSource{IDStr: id, FetchFunc: func(context.Context) (*incident.Snapshot, error) {
		if i < len(script) {
			s := script[i]
			i++
			if s == nil {
				return nil, fmt.Errorf("fetching: %w", incident.ErrUpstream)
			}
			return s, nil
		}
		return snap(id, nil, nil), nil
	}}
}

type harness struct {
	clk   *clock.Fake
	store *fakeStore
	logs  *logCapture
	order []string
	sinkA *notify.Fake
	sinkB *notify.Fake
	opts  Options
}

func newHarness() *harness {
	h := &harness{clk: clock.NewFake(testEpoch), logs: &logCapture{}}
	h.store = &fakeStore{order: &h.order}
	h.sinkA = &notify.Fake{NameStr: "fake/a", SendFunc: func(context.Context, incident.Event) error {
		h.order = append(h.order, "send:a")
		return nil
	}}
	h.sinkB = &notify.Fake{NameStr: "fake/b", SendFunc: func(context.Context, incident.Event) error {
		h.order = append(h.order, "send:b")
		return nil
	}}
	h.opts = Options{
		Interval:          time.Minute,
		FetchTimeout:      10 * time.Second,
		SelfCheckInterval: time.Hour,
		StaleAfter:        5 * time.Minute,
		VanishGrace:       2,
		Filters:           map[string]incident.Filter{"src": {Regions: map[string]bool{"jkt": true}, IncludeGlobal: true}},
		Clock:             h.clk,
		Log:               slog.New(h.logs),
	}
	return h
}

// started builds a Poller over the given sources and runs start. Polls are
// then driven by the test calling p.pollAll after advancing the clock.
func (h *harness) started(t *testing.T, sources ...incident.Source) *Poller {
	t.Helper()
	p := New(sources, []Sink{h.sinkA, h.sinkB}, h.store, h.opts)
	if err := p.start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	return p
}

func (h *harness) tick(p *Poller) {
	h.clk.Advance(h.opts.Interval)
	p.pollAll(context.Background())
}

func kinds(evs []incident.Event) string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = string(e.Kind)
	}
	return strings.Join(out, ",")
}

func TestColdStartAlertsOpenNotHistory(t *testing.T) {
	h := newHarness()
	open := record("src", "13", "jkt")
	old := record("src", "7", "jkt")
	src := scripted("src", snap("src", []incident.Record{open}, []incident.Record{old}))
	p := h.started(t, src)
	p.pollAll(context.Background())

	got := h.sinkA.Calls()
	if kinds(got) != "new" || !got[0].ColdStart {
		t.Fatalf("got %s (cold=%v), want one cold-start new", kinds(got), len(got) > 0 && got[0].ColdStart)
	}
	if kinds(h.sinkB.Calls()) != "new" {
		t.Errorf("sink B got %s, want new", kinds(h.sinkB.Calls()))
	}
	st := h.store.last()
	if len(st) != 2 || st[open.Key].Status != incident.StatusOpen || st[old.Key].Status != incident.StatusResolved {
		t.Errorf("saved state wrong: %+v", st)
	}
	if h.order[0] != "send:a" || h.order[1] != "send:b" || h.order[2] != "save" {
		t.Errorf("order %v, want sends before save", h.order)
	}
	if h.logs.count(slog.LevelInfo, "self-check passed") != 1 {
		t.Error("startup self-check not logged")
	}
}

func TestSteadyStateLifecycle(t *testing.T) {
	h := newHarness()
	r := record("src", "13", "jkt")
	upd := withUpdate(r, "engineers engaged")
	src := scripted("src",
		snap("src", []incident.Record{r}, nil),
		snap("src", []incident.Record{upd}, nil),
		snap("src", nil, []incident.Record{upd}),
		snap("src", nil, []incident.Record{upd}),
	)
	p := h.started(t, src)
	p.pollAll(context.Background())
	h.tick(p)
	h.tick(p)
	h.tick(p)

	if got := kinds(h.sinkA.Calls()); got != "new,updated,resolved" {
		t.Errorf("got %s, want new,updated,resolved", got)
	}
	calls := h.sinkA.Calls()
	if !calls[0].ColdStart || len(calls[1].NewUpdates) != 1 || calls[1].NewUpdates[0].Text != "engineers engaged" {
		t.Errorf("event details wrong: %+v", calls)
	}
	if st := h.store.last(); st[r.Key].Status != incident.StatusResolved {
		t.Errorf("final status %v, want resolved", st[r.Key].Status)
	}
}

func TestFetchErrorSkipsDiffAndSave(t *testing.T) {
	h := newHarness()
	r := record("src", "13", "jkt")
	src := scripted("src",
		snap("src", []incident.Record{r}, nil),
		nil, nil,
		snap("src", []incident.Record{r}, nil),
	)
	p := h.started(t, src)
	p.pollAll(context.Background())
	h.tick(p)
	h.tick(p)
	h.tick(p)

	if got := kinds(h.sinkA.Calls()); got != "new" {
		t.Errorf("got %s, want only new — a failed fetch must not resolve or vanish anything", got)
	}
	if n := len(h.store.saved); n != 2 {
		t.Errorf("got %d saves, want 2 (error polls do not save)", n)
	}
	if h.logs.count(slog.LevelError, "fetch failed") != 2 {
		t.Error("fetch failures not logged at Error")
	}
	if p.src["src"].failures != 0 {
		t.Errorf("failure counter %d after a success, want 0", p.src["src"].failures)
	}
}

func TestIncompleteSnapshotNeverVanishes(t *testing.T) {
	h := newHarness()
	r := record("src", "13", "jkt")
	incomplete := func() *incident.Snapshot {
		s := snap("src", nil, nil)
		s.Complete = false
		s.UnresolvedCount = -1
		s.Warnings = []incident.Warning{{Kind: incident.AnomalyCountMismatch, Detail: "vendor says 1, list held 0"}}
		return s
	}
	src := scripted("src",
		snap("src", []incident.Record{r}, nil),
		incomplete(), incomplete(), incomplete(),
		snap("src", nil, nil), // complete and empty: now the sweep runs
	)
	p := h.started(t, src)
	p.pollAll(context.Background())
	h.tick(p)
	h.tick(p)
	h.tick(p)
	if got := kinds(h.sinkA.Calls()); got != "new" {
		t.Fatalf("after incomplete polls got %s, want only new", got)
	}
	if h.logs.count(slog.LevelWarn, "snapshot anomaly") != 3 {
		t.Error("anomalies not logged")
	}
	h.tick(p)
	if got := kinds(h.sinkA.Calls()); got != "new,vanished" {
		t.Errorf("after a complete empty poll got %s, want new,vanished", got)
	}
}

func TestBlindAndRecoveredOnceEach(t *testing.T) {
	h := newHarness()
	// StaleAfter is 5m, interval 1m: failures at t+1..t+5 → blind at t+5.
	src := scripted("src",
		snap("src", nil, nil),
		nil, nil, nil, nil, nil, nil, nil, // 7 failures
		snap("src", nil, nil),
		snap("src", nil, nil),
	)
	p := h.started(t, src)
	p.pollAll(context.Background())
	for i := 0; i < 7; i++ {
		h.tick(p)
	}
	got := h.sinkA.Calls()
	if kinds(got) != "source_blind" {
		t.Fatalf("got %s, want exactly one source_blind across 7 failing polls", kinds(got))
	}
	if !strings.Contains(got[0].Record.Updates[0].Text, "upstream request failed") {
		t.Errorf("blind reason missing: %q", got[0].Record.Updates[0].Text)
	}
	if got[0].Record.StartedAt != testEpoch {
		t.Errorf("blind since %s, want last complete %s", got[0].Record.StartedAt, testEpoch)
	}
	h.tick(p)
	h.tick(p)
	if got := kinds(h.sinkA.Calls()); got != "source_blind,source_recovered" {
		t.Errorf("got %s, want blind then exactly one recovered", got)
	}
	if h.logs.count(slog.LevelError, "source is blind") != 1 {
		t.Error("blind transition not logged at Error")
	}
}

func TestBlindFromIncompleteSnapshots(t *testing.T) {
	h := newHarness()
	inc := func() *incident.Snapshot {
		s := snap("src", nil, nil)
		s.Complete = false
		s.Warnings = []incident.Warning{{Kind: "past_events_unavailable", Detail: "503"}}
		return s
	}
	src := scripted("src", inc(), inc(), inc(), inc(), inc(), inc())
	p := h.started(t, src)
	p.pollAll(context.Background())
	for i := 0; i < 5; i++ {
		h.tick(p)
	}
	got := h.sinkA.Calls()
	if kinds(got) != "source_blind" {
		t.Fatalf("got %s, want source_blind", kinds(got))
	}
	if !strings.Contains(got[0].Record.Updates[0].Text, "past_events_unavailable: 503") {
		t.Errorf("reason should carry the warnings: %q", got[0].Record.Updates[0].Text)
	}
}

func TestFailingSinkDoesNotBlockOthers(t *testing.T) {
	h := newHarness()
	h.sinkA.SendFunc = func(context.Context, incident.Event) error {
		return fmt.Errorf("telegram: %w", notify.ErrPermanent)
	}
	r := record("src", "13", "jkt")
	src := scripted("src", snap("src", []incident.Record{r}, nil))
	p := h.started(t, src)
	p.pollAll(context.Background())

	if len(h.sinkA.Calls()) != 1 || len(h.sinkB.Calls()) != 1 {
		t.Errorf("A=%d B=%d calls, want 1 each", len(h.sinkA.Calls()), len(h.sinkB.Calls()))
	}
	if h.logs.count(slog.LevelError, "delivery failed") != 1 {
		t.Error("sink failure not logged at Error")
	}
	if len(h.store.saved) != 1 {
		t.Error("state not saved after a sink failure")
	}
}

func TestSaveFailureDoesNotStopTheLoop(t *testing.T) {
	h := newHarness()
	h.store.SaveFunc = func(map[incident.Key]incident.Stored, time.Time) error { return errors.New("disk full") }
	r := record("src", "13", "jkt")
	src := scripted("src",
		snap("src", []incident.Record{r}, nil),
		snap("src", nil, []incident.Record{r}),
	)
	p := h.started(t, src)
	p.pollAll(context.Background())
	h.tick(p)
	if got := kinds(h.sinkA.Calls()); got != "new,resolved" {
		t.Errorf("got %s, want new,resolved — in-memory state must still advance", got)
	}
	if h.logs.count(slog.LevelError, "saving state failed") != 2 {
		t.Error("save failures not logged")
	}
}

func TestTwoSourcesAreIsolated(t *testing.T) {
	h := newHarness()
	h.opts.Filters["other"] = incident.Filter{Regions: map[string]bool{"jkt": true}}
	a := record("src", "13", "jkt")
	b := record("other", "13", "jkt") // same provider id, different source
	srcA := scripted("src", snap("src", []incident.Record{a}, nil), snap("src", []incident.Record{a}, nil))
	srcB := scripted("other", snap("other", []incident.Record{b}, nil), snap("other", []incident.Record{b}, nil))
	p := h.started(t, srcA, srcB)
	p.pollAll(context.Background())
	h.tick(p)

	if got := kinds(h.sinkA.Calls()); got != "new,new" {
		t.Errorf("got %s, want new,new — B's open record must not vanish during A's poll", got)
	}
	st := h.store.last()
	if len(st) != 2 || st[a.Key].Status != incident.StatusOpen || st[b.Key].Status != incident.StatusOpen {
		t.Errorf("state %+v, want both open", st)
	}
}

func TestColdStartIsPerSource(t *testing.T) {
	h := newHarness()
	existing := record("src", "13", "jkt")
	h.store.LoadFunc = func() (map[incident.Key]incident.Stored, error) {
		return map[incident.Key]incident.Stored{existing.Key: {Record: existing, Status: incident.StatusOpen, FP: existing.FP, Matched: true}}, nil
	}
	h.opts.Filters["other"] = incident.Filter{Regions: map[string]bool{"jkt": true}}
	p := h.started(t, scripted("src"), scripted("other"))
	if p.src["src"].coldStart || !p.src["other"].coldStart {
		t.Errorf("cold start src=%v other=%v, want false/true", p.src["src"].coldStart, p.src["other"].coldStart)
	}
}

func TestCorruptStateStartsCold(t *testing.T) {
	h := newHarness()
	h.store.LoadFunc = func() (map[incident.Key]incident.Stored, error) {
		return map[incident.Key]incident.Stored{}, fmt.Errorf("%w: moved aside", store.ErrCorrupt)
	}
	p := h.started(t, scripted("src"))
	if !p.src["src"].coldStart {
		t.Error("corrupt state must cold-start")
	}
	if h.logs.count(slog.LevelError, "state file corrupt") != 1 {
		t.Error("corruption not logged at Error")
	}
}

func TestNewerStateVersionIsFatal(t *testing.T) {
	h := newHarness()
	h.store.LoadFunc = func() (map[incident.Key]incident.Stored, error) {
		return nil, fmt.Errorf("%w: v2", store.ErrVersion)
	}
	p := New([]incident.Source{scripted("src")}, nil, h.store, h.opts)
	if err := p.Run(context.Background()); !errors.Is(err, store.ErrVersion) {
		t.Errorf("got %v, want ErrVersion", err)
	}
}

// validatingSource adds ValidateRegions to a FakeSource.
type validatingSource struct {
	*incident.FakeSource
	err error
}

func (v *validatingSource) ValidateRegions(context.Context) error { return v.err }

func TestRegionValidationAtStartup(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		wantErr bool
		wantLog string
	}{
		{name: "ok", err: nil, wantLog: "reconciled"},
		{name: "mismatch is fatal", err: fmt.Errorf("%w: AP-Jakarta is ap-southeast-4", incident.ErrBadRequest), wantErr: true},
		{name: "unreachable continues", err: fmt.Errorf("%w: timeout", incident.ErrUpstream), wantLog: "continuing unvalidated"},
		{name: "blocked continues", err: fmt.Errorf("%w: 418", incident.ErrBlocked), wantLog: "continuing unvalidated"},
		{name: "deadline continues", err: context.DeadlineExceeded, wantLog: "continuing unvalidated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness()
			src := &validatingSource{FakeSource: scripted("src"), err: tc.err}
			p := New([]incident.Source{src}, nil, h.store, h.opts)
			err := p.start(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("got err %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantLog != "" && h.logs.count(slog.LevelInfo, tc.wantLog)+h.logs.count(slog.LevelWarn, tc.wantLog) != 1 {
				t.Errorf("expected log containing %q", tc.wantLog)
			}
		})
	}
}

func TestSelfCheckCadence(t *testing.T) {
	h := newHarness()
	h.opts.SelfCheckInterval = 3 * time.Minute
	src := scripted("src")
	src.SelfCheckFunc = func(context.Context) error { return fmt.Errorf("%w: probe empty", incident.ErrSchemaDrift) }
	p := h.started(t, src)
	p.pollAll(context.Background()) // t+0: startup check already ran
	h.tick(p)                       // t+1
	h.tick(p)                       // t+2
	h.tick(p)                       // t+3: due again
	if got := src.SelfChecks(); got != 2 {
		t.Errorf("got %d self-checks, want 2 (startup + one at 3m)", got)
	}
	if h.logs.count(slog.LevelError, "self-check failed") != 2 {
		t.Error("self-check failures not logged at Error")
	}
}

func TestNoSinksLogsEvents(t *testing.T) {
	h := newHarness()
	r := record("src", "13", "jkt")
	p := New([]incident.Source{scripted("src", snap("src", []incident.Record{r}, nil))}, nil, h.store, h.opts)
	if err := p.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.pollAll(context.Background())
	if h.logs.count(slog.LevelInfo, "no sinks configured") != 1 {
		t.Error("event not logged when there are no sinks")
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	h := newHarness()
	p := New([]incident.Source{scripted("src")}, nil, h.store, h.opts)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A cancelled ctx still runs start and the first poll (they are
	// synchronous) and then returns from the select immediately.
	if err := p.Run(ctx); err != nil {
		t.Errorf("got %v, want nil on cancel", err)
	}
}

func TestPollAllStopsBetweenSourcesOnCancel(t *testing.T) {
	h := newHarness()
	h.opts.Filters["other"] = incident.Filter{}
	a, b := scripted("src"), scripted("other")
	p := h.started(t, a, b)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.pollAll(ctx)
	if a.Fetches() != 0 || b.Fetches() != 0 {
		t.Errorf("fetched a=%d b=%d after cancel, want 0/0", a.Fetches(), b.Fetches())
	}
}

func TestNewDefaults(t *testing.T) {
	p := New(nil, nil, &fakeStore{}, Options{})
	if p.o.Clock == nil || p.o.Log == nil || p.o.VanishGrace != 1 {
		t.Errorf("defaults not applied: %+v", p.o)
	}
}
