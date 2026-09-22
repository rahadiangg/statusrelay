package incident

import (
	"testing"
	"time"
)

const testSource = "huawei-intl"

var t0 = time.Date(2026, 7, 26, 2, 5, 0, 0, time.UTC)

// build makes a record and computes its fingerprint, so tests never hand-write
// one and can never accidentally compare stale hashes.
func build(id string, mut ...func(*Record)) Record {
	r := Record{
		Key:       Key{SourceID: testSource, ProviderID: id},
		Title:     "Account anomaly",
		TitleLang: "en",
		Titles:    map[string]string{"en": "Account anomaly"},
		Severity:  SeverityCritical,
		Status:    StatusOpen,
		StartedAt: t0,
		Scope: []Scope{{RegionCode: "ap-southeast-4", RegionName: "AP-Jakarta",
			Services: []Service{{ID: "svc-ecs", Abbr: "ECS"}}}},
	}
	for _, m := range mut {
		m(&r)
	}
	r.FP = Compute(r)
	return r
}

func withUpdates(texts ...string) func(*Record) {
	return func(r *Record) {
		r.Updates = nil
		for i, txt := range texts {
			at := t0.Add(time.Duration(i) * time.Hour)
			r.Updates = append(r.Updates, Update{At: at, Text: txt, Lang: "en", Hash: HashUpdateText(at, txt)})
		}
	}
}

func withRegions(codes ...string) func(*Record) {
	return func(r *Record) {
		r.Scope = nil
		for _, c := range codes {
			r.Scope = append(r.Scope, Scope{RegionCode: c, RegionName: c,
				Services: []Service{{ID: "svc-ecs", Abbr: "ECS"}}})
		}
	}
}

func jakartaFilter() Filter {
	return Filter{Regions: map[string]bool{"ap-southeast-4": true}, IncludeGlobal: true}
}

func opts(mut ...func(*DiffOpts)) DiffOpts {
	o := DiffOpts{Complete: true, Filter: jakartaFilter(), VanishGrace: 3, UnresolvedCount: -1}
	for _, m := range mut {
		m(&o)
	}
	return o
}

func snapshot(open, recent []Record, mut ...func(*Snapshot)) *Snapshot {
	s := &Snapshot{SourceID: testSource, FetchedAt: t0, Open: open, Recent: recent,
		Complete: true, UnresolvedCount: -1}
	for _, m := range mut {
		m(s)
	}
	return s
}

// kinds reduces events to their kinds for concise assertions.
func kinds(evs []Event) []EventKind {
	out := make([]EventKind, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Kind)
	}
	return out
}

func wantKinds(t *testing.T, got []Event, want ...EventKind) {
	t.Helper()
	g := kinds(got)
	if len(g) != len(want) {
		t.Fatalf("got events %v, want %v", g, want)
	}
	for i := range want {
		if g[i] != want[i] {
			t.Fatalf("got events %v, want %v", g, want)
		}
	}
}

// state runs Apply so a test can build "what we knew last poll" the same way
// production does, rather than hand-constructing Stored values that could drift
// from what Apply actually writes.
func state(o DiffOpts, snaps ...*Snapshot) map[Key]Stored {
	st := map[Key]Stored{}
	for _, s := range snaps {
		st = Apply(st, s, o, t0)
	}
	return st
}

func TestDiffNewIncidentInWatchedRegion(t *testing.T) {
	o := opts()
	got := Diff(nil, snapshot([]Record{build("13")}, nil), o)
	wantKinds(t, got, KindNew)
	if got[0].Record.Key.ProviderID != "13" {
		t.Errorf("event carried record %q", got[0].Record.Key.ProviderID)
	}
}

// The event carries the watched subset of the scope, so a subject line can
// say "AP-Jakarta" when the provider listed five regions.
func TestDiffEventCarriesWatchedScope(t *testing.T) {
	o := opts()
	got := Diff(nil, snapshot([]Record{build("13", withRegions("ap-southeast-3", "ap-southeast-4"))}, nil), o)
	wantKinds(t, got, KindNew)
	if len(got[0].Watched) != 1 || got[0].Watched[0].RegionCode != "ap-southeast-4" {
		t.Errorf("Watched: got %v, want only ap-southeast-4", got[0].Watched)
	}
	if len(got[0].Record.Scope) != 2 {
		t.Errorf("Record.Scope was trimmed to %d; the full provider scope must survive", len(got[0].Record.Scope))
	}
	// A global event has nothing to match but Watched must still be non-nil,
	// which is how a renderer tells "no region of ours" from "no filter".
	g := Diff(nil, snapshot([]Record{build("14", func(r *Record) { r.Global, r.Scope = true, nil })}, nil), o)
	wantKinds(t, g, KindNew)
	if g[0].Watched == nil {
		t.Error("Watched is nil for a global event; want empty non-nil")
	}
}

func TestDiffIgnoresUnwatchedRegion(t *testing.T) {
	o := opts()
	got := Diff(nil, snapshot([]Record{build("13", withRegions("ap-southeast-3"))}, nil), o)
	if len(got) != 0 {
		t.Errorf("got %v, want no events for an unwatched region", kinds(got))
	}
}

// A region-less platform event is a real shape and must alert.
func TestDiffGlobalIncidentAlerts(t *testing.T) {
	o := opts()
	r := build("13", func(r *Record) { r.Scope = nil; r.Global = true })
	wantKinds(t, Diff(nil, snapshot([]Record{r}, nil), o), KindNew)
}

func TestDiffNoChangeEmitsNothing(t *testing.T) {
	o := opts()
	r := build("13")
	prev := state(o, snapshot([]Record{r}, nil))
	if got := Diff(prev, snapshot([]Record{r}, nil), o); len(got) != 0 {
		t.Errorf("got %v, want no events for an unchanged record", kinds(got))
	}
}

func TestDiffProgressAppendedIsUpdated(t *testing.T) {
	o := opts()
	before := build("13", withUpdates("investigating"))
	after := build("13", withUpdates("investigating", "engineers engaged"))

	prev := state(o, snapshot([]Record{before}, nil))
	got := Diff(prev, snapshot([]Record{after}, nil), o)
	wantKinds(t, got, KindUpdated)

	if len(got[0].NewUpdates) != 1 {
		t.Fatalf("got %d new updates, want 1 (only the news, not the history)", len(got[0].NewUpdates))
	}
	if got[0].NewUpdates[0].Text != "engineers engaged" {
		t.Errorf("new update = %q", got[0].NewUpdates[0].Text)
	}
}

func TestDiffScopeChangeCarriesTheDelta(t *testing.T) {
	o := opts()
	before := build("13", withRegions("ap-southeast-4"))
	after := build("13", withRegions("ap-southeast-4", "tr-west-1"))

	prev := state(o, snapshot([]Record{before}, nil))
	got := Diff(prev, snapshot([]Record{after}, nil), o)
	wantKinds(t, got, KindScopeChanged)

	if len(got[0].Added) != 1 || got[0].Added[0] != "tr-west-1" {
		t.Errorf("added = %v, want [tr-west-1]", got[0].Added)
	}
	if len(got[0].Removed) != 0 {
		t.Errorf("removed = %v, want none", got[0].Removed)
	}
}

func TestDiffTitleEditIsMinorUpdate(t *testing.T) {
	o := opts()
	before := build("13")
	after := build("13", func(r *Record) {
		r.Title = "Account anomaly (updated)"
		r.Titles = map[string]string{"en": "Account anomaly (updated)"}
	})
	prev := state(o, snapshot([]Record{before}, nil))
	wantKinds(t, Diff(prev, snapshot([]Record{after}, nil), o), KindMinorUpdated)
}

// The record mutating without any visible change must wake nobody. This is the
// whole reason the mtime sits outside the hashes.
func TestDiffMtimeOnlyBumpEmitsNothing(t *testing.T) {
	o := opts()
	before := build("13")
	after := build("13", func(r *Record) { r.UpdatedAt = t0.Add(35 * time.Minute) })

	prev := state(o, snapshot([]Record{before}, nil))
	if got := Diff(prev, snapshot([]Record{after}, nil), o); len(got) != 0 {
		t.Errorf("got %v, want no events for an mtime-only change", kinds(got))
	}
}

func TestDiffOpenToResolved(t *testing.T) {
	o := opts()
	r := build("13")
	prev := state(o, snapshot([]Record{r}, nil))

	resolved := build("13", func(x *Record) { x.Status = StatusResolved })
	wantKinds(t, Diff(prev, snapshot(nil, []Record{resolved}), o), KindResolved)
}

func TestDiffReopened(t *testing.T) {
	o := opts()
	resolved := build("13", func(r *Record) { r.Status = StatusResolved })
	prev := state(o, snapshot(nil, []Record{resolved}))

	wantKinds(t, Diff(prev, snapshot([]Record{build("13")}, nil), o), KindReopened)
}

// It opened and closed between two polls: one event, not a new-then-resolved
// pair that would page and then immediately un-page.
func TestDiffMissedAndResolvedIsASingleEvent(t *testing.T) {
	o := opts()
	prev := state(o, snapshot(nil, nil))
	resolved := build("13", func(r *Record) { r.Status = StatusResolved })

	wantKinds(t, Diff(prev, snapshot(nil, []Record{resolved}), o), KindMissedAndResolved)
}

// ---------------------------------------------------------------------------
// The dangerous cases.
// ---------------------------------------------------------------------------

// A record absent from BOTH lists is indistinguishable from a partial fetch or
// a shape change. Calling it resolved would announce "all clear" during an
// outage, which is the worst thing this service can do.
func TestDiffVanishedIsNotResolved(t *testing.T) {
	o := opts()
	prev := state(o, snapshot([]Record{build("13")}, nil))

	got := Diff(prev, snapshot(nil, nil), o)
	wantKinds(t, got, KindVanished)
	if got[0].Kind == KindResolved || got[0].Kind == KindResolvedInferred {
		t.Fatal("a vanished record was reported as resolved")
	}
}

// Only after several complete snapshots agree AND the provider's own count says
// nothing is open may we conclude it is over -- and even then it is labelled
// differently from a resolution the provider vouched for.
func TestDiffVanishedBecomesInferredOnlyWithCorroboration(t *testing.T) {
	for _, tc := range []struct {
		name       string
		vanishes   int
		unresolved int
		want       EventKind
	}{
		{name: "first absence is never enough", vanishes: 1, unresolved: 0, want: KindVanished},
		{name: "grace not yet reached", vanishes: 2, unresolved: 0, want: KindVanished},
		{name: "grace reached and provider agrees", vanishes: 3, unresolved: 0, want: KindResolvedInferred},
		{name: "grace reached but provider still reports one open", vanishes: 3, unresolved: 1, want: KindVanished},
		{name: "grace reached but provider count unavailable", vanishes: 3, unresolved: -1, want: KindVanished},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := opts(func(o *DiffOpts) { o.UnresolvedCount = tc.unresolved })
			st := state(o, snapshot([]Record{build("13")}, nil))

			var got []Event
			empty := snapshot(nil, nil, func(s *Snapshot) { s.UnresolvedCount = tc.unresolved })
			for i := 0; i < tc.vanishes; i++ {
				got = Diff(st, empty, o)
				st = Apply(st, empty, o, t0)
			}
			wantKinds(t, got, tc.want)
		})
	}
}

func TestDiffVanishedThenReappearsIsReopened(t *testing.T) {
	o := opts()
	st := state(o, snapshot([]Record{build("13")}, nil))
	empty := snapshot(nil, nil)
	st = Apply(st, empty, o, t0)

	got := Diff(st, snapshot([]Record{build("13")}, nil), o)
	wantKinds(t, got, KindReopened)
}

// When the snapshot could not see everything, absence means nothing. This is
// the guard that keeps a half-failed fetch from being read as mass resolution.
func TestIncompleteSnapshotNeverInfersResolution(t *testing.T) {
	o := opts()
	st := state(o, snapshot([]Record{build("13"), build("14")}, nil))

	incomplete := snapshot(nil, nil, func(s *Snapshot) { s.Complete = false })
	got := Diff(st, incomplete, opts(func(o *DiffOpts) { o.Complete = false }))
	if len(got) != 0 {
		t.Fatalf("got %v, want no events from an incomplete snapshot", kinds(got))
	}
}

// An incomplete snapshot must not advance vanish counting either, or three
// half-failed polls would silently promote to an inferred resolution.
func TestIncompleteSnapshotDoesNotAdvanceVanishCount(t *testing.T) {
	o := opts(func(o *DiffOpts) { o.Complete = false; o.UnresolvedCount = 0 })
	st := state(opts(), snapshot([]Record{build("13")}, nil))

	incomplete := snapshot(nil, nil, func(s *Snapshot) { s.Complete = false })
	for i := 0; i < 5; i++ {
		st = Apply(st, incomplete, o, t0)
	}
	got := st[Key{SourceID: testSource, ProviderID: "13"}]
	if got.VanishCount != 0 {
		t.Errorf("vanish count = %d, want 0; incomplete snapshots must not count as absences", got.VanishCount)
	}
	if got.Status != StatusOpen {
		t.Errorf("status = %v, want open", got.Status)
	}
}

// New to us, not new to the world. Emitting a scope change here would be silent
// for anyone whose notifier ignores minor updates -- so the region we care
// about entering the blast radius would go unnoticed.
func TestIncidentGainingWatchedRegionMidFlightIsNew(t *testing.T) {
	o := opts()
	elsewhere := build("13", withRegions("ap-southeast-3"))
	st := state(o, snapshot([]Record{elsewhere}, nil))

	// It was stored despite not matching, so the transition is detectable.
	if _, ok := st[Key{SourceID: testSource, ProviderID: "13"}]; !ok {
		t.Fatal("an unmatched record was not stored; the transition would be invisible")
	}

	spread := build("13", withRegions("ap-southeast-3", "ap-southeast-4"))
	wantKinds(t, Diff(st, snapshot([]Record{spread}, nil), o), KindNew)
}

// Leaving our scope is not a resolution: the incident may well still be running.
func TestIncidentLeavingWatchedRegionIsScopeExited(t *testing.T) {
	o := opts()
	st := state(o, snapshot([]Record{build("13", withRegions("ap-southeast-3", "ap-southeast-4"))}, nil))

	shrunk := build("13", withRegions("ap-southeast-3"))
	wantKinds(t, Diff(st, snapshot([]Record{shrunk}, nil), o), KindScopeExited)
}

func TestColdStartSuppressesHistory(t *testing.T) {
	o := opts(func(o *DiffOpts) { o.ColdStart = true })
	resolved := build("13", func(r *Record) { r.Status = StatusResolved })

	if got := Diff(nil, snapshot(nil, []Record{resolved}), o); len(got) != 0 {
		t.Errorf("got %v, want nothing; alerting on history would page for every incident ever published",
			kinds(got))
	}
}

// If our state is genuinely empty, an incident that is happening right now IS
// news to us -- but the reader deserves to know it may not be new to the world.
func TestColdStartStillReportsOpenIncidentsAndFlagsThem(t *testing.T) {
	o := opts(func(o *DiffOpts) { o.ColdStart = true })
	got := Diff(nil, snapshot([]Record{build("13")}, nil), o)
	wantKinds(t, got, KindNew)
	if !got[0].ColdStart {
		t.Error("a cold-start event was not flagged as such")
	}
}

// Providers reuse ids. Treating a reused id as a reopen attaches a fresh outage
// to a stale thread and inherits the wrong history.
func TestReusedEventIDIsANewIncidentNotAReopen(t *testing.T) {
	o := opts()
	old := build("13", func(r *Record) { r.Status = StatusResolved })
	st := state(o, snapshot(nil, []Record{old}))

	different := build("13", func(r *Record) {
		r.StartedAt = t0.AddDate(0, 3, 0)
		r.Title = "A completely different outage"
		r.Titles = map[string]string{"en": "A completely different outage"}
	})
	wantKinds(t, Diff(st, snapshot([]Record{different}, nil), o), KindNew)
}

func TestSameIncidentReturningIsAReopen(t *testing.T) {
	o := opts()
	old := build("13", func(r *Record) { r.Status = StatusResolved })
	st := state(o, snapshot(nil, []Record{old}))

	wantKinds(t, Diff(st, snapshot([]Record{build("13")}, nil), o), KindReopened)
}

// A record in both lists at once is a provider inconsistency. Open wins:
// continuing to alert on something that may still be happening is the safe
// direction to be wrong in.
func TestRecordInBothListsIsTreatedAsOpen(t *testing.T) {
	o := opts()
	st := state(o, snapshot([]Record{build("13")}, nil))
	r := build("13", withUpdates("new information"))

	got := Diff(st, snapshot([]Record{r}, []Record{r}), o)
	wantKinds(t, got, KindUpdated)
}

// Append-only is the contract. A shrinking list is a provider bug, and alerting
// on it would page a human about someone else's regression.
func TestProgressShrinkKeepsTheUnionAndEmitsNothing(t *testing.T) {
	o := opts()
	full := build("13", withUpdates("one", "two", "three"))
	st := state(o, snapshot([]Record{full}, nil))

	shrunk := build("13", withUpdates("one", "two"))
	if got := Diff(st, snapshot([]Record{shrunk}, nil), o); len(got) != 0 {
		t.Errorf("got %v, want nothing for a provider-side progress regression", kinds(got))
	}

	st = Apply(st, snapshot([]Record{shrunk}, nil), o, t0)
	kept := st[Key{SourceID: testSource, ProviderID: "13"}]
	if len(kept.Record.Updates) != 3 {
		t.Errorf("kept %d updates, want 3 (the union must survive)", len(kept.Record.Updates))
	}
	if !ProgressShrank(full.Updates, shrunk.Updates) {
		t.Error("ProgressShrank did not detect the regression")
	}
}

// Matching by content hash rather than position means an out-of-order insert
// does not make every later entry look new.
func TestNewUpdatesMatchesByContentNotPosition(t *testing.T) {
	a := t0
	b := t0.Add(time.Hour)
	c := t0.Add(2 * time.Hour)
	mk := func(at time.Time, txt string) Update {
		return Update{At: at, Text: txt, Hash: HashUpdateText(at, txt)}
	}

	prev := []Update{mk(a, "one"), mk(c, "three")}
	cur := []Update{mk(a, "one"), mk(b, "two"), mk(c, "three")}

	got := newUpdates(prev, cur)
	if len(got) != 1 || got[0].Text != "two" {
		t.Fatalf("got %d updates %v, want just the inserted one", len(got), got)
	}
}

// Map iteration is randomized; event order must not be.
func TestSweepOrderIsDeterministic(t *testing.T) {
	o := opts()
	st := state(o, snapshot([]Record{build("13"), build("14"), build("15")}, nil))

	first := kinds(Diff(st, snapshot(nil, nil), o))
	firstIDs := idsOf(Diff(st, snapshot(nil, nil), o))
	for i := 0; i < 50; i++ {
		got := Diff(st, snapshot(nil, nil), o)
		if len(kinds(got)) != len(first) {
			t.Fatalf("iteration %d produced a different number of events", i)
		}
		gotIDs := idsOf(got)
		for j := range firstIDs {
			if gotIDs[j] != firstIDs[j] {
				t.Fatalf("iteration %d ordered events differently: %v vs %v", i, gotIDs, firstIDs)
			}
		}
	}
}

func idsOf(evs []Event) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Record.Key.ProviderID)
	}
	return out
}

// Restarting mid-incident must not re-page: the stored fingerprint is what
// makes the second run see no change.
func TestRestartMidIncidentDoesNotRealert(t *testing.T) {
	o := opts()
	r := build("13", withUpdates("investigating"))
	persisted := state(o, snapshot([]Record{r}, nil))

	// A fresh process loads that state and is NOT a cold start.
	if got := Diff(persisted, snapshot([]Record{r}, nil), o); len(got) != 0 {
		t.Errorf("got %v, want nothing after a restart with intact state", kinds(got))
	}
}

// An incident that opened and closed while the watcher was down should produce
// exactly one event, not a new-then-resolved pair.
func TestResolutionDuringDowntimeEmitsOneEvent(t *testing.T) {
	o := opts()
	open := build("13")
	persisted := state(o, snapshot([]Record{open}, nil))

	resolved := build("13", func(r *Record) { r.Status = StatusResolved })
	wantKinds(t, Diff(persisted, snapshot(nil, []Record{resolved}), o), KindResolved)
}

func TestApplyPreservesFirstSeenAcrossPolls(t *testing.T) {
	o := opts()
	r := build("13")
	st := Apply(nil, snapshot([]Record{r}, nil), o, t0)
	later := t0.Add(6 * time.Hour)
	st = Apply(st, snapshot([]Record{r}, nil), o, later)

	got := st[Key{SourceID: testSource, ProviderID: "13"}]
	if !got.FirstSeenAt.Equal(t0) {
		t.Errorf("FirstSeenAt = %v, want the original sighting %v", got.FirstSeenAt, t0)
	}
	if !got.LastSeenAt.Equal(later) {
		t.Errorf("LastSeenAt = %v, want %v", got.LastSeenAt, later)
	}
}

// A reused id starts its own clock rather than inheriting the previous
// incident's first sighting.
func TestApplyResetsFirstSeenOnIdentityChange(t *testing.T) {
	o := opts()
	st := Apply(nil, snapshot([]Record{build("13")}, nil), o, t0)

	later := t0.AddDate(0, 3, 0)
	different := build("13", func(r *Record) {
		r.StartedAt = later
		r.Title = "Different outage"
		r.Titles = map[string]string{"en": "Different outage"}
	})
	st = Apply(st, snapshot([]Record{different}, nil), o, later)

	got := st[Key{SourceID: testSource, ProviderID: "13"}]
	if !got.FirstSeenAt.Equal(later) {
		t.Errorf("FirstSeenAt = %v, want the new incident's own clock %v", got.FirstSeenAt, later)
	}
}

func TestApplyStoresUnmatchedRecords(t *testing.T) {
	o := opts()
	st := Apply(nil, snapshot([]Record{build("13", withRegions("ap-southeast-3"))}, nil), o, t0)

	got, ok := st[Key{SourceID: testSource, ProviderID: "13"}]
	if !ok {
		t.Fatal("an unmatched record was not stored")
	}
	if got.Matched {
		t.Error("record stored as matched when it is out of scope")
	}
}

// Records outside our scope must never be swept: we are not tracking whether
// they resolved, so claiming they vanished would be noise.
func TestSweepIgnoresUnmatchedRecords(t *testing.T) {
	o := opts()
	st := state(o, snapshot([]Record{build("13", withRegions("ap-southeast-3"))}, nil))

	if got := Diff(st, snapshot(nil, nil), o); len(got) != 0 {
		t.Errorf("got %v, want nothing; unmatched records are not swept", kinds(got))
	}
}

func TestIdentityDistinguishesIncidents(t *testing.T) {
	a := build("13")
	if identityOf(a) != identityOf(build("13")) {
		t.Error("identity is not stable for the same incident")
	}
	b := build("13", func(r *Record) { r.StartedAt = t0.Add(time.Hour) })
	if identityOf(a) == identityOf(b) {
		t.Error("a different start time produced the same identity")
	}
	c := build("13", func(r *Record) {
		r.Title = "Something else"
		r.Titles = map[string]string{"en": "Something else"}
	})
	if identityOf(a) == identityOf(c) {
		t.Error("a different title produced the same identity")
	}
}
