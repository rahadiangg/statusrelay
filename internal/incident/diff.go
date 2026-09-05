package incident

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"
)

// EventKind is what happened to a record between two observations.
type EventKind string

const (
	// KindNew is a record we have not alerted on before, in a scope we watch.
	// It also covers a record that existed but only just entered our scope: it
	// is new to us, which is what matters.
	KindNew EventKind = "new"
	// KindUpdated is a new progress entry with text.
	KindUpdated EventKind = "updated"
	// KindScopeChanged is a change to the affected regions or services.
	KindScopeChanged EventKind = "scope_changed"
	// KindMinorUpdated is a content change with no new progress and no scope
	// movement: a title correction, a severity regrade.
	KindMinorUpdated EventKind = "minor_updated"
	// KindResolved is the provider vouching that it is over.
	KindResolved EventKind = "resolved"
	// KindResolvedInferred is a record we concluded is over without the
	// provider ever saying so. Weaker than KindResolved, and deliberately named
	// so that a reader can tell the difference.
	KindResolvedInferred EventKind = "resolved_inferred"
	// KindReopened is a record returning to the open list after we recorded it
	// as finished.
	KindReopened EventKind = "reopened"
	// KindMissedAndResolved is a record that opened and closed entirely between
	// two polls. One event, not a new-then-resolved pair.
	KindMissedAndResolved EventKind = "missed_and_resolved"
	// KindUpdatedAfterResolve is a post-mortem edit to a closed record.
	KindUpdatedAfterResolve EventKind = "updated_after_resolve"
	// KindVanished is a record that disappeared from both lists without ever
	// being reported resolved. It is NOT a resolution.
	KindVanished EventKind = "vanished"
	// KindScopeExited is a record that stopped affecting anything we watch.
	KindScopeExited EventKind = "scope_exited"
)

// Event is one transition, ready to be rendered or exported.
type Event struct {
	Kind   EventKind
	Record Record

	// NewUpdates carries only the progress entries added since we last looked,
	// so a notification can quote the news rather than the whole history.
	NewUpdates []Update
	// Added and Removed describe a scope change.
	Added   []string
	Removed []string

	// ColdStart marks an event emitted on the first run against empty state.
	// A reader deserves to know that "new" here may mean "new to us" rather
	// than "just happened".
	ColdStart bool
}

// Stored is what we persist per record between polls.
type Stored struct {
	Record Record
	Status Status
	FP     Fingerprint

	// Identity distinguishes two different incidents that share a provider id.
	// Providers do reuse ids; without this, a reused id looks like a reopen of
	// something unrelated.
	Identity string

	// Matched records whether this record was in our scope when last seen.
	//
	// Records are stored whether or not they match. Storing only matches would
	// make "a watched region was added to an incident we had been ignoring"
	// indistinguishable from "a brand new incident", and would make the reverse
	// transition undetectable entirely.
	Matched bool

	FirstSeenAt time.Time
	LastSeenAt  time.Time

	// VanishCount counts consecutive complete snapshots in which an open record
	// was absent from both lists.
	VanishCount int
}

// DiffOpts controls one comparison.
type DiffOpts struct {
	// Complete reports whether absence in this snapshot is meaningful. When
	// false, no resolution is inferred from a record being missing.
	Complete bool
	// ColdStart is true on the first run against empty state.
	ColdStart bool
	// Filter decides which records are ours.
	Filter Filter
	// VanishGrace is how many consecutive absences are required before an open
	// record may be concluded resolved without the provider saying so.
	VanishGrace int
	// UnresolvedCount is the provider's own count, or -1 when unavailable. A
	// vanished record is only concluded resolved when the provider also claims
	// nothing is open.
	UnresolvedCount int
}

// Identity derives a stable fingerprint of "which incident is this", used to
// detect provider id reuse.
func identityOf(r Record) string {
	h := sha256.New()
	writeField(h, "started", canonicalTime(r.StartedAt))
	writeField(h, "title", r.Title)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Diff compares stored state against one snapshot and returns the transitions.
//
// It is a pure function: no clock, no I/O, no logger. Every branch below is
// therefore reachable from a table test with hand-built inputs, which matters
// because this is the code whose bugs are invisible in production — a wrong
// answer here is silence, and silence is what the service is supposed to detect.
func Diff(prev map[Key]Stored, snap *Snapshot, o DiffOpts) []Event {
	var out []Event
	seen := make(map[Key]bool, len(snap.Open)+len(snap.Recent))

	for _, r := range snap.Open {
		seen[r.Key] = true
		out = append(out, diffOpen(prev, r, o)...)
	}
	for _, r := range snap.Recent {
		if seen[r.Key] {
			// A record in both lists at once is a provider inconsistency. The
			// open list wins: continuing to alert on something that may still
			// be happening is the safe direction.
			continue
		}
		seen[r.Key] = true
		out = append(out, diffRecent(prev, r, o)...)
	}

	if !o.Complete {
		// Absence proves nothing when the snapshot could not see everything.
		// Skipping the sweep is the single most important line in this file.
		return out
	}
	out = append(out, sweepAbsent(prev, seen, o)...)
	return out
}

func diffOpen(prev map[Key]Stored, r Record, o DiffOpts) []Event {
	p, had := prev[r.Key]
	matched := o.Filter.Matches(r)

	if !matched {
		if had && p.Matched {
			// It left our scope. That is not a resolution: the incident may
			// well still be running elsewhere.
			return []Event{{Kind: KindScopeExited, Record: r}}
		}
		return nil
	}

	switch {
	case !had, !p.Matched:
		// Either genuinely new, or an existing incident that just grew into a
		// region we watch. Both are new to us, and emitting a scope change for
		// the latter would be silent for anyone whose notifier ignores minor
		// updates.
		return []Event{{Kind: KindNew, Record: r, ColdStart: o.ColdStart}}

	case p.Status == StatusResolved && p.Identity != identityOf(r):
		// Same id, different incident. Providers reuse ids; treating this as a
		// reopen would attach a fresh outage to a stale thread.
		return []Event{{Kind: KindNew, Record: r}}

	case p.Status == StatusResolved, p.Status == StatusUnknown:
		return []Event{{Kind: KindReopened, Record: r}}
	}

	return changeEvent(p, r)
}

// changeEvent classifies a change to a record we already hold as open.
//
// The dimensions are checked in priority order rather than as a switch on the
// fingerprint, because a moved hash does not always mean there is news: the
// progress hash also moves when the provider REMOVES entries, and reporting
// that as an update produces a notification with nothing in it.
func changeEvent(p Stored, r Record) []Event {
	if p.FP.Progress != r.FP.Progress {
		if nu := newUpdates(p.Record.Updates, r.Updates); len(nu) > 0 {
			return []Event{{Kind: KindUpdated, Record: r, NewUpdates: nu}}
		}
		// The hash moved but nothing new arrived, so entries were dropped or
		// rewritten upstream. Progress is append-only by contract, making this
		// a provider-side regression rather than news for a human. Fall through
		// to the other dimensions instead of emitting a phantom update.
	}
	if p.FP.Scope != r.FP.Scope {
		added, removed := scopeDelta(p.Record, r)
		return []Event{{Kind: KindScopeChanged, Record: r, Added: added, Removed: removed}}
	}
	if p.FP.Content != r.FP.Content {
		return []Event{{Kind: KindMinorUpdated, Record: r}}
	}
	// Everything else, including an mtime that advanced with no visible change,
	// is recorded by Apply but wakes nobody.
	return nil
}

func diffRecent(prev map[Key]Stored, r Record, o DiffOpts) []Event {
	if !o.Filter.Matches(r) {
		return nil
	}
	p, had := prev[r.Key]

	switch {
	case !had && o.ColdStart:
		// History on a first run is not news. Alerting on it would page
		// everyone for every incident the provider has ever published.
		return nil
	case !had:
		// It opened and closed between two polls. One event, not a pair.
		return []Event{{Kind: KindMissedAndResolved, Record: r}}
	case p.Status == StatusOpen, p.Status == StatusUnknown:
		return []Event{{Kind: KindResolved, Record: r}}
	case !p.FP.Equal(r.FP):
		return []Event{{Kind: KindUpdatedAfterResolve, Record: r}}
	}
	return nil
}

// sweepAbsent handles records we hold as open that appeared in neither list.
func sweepAbsent(prev map[Key]Stored, seen map[Key]bool, o DiffOpts) []Event {
	keys := make([]Key, 0, len(prev))
	for k, p := range prev {
		if seen[k] || !p.Matched {
			continue
		}
		if p.Status != StatusOpen && p.Status != StatusUnknown {
			continue
		}
		keys = append(keys, k)
	}
	// Map iteration is randomized; sort so the event order is reproducible.
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })

	out := make([]Event, 0, len(keys))
	for _, k := range keys {
		p := prev[k]
		// A record that is absent from both lists is indistinguishable from a
		// partial fetch, a silently filtered response, or a shape change. It is
		// only concluded resolved once several complete snapshots agree AND the
		// provider's own count says nothing is open.
		if p.VanishCount+1 >= o.VanishGrace && o.UnresolvedCount == 0 {
			out = append(out, Event{Kind: KindResolvedInferred, Record: p.Record})
			continue
		}
		out = append(out, Event{Kind: KindVanished, Record: p.Record})
	}
	return out
}

// newUpdates returns the progress entries in cur that were not already in prev.
//
// Matching is by content hash rather than position, so a provider inserting an
// entry out of order does not make every later entry look new.
func newUpdates(prev, cur []Update) []Update {
	if len(prev) == 0 {
		return cur
	}
	known := make(map[string]bool, len(prev))
	for _, u := range prev {
		known[u.Hash] = true
	}
	var out []Update
	for _, u := range cur {
		if !known[u.Hash] {
			out = append(out, u)
		}
	}
	return out
}

func scopeDelta(prev, cur Record) (added, removed []string) {
	before := scopeSet(prev)
	after := scopeSet(cur)
	for k := range after {
		if !before[k] {
			added = append(added, k)
		}
	}
	for k := range before {
		if !after[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func scopeSet(r Record) map[string]bool {
	out := make(map[string]bool, len(r.Scope))
	for _, sc := range r.Scope {
		out[sc.RegionCode] = true
	}
	return out
}

// Apply folds a snapshot into stored state.
//
// It is separate from Diff so that the decision of what to tell a human and the
// decision of what to remember are independently testable, and so a change to
// notification policy can never accidentally corrupt the state that resolution
// detection depends on.
func Apply(prev map[Key]Stored, snap *Snapshot, o DiffOpts, now time.Time) map[Key]Stored {
	next := make(map[Key]Stored, len(prev)+len(snap.Open))
	for k, v := range prev {
		next[k] = v
	}
	seen := make(map[Key]bool, len(snap.Open)+len(snap.Recent))

	for _, r := range snap.Open {
		seen[r.Key] = true
		next[r.Key] = store(prev, r, StatusOpen, o, now)
	}
	for _, r := range snap.Recent {
		if seen[r.Key] {
			continue
		}
		seen[r.Key] = true
		next[r.Key] = store(prev, r, StatusResolved, o, now)
	}

	if !snap.Complete {
		// Without a complete view we cannot say anything about what is missing,
		// so vanish counting must not advance either.
		return next
	}

	for k, p := range next {
		if seen[k] || p.Status != StatusOpen && p.Status != StatusUnknown {
			continue
		}
		p.VanishCount++
		if p.VanishCount >= o.VanishGrace && o.UnresolvedCount == 0 {
			p.Status = StatusResolved
		} else {
			// Not resolved. Unknown means "we are still alerting on this and we
			// do not know why we cannot see it".
			p.Status = StatusUnknown
		}
		next[k] = p
	}
	return next
}

func store(prev map[Key]Stored, r Record, status Status, o DiffOpts, now time.Time) Stored {
	s := Stored{
		Record:      r,
		Status:      status,
		FP:          r.FP,
		Identity:    identityOf(r),
		Matched:     o.Filter.Matches(r),
		FirstSeenAt: now,
		LastSeenAt:  now,
		VanishCount: 0,
	}
	if p, had := prev[r.Key]; had && p.Identity == s.Identity {
		// Preserve the first sighting across polls, but only for the same
		// incident: a reused id starts its own clock.
		s.FirstSeenAt = p.FirstSeenAt
		// Progress entries are append-only by contract. A shrinking list is a
		// provider bug, so keep the union rather than alerting on a regression.
		s.Record.Updates = unionUpdates(p.Record.Updates, r.Updates)
		if len(s.Record.Updates) != len(r.Updates) {
			s.Record.FP = Compute(s.Record)
			s.FP = s.Record.FP
		}
	}
	return s
}

// unionUpdates merges two progress lists, keeping every entry either has seen.
func unionUpdates(prev, cur []Update) []Update {
	if len(prev) == 0 {
		return cur
	}
	byHash := make(map[string]Update, len(prev)+len(cur))
	for _, u := range prev {
		byHash[u.Hash] = u
	}
	for _, u := range cur {
		byHash[u.Hash] = u
	}
	if len(byHash) == len(cur) {
		return cur
	}
	out := make([]Update, 0, len(byHash))
	for _, u := range byHash {
		out = append(out, u)
	}
	sorted, _ := SortUpdates(out)
	return sorted
}

// ProgressShrank reports whether cur lost entries that prev held. Callers turn
// this into an anomaly metric; it is never itself a notification.
func ProgressShrank(prev, cur []Update) bool {
	if len(prev) == 0 {
		return false
	}
	have := make(map[string]bool, len(cur))
	for _, u := range cur {
		have[u.Hash] = true
	}
	for _, u := range prev {
		if !have[u.Hash] {
			return true
		}
	}
	return false
}
