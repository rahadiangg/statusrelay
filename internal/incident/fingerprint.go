package incident

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sort"
	"strconv"
	"time"
)

// Fingerprint summarises a record so two observations can be compared without
// re-reading the whole payload.
//
// It is deliberately three hashes rather than one, because the three kinds of
// change route differently: new progress text is worth a notification, a change
// in which regions are affected is worth a page, and a cosmetic title edit is
// worth neither.
type Fingerprint struct {
	// Content covers the semantic fields excluding scope and progress.
	Content string
	// Scope covers the affected regions and services.
	Scope string
	// Progress covers the ordered progress entries.
	Progress string

	// Mtime is the provider's record mtime, or zero.
	//
	// It is NOT folded into any hash, for four independent reasons, the first
	// decisive:
	//
	//  1. Providers commonly expose a mtime only for already-resolved records,
	//     so the records most needing change detection have none at all.
	//  2. Time-windowed history endpoints may omit it even where the main
	//     endpoint supplies it.
	//  3. It is not derived from content. On the reference incident the mtime
	//     sat 35 minutes after the newest progress entry: records mutate
	//     without gaining rows, so a bumped mtime implies no visible change and
	//     an unchanged mtime does not imply no change.
	//  4. Provider clocks skew. An mtime moving backwards must not read as a
	//     change.
	//
	// Keeping it beside the hashes rather than inside them makes an
	// mtime-only bump detectable and deliberately non-alerting.
	Mtime time.Time
}

// Equal reports whether two fingerprints describe the same observation,
// ignoring Mtime.
func (f Fingerprint) Equal(o Fingerprint) bool {
	return f.Content == o.Content && f.Scope == o.Scope && f.Progress == o.Progress
}

// Compute derives a record's fingerprint from its normalized fields.
//
// It hashes the normalized struct, never the raw payload bytes. Hashing raw
// bytes would make key reordering, whitespace, and — worst — unrelated
// incidents in the same response array all look like changes to this record.
func Compute(r Record) Fingerprint {
	return Fingerprint{
		Content:  hashContent(r),
		Scope:    hashScope(r),
		Progress: hashProgress(r.Updates),
		Mtime:    r.UpdatedAt.UTC(),
	}
}

func hashContent(r Record) string {
	h := sha256.New()
	// Titles are hashed from the lossless map, sorted, so a provider adding a
	// translation is a content change while map iteration order is not.
	langs := make([]string, 0, len(r.Titles))
	for l := range r.Titles {
		langs = append(langs, l)
	}
	sort.Strings(langs)
	for _, l := range langs {
		writeField(h, "title."+l, r.Titles[l])
	}
	writeField(h, "severity", strconv.Itoa(int(r.Severity)))
	writeField(h, "raw_severity", r.RawSeverity)
	writeField(h, "status", strconv.Itoa(int(r.Status)))
	writeField(h, "started_at", canonicalTime(r.StartedAt))
	writeField(h, "ended_at", canonicalTime(r.EndedAt))
	writeField(h, "global", strconv.FormatBool(r.Global))
	writeField(h, "has_report", strconv.FormatBool(r.HasReport))
	return hex.EncodeToString(h.Sum(nil))
}

func hashScope(r Record) string {
	h := sha256.New()
	// Global is part of the scope hash: a record losing its last region is a
	// scope change, and without this it would hash identically to one that
	// never had regions.
	writeField(h, "global", strconv.FormatBool(r.Global))

	type pair struct{ region, service string }
	pairs := make([]pair, 0, len(r.Scope))
	for _, sc := range r.Scope {
		if len(sc.Services) == 0 {
			// A region named with no services is meaningful on its own.
			pairs = append(pairs, pair{region: sc.RegionCode})
			continue
		}
		for _, sv := range sc.Services {
			pairs = append(pairs, pair{region: sc.RegionCode, service: sv.ID})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].region != pairs[j].region {
			return pairs[i].region < pairs[j].region
		}
		return pairs[i].service < pairs[j].service
	})
	for _, p := range pairs {
		writeField(h, "scope", p.region+"\x1f"+p.service)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hashProgress(us []Update) string {
	h := sha256.New()
	// Progress order is semantic: the same texts in a different order is a
	// different narrative. Callers normalize the order before fingerprinting.
	for _, u := range us {
		writeField(h, "progress", canonicalTime(u.At)+"\x1f"+u.Text)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// writeField length-prefixes every field so that concatenation is unambiguous:
// without it, {"ab", "c"} and {"a", "bc"} would hash identically.
func writeField(h io.Writer, name, value string) {
	_, _ = io.WriteString(h, strconv.Itoa(len(name)))
	_, _ = io.WriteString(h, ":")
	_, _ = io.WriteString(h, name)
	_, _ = io.WriteString(h, strconv.Itoa(len(value)))
	_, _ = io.WriteString(h, ":")
	_, _ = io.WriteString(h, value)
}

// canonicalTime renders a time so that identical instants expressed in
// different zones hash identically. Providers mix "Z" and "+08:00" for the same
// moment, and a zone-format change must not look like an incident update.
//
// The zero time renders as the empty string rather than year 1, so "provider
// supplied no timestamp" is distinguishable in the hash input.
func canonicalTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// SortUpdates orders progress entries deterministically and reports whether the
// input was already ordered.
//
// Out-of-order entries are a provider anomaly worth a metric, but they are not
// a reason to reject the record: a mis-sorted outage is still an outage.
func SortUpdates(us []Update) (sorted []Update, wasOrdered bool) {
	sorted = make([]Update, len(us))
	copy(sorted, us)
	wasOrdered = sort.SliceIsSorted(sorted, func(i, j int) bool {
		return sorted[i].At.Before(sorted[j].At)
	})
	// Stable so that entries sharing a timestamp keep payload order, which is
	// the only ordering signal left for providers that publish second-precision
	// timestamps and post twice within one second.
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].At.Before(sorted[j].At)
	})
	return sorted, wasOrdered
}

// HashUpdateText is the per-entry hash used to detect genuinely new progress
// entries across polls.
func HashUpdateText(at time.Time, text string) string {
	h := sha256.New()
	writeField(h, "progress", canonicalTime(at)+"\x1f"+text)
	return hex.EncodeToString(h.Sum(nil))[:16]
}
